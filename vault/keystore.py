"""Password-protected keystore (D6).

A private key is never written in plaintext. It is encrypted with AES-256-GCM
under a key that scrypt derives from the user's password. The rest of the file
(format, KDF parameters, salt and metadata) is authenticated as AAD, so any
change to it makes the keystore fail to open.
"""
import base64
import json
import os
import shutil
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from vault import crypto_core
from vault.exceptions import IntegrityError, KeyManagementError

from vault.keys import key_id

KEYSTORE_FORMAT = "SDV-KEYSTORE-1"
KDF_PARAMETERS = {"algorithm": "scrypt", "n": 2**17, "r": 8, "p": 1, "length": 32}
SALT_SIZE_BYTES = 16
MIN_PASSWORD_LENGTH = 12

# One keystore holds one key with one job: X25519 unwraps file keys, Ed25519 signs.
KEY_TYPES = {"wrap": x25519.X25519PrivateKey, "sign": ed25519.Ed25519PrivateKey}
PrivateKey = x25519.X25519PrivateKey | ed25519.Ed25519PrivateKey

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Password + salt -> 256-bit key. scrypt is slow and memory-hard on purpose."""
    return Scrypt(
        salt=salt,
        length=KDF_PARAMETERS["length"],
        n=KDF_PARAMETERS["n"],
        r=KDF_PARAMETERS["r"],
        p=KDF_PARAMETERS["p"],
    ).derive(password)


def save_keystore(private_key: PrivateKey, usage: str, path: str | Path, password: bytes) -> None:
    """Encrypt the private key with a password-derived key and write the keystore."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise KeyManagementError(
            f"The password must have at least {MIN_PASSWORD_LENGTH} characters"
        )

    
    if not isinstance(private_key, KEY_TYPES.get(usage, ())):
        raise KeyManagementError(f"Not a valid key for usage '{usage}'")

    
    salt = os.urandom(SALT_SIZE_BYTES)
    store = {
        "format": KEYSTORE_FORMAT,
        "kdf_parameters": KDF_PARAMETERS,
        "salt": _b64e(salt),
        "metadata": {
            "key_id": key_id(private_key.public_key()),
            "usage": usage,
            "created_at": int(time.time()),
        },
    }
    plaintext = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    nonce, ciphertext = crypto_core.encrypt(derive_key(password, salt), plaintext, _aad(store))
    store["nonce"] = _b64e(nonce)
    store["encrypted_private_key"] = _b64e(ciphertext)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise KeyManagementError(f"Keystore already exists: {path}") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=2)


def load_keystore(path: str | Path, password: bytes, usage: str) -> PrivateKey:
    """Derive the key from the password and decrypt the private key, only in memory."""
    try:
        store = json.loads(Path(path).read_text(encoding="utf-8"))
        der = crypto_core.decrypt(
            derive_key(password, _b64d(store["salt"])),
            _b64d(store["nonce"]),
            _b64d(store["encrypted_private_key"]),
            _aad(store),
        )
    except IntegrityError:
        raise KeyManagementError("Could not unlock the keystore (wrong password or modified file)") from None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise KeyManagementError(f"Not a valid keystore: {path}") from exc
    private_key = serialization.load_der_private_key(der, password=None)
    metadata = store["metadata"]
    if metadata["usage"] != usage or not isinstance(private_key, KEY_TYPES[usage]):
        raise KeyManagementError(f"This keystore does not hold a '{usage}' key")
    if metadata["key_id"] != key_id(private_key.public_key()):
        raise KeyManagementError("The key does not match the key ID in the keystore")
    return private_key


def backup_keystore(path: str | Path, backup_dir: str | Path) -> Path:
    """Copy the keystore as it is: the backup stays encrypted, so no password is needed."""
    source = Path(path)
    target = Path(backup_dir) / source.name

    if target.exists():
        raise KeyManagementError(f"Backup already exists: {target}")

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    except OSError as exc:
        raise KeyManagementError(f"Could not back up {source}") from exc

    return target

def restore_keystore(backup_path: str | Path, path: str | Path, password: bytes, usage: str) -> None:
    """Restore a backup only if it unlocks with the password: a modified or foreign file is refused."""
    target = Path(path)
    if target.exists():
        raise KeyManagementError(f"Keystore already exists: {target}")
    load_keystore(backup_path, password, usage)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(backup_path, target)
    except OSError as exc:
        raise KeyManagementError(f"Could not restore {backup_path}") from exc


def _aad(store: dict) -> bytes:
    """Everything except the nonce and the encrypted key is authenticated."""
    fields = ("format", "kdf_parameters", "salt", "metadata")
    return crypto_core.canonicalize_metadata({name: store[name] for name in fields})

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)

