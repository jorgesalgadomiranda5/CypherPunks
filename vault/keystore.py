"""Password-protected keystore (D6).

A private key is never written in plaintext. It is encrypted with AES-256-GCM
under a key that scrypt derives from the user's password. The rest of the file
(format, KDF parameters, salt and metadata) is authenticated as AAD, so any
change to it makes the keystore fail to open.
"""
import base64
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from vault import crypto_core
from vault.exceptions import KeyManagementError
from vault.keys import key_id

KEYSTORE_FORMAT = "SDV-KEYSTORE-1"
KDF_PARAMETERS = {"algorithm": "scrypt", "n": 2**17, "r": 8, "p": 1, "length": 32}
SALT_SIZE_BYTES = 16


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Password + salt -> 256-bit key. scrypt is slow and memory-hard on purpose."""
    return Scrypt(
        salt=salt,
        length=KDF_PARAMETERS["length"],
        n=KDF_PARAMETERS["n"],
        r=KDF_PARAMETERS["r"],
        p=KDF_PARAMETERS["p"],
    ).derive(password)


def save_keystore(private_key, usage: str, path: str | Path, password: bytes) -> None:
    """Encrypt the private key with a password-derived key and write the keystore."""
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


def _aad(store: dict) -> bytes:
    """Everything except the nonce and the encrypted key is authenticated."""

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)

