"""Key management for sharing (D3): RSA key pairs, PEM storage and key IDs."""
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from vault.exceptions import KeyManagementError

RSA_KEY_SIZE = 3072
PUBLIC_EXPONENT = 65537
MIN_RSA_KEY_SIZE = 3072


def generate_keypair(key_size: int = RSA_KEY_SIZE) -> rsa.RSAPrivateKey:
    if key_size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(f"RSA keys must be at least {MIN_RSA_KEY_SIZE} bits")
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size)


def generate_signing_keypair() -> ed25519.Ed25519PrivateKey:
    """Ed25519 pair used only to sign. RSA pairs stay for key wrapping only."""
    return ed25519.Ed25519PrivateKey.generate()


def load_signing_private_key(path: str | Path, passphrase: bytes) -> ed25519.Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)
    except (OSError, ValueError, TypeError) as exc:
        raise KeyManagementError("Could not load signing key (wrong passphrase or corrupt file)") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise KeyManagementError("Only Ed25519 keys can be used for signatures")
    return key


def load_signing_public_key(path: str | Path) -> ed25519.Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise KeyManagementError(f"Could not load public key: {path}") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise KeyManagementError("Only Ed25519 keys can be used for signatures")
    return key


def save_private_key(private_key: rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey, path: str | Path, passphrase: bytes) -> None:
    """Write the private key as PKCS#8 PEM, always encrypted with a passphrase."""
    if not passphrase:
        raise KeyManagementError("A passphrase is required to store a private key")
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    path = Path(path)
    path.write_bytes(pem)
    path.chmod(0o600)


def load_private_key(path: str | Path, passphrase: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)
    except (OSError, ValueError, TypeError) as exc:
        raise KeyManagementError("Could not load private key (wrong passphrase or corrupt file)") from exc
    _check_rsa(key.public_key())
    return key


def save_public_key(public_key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey, path: str | Path) -> None:
    Path(path).write_bytes(public_key_to_pem(public_key))


def load_public_key(path: str | Path) -> rsa.RSAPublicKey:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise KeyManagementError(f"Could not read public key: {path}") from exc
    return public_key_from_pem(data)


def public_key_to_pem(public_key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_pem(data: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise KeyManagementError("Invalid public key") from exc
    _check_rsa(key)
    return key


def key_id(public_key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey) -> str:
    """Key ID = SHA-256 over the DER SubjectPublicKeyInfo, lowercase hex (64 chars).

       The same rule identifies recipients (RSA) and signers (Ed25519).
    """
    der = public_key.public_bytes(
	encoding=serialization.Encoding.DER,
    	format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _check_rsa(key) -> None:
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyManagementError("Only RSA keys are supported")
    if key.key_size < MIN_RSA_KEY_SIZE:
        raise KeyManagementError(f"RSA keys must be at least {MIN_RSA_KEY_SIZE} bits")
