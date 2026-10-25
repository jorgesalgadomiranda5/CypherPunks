
"""Key wrapping (D3): protect the 32-byte file key with RSA-OAEP."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from vault.crypto_core import KEY_SIZE_BYTES
from vault.exceptions import IntegrityError, VaultError

OAEP_LABEL = b"SDV2/file-key"
WRAP_ALGORITHM = "RSA-OAEP-SHA256"

def _oaep() -> padding.OAEP:
    """Configure RSA-OAEP with SHA-256."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=OAEP_LABEL,
    )


def wrap_file_key(public_key: rsa.RSAPublicKey, file_key: bytes) -> bytes:
    """Encrypt the file key using the recipient's public key."""
    if len(file_key) != KEY_SIZE_BYTES:
        raise VaultError(f"Only {KEY_SIZE_BYTES}-byte symmetric file keys may be wrapped")
    return public_key.encrypt(file_key, _oaep())


def unwrap_file_key(private_key: rsa.RSAPrivateKey, wrapped_key: bytes) -> bytes:
    """Recover the file key using the recipient's private key."""
    if len(wrapped_key) != private_key.key_size // 8:
        raise IntegrityError("Authentication failed")
    try:
        file_key = private_key.decrypt(wrapped_key, _oaep())
    except ValueError:
        raise IntegrityError("Authentication failed") from None
    if len(file_key) != KEY_SIZE_BYTES:
        raise IntegrityError("Authentication failed")
    return file_key
