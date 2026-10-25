
"""Key wrapping (D3): protect the 32-byte file key with RSA-OAEP."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from vault.exceptions import IntegrityError


def _oaep() -> padding.OAEP:
    """Configure RSA-OAEP with SHA-256."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_file_key(public_key: rsa.RSAPublicKey, file_key: bytes) -> bytes:
    """Encrypt the file key using the recipient's public key."""
    return public_key.encrypt(file_key, _oaep())


def unwrap_file_key(private_key: rsa.RSAPrivateKey, wrapped_key: bytes) -> bytes:
    """Recover the file key using the recipient's private key."""
    try:
        file_key = private_key.decrypt(wrapped_key, _oaep())
    except ValueError:
        raise IntegrityError("Authentication failed") from None
    return file_key
