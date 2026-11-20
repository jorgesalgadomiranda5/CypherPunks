"""Key wrapping (D3): protect the 32-byte file key with ECIES over X25519.

For each recipient: an ephemeral X25519 pair, HKDF-SHA256 over the shared
secret, and AES-256-GCM around the file key. encrypted_key = E || nonce || wrapped.
"""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vault.crypto_core import KEY_SIZE_BYTES, NONCE_SIZE_BYTES, TAG_SIZE_BYTES
from vault.exceptions import IntegrityError, VaultError

WRAP_ALGORITHM = "ECIES-X25519-HKDF-SHA256-AES256GCM"
HKDF_INFO = b"SDV3/file-key"
PUBLIC_KEY_SIZE = 32
WRAPPED_KEY_SIZE = PUBLIC_KEY_SIZE + NONCE_SIZE_BYTES + KEY_SIZE_BYTES + TAG_SIZE_BYTES  # 92


def _raw(public_key: x25519.X25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _wrap_key(shared: bytes, ephemeral: bytes, recipient: bytes) -> bytes:
    """Bind the derived key to both public keys (HKDF info) so E cannot be swapped."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=None,
        info=HKDF_INFO + ephemeral + recipient,
    ).derive(shared)


def wrap_file_key(public_key: x25519.X25519PublicKey, file_key: bytes) -> bytes:
    """Encrypt the file key for one recipient; a fresh ephemeral key every call."""
    if len(file_key) != KEY_SIZE_BYTES:
        raise VaultError(f"Only {KEY_SIZE_BYTES}-byte symmetric file keys may be wrapped")
    ephemeral = x25519.X25519PrivateKey.generate()
    e_pub, r_pub = _raw(ephemeral.public_key()), _raw(public_key)
    key = _wrap_key(ephemeral.exchange(public_key), e_pub, r_pub)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    return e_pub + nonce + AESGCM(key).encrypt(nonce, file_key, e_pub + r_pub)


def unwrap_file_key(private_key: x25519.X25519PrivateKey, wrapped_key: bytes) -> bytes:
    """Recover the file key; every failure is the same generic IntegrityError."""
    if len(wrapped_key) != WRAPPED_KEY_SIZE:
        raise IntegrityError("Authentication failed")
    e_pub = wrapped_key[:PUBLIC_KEY_SIZE]
    nonce = wrapped_key[PUBLIC_KEY_SIZE:PUBLIC_KEY_SIZE + NONCE_SIZE_BYTES]
    r_pub = _raw(private_key.public_key())
    try:
        # A low-order E gives an all-zero secret: the library raises ValueError.
        shared = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(e_pub))
        key = _wrap_key(shared, e_pub, r_pub)
        return AESGCM(key).decrypt(nonce, wrapped_key[PUBLIC_KEY_SIZE + NONCE_SIZE_BYTES:], e_pub + r_pub)
    except (InvalidTag, ValueError):
        raise IntegrityError("Authentication failed") from None
