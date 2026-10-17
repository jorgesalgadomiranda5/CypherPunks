"""Cryptographic core of the vault: AES-256-GCM (AEAD).

Stage: secure randomness (CSPRNG).
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "AES-256-GCM"
FORMAT_VERSION = "1.0"

KEY_SIZE_BITS = 256
KEY_SIZE_BYTES = KEY_SIZE_BITS // 8   # 32
NONCE_SIZE_BYTES = 12                 # 96 bits, the size recommended for GCM
TAG_SIZE_BYTES = 16                   # 128-bit authentication tag


def generate_key() -> bytes:
    """Return a fresh 256-bit key, drawn from the OS CSPRNG.

    A new key is generated for every file. It is never derived from a
    manual seed or from Python's `random` module (which is predictable).
    """
    return AESGCM.generate_key(bit_length=KEY_SIZE_BITS)


def generate_nonce() -> bytes:
    """Return a fresh 96-bit nonce from os.urandom (OS-provided randomness).

    Called once per encryption operation; a nonce is never reused.
    """
    return os.urandom(NONCE_SIZE_BYTES)
