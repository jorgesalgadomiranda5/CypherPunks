"""Cryptographic core of the vault: AES-256-GCM (AEAD).

Stages: secure randomness (CSPRNG), metadata canonicalization (AAD)
and authenticated encryption / decryption with tamper detection.
"""

import json
import os
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.exceptions import ContainerFormatError, IntegrityError, VaultError

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


REQUIRED_METADATA_FIELDS = {
    "algorithm", "version", "original_name", "timestamp",
    "key_bits", "nonce_bytes", "tag_bytes",
}


def build_metadata(original_name: str, timestamp: int | None = None) -> dict:
    """Build the metadata dictionary that will travel as AAD.

    Only the base name of the file is kept, never the full local path.
    """
    return {
        "algorithm": ALGORITHM,
        "version": FORMAT_VERSION,
        # Normalize Windows separators too, so no local path leaks.
        "original_name": os.path.basename(original_name.replace("\\", "/")),
        "timestamp": int(time.time()) if timestamp is None else int(timestamp),
        "key_bits": KEY_SIZE_BITS,
        "nonce_bytes": NONCE_SIZE_BYTES,
        "tag_bytes": TAG_SIZE_BYTES,
    }


def canonicalize_metadata(metadata: dict) -> bytes:
    """Serialize metadata deterministically.

    Same dictionary -> same bytes, regardless of key insertion order.
    This matters because the AAD must be byte-for-byte identical at
    encryption and decryption time, or authentication fails.
    """
    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def parse_metadata(metadata_bytes: bytes) -> dict:
    """Parse and validate metadata bytes.

    Call this only AFTER the AEAD tag has been verified: until then the
    metadata is attacker-controlled input.
    """
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerFormatError("Metadata is not valid JSON") from exc

    if not isinstance(metadata, dict):
        raise ContainerFormatError("Metadata must be a JSON object")
    missing = REQUIRED_METADATA_FIELDS - metadata.keys()
    if missing:
        raise ContainerFormatError(f"Missing metadata fields: {sorted(missing)}")
    if metadata["algorithm"] != ALGORITHM:
        raise ContainerFormatError(f"Unsupported algorithm: {metadata['algorithm']}")
    if metadata["version"] != FORMAT_VERSION:
        raise ContainerFormatError(f"Unsupported version: {metadata['version']}")
    return metadata


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE_BYTES:
        raise VaultError(f"Key must be exactly {KEY_SIZE_BYTES} bytes")


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt and authenticate.

    Returns (nonce, ciphertext_with_tag). A fresh nonce is generated inside
    this function on every call, so callers cannot accidentally reuse one.
    The last 16 bytes of the result are the GCM authentication tag, which
    covers both the ciphertext and the AAD.
    """
    _check_key(key)
    nonce = generate_nonce()
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext_with_tag


def decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    """Verify the tag and decrypt.

    Raises IntegrityError if the key is wrong or if the ciphertext, tag,
    nonce or AAD were modified. AES-GCM checks the tag before returning
    anything, so no partial plaintext is ever released.
    """
    _check_key(key)
    if len(nonce) != NONCE_SIZE_BYTES:
        raise IntegrityError("Authentication failed")
    if len(ciphertext_with_tag) < TAG_SIZE_BYTES:
        raise IntegrityError("Authentication failed")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag:
        # Generic message on purpose: do not reveal which part failed.
        raise IntegrityError("Authentication failed") from None
