"""Key generation and metadata handling for the vault."""
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.exceptions import ContainerFormatError

ALGORITHM = "AES-256-GCM"
FORMAT_VERSION = "1.0"

KEY_SIZE_BITS = 256
KEY_SIZE_BYTES = KEY_SIZE_BITS // 8   # 32 bytes
NONCE_SIZE_BYTES = 12                 # 96-bit nonce
TAG_SIZE_BYTES = 16                   # 128-bit tag


def generate_key() -> bytes:
    """Generate a new 256-bit key using secure randomness."""
    return AESGCM.generate_key(bit_length=KEY_SIZE_BITS)


def generate_nonce() -> bytes:
    """Generate a random 12-byte nonce for encryption."""
    return os.urandom(NONCE_SIZE_BYTES)


REQUIRED_METADATA_FIELDS = {
    "algorithm", "version", "original_name", "timestamp",
    "key_bits", "nonce_bytes", "tag_bytes",
}


def build_metadata(original_name: str, timestamp: int | None = None) -> dict:
    """Create metadata, keeping only the file name, not its path."""
    return {
        "algorithm": ALGORITHM,
        "version": FORMAT_VERSION,
        # Handle Windows paths as well.
        "original_name": os.path.basename(original_name.replace("\\", "/")),
        "timestamp": int(time.time()) if timestamp is None else int(timestamp),
        "key_bits": KEY_SIZE_BITS,
        "nonce_bytes": NONCE_SIZE_BYTES,
        "tag_bytes": TAG_SIZE_BYTES,
    }


def canonicalize_metadata(metadata: dict) -> bytes:
    """Convert metadata to consistent JSON bytes for AAD."""
    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def parse_metadata(metadata_bytes: bytes) -> dict:
    """Read and validate metadata after checking the AEAD tag."""
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
