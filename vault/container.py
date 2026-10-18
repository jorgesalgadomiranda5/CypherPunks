"""Binary container format (.sdv).
Layout (all integers big-endian):

    +----------------+----------------+-----------------+-----------+---------------------+
    | magic  (4 B)   | meta_len (4 B) | metadata (JSON) | nonce 12B | ciphertext || tag   |
    +----------------+----------------+-----------------+-----------+---------------------+
    |<-------------------- header (used as AAD) ------->|

The whole header (magic + length + metadata) is passed as AAD, so changing
any of those bytes makes authentication fail. The nonce is not part of the
AAD but GCM authenticates it implicitly: a different nonce produces a
different keystream and tag, so the check fails as well.
"""
import struct
from dataclasses import dataclass

from vault.crypto_core import NONCE_SIZE_BYTES, TAG_SIZE_BYTES
from vault.exceptions import ContainerFormatError

MAGIC = b"SDV1"
LENGTH_FORMAT = ">I"                     # unsigned 32-bit, big-endian
LENGTH_SIZE = struct.calcsize(LENGTH_FORMAT)
MAX_METADATA_SIZE = 64 * 1024            # refuse absurd lengths before allocating
FILE_EXTENSION = ".sdv"


@dataclass(frozen=True)
class Container:
    header: bytes             # magic + meta_len + metadata  (this is the AAD)
    metadata_bytes: bytes     # raw JSON bytes, exactly as stored
    nonce: bytes
    ciphertext_with_tag: bytes


def build_header(metadata_bytes: bytes) -> bytes:
    """Return magic + length + metadata. Used both to pack and as AAD."""
    if len(metadata_bytes) > MAX_METADATA_SIZE:
        raise ContainerFormatError("Metadata too large")
    return MAGIC + struct.pack(LENGTH_FORMAT, len(metadata_bytes)) + metadata_bytes


def pack(metadata_bytes: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    """Concatenate all parts into a single container."""
    if len(nonce) != NONCE_SIZE_BYTES:
        raise ContainerFormatError("Invalid nonce length")
    return build_header(metadata_bytes) + nonce + ciphertext_with_tag


def unpack(data: bytes) -> Container:
    """Split a container into its parts using fixed offsets.

    This only checks the *structure*. Nothing extracted here is trusted
    until the AEAD tag has been verified.
    """
    min_size = len(MAGIC) + LENGTH_SIZE + NONCE_SIZE_BYTES + TAG_SIZE_BYTES
    if len(data) < min_size:
        raise ContainerFormatError("Container too short")

    if data[:len(MAGIC)] != MAGIC:
        raise ContainerFormatError("Not a vault container (bad magic)")

    offset = len(MAGIC)
    (meta_len,) = struct.unpack(LENGTH_FORMAT, data[offset:offset + LENGTH_SIZE])
    offset += LENGTH_SIZE

    if meta_len > MAX_METADATA_SIZE:
        raise ContainerFormatError("Declared metadata length too large")
    if len(data) < offset + meta_len + NONCE_SIZE_BYTES + TAG_SIZE_BYTES:
        raise ContainerFormatError("Container truncated")

    metadata_bytes = data[offset:offset + meta_len]
    offset += meta_len
    header = data[:offset]

    nonce = data[offset:offset + NONCE_SIZE_BYTES]
    offset += NONCE_SIZE_BYTES

    return Container(
        header=header,
        metadata_bytes=metadata_bytes,
        nonce=nonce,
        ciphertext_with_tag=data[offset:],
    )
