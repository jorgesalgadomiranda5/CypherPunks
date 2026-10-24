"""Multi-recipient container format (.sdv, version 2) for D3.

Layout (all integers big-endian), same shape as SDV1 so both readers stay simple:

    +-------------+------------------+---------------+------------+--------------------------+
    | magic (4 B) | header_len (4 B) | header (JSON) | nonce (12) | ciphertext || tag (16 B) |
    |   "SDV2"    |   uint32 BE      |               |            |                          |
    +-------------+------------------+---------------+------------+--------------------------+
    |<------------ AAD (magic + length + header) --->|

The header carries the format version, algorithm identifiers, minimal metadata
and the recipient list. Because it is authenticated as AAD, adding, removing
or swapping recipients makes the tag check fail for everyone.
"""
import base64
import json
import re
import struct
from dataclasses import dataclass, field

from vault.crypto_core import NONCE_SIZE_BYTES, TAG_SIZE_BYTES, canonicalize_metadata
from vault.exceptions import ContainerFormatError

MAGIC = b"SDV2"
FORMAT_VERSION = "2.0"
LENGTH_FORMAT = ">I"
LENGTH_SIZE = struct.calcsize(LENGTH_FORMAT)
MAX_HEADER_SIZE = 64 * 1024

MAX_RECIPIENTS = 64  # Added for step 5!

ALGORITHMS = {"aead": "AES-256-GCM", "key_wrap": "RSA-OAEP-SHA256", "key_id": "SHA256-SPKI"}

_KID_PATTERN = re.compile(r"^[0-9a-f]{64}$")  # Added for step 5!

@dataclass(frozen=True)
class RecipientEntry:
    kid: str
    encrypted_key: bytes


@dataclass
class Header:
    recipients: list[RecipientEntry]
    metadata: dict = field(default_factory=dict)
    algorithms: dict = field(default_factory=lambda: dict(ALGORITHMS))
    version: str = FORMAT_VERSION

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "algorithms": self.algorithms,
            "metadata": self.metadata,
            "recipients": [
                {"kid": r.kid, "encrypted_key": _b64e(r.encrypted_key)}
                for r in sorted(self.recipients, key=lambda r: r.kid)
            ],
        }


@dataclass(frozen=True)
class ContainerV2:
    aad: bytes                # magic + header_len + header_json
    header_json: bytes        # raw JSON bytes, exactly as stored
    header: Header
    nonce: bytes
    ciphertext_with_tag: bytes


def serialize_header(header: Header) -> bytes:
    """Validate and serialize canonically (same rules as D2 metadata)."""
    _validate_header(header)
    return canonicalize_metadata(header.to_dict())


def build_aad(header_json: bytes) -> bytes:
    if len(header_json) > MAX_HEADER_SIZE:
        raise ContainerFormatError("Header too large")
    return MAGIC + struct.pack(LENGTH_FORMAT, len(header_json)) + header_json


def pack(header_json: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    if len(nonce) != NONCE_SIZE_BYTES:
        raise ContainerFormatError("Invalid nonce length")
    return build_aad(header_json) + nonce + ciphertext_with_tag


def unpack(data: bytes) -> ContainerV2:
    """Split and validate the structure. Nothing here is trusted until the tag verifies."""
    min_size = len(MAGIC) + LENGTH_SIZE + NONCE_SIZE_BYTES + TAG_SIZE_BYTES
    if len(data) < min_size:
        raise ContainerFormatError("Container too short")
    if data[:len(MAGIC)] != MAGIC:
        raise ContainerFormatError("Not a shared vault container (bad magic)")

    offset = len(MAGIC)
    (header_len,) = struct.unpack(LENGTH_FORMAT, data[offset:offset + LENGTH_SIZE])
    offset += LENGTH_SIZE
    if header_len == 0 or header_len > MAX_HEADER_SIZE:
        raise ContainerFormatError("Declared header length out of range")
    if len(data) < offset + header_len + NONCE_SIZE_BYTES + TAG_SIZE_BYTES:
        raise ContainerFormatError("Container truncated")

    header_json = data[offset:offset + header_len]
    offset += header_len
    aad = data[:offset]
    nonce = data[offset:offset + NONCE_SIZE_BYTES]
    offset += NONCE_SIZE_BYTES

    try:
        header = _header_from_dict(json.loads(header_json.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ContainerFormatError("Malformed header") from exc

    return ContainerV2(aad=aad, header_json=header_json, header=header,
                       nonce=nonce, ciphertext_with_tag=data[offset:])


def find_recipient(header: Header, kid: str) -> RecipientEntry | None:
    matches = [r for r in header.recipients if r.kid == kid]
    return matches[0] if len(matches) == 1 else None


def _header_from_dict(raw: dict) -> Header:
    recipients = []
    for item in raw["recipients"]:
        recipients.append(RecipientEntry(item["kid"], _b64d(item["encrypted_key"])))
    header = Header(recipients=recipients, metadata=raw["metadata"],
                    algorithms=raw["algorithms"], version=raw["version"])
    _validate_header(header)
    return header


def _validate_header(header: Header) -> None:
    if header.version != FORMAT_VERSION:
        raise ContainerFormatError("Unsupported container version")
    if header.algorithms != ALGORITHMS:
        raise ContainerFormatError("Unsupported algorithm identifiers")
    if not isinstance(header.metadata, dict):
        raise ContainerFormatError("Metadata must be a JSON object")

        # Check the number of recipients.
    if not 1 <= len(header.recipients) <= MAX_RECIPIENTS:
        raise ContainerFormatError("Recipient count out of range")

    # Reject repeated key IDs.
    kids = [r.kid for r in header.recipients]
    if len(set(kids)) != len(kids):
        raise ContainerFormatError("Duplicate recipient key ID")

    # Check the format of each key ID.
    for kid in kids:
        if not isinstance(kid, str) or not _KID_PATTERN.match(kid):
            raise ContainerFormatError("Invalid key ID")


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)
