"""Tests for the binary container format."""
import struct
import pytest

from vault import container
from vault.exceptions import ContainerFormatError

META = b'{"algorithm":"AES-256-GCM"}'
NONCE = b"\x01" * 12
CT = b"\xaa" * 40 + b"\xbb" * 16      # fake ciphertext + 16-byte tag


def test_pack_then_unpack_returns_same_parts():
    data = container.pack(META, NONCE, CT)
    c = container.unpack(data)
    assert c.metadata_bytes == META
    assert c.nonce == NONCE
    assert c.ciphertext_with_tag == CT


def test_layout_starts_with_magic_and_length():
    data = container.pack(META, NONCE, CT)
    assert data[:4] == b"SDV1"
    assert struct.unpack(">I", data[4:8])[0] == len(META)


def test_header_is_magic_length_metadata():
    data = container.pack(META, NONCE, CT)
    c = container.unpack(data)
    assert c.header == container.build_header(META)
    assert c.header == data[:8 + len(META)]


def test_bad_magic_rejected():
    data = b"XXXX" + container.pack(META, NONCE, CT)[4:]
    with pytest.raises(ContainerFormatError):
        container.unpack(data)


def test_too_short_rejected():
    with pytest.raises(ContainerFormatError):
        container.unpack(b"SDV1")


def test_truncated_rejected():
    data = container.pack(META, NONCE, CT)
    with pytest.raises(ContainerFormatError):
        container.unpack(data[:8 + len(META) + 5])


def test_huge_declared_length_rejected():
    data = b"SDV1" + struct.pack(">I", 2**32 - 1) + b"\x00" * 64
    with pytest.raises(ContainerFormatError):
        container.unpack(data)


def test_invalid_nonce_length_rejected_on_pack():
    with pytest.raises(ContainerFormatError):
        container.pack(META, b"\x00" * 8, CT)
