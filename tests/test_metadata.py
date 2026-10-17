"""Tests for metadata construction and canonicalization."""
import pytest

from vault import crypto_core
from vault.exceptions import ContainerFormatError


def test_metadata_contains_required_fields():
    meta = crypto_core.build_metadata("report.pdf")
    assert crypto_core.REQUIRED_METADATA_FIELDS <= meta.keys()
    assert meta["algorithm"] == "AES-256-GCM"
    assert meta["key_bits"] == 256


def test_only_base_name_is_stored():
    meta = crypto_core.build_metadata("/home/alice/secret/report.pdf")
    assert meta["original_name"] == "report.pdf"


def test_canonicalization_is_deterministic():
    a = {"b": 1, "a": 2, "c": "x"}
    b = {"c": "x", "a": 2, "b": 1}
    assert crypto_core.canonicalize_metadata(a) == crypto_core.canonicalize_metadata(b)


def test_canonical_form_has_no_spaces():
    out = crypto_core.canonicalize_metadata({"a": 1, "b": 2})
    assert out == b'{"a":1,"b":2}'


def test_parse_roundtrip():
    meta = crypto_core.build_metadata("report.pdf", timestamp=1_700_000_000)
    raw = crypto_core.canonicalize_metadata(meta)
    assert crypto_core.parse_metadata(raw) == meta


def test_parse_rejects_garbage():
    with pytest.raises(ContainerFormatError):
        crypto_core.parse_metadata(b"\xff\xfe not json")


def test_parse_rejects_unknown_algorithm():
    meta = crypto_core.build_metadata("a.pdf")
    meta["algorithm"] = "DES"
    with pytest.raises(ContainerFormatError):
        crypto_core.parse_metadata(crypto_core.canonicalize_metadata(meta))
