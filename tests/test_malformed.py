"""D5 follow-up: malformed signed packages never reach key recovery.

Family A breaks the signed package itself (truncation, empty, trailing bytes):
the length check or the signature stops it.
Family B corrupts the container and signs it again with the legitimate key,
as a buggy or malicious sender would: the signature passes, so the parser
has to stop it.
"""
import json
import struct

import pytest

from vault import container_v2, crypto_core, hybrid, keys, keywrap, signatures
from vault.exceptions import ContainerFormatError, IntegrityError

PLAINTEXT = b"%PDF-1.7\n" + b"paquete malformado " * 500
SIG = signatures.SIGNATURE_SIZE_BYTES


@pytest.fixture(scope="module")
def alice():
    return keys.generate_signing_keypair()


@pytest.fixture(scope="module")
def bob():
    return keys.generate_keypair()


@pytest.fixture
def signed(alice, bob):
    return hybrid.encrypt_and_sign(PLAINTEXT, [bob.public_key()], alice)


@pytest.fixture(autouse=True)
def no_key_recovery(monkeypatch):
    """Same trick as D5: fail if a malformed package reaches a secret-key step."""
    def must_not_run(*args, **kwargs):
        raise AssertionError("a malformed package reached key recovery")
    monkeypatch.setattr(keywrap, "unwrap_file_key", must_not_run)
    monkeypatch.setattr(crypto_core, "decrypt", must_not_run)


# --- Family A: the signed package itself is broken ---------------------------
@pytest.mark.parametrize("mutate", [
    lambda d: d[:-1],
    lambda d: d[:-32],
    lambda d: d[:-63],
    lambda d: b"",
    lambda d: d[:10],
    lambda d: d + bytes(64),
], ids=["sig-minus-1", "sig-minus-32", "sig-minus-63", "empty", "ten-bytes", "trailing-64"])
def test_broken_signed_package(signed, alice, bob, mutate):
    with pytest.raises(IntegrityError):
        hybrid.verify_and_decrypt(mutate(signed), bob, alice.public_key())


# --- Family B: corrupt container, signed again --------------------------------
def _split(container: bytes):
    parts = container_v2.unpack(container)
    return json.loads(parts.header_json), parts.nonce + parts.ciphertext_with_tag


def _join(header: dict, rest: bytes, magic: bytes = container_v2.MAGIC, header_len: int | None = None) -> bytes:
    header_json = crypto_core.canonicalize_metadata(header)  # canonical, or the parser stops it first
    length = len(header_json) if header_len is None else header_len
    return magic + struct.pack(container_v2.LENGTH_FORMAT, length) + header_json + rest


def _bad_magic(c):
    h, r = _split(c)
    return _join(h, r, magic=b"SDV2")


def _bad_json(c):
    h, r = _split(c)
    return _join(h, r)[:8] + b"#" + _join(h, r)[9:]


def _header_len_past_end(c):
    h, r = _split(c)
    return _join(h, r, header_len=len(c) * 2)


def _unknown_field(c):
    h, r = _split(c)
    h["unexpected"] = 1
    return _join(h, r)


def _short_wrapped_key(c):
    h, r = _split(c)
    h["recipients"][0]["encrypted_key"] = h["recipients"][0]["encrypted_key"][:-4]  # 90 B
    return _join(h, r)


@pytest.mark.parametrize("edit", [_bad_magic, _bad_json, _header_len_past_end,
                                  _unknown_field, _short_wrapped_key])
def test_corrupt_container_signed_again(signed, alice, bob, edit):
    container = edit(signed[:-SIG])
    resigned = container + signatures.sign(alice, container)
    with pytest.raises(ContainerFormatError):
        hybrid.verify_and_decrypt(resigned, bob, alice.public_key())
