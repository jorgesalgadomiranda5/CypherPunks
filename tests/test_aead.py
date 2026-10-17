"""Tests for AES-256-GCM encryption, decryption and tamper detection."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault import crypto_core
from vault.exceptions import IntegrityError, VaultError

PLAINTEXT = b"%PDF-1.7 confidential contents of the document" * 20
AAD = crypto_core.canonicalize_metadata(crypto_core.build_metadata("doc.pdf"))


def flip_byte(data: bytes, index: int) -> bytes:
    """Return a copy of data with one byte changed."""
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


@pytest.fixture
def encrypted():
    key = crypto_core.generate_key()
    nonce, ct = crypto_core.encrypt(key, PLAINTEXT, AAD)
    return key, nonce, ct


# Required: encrypt -> decrypt returns identical data
def test_roundtrip(encrypted):
    key, nonce, ct = encrypted
    assert crypto_core.decrypt(key, nonce, ct, AAD) == PLAINTEXT


def test_roundtrip_empty_file():
    key = crypto_core.generate_key()
    nonce, ct = crypto_core.encrypt(key, b"", AAD)
    assert crypto_core.decrypt(key, nonce, ct, AAD) == b""


def test_ciphertext_includes_16_byte_tag(encrypted):
    _, _, ct = encrypted
    assert len(ct) == len(PLAINTEXT) + 16


# Required: wrong key fails
def test_wrong_key_fails(encrypted):
    _, nonce, ct = encrypted
    with pytest.raises(IntegrityError):
        crypto_core.decrypt(crypto_core.generate_key(), nonce, ct, AAD)


def test_short_key_rejected():
    with pytest.raises(VaultError):
        crypto_core.encrypt(b"too short", PLAINTEXT, AAD)


# Required: modified ciphertext fails
@pytest.mark.parametrize("index", [0, 10, -17])
def test_modified_ciphertext_fails(encrypted, index):
    key, nonce, ct = encrypted
    with pytest.raises(IntegrityError):
        crypto_core.decrypt(key, nonce, flip_byte(ct, index), AAD)


def test_modified_tag_fails(encrypted):
    key, nonce, ct = encrypted
    with pytest.raises(IntegrityError):
        crypto_core.decrypt(key, nonce, flip_byte(ct, -1), AAD)


def test_truncated_ciphertext_fails(encrypted):
    key, nonce, ct = encrypted
    with pytest.raises(IntegrityError):
        crypto_core.decrypt(key, nonce, ct[:-1], AAD)


def test_modified_nonce_fails(encrypted):
    key, nonce, ct = encrypted
    with pytest.raises(IntegrityError):
        crypto_core.decrypt(key, flip_byte(nonce, 0), ct, AAD)


# Required: modified metadata fails
def test_modified_metadata_fails(encrypted):
    key, nonce, ct = encrypted
    tampered = AAD.replace(b"doc.pdf", b"evil.pdf")
    with pytest.raises(IntegrityError):
        crypto_core.decrypt(key, nonce, ct, tampered)


# Required: multiple encryptions produce different ciphertexts
def test_same_input_gives_different_ciphertexts():
    key = crypto_core.generate_key()
    n1, c1 = crypto_core.encrypt(key, PLAINTEXT, AAD)
    n2, c2 = crypto_core.encrypt(key, PLAINTEXT, AAD)
    assert n1 != n2
    assert c1 != c2


def test_nonce_reuse_leaks_plaintext_xor():
    """Documents WHY nonce reuse is forbidden.

    GCM is a stream cipher (CTR mode) underneath: with the same key and
    nonce the keystream repeats, so C1 XOR C2 == P1 XOR P2. Anyone who
    knows one plaintext recovers the other. Our encrypt() never allows
    this because it always draws a new nonce; here we force it on purpose
    using the raw library.
    """
    key = crypto_core.generate_key()
    nonce = crypto_core.generate_nonce()
    p1 = b"Transfer 100 pesos to Bob"
    p2 = b"Transfer 999 pesos to Eve"
    c1 = AESGCM(key).encrypt(nonce, p1, None)[:-16]
    c2 = AESGCM(key).encrypt(nonce, p2, None)[:-16]

    xor_c = bytes(a ^ b for a, b in zip(c1, c2))
    xor_p = bytes(a ^ b for a, b in zip(p1, p2))
    assert xor_c == xor_p
    recovered_p2 = bytes(a ^ b for a, b in zip(xor_c, p1))
    assert recovered_p2 == p2
