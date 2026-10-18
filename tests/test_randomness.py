"""Tests for secure key and nonce generation."""
from vault import crypto_core


def test_key_has_256_bits():
    assert len(crypto_core.generate_key()) == 32


def test_nonce_has_96_bits():
    assert len(crypto_core.generate_nonce()) == 12


def test_keys_are_fresh():
    keys = {crypto_core.generate_key() for _ in range(1000)}
    assert len(keys) == 1000


def test_nonces_are_unique():
    nonces = {crypto_core.generate_nonce() for _ in range(10_000)}
    assert len(nonces) == 10_000
