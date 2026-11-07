"""D5 required tests: the signature is always verified before decrypting."""
import json
import pytest
from vault import container_v2, crypto_core, hybrid, keys, keywrap, signatures
from vault.exceptions import IntegrityError

PLAINTEXT = b"%PDF-1.7\n" + b"contenido firmado " * 2000
SIGNATURE_SIZE = signatures.SIGNATURE_SIZE_BYTES

@pytest.fixture(scope="module")
def alice():
    return keys.generate_signing_keypair()

@pytest.fixture(scope="module")
def eve():
    return keys.generate_signing_keypair()

@pytest.fixture(scope="module")
def bob():
    return keys.generate_keypair()

@pytest.fixture
def signed(alice, bob):
    return hybrid.encrypt_and_sign(PLAINTEXT, [bob.public_key()], alice)

@pytest.fixture
def no_decryption(monkeypatch):
    """Fail if a rejected package reaches the secret-key steps.
    Without this, the AEAD tag could be what rejects a tampered package and the
    test would pass even with signature verification removed.
    """
    def must_not_run(*args, **kwargs):
        raise AssertionError("used a secret key before verifying the signature")
    monkeypatch.setattr(keywrap, "unwrap_file_key", must_not_run)
    monkeypatch.setattr(crypto_core, "decrypt", must_not_run)

# Required test A
def test_valid_signature_accepted(signed, alice, bob):
    assert hybrid.verify_and_decrypt(signed, bob, alice.public_key()) == PLAINTEXT


# Required test B
def test_modified_ciphertext_rejected(signed, alice, bob, no_decryption):
    tampered = bytearray(signed)
    tampered[-SIGNATURE_SIZE - 40] ^= 0x01  # inside the ciphertext
    with pytest.raises(IntegrityError):
        hybrid.verify_and_decrypt(bytes(tampered), bob, alice.public_key())

# Required test D
def test_wrong_public_key_rejected(signed, eve, bob, no_decryption):
    with pytest.raises(IntegrityError):
        hybrid.verify_and_decrypt(signed, bob, eve.public_key())

