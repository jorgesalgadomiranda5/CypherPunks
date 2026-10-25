"""D3 tests: hybrid encryption, multi-recipient sharing and tampering."""
import pytest

from vault import keys, keywrap
from vault.exceptions import KeyManagementError, VaultError

PLAINTEXT = b"%PDF-1.7\n" + b"contenido confidencial " * 2000


@pytest.fixture(scope="module")
def alice():
    return keys.generate_keypair()


@pytest.fixture(scope="module")
def bob():
    return keys.generate_keypair()


@pytest.fixture(scope="module")
def eve():
    return keys.generate_keypair()

# --- Building blocks: keys and key wrapping ---------------------------------


def test_key_id_is_deterministic(alice):
    # The same public key must always have the same ID.
    pem = keys.public_key_to_pem(alice.public_key())

    assert keys.key_id(keys.public_key_from_pem(pem)) == keys.key_id(alice.public_key())
    assert len(keys.key_id(alice.public_key())) == 64


def test_private_key_roundtrip_with_passphrase(tmp_path, alice):
    # Save and reload a private key using a password.
    path = tmp_path / "alice.key.pem"
    keys.save_private_key(alice, path, b"correct horse")
    loaded = keys.load_private_key(path, b"correct horse")

    assert keys.key_id(loaded.public_key()) == keys.key_id(alice.public_key())

    # A wrong password must be rejected.
    with pytest.raises(KeyManagementError):
        keys.load_private_key(path, b"wrong")


def test_weak_rsa_key_rejected():
    with pytest.raises(KeyManagementError):
        keys.generate_keypair(2048)


def test_wrap_only_accepts_32_byte_keys(alice):
    with pytest.raises(VaultError):
        keywrap.wrap_file_key(alice.public_key(), PLAINTEXT[:200])

