"""D3 tests: hybrid encryption, multi-recipient sharing and tampering."""
import json

import pytest

from vault import container_v2, crypto_core, hybrid, keys, keywrap
from vault.exceptions import IntegrityError, KeyManagementError, VaultError

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


# --- Hybrid encryption ------------------------------------------------------
@pytest.fixture
def shared(alice, bob):
    return hybrid.encrypt_for_recipients(PLAINTEXT, [alice.public_key(), bob.public_key()])


def _rewrite_header(blob: bytes, mutate) -> bytes:
    """Attacker helper: edit the header JSON and re-pack it (keeps nonce, ciphertext and tag)."""
    parts = container_v2.unpack(blob)
    header = json.loads(parts.header_json)
    mutate(header)
    new_json = crypto_core.canonicalize_metadata(header)
    return container_v2.pack(new_json, parts.nonce, parts.ciphertext_with_tag)


# Required test 1
def test_two_recipients_can_both_decrypt(shared, alice, bob):
    assert hybrid.decrypt_as_recipient(shared, alice) == PLAINTEXT
    assert hybrid.decrypt_as_recipient(shared, bob) == PLAINTEXT


# Required test 2
def test_unauthorized_user_cannot_decrypt(shared, eve):
    with pytest.raises(IntegrityError):
        hybrid.decrypt_as_recipient(shared, eve)


# Required test 5
def test_removing_recipient_entry_breaks_access(shared, alice, bob):
    bob_kid = keys.key_id(bob.public_key())

    def drop_bob(header):
        header["recipients"] = [r for r in header["recipients"] if r["kid"] != bob_kid]

    tampered = _rewrite_header(shared, drop_bob)
    with pytest.raises(IntegrityError):
        hybrid.decrypt_as_recipient(tampered, bob)
    with pytest.raises(IntegrityError):  # AAD changed, so Alice fails too
        hybrid.decrypt_as_recipient(tampered, alice)
