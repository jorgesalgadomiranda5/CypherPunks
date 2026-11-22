"""D6 required tests: a private key is usable only with its password."""
import base64
import os
import json

import pytest
from cryptography.hazmat.primitives import serialization

from vault import hybrid, keys, keystore
from vault.exceptions import KeyManagementError

PASSWORD = b"correct horse battery staple"
PLAINTEXT = b"%PDF-1.7\n" + b"llave protegida " * 2000


@pytest.fixture(scope="module")
def bob():
    return keys.generate_keypair()


@pytest.fixture
def bob_keystore(tmp_path, bob):
    path = tmp_path / "bob.key.json"
    keystore.save_keystore(bob, "wrap", path, PASSWORD)
    return path


@pytest.fixture
def shared(bob):
    return hybrid.encrypt_for_recipients(PLAINTEXT, [bob.public_key()])


# Required test 1
def test_correct_password_grants_access(bob_keystore, bob, shared):
    unlocked = keystore.load_keystore(bob_keystore, PASSWORD, "wrap")
    assert keys.key_id(unlocked.public_key()) == keys.key_id(bob.public_key())
    assert hybrid._decrypt_unsigned(shared, unlocked) == PLAINTEXT


# Required test 2
def test_wrong_password_denied(bob_keystore):
    with pytest.raises(KeyManagementError):
        keystore.load_keystore(bob_keystore, b"correct horse battery stapler", "wrap")


def _flip(value: str) -> str:
    """Change one bit of a Base64 field."""
    data = bytearray(base64.b64decode(value))
    data[0] ^= 0x01
    return base64.b64encode(bytes(data)).decode("ascii")


# Required test 3
@pytest.mark.parametrize("mutate", [
    lambda store: store.update(
        encrypted_private_key=_flip(store["encrypted_private_key"])
    ),
    lambda store: store.update(salt=_flip(store["salt"])),
    lambda store: store["kdf_parameters"].update(n=2**14),
    lambda store: store["metadata"].update(key_id="0" * 64),
], ids=["encrypted_key", "salt", "kdf_parameters", "metadata"])
def test_modified_keystore_fails(bob_keystore, mutate):
    store = json.loads(bob_keystore.read_text(encoding="utf-8"))
    mutate(store)
    bob_keystore.write_text(json.dumps(store), encoding="utf-8")

    with pytest.raises(KeyManagementError):
        keystore.load_keystore(bob_keystore, PASSWORD, "wrap")


# Required test 4
def test_backup_then_restore_works(tmp_path, bob_keystore, shared):
    backup = keystore.backup_keystore(bob_keystore, tmp_path / "backups")
    assert backup.read_bytes() == bob_keystore.read_bytes()  # the copy stays encrypted

    bob_keystore.unlink()  # the original is lost
    keystore.restore_keystore(backup, bob_keystore, PASSWORD, "wrap")
    restored = keystore.load_keystore(bob_keystore, PASSWORD, "wrap")
    assert hybrid._decrypt_unsigned(shared, restored) == PLAINTEXT


# Required test 5
def test_stolen_keystore_alone_cannot_decrypt(bob_keystore, bob):
    """The attacker copies the keystore but does not know the password."""
    stolen = json.loads(bob_keystore.read_text(encoding="utf-8"))
    plain_key = bob.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    assert plain_key not in base64.b64decode(stolen["encrypted_private_key"])

    for guess in (b"", b"password", b"123456789012", b"correct horse battery"):
        with pytest.raises(KeyManagementError):
            keystore.load_keystore(bob_keystore, guess, "wrap")


def test_rsa_private_key_rejected_for_wrap(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa

    legacy = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(KeyManagementError):
        keystore.save_keystore(legacy, "wrap", tmp_path / "old.key.json", PASSWORD)
    assert not (tmp_path / "old.key.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_backup_and_restore_are_owner_only(tmp_path, bob_keystore):
    backup = keystore.backup_keystore(bob_keystore, tmp_path / "backups")
    restored = tmp_path / "restored" / "bob.key.json"
    keystore.restore_keystore(backup, restored, PASSWORD, "wrap")
    for path in (backup, restored):
        assert (path.stat().st_mode & 0o777) == 0o600


def test_restore_refuses_existing_target(tmp_path, bob_keystore):
    backup = keystore.backup_keystore(bob_keystore, tmp_path / "backups")
    before = bob_keystore.read_bytes()
    with pytest.raises(KeyManagementError):
        keystore.restore_keystore(backup, bob_keystore, PASSWORD, "wrap")
    assert bob_keystore.read_bytes() == before
