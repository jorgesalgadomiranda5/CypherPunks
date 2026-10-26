"""D3 tests: hybrid encryption, multi-recipient sharing and tampering."""
import json

import pytest

from vault import cli, container_v2, crypto_core, hybrid, keys, keywrap
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

# Required test 3
def test_tampered_recipient_list_fails(shared, bob, eve):
    eve_kid = keys.key_id(eve.public_key())
    eve_wrap = keywrap.wrap_file_key(eve.public_key(), b"\x00" * 32)

    def add_eve(header):
        header["recipients"].append({"kid": eve_kid, "encrypted_key": container_v2._b64e(eve_wrap)})
        header["recipients"].sort(key=lambda r: r["kid"])

    tampered = _rewrite_header(shared, add_eve)
    for key in (bob, eve):
        with pytest.raises(IntegrityError):
            hybrid.decrypt_as_recipient(tampered, key)


def test_swapped_identities_fail(shared, alice, bob):
    """Swap the encrypted_key values between the Alice and Bob entries."""
    def swap(header):
        a, b = header["recipients"]
        a["encrypted_key"], b["encrypted_key"] = b["encrypted_key"], a["encrypted_key"]

    tampered = _rewrite_header(shared, swap)
    for key in (alice, bob):
        with pytest.raises(IntegrityError):
            hybrid.decrypt_as_recipient(tampered, key)

# Required test 4
def test_wrong_private_key_fails(alice, bob, eve):
    blob = hybrid.encrypt_for_recipients(PLAINTEXT, [alice.public_key(), bob.public_key()])
    parts = container_v2.unpack(blob)
    entry = container_v2.find_recipient(parts.header, keys.key_id(bob.public_key()))
    with pytest.raises(IntegrityError):
        keywrap.unwrap_file_key(eve, entry.encrypted_key)


def test_wrong_public_key_at_encryption_locks_out_intended_recipient(alice, eve):
    """If the sender uses the wrong public key, the intended recipient cannot open the file."""
    blob = hybrid.encrypt_for_recipients(PLAINTEXT, [eve.public_key()])
    with pytest.raises(IntegrityError):
        hybrid.decrypt_as_recipient(blob, alice)

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
# --- Extra attack tests -----------------------------------------------------
def test_each_recipient_gets_different_wrapped_key(shared):
    wraps = [r.encrypted_key for r in container_v2.unpack(shared).header.recipients]
    assert len(set(wraps)) == len(wraps)


def test_file_is_encrypted_once(shared):
    assert len(shared) < len(PLAINTEXT) + 4096  # one ciphertext, not one per recipient


def test_algorithm_downgrade_fails(shared, alice):
    def downgrade(header):
        header["algorithms"]["key_wrap"] = "RSA-PKCS1v15"

    tampered = _rewrite_header(shared, downgrade)
    with pytest.raises(IntegrityError):
        hybrid.decrypt_as_recipient(tampered, alice)


def test_ciphertext_bitflip_fails(shared, alice):
    tampered = bytearray(shared)
    tampered[-20] ^= 0x01
    with pytest.raises(IntegrityError):
        hybrid.decrypt_as_recipient(bytes(tampered), alice)


def test_truncated_container_fails(shared, alice):
    with pytest.raises(IntegrityError):
        hybrid.decrypt_as_recipient(shared[:50], alice)


def test_duplicate_recipient_rejected(alice):
    with pytest.raises(VaultError):
        hybrid.encrypt_for_recipients(PLAINTEXT, [alice.public_key(), alice.public_key()])


def test_cli_share_open_and_recipients(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "pass-phrase")
    for name in ("alice", "bob", "eve"):
        assert cli.main(["keygen", name, "-d", str(tmp_path)]) == 0
    src = tmp_path / "report.pdf"
    src.write_bytes(PLAINTEXT)
    sdv = tmp_path / "report.pdf.sdv"

    assert cli.main(["share", str(src), "-r", str(tmp_path / "alice.pub.pem"),
                     "-r", str(tmp_path / "bob.pub.pem")]) == 0
    capsys.readouterr()
    assert cli.main(["recipients", str(sdv)]) == 0
    assert len(capsys.readouterr().out.split()) == 2

    out = tmp_path / "bob.pdf"
    assert cli.main(["open", str(sdv), "-i", str(tmp_path / "bob.key.pem"), "-o", str(out)]) == 0
    assert out.read_bytes() == PLAINTEXT

    denied = tmp_path / "eve.pdf"
    assert cli.main(["open", str(sdv), "-i", str(tmp_path / "eve.key.pem"), "-o", str(denied)]) == 2
    assert not denied.exists()
