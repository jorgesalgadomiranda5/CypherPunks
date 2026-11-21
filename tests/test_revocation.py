
"""D6 tests: key revocation, rotation and keystore error handling."""

import json

import pytest

from vault import cli, crypto_core, keys, keystore, keywrap, revocation
from vault.exceptions import KeyManagementError


PASSWORD = "correct horse battery"
PLAINTEXT = b"Confidential document for Bob."


@pytest.fixture
def users(tmp_path, monkeypatch):
    """Create Alice and Bob with password-protected keystores."""
    monkeypatch.setattr(
        cli.getpass,
        "getpass",
        lambda prompt="": PASSWORD,
    )

    for name in ("alice", "bob"):
        assert cli.main(["keygen", name, "-d", str(tmp_path)]) == 0

    return tmp_path


def test_share_to_revoked_recipient_fails(users):
    """A revoked recipient must not receive new encrypted packages."""
    folder = users

    bob_public = folder / "bob.pub.pem"
    alice_signing = folder / "alice.sign.key.json"

    document = folder / "document.txt"
    document.write_bytes(PLAINTEXT)

    output = folder / "document.sdv"

    # Revoke Bob's public key.
    assert cli.main([
        "revoke",
        str(bob_public),
        "-d",
        str(folder),
    ]) == 0

    # Alice must not be able to share a new file with Bob.
    result = cli.main([
        "share",
        str(document),
        "-r",
        str(bob_public),
        "-s",
        str(alice_signing),
        "-o",
        str(output),
    ])

    assert result == 1
    assert not output.exists()

    # Confirm Bob's key ID is in the revocation list.
    revoked = revocation.load(revocation.path_for(folder))
    bob_key = keys.load_public_key(bob_public)

    assert keys.key_id(bob_key) in revoked


def test_open_from_revoked_sender_never_unwraps(users, monkeypatch):
    """A revoked sender is rejected before private-key recovery."""
    folder = users

    document = folder / "signed_document.txt"
    document.write_bytes(PLAINTEXT)

    package = folder / "signed_document.sdv"
    sender = folder / "alice.sign.pub.pem"
    output = folder / "recovered.txt"

    # Alice shares the document with Bob while her signing key is valid.
    assert cli.main([
        "share", str(document),
        "-r", str(folder / "bob.pub.pem"),
        "-s", str(folder / "alice.sign.key.json"),
        "-o", str(package),
    ]) == 0

    # Bob revokes Alice's signing key.
    assert cli.main([
        "revoke", str(sender),
        "-d", str(folder),
    ]) == 0

    # Neither operation should be reached for a revoked sender.
    def forbidden(*args, **kwargs):
        pytest.fail("Decryption was attempted for a revoked sender")

    monkeypatch.setattr(keywrap, "unwrap_file_key", forbidden)
    monkeypatch.setattr(crypto_core, "decrypt", forbidden)

    result = cli.main([
        "open", str(package),
        "-i", str(folder / "bob.key.json"),
        "--sender", str(sender),
        "-o", str(output),
    ])

    assert result == 1
    assert not output.exists()


def test_planned_rotation_keeps_files_readable(users):
    """Rotate Bob's keys without losing access to an important file."""
    folder = users
    source = folder / "important.txt"
    source.write_bytes(PLAINTEXT)

    old_package = folder / "old.sdv"
    assert cli.main([
        "share", str(source),
        "-r", str(folder / "bob.pub.pem"),
        "-s", str(folder / "alice.sign.key.json"),
        "-o", str(old_package),
    ]) == 0

    # Generate Bob's replacement keys.
    assert cli.main([
        "keygen", "bob-new", "-d", str(folder)
    ]) == 0

    # Recover the file before revoking the old keys.
    recovered = folder / "recovered.txt"
    assert cli.main([
        "open", str(old_package),
        "-i", str(folder / "bob.key.json"),
        "--sender", str(folder / "alice.sign.pub.pem"),
        "-o", str(recovered),
    ]) == 0
    assert recovered.read_bytes() == PLAINTEXT

    # Share the recovered file with Bob's new public key.
    new_package = folder / "new.sdv"
    assert cli.main([
        "share", str(recovered),
        "-r", str(folder / "bob-new.pub.pem"),
        "-s", str(folder / "alice.sign.key.json"),
        "-o", str(new_package),
    ]) == 0

    # Revoke Bob's old wrapping and signing keys.
    for filename in ("bob.pub.pem", "bob.sign.pub.pem"):
        assert cli.main([
            "revoke", str(folder / filename),
            "-d", str(folder),
        ]) == 0

    # The new key can still recover the document.
    final_output = folder / "final.txt"
    assert cli.main([
        "open", str(new_package),
        "-i", str(folder / "bob-new.key.json"),
        "--sender", str(folder / "alice.sign.pub.pem"),
        "-o", str(final_output),
    ]) == 0
    assert final_output.read_bytes() == PLAINTEXT

    # Sharing again with Bob's old public key is forbidden.
    denied = folder / "denied.sdv"
    assert cli.main([
        "share", str(source),
        "-r", str(folder / "bob.pub.pem"),
        "-s", str(folder / "alice.sign.key.json"),
        "-o", str(denied),
    ]) == 1
    assert not denied.exists()


def test_revoke_accepts_key_id_and_rejects_garbage(users):
    """A valid key ID is accepted once; invalid IDs are rejected."""
    folder = users
    public_key = keys.load_public_key(folder / "bob.pub.pem")
    kid = keys.key_id(public_key)
    revoked_path = revocation.path_for(folder)

    assert cli.main(["revoke", kid, "-d", str(folder)]) == 0
    assert cli.main(["revoke", kid, "-d", str(folder)]) == 0

    assert revocation.load(revoked_path) == {kid}
    assert revoked_path.read_text(encoding="utf-8").splitlines() == [kid]

    assert cli.main([
        "revoke", "not-a-valid-key-id", "-d", str(folder)
    ]) == 1

    assert revocation.load(revoked_path) == {kid}


def test_damaged_revocation_list_is_an_error(users):
    """A damaged revocation list must not be treated as empty."""
    folder = users
    path = revocation.path_for(folder)
    path.write_text("this-is-not-a-valid-key-id\n", encoding="utf-8")

    with pytest.raises(KeyManagementError):
        revocation.load(path)

    source = folder / "document.txt"
    source.write_bytes(PLAINTEXT)
    output = folder / "denied.sdv"

    assert cli.main([
        "share", str(source),
        "-r", str(folder / "bob.pub.pem"),
        "-s", str(folder / "alice.sign.key.json"),
        "-o", str(output),
    ]) == 1
    assert not output.exists()


@pytest.mark.parametrize(
    "damage",
    [
        "broken_json",
        "missing_salt",
        "invalid_base64",
        "json_list",
        "invalid_utf8",
    ],
)
def test_malformed_keystore_gives_key_management_error(users, damage):
    """Malformed keystores must raise our controlled exception."""
    folder = users
    original = folder / "bob.key.json"
    damaged = folder / "damaged.key.json"

    data = original.read_bytes()

    if damage == "broken_json":
        data = b'{"format":'

    elif damage == "invalid_utf8":
        data = b"\xff\xfe\xfa"

    elif damage == "json_list":
        data = b'["not", "a", "keystore"]'

    else:
        store = json.loads(data.decode("utf-8"))

        if damage == "missing_salt":
            del store["salt"]

        elif damage == "invalid_base64":
            store["salt"] = "not-valid-base64!!!"

        data = json.dumps(store).encode("utf-8")

    damaged.write_bytes(data)

    with pytest.raises(KeyManagementError):
        keystore.load_keystore(
            damaged, PASSWORD.encode("utf-8"), "wrap"
        )


def test_invalid_private_key_encoding(users, monkeypatch):
    """Invalid DER must produce KeyManagementError, not ValueError."""
    folder = users
    path = folder / "bob.key.json"

    def invalid_der(*args, **kwargs):
        raise ValueError("Invalid DER private key")

    monkeypatch.setattr(
        keystore.serialization,
        "load_der_private_key",
        invalid_der,
    )

    with pytest.raises(
        KeyManagementError,
        match="Invalid private key encoding",
    ):
        keystore.load_keystore(
            path, PASSWORD.encode("utf-8"), "wrap"
        )

