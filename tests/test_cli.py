"""Tests for the command-line interface."""
import os

import pytest

from vault import cli


def test_cli_roundtrip(tmp_path):
    src = tmp_path / "notes.pdf"
    src.write_bytes(b"%PDF-1.4 hello vault")
    sdv = tmp_path / "notes.sdv"
    key = tmp_path / "notes.key"

    assert cli.main(["encrypt", str(src), "-o", str(sdv), "-k", str(key)]) == 0
    assert sdv.exists() and key.exists()
    assert len(bytes.fromhex(key.read_text())) == 32

    out = tmp_path / "restored.pdf"
    assert cli.main(["decrypt", str(sdv), "-k", str(key), "-o", str(out)]) == 0
    assert out.read_bytes() == src.read_bytes()


def test_cli_tampered_container_returns_error(tmp_path, capsys):
    src = tmp_path / "a.pdf"
    src.write_bytes(b"%PDF-1.4 data" * 10)
    sdv, key = tmp_path / "a.sdv", tmp_path / "a.key"
    cli.main(["encrypt", str(src), "-o", str(sdv), "-k", str(key)])

    data = bytearray(sdv.read_bytes())
    data[-5] ^= 0xFF
    sdv.write_bytes(bytes(data))

    out = tmp_path / "out.pdf"
    assert cli.main(["decrypt", str(sdv), "-k", str(key), "-o", str(out)]) == 2
    assert "authentication failed" in capsys.readouterr().err
    assert not out.exists()


def test_cli_missing_input(tmp_path):
    assert cli.main(["encrypt", str(tmp_path / "nope.pdf")]) == 1


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_key_file_permissions(tmp_path):
    src = tmp_path / "p.pdf"
    src.write_bytes(b"x")
    key = tmp_path / "p.key"
    cli.main(["encrypt", str(src), "-k", str(key)])
    assert (key.stat().st_mode & 0o777) == 0o600


def test_cli_refuses_to_overwrite_without_force(tmp_path):
    src = tmp_path / "f.pdf"
    src.write_bytes(b"%PDF-1.4 original")
    sdv, key = tmp_path / "f.sdv", tmp_path / "f.key"
    cli.main(["encrypt", str(src), "-o", str(sdv), "-k", str(key)])

    out = tmp_path / "existing.pdf"
    out.write_bytes(b"do not touch")
    assert cli.main(["decrypt", str(sdv), "-k", str(key), "-o", str(out)]) == 1
    assert out.read_bytes() == b"do not touch"

    assert cli.main(["decrypt", str(sdv), "-k", str(key), "-o", str(out), "--force"]) == 0
    assert out.read_bytes() == src.read_bytes()


# --- Overwrite policy (D2 feedback) ------------------------------------------
def test_encrypt_twice_keeps_original_container_and_key(tmp_path):
    src = tmp_path / "f.pdf"
    src.write_bytes(b"%PDF-1.4 original")
    sdv, key = tmp_path / "f.sdv", tmp_path / "f.key"
    assert cli.main(["encrypt", str(src), "-o", str(sdv), "-k", str(key)]) == 0
    before = (sdv.read_bytes(), key.read_bytes())

    assert cli.main(["encrypt", str(src), "-o", str(sdv), "-k", str(key)]) == 1
    assert (sdv.read_bytes(), key.read_bytes()) == before


def test_encrypt_refuses_existing_key_file_before_encrypting(tmp_path):
    src = tmp_path / "f.pdf"
    src.write_bytes(b"%PDF-1.4 original")
    sdv, key = tmp_path / "f.sdv", tmp_path / "f.key"
    key.write_text("do not touch")
    assert cli.main(["encrypt", str(src), "-o", str(sdv), "-k", str(key)]) == 1
    assert key.read_text() == "do not touch"
    assert not sdv.exists()  # no container left without its key


def test_encrypt_force_replaces(tmp_path):
    src = tmp_path / "f.pdf"
    src.write_bytes(b"%PDF-1.4 original")
    sdv, key = tmp_path / "f.sdv", tmp_path / "f.key"
    cli.main(["encrypt", str(src), "-o", str(sdv), "-k", str(key)])
    old = sdv.read_bytes()
    assert cli.main(["encrypt", str(src), "-o", str(sdv), "-k", str(key), "--force"]) == 0
    assert sdv.read_bytes() != old
    out = tmp_path / "back.pdf"
    assert cli.main(["decrypt", str(sdv), "-k", str(key), "-o", str(out)]) == 0
    assert out.read_bytes() == src.read_bytes()


@pytest.fixture
def two_users(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "correct horse battery")
    for name in ("alice", "bob"):
        assert cli.main(["keygen", name, "-d", str(tmp_path)]) == 0
    return tmp_path


def test_share_refuses_existing_output(two_users):
    d = two_users
    src = d / "r.pdf"
    src.write_bytes(b"%PDF-1.4 shared")
    out = d / "r.sdv"
    out.write_bytes(b"do not touch")
    args = ["share", str(src), "-r", str(d / "bob.pub.pem"),
            "-s", str(d / "alice.sign.key.json"), "-o", str(out)]
    assert cli.main(args) == 1
    assert out.read_bytes() == b"do not touch"
    assert cli.main(args + ["--force"]) == 0
    assert out.read_bytes() != b"do not touch"


@pytest.mark.parametrize("existing", ["carol.sign.key.json", "carol.pub.pem"])
def test_keygen_refuses_any_existing_output(tmp_path, monkeypatch, existing):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "correct horse battery")
    (tmp_path / existing).write_text("old")
    assert cli.main(["keygen", "carol", "-d", str(tmp_path)]) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == [existing]
