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
