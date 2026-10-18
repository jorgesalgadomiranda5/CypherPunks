"""End-to-end tests on real files (the five tests required by D2)."""
import json
import os
from pathlib import Path

import pytest

from vault import container, crypto_core, file_vault
from vault.exceptions import ContainerFormatError, IntegrityError, VaultError

PDF_LIKE = b"%PDF-1.7\n" + os.urandom(4096) + b"\n%%EOF\n"


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "contract.pdf"
    path.write_bytes(PDF_LIKE)
    return path


def tamper(path, index):
    data = bytearray(path.read_bytes())
    data[index] ^= 0x01
    path.write_bytes(bytes(data))


# 1. Encrypt -> decrypt returns identical file
def test_encrypt_decrypt_identical_file(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    restored = file_vault.decrypt_file(sdv, key, output_dir=str(out_dir))
    assert os.path.basename(restored) == "contract.pdf"
    assert open(restored, "rb").read() == PDF_LIKE


def test_container_does_not_contain_plaintext_or_key(sample):
    sdv, key = file_vault.encrypt_file(str(sample))
    data = open(sdv, "rb").read()
    assert PDF_LIKE[:64] not in data
    assert key not in data


# 2. Wrong key fails
def test_wrong_key_fails(sample, tmp_path):
    sdv, _ = file_vault.encrypt_file(str(sample))
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, crypto_core.generate_key(),
                                output_path=str(tmp_path / "x.pdf"))


# 3. Modified ciphertext fails
def test_modified_ciphertext_fails(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    tamper(Path(sdv), -100)
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, key, output_path=str(tmp_path / "x.pdf"))


# 4. Modified metadata fails
def test_modified_metadata_fails(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    data = open(sdv, "rb").read()
    # Rename the file inside the metadata, keeping the same length.
    tampered = data.replace(b"contract.pdf", b"contrakt.pdf")
    assert tampered != data
    open(sdv, "wb").write(tampered)
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, key, output_path=str(tmp_path / "x.pdf"))


def test_modified_timestamp_fails(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    parts = container.unpack(open(sdv, "rb").read())
    meta = json.loads(parts.metadata_bytes)
    meta["timestamp"] += 1
    new_meta = crypto_core.canonicalize_metadata(meta)
    forged = container.pack(new_meta, parts.nonce, parts.ciphertext_with_tag)
    open(sdv, "wb").write(forged)
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, key, output_path=str(tmp_path / "x.pdf"))


def test_modified_nonce_fails(sample, tmp_path):
    sdv, key = file_vault.encrypt_file(str(sample))
    parts = container.unpack(open(sdv, "rb").read())
    tamper(Path(sdv), len(parts.header))   # first nonce byte
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, key, output_path=str(tmp_path / "x.pdf"))


def test_modified_magic_fails(sample):
    sdv, key = file_vault.encrypt_file(str(sample))
    tamper(Path(sdv), 0)
    with pytest.raises(ContainerFormatError):
        file_vault.decrypt_file(sdv, key)


# 5. Multiple encryptions produce different ciphertexts
def test_two_encryptions_differ(sample, tmp_path):
    a, key_a = file_vault.encrypt_file(str(sample), str(tmp_path / "a.sdv"))
    b, key_b = file_vault.encrypt_file(str(sample), str(tmp_path / "b.sdv"))
    pa = container.unpack(open(a, "rb").read())
    pb = container.unpack(open(b, "rb").read())
    assert key_a != key_b
    assert pa.nonce != pb.nonce
    assert pa.ciphertext_with_tag != pb.ciphertext_with_tag


# Safe failure
def test_failed_decryption_writes_nothing(sample, tmp_path):
    sdv, _ = file_vault.encrypt_file(str(sample))
    target = tmp_path / "should_not_exist.pdf"
    with pytest.raises(IntegrityError):
        file_vault.decrypt_file(sdv, crypto_core.generate_key(), output_path=str(target))
    assert not target.exists()
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".vault-tmp-")]


def test_decrypt_does_not_overwrite_existing_file(sample):
    # Default output is the original name in the same folder: the original.
    sdv, key = file_vault.encrypt_file(str(sample))
    sample.write_bytes(b"newer local version")
    with pytest.raises(VaultError):
        file_vault.decrypt_file(sdv, key)
    assert sample.read_bytes() == b"newer local version"


def test_decrypt_overwrite_when_requested(sample):
    sdv, key = file_vault.encrypt_file(str(sample))
    sample.write_bytes(b"newer local version")
    file_vault.decrypt_file(sdv, key, overwrite=True)
    assert sample.read_bytes() == PDF_LIKE