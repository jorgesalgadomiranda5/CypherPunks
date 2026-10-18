"""File-level API: encrypt a file into a .sdv container and back.

D2 scope: a single owner. The per-file key is returned to the caller; how
it is stored (Key Store, wrapping with a public key) belongs to later
deliverables.
"""
import os
import tempfile

from vault import container, crypto_core
from vault.exceptions import VaultError


def _atomic_write(path: str, data: bytes) -> None:
    """Write to a temp file in the same folder, then rename.

    If anything fails midway, the destination is never left half-written.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".vault-tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def encrypt_file(input_path: str, output_path: str | None = None) -> tuple[str, bytes]:
    """Encrypt a file with a fresh key.

    Returns (container_path, key). The key is NOT stored in the container.
    """
    if not os.path.isfile(input_path):
        raise VaultError(f"Input file not found: {input_path}")
    if output_path is None:
        output_path = input_path + container.FILE_EXTENSION

    with open(input_path, "rb") as fh:
        plaintext = fh.read()

    key = crypto_core.generate_key()
    metadata = crypto_core.build_metadata(input_path)
    metadata_bytes = crypto_core.canonicalize_metadata(metadata)
    aad = container.build_header(metadata_bytes)

    nonce, ciphertext_with_tag = crypto_core.encrypt(key, plaintext, aad)
    _atomic_write(output_path, container.pack(metadata_bytes, nonce, ciphertext_with_tag))
    return output_path, key


def decrypt_bytes(data: bytes, key: bytes) -> tuple[dict, bytes]:
    """Authenticate and decrypt a container held in memory.

    Order matters: 1) parse structure, 2) verify tag and decrypt,
    3) only then trust and parse the metadata.
    """
    parts = container.unpack(data)
    plaintext = crypto_core.decrypt(key, parts.nonce, parts.ciphertext_with_tag, parts.header)
    metadata = crypto_core.parse_metadata(parts.metadata_bytes)
    return metadata, plaintext


def decrypt_file(container_path: str, key: bytes, output_path: str | None = None,
                 output_dir: str | None = None, overwrite: bool = False) -> str:
    """Decrypt a .sdv container and write the original file.

    If no output_path is given, the authenticated original name is used
    inside output_dir (default: the container's folder). Nothing is
    written unless every check passes.
    """
    if not os.path.isfile(container_path):
        raise VaultError(f"Container not found: {container_path}")
    with open(container_path, "rb") as fh:
        data = fh.read()

    metadata, plaintext = decrypt_bytes(data, key)

    if output_path is None:
        # basename() again: never let a stored name point outside output_dir.
        name = os.path.basename(metadata["original_name"]) or "decrypted.bin"
        output_dir = output_dir or os.path.dirname(os.path.abspath(container_path))
        output_path = os.path.join(output_dir, name)
    if os.path.exists(output_path) and not overwrite:
        raise VaultError(f"Output file already exists: {output_path}")
    _atomic_write(output_path, plaintext)
    return output_path
