"""Command-line interface.

    python -m vault encrypt <file> [-o out.sdv] [-k out.key]
    python -m vault decrypt <file.sdv> -k <file.key> [-o out_file]

D2 note: the per-file key is saved as hex in a separate .key file so the
owner can decrypt later. Protecting that key (Key Store, password, public
key wrapping) is the job of the next deliverables.
"""
import argparse
import os
import sys

from vault import file_vault
from vault.exceptions import ContainerFormatError, IntegrityError, VaultError


def _read_key(path: str) -> bytes:
    try:
        with open(path, "r", encoding="ascii") as fh:
            return bytes.fromhex(fh.read().strip())
    except (OSError, ValueError) as exc:
        raise VaultError("Could not read a valid key file") from exc


def _write_key(path: str, key: bytes) -> None:
    # Owner read/write only, where the OS supports it.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(key.hex())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="Secure Digital Document Vault (D2)")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a file")
    enc.add_argument("input")
    enc.add_argument("-o", "--output", help="container path (default: <input>.sdv)")
    enc.add_argument("-k", "--key-out", help="key file path (default: <container>.key)")

    dec = sub.add_parser("decrypt", help="decrypt a .sdv container")
    dec.add_argument("input")
    dec.add_argument("-k", "--key", required=True, help="key file produced by encrypt")
    dec.add_argument("-o", "--output", help="output path (default: original name)")
    dec.add_argument("-f", "--force", action="store_true",
                     help="overwrite the output file if it already exists")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "encrypt":
            out, key = file_vault.encrypt_file(args.input, args.output)
            key_path = args.key_out or out + ".key"
            _write_key(key_path, key)
            print(f"Encrypted -> {out}")
            print(f"Key       -> {key_path}  (keep it safe; it is not in the container)")
        else:
            key = _read_key(args.key)
            out = file_vault.decrypt_file(args.input, key, output_path=args.output,
                                         overwrite=args.force)
            print(f"Decrypted -> {out}")
        return 0
    except IntegrityError:
        print("ERROR: authentication failed (wrong key or the file was modified). "
              "Nothing was written.", file=sys.stderr)
        return 2
    except ContainerFormatError as exc:
        print(f"ERROR: invalid container: {exc}", file=sys.stderr)
        return 3
    except VaultError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
