"""Command-line interface.

    python -m vault encrypt <file> [-o out.sdv] [-k out.key]
    python -m vault decrypt <file.sdv> -k <file.key> [-o out_file]
    python -m vault share <file> -r alice.pub.pem -r bob.pub.pem [-o out.sdv]
    python -m vault open <file.sdv> -i bob.key.pem [-o out_file]

D2 note: the per-file key is saved as hex in a separate .key file so the
owner can decrypt later. Protecting that key (Key Store, password, public
key wrapping) is the job of the next deliverables.
D3 note: share/open never write the file key to disk. It is wrapped with each
recipient's RSA public key and stored inside the container.
"""
import argparse
import getpass
import os
import sys

from vault import file_vault, hybrid, keys
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


def _read_input(path: str) -> bytes:
    if not os.path.isfile(path):
        raise VaultError(f"Input file not found: {path}")
    with open(path, "rb") as fh:
        return fh.read()


def _ask_passphrase() -> bytes:
    passphrase = getpass.getpass("Private key passphrase: ")
    if not passphrase:
        raise VaultError("A passphrase is required")
    return passphrase.encode("utf-8")


def _cmd_share(args) -> None:
    plaintext = _read_input(args.input)
    public_keys = [keys.load_public_key(path) for path in args.recipient]
    out = args.output or args.input + ".sdv"
    file_vault._atomic_write(out, hybrid.encrypt_for_recipients(plaintext, public_keys))
    print(f"Encrypted for {len(public_keys)} recipient(s) -> {out}")


def _cmd_open(args) -> None:
    data = _read_input(args.input)
    out = args.output or (args.input[:-4] if args.input.endswith(".sdv") else args.input + ".out")
    if os.path.exists(out) and not args.force:
        raise VaultError(f"Output file already exists: {out}")
    private_key = keys.load_private_key(args.identity, _ask_passphrase())
    file_vault._atomic_write(out, hybrid.decrypt_as_recipient(data, private_key))
    print(f"Decrypted -> {out}")



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="Secure Digital Document Vault (D2-D3)")
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
    
    sh = sub.add_parser("share", help="encrypt a file for one or more recipients (D3)")
    sh.add_argument("input")
    sh.add_argument("-r", "--recipient", action="append", required=True,
                    metavar="PUB_PEM",
                    help="recipient public key; repeat once per recipient")
    sh.add_argument("-o", "--output", help="container path (default: <input>.sdv)")

    op = sub.add_parser("open", help="decrypt a shared container with your private key (D3)")
    op.add_argument("input")
    op.add_argument("-i", "--identity", required=True, metavar="KEY_PEM",
                    help="your private key")
    op.add_argument("-o", "--output", help="output path (default: input without .sdv)")
    op.add_argument("-f", "--force", action="store_true",
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
        elif args.command == "decrypt":
            key = _read_key(args.key)
            out = file_vault.decrypt_file(args.input, key, output_path=args.output,
                                         overwrite=args.force)
            print(f"Decrypted -> {out}")
        elif args.command == "share":
            _cmd_share(args)
        else:
            _cmd_open(args)
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
