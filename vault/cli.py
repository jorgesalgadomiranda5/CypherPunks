"""Command-line interface.

    python -m vault encrypt <file> [-o out.sdv] [-k out.key]
    python -m vault decrypt <file.sdv> -k <file.key> [-o out_file]
    python -m vault keygen <name> [-d keystore]
    python -m vault share <file> -r alice.pub.pem -r bob.pub.pem -s keystore/me.sign.key.json [-o out.sdv]
    python -m vault open <file.sdv> -i keystore/bob.key.json --sender alice.sign.pub.pem [-o out_file]
    python -m vault recipients <file.sdv>
    python -m vault backup keystore/me.key.json keystore/me.sign.key.json [-d backups]
    python -m vault restore backups/me.key.json [-d keystore]

D2 note: the per-file key is saved as hex in a separate .key file so the
owner can decrypt later. Protecting that key (Key Store, password, public
key wrapping) is the job of the next deliverables.
D3 note: share/open never write the file key to disk. It is wrapped with each
recipient's X25519 public key (ECIES) and stored inside the container.
D5 note: share always signs and open always verifies first, so unsigned
containers are no longer accepted by open.
D6 note: private keys live only in password-protected keystores (.key.json).
The password is asked for every time a key is needed and is never stored.
"""
import argparse
import getpass
import os
import sys


from vault import file_vault, hybrid, keys, keystore, revocation
from vault.exceptions import ContainerFormatError, IntegrityError, VaultError


def _read_key(path: str) -> bytes:
    try:
        with open(path, "r", encoding="ascii") as fh:
            return bytes.fromhex(fh.read().strip())
    except (OSError, ValueError) as exc:
        raise VaultError("Could not read a valid key file") from exc


def _write_key(path: str, key: bytes, force: bool = False) -> None:
    # Owner read/write only, where the OS supports it. Never truncate silently.
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise VaultError(f"Key file already exists: {path}") from None
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(key.hex())
    os.chmod(path, 0o600)  # O_TRUNC keeps the old mode


def _read_input(path: str) -> bytes:
    if not os.path.isfile(path):
        raise VaultError(f"Input file not found: {path}")
    with open(path, "rb") as fh:
        return fh.read()

def _ask_passphrase(confirm: bool = False) -> bytes:
    passphrase = getpass.getpass("Keystore password: ")
    if confirm and passphrase != getpass.getpass("Repeat password: "):
        raise VaultError("Passwords do not match")
    if not passphrase:
        raise VaultError("A password is required")
    return passphrase.encode("utf-8")



def _cmd_keygen(args) -> None:
    os.makedirs(args.dir, exist_ok=True)
    private_path = os.path.join(args.dir, f"{args.name}.key.json")
    public_path = os.path.join(args.dir, f"{args.name}.pub.pem")
    sign_private_path = os.path.join(args.dir, f"{args.name}.sign.key.json")
    sign_public_path = os.path.join(args.dir, f"{args.name}.sign.pub.pem")
    taken = [p for p in (private_path, public_path, sign_private_path, sign_public_path)
             if os.path.exists(p)]
    if taken:
        raise VaultError("Refusing to overwrite: " + ", ".join(taken))
    private_key = keys.generate_keypair()
    passphrase = _ask_passphrase(confirm=True)
    keystore.save_keystore(private_key, "wrap", private_path, passphrase)
    keys.save_public_key(private_key.public_key(), public_path)
    signing_key = keys.generate_signing_keypair()
    keystore.save_keystore(signing_key, "sign", sign_private_path, passphrase)
    keys.save_public_key(signing_key.public_key(), sign_public_path)
    print(f"Keystore -> {private_path} (encrypted; never share it)")
    print(f"Public key  -> {public_path}")
    print(f"Key ID      -> {keys.key_id(private_key.public_key())}")


def _cmd_share(args) -> None:
    plaintext = _read_input(args.input)
    public_keys = [keys.load_public_key(path) for path in args.recipient]
    out = args.output or args.input + ".sdv"
    
    if os.path.exists(out) and not args.force:
        raise VaultError(f"Output file already exists: {out}")

    revoked = revocation.load(revocation.path_for(os.path.dirname(args.sign_key) or "."))
    for public_key in public_keys:
        revocation.ensure_not_revoked(keys.key_id(public_key), revoked)

    signing_key = keystore.load_keystore(args.sign_key, _ask_passphrase(), "sign")
    revocation.ensure_not_revoked(keys.key_id(signing_key.public_key()), revoked)

    file_vault._atomic_write(out, hybrid.encrypt_and_sign(plaintext, public_keys, signing_key),
                             overwrite=args.force)
    print(f"Encrypted for {len(public_keys)} recipient(s) -> {out}")


def _cmd_open(args) -> None:
    data = _read_input(args.input)
    out = args.output or (args.input[:-4] if args.input.endswith(".sdv") else args.input + ".out")
    if os.path.exists(out) and not args.force:
        raise VaultError(f"Output file already exists: {out}")
    sender_key = keys.load_signing_public_key(args.sender)
    revoked = revocation.load(revocation.path_for(os.path.dirname(args.identity) or "."))
    revocation.ensure_not_revoked(keys.key_id(sender_key), revoked)
    private_key = keystore.load_keystore(args.identity, _ask_passphrase(), "wrap")
    file_vault._atomic_write(out, hybrid.verify_and_decrypt(data, private_key, sender_key),
                             overwrite=args.force)
    print(f"Decrypted -> {out}")


def _cmd_backup(args) -> None:
    for path in args.input:
        print(f"Backup -> {keystore.backup_keystore(path, args.dir)}")


def _cmd_restore(args) -> None:
    name = os.path.basename(args.input)
    usage = "sign" if name.endswith(".sign.key.json") else "wrap"
    target = os.path.join(args.dir, name)
    keystore.restore_keystore(args.input, target, _ask_passphrase(), usage)
    print(f"Restored -> {target}")



def _cmd_revoke(args) -> None:
    if os.path.isfile(args.key):
        kid = keys.key_id(keys.load_any_public_key(args.key))
    else:
        kid = args.key

    path = revocation.path_for(args.dir)
    added = revocation.revoke(path, kid)
    print(f"{'Revoked' if added else 'Already revoked'}: {kid} ({path})")



def _cmd_recipients(args) -> None:
    """Display the key IDs of authorized recipients."""
    for kid in hybrid.list_recipients(_read_input(args.input)):
        print(kid)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="Secure Digital Document Vault (D2-D6)")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a file")
    enc.add_argument("input")
    enc.add_argument("-o", "--output", help="container path (default: <input>.sdv)")
    enc.add_argument("-k", "--key-out", help="key file path (default: <container>.key)")
    enc.add_argument("-f", "--force", action="store_true",
                     help="overwrite the container and key file if they already exist")

    dec = sub.add_parser("decrypt", help="decrypt a .sdv container")
    dec.add_argument("input")
    dec.add_argument("-k", "--key", required=True, help="key file produced by encrypt")
    dec.add_argument("-o", "--output", help="output path (default: original name)")
    dec.add_argument("-f", "--force", action="store_true",
                     help="overwrite the output file if it already exists")
    kg = sub.add_parser("keygen", help="create X25519 (sharing) and Ed25519 (signing) key pairs")
    kg.add_argument("name", help="writes <name>.key.json, <name>.pub.pem, <name>.sign.key.json, <name>.sign.pub.pem") 
    kg.add_argument("-d", "--dir", default="keystore", help="output folder (default: keystore)")
    sh = sub.add_parser("share", help="encrypt a file for one or more recipients (D3)")
    sh.add_argument("input")
    sh.add_argument("-r", "--recipient", action="append", required=True,
                    metavar="PUB_PEM",
                    help="recipient public key; repeat once per recipient")
    sh.add_argument("-s", "--sign-key", required=True, metavar="SIGN_KEYSTORE",
                help="your signing keystore (<name>.sign.key.json)")
    sh.add_argument("-o", "--output", help="container path (default: <input>.sdv)")
    sh.add_argument("-f", "--force", action="store_true",
                    help="overwrite the container if it already exists")

    op = sub.add_parser("open", help="decrypt a shared container with your private key (D3)")
    op.add_argument("input")
    op.add_argument("-i", "--identity", required=True, metavar="KEYSTORE",
                    help="your keystore (<name>.key.json)")
    op.add_argument("--sender", required=True, metavar="SIGN_PUB_PEM",
                    help="public signing key of the expected sender")
    op.add_argument("-o", "--output", help="output path (default: input without .sdv)")
    op.add_argument("-f", "--force", action="store_true",
                    help="overwrite the output file if it already exists")
    # Command to display authorized recipients.
    rc = sub.add_parser(
        "recipients",
        help="list the key IDs that can open a container (D3)"
    )
    rc.add_argument("input")
    
    bk = sub.add_parser("backup", help="copy encrypted keystores to a backup folder (D6)")
    bk.add_argument("input", nargs="+", metavar="KEYSTORE")
    bk.add_argument("-d", "--dir", default="backups", help="backup folder (default: backups)")
    rs = sub.add_parser("restore", help="restore a keystore from a backup, after checking its password (D6)")
    rs.add_argument("input", metavar="BACKUP")
    rs.add_argument("-d", "--dir", default="keystore", help="keystore folder (default: keystore)")
    
    rv = sub.add_parser("revoke", help="revoke a public key or key ID (D6)")
    rv.add_argument("key", metavar="PUB_PEM_OR_KEY_ID",
                    help="public key PEM file or its 64-character hexadecimal key ID")
    rv.add_argument("-d", "--dir", default="keystore",
                    help="folder containing revoked.txt (default: keystore)")


    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "encrypt":
            out = args.output or args.input + ".sdv"
            key_path = args.key_out or out + ".key"
            taken = [p for p in (out, key_path) if os.path.exists(p)]
            if taken and not args.force:
                raise VaultError("Output file already exists: " + ", ".join(taken))
            out, key = file_vault.encrypt_file(args.input, out, overwrite=args.force)
            _write_key(key_path, key, force=args.force)
            print(f"Encrypted -> {out}")
            print(f"Key       -> {key_path}  (keep it safe; it is not in the container)")
        elif args.command == "decrypt":
            key = _read_key(args.key)
            out = file_vault.decrypt_file(args.input, key, output_path=args.output,
                                         overwrite=args.force)
            print(f"Decrypted -> {out}")
        elif args.command == "keygen":
            _cmd_keygen(args)
        elif args.command == "share":
            _cmd_share(args)
        elif args.command == "open":
            _cmd_open(args)
        elif args.command == "backup":
            _cmd_backup(args)        
        elif args.command == "restore":
            _cmd_restore(args)
        elif args.command == "revoke":
            _cmd_revoke(args)
        else:
            _cmd_recipients(args)

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
