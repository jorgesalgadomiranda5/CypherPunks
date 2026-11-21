
"""Local key revocation list (D6): one 64-hex key ID per line, '#' starts a comment.

The list lives next to the user's keystores (keystore/revoked.txt). share refuses
revoked recipients and revoked signing keys; open refuses revoked senders.
"""
import os
import re
from pathlib import Path

from vault.exceptions import KeyManagementError

FILE_NAME = "revoked.txt"
_KID = re.compile(r"[0-9a-f]{64}")


def path_for(keystore_dir: str | Path) -> Path:
    return Path(keystore_dir) / FILE_NAME


def load(path: str | Path) -> set[str]:
    """A missing list is empty; a damaged one is an error, never an empty list."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return set()
    except (OSError, UnicodeDecodeError):
        raise KeyManagementError(f"Could not read the revocation list: {path}") from None

    revoked = set()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if not _KID.fullmatch(line):
            raise KeyManagementError(f"Malformed revocation list (line {number})")
        revoked.add(line)
    return revoked


def revoke(path: str | Path, kid: str) -> bool:
    """Append a key ID. Returns False if it was already revoked."""
    kid = kid.strip().lower()
    if not _KID.fullmatch(kid):
        raise KeyManagementError("A key ID must be 64 hexadecimal characters")
    if kid in load(path):
        return False
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(kid + "\n")
    return True


def ensure_not_revoked(kid: str, revoked: set[str]) -> None:
    if kid.lower() in revoked:
        raise KeyManagementError(f"Key has been revoked: {kid}")
