"""Key pairs (D3, D5): X25519 and Ed25519 generation, public PEM files and key IDs.

Private keys are stored only through vault.keystore (D6).
"""
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from vault.exceptions import KeyManagementError

def generate_keypair() -> x25519.X25519PrivateKey:
    """X25519 pair used only to wrap file keys (D3)."""
    return x25519.X25519PrivateKey.generate()


def generate_signing_keypair() -> ed25519.Ed25519PrivateKey:
    """Ed25519 pair used only to sign. X25519 pairs are for key wrapping only."""
    return ed25519.Ed25519PrivateKey.generate()


def load_signing_public_key(path: str | Path) -> ed25519.Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise KeyManagementError(f"Could not load public key: {path}") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise KeyManagementError("Only Ed25519 keys can be used for signatures")
    return key

def load_any_public_key(path: str | Path) -> x25519.X25519PublicKey | ed25519.Ed25519PublicKey:
    """Wrapping or signing public key, for commands that accept either (revoke)."""
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise KeyManagementError(f"Could not load public key: {path}") from exc
    if not isinstance(key, (x25519.X25519PublicKey, ed25519.Ed25519PublicKey)):
        raise KeyManagementError("Only X25519 and Ed25519 public keys are supported")
    return key



def save_public_key(public_key: x25519.X25519PublicKey | ed25519.Ed25519PublicKey, path: str | Path) -> None:
    Path(path).write_bytes(public_key_to_pem(public_key))


def load_public_key(path: str | Path) -> x25519.X25519PublicKey:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise KeyManagementError(f"Could not read public key: {path}") from exc
    return public_key_from_pem(data)


def public_key_to_pem(public_key: x25519.X25519PublicKey | ed25519.Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_pem(data: bytes) -> x25519.X25519PublicKey:
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise KeyManagementError("Invalid public key") from exc
    if not isinstance(key, x25519.X25519PublicKey):
        raise KeyManagementError("Only X25519 keys can be used for key wrapping")
    return key


def key_id(public_key: x25519.X25519PublicKey | ed25519.Ed25519PublicKey) -> str:
    """Key ID = SHA-256 over the DER SubjectPublicKeyInfo, lowercase hex (64 chars).

    The same rule identifies recipients (X25519) and signers (Ed25519).
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()

