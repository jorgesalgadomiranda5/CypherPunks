"""Digital signatures (D5): hash, sign and verify with Ed25519."""
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from vault.exceptions import IntegrityError

SIGNATURE_SIZE_BYTES = 64


def compute_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sign(signing_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Hash the data with SHA-256 and sign the digest (64 bytes, RFC 8032)."""
    return signing_key.sign(compute_digest(data))


def verify(public_key: ed25519.Ed25519PublicKey, signature: bytes, data: bytes) -> None:
    """Raise IntegrityError unless the signature matches the data and the key."""
    try:
        public_key.verify(signature, compute_digest(data))
    except InvalidSignature:
       # Same message as every other failure: do not reveal which check failed.
        raise IntegrityError("Authentication failed") from None
