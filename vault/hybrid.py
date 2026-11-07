"""Hybrid encryption (D3): one AES-GCM ciphertext, one wrapped file key per recipient."""
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from vault import container_v2, crypto_core, keywrap, signatures
from vault.exceptions import ContainerFormatError, IntegrityError, VaultError
from vault.keys import key_id


def encrypt_for_recipients(
    plaintext: bytes,
    recipient_keys: list[rsa.RSAPublicKey],
    signer_id: str | None = None,
) -> bytes:
    """Encrypt once with a fresh file key; wrap that key for every recipient."""
    if not recipient_keys:
        raise VaultError("At least one recipient is required")
    kids = [key_id(pk) for pk in recipient_keys]
    if len(set(kids)) != len(kids):
        raise VaultError("The same public key was given twice")

    file_key = crypto_core.generate_key()
    entries = [
        container_v2.RecipientEntry(kid, keywrap.wrap_file_key(pk, file_key))
        for kid, pk in zip(kids, recipient_keys)
    ]
    metadata = {"file_id": str(uuid.uuid4()), "created_at": int(time.time())}

    if signer_id:
        metadata["signer_id"] = signer_id

    header_json = container_v2.serialize_header(
        container_v2.Header(recipients=entries, metadata=metadata)
    )
    aad = container_v2.build_aad(header_json)
    nonce, ciphertext_with_tag = crypto_core.encrypt(file_key, plaintext, aad)
    return container_v2.pack(header_json, nonce, ciphertext_with_tag)

def decrypt_as_recipient(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Find our entry by key ID, unwrap the file key and decrypt.

    Every failure (malformed container, not a recipient, wrong key, tampering)
    raises the same generic IntegrityError, so the caller learns nothing about
    which check failed.
    """
    try:
        parts = container_v2.unpack(data)
    except ContainerFormatError:
        raise IntegrityError("Authentication failed") from None

    entry = container_v2.find_recipient(parts.header, key_id(private_key.public_key()))
    if entry is None:
        raise IntegrityError("Authentication failed")
    file_key = keywrap.unwrap_file_key(private_key, entry.encrypted_key)
    return crypto_core.decrypt(file_key, parts.nonce, parts.ciphertext_with_tag, parts.aad)


def encrypt_and_sign(
    plaintext: bytes,
    recipient_keys: list[rsa.RSAPublicKey],
    signing_key: ed25519.Ed25519PrivateKey,
) -> bytes:
    """Encrypt the package and append its Ed25519 signature."""
    package = encrypt_for_recipients(
        plaintext,
        recipient_keys,
        key_id(signing_key.public_key()),
    )
    return package + signatures.sign(signing_key, package)


def verify_and_decrypt(
    data: bytes,
    private_key: rsa.RSAPrivateKey,
    sender_key: ed25519.Ed25519PublicKey,
) -> bytes:
    """Verify first; only a package with a valid signature reaches decryption."""
    package = data[:-signatures.SIGNATURE_SIZE_BYTES]
    signatures.verify(
        sender_key,
        data[-signatures.SIGNATURE_SIZE_BYTES:],
        package,
    )
    if container_v2.unpack(package).header.metadata.get("signer_id") != key_id(sender_key):
        raise IntegrityError("Authentication failed")
    return decrypt_as_recipient(package, private_key)


def list_recipients(data: bytes) -> list[str]:
    return [r.kid for r in container_v2.unpack(data).header.recipients]
