
"""Hybrid encryption (D3): one AES-GCM ciphertext, one wrapped file key per recipient."""

from cryptography.hazmat.primitives.asymmetric import rsa

from vault import container_v2, crypto_core, keywrap
from vault.exceptions import VaultError
from vault.keys import key_id


def encrypt_for_recipients(plaintext: bytes, recipient_keys: list[rsa.RSAPublicKey]) -> bytes:
    """Encrypt once with a fresh file key; wrap that key for every recipient."""
    if not recipient_keys:
        raise VaultError("At least one recipient is required")
    kids = [key_id(pk) for pk in recipient_keys]

    file_key = crypto_core.generate_key()
    entries = [
        container_v2.RecipientEntry(kid, keywrap.wrap_file_key(pk, file_key))
        for kid, pk in zip(kids, recipient_keys)
    ]
    metadata = {}

    header_json = container_v2.serialize_header(
        container_v2.Header(recipients=entries, metadata=metadata)
    )
    aad = container_v2.build_aad(header_json)
    nonce, ciphertext_with_tag = crypto_core.encrypt(file_key, plaintext, aad)
    return container_v2.pack(header_json, nonce, ciphertext_with_tag)


def decrypt_as_recipient(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Find our entry by key ID, unwrap the file key and decrypt."""
    parts = container_v2.unpack(data)

    entry = container_v2.find_recipient(
        parts.header, key_id(private_key.public_key())
    )
    if entry is None:
        raise VaultError("You are not a recipient of this file")
    file_key = keywrap.unwrap_file_key(private_key, entry.encrypted_key)
    return crypto_core.decrypt(
        file_key, parts.nonce, parts.ciphertext_with_tag, parts.aad
    )


def list_recipients(data: bytes) -> list[str]:
    return [r.kid for r in container_v2.unpack(data).header.recipients]
