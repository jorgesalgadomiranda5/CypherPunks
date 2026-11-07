    """Digital signatures (D5): hash, sign and verify with Ed25519."""
    import hashlib

    from cryptography.hazmat.primitives.asymmetric import ed25519

    SIGNATURE_SIZE_BYTES = 64


    def compute_digest(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()


    def sign(signing_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
        """Hash the data with SHA-256 and sign the digest (64 bytes, RFC 8032)."""
        return signing_key.sign(compute_digest(data))
