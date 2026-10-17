"""Custom exceptions for the vault.

Every failure raised to the caller is one of these types, so the rest of the
system can fail safely without having to know about the underlying library.
"""


class VaultError(Exception):
    """Base class for all vault errors."""


class IntegrityError(VaultError):
    """Authentication failed: wrong key, or the container was modified.

    The message is intentionally generic. We do not tell the caller *which*
    part failed (ciphertext, nonce, metadata or key), because that detail
    only helps an attacker.
    """


class ContainerFormatError(VaultError):
    """The container is malformed and cannot even be parsed."""
