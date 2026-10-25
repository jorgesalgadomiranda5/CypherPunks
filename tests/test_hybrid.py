"""D3 tests: hybrid encryption, multi-recipient sharing and tampering."""
import pytest

from vault import keys, keywrap
from vault.exceptions import KeyManagementError, VaultError

PLAINTEXT = b"%PDF-1.7\n" + b"contenido confidencial " * 2000


@pytest.fixture(scope="module")
def alice():
    return keys.generate_keypair()


@pytest.fixture(scope="module")
def bob():
    return keys.generate_keypair()


@pytest.fixture(scope="module")
def eve():
    return keys.generate_keypair()


# --- Building blocks: keys and key wrapping ---------------------------------
