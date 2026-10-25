# D3: Hybrid Encryption

D3 extends the vault from a single owner to **several authorized recipients**. A file is encrypted once; only the people it was shared with can decrypt it, even if the encrypted container is publicly exposed. The D2 core (`crypto_core.py`, `container.py`, `file_vault.py`) is reused unchanged.

## 1. Module layout

| File | Responsibility |
| --- | --- |
| `vault/keys.py` | RSA-3072 key pairs, passphrase-protected PEM storage, key IDs |
| `vault/keywrap.py` | Wrap / unwrap the 32-byte file key with RSA-OAEP |
| `vault/container_v2.py` | `SDV2` multi-recipient format, header validation, AAD |
| `vault/hybrid.py` | Encrypt for many recipients, decrypt as one of them |
| `vault/cli.py` | New commands: `keygen`, `share`, `open`, `recipients` |
| `vault/exceptions.py` | New `KeyManagementError` |

## 2. Hybrid design explanation

