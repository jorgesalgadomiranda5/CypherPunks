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


### Why hybrid encryption is used

Public-key encryption lets the sender protect data for a recipient without a shared secret, but RSA can only encrypt a few hundred bytes per operation and is orders of magnitude slower than AES. Hybrid encryption combines both: public-key encryption solves key distribution and symmetric encryption handles the data.

### Why symmetric encryption is still needed

The file itself is encrypted once with AES-256-GCM through `crypto_core.encrypt()`, exactly as in D2. AEAD gives confidentiality and integrity of the content and authenticates the header as associated data. RSA-OAEP only ever encrypts the 32-byte file key; `wrap_file_key()` refuses any other input.

### Why per-recipient key encryption is required

Each recipient has a different key pair, so the same file key is wrapped separately with each recipient's public key. Adding a recipient costs one RSA-OAEP block (384 bytes), not a second copy of the file, and no recipient needs anyone else's private key. OAEP is randomized, so even the same key wrapped twice for the same person gives different bytes.

## References

[1] K. Moriarty, B. Kaliski, J. Jonsson and A. Rusch, "PKCS #1: RSA Cryptography Specifications Version 2.2," RFC 8017, IETF, 2016.

[2] E. Barker, "Recommendation for Key Management: Part 1 – General," NIST SP 800-57 Part 1 Rev. 5, 2020.

[3] D. Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1," CRYPTO '98, LNCS 1462, 1998.

[4] Python Cryptographic Authority, "Asymmetric algorithms: RSA — cryptography documentation." [Online]. Available: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
