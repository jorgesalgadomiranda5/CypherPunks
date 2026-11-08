# D5: Signatures & Authentication
Up to D3 the vault gave confidentiality and access control, but nothing told a recipient who created a file: anyone holding a public key could build a valid package. D5 closes that gap (SR-04). Every shared package is now signed by its sender, and a recipient verifies that signature before any secret key is touched.

## 1. Module layout
| File | Change |
| --- | --- |
| `vault/keys.py` | Ed25519 signing key pairs; the signer ID reuses the D3 key ID rule |
| `vault/signatures.py` | New: hash, sign and verify |
| `vault/hybrid.py` | `encrypt_and_sign` and `verify_and_decrypt`, built on the D3 functions |
| `vault/cli.py` | `keygen` creates both pairs, `share` signs, `open` verifies |

## 2. Workflow
Sending follows Encrypt, Add metadata, Sign, Store. The file key is wrapped for each recipient, the header with the metadata is assembled, AES-256-GCM encrypts the file with that header as AAD, and the signature is computed last, over the finished SDV2 container. The header has to exist before the AEAD step because it is the associated data.
Receiving follows the required order: read the container, separate the signature, verify it, then decrypt if it is valid and reject if it is not. Any failure ends without an output file.
