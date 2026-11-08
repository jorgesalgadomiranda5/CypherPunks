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

## 3. Signature design

### Algorithm chosen
We use Ed25519 (RFC 8032 [1], FIPS 186-5 [2]) through the `cryptography` library [4], the option the course prefers. Its signing nonce is derived deterministically from the private key and the message, so a weak random number generator at signing time cannot leak the key. Signatures are 64 bytes. The signing pair is separate from the RSA-3072 wrapping pair: one key, one purpose. RSA-PSS is not used anywhere in the project.

### Why hashing is required before signing
A signature scheme works on a short, fixed-size value, while our files have no size limit. `compute_digest` reduces the whole container to one SHA-256 digest, and that digest is what gets signed. This is safe because SHA-256 is collision resistant: an attacker cannot find different data with the same digest. Any changed byte gives a different digest and verification fails.


### What data is signed

The signature covers the complete SDV2 container: magic, header length, header (metadata, algorithms, recipients and signer ID), nonce, ciphertext and tag. This includes everything used as AAD. The only bytes left out are the signature itself.

### Signature storage

```
+-------------+------------------+---------------+------------+--------------------------+----------------+
| magic (4 B) | header_len (4 B) | header (JSON) | nonce (12) | ciphertext || tag (16 B) | signature (64) |
+-------------+------------------+---------------+------------+--------------------------+----------------+
|<--------------------------------- SDV2 container, covered by the signature ---------->|
```

The SDV2 format does not change. `metadata`, `recipients` and `signer_id` are in the header, `ciphertext` and `tag` keep the D2 layout, and `signature` is added at the end.

### How the signer is identified

`signer_id` is the SHA-256 fingerprint of the signer's public key in DER `SubjectPublicKeyInfo` form, in lowercase hex, the same rule as the D3 recipient key ID. It is stored in the header metadata. The recipient chooses the expected sender's public key, and the vault rejects the package if the ID does not match that key.

### How the signature is encoded

The signature uses the standard RFC 8032 encoding: 64 raw bytes, `R || S`.

## 4. Security decisions

### Why sign ciphertext and not plaintext?

Because the check has to happen before decryption. A signature over the ciphertext can be verified with public information only, so a forged package is rejected without using a private key or running the decryption code on attacker input. It also binds the signature to this exact package, with its recipient list and metadata, so the same content cannot be reused in another context.

An attacker could try to remove the signature and sign the same bytes as their own. The `signer_id` is inside the AAD, so changing it breaks the AEAD tag, and leaving it unchanged makes the package fail the signer check.


### What happens if the signature is not verified first?

The private key and the decryption code would run on data from an unknown source, which gives an attacker more ways to probe the system [3]. The AEAD check does not replace the signature either: every recipient holds the file key, so any of them could produce a new ciphertext with a valid tag and present it as coming from the sender. Only the signature stops that. The `no_decryption` test fixture makes tests B to E fail if a rejected package reaches key unwrapping or decryption (SR-### What happens if metadata is excluded?
The signature would prove who produced the ciphertext but say nothing about its context. An attacker could edit the creation date, the algorithm identifiers or the recipient list, and the signature would still verify. The AEAD tag would catch some of this, but only after a recipient had used their private key. Signing the header rejects these changes first.

## 5. Tests
Run with `python -m pytest -v` (`tests/test_signatures.py`).
| Requirement | Test |
| --- | --- |
| A. Valid signature, file accepted | `test_valid_signature_accepted` |
| B. Modified ciphertext, rejected | `test_modified_ciphertext_rejected` |
| C. Modified metadata, rejected | `test_modified_metadata_rejected` |
| D. Wrong public key, rejected | `test_wrong_public_key_rejected` |
| E. Signature removed, rejected | `test_signature_removed_rejected` |

## References
[1] S. Josefsson and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, IETF, 2017.
[2] NIST, "Digital Signature Standard (DSS)," FIPS 186-5, 2023.
[3] D. Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1," CRYPTO '98, LNCS 1462, 1998.
[4] Python Cryptographic Authority, "Ed25519 signing — cryptography documentation." [Online]. Available: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/


