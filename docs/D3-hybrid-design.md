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

## 3. Container format (`SDV2`)

```
+-------------+------------------+---------------+------------+---------------------------+
| magic (4 B) | header_len (4 B) | header (JSON) | nonce (12) | ciphertext || tag (16 B)  |
|   "SDV2"    |   uint32 BE      |               |            |                           |
+-------------+------------------+---------------+------------+---------------------------+
|<---------------- AAD (magic + length + header) ->|
```

It keeps the SDV1 shape (header as AAD, nonce outside it, tag at the end), so the different magic is the only thing a reader needs to tell them apart. The header is canonical JSON:

```json
{"algorithms":{"aead":"AES-256-GCM","key_id":"SHA256-SPKI","key_wrap":"RSA-OAEP-SHA256"},
 "metadata":{"created_at":1792900000,"file_id":"<uuid4>"},
 "recipients":[{"encrypted_key":"<base64, 384 bytes>","kid":"<64 hex>"}, ...],
 "version":"2.0"}
```

Recipients are sorted by key ID so the same set always produces the same bytes. The parser rejects unknown fields, unsupported versions or algorithms, zero or more than 64 recipients, duplicate or malformed key IDs, and any header that is not in canonical form. The original file name is **not** stored (unlike SDV1); `open` restores it from the container name (`report.pdf.sdv` → `report.pdf`). This closes the SR-07 gap noted in D2 for shared files.

## 4. Security decisions

### How do recipients identify their key?

Each entry carries a key ID: SHA-256 over the DER `SubjectPublicKeyInfo` of the recipient's public key, in lowercase hex. The recipient computes the ID of their own public key and looks for exactly one matching entry. The mapping is deterministic (same key, same ID, regardless of PEM line breaks), duplicate IDs are rejected when encrypting and when parsing, and the ID reveals nothing about the private key.

### What happens if an attacker modifies the recipient list?

The whole header, including every key ID and wrapped key, is the AEAD associated data. Adding, removing, reordering or swapping entries changes the AAD, so tag verification fails for **every** recipient and no plaintext is released. Changing an algorithm identifier is rejected by the parser before any decryption, so a downgrade is not possible.

### What happens if the public key is wrong?

If the sender wraps the file key with the wrong public key, only the holder of the matching private key could unwrap it; the intended recipient finds no entry with their key ID and cannot open the file. If a recipient uses the wrong private key, RSA-OAEP unwrapping fails. In every case the user gets the same generic IntegrityError ("authentication failed") and nothing is written. Public keys must therefore come from a trusted source (the Secure Address Book in D1); authenticating them is out of scope for D3.

| Attacker action | Result |
| --- | --- |
| Opens the file without being a recipient | IntegrityError, nothing written |
| Adds their own entry to the recipient list | IntegrityError for everyone |
| Removes or swaps recipient entries | IntegrityError for everyone |
| Changes an algorithm identifier | IntegrityError (rejected by the parser) |
| Flips bits in the ciphertext or truncates the file | IntegrityError, nothing written |

## References

[1] K. Moriarty, B. Kaliski, J. Jonsson and A. Rusch, "PKCS #1: RSA Cryptography Specifications Version 2.2," RFC 8017, IETF, 2016.

[2] E. Barker, "Recommendation for Key Management: Part 1 – General," NIST SP 800-57 Part 1 Rev. 5, 2020.

[3] D. Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1," CRYPTO '98, LNCS 1462, 1998.

[4] Python Cryptographic Authority, "Asymmetric algorithms: RSA — cryptography documentation." [Online]. Available: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
