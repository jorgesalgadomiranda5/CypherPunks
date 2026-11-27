# D3: Hybrid Encryption

> **Revision note (November 2026).** The version submitted for D3 protected file keys with RSA-OAEP-SHA256, contrary to the assignment's explicit prohibition of RSA. This revision replaces it with ECIES over X25519 (HKDF-SHA256, AES-256-GCM) and bumps the container to SDV3. SDV2 files are no longer readable.

D3 extends the vault from a single owner to **several authorized recipients**. A file is encrypted once; only the people it was shared with can decrypt it, even if the encrypted container is publicly exposed. The D2 core (`crypto_core.py`, `container.py`, `file_vault.py`) is reused unchanged.

## 1. Module layout

| File | Responsibility |
| --- | --- |
| `vault/keys.py` | X25519 key pairs (wrapping) and key IDs. Private keys were stored as passphrase-protected PEM files until D6 replaced them with the keystore |
| `vault/keywrap.py` | ECIES over X25519: wraps and unwraps the 32-byte file key for each recipient |
| `vault/container_v2.py` | `SDV3` multi-recipient format, header validation, AAD |
| `vault/hybrid.py` | Encrypt for many recipients, decrypt as one of them |
| `vault/cli.py` | New commands: `keygen`, `share`, `open`, `recipients` |
| `vault/exceptions.py` | New `KeyManagementError` |

## 2. Hybrid design explanation


### Why hybrid encryption is used

Public-key encryption lets the sender protect data for a recipient without a shared secret, but it is only efficient for small values and is far slower than AES. Hybrid encryption combines both: public-key cryptography solves key distribution and symmetric encryption handles the data. Here the public-key part is ECIES over X25519 [1]-[3]; RSA is not used anywhere in the project.

### Why symmetric encryption is still needed

The file itself is encrypted once with AES-256-GCM through `crypto_core.encrypt()`, exactly as in D2. AEAD gives confidentiality and integrity of the content and authenticates the header as associated data. The key-wrapping step only ever protects the 32-byte file key; `wrap_file_key()` refuses any other input.

### Why per-recipient key encryption is required

Each recipient has a different key pair, so the same file key is wrapped separately for each recipient's X25519 public key `R`, following ECIES [3]:

1. Generate a fresh ephemeral X25519 pair `(e, E)` and compute `shared = X25519(e, R)` [1].
2. Derive `wrap_key = HKDF-SHA256(shared, salt = None, info = "SDV3/file-key" || E || R)`, 32 bytes [2].
3. Encrypt the file key: `wrapped = AES-256-GCM(wrap_key, nonce, file_key, aad = E || R)`.
4. Store `encrypted_key = E (32 B) || nonce (12 B) || wrapped (48 B)`, 92 bytes in total.

The recipient takes `E` from the entry, recomputes `shared` with their private key and decrypts. Adding a recipient costs 92 bytes, not a second copy of the file, and no recipient needs anyone else's private key. A new ephemeral key is drawn for every wrap, so the same file key wrapped twice for the same person gives different bytes.

Both public keys are bound into the HKDF info and into the GCM associated data. A swapped ephemeral key, or an entry wrapped for another recipient, therefore fails authentication. A low-order `E` is rejected the same way. Every failure ends in the same generic IntegrityError.

## 3. Container format (`SDV3`)

```
+-------------+------------------+---------------+------------+---------------------------+
| magic (4 B) | header_len (4 B) | header (JSON) | nonce (12) | ciphertext || tag (16 B)  |
|   "SDV3"    |   uint32 BE      |               |            |                           |
+-------------+------------------+---------------+------------+---------------------------+
|<---------------- AAD (magic + length + header) ->|
```

It keeps the SDV1 shape (header as AAD, nonce outside it, tag at the end), so the different magic is the only thing a reader needs to tell them apart. The header is canonical JSON:

```json
{"algorithms":{"aead":"AES-256-GCM","key_id":"SHA256-SPKI","key_wrap":"ECIES-X25519-HKDF-SHA256-AES256GCM"},
 "metadata":{"created_at":1792900000,"file_id":"<uuid4>","signer_id":"<64 hex>"},
 "recipients":[{"encrypted_key":"<base64, 92 bytes>","kid":"<64 hex>"}, ...],
 "version":"3.0"}
```

`signer_id` was added to the metadata in D5. Recipients are sorted by key ID so the same set always produces the same bytes. The parser rejects unknown fields, unsupported versions or algorithms, zero or more than 64 recipients, duplicate or malformed key IDs, wrapped keys that are not exactly 92 bytes, and any header that is not in canonical form. RSA-based SDV2 containers are rejected as an unknown format. The original file name is **not** stored (unlike SDV1); `open` restores it from the container name (`report.pdf.sdv` → `report.pdf`). This closes the SR-07 gap noted in D2 for shared files.

## 4. Security decisions

### How do recipients identify their key?

Each entry carries a key ID: SHA-256 over the DER `SubjectPublicKeyInfo` of the recipient's public key, in lowercase hex. The recipient computes the ID of their own public key and looks for exactly one matching entry. The mapping is deterministic (same key, same ID, regardless of PEM line breaks), duplicate IDs are rejected when encrypting and when parsing, and the ID reveals nothing about the private key.

### What happens if an attacker modifies the recipient list?

The whole header, including every key ID and wrapped key, is the AEAD associated data. Adding, removing, reordering or swapping entries changes the AAD, so tag verification fails for **every** recipient and no plaintext is released. Changing an algorithm identifier is rejected by the parser before any decryption, so a downgrade is not possible.

### What happens if the public key is wrong?

If the sender wraps the file key with the wrong public key, only the holder of the matching private key could unwrap it; the intended recipient finds no entry with their key ID and cannot open the file. If a recipient uses the wrong private key, the derived wrapping key is different and AES-GCM rejects the wrapped key. In every case the user gets the same generic IntegrityError ("authentication failed") and nothing is written. Public keys must therefore come from a trusted source (the Secure Address Book in D1); authenticating them is out of scope for D3.

| Attacker action | Result |
| --- | --- |
| Opens the file without being a recipient | IntegrityError, nothing written |
| Adds their own entry to the recipient list | IntegrityError for everyone |
| Removes or swaps recipient entries | IntegrityError for everyone |
| Changes an algorithm identifier | IntegrityError (rejected by the parser) |
| Flips bits in the ciphertext or truncates the file | IntegrityError, nothing written |

## 5. Tests

Run with `python -m pytest -v` (`tests/test_hybrid.py`).

| Requirement | Tests |
| --- | --- |
| File shared with 2 users, both can decrypt | `test_two_recipients_can_both_decrypt`, `test_cli_share_open_and_recipients` |
| Unauthorized user cannot decrypt | `test_unauthorized_user_cannot_decrypt` |
| Tampered recipient list fails | `test_tampered_recipient_list_fails`, `test_swapped_identities_fail` |
| Wrong private key fails | `test_wrong_private_key_fails`, `test_wrong_public_key_at_encryption_locks_out_intended_recipient` |
| Removing a recipient entry breaks access | `test_removing_recipient_entry_breaks_access` |
| Supporting checks | downgrade, bit-flip, truncation, duplicate recipients, key ID determinism, RSA keys rejected, ECIES wrapping (wrong recipient, tampered ephemeral key, two wraps differ), password round-trip through the keystore (D6)|

## References

[1] A. Langley, M. Hamburg and S. Turner, "Elliptic Curves for Security," RFC 7748, IETF, 2016.

[2] H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," RFC 5869, IETF, 2010.

[3] Standards for Efficient Cryptography Group, "SEC 1: Elliptic Curve Cryptography," Version 2.0, Sec. 5.1, 2009.

[4] E. Barker, "Recommendation for Key Management: Part 1 – General," NIST SP 800-57 Part 1 Rev. 5, 2020.

[5] Python Cryptographic Authority, "X25519 key exchange — cryptography documentation." [Online]. Available: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
