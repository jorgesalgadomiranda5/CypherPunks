# D6: Key Management

Up to D5 the vault encrypted, shared and signed files, but every guarantee rested on private keys kept in passphrase-protected PEM files whose KDF and parameters were chosen by the library and documented nowhere. If a private key is exposed, all of that collapses. D6 replaces those files with a keystore the team defines: each private key is encrypted under a key derived from the user's password, the file states exactly how, and any change to it is detected. This is what D1 asks for in SR-08 (private keys never leave the Key Store in usable form) and SR-09 (the password is never stored and a wrong one reveals nothing).

## 1. Module layout

| File | Change |
| --- | --- |
| `vault/keystore.py` | New: password-derived key (scrypt), encrypted keystore, backup and restore |
| `vault/keys.py` | Generates key pairs and handles public keys and key IDs; it no longer writes private keys |
| `vault/cli.py` | `keygen` writes keystores, `share` and `open` unlock them, new `backup` and `restore` commands, and `revoke` (added after review) |
| `vault/revocation.py` | Local revocation list (`keystore/revoked.txt`), added after review |
| `tests/test_keystore.py` | The five required tests |

Unlocking follows the steps D6 requires. The CLI prompts for the password, scrypt derives a 256-bit key from it and the stored salt, AES-256-GCM decrypts the private key, and the key is used for that one command. The password is never written anywhere, and the decrypted key lives only in the memory of that process, which ends when the command finishes.

## 2. Key management design

### KDF selection and parameters

The KDF is scrypt [1] with N = 2^17, r = 8, p = 1, a 16-byte random salt and a 32-byte output, one of the configurations OWASP recommends [2]. Every guess costs about 128 MiB of memory and around 0.3 s in our test runs. We chose scrypt over PBKDF2 because it is memory-hard: an attacker who runs many guesses in parallel on GPUs has to pay for memory on each one, not only for computation. OWASP ranks Argon2id first, but the `cryptography` versions our `requirements.txt` allows (42 and later) only include it from version 44, while scrypt is available in all of them [4].

The derived key has a single use: it is the AES-256-GCM key that encrypts the private key. The encryption goes through the D2 core (`crypto_core.encrypt`), so every keystore gets a fresh random nonce, and a new salt is drawn from `os.urandom` each time a keystore is written. Passwords shorter than 12 characters are refused when a keystore is created.

### Key storage format

Each private key is stored in its own JSON file. `python -m vault keygen alice` writes four files:

```text
keystore/
├── alice.key.json      X25519 private key (usage "wrap"), encrypted
├── alice.pub.pem       X25519 public key, given to senders
├── alice.sign.key.json Ed25519 private key (usage "sign"), encrypted
└── alice.sign.pub.pem  Ed25519 public key, given to recipients
```

A keystore file looks like this (Base64 values shortened):

```json
{
  "format": "SDV-KEYSTORE-1",
  "kdf_parameters": {"algorithm": "scrypt", "n": 131072, "r": 8, "p": 1, "length": 32},
  "salt": "p+ddvM+kMXc1SLiCp08U4g==",
  "metadata": {"key_id": "44f33404...513564b", "usage": "wrap", "created_at": 1794187007},
  "nonce": "Ov+ywbMzrKnWEylV",
  "encrypted_private_key": "gcpS4Q..."
}
```

| Field | Content | Protection |
| --- | --- | --- |
| `format` | `SDV-KEYSTORE-1` | AAD |
| `kdf_parameters` | KDF name, N, r, p and output length | AAD |
| `salt` | 16 random bytes | AAD |
| `metadata` | `key_id`, `usage` (`wrap` or `sign`) and `created_at` | AAD |
| `nonce` | 12-byte GCM nonce | Input to GCM |
| `encrypted_private_key` | PKCS#8 DER private key encrypted with AES-256-GCM, followed by the 16-byte tag | Encrypted and covered by the tag |

The first four fields are the AAD of the encryption, so a change to the salt, the parameters or the metadata makes the tag check fail exactly like a wrong password. Binary values are Base64. The file is created with owner-only permissions where the operating system supports them, and an existing keystore is never overwritten.

### Backup strategy

A backup is an exact copy of the keystore file. Because the file is already encrypted, making a backup needs no password, and the copy can be kept on a USB drive or in a cloud folder with the same protection as the original:

```bash
python -m vault backup keystore/alice.key.json keystore/alice.sign.key.json # -> backups/
python -m vault restore backups/alice.key.json                  # -> keystore/
```

Restoring is stricter than backing up. `restore` asks for the password and unlocks the backup
before copying it, so a modified backup or one that belongs to another user is refused instead
of replacing a working keystore, and an existing keystore is never overwritten. Backups should
be kept away from the device that holds the keystore, because a single loss would otherwise
take both. Public keys are not secret and need no special handling. Backups and restored keystores are written with exclusive creation and owner-only permissions, and `restore` validates and writes the same bytes, so the file cannot be swapped between the check and the copy.


### Security assumptions

1. The device is trusted while a key is unlocked: no malware reads the keyboard or the memory of the process (D1, assumption 3).
2. The password is known only to its owner, is not reused elsewhere and has at least 12 characters.
3. Public keys are authentic (D1, assumption 4 and SR-10). The keystore protects private keys, not the address book.
4. The operating system's random generator (`os.urandom`) is sound, since it produces the salt and the nonce.
5. Backups are kept apart from the device that holds the keystore.

## 3. Key lifecycle

The stages below follow the key lifecycle described in NIST SP 800-57 [3].


| Stage | What it means | How the vault handles it |
| --- | --- | --- |
| Generation | Create a user's key pairs | `keygen` creates an X25519 pair (wrap) and an Ed25519 pair (sign) from the OS random generator, asks for the password twice and writes both keystores right away. The private key never reaches the disk in plaintext. |
| Usage | Use a private key | `share` unlocks the signing keystore and `open` unlocks the wrapping keystore. Each command asks for the password, uses the key once and ends; nothing is cached between commands. |
| Rotation | Replace a key that is still safe | `keygen alice-2027` creates new pairs and the new public keys go to contacts with their key IDs. Each file that must stay readable is opened with the old key and shared again for the new one. Only then are the old public keys revoked (`revoke keystore/alice.pub.pem`, `revoke keystore/alice.sign.pub.pem`), so the user can still open files they signed with the old key. |
| Compromise response | A private key, or a keystore together with its password, has leaked | `revoke` both old public keys at once and ask contacts to revoke them in their own lists; from then on `share` refuses the old keys and `open` refuses packages signed with them. Generate new pairs and send the public keys over a separate channel. Files received from others are opened and shared again for the new key; files signed with the compromised key are not trusted and must be sent again by their legitimate sender. Every package encrypted for the old key must be treated as readable by the attacker. |
| Revocation | Stop trusting a key | `python -m vault revoke <pub.pem or key ID>` appends the key ID to `keystore/revoked.txt`. `share` refuses revoked recipients and revoked signing keys; `open` refuses a revoked sender before asking for the password. A damaged list makes the command fail instead of being read as empty. |
| Existing encrypted files | Keep access after a key change | Open with the old key and share again for the new key, then delete the old `.sdv`. Tested end to end in `test_planned_rotation_keeps_files_readable`. |
| Expiration (optional) | Retire a key after a set time | Not automated. `created_at` in the metadata records when each key was created, so a team rule such as "rotate every year" can be checked by hand. |

Revocation is implemented (`vault/revocation.py`, `tests/test_revocation.py`); rotation and compromise response combine it with the existing `keygen`, `open` and `share` commands.

## 4. Access control via keys

Only the holder of the right private key can decrypt. `open` unwraps the file key with the X25519 key unlocked from the keystore, and sharing still depends on the encrypted file keys from D3: the container stores one wrapped file key per recipient and nothing else that could open it.

Key identity is consistent. A single rule, SHA-256 of the DER public key, gives the key ID everywhere: the recipient entries in `SDV3` (D3), `signer_id` (D5) and `key_id` in the keystore metadata (D6). When a keystore is unlocked, the vault computes the ID of the decrypted key again and rejects the keystore if it does not match the one stored in the metadata.

Key usage is never ambiguous. Each keystore holds one key with one usage: `wrap` for X25519 and `sign` for Ed25519. The caller always states which one it needs (`share` asks for `sign`, `open` asks for `wrap`), and `load_keystore` refuses any other usage, so a signing key can never be used to unwrap a file key, or the other way round.

## 5. Threat model alignment

### A. What if an attacker steals the keystore?

They get the encrypted key, the salt and the parameters, but not the password. To recover the key they have to guess the password offline, and each guess costs a full scrypt run with 128 MiB of memory. Editing the file does not help, because every field is authenticated. Required test 5 checks this: the stolen file does not contain the plaintext key, and wrong passwords do not open it. This is scenario S6 of D1, covered by SR-08 and SR-09.

### B. What if a password is weak?

The keystore is only as strong as its password. scrypt makes every guess expensive, but an offline attacker can still try a list of common passwords, and a weak one will fall sooner or later. The 12-character minimum rules out the shortest passwords, but the vault does not check whether a password is common or reused. If a weak password may have been exposed, the user follows the compromise response in Section 3.

### C. What if a device is compromised?

If malware runs on the device while the user types the password, or while a command holds the unlocked key, it can capture both, and the keystore cannot prevent that. D1 assumes the trusted environment works correctly (assumption 3). The design limits the damage: the password is never stored, the key is decrypted only for one command, and a device stolen while the vault is not running is the same as case A. After a compromise, the user follows the compromise response in Section 3 from a clean device.

### What the system protects against and what it does not

| Protects against | Does not protect against |
| --- | --- |
| A stolen keystore or backup without its password | Malware or a keylogger on the device while a key is in use |
| Changes to any field of the keystore | A weak or reused password, given enough guesses |
| Using a key for the wrong job, or a keystore whose key does not match its key ID | Reading the memory of a running process |
| Restoring a modified or foreign backup | A forgotten password: there is no recovery, and the backup needs the same password |
| The password being stored or logged | Revocation on other users' machines: each contact must run `revoke` on their own list |

## 6. Security discussion

### Why encrypt private keys?

A private key is the user's identity in the vault. Whoever holds the X25519 key can open every package sent to the user, and whoever holds the Ed25519 key can sign packages in the user's name. Keys leak through storage more often than through cryptography: a copied disk, a backup or a synchronized folder. Encrypting the key makes a copy of the file useless without the password, which never leaves the user's head.

### What happens if the password is weak?

An attacker with the keystore can guess offline, at their own pace, and scrypt only makes each guess slower. Section 5.B gives the details. In short, a weak password turns a stolen keystore into a stolen key.

### What are the system limitations?

- The vault cannot detect a compromised device (Section 5.C).
- Password quality is enforced only by length.
- A forgotten password cannot be recovered, and backups do not help with that.
- Revocation is local: each user keeps their own `revoked.txt`, and contacts must be told to revoke a compromised key.
- Python cannot reliably erase the decrypted key from memory. The vault limits its lifetime to one command but cannot wipe it.
- The per-file key file of the single-owner D2 mode (`.key`) is a symmetric key, not a private key, and is still stored in hex outside the keystore.

## 7. Tests

Run with `python -m pytest -v` (`tests/test_keystore.py`).

| Requirement | Test |
| --- | --- |
| Correct password, access granted | `test_correct_password_grants_access` |
| Wrong password, access denied | `test_wrong_password_denied` |
| Modified keystore, failure | `test_modified_keystore_fails` (encrypted key, salt, KDF parameters, metadata) |
| Backup, then restore works | `test_backup_then_restore_works` |
| Stolen keystore alone cannot decrypt | `test_stolen_keystore_alone_cannot_decrypt` |
| Backup and restore are owner-only and never overwrite (after review) | `test_backup_and_restore_are_owner_only`, `test_restore_refuses_existing_target` |
| Revocation, rotation and keystore errors (after review) | `tests/test_revocation.py` (11 tests) |

## References

[1] C. Percival and S. Josefsson, "The scrypt Password-Based Key Derivation Function," RFC 7914, IETF, 2016.

[2] OWASP Foundation, "Password Storage Cheat Sheet," OWASP Cheat Sheet Series. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

[3] E. Barker, "Recommendation for Key Management: Part 1 – General," NIST SP 800-57 Part 1 Rev. 5, 2020.

[4] Python Cryptographic Authority, "Key derivation functions — cryptography documentation." [Online]. Available: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
