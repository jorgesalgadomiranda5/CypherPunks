## D2: Secure Symmetric Encryption Module

The `vault/` package encrypts a file for a single owner with **AES-256-GCM**, a fresh 256-bit key per file and a random 96-bit nonce per encryption. Metadata (algorithm, version, parameters, original name, timestamp) travels in the container header, which is authenticated as AAD. Any change to the ciphertext, nonce, tag or metadata is detected and nothing is written.

Full design and security decisions: [`docs/D2-encryption-design.md`](docs/D2-encryption-design.md)

### Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Usage

```bash
python -m vault encrypt contract.pdf                  # -> contract.pdf.sdv + contract.pdf.sdv.key
python -m vault decrypt contract.pdf.sdv -k contract.pdf.sdv.key -o restored.pdf
```

Decryption never overwrites an existing file; add `--force` to allow it.

### Tests

```bash
python -m pytest -v
```

## D3: Hybrid Encryption (multi-recipient sharing)

A file is encrypted **once** with AES-256-GCM (the D2 core) under a fresh file key, and that key is wrapped with **RSA-OAEP** for each recipient's public key. Only the listed recipients can open the shared `.sdv` (format `SDV2`); the whole recipient list is authenticated as AAD, so adding, removing or swapping recipients is detected.

Full design and security decisions: [`docs/D3-hybrid-design.md`](docs/D3-hybrid-design.md)

### Usage

```bash
python -m vault keygen alice -d keys                  # -> keys/alice.key.pem (passphrase) + keys/alice.pub.pem
python -m vault keygen bob -d keys
python -m vault share report.pdf -r keys/alice.pub.pem -r keys/bob.pub.pem   # -> report.pdf.sdv
python -m vault recipients report.pdf.sdv             # key IDs allowed to open it
python -m vault open report.pdf.sdv -i keys/bob.key.pem -o report-bob.pdf
```

Private keys are always stored encrypted with a passphrase. Never commit `*.pem` files.

