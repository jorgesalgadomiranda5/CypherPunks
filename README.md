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
