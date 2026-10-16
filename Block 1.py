#Secure Randomness Generation (CSPRNG) and Metadata Canonicalization (AAD):
import os
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AdminEncryption:
    def __init__(self, version="1.0"):
        self.version = version
        self.algoritmo = "AES-256-GCM"

    def generate_parameters_encrypt(self):
        """
        nonce and key
        """
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        
        return key, nonce

    def generate_metadata(self, file_name):
        """
        Generate and serialize the metadata in a deterministic way.
        """
        # Def a dictionary of metada
        metadata = {
            "algorithm": self.algorithm,
            "version": self.version,
            "original_name": file_name,
            "timestamp": int(time.time()) 
        }
        
        # Convert it to bytes deterministically using json.dumps
        metadata_bytes = json.dumps(
            metadata, 
            sort_keys=True, 
            separators=(",", ":")
        ).encode("utf-8")
        
        return metadata_bytes, metadata
