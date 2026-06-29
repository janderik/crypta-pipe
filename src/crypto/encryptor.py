from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .key_manager import KeyManager


class Encryptor:
    """AES-256-GCM content encryption with RSA-OAEP key wrapping."""

    AES_KEY_SIZE = 32
    NONCE_SIZE = 12

    def __init__(self, key_manager: KeyManager):
        self._km = key_manager

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        """Encrypt plaintext using AES-256-GCM and wrap the key with RSA-OAEP.

        Returns a packed byte structure:
          [4-byte key_id_len][key_id][4-byte wrapped_key_len][wrapped_key][nonce(12)][ciphertext][tag(16)]
        """
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad or b"")

        kp = self._km.active
        wrapped_key = kp.public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        kid_bytes = kp.key_id.encode()
        parts = [
            len(kid_bytes).to_bytes(4, "big"),
            kid_bytes,
            len(wrapped_key).to_bytes(4, "big"),
            wrapped_key,
            nonce,
            ciphertext,
        ]
        return b"".join(parts)

    def decrypt(self, payload: bytes, aad: Optional[bytes] = None) -> bytes:
        """Reverse of encrypt."""
        offset = 0
        kid_len = int.from_bytes(payload[offset : offset + 4], "big")
        offset += 4
        kid = payload[offset : offset + kid_len].decode()
        offset += kid_len
        wk_len = int.from_bytes(payload[offset : offset + 4], "big")
        offset += 4
        wrapped_key = payload[offset : offset + wk_len]
        offset += wk_len

        nonce = payload[offset : offset + self.NONCE_SIZE]
        offset += self.NONCE_SIZE
        ciphertext = payload[offset:]

        kp = self._km.get_key(kid)
        if kp is None:
            raise ValueError(f"Unknown key ID: {kid}")

        aes_key = kp.private_key.decrypt(
            wrapped_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, aad or b"")
