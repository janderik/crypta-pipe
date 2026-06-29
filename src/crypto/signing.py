from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class Signer:
    """Ed25519 signing and verification."""

    def __init__(self) -> None:
        self._private_key: ed25519.Ed25519PrivateKey = ed25519.Ed25519PrivateKey.generate()
        self._public_key: ed25519.Ed25519PublicKey = self._private_key.public_key()

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> Signer:
        s = cls.__new__(cls)
        s._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        s._public_key = s._private_key.public_key()
        return s

    @classmethod
    def from_public_bytes(cls, raw: bytes) -> Signer:
        s = cls.__new__(cls)
        s._private_key = None  # type: ignore
        s._public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        return s

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def private_key_bytes(self) -> bytes:
        if self._private_key is None:
            raise RuntimeError("No private key available")
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, data: bytes) -> bytes:
        if self._private_key is None:
            raise RuntimeError("Cannot sign without private key")
        return self._private_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False
