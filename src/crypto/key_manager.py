from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class KeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    created_at: float = field(default_factory=time.time)
    key_id: str = field(default_factory=lambda: f"k{int(time.time() * 1000)}")
    algorithm: str = "RSA-OAEP"
    key_size: int = 4096


class KeyManager:
    """Manages RSA key pairs with rotation, secure storage, and KDF derivation."""

    SALT_FILE = ".cryptapipe_salt"

    def __init__(self, store_dir: Path = Path("./certs")):
        self._store = store_dir.resolve()
        self._store.mkdir(parents=True, exist_ok=True)
        self._active: Optional[KeyPair] = None
        self._archive: dict[str, KeyPair] = {}
        self._salt = self._load_or_create_salt()
        self._load_keys()

    def _load_or_create_salt(self) -> bytes:
        salt_path = self._store / self.SALT_FILE
        if salt_path.exists():
            return salt_path.read_bytes()
        salt = os.urandom(16)
        salt_path.write_bytes(salt)
        return salt

    def derive_key(self, password: str, length: int = 32) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=self._salt,
            iterations=600_000,
        )
        return kdf.derive(password.encode())

    def generate_key_pair(self, key_size: int = 4096) -> KeyPair:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        kp = KeyPair(
            private_key=private_key,
            public_key=private_key.public_key(),
            key_size=key_size,
        )
        self._archive[kp.key_id] = kp
        self._active = kp
        self._persist_key(kp)
        return kp

    def rotate(self) -> KeyPair:
        new_kp = self.generate_key_pair()
        old_kp = self._active
        if old_kp:
            self._archive[old_kp.key_id] = old_kp
        self._active = new_kp
        return new_kp

    @property
    def active(self) -> KeyPair:
        if self._active is None:
            self.generate_key_pair()
        return self._active

    def get_key(self, key_id: str) -> Optional[KeyPair]:
        if self._active and self._active.key_id == key_id:
            return self._active
        return self._archive.get(key_id)

    def _persist_key(self, kp: KeyPair) -> None:
        pem = kp.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = kp.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (self._store / f"{kp.key_id}.pem").write_bytes(pem)
        (self._store / f"{kp.key_id}.pub").write_bytes(pub_pem)
        meta = {
            "key_id": kp.key_id,
            "algorithm": kp.algorithm,
            "key_size": kp.key_size,
            "created_at": kp.created_at,
        }
        (self._store / f"{kp.key_id}.json").write_text(json.dumps(meta, indent=2))

    def _load_keys(self) -> None:
        for pem_path in self._store.glob("*.pem"):
            kid = pem_path.stem
            if kid == self.SALT_FILE.replace(".", ""):
                continue
            try:
                key_pem = pem_path.read_bytes()
                private_key = serialization.load_pem_private_key(
                    key_pem, password=None
                )
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    continue
                kp = KeyPair(
                    private_key=private_key,
                    public_key=private_key.public_key(),
                    key_id=kid,
                    created_at=pem_path.stat().st_ctime,
                )
                if self._active is None:
                    self._active = kp
                self._archive[kid] = kp
            except Exception:
                continue
