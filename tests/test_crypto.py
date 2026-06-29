from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from src.crypto.encryptor import Encryptor
from src.crypto.key_manager import KeyManager
from src.crypto.signing import Signer


@pytest.fixture
def key_manager():
    with tempfile.TemporaryDirectory() as tmp:
        km = KeyManager(store_dir=Path(tmp))
        km.generate_key_pair(key_size=2048)
        yield km


@pytest.fixture
def encryptor(key_manager):
    return Encryptor(key_manager)


@pytest.fixture
def signer():
    return Signer()


class TestEncryptor:
    def test_encrypt_decrypt_roundtrip(self, encryptor):
        plaintext = b"Hello, CryptaPipe! Secure data pipeline test."
        ciphertext = encryptor.encrypt(plaintext)
        assert ciphertext != plaintext
        decrypted = encryptor.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self, encryptor):
        plaintext = b"Sensitive payload with AAD"
        aad = b"source-api-v1"
        ciphertext = encryptor.encrypt(plaintext, aad=aad)
        decrypted = encryptor.decrypt(ciphertext, aad=aad)
        assert decrypted == plaintext

    def test_decrypt_wrong_aad_fails(self, encryptor):
        plaintext = b"AAD mismatch test"
        ciphertext = encryptor.encrypt(plaintext, aad=b"correct")
        with pytest.raises(Exception):
            encryptor.decrypt(ciphertext, aad=b"wrong")

    def test_different_payloads(self, encryptor):
        for pt in [b"a", b"" * 100, json.dumps({"a": 1}).encode()]:
            ct = encryptor.encrypt(pt)
            assert encryptor.decrypt(ct) == pt

    def test_key_rotation_still_decrypts(self, key_manager):
        encryptor1 = Encryptor(key_manager)
        pt = b"Before rotation"
        ct = encryptor1.encrypt(pt)
        key_manager.rotate()
        encryptor2 = Encryptor(key_manager)
        pt2 = b"After rotation"
        ct2 = encryptor2.encrypt(pt2)
        assert encryptor2.decrypt(ct) == pt
        assert encryptor2.decrypt(ct2) == pt2


class TestSigner:
    def test_sign_verify(self, signer):
        data = b"Important pipeline message"
        sig = signer.sign(data)
        assert signer.verify(data, sig) is True

    def test_verify_tampered(self, signer):
        data = b"Original message"
        sig = signer.sign(data)
        assert signer.verify(b"Tampered message", sig) is False

    def test_serialization_roundtrip(self):
        s1 = Signer()
        data = b"test data"
        sig = s1.sign(data)
        pub_bytes = s1.public_key_bytes
        priv_bytes = s1.private_key_bytes
        s2 = Signer.from_private_bytes(priv_bytes)
        assert s2.verify(data, sig) is True
        s3 = Signer.from_public_bytes(pub_bytes)
        assert s3.verify(data, sig) is True
        assert s3.verify(data, b"fakesig") is False


class TestKeyManager:
    def test_generate_and_retrieve(self, key_manager):
        kp = key_manager.active
        assert kp.key_id is not None
        retrieved = key_manager.get_key(kp.key_id)
        assert retrieved is not None
        assert retrieved.key_id == kp.key_id

    def test_derive_key(self, key_manager):
        k1 = key_manager.derive_key("my-password")
        k2 = key_manager.derive_key("my-password")
        assert k1 == k2
        k3 = key_manager.derive_key("different")
        assert k1 != k3
