from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from src.audit.lineage import LineageTracker
from src.audit.logger import AuditLogger
from src.crypto.encryptor import Encryptor
from src.crypto.key_manager import KeyManager
from src.crypto.signing import Signer


@pytest.fixture
def deps():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        km = KeyManager(store_dir=d)
        km.generate_key_pair(key_size=2048)
        enc = Encryptor(km)
        sig = Signer()
        audit = AuditLogger(log_path=d / "audit.log")
        lineage = LineageTracker(store_path=d / "lineage.json")
        yield {
            "encryptor": enc,
            "signer": sig,
            "audit": audit,
            "lineage": lineage,
            "key_manager": km,
        }


class TestAuditLogger:
    def test_log_and_verify(self, deps):
        audit = deps["audit"]
        e1 = audit.log("publish", "msg-1", {"source": "test"})
        e2 = audit.log("consume", "msg-1", {"sink": "db"})
        assert e2.previous_hash == e1.hash
        assert audit.verify_chain() is True

    def test_tamper_detection(self, deps):
        audit = deps["audit"]
        audit.log("publish", "msg-1")
        audit.log("consume", "msg-1")
        original = audit._log_path.read_text()
        tampered = original.replace("publish", "PUBLISH")
        audit._log_path.write_text(tampered)
        assert audit.verify_chain() is False

    def test_security_error_on_load_tampered(self, deps):
        audit = deps["audit"]
        audit.log("publish", "msg-1", {"k": "v"})
        audit.log("publish", "msg-2")
        audit.log("consume", "msg-2")
        original = audit._log_path.read_text()
        lines = original.strip().split("\n")
        changed = json.loads(lines[0])
        changed["action"] = "hacked"
        lines[0] = json.dumps(changed, sort_keys=True, separators=(",", ":"))
        audit._log_path.write_text("\n".join(lines) + "\n")
        with pytest.raises(Exception):
            AuditLogger(log_path=audit._log_path)


class TestLineageTracker:
    def test_register_node(self, deps):
        lineage = deps["lineage"]
        nid = lineage.register_node("source", "file-ingest", {"path": "/tmp/data"})
        assert nid is not None
        graph = lineage.graph()
        assert nid in graph["nodes"]

    def test_register_edge(self, deps):
        lineage = deps["lineage"]
        src = lineage.register_node("source", "s3-bucket")
        tgt = lineage.register_node("transform", "normalize")
        eid = lineage.register_edge(src, tgt, transform="remove_nulls")
        assert eid is not None

    def test_provenance(self, deps):
        lineage = deps["lineage"]
        src = lineage.register_node("source", "api-gateway")
        t1 = lineage.register_node("transform", "encrypt")
        t2 = lineage.register_node("transform", "validate")
        sink = lineage.register_node("sink", "postgres")
        lineage.register_edge(src, t1, transform="aes256")
        lineage.register_edge(t1, t2, transform="schema_check")
        lineage.register_edge(t2, sink, transform="insert")
        prov = lineage.provenance(sink)
        assert "ancestors" in prov
        assert src in prov["ancestors"]
        assert t1 in prov["ancestors"]
        assert t2 in prov["ancestors"]

    def test_provenance_unknown(self, deps):
        lineage = deps["lineage"]
        prov = lineage.provenance("nonexistent")
        assert "error" in prov

    def test_clear(self, deps):
        lineage = deps["lineage"]
        lineage.register_node("source", "test")
        lineage.clear()
        assert len(lineage.graph()["nodes"]) == 0


class TestIntegration:
    async def test_full_pipeline_flow(self, deps):
        enc = deps["encryptor"]
        sig = deps["signer"]
        audit = deps["audit"]
        lineage = deps["lineage"]

        payload = {"user_id": 42, "action": "login", "timestamp": "2026-01-01T00:00:00Z"}
        plaintext = json.dumps(payload).encode()
        aad = b"integration-test"

        ciphertext = enc.encrypt(plaintext, aad=aad)
        assert ciphertext is not None

        signature = sig.sign(ciphertext)
        assert sig.verify(ciphertext, signature) is True

        decrypted = enc.decrypt(ciphertext, aad=aad)
        assert json.loads(decrypted.decode()) == payload

        src_id = lineage.register_node("source", "integration-test")
        snk_id = lineage.register_node("sink", "integration-test")
        lineage.register_edge(src_id, snk_id, transform="produce_consume")

        audit.log("publish", "integ-msg-1", {"payload_size": len(plaintext)})
        audit.log("consume", "integ-msg-1")
        assert audit.verify_chain() is True
