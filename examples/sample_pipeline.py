"""Example: run a full pipeline end-to-end (standalone, no Redis)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from src.audit.lineage import LineageTracker
from src.audit.logger import AuditLogger
from src.crypto.encryptor import Encryptor
from src.crypto.key_manager import KeyManager
from src.crypto.signing import Signer


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp)
        print(f"[*] Using temporary store: {store}")

        km = KeyManager(store_dir=store)
        km.generate_key_pair(key_size=2048)
        print(f"[+] Active key: {km.active.key_id}")

        enc = Encryptor(km)
        sig = Signer()
        audit = AuditLogger(log_path=store / "audit.log")
        lineage = LineageTracker(store_path=store / "lineage.json")

        source_id = lineage.register_node("source", "sample-api")
        transform_id = lineage.register_node("transform", "schema-validator")
        sink_id = lineage.register_node("sink", "sample-db")

        lineage.register_edge(source_id, transform_id, transform="validate_json")
        lineage.register_edge(transform_id, sink_id, transform="insert")

        payload = {
            "event": "user_signup",
            "user_id": 1001,
            "email": "alice@example.com",
            "timestamp": "2026-06-29T12:00:00Z",
        }

        print(f"[*] Original: {payload}")

        plaintext = json.dumps(payload).encode()
        aad = b"sample-pipeline"

        ciphertext = enc.encrypt(plaintext, aad=aad)
        print(f"[+] Encrypted: {len(ciphertext)} bytes")

        signature = sig.sign(ciphertext)
        print(f"[+] Signature: {signature.hex()[:32]}...")

        verified = sig.verify(ciphertext, signature)
        print(f"[+] Signature valid: {verified}")

        decrypted = enc.decrypt(ciphertext, aad=aad)
        restored = json.loads(decrypted.decode())
        print(f"[+] Decrypted: {restored}")

        assert restored == payload

        audit.log("publish", "sample-msg", {"source": "example", "size": len(ciphertext)})
        audit.log("process", "sample-msg", {"transform": "schema-validator"})
        audit.log("consume", "sample-msg", {"sink": "sample-db"})

        print(f"[+] Audit entries: {len(audit)}")
        print(f"[+] Audit chain valid: {audit.verify_chain()}")

        graph = lineage.graph()
        print(f"[+] Lineage nodes: {len(graph['nodes'])}")
        print(f"[+] Lineage edges: {len(graph['edges'])}")

        prov = lineage.provenance(sink_id)
        print(f"[+] Provenance for sink: {len(prov['ancestors'])} ancestors")

        print("\n[✓] Pipeline completed successfully!")


if __name__ == "__main__":
    main()
