from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, TextIO


@dataclass
class AuditEntry:
    sequence: int
    timestamp: float
    action: str
    entity_id: str
    metadata: dict = field(default_factory=dict)
    previous_hash: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "action": self.action,
            "entity_id": self.entity_id,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()


class AuditLogger:
    """Tamper-evident audit log with chained hashing."""

    def __init__(self, log_path: Optional[Path] = None) -> None:
        self._log_path = log_path or Path("audit.log")
        self._entries: list[AuditEntry] = []
        self._last_hash = "0" * 64
        self._load_existing()

    def _load_existing(self) -> None:
        if not self._log_path.exists():
            return
        with self._log_path.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = self._deserialize(line)
                expected = entry.compute_hash()
                if entry.hash != expected:
                    raise SecurityError(f"Tampered audit entry {entry.sequence}")
                if entry.previous_hash != self._last_hash:
                    raise SecurityError(
                        f"Broken chain at entry {entry.sequence}"
                    )
                self._last_hash = entry.hash
        self._entries.clear()

    def _serialize(self, entry: AuditEntry) -> str:
        return json.dumps(asdict(entry), sort_keys=True, separators=(",", ":"))

    def _deserialize(self, line: str) -> AuditEntry:
        data = json.loads(line)
        return AuditEntry(**data)

    def log(
        self,
        action: str,
        entity_id: str,
        metadata: Optional[dict] = None,
    ) -> AuditEntry:
        seq = len(self._entries) + 1
        entry = AuditEntry(
            sequence=seq,
            timestamp=time.time(),
            action=action,
            entity_id=entity_id,
            metadata=metadata or {},
            previous_hash=self._last_hash,
        )
        entry.hash = entry.compute_hash()
        self._last_hash = entry.hash
        self._entries.append(entry)
        with self._log_path.open("a") as f:
            f.write(self._serialize(entry) + "\n")
        return entry

    def verify_chain(self) -> bool:
        chain_hash = "0" * 64
        if not self._log_path.exists():
            return True
        with self._log_path.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = self._deserialize(line)
                if entry.previous_hash != chain_hash:
                    return False
                if entry.hash != entry.compute_hash():
                    return False
                chain_hash = entry.hash
        return True

    def tail(self, n: int = 10) -> list[AuditEntry]:
        return self._entries[-n:]

    def __iter__(self):
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


class SecurityError(Exception):
    pass
