from __future__ import annotations

import json
import logging
from typing import Any, Optional

import msgpack

from src.audit.logger import AuditLogger
from src.audit.lineage import LineageTracker
from src.crypto.encryptor import Encryptor
from src.crypto.signing import Signer

logger = logging.getLogger(__name__)


class PipelineConsumer:
    """Decrypt and deliver data to sinks."""

    def __init__(
        self,
        encryptor: Encryptor,
        signer: Signer,
        audit: AuditLogger,
        lineage: LineageTracker,
        redis_client: Any,
        stream: str = "cryptapipe:processed",
    ):
        self._encryptor = encryptor
        self._signer = signer
        self._audit = audit
        self._lineage = lineage
        self._redis = redis_client
        self._stream = stream
        self._sink_node: Optional[str] = None

    async def register_sink(self, name: str, metadata: Optional[dict] = None) -> str:
        self._sink_node = self._lineage.register_node(
            node_type="sink", name=name, metadata=metadata
        )
        return self._sink_node

    async def consume(self, msg_id: str, raw_data: bytes) -> Optional[dict]:
        try:
            envelope = msgpack.unpackb(raw_data)
            ciphertext = envelope[b"ciphertext"]
            signature = envelope.get(b"signature")
            source = envelope.get(b"source", b"unknown").decode()
            aad_data = source.encode()

            if signature is not None:
                valid = self._signer.verify(ciphertext, signature)
                if not valid:
                    self._audit.log(
                        action="signature_verification_failed",
                        entity_id=msg_id,
                        metadata={"source": source},
                    )
                    logger.warning("Signature verification failed for %s", msg_id)
                    return None

            plaintext = self._encryptor.decrypt(ciphertext, aad=aad_data)
            data = json.loads(plaintext.decode())

            self._audit.log(
                action="consume",
                entity_id=msg_id,
                metadata={
                    "source": source,
                    "stream": self._stream,
                    "decrypted_size": len(plaintext),
                },
            )

            if self._sink_node:
                self._lineage.register_edge(
                    source_id=f"transform:{source}",
                    target_id=self._sink_node,
                    transform=__name__,
                    metadata={"msg_id": msg_id},
                )

            logger.info("Consumed and decrypted message %s", msg_id)
            return data
        except Exception as exc:
            logger.error("Failed to consume %s: %s", msg_id, exc)
            self._audit.log(
                action="consume_error",
                entity_id=msg_id,
                metadata={"error": str(exc)},
            )
            return None

    async def consume_latest(self) -> Optional[tuple[str, dict]]:
        results = await self._redis.xread({self._stream: "$"}, count=1)
        for stream_name, messages in results:
            for msg_id, msg_data in messages:
                raw = msg_data.get(b"data", b"")
                data = await self.consume(msg_id, raw)
                if data is not None:
                    return msg_id, data
        return None
