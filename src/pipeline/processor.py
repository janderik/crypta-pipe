from __future__ import annotations

import json
import logging
from typing import Any

import msgpack

from src.audit.lineage import LineageTracker
from src.audit.logger import AuditLogger

logger = logging.getLogger(__name__)


class PipelineProcessor:
    """Transform/validate encrypted data without decrypting (metadata ops)."""

    def __init__(
        self,
        audit: AuditLogger,
        lineage: LineageTracker,
        redis_client: Any,
        input_stream: str = "cryptapipe:data",
        output_stream: str = "cryptapipe:processed",
    ):
        self._audit = audit
        self._lineage = lineage
        self._redis = redis_client
        self._input = input_stream
        self._output = output_stream
        self._transform_node: str | None = None

    async def register_transform(
        self, name: str, metadata: dict | None = None
    ) -> str:
        self._transform_node = self._lineage.register_node(
            node_type="transform", name=name, metadata=metadata
        )
        return self._transform_node

    async def process_one(self, msg_id: str, raw_data: bytes) -> str | None:
        try:
            envelope = msgpack.unpackb(raw_data)
            ciphertext = envelope[b"ciphertext"]
            signature = envelope.get(b"signature")
            source = envelope.get(b"source", b"unknown").decode()

            if signature is not None:
                pass

            metadata = {
                "original_msg_id": msg_id,
                "source": source,
                "size_bytes": len(ciphertext),
            }

            out_envelope = msgpack.packb({
                "ciphertext": ciphertext,
                "signature": signature,
                "source": source,
                "processed_by": "processor",
                "metadata": json.dumps(metadata),
            })

            out_id = await self._redis.xadd(
                self._output, {"data": out_envelope}
            )
            out_id = out_id.decode() if isinstance(out_id, bytes) else str(out_id)

            if self._transform_node:
                self._lineage.register_edge(
                    source_id=f"src:{source}",
                    target_id=self._transform_node,
                    transform=__name__,
                    metadata={"input_msg": msg_id, "output_msg": out_id},
                )

            self._audit.log(
                action="process",
                entity_id=out_id,
                metadata={
                    "input_msg": msg_id,
                    "input_stream": self._input,
                    "output_stream": self._output,
                    "source": source,
                },
            )
            return out_id
        except Exception as exc:  # noqa: BLE001 - worker boundary: log, audit and keep running
            logger.error("Failed to process %s: %s", msg_id, exc)
            self._audit.log(
                action="process_error",
                entity_id=msg_id,
                metadata={"error": str(exc)},
            )
            return None

    async def consume_and_process(self, count: int = 1) -> list[str]:
        results = await self._redis.xread({self._input: "$"}, count=count)
        out_ids = []
        for stream_name, messages in results:
            for msg_id, msg_data in messages:
                raw = msg_data.get(b"data", b"")
                out_id = await self.process_one(msg_id, raw)
                if out_id:
                    out_ids.append(out_id)
        return out_ids
