from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator, Optional

import msgpack

from src.audit.logger import AuditLogger
from src.audit.lineage import LineageTracker
from src.crypto.encryptor import Encryptor
from src.crypto.signing import Signer

logger = logging.getLogger(__name__)


class PipelineProducer:
    """Read data from sources, encrypt, sign, and publish to a message queue."""

    def __init__(
        self,
        encryptor: Encryptor,
        signer: Signer,
        audit: AuditLogger,
        lineage: LineageTracker,
        redis_client: Any,
        stream: str = "cryptapipe:data",
    ):
        self._encryptor = encryptor
        self._signer = signer
        self._audit = audit
        self._lineage = lineage
        self._redis = redis_client
        self._stream = stream
        self._source_node: Optional[str] = None

    async def register_source(self, name: str, metadata: Optional[dict] = None) -> str:
        self._source_node = self._lineage.register_node(
            node_type="source", name=name, metadata=metadata
        )
        return self._source_node

    async def publish(self, payload: dict, source_name: str = "api") -> str:
        plaintext = json.dumps(payload, default=str).encode()
        aad = source_name.encode()
        ciphertext = self._encryptor.encrypt(plaintext, aad=aad)
        signature = self._signer.sign(ciphertext)

        msg = msgpack.packb({
            "ciphertext": ciphertext,
            "signature": signature,
            "source": source_name,
            "aad": source_name,
        })

        msg_id = await self._redis.xadd(self._stream, {"data": msg})
        msg_id = msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)

        self._audit.log(
            action="publish",
            entity_id=msg_id,
            metadata={"source": source_name, "stream": self._stream},
        )
        logger.info("Published message %s to %s", msg_id, self._stream)
        return msg_id

    async def publish_batch(
        self, items: list[dict], source_name: str = "api"
    ) -> list[str]:
        ids = []
        for item in items:
            mid = await self.publish(item, source_name)
            ids.append(mid)
        return ids

    async def stream_from(
        self, async_iter: AsyncIterator[dict], source_name: str = "stream"
    ) -> AsyncIterator[str]:
        async for item in async_iter:
            mid = await self.publish(item, source_name)
            yield mid
