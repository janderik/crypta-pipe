from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.audit.lineage import LineageTracker
from src.audit.logger import AuditLogger
from src.crypto.encryptor import Encryptor
from src.crypto.key_manager import KeyManager
from src.crypto.signing import Signer
from src.pipeline.producer import PipelineProducer

router = APIRouter()

_km = KeyManager(store_dir=Path("./certs"))
_encryptor = Encryptor(_km)
_signer = Signer()
_audit = AuditLogger(log_path=Path("audit.log"))
_lineage = LineageTracker(store_path=Path("lineage.json"))


class PublishRequest(BaseModel):
    payload: dict
    source: str = "api"


class PublishResponse(BaseModel):
    message_id: str


class KeyResponse(BaseModel):
    key_id: str
    algorithm: str
    key_size: int
    created_at: float


class AuditResponse(BaseModel):
    entries: list[dict]


class LineageResponse(BaseModel):
    graph: dict


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse()


@router.get("/keys", response_model=list[KeyResponse])
async def list_keys() -> list[KeyResponse]:
    return [
        KeyResponse(
            key_id=kp.key_id,
            algorithm=kp.algorithm,
            key_size=kp.key_size,
            created_at=kp.created_at,
        )
        for kp in _km._archive.values()
    ]


@router.post("/keys/rotate")
async def rotate_key() -> KeyResponse:
    kp = _km.rotate()
    _audit.log(action="key_rotate", entity_id=kp.key_id)
    return KeyResponse(
        key_id=kp.key_id,
        algorithm=kp.algorithm,
        key_size=kp.key_size,
        created_at=kp.created_at,
    )


@router.post("/publish", response_model=PublishResponse)
async def publish(req: PublishRequest, request: Request) -> PublishResponse:
    producer = PipelineProducer(
        encryptor=_encryptor,
        signer=_signer,
        audit=_audit,
        lineage=_lineage,
        redis_client=request.app.state.redis,
    )
    msg_id = await producer.publish(req.payload, source_name=req.source)
    return PublishResponse(message_id=msg_id)


@router.get("/audit")
async def get_audit(tail: int = 50) -> AuditResponse:
    entries = _audit.tail(n=tail)
    return AuditResponse(
        entries=[
            {
                "sequence": e.sequence,
                "timestamp": e.timestamp,
                "action": e.action,
                "entity_id": e.entity_id,
                "metadata": e.metadata,
                "previous_hash": e.previous_hash,
                "hash": e.hash,
            }
            for e in entries
        ]
    )


@router.get("/audit/verify")
async def verify_audit() -> dict:
    valid = _audit.verify_chain()
    return {"valid": valid}


@router.get("/lineage")
async def get_lineage() -> LineageResponse:
    return LineageResponse(graph=_lineage.graph())


@router.get("/lineage/provenance/{node_id}")
async def get_provenance(node_id: str) -> dict:
    return _lineage.provenance(node_id)


@router.post("/lineage/node")
async def create_node(
    node_type: str, name: str, metadata: str | None = None
) -> dict:
    md = json.loads(metadata) if metadata else {}
    nid = _lineage.register_node(node_type=node_type, name=name, metadata=md)
    return {"node_id": nid}
