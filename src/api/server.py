from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI

from .routes import router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.redis = redis.Redis(
        host="localhost", port=6379, decode_responses=False
    )
    await app.state.redis.ping()
    logger.info("Connected to Redis")
    yield
    await app.state.redis.aclose()
    logger.info("Redis connection closed")


def create_app() -> FastAPI:
    app = FastAPI(
        title="CryptaPipe API",
        description="End-to-end encrypted data pipeline management API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router, prefix="/api/v1")
    return app
