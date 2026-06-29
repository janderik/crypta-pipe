# 🔐 CryptaPipe

[![CI](https://github.com/cryptapipe/cryptapipe/actions/workflows/ci.yml/badge.svg)](https://github.com/cryptapipe/cryptapipe/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000)](https://github.com/astral-sh/ruff)
[![Security: AES-256-GCM](https://img.shields.io/badge/security-AES--256--GCM-orange)](src/crypto/encryptor.py)

End-to-end encrypted secure data pipeline with tamper-evident audit logging and data lineage tracking.

---

## Features

- **End-to-End Encryption** — AES-256-GCM content encryption with RSA-OAEP key wrapping
- **Cryptographic Signing** — Ed25519 signatures for non-repudiation
- **Key Management** — Automatic key generation, rotation, and secure storage with PBKDF2
- **Tamper-Evident Audit** — Blockchain-style chained SHA-256 hash log
- **Data Lineage** — Full provenance graph tracking every source, transform, and sink
- **FastAPI Management API** — RESTful control plane
- **Async Pipeline** — Producer → Processor → Consumer via Redis Streams
- **Docker Compose** — One-command deployment with Redis

## Architecture

```
┌──────────┐    ┌───────────┐    ┌──────────┐
│ Producer │───▶│ Processor │───▶│ Consumer │
│ (encrypt │    │ (metadata │    │ (decrypt │
│  + sign) │    │   only)   │    │  + sink) │
└──────────┘    └───────────┘    └──────────┘
     │                │                │
     ▼                ▼                ▼
┌─────────────────────────────────────────┐
│            Redis Streams                │
│         (encrypted payloads)            │
└─────────────────────────────────────────┘
     │                │                │
     ▼                ▼                ▼
┌─────────────────────────────────────────┐
│         Audit Log (chained hash)        │
│         Lineage Graph (provenance)      │
└─────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/cryptapipe/cryptapipe.git
cd cryptapipe
pip install -r requirements.txt

# 2. Start Redis (optional, for pipeline)
docker compose up -d redis

# 3. Start the API server
python -m src.main serve --reload

# 4. Run the example
python examples/sample_pipeline.py
```

### Using Docker Compose

```bash
docker compose up --build
```

The API is available at `http://localhost:8000`.

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/keys` | List encryption keys |
| `POST` | `/api/v1/keys/rotate` | Rotate active key |
| `POST` | `/api/v1/publish` | Publish encrypted payload |
| `GET` | `/api/v1/audit` | Query audit log |
| `GET` | `/api/v1/audit/verify` | Verify audit chain integrity |
| `GET` | `/api/v1/lineage` | Get full lineage graph |
| `GET` | `/api/v1/lineage/provenance/{id}` | Provenance for a node |
| `POST` | `/api/v1/lineage/node` | Register a lineage node |

### Publish a Message

```bash
curl -s -X POST http://localhost:8000/api/v1/publish \
  -H "Content-Type: application/json" \
  -d '{"payload": {"event": "click", "user": 42}, "source": "web"}'
```

Response:
```json
{"message_id": "1712345678000-0"}
```

## Project Structure

```
crypta-pipe/
├── src/
│   ├── crypto/       # AES-256-GCM, RSA-OAEP, Ed25519, KDF
│   ├── pipeline/     # Producer/Processor/Consumer
│   ├── audit/        # Chained-hash logger + lineage tracker
│   ├── api/          # FastAPI server + routes
│   └── main.py       # CLI entrypoint
├── tests/            # Crypto + pipeline tests
├── examples/         # Sample pipeline (no Redis needed)
├── Dockerfile
└── docker-compose.yml
```

## Security

- **AES-256-GCM** — authenticated encryption with associated data (AAD)
- **RSA-OAEP (4096-bit)** — secure key wrapping with SHA-256 MGF1
- **Ed25519** — high-speed digital signatures
- **PBKDF2-HMAC-SHA256** — key derivation with 600,000 iterations
- **Chained Audit** — each entry includes the SHA-256 hash of the previous entry

## Development

```bash
pip install ruff mypy pytest pytest-asyncio
ruff check src/ tests/
mypy src/
pytest tests/ -v
```

## License

MIT
