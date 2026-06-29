FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 cryptapipe

WORKDIR /app
COPY --from=builder /root/.local /home/cryptapipe/.local
COPY src/ src/
COPY certs/ certs/

ENV PATH=/home/cryptapipe/.local/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

USER cryptapipe

EXPOSE 8000

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
