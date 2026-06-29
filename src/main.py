from __future__ import annotations

import argparse
import logging
import sys

import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cryptapipe")


def entry() -> None:
    parser = argparse.ArgumentParser(description="CryptaPipe CLI")
    sub = parser.add_subparsers(dest="command")

    serve_parser = sub.add_parser("serve", help="Start the FastAPI server")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")

    sub.add_parser("version", help="Print version")

    args = parser.parse_args()

    if args.command == "serve":
        from src.api.server import create_app

        app = create_app()
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level="info",
        )
    elif args.command == "version":
        print("CryptaPipe 0.1.0")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    entry()
