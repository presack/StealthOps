"""StealthOps entrypoint with CLI and web modes."""

from __future__ import annotations

import argparse
import json

import uvicorn

from core_ops import QueryConfig, StealthQueryEngine
from tor_engine import TorEngine
from web_ui import build_app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="StealthOps - privacy-hardened reconnaissance utility")
    parser.add_argument("--query", help="Domain/URL target for CLI mode")
    parser.add_argument(
        "--block-non-tor",
        action="store_true",
        help="Fail requests if Tor is unavailable",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Web server bind host")
    parser.add_argument("--port", type=int, default=5000, help="Web server bind port")
    return parser.parse_args()


def run_cli(target: str, block_non_tor: bool) -> int:
    tor_engine = TorEngine()
    tor_ok = tor_engine.ensure_tor()

    query_engine = StealthQueryEngine(tor_engine, QueryConfig(block_non_tor=block_non_tor))

    print(f"[privacy] tor_verified={tor_ok}")
    if tor_engine.last_error:
        print(f"[privacy] notice={tor_engine.last_error}")

    try:
        result = query_engine.run_all(target)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"error: {exc}")
        return 1


def run_web(host: str, port: int) -> None:
    app = build_app()
    uvicorn.run(app, host=host, port=port)


def main() -> int:
    args = parse_args()

    if args.query:
        return run_cli(args.query, args.block_non_tor)

    run_web(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
