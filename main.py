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
    parser.add_argument(
        "--tor-update",
        choices=["auto", "off", "force"],
        default="auto",
        help="Tor managed-runtime update behavior",
    )
    parser.add_argument(
        "--tor-update-manifest",
        help="URL to JSON manifest: {version, windows_url, sha256}",
    )
    parser.add_argument(
        "--prefer-system-tor",
        action="store_true",
        help="Prefer installed system Tor over managed bundled runtime",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Web server bind host")
    parser.add_argument("--port", type=int, default=5000, help="Web server bind port")
    return parser.parse_args()


def create_tor_engine(args: argparse.Namespace) -> TorEngine:
    return TorEngine(
        tor_update_mode=args.tor_update,
        tor_update_manifest=args.tor_update_manifest,
        prefer_system_tor=args.prefer_system_tor,
    )


def run_cli(args: argparse.Namespace) -> int:
    if not args.query:
        return 1

    tor_engine = create_tor_engine(args)
    tor_ok = tor_engine.ensure_tor()

    query_engine = StealthQueryEngine(tor_engine, QueryConfig(block_non_tor=args.block_non_tor))

    print(f"[privacy] tor_verified={tor_ok}")
    if tor_engine.last_update_message:
        print(f"[privacy] tor_runtime={tor_engine.last_update_message}")
    if tor_engine.last_error:
        print(f"[privacy] notice={tor_engine.last_error}")

    try:
        result = query_engine.run_all(args.query)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"error: {exc}")
        return 1


def run_web(args: argparse.Namespace) -> None:
    app = build_app(
        tor_update_mode=args.tor_update,
        tor_update_manifest=args.tor_update_manifest,
        prefer_system_tor=args.prefer_system_tor,
    )
    uvicorn.run(app, host=args.host, port=args.port)


def main() -> int:
    args = parse_args()

    if args.query:
        return run_cli(args)

    run_web(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
