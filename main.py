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
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit raw JSON results in CLI mode",
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


def format_cli_report(result: dict) -> str:
    dns_data = result.get("dns", {})
    mx_data = result.get("mx", {})
    whois_data = result.get("whois", {})
    headers_data = result.get("headers", {})

    lines: list[str] = []
    lines.append("=== WHOIS ===  [source: whois <domain>]")
    for field in ["domain_name", "registrar", "creation_date", "expiration_date", "status", "whois_error"]:
        if field in whois_data:
            value = whois_data[field]
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "-"
            lines.append(f"{field}: {value}")

    lines.append("")
    lines.append("=== DNS SUMMARY ===  [source: dns query A/AAAA]")
    lines.append(f"domain: {dns_data.get('domain', '-')}")
    lines.append(f"A: {', '.join(dns_data.get('a', [])) or '-'}")
    lines.append(f"AAAA: {', '.join(dns_data.get('aaaa', [])) or '-'}")

    lines.append("")
    lines.append("=== MX RECORDS ===  [source: dns query MX]")
    lines.append(f"Domain: {mx_data.get('domain', '-')}")
    mx_records = mx_data.get("mx", [])
    if mx_records:
        for entry in mx_records:
            lines.append(f"- {entry.get('priority', '-')}: {entry.get('host', '-')}")
    else:
        lines.append("- none")
    if "mx_warning" in mx_data:
        lines.append(f"mx_warning: {mx_data.get('mx_warning')}")
    if "mx_error" in mx_data:
        lines.append(f"mx_error: {mx_data.get('mx_error')}")

    lines.append("")
    lines.append("=== NS RECORDS ===  [source: dns query NS]")
    ns_records = dns_data.get("ns", [])
    if ns_records:
        for value in ns_records:
            lines.append(f"- {value}")
    else:
        lines.append("- none")

    lines.append("")
    lines.append("=== TXT RECORDS ===  [source: dns query TXT]")
    txt_records = dns_data.get("txt", [])
    if txt_records:
        for value in txt_records:
            lines.append(f"- {value}")
    else:
        lines.append("- none")

    lines.append("")
    lines.append("=== HTTP HEADERS ===  [source: GET + response headers]")
    lines.append(f"url: {headers_data.get('url', '-')}")
    lines.append(f"status_code: {headers_data.get('status_code', '-')}")
    lines.append(f"final_url: {headers_data.get('final_url', '-')}")
    lines.append(f"tor_routed: {headers_data.get('tor_routed', '-')}")
    if "header_error" in headers_data:
        lines.append(f"header_error: {headers_data.get('header_error')}")
    else:
        lines.append("headers:")
        for key, value in headers_data.get("headers", {}).items():
            lines.append(f"- {key}: {value}")

    extra_dns = []
    for field in ("cname", "caa", "soa"):
        vals = dns_data.get(field, [])
        if vals:
            extra_dns.append(f"{field.upper()}: {', '.join(vals)}")
    dns_notes = [f"{k}: {dns_data.get(k)}" for k in sorted(k for k in dns_data.keys() if k.endswith(("_error", "_warning")))]
    if extra_dns or dns_notes:
        lines.append("")
        lines.append("=== ADDITIONAL DNS ===")
        lines.extend(extra_dns)
        lines.extend(dns_notes)

    return "\n".join(lines)


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
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(format_cli_report(result))
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
