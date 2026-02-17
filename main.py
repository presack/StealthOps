"""StealthOps entrypoint with CLI and web modes."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from typing import Callable

import uvicorn

from core_ops import QueryConfig, StealthQueryEngine
from tor_engine import TorEngine
from web_ui import build_app


def human_label(key: str) -> str:
    labels = {
        "domain_name": "Domain Name",
        "creation_date": "Creation Date",
        "expiration_date": "Expiration Date",
        "updated_date": "Updated Date",
        "whois_server": "WHOIS Server",
        "canonical_name": "Canonical Name",
        "derived_domain": "Derived Domain",
        "aliases": "Aliases",
        "addresses": "Addresses",
        "address_lookup_error": "Address Lookup Error",
        "status_code": "Status Code",
        "final_url": "Final URL",
        "tor_routed": "Tor Routed",
        "whois_error": "WHOIS Error",
        "network_whois_error": "Network WHOIS Error",
        "network_whois_warning": "Network WHOIS Warning",
        "net_name": "Net Name",
        "net_type": "Net Type",
        "start_address": "Start Address",
        "end_address": "End Address",
        "ip_version": "IP Version",
        "abuse_email": "Abuse Email",
        "abuse_phone": "Abuse Phone",
        "rdap_url": "RDAP URL",
    }
    if key in labels:
        return labels[key]
    return key.replace("_", " ").strip().title()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="StealthOps - privacy-hardened reconnaissance utility")
    parser.add_argument("--query", help="Domain/URL target for CLI mode")
    parser.add_argument(
        "--console",
        action="store_true",
        help="Run interactive console mode",
    )
    parser.add_argument(
        "--install-tor",
        action="store_true",
        help="Install/update managed Tor runtime before query execution",
    )
    parser.add_argument(
        "--public-route",
        action="store_true",
        help="Bypass Tor and run queries over standard network route",
    )
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
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in console mode",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Web server bind host")
    parser.add_argument("--port", type=int, default=5000, help="Web server bind port")
    return parser.parse_args()


def create_tor_engine(args: argparse.Namespace, status_callback: Callable[[str], None] | None = None) -> TorEngine:
    return TorEngine(
        tor_update_mode=args.tor_update,
        tor_update_manifest=args.tor_update_manifest,
        prefer_system_tor=args.prefer_system_tor,
        status_callback=status_callback,
    )


def format_cli_report(result: dict) -> str:
    address_data = result.get("address", {})
    dns_data = result.get("dns", {})
    mx_data = result.get("mx", {})
    whois_data = result.get("whois", {})
    network_whois_data = result.get("network_whois", {})
    headers_data = result.get("headers", {})

    lines: list[str] = []
    lines.append("=== ADDRESS LOOKUP ===  [source: resolver + DNS records]")
    for field in ["query", "canonical_name", "derived_domain", "aliases", "addresses", "address_lookup_error"]:
        if field in address_data:
            value = address_data[field]
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "-"
            lines.append(f"{human_label(field)}: {value}")

    lines.append("")
    lines.append("=== WHOIS ===  [source: whois <domain>]")
    for field in ["domain_name", "registrar", "creation_date", "expiration_date", "status", "whois_error"]:
        if field in whois_data:
            value = whois_data[field]
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "-"
            lines.append(f"{human_label(field)}: {value}")

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
    lines.append("=== NETWORK WHOIS ===  [source: RDAP]")
    for field in [
        "ip",
        "organization",
        "net_name",
        "cidr",
        "start_address",
        "end_address",
        "country",
        "ip_version",
        "net_type",
        "abuse_email",
        "abuse_phone",
        "rdap_url",
        "network_whois_warning",
        "network_whois_error",
    ]:
        if field in network_whois_data:
            value = network_whois_data[field]
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "-"
            lines.append(f"{human_label(field)}: {value}")

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
    lines.append(f"URL: {headers_data.get('url', '-')}")
    lines.append(f"Status Code: {headers_data.get('status_code', '-')}")
    lines.append(f"Final URL: {headers_data.get('final_url', '-')}")
    lines.append(f"Tor Routed: {headers_data.get('tor_routed', '-')}")
    if "header_error" in headers_data:
        lines.append(f"header_error: {headers_data.get('header_error')}")
    else:
        lines.append("headers:")
        for key, value in headers_data.get("headers", {}).items():
            lines.append(f"- {key}: {value}")

    extra_dns = []
    for field in ("cname", "caa", "soa", "ptr"):
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


def _interactive_stdio() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _maybe_prompt_install_tor(tor_engine: TorEngine) -> bool:
    if not _interactive_stdio():
        return False
    try:
        answer = input("Tor is unavailable. Install managed Tor now? [Y/n]: ").strip().lower()
    except EOFError:
        return False
    if answer in ("", "y", "yes"):
        print("[privacy] starting managed Tor install/update")
        message = tor_engine.manage_tor_runtime(force_update=True)
        print(f"[privacy] tor_runtime={message}")
        return tor_engine.ensure_tor()
    return False


def _execute_query(query_engine: StealthQueryEngine, target: str, emit_json: bool, use_color: bool = False) -> int:
    try:
        result = query_engine.run_all(target)
        if emit_json:
            print(json.dumps(result, indent=2))
        else:
            print(_colorize_report(format_cli_report(result), use_color))
        return 0
    except Exception as exc:
        print(f"error: {exc}")
        return 1


def _colorize_report(report: str, use_color: bool) -> str:
    if not use_color:
        return report
    out = []
    for line in report.splitlines():
        if line.startswith("==="):
            out.append(_c(True, line, "96"))
        elif line.startswith("error:"):
            out.append(_c(True, line, "91"))
        else:
            out.append(line)
    return "\n".join(out)


def _truncate_text(value: str, max_len: int = 64) -> str:
    text = value.strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def _color_enabled(args: argparse.Namespace) -> bool:
    if args.no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return _interactive_stdio()


def _c(enabled: bool, text: str, code: str) -> str:
    if not enabled:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def _render_console_banner(
    query_engine: StealthQueryEngine,
    tor_engine: TorEngine,
    tor_ok: bool,
    emit_json: bool,
    use_color: bool,
) -> str:
    title = _c(use_color, "[ PRIVACY-CENTRIC NETWORK INTELLIGENCE ]", "92")
    rule = _c(use_color, "  _____________________________________________________________", "90")
    art_lines = [
        "  ____  _             _ _   _      ___               ",
        " / ___|| |_ ___  __ _| | |_| |__  / _ \\ _ __  ___   ",
        " \\___ \\| __/ _ \\/ _` | | __| '_ \\| | | | '_ \\/ __|  ",
        "  ___) | ||  __/ (_| | | |_| | | | |_| | |_) \\__ \\  ",
        " |____/ \\__\\___|\\__,_|_|\\__|_| |_|\\___/| .__/|___/  ",
        "                                        |_|          ",
    ]
    art = "\n".join(_c(use_color, line, "36") for line in art_lines)

    return (
        f"{art}\n"
        f"   {title}\n"
        "\n"
        f"{_render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color)}\n"
        f"{rule}"
    )


def _render_status_lines(
    query_engine: StealthQueryEngine,
    tor_engine: TorEngine,
    tor_ok: bool,
    emit_json: bool,
    use_color: bool,
) -> str:
    route = "Stealth" if query_engine.config.route_mode == "stealth" else "Public"
    if query_engine.config.route_mode == "public":
        tor_status = "Bypassed (Public Mode)"
    elif tor_ok:
        tor_status = f"Socks Proxy {tor_engine.socks_host}:{tor_engine.socks_port}"
    else:
        err = _truncate_text(tor_engine.last_error or "Unavailable")
        tor_status = f"Unavailable ({err})"

    block_mode = "On" if query_engine.config.block_non_tor else "Off"
    output_mode = "JSON" if emit_json else "Pretty"
    route_disp = _c(use_color, route, "96" if route == "Stealth" else "93")
    tor_disp = _c(use_color, tor_status, "92" if tor_ok and query_engine.config.route_mode == "stealth" else "93")
    block_disp = _c(use_color, block_mode, "91" if block_mode == "On" else "90")
    output_disp = _c(use_color, output_mode, "95" if output_mode == "JSON" else "97")

    return (
        f"  > Route Mode ...................... [{route_disp}]\n"
        f"  > TOR Routing ..................... [{tor_disp}]\n"
        f"  > Block Non-TOR ................... [{block_disp}]\n"
        f"  > Output Mode ..................... [{output_disp}]"
    )


def run_cli(args: argparse.Namespace) -> int:
    if not args.query:
        return 1

    route_mode = "public" if args.public_route else "stealth"
    tor_engine = create_tor_engine(args, status_callback=lambda msg: print(f"[privacy] tor_runtime={msg}"))
    if args.install_tor:
        print("[privacy] starting managed Tor install/update")
        message = tor_engine.manage_tor_runtime(force_update=True)
        print(f"[privacy] tor_runtime={message}")
    tor_ok = tor_engine.ensure_tor() if route_mode == "stealth" else False
    if route_mode == "stealth" and not tor_ok and not args.install_tor and not args.block_non_tor:
        tor_ok = _maybe_prompt_install_tor(tor_engine)

    query_engine = StealthQueryEngine(
        tor_engine,
        QueryConfig(
            block_non_tor=args.block_non_tor,
            route_mode=route_mode,
        ),
    )

    print(f"[privacy] tor_verified={tor_ok}")
    if route_mode == "public":
        print("[privacy] route_mode=public")
    if tor_engine.last_update_message:
        print(f"[privacy] tor_runtime={tor_engine.last_update_message}")
    if tor_engine.last_error:
        print(f"[privacy] notice={tor_engine.last_error}")

    return _execute_query(query_engine, args.query, args.json, use_color=False)


def run_console(args: argparse.Namespace) -> int:
    route_mode = "public" if args.public_route else "stealth"
    emit_json = bool(args.json)
    block_non_tor = bool(args.block_non_tor)

    tor_engine = create_tor_engine(args, status_callback=lambda msg: print(f"[privacy] tor_runtime={msg}"))
    use_color = _color_enabled(args)
    if args.install_tor:
        print("[privacy] starting managed Tor install/update")
        message = tor_engine.manage_tor_runtime(force_update=True)
        print(f"[privacy] tor_runtime={message}")

    tor_ok = tor_engine.ensure_tor() if route_mode == "stealth" else False
    if route_mode == "stealth" and not tor_ok and not args.install_tor and not block_non_tor:
        tor_ok = _maybe_prompt_install_tor(tor_engine)

    query_engine = StealthQueryEngine(
        tor_engine,
        QueryConfig(block_non_tor=block_non_tor, route_mode=route_mode),
    )

    os.system("cls" if os.name == "nt" else "clear")
    print(_render_console_banner(query_engine, tor_engine, tor_ok, emit_json, use_color))
    print("")
    print("Type 'help' for commands.")
    print("")

    while True:
        try:
            raw = input("stealthops> ").strip()
        except EOFError:
            print("")
            return 0
        except KeyboardInterrupt:
            print("")
            return 0

        if not raw:
            continue

        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            print(f"error: {exc}")
            continue

        cmd = parts[0].lower()
        if cmd in {"exit", "quit"}:
            return 0
        if cmd == "help":
            print("Commands:")
            print("  query <target>         run lookup on target")
            print("  mode <stealth|public>  set routing mode")
            print("  tor install            install/update managed Tor runtime")
            print("  tor status             show Tor status")
            print("  banner                 print full intro banner")
            print("  status                 print console status banner")
            print("  block <on|off>         set block non-tor mode")
            print("  json <on|off>          toggle JSON output")
            print("  clear                  clear the screen")
            print("  exit                   quit console")
            print("")
            continue
        if cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            print("")
            continue
        if cmd == "banner":
            print(_render_console_banner(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue
        if cmd == "status":
            print(_render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue
        if cmd == "query":
            if len(parts) < 2:
                print("usage: query <target>")
                print("")
                continue
            target = parts[1]
            _execute_query(query_engine, target, emit_json, use_color=use_color)
            print("")
            continue
        if cmd == "mode":
            if len(parts) != 2 or parts[1].lower() not in {"stealth", "public"}:
                print("usage: mode <stealth|public>")
                print("")
                continue
            route_mode = parts[1].lower()
            query_engine.config.route_mode = route_mode
            if route_mode == "stealth":
                tor_ok = tor_engine.ensure_tor()
                if not tor_ok and not query_engine.config.block_non_tor:
                    tor_ok = _maybe_prompt_install_tor(tor_engine)
            else:
                tor_ok = False
            print(_render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue
        if cmd == "tor":
            if len(parts) != 2 or parts[1].lower() not in {"install", "status"}:
                print("usage: tor <install|status>")
                print("")
                continue
            action = parts[1].lower()
            if action == "install":
                print("[privacy] starting managed Tor install/update")
                message = tor_engine.manage_tor_runtime(force_update=True)
                print(f"[privacy] tor_runtime={message}")
                tor_ok = tor_engine.ensure_tor() if query_engine.config.route_mode == "stealth" else False
                print(_render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            else:
                if query_engine.config.route_mode == "stealth":
                    tor_ok = tor_engine.ensure_tor()
                print(_render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
                if tor_engine.last_update_message:
                    print(f"[privacy] tor_runtime={tor_engine.last_update_message}")
                if tor_engine.last_error:
                    print(f"[privacy] notice={tor_engine.last_error}")
            print("")
            continue
        if cmd == "block":
            if len(parts) != 2 or parts[1].lower() not in {"on", "off"}:
                print("usage: block <on|off>")
                print("")
                continue
            block_non_tor = parts[1].lower() == "on"
            query_engine.config.block_non_tor = block_non_tor
            print(_render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue
        if cmd == "json":
            if len(parts) != 2 or parts[1].lower() not in {"on", "off"}:
                print("usage: json <on|off>")
                print("")
                continue
            emit_json = parts[1].lower() == "on"
            print(_render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue

        print("unknown command. type 'help'")
        print("")


def run_web(args: argparse.Namespace) -> None:
    app = build_app(
        tor_update_mode=args.tor_update,
        tor_update_manifest=args.tor_update_manifest,
        prefer_system_tor=args.prefer_system_tor,
    )
    uvicorn.run(app, host=args.host, port=args.port)


def main() -> int:
    args = parse_args()

    if args.install_tor and not args.query and not args.console:
        tor_engine = create_tor_engine(args, status_callback=lambda msg: print(f"[privacy] tor_runtime={msg}"))
        print("[privacy] starting managed Tor install/update")
        message = tor_engine.manage_tor_runtime(force_update=True)
        print(f"[privacy] tor_runtime={message}")
        return 0

    if args.console:
        return run_console(args)

    if args.query:
        return run_cli(args)

    run_web(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
