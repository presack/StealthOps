"""StealthOps entrypoint with CLI and web modes."""

from __future__ import annotations

import argparse
import os

from _version import __version__
from console import _maybe_prompt_install_tor, run_console
from core_ops import QueryConfig, StealthQueryEngine, internet_available
from enrichment import EnrichmentManager, parse_enrichment_selection
from formatter import _c, color_enabled, interactive_stdio
from runner import execute_enrichment_only, execute_query
from tor_engine import TorEngine
from updater import check_for_update_background, cleanup_old_binary, do_update, get_update_notice
from utils import refang
from web_ui import build_app

_SERVER_MODE  = bool(os.environ.get("SERVER_MODE"))
_TRAINING_MODE = bool(os.environ.get("TRAINING_MODE"))


def parse_args() -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    parser = argparse.ArgumentParser(description="StealthOps - privacy-hardened reconnaissance utility")
    parser.add_argument("--version", action="version", version=f"StealthOps {__version__}")
    parser.add_argument("target", nargs="?", help="Domain, URL, or IP to query")
    parser.add_argument("--query", metavar="TARGET",
                        help="Named alternative to the positional target (useful in scripts)")

    exec_grp = parser.add_argument_group("execution mode")
    exec_grp.add_argument("--console", action="store_true", help="Start the interactive console (REPL)")
    exec_grp.add_argument("--web", action="store_true", help="Start the web dashboard")
    exec_grp.add_argument("--update", action="store_true",
                          help="Check for and apply the latest release from GitHub")

    query_grp = parser.add_argument_group("query options")
    query_grp.add_argument("--json", action="store_true", help="Output raw JSON instead of a formatted report")
    query_grp.add_argument("--headers", action="store_true", help="Include HTTP header inspection")
    query_grp.add_argument("--enrich", default="off", metavar="PROVIDERS",
                           help="Enrichment providers: off, all, or comma-separated list (e.g. virustotal,spur)")
    query_grp.add_argument("--enrich-only", action="store_true",
                           help="Run enrichment providers only, skip core query (requires --enrich)")
    query_grp.add_argument("--pdf", nargs="?", const=True, default=None, metavar="PATH",
                           help="Save a PDF report after the query (default path: ~/Downloads)")
    query_grp.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    tor_grp = parser.add_argument_group("routing / Tor")
    tor_grp.add_argument("--mode", choices=["stealth", "public"], default=None,
                         help="Routing mode: stealth (via Tor) or public (direct); default: public")
    tor_grp.add_argument("--block-non-tor", action="store_true",
                         help="Abort the query if Tor is unavailable (stealth mode only)")
    tor_grp.add_argument("--install-tor", action="store_true",
                         help="Install or update the managed Tor runtime, then continue")
    tor_grp.add_argument("--tor-update", choices=["auto", "off", "force"], default="auto",
                         help="Managed-runtime update policy: auto (default), off, or force")
    tor_grp.add_argument("--tor-update-manifest", metavar="URL_OR_PATH",
                         help="Custom Tor manifest (JSON: {version, download_url, sha256})")
    tor_grp.add_argument("--prefer-system-tor", action="store_true",
                         help="Prefer system-installed Tor over the managed runtime")

    keys_grp = parser.add_argument_group("key management")
    keys_grp.add_argument("--providers", action="store_true",
                          help="Show enrichment provider status and API key info, then exit")
    keys_grp.add_argument("--configure-keys", action="store_true",
                          help="Interactive API key setup wizard (personal mode)")
    keys_grp.add_argument("--set-key", nargs=2, metavar=("PROVIDER", "KEY"),
                          help="Set a provider API key (personal: saves to keystore;"
                               " SERVER_MODE: use with --username or --all-users)")

    web_grp = parser.add_argument_group("web server")
    web_grp.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    web_grp.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")

    admin_grp = parser.add_argument_group("server admin (SERVER_MODE only)")
    admin_grp.add_argument("--create-user", metavar="USERNAME",
                           help="Create a user account (prompts for password)")
    admin_grp.add_argument("--delete-user", metavar="USERNAME", help="Delete a user account")
    admin_grp.add_argument("--list-users", action="store_true", help="List all user accounts")
    admin_grp.add_argument("--reset-password", metavar="USERNAME",
                           help="Reset a user's password (prompts for new password)")
    admin_grp.add_argument("--delete-key", nargs=2, metavar=("USERNAME", "PROVIDER"),
                           help="Remove a user's provider key")
    admin_grp.add_argument("--copy-keys", nargs=2, metavar=("FROM_USER", "TO_USER"),
                           help="Copy all provider keys from one user to another")
    admin_grp.add_argument("--username", metavar="USERNAME", help="Target username for --set-key")
    admin_grp.add_argument("--all-users", action="store_true",
                           help="Apply --set-key to every existing user")
    admin_grp.add_argument("--generate-fernet-key", action="store_true",
                           help="Generate and print a new FERNET_KEY value")

    return parser, parser.parse_args()


def create_tor_engine(args: argparse.Namespace, status_callback=None) -> TorEngine:
    return TorEngine(
        tor_update_mode=args.tor_update,
        tor_update_manifest=args.tor_update_manifest,
        prefer_system_tor=args.prefer_system_tor,
        status_callback=status_callback,
    )


def run_cli(args: argparse.Namespace) -> int:
    target = args.query or args.target
    if not target:
        return 1
    target = refang(target)

    route_mode = args.mode or "public"
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
        QueryConfig(block_non_tor=args.block_non_tor, route_mode=route_mode),
    )
    enrichment_manager = EnrichmentManager()
    use_color = color_enabled(args.no_color) and not args.json

    if args.enrich_only:
        if not parse_enrichment_selection(args.enrich):
            print("error: --enrich-only requires --enrich with one or more providers")
            return 1
        return execute_enrichment_only(enrichment_manager, target, args.enrich, args.json, use_color=use_color)

    if route_mode == "stealth":
        print(f"[privacy] tor_verified={tor_ok}")
        if tor_engine.last_update_message:
            print(f"[privacy] tor_runtime={tor_engine.last_update_message}")
        if tor_engine.last_error:
            print(f"[privacy] notice={tor_engine.last_error}")

    rc, result_data = execute_query(
        query_engine, target, args.json,
        use_color=use_color, include_headers=bool(args.headers),
        enrichment_manager=enrichment_manager, enrichment_selection=args.enrich,
    )
    if rc == 0 and result_data is not None and args.pdf is not None:
        try:
            from report import generate_report
            pdf_path = None if args.pdf is True else args.pdf
            saved = generate_report(target, result_data, out_path=pdf_path, route_mode=route_mode)
            print(f"report saved: {saved}")
        except RuntimeError as exc:
            print(f"error: {exc}")
        except Exception as exc:
            print(f"error generating PDF report: {exc}")
    if interactive_stdio():
        notice = get_update_notice(use_color)
        if notice:
            print(notice)
    return rc


def run_web(args: argparse.Namespace, host_override: str | None = None, port_override: int | None = None) -> None:
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Web mode requires uvicorn. Rebuild with dependencies installed (python -m pip install -r requirements.txt)."
        ) from exc
    app = build_app(
        tor_update_mode=args.tor_update,
        tor_update_manifest=args.tor_update_manifest,
        prefer_system_tor=args.prefer_system_tor,
    )
    if not internet_available(timeout=1.0):
        print("[notice] internet connectivity check failed; queries will fail until connectivity returns")
    uvicorn.run(
        app,
        host=host_override or args.host,
        port=port_override or args.port,
        use_colors=False,
        # Trust X-Forwarded-For from localhost only (nginx reverse proxy).
        # Keeps per-IP rate limiting correct when running behind nginx.
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )


def main() -> int:
    parser, args = parse_args()

    # Startup housekeeping for personal mode (skip on server/training deployments)
    if not _SERVER_MODE and not _TRAINING_MODE:
        from keystore import load_into_environ
        load_into_environ()
        cleanup_old_binary()
        check_for_update_background()

    if args.update:
        do_update(use_color=color_enabled(args.no_color))
        return 0

    if args.configure_keys:
        if _SERVER_MODE:
            print("In SERVER_MODE, manage keys via the web UI at /settings")
            return 0
        from keystore import run_setup_wizard
        run_setup_wizard()
        return 0

    if args.providers:
        import os as _os
        manager = EnrichmentManager()
        _key_data = None
        if not _os.environ.get("SERVER_MODE"):
            from keystore import get_all as _ks_all
            _key_data = _ks_all()
        for line in manager.format_provider_status_lines(key_data=_key_data):
            print(line)
        return 0

    if args.generate_fernet_key:
        from cryptography.fernet import Fernet
        print(Fernet.generate_key().decode())
        return 0

    _admin_cmds = any([
        args.create_user, args.delete_user, args.list_users, args.reset_password,
        args.set_key, args.delete_key, args.copy_keys,
    ])
    if _admin_cmds:
        # Personal mode --set-key: write to keystore, no auth module needed
        if args.set_key and not _SERVER_MODE:
            from keystore import set_key as _ks_set
            provider, key = args.set_key
            if _ks_set(provider.lower(), key):
                print(f"key saved for {provider}")
            else:
                print(f"error: unknown provider '{provider}'")
            return 0

        import auth as _auth
        import getpass

        if args.list_users:
            users = _auth.list_users()
            if users:
                for u in users:
                    print(u)
            else:
                print("(no users)")
            return 0

        if args.create_user:
            password = getpass.getpass(f"Password for '{args.create_user}': ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("error: passwords do not match")
                return 1
            if _auth.create_user(args.create_user, password):
                print(f"user '{args.create_user}' created")
            else:
                print(f"error: user '{args.create_user}' already exists")
                return 1
            return 0

        if args.delete_user:
            if _auth.delete_user(args.delete_user):
                print(f"user '{args.delete_user}' deleted")
            else:
                print(f"error: user '{args.delete_user}' not found")
                return 1
            return 0

        if args.reset_password:
            new_pass = getpass.getpass(f"New password for '{args.reset_password}': ")
            confirm = getpass.getpass("Confirm password: ")
            if new_pass != confirm:
                print("error: passwords do not match")
                return 1
            if _auth.admin_reset_password(args.reset_password, new_pass):
                print(f"password reset for '{args.reset_password}'")
            else:
                print(f"error: user '{args.reset_password}' not found")
                return 1
            return 0

        if args.set_key:
            provider, key = args.set_key
            if args.all_users:
                count = _auth.set_key_all_users(provider, key)
                print(f"set {provider} key for {count} user(s)")
            elif args.username:
                if _auth.set_key(args.username, provider, key):
                    print(f"set {provider} key for '{args.username}'")
                else:
                    print(f"error: user '{args.username}' not found")
                    return 1
            else:
                print("error: --set-key requires --username <user> or --all-users")
                return 1
            return 0

        if args.delete_key:
            username, provider = args.delete_key
            _auth.delete_key(username, provider)
            print(f"removed {provider} key for '{username}'")
            return 0

        if args.copy_keys:
            from_user, to_user = args.copy_keys
            count = _auth.copy_keys(from_user, to_user)
            print(f"copied {count} key(s) from '{from_user}' to '{to_user}'")
            return 0

    if args.install_tor and not args.query and not args.target and not args.console and not args.web:
        tor_engine = create_tor_engine(args, status_callback=lambda msg: print(f"[privacy] tor_runtime={msg}"))
        print("[privacy] starting managed Tor install/update")
        message = tor_engine.manage_tor_runtime(force_update=True)
        print(f"[privacy] tor_runtime={message}")
        return 0

    no_explicit_action = not any([args.query, args.target, args.console, args.web, args.install_tor])
    if no_explicit_action:
        parser.print_help()
        if interactive_stdio():
            use_color = color_enabled(args.no_color)
            print("")
            print(_c(use_color, "Quick Start", "1;96"))
            print(f"  {_c(use_color, '1', '1;93')}. {_c(use_color, 'Start Web + Console', '92')}")
            print(f"  {_c(use_color, '2', '1;93')}. {_c(use_color, 'Start Console', '92')}")
            print(f"  {_c(use_color, '3', '1;93')}. {_c(use_color, 'Exit', '92')}")
            prompt = f"{_c(use_color, '>', '96')} Select option [Enter to exit]: " if use_color else "Select option [Enter to exit]: "
            try:
                choice = input(prompt).strip()
            except EOFError:
                return 0
            if choice == "1":
                from console import run_web_background
                tor_engine = create_tor_engine(args, status_callback=lambda msg: print(f"[privacy] tor_runtime={msg}"))
                host = args.host
                port = args.port
                web_process = run_web_background(args, host_override=host, port_override=port)
                print(f"[web] pid={web_process.pid} url=http://{host}:{port}")
                print("")
                return run_console(args, tor_engine)
            if choice == "2":
                tor_engine = create_tor_engine(args, status_callback=lambda msg: print(f"[privacy] tor_runtime={msg}"))
                return run_console(args, tor_engine)
            return 0
        return 0

    if args.console:
        tor_engine = create_tor_engine(args, status_callback=lambda msg: print(f"[privacy] tor_runtime={msg}"))
        return run_console(args, tor_engine)

    if args.query or args.target:
        return run_cli(args)

    if args.web:
        run_web(args)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
