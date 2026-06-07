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
from web_ui import build_app


def parse_args() -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    parser = argparse.ArgumentParser(description="StealthOps - privacy-hardened reconnaissance utility")
    parser.add_argument("--version", action="version", version=f"StealthOps {__version__}")
    parser.add_argument("target", nargs="?", help="Domain/URL/IP target for CLI mode")
    parser.add_argument("--query", help="Domain/URL target for CLI mode")
    parser.add_argument("--web", action="store_true", help="Run web server mode")
    parser.add_argument("--console", action="store_true", help="Run interactive console mode")
    parser.add_argument("--install-tor", action="store_true", help="Install/update managed Tor runtime before query execution")
    parser.add_argument("--public-route", action="store_true", help="Bypass Tor and run queries over standard network route")
    parser.add_argument("--mode", choices=["stealth", "public"], help="Routing mode for CLI/console (overrides --public-route)")
    parser.add_argument("--block-non-tor", action="store_true", help="Fail requests if Tor is unavailable")
    parser.add_argument("--tor-update", choices=["auto", "off", "force"], default="auto", help="Tor managed-runtime update behavior")
    parser.add_argument("--tor-update-manifest", help="URL to JSON manifest: {version, windows_url, sha256}")
    parser.add_argument("--prefer-system-tor", action="store_true", help="Prefer installed system Tor over managed bundled runtime")
    parser.add_argument("--json", action="store_true", help="Emit raw JSON results in CLI mode")
    parser.add_argument("--headers", action="store_true", help="Include HTTP header inspection in CLI/console queries")
    parser.add_argument("--enrich", default="off", help="Optional enrichment providers: off, all-enabled, allip, alldns, allasn, or CSV (e.g. virustotal,spur)")
    parser.add_argument("--enrich-only", action="store_true", help="Run only enrichment providers (requires --enrich)")
    parser.add_argument("--providers", action="store_true", help="Show enrichment provider/key status and exit")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in console/CLI output")
    parser.add_argument("--pdf", nargs="?", const=True, default=None, metavar="PATH",
                        help="Save a PDF report to PATH after the query (default: ~/Downloads)")
    parser.add_argument("--host", default="127.0.0.1", help="Web server bind host")
    parser.add_argument("--port", type=int, default=5000, help="Web server bind port")
    # Server mode admin commands
    parser.add_argument("--create-user", metavar="USERNAME", help="SERVER_MODE: create a user account (prompts for password)")
    parser.add_argument("--delete-user", metavar="USERNAME", help="SERVER_MODE: delete a user account")
    parser.add_argument("--list-users", action="store_true", help="SERVER_MODE: list all user accounts")
    parser.add_argument("--reset-password", metavar="USERNAME", help="SERVER_MODE: reset a user's password (prompts for new password)")
    parser.add_argument("--set-key", nargs=2, metavar=("PROVIDER", "KEY"), help="SERVER_MODE: set a provider API key (use with --username or --all-users)")
    parser.add_argument("--delete-key", nargs=2, metavar=("USERNAME", "PROVIDER"), help="SERVER_MODE: remove a user's provider key")
    parser.add_argument("--copy-keys", nargs=2, metavar=("FROM_USER", "TO_USER"), help="SERVER_MODE: copy all keys from one user to another")
    parser.add_argument("--username", metavar="USERNAME", help="Target username for --set-key")
    parser.add_argument("--all-users", action="store_true", help="Apply --set-key to all existing users")
    parser.add_argument("--generate-fernet-key", action="store_true", help="Generate and print a new FERNET_KEY value")
    parser.add_argument("--update", action="store_true", help="Check for and apply the latest release from GitHub")
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
    if not os.environ.get("SERVER_MODE") and not os.environ.get("TRAINING_MODE"):
        cleanup_old_binary()
        check_for_update_background()

    if args.update:
        do_update(use_color=color_enabled(args.no_color))
        return 0

    if args.providers:
        manager = EnrichmentManager()
        for line in manager.format_provider_status_lines():
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
            print(f"  {_c(use_color, '1', '1;93')}. {_c(use_color, 'Start Web Server', '92')}")
            print(f"  {_c(use_color, '2', '1;93')}. {_c(use_color, 'Start Console', '92')}")
            print(f"  {_c(use_color, '3', '1;93')}. {_c(use_color, 'Exit', '92')}")
            prompt = f"{_c(use_color, '>', '96')} Select option [Enter to exit]: " if use_color else "Select option [Enter to exit]: "
            try:
                choice = input(prompt).strip()
            except EOFError:
                return 0
            if choice == "1":
                run_web(args)
                return 0
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
