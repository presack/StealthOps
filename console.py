"""Interactive console REPL for StealthOps."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

try:
    import readline  # noqa: F401  enables arrow-key history for input() on Linux
except ImportError:
    pass

from _version import __version__
from core_ops import QueryConfig, StealthQueryEngine, internet_available
from enrichment import EnrichmentManager, PROVIDER_ALIASES
from formatter import (
    _c,
    color_enabled,
    interactive_stdio,
    truncate_text,
)
import cache as _cache_module
import time as _time_module

from runner import execute_enrichment_only, execute_query
from tor_engine import TorEngine
from utils import refang


def render_console_banner(
    query_engine: StealthQueryEngine,
    tor_engine: TorEngine,
    tor_ok: bool,
    emit_json: bool,
    use_color: bool,
) -> str:
    title = _c(use_color, f"[ PRIVACY-CENTRIC NETWORK INTELLIGENCE ]  v{__version__}", "92")
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
    banner = (
        f"{art}\n"
        f"   {title}\n"
        "\n"
        f"{render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color)}\n"
        f"{rule}"
    )
    from updater import get_update_notice
    notice = get_update_notice(use_color)
    if notice:
        banner += f"\n{notice}"
    return banner


def render_status_lines(
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
        err = truncate_text(tor_engine.last_error or "Unavailable")
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


def run_web_background(
    args: argparse.Namespace,
    host_override: str | None = None,
    port_override: int | None = None,
) -> subprocess.Popen:
    host = host_override or args.host
    port = str(port_override or args.port)
    tor_update = args.tor_update

    _main_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "--web", "--host", host, "--port", port, "--tor-update", tor_update]
    else:
        cmd = [sys.executable, _main_py, "--web", "--host", host, "--port", port, "--tor-update", tor_update]

    if args.tor_update_manifest:
        cmd.extend(["--tor-update-manifest", args.tor_update_manifest])
    if args.prefer_system_tor:
        cmd.append("--prefer-system-tor")

    return subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_console(args: argparse.Namespace, tor_engine: TorEngine) -> int:
    route_mode = args.mode or "public"
    emit_json = bool(args.json)
    block_non_tor = bool(args.block_non_tor)
    include_headers = bool(args.headers)
    enrich_selection = str(args.enrich or "off")
    use_color = color_enabled(args.no_color)

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
    enrichment_manager = EnrichmentManager()

    os.system("cls" if os.name == "nt" else "clear")
    print(render_console_banner(query_engine, tor_engine, tor_ok, emit_json, use_color))
    print("")
    print("Type 'help' for commands.")
    print("")
    web_process: subprocess.Popen | None = None
    last_target: str = ""
    session_history: dict[str, dict] = {}  # target -> result data, most recent last

    def shutdown_web() -> None:
        nonlocal web_process
        if not web_process:
            return
        try:
            if web_process.poll() is None:
                web_process.terminate()
                web_process.wait(timeout=2.0)
        except Exception:
            try:
                if web_process.poll() is None:
                    web_process.kill()
            except Exception:
                pass
        web_process = None

    while True:
        try:
            raw_in = input("stealthops> ")
        except EOFError:
            shutdown_web()
            print("")
            return 0
        except KeyboardInterrupt:
            shutdown_web()
            print("")
            return 0

        if "\x0c" in raw_in and raw_in.replace("\x0c", "").strip() == "":
            os.system("cls" if os.name == "nt" else "clear")
            print("")
            continue

        raw = raw_in.strip()
        if not raw:
            continue

        # Re-sync keystore file → os.environ and rebuild the enrichment manager
        # so keys saved externally (web UI, another terminal) take effect
        # immediately without restarting the console.
        if not os.environ.get("SERVER_MODE") and not os.environ.get("TRAINING_MODE"):
            try:
                from keystore import sync_into_environ as _ks_sync
                _ks_sync()
                enrichment_manager.reload_keys()
            except ImportError:
                pass

        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            print(f"error: {exc}")
            continue

        cmd = parts[0].lower()

        if cmd in {"exit", "quit"}:
            shutdown_web()
            return 0

        if cmd == "help":
            def _h(text: str) -> str:
                return _c(use_color, text, "1;96")
            print("")
            print(f"  {_h('Query')}")
            print("    <target>                       run lookup (e.g. 8.8.8.8 or example.com)")
            print("    last [clear]                   show or clear last successful target")
            print("    reload                         re-run last query bypassing 6h cache")
            print("    full                           re-display last result with all truncation removed")
            print("")
            print(f"  {_h('Enrichment')}")
            print("    enrich <all|off|provider,...>  set persistent enrichment mode")
            print("    all [target]                   run all providers now (uses last target if omitted)")
            print("    <provider> [target]            run single provider (uses last target if omitted)")
            print("    providers                      provider status, keys, aliases, and session usage")
            print("")
            print(f"  {_h('Keys')}")
            print("    set-key [provider key]         add or update API key (no args = wizard)")
            print("    delete-key <provider>          remove a key")
            print("")
            print(f"  {_h('Output')}")
            print("    json <on|off>                  toggle JSON output")
            print("    headers <on|off>               toggle HTTP header inspection")
            print("    report [target] [path]         save PDF report (default: ~/Downloads)")
            print("    bulk [file]                    triage indicators to CSV (paste or file, saved to ~/Downloads)")
            print("")
            print(f"  {_h('Routing')}")
            print("    mode <stealth|public>          switch routing mode")
            print("    block <on|off>                 block non-Tor traffic")
            print("    tor install|status             Tor runtime management")
            print("")
            print(f"  {_h('Session')}")
            print("    web [host] [port]              start web server in background")
            print("    status                         print console status")
            print("    clear / version / update       utility commands")
            print("    exit                           quit")
            print("")
            continue

        if cmd == "version":
            print(f"StealthOps {__version__}")
            print("")
            continue

        if cmd == "update":
            from updater import do_update
            do_update(use_color)
            continue

        if cmd == "keys":
            import os as _os
            if _os.environ.get("SERVER_MODE"):
                print("In SERVER_MODE — manage keys via the web UI at /settings")
                print("")
                continue
            from keystore import get_all as _ks_all
            _key_data = _ks_all()
            for line in enrichment_manager.format_provider_status_lines(use_color=use_color, key_data=_key_data):
                print(line)
            continue

        if cmd == "set-key":
            import os as _os
            if _os.environ.get("SERVER_MODE"):
                print("In SERVER_MODE — manage keys via the web UI at /settings")
                print("")
                continue
            if len(parts) == 1:
                from keystore import run_setup_wizard
                run_setup_wizard()
            elif len(parts) == 3:
                from keystore import set_key as _ks_set, WIZARD_ORDER as _WO
                provider_arg = parts[1].lower()
                if provider_arg not in _WO:
                    print(f"error: unknown provider '{parts[1]}'")
                    print(f"  known providers: {', '.join(_WO)}")
                elif _ks_set(provider_arg, parts[2]):
                    print(f"key saved for {parts[1]}")
                else:
                    print(f"error: could not save key for '{parts[1]}'")
            else:
                print("usage: set-key [provider key]")
            print("")
            continue

        if cmd == "delete-key":
            import os as _os
            if _os.environ.get("SERVER_MODE"):
                print("In SERVER_MODE — manage keys via the web UI at /settings")
                print("")
                continue
            if len(parts) != 2:
                print("usage: delete-key <provider>")
                print("")
                continue
            from keystore import delete_key as _ks_del, WIZARD_ORDER as _WO
            provider_arg = parts[1].lower()
            if provider_arg not in _WO:
                print(f"error: unknown provider '{parts[1]}'")
                print(f"  known providers: {', '.join(_WO)}")
            elif _ks_del(provider_arg):
                print(f"key removed for {parts[1]}")
            else:
                print(f"error: could not remove key for '{parts[1]}'")
            print("")
            continue

        if cmd == "last":
            if len(parts) == 1:
                print(f"last target: {last_target or '-'}")
                print("")
                continue
            if len(parts) == 2 and parts[1].lower() == "clear":
                last_target = ""
                print("last target cleared")
                print("")
                continue
            print("usage: last [clear]")
            print("")
            continue

        if cmd == "full":
            if not last_target or last_target not in session_history:
                print("no query results in this session — run a query first")
                print("")
                continue
            from formatter import colorize_report, format_cli_report
            data = session_history[last_target]
            print(colorize_report(format_cli_report(data, full=True), use_color))
            print("")
            continue

        if cmd in ("providers", "quota"):
            import os as _os
            _key_data = None
            if not _os.environ.get("SERVER_MODE"):
                from keystore import get_all as _ks_all
                _key_data = _ks_all()
            for line in enrichment_manager.format_provider_status_lines(use_color=use_color, key_data=_key_data):
                print(line)
            continue

        if cmd == "enrich":
            if len(parts) != 2:
                print("usage: enrich <all|off|provider,...>")
                print("")
                continue
            enrich_selection = parts[1].strip().lower()
            resolved = enrichment_manager.resolve_requested(enrich_selection)
            print(f"enrichment selection: {enrich_selection}")
            print(f"resolved providers: {', '.join(resolved) if resolved else '-'}")
            print("")
            continue

        if cmd == "all":
            if len(parts) == 2:
                target = refang(parts[1])
            elif len(parts) == 1 and last_target:
                target = last_target
                print(f"[notice] using last target: {target}")
            elif len(parts) == 1:
                print("usage: all <target>  (or run a target first, then type 'all')")
                print("")
                continue
            else:
                print("usage: all [target]")
                print("")
                continue
            rc, _enrich = execute_enrichment_only(enrichment_manager, target, "all-enabled", emit_json, use_color=use_color)
            if rc == 0:
                last_target = target
                if _enrich and target in session_history:
                    stored_enrich = session_history[target].setdefault("enrichment", {
                        "enabled": True, "selection": [], "resolved": [], "skipped": [], "providers": {},
                    })
                    stored_enrich["enabled"] = True
                    stored_enrich.setdefault("providers", {}).update(_enrich.get("providers", {}))
                    for key in ("selection", "resolved"):
                        bucket = stored_enrich.setdefault(key, [])
                        for item in _enrich.get(key, []):
                            if item not in bucket:
                                bucket.append(item)
            print("")
            continue

        if cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            print("")
            continue

        if cmd == "web":
            host = args.host
            port = args.port
            if len(parts) >= 2:
                host = parts[1]
            if len(parts) >= 3:
                try:
                    port = int(parts[2])
                except ValueError:
                    print("usage: web [host] [port]")
                    print("")
                    continue
            if len(parts) > 3:
                print("usage: web [host] [port]")
                print("")
                continue
            if web_process and web_process.poll() is None:
                print("web server already running in background")
                print("")
                continue
            if not internet_available(timeout=1.0):
                print("[notice] internet connectivity check failed; web UI will start but queries may fail until connectivity returns")
            print(f"Starting web server in background on {host}:{port}")
            print("")
            web_process = run_web_background(args, host_override=host, port_override=port)
            print(f"[web] pid={web_process.pid} url=http://{host}:{port}")
            print("")
            continue

        if cmd == "banner":
            print(render_console_banner(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue

        if cmd == "status":
            print(render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue

        if cmd == "query":
            if len(parts) < 2:
                print("usage: query <target>")
                print("")
                continue
            target = refang(parts[1])
            _cache_hit = _cache_module.get(target, "full")
            if _cache_hit is not None:
                _cached_data, _cached_ts = _cache_hit
                if emit_json:
                    import json as _json
                    print(_json.dumps(_cached_data, indent=2))
                else:
                    from formatter import format_cli_report, colorize_report
                    print(colorize_report(format_cli_report(_cached_data), use_color))
                _age_m = int((_time_module.time() - _cached_ts) / 60)
                _age_s = f"{_age_m}m" if _age_m < 60 else f"{_age_m // 60}h {_age_m % 60}m"
                print(f"[cached {_age_s} ago — type 'reload' to refresh]")
                last_target = target
                session_history.pop(target, None)
                session_history[target] = _cached_data
                if len(session_history) > 10:
                    del session_history[next(iter(session_history))]
                print("")
                continue
            rc, _result = execute_query(
                query_engine, target, emit_json,
                use_color=use_color, include_headers=include_headers,
                enrichment_manager=enrichment_manager, enrichment_selection=enrich_selection,
            )
            if rc == 0 and _result:
                last_target = target
                _cache_module.put(target, "full", _result)
                session_history.pop(target, None)
                session_history[target] = _result
                if len(session_history) > 10:
                    del session_history[next(iter(session_history))]
            elif rc == 0:
                last_target = target
            print("")
            continue

        provider_cmd = PROVIDER_ALIASES.get(cmd)
        if provider_cmd:
            if len(parts) == 2:
                target = refang(parts[1])
            elif len(parts) == 1 and last_target:
                target = last_target
                print(f"[notice] using last target: {target}")
            elif len(parts) == 1:
                print(f"usage: {cmd} <target>  (or run a target first, then use {cmd})")
                print("")
                continue
            else:
                print(f"usage: {cmd} [target]")
                print("")
                continue
            rc, _enrich = execute_enrichment_only(enrichment_manager, target, provider_cmd, emit_json, use_color=use_color)
            if rc == 0:
                last_target = target
                if _enrich and target in session_history:
                    stored_enrich = session_history[target].setdefault("enrichment", {
                        "enabled": True, "selection": [], "resolved": [], "skipped": [], "providers": {},
                    })
                    stored_enrich["enabled"] = True
                    stored_enrich.setdefault("providers", {}).update(_enrich.get("providers", {}))
                    for key in ("selection", "resolved"):
                        bucket = stored_enrich.setdefault(key, [])
                        for item in _enrich.get(key, []):
                            if item not in bucket:
                                bucket.append(item)
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
            print(render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
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
                print(render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            else:
                if query_engine.config.route_mode == "stealth":
                    tor_ok = tor_engine.ensure_tor()
                print(render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
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
            print(render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue

        if cmd == "json":
            if len(parts) != 2 or parts[1].lower() not in {"on", "off"}:
                print("usage: json <on|off>")
                print("")
                continue
            emit_json = parts[1].lower() == "on"
            print(render_status_lines(query_engine, tor_engine, tor_ok, emit_json, use_color))
            print("")
            continue

        if cmd == "headers":
            if len(parts) != 2 or parts[1].lower() not in {"on", "off"}:
                print("usage: headers <on|off>")
                print("")
                continue
            include_headers = parts[1].lower() == "on"
            print(f"http headers: {'on' if include_headers else 'off'}")
            print("")
            continue

        if cmd == "reload":
            if not last_target:
                print("no previous query — run a query first")
                print("")
                continue
            target = last_target
            rc, _result = execute_query(
                query_engine, target, emit_json,
                use_color=use_color, include_headers=include_headers,
                enrichment_manager=enrichment_manager, enrichment_selection=enrich_selection,
            )
            if rc == 0 and _result:
                last_target = target
                _cache_module.put(target, "full", _result)
                session_history.pop(target, None)
                session_history[target] = _result
                if len(session_history) > 10:
                    del session_history[next(iter(session_history))]
            print("")
            continue

        if cmd == "report":
            out_path_arg: str | None = None
            target_arg: str | None = None
            if len(parts) == 2:
                arg = parts[1]
                if "/" in arg or "\\" in arg or arg.lower().endswith(".pdf"):
                    out_path_arg = arg
                else:
                    target_arg = arg
            elif len(parts) == 3:
                target_arg = parts[1]
                out_path_arg = parts[2]
            elif len(parts) > 3:
                print("usage: report [target] [path]")
                print("")
                continue

            if target_arg is not None:
                if target_arg not in session_history:
                    print(f"error: no cached result for '{target_arg}' — run a query first")
                    print("")
                    continue
                report_target = target_arg
                report_data = session_history[target_arg]
            elif not session_history:
                print("no query results in this session — run a query first")
                print("")
                continue
            elif len(session_history) == 1:
                report_target = next(iter(session_history))
                report_data = session_history[report_target]
            else:
                targets_rev = list(reversed(list(session_history.keys())))
                print("Select indicator for report:")
                for i, t in enumerate(targets_rev, 1):
                    suffix = _c(use_color, "  (most recent)", "90") if i == 1 else ""
                    print(f"  {_c(use_color, str(i), '1;93')}. {t}{suffix}")
                print("")
                try:
                    pick = input("Enter number [Enter for most recent]: ").strip()
                except EOFError:
                    print("")
                    continue
                if not pick:
                    report_target = targets_rev[0]
                else:
                    try:
                        idx = int(pick) - 1
                        if 0 <= idx < len(targets_rev):
                            report_target = targets_rev[idx]
                        else:
                            print("invalid selection")
                            print("")
                            continue
                    except ValueError:
                        print("invalid selection")
                        print("")
                        continue
                report_data = session_history[report_target]

            try:
                from report import generate_report
                print(f"generating report for {report_target}...")
                saved = generate_report(
                    target=report_target,
                    result=report_data,
                    out_path=out_path_arg,
                    route_mode=query_engine.config.route_mode,
                )
                print(f"report saved: {_c(use_color, str(saved), '92')}")
            except RuntimeError as exc:
                print(f"error: {exc}")
            except Exception as exc:
                print(f"error generating report: {exc}")
            print("")
            continue

        if cmd == "bulk":
            if len(parts) == 2:
                try:
                    with open(parts[1], encoding="utf-8", errors="replace") as _f:
                        raw_targets = [ln.strip() for ln in _f if ln.strip()]
                except OSError as exc:
                    print(f"error: cannot read file: {exc}")
                    print("")
                    continue
            elif len(parts) == 1:
                print("Enter indicators (one per line). Blank line when done:")
                raw_targets = []
                while True:
                    try:
                        _line = input("  ").strip()
                    except EOFError:
                        break
                    if not _line:
                        break
                    raw_targets.append(_line)
            else:
                print("usage: bulk [file]")
                print("")
                continue

            if not raw_targets:
                print("no targets provided")
                print("")
                continue

            seen: set[str] = set()
            bulk_targets: list[str] = []
            for _t in raw_targets:
                _t = refang(_t)
                if _t not in seen:
                    seen.add(_t)
                    bulk_targets.append(_t)

            print(f"running bulk triage for {len(bulk_targets)} indicator(s)...")

            def _bulk_progress(done: int, total: int) -> None:
                sys.stderr.write(f"\r  [{done}/{total}] processing...")
                sys.stderr.flush()

            from bulk import bulk_query as _bulk_query, write_csv as _write_csv
            from pathlib import Path as _Path

            _bulk_rows = _bulk_query(
                bulk_targets,
                query_engine,
                enrichment_manager,
                enrich_selection=enrich_selection,
                force_refresh=False,
                on_progress=_bulk_progress,
            )

            sys.stderr.write("\r" + " " * 40 + "\r")
            sys.stderr.flush()

            _downloads = _Path.home() / "Downloads"
            _downloads.mkdir(exist_ok=True)
            _ts = _time_module.strftime("%Y%m%d-%H%M%S")
            _csv_path = _downloads / f"stealthops-bulk-{_ts}.csv"
            _write_csv(_bulk_rows, _csv_path)
            print(f"saved: {_c(use_color, str(_csv_path), '92')}")
            print("")
            continue

        shorthand_target = refang(raw)
        if shorthand_target != raw:
            print(f"→ Refanged: {shorthand_target}")
        if shorthand_target:
            _cache_hit = _cache_module.get(shorthand_target, "full")
            if _cache_hit is not None:
                _cached_data, _cached_ts = _cache_hit
                if emit_json:
                    import json as _json
                    print(_json.dumps(_cached_data, indent=2))
                else:
                    from formatter import format_cli_report, colorize_report
                    print(colorize_report(format_cli_report(_cached_data), use_color))
                _age_m = int((_time_module.time() - _cached_ts) / 60)
                _age_s = f"{_age_m}m" if _age_m < 60 else f"{_age_m // 60}h {_age_m % 60}m"
                print(f"[cached {_age_s} ago — type 'reload' to refresh]")
                last_target = shorthand_target
                session_history.pop(shorthand_target, None)
                session_history[shorthand_target] = _cached_data
                if len(session_history) > 10:
                    del session_history[next(iter(session_history))]
                print("")
                continue
            rc, _result = execute_query(
                query_engine, shorthand_target, emit_json,
                use_color=use_color, include_headers=include_headers,
                enrichment_manager=enrichment_manager, enrichment_selection=enrich_selection,
            )
            if rc == 0 and _result:
                last_target = shorthand_target
                _cache_module.put(shorthand_target, "full", _result)
                session_history.pop(shorthand_target, None)
                session_history[shorthand_target] = _result
                if len(session_history) > 10:
                    del session_history[next(iter(session_history))]
            elif rc == 0:
                last_target = shorthand_target
            print("")
            continue

        print("unknown command. type 'help'")
        print("")


def _maybe_prompt_install_tor(tor_engine: TorEngine) -> bool:
    if not interactive_stdio():
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
