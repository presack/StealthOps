"""Query execution with spinner and output rendering for StealthOps."""

from __future__ import annotations

import json
import sys
import threading
import time
from typing import Callable

from core_ops import StealthQueryEngine, internet_available
from enrichment import EnrichmentManager, parse_enrichment_selection
from formatter import (
    _c,
    colorize_report,
    format_cli_report,
    format_enrichment_report,
    interactive_stdio,
)


def run_with_activity(label: str, fn: Callable[[], dict]) -> dict:
    if not interactive_stdio():
        return fn()
    stop = threading.Event()

    def spinner() -> None:
        glyphs = "|/-\\"
        idx = 0
        while not stop.wait(0.12):
            sys.stderr.write(f"\r[{glyphs[idx % len(glyphs)]}] {label}...")
            sys.stderr.flush()
            idx += 1
        clear_len = len(label) + 10
        sys.stderr.write("\r" + (" " * clear_len) + "\r")
        sys.stderr.flush()

    thread = threading.Thread(target=spinner, daemon=True)
    thread.start()
    try:
        return fn()
    finally:
        stop.set()
        thread.join(timeout=0.3)


def execute_query(
    query_engine: StealthQueryEngine,
    target: str,
    emit_json: bool,
    use_color: bool = False,
    include_headers: bool = False,
    enrichment_manager: EnrichmentManager | None = None,
    enrichment_selection: str = "off",
) -> tuple[int, dict | None]:
    def render_query_banner() -> str:
        title = f"[ QUERY START ]  target={target}"
        border = "=" * max(64, len(title) + 6)
        if not use_color:
            return f"{border}\n{title}\n{border}"
        return (
            f"{_c(True, border, '94')}\n"
            f"{_c(True, title, '30;106')}\n"
            f"{_c(True, border, '94')}"
        )

    try:
        if not internet_available(timeout=1.0):
            print("error: internet connectivity check failed (no network route detected)")
            return 1, None
        print("")
        print(render_query_banner())
        print("")
        start = time.monotonic()
        result = run_with_activity("Gathering results", lambda: query_engine.run_all(target, include_headers=include_headers))
        if enrichment_manager and parse_enrichment_selection(enrichment_selection):
            result["enrichment"] = run_with_activity(
                "Gathering enrichment",
                lambda: enrichment_manager.run(target, enrichment_selection),
            )
            result["enrichment"]["_use_color"] = bool(use_color)
        elapsed = time.monotonic() - start
        if emit_json:
            print(json.dumps(result, indent=2))
        else:
            print(colorize_report(format_cli_report(result), use_color))
        if interactive_stdio():
            print(f"[status] query_complete elapsed={elapsed:.1f}s")
        return 0, result
    except Exception as exc:
        print(f"error: {exc}")
        return 1, None


def execute_enrichment_only(
    enrichment_manager: EnrichmentManager,
    target: str,
    selection: str,
    emit_json: bool,
    use_color: bool = False,
) -> tuple[int, dict | None]:
    try:
        if not internet_available(timeout=1.0):
            print("error: internet connectivity check failed (no network route detected)")
            return 1, None
        title = f"[ ENRICHMENT START ]  target={target}  selection={selection}"
        border = "=" * max(64, len(title) + 6)
        print("")
        if use_color:
            print(_c(True, border, "94"))
            print(_c(True, title, "30;106"))
            print(_c(True, border, "94"))
        else:
            print(border)
            print(title)
            print(border)
        print("")
        start = time.monotonic()
        result = run_with_activity("Gathering enrichment", lambda: enrichment_manager.run(target, selection))
        result["_use_color"] = bool(use_color)
        elapsed = time.monotonic() - start
        if emit_json:
            print(json.dumps(result, indent=2))
        else:
            print(colorize_report(format_enrichment_report(result), use_color))
        if interactive_stdio():
            print(f"[status] enrichment_complete elapsed={elapsed:.1f}s")
        return 0, result
    except Exception as exc:
        print(f"error: {exc}")
        return 1, None
