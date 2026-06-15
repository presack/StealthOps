"""Wayback Machine CDX enrichment adapter — historical archive analysis for domains."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

import requests

from ._shared import classify_target, short_http_error

_CDX_BASE = "https://web.archive.org/cdx/search/cdx"

# CDX timestamp-scanning queries can take 4-15s depending on domain size and server load;
# uncollapsed queries (limit=1, no collapse) can occasionally reach 20-25s.
# 20s gives comfortable headroom while keeping enrichment from stalling indefinitely.
_TIMEOUT = 20

# How many unique URL entries to pull from the wildcard query.
# 200 gives good subdomain coverage.  Wildcard + collapse=urlkey is fast (< 2s).
_URL_LIMIT = 200

# Monthly-collapsed timeline cap.  500 = ~41 years of monthly entries.
_SNAPSHOT_LIMIT = 500

# Path segments that warrant highlighting (admin panels, login pages, etc.)
_NOTABLE_SEGMENTS = frozenset({
    "admin", "administrator", "login", "signin", "signup", "register",
    "panel", "dashboard", "api", "upload", "download", "shell", "phpmyadmin",
    "wp-admin", "wp-login", "wp-content", "install", "setup", "config",
    "console", "cpanel", "webmail", "manage", "management", "portal",
    "backend", "cms", "db", "database", "sql", "xmlrpc",
})


def _fetch_timeline(domain: str) -> dict[str, Any]:
    """Monthly-collapsed snapshot history for the root domain."""
    resp = requests.get(
        _CDX_BASE,
        params={
            "url": domain,
            "output": "json",
            "fl": "timestamp,statuscode",
            "collapse": "timestamp:6",
            "limit": str(_SNAPSHOT_LIMIT),
        },
        timeout=_TIMEOUT,
    )
    if resp.status_code >= 400:
        return {"timeline_error": short_http_error(resp)}

    rows = resp.json()
    if not isinstance(rows, list) or len(rows) <= 1:
        return {"archive_months": 0}

    data = rows[1:]
    first_ts = str(data[0][0])
    last_ts = str(data[-1][0])
    status_counts: dict[str, int] = {}
    for row in data:
        code = str(row[1]) if len(row) > 1 else "?"
        status_counts[code] = status_counts.get(code, 0) + 1

    return {
        "first_seen": f"{first_ts[:4]}-{first_ts[4:6]}-{first_ts[6:8]}",
        "last_seen": f"{last_ts[:4]}-{last_ts[4:6]}-{last_ts[6:8]}",
        "archive_months": len(data),
        "status_codes": status_counts,
    }


def _fetch_urls(domain: str) -> dict[str, Any]:
    """Wildcard URL/subdomain discovery for the domain."""
    resp = requests.get(
        _CDX_BASE,
        params={
            "url": f"*.{domain}",
            "output": "json",
            "fl": "original,timestamp",
            "matchType": "domain",
            "collapse": "urlkey",
            "limit": str(_URL_LIMIT),
        },
        timeout=_TIMEOUT,
    )
    if resp.status_code >= 400:
        return {"url_discovery_error": short_http_error(resp)}

    url_rows = resp.json()
    if not isinstance(url_rows, list) or len(url_rows) <= 1:
        return {"unique_urls": 0, "subdomains": [], "notable_paths": []}

    url_data = url_rows[1:]
    subdomains: set[str] = set()
    notable_paths: list[str] = []

    for row in url_data:
        raw_url = str(row[0]) if row else ""
        try:
            parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
            host = (parsed.hostname or "").lower()
            if host.endswith(f".{domain}"):
                sub = host[: -(len(domain) + 1)]
                if sub:
                    subdomains.add(sub)
            path_parts = {p.lower() for p in (parsed.path or "").strip("/").split("/")}
            if path_parts & _NOTABLE_SEGMENTS and len(notable_paths) < 20:
                notable_paths.append(raw_url)
        except Exception:
            continue

    return {
        "unique_urls": len(url_data),
        "url_cap_hit": len(url_data) >= _URL_LIMIT,
        "subdomains": sorted(subdomains),
        "notable_paths": notable_paths,
    }


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type not in ("domain", "url"):
        return {
            "source": "wayback",
            "target_type": target_type,
            "error": "unsupported_target_type",
        }

    if target_type == "url":
        parsed = urlparse(normalized)
        domain = (parsed.hostname or normalized).lower()
    else:
        domain = normalized

    out: dict[str, Any] = {"source": "wayback", "target_type": target_type, "domain": domain}

    # Run both CDX calls in parallel — timeline is slow (~10-15s), wildcard is fast (~1s).
    # Parallel execution caps total wall time at max(timeline, wildcard) instead of the sum.
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_timeline = pool.submit(_fetch_timeline, domain)
        f_urls = pool.submit(_fetch_urls, domain)
        for future in as_completed([f_timeline, f_urls], timeout=_TIMEOUT + 2):
            try:
                out.update(future.result())
            except Exception as exc:
                if future is f_timeline:
                    out["timeline_error"] = str(exc)
                else:
                    out["url_discovery_error"] = str(exc)

    return out


def summary(payload: dict[str, Any]) -> str:
    if payload.get("error"):
        return f"wayback {payload['error']}"

    first = payload.get("first_seen") or "-"
    last = payload.get("last_seen") or "-"
    months = payload.get("archive_months")
    months_str = f" | {months} archive months" if months is not None else ""

    urls = payload.get("unique_urls")
    cap = "+" if payload.get("url_cap_hit") else ""
    urls_str = f" | {urls}{cap} unique URLs" if urls is not None else ""

    subs = payload.get("subdomains") or []
    subs_str = f" | {len(subs)} subdomain{'s' if len(subs) != 1 else ''}" if subs else ""

    if first == "-" and last == "-":
        note = payload.get("timeline_error", "timeline unavailable")
        return f"wayback timeline_error ({note[:60]}){urls_str}{subs_str}"

    return f"First archived: {first} | Last: {last}{months_str}{urls_str}{subs_str}"
