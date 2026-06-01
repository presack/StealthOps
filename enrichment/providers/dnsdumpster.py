"""DNSDumpster enrichment adapter."""

from __future__ import annotations

import os
import time
from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, extract_domain_from_url, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type == "ip":
        return {"source": "dnsdumpster", "target_type": target_type, "error": "dnsdumpster_domain_lookup_requires_domain_or_url"}
    domain = normalized if target_type == "domain" else extract_domain_from_url(normalized)
    if not domain:
        return {"source": "dnsdumpster", "target_type": target_type, "error": "unable_to_extract_domain"}

    base_url = f"https://api.dnsdumpster.com/domain/{domain}"
    response = requests.get(
        base_url,
        headers={"accept": "application/json", "X-API-Key": key},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code == 429:
        return {
            "source": "dnsdumpster",
            "target_type": target_type,
            "domain": domain,
            "error": "http 429: rate limit exceeded (DNSDumpster allows 1 request per 2 seconds)",
        }
    if response.status_code >= 400:
        return {"source": "dnsdumpster", "target_type": target_type, "error": short_http_error(response)}

    data = response.json()
    if not isinstance(data, dict):
        return {"source": "dnsdumpster", "target_type": target_type, "error": "unexpected_non_json_response"}
    if data.get("error"):
        return {
            "source": "dnsdumpster",
            "target_type": target_type,
            "domain": domain,
            "error": str(data.get("error")),
            "result_keys": sorted(data.keys()),
        }

    a_rows = _list_for(data, "a", "A")
    ns_rows = _list_for(data, "ns", "NS")
    mx_rows = _list_for(data, "mx", "MX")
    cname_rows = _list_for(data, "cname", "CNAME")
    txt_rows = _list_for(data, "txt", "TXT")

    total_a_recs_raw = data.get("total_a_recs") or data.get("total_A_recs")
    try:
        total_a_recs = int(total_a_recs_raw) if total_a_recs_raw not in (None, "") else 0
    except Exception:
        total_a_recs = 0

    max_pages_raw = str(os.environ.get("DNSDUMPSTER_MAX_PAGES", "5")).strip()
    try:
        max_pages = max(1, int(max_pages_raw))
    except Exception:
        max_pages = 5
    pages_fetched = 1
    for page in range(2, max_pages + 1):
        if total_a_recs and len(a_rows) >= total_a_recs:
            break
        time.sleep(2.1)
        page_resp = requests.get(
            base_url,
            params={"page": page},
            headers={"accept": "application/json", "X-API-Key": key},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if page_resp.status_code == 429:
            break
        if page_resp.status_code >= 400:
            break
        page_data = page_resp.json()
        if not isinstance(page_data, dict):
            break
        prev_count = len(a_rows)
        a_rows = _merge_record_rows(a_rows, _list_for(page_data, "a", "A"))
        ns_rows = _merge_record_rows(ns_rows, _list_for(page_data, "ns", "NS"))
        mx_rows = _merge_record_rows(mx_rows, _list_for(page_data, "mx", "MX"))
        cname_rows = _merge_record_rows(cname_rows, _list_for(page_data, "cname", "CNAME"))
        txt_rows = _unique_extend_strings(
            [str(v) for v in txt_rows if str(v).strip()],
            [str(v) for v in _list_for(page_data, "txt", "TXT") if str(v).strip()],
        )
        pages_fetched = page
        if len(a_rows) == prev_count:
            break

    txt_values = [str(v) for v in txt_rows if str(v).strip()]
    api_record_limit_hit = bool(total_a_recs and len(a_rows) < total_a_recs)
    limit_note = ""
    if api_record_limit_hit:
        limit_note = (
            f"returned {len(a_rows)} of {total_a_recs} A records; "
            "account/API limits or pagination cap may apply"
        )

    return {
        "source": "dnsdumpster",
        "target_type": target_type,
        "domain": domain,
        "a_count": _count_records(a_rows),
        "ns_count": _count_records(ns_rows),
        "mx_count": _count_records(mx_rows),
        "cname_count": _count_records(cname_rows),
        "txt_count": len(txt_values),
        "total_a_recs": total_a_recs or total_a_recs_raw,
        "pages_fetched": pages_fetched,
        "api_record_limit_hit": api_record_limit_hit,
        "limit_note": limit_note,
        "a_hosts": _sample_hosts(a_rows),
        "ns_hosts": _sample_hosts(ns_rows),
        "mx_hosts": _sample_hosts(mx_rows),
        "resolved_ips": _sample_ips(a_rows),
        "txt_records": txt_values,
        "result_keys": sorted(data.keys()),
    }


def summary(payload: dict[str, Any]) -> str:
    domain = payload.get("domain") or "-"
    total = payload.get("total_a_recs") or payload.get("a_count") or 0
    return f"dnsdumpster domain={domain} a_records={total}"


def _list_for(payload: dict[str, Any], *keys: str) -> list[Any]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def _unique_extend_strings(existing: list[str], incoming: list[str]) -> list[str]:
    out = list(existing)
    for value in incoming:
        text = str(value).strip()
        if text and text not in out:
            out.append(text)
    return out


def _merge_record_rows(primary: list[Any], secondary: list[Any]) -> list[Any]:
    out = list(primary)
    seen_hosts = {
        str(item.get("host")).strip().lower()
        for item in out
        if isinstance(item, dict) and str(item.get("host")).strip()
    }
    for row in secondary:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or "").strip().lower()
        if host and host in seen_hosts:
            continue
        out.append(row)
        if host:
            seen_hosts.add(host)
    return out


def _count_records(rows: list[Any]) -> int:
    return len(rows) if isinstance(rows, list) else 0


def _sample_hosts(rows: list[Any], limit: int = 250) -> list[str]:
    out: list[str] = []
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or "").strip()
        if host and host not in out:
            out.append(host)
        if len(out) >= limit:
            break
    return out


def _sample_ips(rows: list[Any], limit: int = 120) -> list[str]:
    out: list[str] = []
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        ips = row.get("ips", [])
        if not isinstance(ips, list):
            continue
        for ip_row in ips:
            if not isinstance(ip_row, dict):
                continue
            ip = str(ip_row.get("ip") or "").strip()
            if ip and ip not in out:
                out.append(ip)
            if len(out) >= limit:
                return out
    return out
