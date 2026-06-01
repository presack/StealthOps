"""DNSDB enrichment adapter."""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any
from urllib.parse import quote

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, extract_domain_from_url, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    rr_limit = _limit("DNSDB_RRSET_LIMIT", 25)
    sub_limit = _limit("DNSDB_SUBDOMAIN_LIMIT", 60)

    if target_type == "ip":
        rows, error, api_mode = _lookup("rdata", "ip", normalized, key, limit=sub_limit)
        out: dict[str, Any] = {
            "source": "dnsdb",
            "target_type": target_type,
            "ip": normalized,
            "api_mode": api_mode,
        }
        if error:
            out["error"] = error
            return out
        rrnames = _extract_rrnames(rows)
        out["rrname_count"] = len(rrnames)
        out["rrnames"] = rrnames[:60]
        out["rdata_records"] = [_row_preview(row) for row in rows[:40] if isinstance(row, dict)]
        return out

    domain = normalized if target_type == "domain" else extract_domain_from_url(normalized)
    if not domain:
        return {"source": "dnsdb", "target_type": target_type, "error": "unable_to_extract_domain"}

    apex_rows, apex_error, api_mode = _lookup("rrset", "name", domain, key, limit=rr_limit)
    wildcard_rows, sub_error, _ = _lookup("rrset", "name", f"*.{domain}", key, limit=sub_limit)
    out = {
        "source": "dnsdb",
        "target_type": target_type,
        "domain": domain,
        "api_mode": api_mode,
    }
    if apex_error:
        out["error"] = apex_error
        return out

    out.update(_extract_record_sets(apex_rows))
    out["rrset_count"] = len(apex_rows)
    rrtypes = sorted({str(row.get("rrtype") or row.get("type") or "").strip().upper() for row in apex_rows if isinstance(row, dict)})
    if rrtypes:
        out["rrtypes"] = rrtypes
    out["rrsets"] = [_row_preview(row) for row in apex_rows[:30] if isinstance(row, dict)]

    subdomains = _extract_subdomains(wildcard_rows, domain)
    if subdomains:
        out["subdomain_count"] = len(subdomains)
        out["subdomains"] = subdomains[:60]
    if wildcard_rows:
        out["subdomain_rrset_count"] = len(wildcard_rows)
        out["subdomain_rrsets"] = [_row_preview(row) for row in wildcard_rows[:40] if isinstance(row, dict)]
    if sub_error:
        out["subdomain_error"] = sub_error
    return out


def summary(payload: dict[str, Any]) -> str:
    if str(payload.get("target_type")) == "ip":
        ip = payload.get("ip") or "-"
        count = payload.get("rrname_count") or 0
        return f"dnsdb ip={ip} rrnames={count}"
    domain = payload.get("domain") or "-"
    sub_count = payload.get("subdomain_count") or 0
    return f"dnsdb domain={domain} subdomains={sub_count}"


def _limit(name: str, default: int, minimum: int = 1, maximum: int = 500) -> int:
    raw = str(os.environ.get(name, "")).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except Exception:
        return default
    return max(minimum, min(maximum, value))


def _timestamp(value: object) -> str | None:
    try:
        ts = int(value)
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%SZ")
    except Exception:
        text = str(value or "").strip()
        return text or None


def _root_config() -> tuple[str, str]:
    raw = (
        str(os.environ.get("DNSDB_API_ROOT", "")).strip()
        or str(os.environ.get("DNSDB_BASE_URL", "")).strip()
        or "https://api.dnsdb.info/dnsdb/v2"
    )
    raw = raw.rstrip("/")
    lower = raw.lower()
    if "/dnsdb/v2" in lower:
        idx = lower.index("/dnsdb/v2") + len("/dnsdb/v2")
        return raw[:idx], "v2"
    if lower.endswith("/lookup_api"):
        return raw[: -len("/lookup_api")], "legacy"
    return raw, "legacy"


def _lookup_url(section: str, mode_key: str, value: str) -> tuple[str, str]:
    root, api_mode = _root_config()
    safe_value = quote(str(value or "").strip(), safe="*._:-/")
    url = f"{root.rstrip('/')}/lookup/{section}/{mode_key}/{safe_value}/ANY"
    return url, api_mode


def _parse_response(response: requests.Response) -> tuple[list[dict[str, Any]], str]:
    body = str(response.text or "").strip()
    if not body:
        return [], ""
    try:
        payload = json.loads(body)
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)], ""
        if isinstance(payload, dict):
            if isinstance(payload.get("results"), list):
                return [row for row in payload.get("results", []) if isinstance(row, dict)], ""
            return [payload], ""
    except Exception:
        pass

    rows: list[dict[str, Any]] = []
    for line in body.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except Exception:
            return [], "unexpected_non_json_response"
        if isinstance(item, dict):
            rows.append(item)
    return rows, ""


def _lookup(section: str, mode_key: str, value: str, api_key: str, limit: int) -> tuple[list[dict[str, Any]], str, str]:
    url, api_mode = _lookup_url(section, mode_key, value)
    try:
        response = requests.get(
            url,
            headers={
                "accept": "application/x-ndjson, application/json;q=0.9",
                "X-API-Key": api_key,
            },
            params={"limit": limit},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return [], str(exc), api_mode
    if response.status_code >= 400:
        return [], short_http_error(response), api_mode
    rows, parse_error = _parse_response(response)
    return rows, parse_error, api_mode


def _row_preview(row: dict[str, Any]) -> dict[str, Any]:
    rdata_values = row.get("rdata", [])
    if not isinstance(rdata_values, list):
        rdata_values = [rdata_values] if rdata_values not in (None, "") else []
    preview_values = [str(v).strip() for v in rdata_values if str(v).strip()]
    rdata_preview = ", ".join(preview_values[:3])
    if len(preview_values) > 3:
        rdata_preview += f" ... (+{len(preview_values)-3} more)"
    out: dict[str, Any] = {
        "rrname": str(row.get("rrname") or row.get("owner") or "").strip(),
        "rrtype": str(row.get("rrtype") or row.get("type") or "").strip(),
        "rdata": rdata_preview,
    }
    count = row.get("count")
    if count not in (None, ""):
        out["count"] = count
    first_seen = _timestamp(row.get("time_first"))
    last_seen = _timestamp(row.get("time_last"))
    if first_seen:
        out["first_seen"] = first_seen
    if last_seen:
        out["last_seen"] = last_seen
    bailiwick = str(row.get("bailiwick") or "").strip()
    if bailiwick:
        out["bailiwick"] = bailiwick
    return out


def _extract_record_sets(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {
        "a_records": [], "aaaa_records": [], "ns_records": [], "mx_records": [], "txt_records": [],
    }
    for row in rows:
        if not isinstance(row, dict):
            continue
        rrtype = str(row.get("rrtype") or row.get("type") or "").strip().upper()
        rdata_values = row.get("rdata", [])
        if not isinstance(rdata_values, list):
            rdata_values = [rdata_values] if rdata_values not in (None, "") else []
        for item in rdata_values:
            value = str(item or "").strip()
            if not value:
                continue
            if rrtype == "A" and value not in buckets["a_records"]:
                buckets["a_records"].append(value)
            elif rrtype == "AAAA" and value not in buckets["aaaa_records"]:
                buckets["aaaa_records"].append(value)
            elif rrtype == "NS":
                host = value.rstrip(".")
                if host and host not in buckets["ns_records"]:
                    buckets["ns_records"].append(host)
            elif rrtype == "MX":
                parts = value.split()
                host = (parts[-1] if parts else value).rstrip(".")
                if host and host not in buckets["mx_records"]:
                    buckets["mx_records"].append(host)
            elif rrtype == "TXT" and value not in buckets["txt_records"]:
                buckets["txt_records"].append(value)
    return buckets


def _extract_subdomains(rows: list[dict[str, Any]], apex: str) -> list[str]:
    out: list[str] = []
    suffix = "." + apex.lower()
    for row in rows:
        rrname = str(row.get("rrname") or row.get("owner") or "").strip().rstrip(".")
        if not rrname:
            continue
        lowered = rrname.lower()
        if lowered == apex.lower():
            continue
        if lowered.endswith(suffix) and rrname not in out:
            out.append(rrname)
    return out


def _extract_rrnames(rows: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for row in rows:
        rrname = str(row.get("rrname") or row.get("owner") or "").strip().rstrip(".")
        if rrname and rrname not in out:
            out.append(rrname)
    return out
