"""RIPEstat enrichment adapter."""

from __future__ import annotations

from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type != "asn":
        return {"source": "ripestat", "target_type": target_type, "error": "ripestat_asn_lookup_requires_asn_target"}

    resource = f"AS{normalized}"
    out: dict[str, Any] = {
        "source": "ripestat",
        "target_type": target_type,
        "asn": int(normalized),
        "resource": resource,
    }

    overview, overview_err = _get("as-overview", resource)
    if overview_err:
        out["error"] = overview_err
        return out
    out["holder"] = overview.get("holder")
    out["country"] = overview.get("country")
    out["rir"] = overview.get("rir")

    abuse_data, abuse_err = _get("abuse-contact-finder", resource)
    if not abuse_err:
        emails = abuse_data.get("abuse_contacts")
        if isinstance(emails, list):
            out["abuse_contacts"] = [str(v).strip() for v in emails if str(v).strip()][:15]
    else:
        out["abuse_contacts_error"] = abuse_err

    routing_data, routing_err = _get("routing-status", resource)
    if not routing_err:
        for rkey in ("is_announced", "is_visible", "originating", "observed_upstreams"):
            value = routing_data.get(rkey)
            if value not in (None, "", []):
                out[rkey] = value
        if routing_data.get("less_specifics") not in (None, "", []):
            out["less_specifics"] = routing_data.get("less_specifics")
        if routing_data.get("more_specifics") not in (None, "", []):
            out["more_specifics"] = routing_data.get("more_specifics")
    else:
        out["routing_status_error"] = routing_err

    prefixes_data, prefixes_err = _get("announced-prefixes", resource)
    if not prefixes_err:
        prefixes = prefixes_data.get("prefixes")
        if isinstance(prefixes, list):
            prefix_rows: list[dict[str, Any]] = []
            for item in prefixes[:40]:
                if not isinstance(item, dict):
                    continue
                timelines = item.get("timelines")
                first_seen = None
                last_seen = None
                events = 0
                if isinstance(timelines, list):
                    starts: list[str] = []
                    ends: list[str] = []
                    for t in timelines:
                        if not isinstance(t, dict):
                            continue
                        start = str(t.get("starttime") or "").strip()
                        end = str(t.get("endtime") or "").strip()
                        if start:
                            starts.append(start)
                        if end:
                            ends.append(end)
                    events = len(timelines)
                    if starts:
                        first_seen = min(starts)
                    if ends:
                        last_seen = max(ends)
                    elif starts:
                        last_seen = max(starts)
                prefix_rows.append({
                    "prefix": item.get("prefix"),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "events": events if events else None,
                })
            out["announced_prefix_count"] = len(prefixes)
            out["announced_prefixes"] = prefix_rows
    else:
        out["announced_prefixes_error"] = prefixes_err

    visible = out.get("is_visible")
    announced = out.get("is_announced")
    out["risk_level"] = "medium" if (visible is False or announced is False) else "low"
    return out


def summary(payload: dict[str, Any]) -> str:
    asn = payload.get("asn")
    holder = payload.get("holder") or payload.get("resource")
    cc = payload.get("country") or "-"
    return f"ripestat asn=AS{asn} holder={holder} country={cc}"


def _get(endpoint: str, resource: str) -> tuple[dict[str, Any], str]:
    url = f"https://stat.ripe.net/data/{endpoint}/data.json"
    try:
        response = requests.get(
            url,
            params={"resource": resource},
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {}, short_http_error(response)
        payload = response.json()
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        if isinstance(data, dict):
            return data, ""
        return {}, "unexpected_non_json_response"
    except Exception as exc:
        return {}, str(exc)
