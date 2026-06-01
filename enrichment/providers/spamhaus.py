"""Spamhaus ASN-DROP enrichment adapter."""

from __future__ import annotations

from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type != "asn":
        return {"source": "spamhaus", "target_type": target_type, "error": "spamhaus_asndrop_requires_asn_target"}

    response = requests.get(
        "https://www.spamhaus.org/drop/asndrop.json",
        headers={"accept": "application/json"},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return {"source": "spamhaus", "target_type": target_type, "asn": int(normalized), "error": short_http_error(response)}

    rows: list[dict[str, Any]] = []
    feed_type = None
    text = str(response.text or "").strip()
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = requests.models.complexjson.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
        if not rows:
            try:
                payload = requests.models.complexjson.loads(text)
            except Exception:
                payload = None
            if isinstance(payload, dict):
                feed_type = payload.get("type")
                records = payload.get("records")
                if isinstance(records, list):
                    rows = [row for row in records if isinstance(row, dict)]
            elif isinstance(payload, list):
                rows = [row for row in payload if isinstance(row, dict)]

    matches: list[dict[str, Any]] = []
    for row in rows:
        asn_raw = str(row.get("asn") or row.get("asn_number") or row.get("autonomous_system_number") or "").strip().upper()
        if asn_raw.startswith("AS"):
            asn_raw = asn_raw[2:].strip()
        if asn_raw == normalized:
            matches.append(row)

    listed = bool(matches)
    first = matches[0] if matches else {}
    return {
        "source": "spamhaus",
        "target_type": target_type,
        "asn": int(normalized),
        "listed": listed,
        "risk_level": "high" if listed else "low",
        "match_count": len(matches),
        "as_name": first.get("asname") if isinstance(first, dict) else None,
        "domain": first.get("domain") if isinstance(first, dict) else None,
        "country_code": first.get("cc") if isinstance(first, dict) else None,
        "rir": first.get("rir") if isinstance(first, dict) else None,
        "feed_type": feed_type or "ndjson",
    }


def summary(payload: dict[str, Any]) -> str:
    listed = bool(payload.get("listed"))
    asn = payload.get("asn")
    return f"spamhaus asn=AS{asn} listed={'yes' if listed else 'no'}"
