"""AbuseIPDB enrichment adapter."""

from __future__ import annotations

from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type != "ip":
        return {"source": "abuseipdb", "target_type": target_type, "error": "abuseipdb_check_requires_ip_target"}
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": normalized, "maxAgeInDays": 90, "verbose": ""},
        headers={"accept": "application/json", "Key": key},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return {"source": "abuseipdb", "target_type": target_type, "error": short_http_error(response)}
    data = response.json().get("data", {})
    score = int(data.get("abuseConfidenceScore", 0) or 0)
    risk_level = "high" if score >= 70 else ("medium" if score >= 20 else "low")
    return {
        "source": "abuseipdb",
        "target_type": target_type,
        "ip_address": data.get("ipAddress"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "is_whitelisted": data.get("isWhitelisted"),
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "risk_level": risk_level,
    }


def summary(payload: dict[str, Any]) -> str:
    score = payload.get("abuse_confidence_score")
    risk = payload.get("risk_level", "low")
    return f"abuseipdb score={score} risk={risk}"
