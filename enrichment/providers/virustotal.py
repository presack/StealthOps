"""VirusTotal enrichment adapter."""

from __future__ import annotations

import base64
from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    headers = {"x-apikey": key}
    if target_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{normalized}"
        response = requests.get(url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)
    elif target_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{normalized}"
        response = requests.get(url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)
    else:
        url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)

    if response.status_code >= 400:
        return {"source": "virustotal", "target_type": target_type, "error": short_http_error(response)}

    payload = response.json()
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    last_results = attrs.get("last_analysis_results", {}) if isinstance(attrs, dict) else {}
    findings = _detection_findings(last_results)
    total_votes = attrs.get("total_votes", {}) if isinstance(attrs, dict) else {}
    return {
        "source": "virustotal",
        "target_type": target_type,
        "id": payload.get("data", {}).get("id"),
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": stats,
        "malicious_or_suspicious_findings": findings,
        "finding_count": len(findings),
        "total_votes": total_votes,
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "network": attrs.get("network"),
        "whois_date": attrs.get("whois_date"),
        "tags": attrs.get("tags"),
    }


def summary(payload: dict[str, Any]) -> str:
    stats = payload.get("last_analysis_stats", {})
    mal = int(stats.get("malicious", 0) or 0) if isinstance(stats, dict) else 0
    susp = int(stats.get("suspicious", 0) or 0) if isinstance(stats, dict) else 0
    rep = int(payload.get("reputation", 0) or 0)
    return f"vt malicious={mal} suspicious={susp} reputation={rep}"


def _detection_findings(last_results: Any, limit: int = 20) -> list[dict[str, str]]:
    if not isinstance(last_results, dict):
        return []
    findings: list[dict[str, str]] = []
    for engine_name, verdict in last_results.items():
        if not isinstance(verdict, dict):
            continue
        category = str(verdict.get("category", "")).strip().lower()
        if category not in {"malicious", "suspicious"}:
            continue
        result = str(verdict.get("result", "")).strip() or category
        findings.append({"engine": str(engine_name), "category": category, "result": result})
    findings.sort(key=lambda item: (item.get("category", ""), item.get("engine", "")))
    return findings[:limit]
