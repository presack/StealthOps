"""urlscan.io enrichment adapter."""

from __future__ import annotations

import os
from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    raw_target = str(target or "").strip()
    if any(token in raw_target for token in ("*", " AND ", " OR ", ":", "(", ")")) and "://" not in raw_target:
        search_query = raw_target
    elif target_type == "ip":
        search_query = f"ip:{normalized}"
    elif target_type == "domain":
        search_query = f"domain:{normalized}"
    else:
        search_query = f'page.url:"{normalized}"'

    headers = {"accept": "application/json", "API-Key": key}
    max_results_raw = str(os.environ.get("URLSCAN_MAX_RESULTS", "50")).strip()
    try:
        max_results = max(1, min(100, int(max_results_raw)))
    except Exception:
        max_results = 50
    response = requests.get(
        "https://urlscan.io/api/v1/search/",
        params={"q": search_query, "size": max_results},
        headers=headers,
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return {"source": "urlscan", "target_type": target_type, "error": short_http_error(response)}

    payload = response.json()
    results = payload.get("results", []) if isinstance(payload, dict) else []
    if not isinstance(results, list):
        results = []
    total = payload.get("total") if isinstance(payload, dict) else None

    scans: list[dict[str, Any]] = []
    malicious_votes = 0
    suspicious_votes = 0
    for row in results[:max_results]:
        if not isinstance(row, dict):
            continue
        page = row.get("page", {}) if isinstance(row.get("page"), dict) else {}
        task = row.get("task", {}) if isinstance(row.get("task"), dict) else {}
        verdicts = row.get("verdicts", {}) if isinstance(row.get("verdicts"), dict) else {}
        overall = verdicts.get("overall", {}) if isinstance(verdicts.get("overall"), dict) else {}
        score = overall.get("score")
        categories = overall.get("categories", [])
        brands = overall.get("brands", [])
        if isinstance(score, (int, float)):
            if score >= 50:
                malicious_votes += 1
            elif score > 0:
                suspicious_votes += 1
        scans.append({
            "time": task.get("time"),
            "country": page.get("country"),
            "ip": page.get("ip"),
            "domain": page.get("domain"),
            "url": page.get("url"),
            "uuid": row.get("_id"),
            "score": score,
            "categories": categories if isinstance(categories, list) else [],
            "brands": brands if isinstance(brands, list) else [],
            "result_url": row.get("result"),
        })

    risk_level = "low"
    if malicious_votes > 0:
        risk_level = "high"
    elif suspicious_votes > 0:
        risk_level = "medium"

    out: dict[str, Any] = {
        "source": "urlscan",
        "target_type": target_type,
        "query": search_query,
        "result_count": len(scans),
        "total_available": total,
        "max_results_used": max_results,
        "truncated": bool(isinstance(total, int) and total > len(scans)),
        "risk_level": risk_level,
        "malicious_hits": malicious_votes,
        "suspicious_hits": suspicious_votes,
        "recent_scans": scans,
    }

    submit_on_miss = str(os.environ.get("URLSCAN_SUBMIT_ON_MISS", "")).strip().lower() in {"1", "true", "yes"}
    if not scans and submit_on_miss and target_type == "url":
        submit_resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={**headers, "content-type": "application/json"},
            json={"url": normalized, "visibility": "unlisted"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if submit_resp.status_code < 400:
            submit_payload = submit_resp.json() if submit_resp.headers.get("content-type", "").startswith("application/json") else {}
            out["submitted_scan"] = True
            out["submitted_uuid"] = submit_payload.get("uuid")
            out["submitted_result"] = submit_payload.get("result")
        else:
            out["submitted_scan"] = False
            out["submit_error"] = short_http_error(submit_resp)

    return out


def summary(payload: dict[str, Any]) -> str:
    count = payload.get("result_count") or 0
    risk = payload.get("risk_level", "low")
    return f"urlscan results={count} risk={risk}"
