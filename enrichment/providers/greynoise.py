"""GreyNoise enrichment adapter."""

from __future__ import annotations

from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type == "asn":
        query = f"asn:{normalized}"
        last_error = ""
        response = requests.get(
            "https://api.greynoise.io/v3/gnql/metadata",
            params={"query": query},
            headers={"accept": "application/json", "key": key},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code < 400:
            data = response.json()
            metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
            stats = data.get("stats", {}) if isinstance(data, dict) else {}
            total = stats.get("total") if isinstance(stats, dict) else data.get("total")
            classifications = data.get("classifications", []) if isinstance(data, dict) else []
            malicious_count = _count_malicious(classifications)
            risk_level = "high" if malicious_count > 0 else "low"
            return {
                "source": "greynoise",
                "target_type": target_type,
                "asn": int(normalized),
                "query": query,
                "total": total,
                "classifications": classifications if isinstance(classifications, list) else [],
                "actors": metadata.get("actors") if isinstance(metadata, dict) else None,
                "tags": metadata.get("tags") if isinstance(metadata, dict) else None,
                "countries": metadata.get("countries") if isinstance(metadata, dict) else None,
                "organizations": metadata.get("organizations") if isinstance(metadata, dict) else None,
                "operating_systems": metadata.get("operating_systems") if isinstance(metadata, dict) else None,
                "risk_level": risk_level,
                "api_model": "v3_gnql_metadata",
            }
        last_error = short_http_error(response)

        response = requests.get(
            "https://api.greynoise.io/v2/experimental/gnql/stats",
            params={"query": query},
            headers={"accept": "application/json", "key": key},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            message = short_http_error(response)
            return {
                "source": "greynoise",
                "target_type": target_type,
                "asn": int(normalized),
                "query": query,
                "error": message,
                "fallback_error": last_error,
                "plan_limited": response.status_code in {401, 403},
            }
        data = response.json()
        classifications = data.get("classifications", []) if isinstance(data, dict) else []
        malicious_count = _count_malicious(classifications)
        risk_level = "high" if malicious_count > 0 else "low"
        return {
            "source": "greynoise",
            "target_type": target_type,
            "asn": int(normalized),
            "query": query,
            "total": data.get("total") if isinstance(data, dict) else None,
            "classifications": classifications if isinstance(classifications, list) else [],
            "actors": data.get("actors") if isinstance(data, dict) else None,
            "tags": data.get("tags") if isinstance(data, dict) else None,
            "countries": data.get("countries") if isinstance(data, dict) else None,
            "organizations": data.get("organizations") if isinstance(data, dict) else None,
            "operating_systems": data.get("operating_systems") if isinstance(data, dict) else None,
            "risk_level": risk_level,
            "api_model": "v2_experimental_gnql_stats",
        }

    if target_type != "ip":
        return {"source": "greynoise", "target_type": target_type, "error": "greynoise_check_requires_ip_or_asn_target"}
    response = requests.get(
        f"https://api.greynoise.io/v3/community/{normalized}",
        headers={"accept": "application/json", "key": key},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return {"source": "greynoise", "target_type": target_type, "error": short_http_error(response)}
    data = response.json()
    noise = bool(data.get("noise"))
    riot = bool(data.get("riot"))
    classification = str(data.get("classification") or "").strip().lower()
    risk_level = "high" if classification == "malicious" else ("low" if riot else ("medium" if noise else "low"))
    return {
        "source": "greynoise",
        "target_type": target_type,
        "ip": data.get("ip"),
        "noise": noise,
        "riot": riot,
        "classification": data.get("classification"),
        "name": data.get("name"),
        "last_seen": data.get("last_seen"),
        "message": data.get("message"),
        "risk_level": risk_level,
    }


def summary(payload: dict[str, Any]) -> str:
    if str(payload.get("target_type")) == "asn":
        total = payload.get("total")
        risk = payload.get("risk_level", "low")
        return f"greynoise asn={payload.get('asn')} total={total} risk={risk}"
    cls = payload.get("classification")
    risk = payload.get("risk_level", "low")
    return f"greynoise classification={cls} risk={risk}"


def _count_malicious(classifications: list) -> int:
    for row in classifications:
        if not isinstance(row, dict):
            continue
        label = str(row.get("value") or row.get("name") or "").strip().lower()
        if label == "malicious":
            return int(row.get("count", 0) or 0)
    return 0
