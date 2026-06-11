"""AlienVault OTX enrichment adapter — threat intelligence pulse lookup."""

from __future__ import annotations

import ipaddress
from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error

_BASE = "https://otx.alienvault.com/api/v1/indicators"


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)

    if target_type == "ip":
        try:
            version = ipaddress.ip_address(normalized).version
        except ValueError:
            version = 4
        itype = "IPv4" if version == 4 else "IPv6"
        url = f"{_BASE}/{itype}/{normalized}/general"
    elif target_type == "domain":
        url = f"{_BASE}/domain/{normalized}/general"
    else:
        return {
            "source": "otx",
            "target_type": target_type,
            "error": "otx_lookup_requires_ip_or_domain_target",
        }

    response = requests.get(
        url,
        headers={"X-OTX-API-KEY": key, "accept": "application/json"},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return {"source": "otx", "target_type": target_type, "error": short_http_error(response)}

    data = response.json()
    pulse_info = data.get("pulse_info") or {}
    pulse_count = int(pulse_info.get("count") or 0)
    pulses = pulse_info.get("pulses") or []

    out: dict[str, Any] = {
        "source": "otx",
        "target_type": target_type,
        "pulse_count": pulse_count,
    }

    if target_type == "ip":
        reputation = data.get("reputation")
        out["reputation"] = reputation
        out["country_code"] = data.get("country_code")
        out["country_name"] = data.get("country_name")
        out["asn"] = data.get("asn")
        out["city"] = data.get("city")
        rep_val = int(reputation) if reputation is not None else 0
        if rep_val < 0:
            out["risk_level"] = "high"
        elif pulse_count > 0:
            out["risk_level"] = "medium"
        else:
            out["risk_level"] = "low"

    if pulses:
        out["top_pulse_names"] = [p.get("name", "") for p in pulses[:5] if p.get("name")]

    return out


def summary(payload: dict[str, Any]) -> str:
    count = payload.get("pulse_count", 0)
    rep = payload.get("reputation")
    if rep is not None:
        return f"otx pulses={count} reputation={rep}"
    return f"otx pulses={count}"
