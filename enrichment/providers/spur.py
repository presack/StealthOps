"""Spur enrichment adapter."""

from __future__ import annotations

from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def _tunnel_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _unique_tunnel_values(tunnels: list[dict[str, Any]], key: str) -> list[Any]:
    values: list[Any] = []
    for tunnel in tunnels:
        value = tunnel.get(key)
        if value in (None, "") or value in values:
            continue
        values.append(value)
    return values


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type != "ip":
        return {"source": "spur", "target_type": target_type, "error": "spur_context_lookup_requires_ip_target"}

    url = f"https://api.spur.us/v2/context/{normalized}"
    response = requests.get(
        url,
        headers={"token": key, "accept": "application/json"},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return {"source": "spur", "target_type": target_type, "error": short_http_error(response)}
    payload = response.json()

    tunnels = _tunnel_records(payload.get("tunnels") if isinstance(payload, dict) else None)
    tunnel_operators = _unique_tunnel_values(tunnels, "operator")
    tunnel_types = _unique_tunnel_values(tunnels, "type")
    client = payload.get("client", {}) if isinstance(payload, dict) else {}
    asn = payload.get("as", {}) if isinstance(payload, dict) else {}
    location = payload.get("location", {}) if isinstance(payload, dict) else {}
    risks = payload.get("risks") if isinstance(payload, dict) else None
    if not isinstance(risks, list):
        risks = []
    proxies = client.get("proxies") if isinstance(client, dict) else None
    if not isinstance(proxies, list):
        proxies = []
    risk_level = "low"
    high_markers = {"CALLBACK_PROXY", "TUNNEL"}
    if any(str(r).upper() in high_markers for r in risks):
        risk_level = "high"
    elif risks or proxies:
        risk_level = "medium"
    return {
        "source": "spur",
        "target_type": target_type,
        "ip": payload.get("ip") if isinstance(payload, dict) else normalized,
        "organization": payload.get("organization") if isinstance(payload, dict) else None,
        "as": asn if isinstance(asn, dict) else None,
        "as_number": asn.get("number") if isinstance(asn, dict) else None,
        "as_organization": asn.get("organization") if isinstance(asn, dict) else None,
        "location": location if isinstance(location, dict) else None,
        "location_city": location.get("city") if isinstance(location, dict) else None,
        "location_state": location.get("state") if isinstance(location, dict) else None,
        "location_country": location.get("country") if isinstance(location, dict) else None,
        "client": client if isinstance(client, dict) else None,
        "client_count": client.get("count") if isinstance(client, dict) else None,
        "client_types": client.get("types") if isinstance(client, dict) else None,
        "infrastructure": payload.get("infrastructure"),
        "client_proxies": proxies,
        "client_behaviors": client.get("behaviors") if isinstance(client, dict) else None,
        "tunnels": tunnels,
        "tunnel_operator": tunnel_operators[0] if tunnel_operators else None,
        "tunnel_operators": tunnel_operators,
        "tunnel_type": tunnel_types[0] if tunnel_types else None,
        "tunnel_types": tunnel_types,
        "risks": risks,
        "risk_level": risk_level,
    }


def summary(payload: dict[str, Any]) -> str:
    risk = payload.get("risk_level", "low")
    count = len(payload.get("risks", [])) if isinstance(payload.get("risks"), list) else 0
    return f"spur risk={risk} markers={count}"
