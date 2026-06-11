"""IPinfo enrichment adapter — IP geolocation, ASN, and hostname."""

from __future__ import annotations

import os
from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type != "ip":
        return {"source": "ipinfo", "target_type": target_type, "error": "ipinfo_lookup_requires_ip_target"}

    # Free tier works without a token; token raises the rate limit
    token = key or os.environ.get("IPINFO_API_KEY", "")
    if token:
        url = f"https://ipinfo.io/{normalized}"
        params: dict[str, str] = {"token": token}
    else:
        url = f"https://ipinfo.io/{normalized}/json"
        params = {}

    response = requests.get(
        url,
        params=params,
        headers={"accept": "application/json"},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return {"source": "ipinfo", "target_type": target_type, "error": short_http_error(response)}

    data = response.json()
    org = str(data.get("org") or "")

    out: dict[str, Any] = {
        "source": "ipinfo",
        "target_type": target_type,
        "ip": data.get("ip"),
        "hostname": data.get("hostname"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "org": org,
        "timezone": data.get("timezone"),
        "loc": data.get("loc"),
    }

    # org field is "AS15169 Google LLC" — split into asn + org_name
    if org:
        parts = org.split(" ", 1)
        if parts[0].startswith("AS"):
            out["asn"] = parts[0]
            out["org_name"] = parts[1] if len(parts) > 1 else ""
        else:
            out["org_name"] = org

    return out


def summary(payload: dict[str, Any]) -> str:
    city = payload.get("city") or "-"
    country = payload.get("country") or "-"
    org = payload.get("org") or "-"
    return f"ipinfo city={city} country={country} org={org}"
