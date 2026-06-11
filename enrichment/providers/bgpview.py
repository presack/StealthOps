"""BGPView enrichment adapter — ASN prefix and upstream data."""

from __future__ import annotations

from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error

_BASE = "https://api.bgpview.io"


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type != "asn":
        return {"source": "bgpview", "target_type": target_type, "error": "bgpview_lookup_requires_asn_target"}

    out: dict[str, Any] = {
        "source": "bgpview",
        "target_type": target_type,
        "asn": int(normalized),
    }

    # Basic ASN details
    asn_data, asn_err = _get(f"/asn/{normalized}")
    if asn_err:
        out["error"] = asn_err
        return out
    out["name"] = asn_data.get("name")
    out["description"] = asn_data.get("description_short")
    out["country_code"] = asn_data.get("country_code")
    out["website"] = asn_data.get("website")
    abuse = asn_data.get("abuse_contacts") or []
    if abuse:
        out["abuse_contacts"] = [c for c in abuse[:5] if c]

    # Announced prefixes
    pfx_data, pfx_err = _get(f"/asn/{normalized}/prefixes")
    if not pfx_err:
        ipv4 = pfx_data.get("ipv4_prefixes") or []
        ipv6 = pfx_data.get("ipv6_prefixes") or []
        out["ipv4_prefix_count"] = len(ipv4)
        out["ipv6_prefix_count"] = len(ipv6)
        out["ipv4_prefixes"] = [p.get("prefix") for p in ipv4[:20] if isinstance(p, dict)]
    else:
        out["prefixes_error"] = pfx_err

    # Upstream ASNs
    up_data, up_err = _get(f"/asn/{normalized}/upstreams")
    if not up_err:
        ipv4_up = up_data.get("ipv4_upstreams") or []
        out["upstream_count"] = len(ipv4_up)
        out["upstreams"] = [
            {"asn": u.get("asn"), "name": u.get("name")}
            for u in ipv4_up[:10] if isinstance(u, dict)
        ]
    else:
        out["upstreams_error"] = up_err

    return out


def summary(payload: dict[str, Any]) -> str:
    asn = payload.get("asn")
    name = payload.get("name") or payload.get("description") or "-"
    cc = payload.get("country_code") or "-"
    pfx = payload.get("ipv4_prefix_count")
    pfx_str = f" prefixes={pfx}" if pfx is not None else ""
    return f"bgpview asn=AS{asn} name={name} country={cc}{pfx_str}"


def _get(path: str) -> tuple[dict[str, Any], str]:
    try:
        response = requests.get(
            f"{_BASE}{path}",
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {}, short_http_error(response)
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("status") != "ok":
            return {}, f"unexpected_response: {str(payload)[:120]}"
        data = payload.get("data") or {}
        return data if isinstance(data, dict) else {}, ""
    except Exception as exc:
        return {}, str(exc)
