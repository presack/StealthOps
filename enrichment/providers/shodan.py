"""Shodan enrichment adapter."""

from __future__ import annotations

from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type not in {"ip", "asn"}:
        return {"source": "shodan", "target_type": target_type, "error": "shodan_lookup_requires_ip_or_asn_target"}

    if target_type == "asn":
        query = f"asn:AS{normalized}"
        base: dict[str, Any] = {
            "source": "shodan",
            "target_type": target_type,
            "asn": f"AS{normalized}",
            "query": query,
        }
        count_resp = requests.get(
            "https://api.shodan.io/shodan/host/count",
            params={"key": key, "query": query, "facets": "org:10,country:10,port:10"},
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if count_resp.status_code >= 400:
            if count_resp.status_code in {401, 403}:
                base["error"] = short_http_error(count_resp)
                base["auth_hint"] = _auth_diagnostic(key)
                return base
            base["error"] = short_http_error(count_resp)
            return base
        count_payload = count_resp.json()
        facets = count_payload.get("facets", {}) if isinstance(count_payload, dict) else {}

        def facet_values(name: str) -> list[dict[str, Any]]:
            values = facets.get(name, []) if isinstance(facets, dict) else []
            if not isinstance(values, list):
                return []
            return [v for v in values if isinstance(v, dict)]

        out = dict(base)
        out["total_matches"] = count_payload.get("total")
        out["top_orgs"] = facet_values("org")
        out["top_countries"] = facet_values("country")
        out["top_ports"] = facet_values("port")

        search_resp = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": query, "page": 1, "minify": "true"},
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if search_resp.status_code < 400:
            search_payload = search_resp.json()
            matches = search_payload.get("matches", []) if isinstance(search_payload, dict) else []
            sample_hosts: list[dict[str, Any]] = []
            if isinstance(matches, list):
                for item in matches[:12]:
                    if not isinstance(item, dict):
                        continue
                    location = item.get("location")
                    sample_hosts.append({
                        "ip": item.get("ip_str") or item.get("ip"),
                        "port": item.get("port"),
                        "transport": item.get("transport"),
                        "org": item.get("org"),
                        "isp": item.get("isp"),
                        "country": location.get("country_name") if isinstance(location, dict) else None,
                    })
            out["sample_hosts"] = sample_hosts
            out["sample_count"] = len(sample_hosts)
        return out

    url = f"https://api.shodan.io/shodan/host/{normalized}"
    response = requests.get(
        url,
        params={"key": key},
        headers={"accept": "application/json"},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        if response.status_code in {401, 403}:
            return {
                "source": "shodan",
                "target_type": target_type,
                "error": short_http_error(response),
                "auth_hint": _auth_diagnostic(key),
            }
        return {"source": "shodan", "target_type": target_type, "error": short_http_error(response)}

    payload = response.json()
    ports = payload.get("ports", []) if isinstance(payload, dict) else []
    vulns = payload.get("vulns", []) if isinstance(payload, dict) else []
    hostnames = payload.get("hostnames", []) if isinstance(payload, dict) else []
    tags = payload.get("tags", []) if isinstance(payload, dict) else []
    data_rows = payload.get("data", []) if isinstance(payload, dict) else []
    service_preview: list[str] = []
    if isinstance(data_rows, list):
        for row in data_rows[:8]:
            if not isinstance(row, dict):
                continue
            port = row.get("port")
            transport = str(row.get("transport") or "tcp")
            product = str(row.get("product") or row.get("devicetype") or "unknown")
            service_preview.append(f"{port}/{transport} {product}")
    open_port_count = len(ports) if isinstance(ports, list) else 0
    return {
        "source": "shodan",
        "target_type": target_type,
        "ip_str": payload.get("ip_str"),
        "org": payload.get("org"),
        "isp": payload.get("isp"),
        "os": payload.get("os"),
        "ports": ports[:20],
        "open_port_count": open_port_count,
        "hostnames": hostnames[:8] if isinstance(hostnames, list) else [],
        "tags": tags[:8] if isinstance(tags, list) else [],
        "last_update": payload.get("last_update"),
        "service_preview": service_preview,
        "vuln_count": len(vulns) if isinstance(vulns, list) else 0,
        "country_name": payload.get("country_name"),
    }


def summary(payload: dict[str, Any]) -> str:
    if str(payload.get("target_type")) == "asn":
        total = payload.get("total_matches")
        asn = payload.get("asn")
        return f"shodan asn={asn} matches={total}"
    ports = int(payload.get("open_port_count", 0) or 0)
    vulns = int(payload.get("vuln_count", 0) or 0)
    return f"shodan ports={ports} vulns={vulns}"


def _auth_diagnostic(api_key: str) -> str:
    try:
        response = requests.get(
            "https://api.shodan.io/api-info",
            params={"key": api_key},
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return "API key rejected by /api-info; verify SHODAN_API_KEY and account API access."
        payload = response.json()
        if isinstance(payload, dict):
            plan = payload.get("plan")
            scan_credits = payload.get("scan_credits")
            query_credits = payload.get("query_credits")
            return f"api-info ok (plan={plan}, query_credits={query_credits}, scan_credits={scan_credits})"
        return "api-info returned non-JSON payload."
    except Exception:
        return "Could not validate key with /api-info endpoint."
