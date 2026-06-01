"""Censys enrichment adapter."""

from __future__ import annotations

import os
from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, short_http_error


def run(target: str, credentials: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if credentials.startswith("pat:"):
        token = credentials[len("pat:"):]
        if target_type == "asn":
            organization_id = str(os.environ.get("CENSYS_ORGANIZATION_ID", "")).strip()
            hits, query_used, error = _platform_asn_search(token, normalized, organization_id)
            if error:
                legacy_hits = _legacy_asn_fallback(token, normalized)
                if legacy_hits:
                    sample_hosts: list[dict[str, Any]] = []
                    for item in legacy_hits[:20]:
                        if not isinstance(item, dict):
                            continue
                        sample_hosts.append({"ip": item.get("ip"), "name": item.get("name"), "services": item.get("services")})
                    return {
                        "source": "censys",
                        "target_type": target_type,
                        "auth_model": "pat_legacy_fallback",
                        "asn": int(normalized),
                        "query": f"autonomous_system.asn: {normalized}",
                        "match_count": len(legacy_hits),
                        "sample_hosts": sample_hosts,
                        "fallback_reason": error,
                    }
                return {
                    "source": "censys",
                    "target_type": target_type,
                    "auth_model": "pat",
                    "asn": int(normalized),
                    "error": error,
                }
            sample_hosts = []
            sample_orgs: list[str] = []
            sample_countries: list[str] = []
            for item in hits[:20]:
                host = item.get("host") if isinstance(item.get("host"), dict) else item
                if not isinstance(host, dict):
                    continue
                ip = host.get("ip") or host.get("id")
                as_block = host.get("autonomous_system")
                org = None
                if isinstance(as_block, dict):
                    org = as_block.get("organization") or as_block.get("name")
                loc = host.get("location")
                country = loc.get("country") if isinstance(loc, dict) else None
                if ip:
                    sample_hosts.append({"ip": ip, "organization": org, "country": country})
                if org and str(org) not in sample_orgs:
                    sample_orgs.append(str(org))
                if country and str(country) not in sample_countries:
                    sample_countries.append(str(country))
            return {
                "source": "censys",
                "target_type": target_type,
                "auth_model": "pat",
                "asn": int(normalized),
                "query": query_used,
                "match_count": len(hits),
                "sample_hosts": sample_hosts,
                "sample_orgs": sample_orgs[:12],
                "sample_countries": sample_countries[:12],
                "organization_id_used": organization_id or None,
            }

        if target_type != "ip":
            return {
                "source": "censys",
                "target_type": target_type,
                "error": "platform_pat_adapter_currently_supports_ip_or_asn_lookup_only",
            }
        organization_id = str(os.environ.get("CENSYS_ORGANIZATION_ID", "")).strip()
        url = f"https://api.platform.censys.io/v3/global/asset/host/{normalized}"
        params = {"organization_id": organization_id} if organization_id else None
        response = requests.get(
            url,
            headers={"accept": "application/vnd.censys.api.v3.host.v1+json", "authorization": token},
            params=params,
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code in {401, 403}:
            response = requests.get(
                url,
                headers={"accept": "application/vnd.censys.api.v3.host.v1+json", "authorization": f"Bearer {token}"},
                params=params,
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
        if response.status_code >= 400:
            return {"source": "censys", "target_type": target_type, "error": short_http_error(response)}
        payload = response.json().get("result", {})
        host_view = _select_host_view(payload)
        services = _extract_services(host_view)
        if not services:
            fallback_services = _search_services_fallback(token, normalized, organization_id)
            if fallback_services:
                services = fallback_services
        if not services:
            legacy_host = _legacy_host_fallback(token, normalized)
            legacy_services = _extract_services(legacy_host)
            if legacy_services:
                services = legacy_services
                host_view = legacy_host
        autonomous_system = host_view.get("autonomous_system", {}) if isinstance(host_view, dict) else {}
        location = host_view.get("location", {}) if isinstance(host_view, dict) else {}
        names = host_view.get("names", []) if isinstance(host_view, dict) else []
        reverse_dns = names[0] if isinstance(names, list) and names else None
        return {
            "source": "censys",
            "target_type": target_type,
            "auth_model": "pat",
            "ip": host_view.get("ip"),
            "reverse_dns": reverse_dns,
            "asn": autonomous_system.get("asn") if isinstance(autonomous_system, dict) else None,
            "autonomous_system": autonomous_system.get("name") if isinstance(autonomous_system, dict) else None,
            "organization": _extract_org(host_view),
            "location_city": location.get("city") if isinstance(location, dict) else None,
            "location_country": location.get("country") if isinstance(location, dict) else None,
            "service_count": len(services) if isinstance(services, list) else 0,
            "sample_ports": _extract_ports(services),
            "top_services": _top_services(services),
            "organization_id_used": organization_id or None,
            "result_keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
        }

    if credentials.startswith("basic:"):
        _, api_id, api_secret = credentials.split(":", 2)
        auth = (api_id, api_secret)
        if target_type == "asn":
            query = f"autonomous_system.asn: {normalized}"
            response = requests.get(
                "https://search.censys.io/api/v2/hosts/search",
                auth=auth,
                params={"q": query, "per_page": 25},
                headers={"accept": "application/json"},
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
            if response.status_code >= 400:
                return {"source": "censys", "target_type": target_type, "error": short_http_error(response)}
            payload = response.json().get("result", {})
            hits = payload.get("hits", []) if isinstance(payload, dict) else []
            sample_hosts = []
            if isinstance(hits, list):
                for item in hits[:20]:
                    if not isinstance(item, dict):
                        continue
                    sample_hosts.append({"ip": item.get("ip"), "name": item.get("name"), "services": item.get("services")})
            return {
                "source": "censys",
                "target_type": target_type,
                "auth_model": "legacy_basic",
                "asn": int(normalized),
                "query": query,
                "match_count": payload.get("total") if isinstance(payload, dict) else len(sample_hosts),
                "sample_hosts": sample_hosts,
            }
        if target_type == "ip":
            url = f"https://search.censys.io/api/v2/hosts/{normalized}"
            response = requests.get(url, auth=auth, headers={"accept": "application/json"}, timeout=ENRICHMENT_TIMEOUT_SECONDS)
            if response.status_code >= 400:
                return {"source": "censys", "target_type": target_type, "error": short_http_error(response)}
            payload = response.json().get("result", {})
            services = payload.get("services", []) if isinstance(payload, dict) else []
            return {
                "source": "censys",
                "target_type": target_type,
                "auth_model": "legacy_basic",
                "ip": payload.get("ip"),
                "autonomous_system": (payload.get("autonomous_system") or {}).get("name") if isinstance(payload, dict) else None,
                "location_country": (payload.get("location") or {}).get("country") if isinstance(payload, dict) else None,
                "service_count": len(services) if isinstance(services, list) else 0,
            }
        domain = normalized
        if target_type == "url":
            domain = normalized.split("://", 1)[-1].split("/", 1)[0].lower()
        query = f"names: {domain}"
        response = requests.get(
            "https://search.censys.io/api/v2/certificates/search",
            auth=auth,
            params={"q": query, "per_page": 5},
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {"source": "censys", "target_type": target_type, "error": short_http_error(response)}
        payload = response.json().get("result", {})
        hits = payload.get("hits", []) if isinstance(payload, dict) else []
        first = hits[0] if isinstance(hits, list) and hits else {}
        return {
            "source": "censys",
            "target_type": target_type,
            "auth_model": "legacy_basic",
            "query": query,
            "match_count": len(hits) if isinstance(hits, list) else 0,
            "sample_fingerprint": first.get("fingerprint_sha256") if isinstance(first, dict) else None,
        }

    return {"source": "censys", "target_type": target_type, "error": "invalid_censys_credentials_format"}


def summary(payload: dict[str, Any]) -> str:
    if str(payload.get("target_type")) == "asn":
        asn = payload.get("asn")
        matches = payload.get("match_count", 0)
        return f"censys asn={asn} matches={matches}"
    svc = int(payload.get("service_count", 0) or 0)
    asn = payload.get("asn")
    return f"censys services={svc} asn={asn}"


def _extract_services(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    for key in ("services", "host_services", "matched_services"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    for value in payload.values():
        if isinstance(value, dict):
            nested = _extract_services(value)
            if nested:
                return nested
        if isinstance(value, list):
            as_dicts = [item for item in value if isinstance(item, dict)]
            if as_dicts and any("port" in item for item in as_dicts):
                return as_dicts
    return []


def _select_host_view(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    resource = payload.get("resource")
    if isinstance(resource, dict):
        extensions = payload.get("extensions")
        if isinstance(extensions, dict):
            merged = dict(resource)
            for key, value in extensions.items():
                if key not in merged:
                    merged[key] = value
            return merged
        return resource
    return payload


def _extract_ports(services: list[dict[str, Any]], limit: int = 12) -> list[int]:
    ports: list[int] = []
    for item in services:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        if isinstance(port, int) and port not in ports:
            ports.append(port)
        if len(ports) >= limit:
            break
    return ports


def _top_services(services: list[dict[str, Any]], limit: int = 12) -> list[str]:
    out: list[str] = []
    for item in services:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        transport = str(item.get("transport_protocol") or item.get("transport") or "tcp")
        service_name = str(
            item.get("service_name") or item.get("extended_service_name") or item.get("banner_hash") or "unknown"
        )
        software = item.get("software")
        if isinstance(software, list) and software:
            first = software[0]
            if isinstance(first, dict):
                vendor = str(first.get("vendor") or "").strip()
                product = str(first.get("product") or "").strip()
                if vendor or product:
                    service_name = (vendor + " " + product).strip()
        value = f"{port}/{transport} {service_name}"
        if value not in out:
            out.append(value)
        if len(out) >= limit:
            break
    return out


def _extract_org(host_view: dict[str, Any]) -> str | None:
    if not isinstance(host_view, dict):
        return None
    candidates = [host_view.get("organization"), host_view.get("registered_owner"), host_view.get("whois_organization")]
    network = host_view.get("network")
    if isinstance(network, dict):
        candidates.append(network.get("name"))
        candidates.append(network.get("organization"))
    for value in candidates:
        text = str(value or "").strip()
        if text:
            return text
    return None


def _search_services_fallback(token: str, ip: str, organization_id: str) -> list[dict[str, Any]]:
    url = "https://api.platform.censys.io/v3/global/search/query"
    params = {"organization_id": organization_id} if organization_id else None
    body = {"query": f'host.ip="{ip}"', "per_page": 1}
    try:
        response = requests.post(
            url,
            headers={"accept": "application/json", "content-type": "application/json", "authorization": token},
            params=params,
            json=body,
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return []
        payload = response.json()
        hits = payload.get("result", {}).get("hits", []) if isinstance(payload, dict) else []
        if isinstance(hits, list) and hits:
            first_hit = hits[0]
            host = first_hit.get("host") if isinstance(first_hit.get("host"), dict) else first_hit
            return _extract_services(host)
    except Exception:
        pass
    return []


def _platform_asn_search(token: str, asn: str, organization_id: str) -> tuple[list[dict[str, Any]], str, str]:
    url = "https://api.platform.censys.io/v3/global/search/query"
    params = {"organization_id": organization_id} if organization_id else None
    body = {"query": f"autonomous_system.asn: {asn}", "per_page": 25}
    try:
        response = requests.post(
            url,
            headers={"accept": "application/json", "content-type": "application/json", "authorization": token},
            params=params,
            json=body,
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return [], "", short_http_error(response)
        payload = response.json()
        result = payload.get("result", {}) if isinstance(payload, dict) else {}
        hits = result.get("hits", []) if isinstance(result, dict) else []
        query_used = body["query"]
        return hits if isinstance(hits, list) else [], query_used, ""
    except Exception as exc:
        return [], "", str(exc)


def _legacy_asn_fallback(token: str, asn: str) -> list[dict[str, Any]]:
    query = f"autonomous_system.asn: {asn}"
    try:
        response = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            headers={"accept": "application/json", "authorization": f"Bearer {token}"},
            params={"q": query, "per_page": 25},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return []
        payload = response.json().get("result", {})
        hits = payload.get("hits", []) if isinstance(payload, dict) else []
        return hits if isinstance(hits, list) else []
    except Exception:
        return []


def _legacy_host_fallback(token: str, ip: str) -> dict[str, Any]:
    try:
        response = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            headers={"accept": "application/json", "authorization": f"Bearer {token}"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {}
        return response.json().get("result", {})
    except Exception:
        return {}
