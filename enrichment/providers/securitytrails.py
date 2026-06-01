"""SecurityTrails enrichment adapter."""

from __future__ import annotations

from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, extract_domain_from_url, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type == "ip":
        return {"source": "securitytrails", "target_type": target_type, "error": "securitytrails_domain_lookup_requires_domain_or_url"}
    domain = normalized if target_type == "domain" else extract_domain_from_url(normalized)
    if not domain:
        return {"source": "securitytrails", "target_type": target_type, "error": "unable_to_extract_domain"}

    headers = {"accept": "application/json", "APIKEY": key}
    out: dict[str, Any] = {
        "source": "securitytrails",
        "target_type": target_type,
        "domain": domain,
    }

    domain_resp = requests.get(
        f"https://api.securitytrails.com/v1/domain/{domain}",
        headers=headers,
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if domain_resp.status_code >= 400:
        return {
            "source": "securitytrails",
            "target_type": target_type,
            "domain": domain,
            "error": short_http_error(domain_resp),
        }
    domain_payload = domain_resp.json() if domain_resp.headers.get("content-type", "").startswith("application/json") else {}
    if isinstance(domain_payload, dict):
        current_dns = domain_payload.get("current_dns", {})
        a_records = []
        if isinstance(current_dns, dict):
            a_obj = current_dns.get("a", {})
            if isinstance(a_obj, dict):
                values = a_obj.get("values", [])
                if isinstance(values, list):
                    for item in values:
                        if isinstance(item, dict):
                            ip = str(item.get("ip") or "").strip()
                            if ip and ip not in a_records:
                                a_records.append(ip)
        out.update({
            "apex_domain": domain_payload.get("apex_domain"),
            "hostname": domain_payload.get("hostname"),
            "current_a_records": a_records,
            "current_ns_records": (
                current_dns.get("ns", {}).get("values", [])
                if isinstance(current_dns.get("ns"), dict) else []
            ),
            "current_mx_records": (
                current_dns.get("mx", {}).get("values", [])
                if isinstance(current_dns.get("mx"), dict) else []
            ),
            "current_txt_records": (
                current_dns.get("txt", {}).get("values", [])
                if isinstance(current_dns.get("txt"), dict) else []
            ),
        })

    sub_resp = requests.get(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        headers=headers,
        params={"children_only": "false"},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if sub_resp.status_code < 400 and sub_resp.headers.get("content-type", "").startswith("application/json"):
        sub_payload = sub_resp.json()
        subdomains = sub_payload.get("subdomains", []) if isinstance(sub_payload, dict) else []
        if isinstance(subdomains, list):
            out["subdomain_count"] = len(subdomains)
            out["subdomains"] = [f"{str(s).strip()}.{domain}" for s in subdomains if str(s).strip()]
    else:
        out["subdomains_error"] = short_http_error(sub_resp)

    hist_resp = requests.get(
        f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
        headers=headers,
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if hist_resp.status_code < 400 and hist_resp.headers.get("content-type", "").startswith("application/json"):
        hist_payload = hist_resp.json()
        records = hist_payload.get("records", []) if isinstance(hist_payload, dict) else []
        history_entries: list[str] = []
        if isinstance(records, list):
            for row in records:
                if not isinstance(row, dict):
                    continue
                first_seen = str(row.get("first_seen") or "").strip()
                last_seen = str(row.get("last_seen") or "").strip()
                values = row.get("values", [])
                ips: list[str] = []
                if isinstance(values, list):
                    for item in values:
                        if isinstance(item, dict):
                            ip = str(item.get("ip") or "").strip()
                            if ip and ip not in ips:
                                ips.append(ip)
                if ips:
                    stamp = f"{first_seen}..{last_seen}" if first_seen and last_seen else (first_seen or last_seen)
                    entry = f"{', '.join(ips)} ({stamp})" if stamp else ", ".join(ips)
                    history_entries.append(entry)
        if history_entries:
            out["ip_history_count"] = len(history_entries)
            out["ip_history"] = history_entries
    else:
        out["ip_history_error"] = short_http_error(hist_resp)

    return out


def summary(payload: dict[str, Any]) -> str:
    domain = payload.get("domain") or "-"
    sub_count = payload.get("subdomain_count") or 0
    return f"securitytrails domain={domain} subdomains={sub_count}"
