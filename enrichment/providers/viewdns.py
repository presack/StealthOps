"""ViewDNS enrichment adapter."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, env_flag, extract_domain_from_url, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type == "ip":
        out: dict[str, Any] = {"source": "viewdns", "target_type": target_type}
        payload, error = _get("iplocation", {"ip": normalized}, key)
        if error:
            out["error"] = error
        else:
            node = payload.get("response", {}) if isinstance(payload, dict) else {}
            if isinstance(node, dict):
                out.update({
                    "country_name": node.get("country_name"),
                    "region_name": node.get("region_name"),
                    "city": node.get("city"),
                    "latitude": node.get("latitude"),
                    "longitude": node.get("longitude"),
                })

        rdns_payload, rdns_error = _get("reversedns", {"ip": normalized}, key)
        if not rdns_error and isinstance(rdns_payload, dict):
            response_node = rdns_payload.get("response", {})
            records = response_node.get("rdns", []) if isinstance(response_node, dict) else []
            if isinstance(records, list):
                hostnames: list[str] = []
                for row in records:
                    if isinstance(row, dict):
                        value = str(row.get("name") or row.get("ptr") or "").strip()
                        if value and value not in hostnames:
                            hostnames.append(value)
                if hostnames:
                    out["reverse_dns_hostnames"] = hostnames

        rev_ip_payload, rev_ip_error = _get("reverseip", {"host": normalized}, key)
        if not rev_ip_error and isinstance(rev_ip_payload, dict):
            domains = _extract_domains(rev_ip_payload)
            if domains:
                out["reverseip_domains"] = domains
                out["reverseip_domain_count"] = len(domains)

        spam_payload, spam_error = _get("spamdblookup", {"host": normalized}, key)
        if not spam_error and isinstance(spam_payload, dict):
            spam_rows = _extract_rows(spam_payload, ("spams", "spamdb", "records", "entries"))
            out["spam_db_listed"] = bool(spam_rows)
            if spam_rows:
                out["spam_db_hits"] = spam_rows
                out["spam_db_hit_count"] = len(spam_rows)
        elif spam_error:
            out["spam_db_error"] = spam_error

        abuse_payload, abuse_error = _get("abuselookup", {"domain": normalized}, key)
        if not abuse_error and isinstance(abuse_payload, dict):
            contacts = _extract_contact_emails(abuse_payload)
            if contacts:
                out["abuse_contacts"] = contacts
                out["abuse_contact_count"] = len(contacts)
        elif abuse_error:
            out["abuse_contact_error"] = abuse_error

        return out

    domain = normalized if target_type == "domain" else extract_domain_from_url(normalized)
    if not domain:
        return {"source": "viewdns", "target_type": target_type, "error": "unable_to_extract_domain"}

    out = {"source": "viewdns", "target_type": target_type, "domain": domain}

    whois_payload, whois_error = _get("whois/v2", {"domain": domain}, key)
    if whois_error:
        fallback = _domain_dnsrecord_fallback(domain, key, target_type)
        if fallback:
            out.update(fallback)
            out["partial_whois_error"] = whois_error
        else:
            out["error"] = whois_error
    else:
        node = whois_payload.get("response", {}) if isinstance(whois_payload, dict) else {}
        reg = node.get("registryData", {}) if isinstance(node, dict) else {}
        out.update({
            "domain_name": node.get("domainName") if isinstance(node, dict) else None,
            "registrar_name": node.get("registrarName") if isinstance(node, dict) else None,
            "created_date": reg.get("standardCreatedDate") or reg.get("createdDate") if isinstance(reg, dict) else None,
            "updated_date": reg.get("standardUpdatedDate") or reg.get("updatedDate") if isinstance(reg, dict) else None,
            "expires_date": reg.get("standardExpiresDate") or reg.get("expiresDate") if isinstance(reg, dict) else None,
            "abuse_email": reg.get("abuseEmail") if isinstance(reg, dict) else None,
            "registrant_name": _pick_value(node, reg, keys=("registrantName", "registrant_name", "name")),
            "registrant_organization": _pick_value(node, reg, keys=("registrantOrganization", "registrant_organization", "organization")),
            "registrant_email": _pick_value(node, reg, keys=("registrantEmail", "registrant_email", "email")),
        })

    dnsrecord_payload, dnsrecord_error = _get("dnsrecord", {"domain": domain}, key)
    if not dnsrecord_error and isinstance(dnsrecord_payload, dict):
        out.update(_extract_dns_records(dnsrecord_payload))
    elif dnsrecord_error:
        out["dnsrecord_error"] = dnsrecord_error

    sub_payload, sub_error = _get("subdomains", {"domain": domain}, key)
    if not sub_error and isinstance(sub_payload, dict):
        subs = _extract_subdomains(sub_payload)
        if subs:
            out["subdomain_count"] = len(subs)
            out["subdomains"] = subs
    elif sub_error:
        out["subdomains_error"] = sub_error

    ip_hist_payload, ip_hist_error = _get("iphistory", {"domain": domain}, key)
    if not ip_hist_error and isinstance(ip_hist_payload, dict):
        ip_history = _extract_ip_history(ip_hist_payload)
        if ip_history:
            out["ip_history_count"] = len(ip_history)
            out["ip_history"] = ip_history
    elif ip_hist_error:
        out["ip_history_error"] = ip_hist_error

    rev_payload, rev_error = _get("reverseip", {"host": domain}, key)
    if not rev_error and isinstance(rev_payload, dict):
        related = _extract_domains(rev_payload)
        if related:
            out["reverseip_domain_count"] = len(related)
            out["reverseip_domains"] = related
    elif rev_error:
        out["reverseip_error"] = rev_error

    spam_payload, spam_error = _get("spamdblookup", {"host": domain}, key)
    if not spam_error and isinstance(spam_payload, dict):
        spam_rows = _extract_rows(spam_payload, ("spams", "spamdb", "records", "entries"))
        out["spam_db_listed"] = bool(spam_rows)
        if spam_rows:
            out["spam_db_hits"] = spam_rows
            out["spam_db_hit_count"] = len(spam_rows)
    elif spam_error:
        out["spam_db_error"] = spam_error

    abuse_payload, abuse_error = _get("abuselookup", {"domain": domain}, key)
    if not abuse_error and isinstance(abuse_payload, dict):
        contacts = _extract_contact_emails(abuse_payload)
        if contacts:
            out["abuse_contacts"] = contacts
            out["abuse_contact_count"] = len(contacts)
    elif abuse_error:
        out["abuse_contact_error"] = abuse_error

    if env_flag("VIEWDNS_ENABLE_PIVOTS", default=False):
        mx_hosts = [str(v).strip() for v in out.get("mx_records", []) if str(v).strip()]
        if mx_hosts:
            reverse_mx_rows: list[dict[str, Any]] = []
            for host in mx_hosts[:3]:
                mx_payload, mx_error = _get("reversemx", {"mx": host}, key)
                if mx_error:
                    continue
                for row in _extract_domains_with_context(mx_payload, "mx", host):
                    if row not in reverse_mx_rows:
                        reverse_mx_rows.append(row)
            if reverse_mx_rows:
                out["reverse_mx_domains"] = reverse_mx_rows
                out["reverse_mx_domain_count"] = len(reverse_mx_rows)

        ns_hosts = [str(v).strip() for v in out.get("ns_records", []) if str(v).strip()]
        if ns_hosts:
            reverse_ns_rows: list[dict[str, Any]] = []
            for host in ns_hosts[:3]:
                ns_payload, ns_error = _get("reversens", {"ns": host}, key)
                if ns_error:
                    continue
                for row in _extract_domains_with_context(ns_payload, "ns", host):
                    if row not in reverse_ns_rows:
                        reverse_ns_rows.append(row)
            if reverse_ns_rows:
                out["reverse_ns_domains"] = reverse_ns_rows
                out["reverse_ns_domain_count"] = len(reverse_ns_rows)

        reverse_whois_query = (
            str(out.get("registrant_email") or "").strip()
            or str(out.get("abuse_email") or "").strip()
            or str(out.get("registrant_organization") or "").strip()
            or str(out.get("registrant_name") or "").strip()
        )
        if reverse_whois_query:
            rw_payload, rw_error = _get("reversewhois", {"q": reverse_whois_query}, key)
            if not rw_error and isinstance(rw_payload, dict):
                rw_rows = _extract_domains_with_context(rw_payload, "query", reverse_whois_query)
                if rw_rows:
                    out["reverse_whois_query"] = reverse_whois_query
                    out["reverse_whois_domains"] = rw_rows
                    out["reverse_whois_domain_count"] = len(rw_rows)
            elif rw_error:
                out["reverse_whois_error"] = rw_error
    else:
        out["pivot_lookups_skipped"] = True

    return out


def summary(payload: dict[str, Any]) -> str:
    domain = payload.get("domain") or "-"
    sub_count = payload.get("subdomain_count") or 0
    return f"viewdns domain={domain} subdomains={sub_count}"


def _get(endpoint: str, params: dict[str, Any], api_key: str) -> tuple[dict[str, Any], str]:
    query = {"apikey": api_key, "output": "json"}
    query.update(params)
    try:
        response = requests.get(
            f"https://api.viewdns.info/{endpoint}/",
            params=query,
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return {}, f"{endpoint}: {exc}"
    if response.status_code >= 400:
        return {}, short_http_error(response)
    try:
        payload = response.json()
    except ValueError:
        return {}, f"{endpoint}: unexpected_non_json_response"
    if not isinstance(payload, dict):
        return {}, "unexpected_non_json_response"
    if payload.get("error"):
        err = payload.get("error")
        if isinstance(err, dict):
            return payload, str(err.get("message") or err.get("code") or "viewdns_error")
        return payload, str(err)
    return payload, ""


def _extract_subdomains(payload: dict[str, Any]) -> list[str]:
    response_node = payload.get("response", {})
    rows = response_node.get("subdomains", []) if isinstance(response_node, dict) else []
    out: list[str] = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = str(row.get("subdomain") or row.get("name") or "").strip()
            if value and value not in out:
                out.append(value)
    priority_roots = {
        "www", "api", "app", "mail", "mx", "ns", "vpn", "sso", "portal", "login",
        "auth", "owa", "webmail", "cdn", "edge", "gateway", "admin", "prod", "staging", "stage", "dev", "test",
    }

    def score(hostname: str) -> tuple[int, int, int, str]:
        host = hostname.strip().lower()
        labels = [part for part in host.split(".") if part]
        depth = len(labels)
        left = labels[0] if labels else host
        left_root = left.split("-", 1)[0]
        bonus = 0
        if left in priority_roots or left_root in priority_roots:
            bonus += 100
        if any(ch.isdigit() for ch in left):
            bonus -= 15
        if len(left) >= 20:
            bonus -= 10
        return (-bonus, depth, len(host), host)

    return sorted(out, key=score)


def _extract_ip_history(payload: dict[str, Any]) -> list[str]:
    response_node = payload.get("response", {})
    rows = response_node.get("records", []) if isinstance(response_node, dict) else []
    grouped: dict[str, list[str]] = {}
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = str(row.get("ip") or row.get("address") or "").strip()
            date = str(row.get("lastseen") or row.get("date") or "").strip()
            if not ip:
                continue
            grouped.setdefault(ip, [])
            if date:
                grouped[ip].append(date)

    def parse_date(text: str) -> datetime | None:
        text = str(text or "").strip()
        if not text:
            return None
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except Exception:
            return None

    summaries: list[tuple[datetime, str]] = []
    for ip, dates in grouped.items():
        clean_dates = sorted({d for d in dates if d})
        parsed = [parse_date(d) for d in clean_dates]
        parsed_ok = [d for d in parsed if d is not None]
        if parsed_ok:
            first_seen_dt = min(parsed_ok)
            last_seen_dt = max(parsed_ok)
            first_seen = first_seen_dt.strftime("%Y-%m-%d")
            last_seen = last_seen_dt.strftime("%Y-%m-%d")
            count = len(clean_dates)
            summary_str = (
                f"{ip} ({last_seen}, hits={count})" if first_seen == last_seen
                else f"{ip} ({first_seen}..{last_seen}, hits={count})"
            )
            summaries.append((last_seen_dt, summary_str))
        else:
            summaries.append((datetime.min, ip))

    summaries.sort(key=lambda item: item[0], reverse=True)
    return [s for _, s in summaries]


def _extract_domains(payload: dict[str, Any]) -> list[str]:
    response_node = payload.get("response", {})
    rows = response_node.get("domains", []) if isinstance(response_node, dict) else []
    out: list[str] = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                value = str(row.get("name") or row.get("domain") or "").strip()
            else:
                value = str(row).strip()
            if value and value not in out:
                out.append(value)
    return out


def _pick_value(*sources: object, keys: tuple[str, ...]) -> str | None:
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in keys:
            value = source.get(key)
            if isinstance(value, dict):
                for nested_key in ("value", "name", "organization", "email"):
                    nested = str(value.get(nested_key) or "").strip()
                    if nested:
                        return nested
            text = str(value or "").strip()
            if text:
                return text
    return None


def _extract_rows(payload: dict[str, Any], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    response_node = payload.get("response", {})
    if not isinstance(response_node, dict):
        return []
    for key in keys:
        rows = response_node.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _extract_contact_emails(payload: dict[str, Any]) -> list[str]:
    rows = _extract_rows(payload, ("contacts", "abusecontacts", "abuse_contacts", "records"))
    out: list[str] = []
    for row in rows:
        for key in ("email", "contact", "abuse_contact", "abuse_email"):
            value = str(row.get(key) or "").strip()
            if value and value not in out:
                out.append(value)
    response_node = payload.get("response", {})
    if isinstance(response_node, dict):
        direct_contact = str(response_node.get("abusecontact") or "").strip()
        if direct_contact and direct_contact not in out:
            out.append(direct_contact)
        for key in ("email", "abuse_contact", "abuse_email"):
            value = str(response_node.get(key) or "").strip()
            if value and value not in out:
                out.append(value)
    return out


def _extract_domains_with_context(payload: dict[str, Any], label: str, label_value: str) -> list[dict[str, Any]]:
    rows = _extract_rows(payload, ("domains", "records", "results"))
    out: list[dict[str, Any]] = []
    for row in rows:
        domain = str(row.get("name") or row.get("domain") or "").strip()
        if not domain:
            continue
        entry: dict[str, Any] = {"domain": domain, label: label_value}
        last_resolved = str(row.get("last_resolved") or row.get("lastseen") or row.get("date") or "").strip()
        if last_resolved:
            entry["last_resolved"] = last_resolved
        if entry not in out:
            out.append(entry)
    return out


def _extract_dns_records(payload: dict[str, Any]) -> dict[str, Any]:
    response_node = payload.get("response", {})
    records = response_node.get("records", []) if isinstance(response_node, dict) else []
    if not isinstance(records, list):
        return {}
    a_records: list[str] = []
    ns_records: list[str] = []
    mx_records: list[str] = []
    txt_records: list[str] = []
    for row in records:
        if not isinstance(row, dict):
            continue
        record_type = str(row.get("type") or "").strip().upper()
        value = str(row.get("data") or row.get("value") or "").strip()
        if not value:
            continue
        if record_type == "A" and value not in a_records:
            a_records.append(value)
        elif record_type == "NS":
            ns_host = value.rstrip(".")
            if ns_host and ns_host not in ns_records:
                ns_records.append(ns_host)
        elif record_type == "MX":
            parts = value.split()
            mx_host = (parts[-1] if parts else value).rstrip(".")
            if mx_host and mx_host not in mx_records:
                mx_records.append(mx_host)
        elif record_type == "TXT" and value not in txt_records:
            txt_records.append(value)
    return {
        "record_count": len(records),
        "a_records": a_records[:8],
        "ns_records": ns_records[:8],
        "mx_records": mx_records[:8],
        "txt_records": txt_records[:8],
    }


def _domain_dnsrecord_fallback(domain: str, api_key: str, target_type: str) -> dict[str, Any] | None:
    response = requests.get(
        "https://api.viewdns.info/dnsrecord/",
        params={"apikey": api_key, "domain": domain, "output": "json"},
        headers={"accept": "application/json"},
        timeout=ENRICHMENT_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return None
    payload = response.json()
    out = {"source": "viewdns", "target_type": target_type, "domain": domain, "fallback_used": "dnsrecord"}
    out.update(_extract_dns_records(payload))
    return out
