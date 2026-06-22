"""Bulk indicator triage — flatten query results to CSV rows."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Callable

import cache as _cache_module
from enrichment import parse_enrichment_selection
from enrichment.providers._shared import classify_target


TRIAGE_COLUMNS = [
    "Target",
    "Type",
    "PTR / Hostname",
    "Resolved IPs",
    "ASN",
    "Organization",
    "Country",
    "CIDR",
    "City",
    "Registrar",
    "Created",
    "Expires",
    "Domain Status",
    "Nameservers",
    "MX Hosts",
    "VT Malicious",
    "VT Reputation",
    "AbuseIPDB Score",
    "AbuseIPDB Risk",
    "GreyNoise",
    "Shodan",
    "OTX Pulses",
    "IPv4 Prefixes",
    "Notes",
]

# Pre-checked provider set on the web UI triage form
TRIAGE_PRESET_PROVIDERS = {"virustotal", "abuseipdb", "greynoise", "otx", "ipinfo"}


def _safe(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _join(values: list | None, limit: int = 2) -> str:
    if not values:
        return ""
    items = [str(v) for v in values if v is not None and str(v).strip()][:limit]
    return ", ".join(items)


def flatten_result(target: str, result: dict) -> dict[str, str]:
    """Extract triage fields from a single query result into a flat row dict."""
    target_type, normalized = classify_target(target)

    row: dict[str, str] = {col: "" for col in TRIAGE_COLUMNS}
    row["Target"] = target
    row["Type"] = target_type

    address = result.get("address") or {}
    dns = result.get("dns") or {}
    mx_data = result.get("mx") or {}
    whois_data = result.get("whois") or {}
    nw = result.get("network_whois") or {}
    providers = (result.get("enrichment") or {}).get("providers") or {}

    errors: list[str] = []
    for key, section in [
        ("address_lookup_error", address),
        ("whois_error", whois_data),
        ("network_whois_error", nw),
        ("mx_error", mx_data),
    ]:
        val = _safe(section.get(key))
        if val:
            errors.append(val)

    if target_type == "ip":
        ptr = dns.get("ptr") or []
        row["PTR / Hostname"] = _safe(
            address.get("canonical_name") or (ptr[0] if ptr else "")
        )
        row["ASN"] = _safe(nw.get("asn"))
        row["Organization"] = _safe(nw.get("organization"))
        row["Country"] = _safe(nw.get("country"))
        row["CIDR"] = _safe(nw.get("cidr"))
        # Registration fields don't apply to IP targets
        for col in ("Registrar", "Created", "Expires", "Domain Status", "Nameservers", "MX Hosts"):
            row[col] = "N/A"

    elif target_type == "domain":
        a_records = dns.get("a") or []
        aaaa_records = dns.get("aaaa") or []
        row["Resolved IPs"] = _join(a_records + aaaa_records, 3)
        row["Registrar"] = _safe(whois_data.get("registrar"))
        row["Created"] = _safe(whois_data.get("creation_date"))
        row["Expires"] = _safe(whois_data.get("expiration_date"))
        status_list = whois_data.get("status") or []
        if isinstance(status_list, str):
            status_list = [status_list]
        row["Domain Status"] = _join(status_list, 3)
        ns = dns.get("ns") or whois_data.get("name_servers") or []
        row["Nameservers"] = _join(ns, 2)
        mx_list = mx_data.get("mx") or []
        hosts = [str(m.get("host", "")) for m in mx_list if isinstance(m, dict)]
        row["MX Hosts"] = _join(hosts, 2)
        # Network data is available for domains via the resolved A record
        if nw and not nw.get("network_whois_error"):
            row["ASN"] = _safe(nw.get("asn"))
            row["Organization"] = _safe(nw.get("organization"))
            row["Country"] = _safe(nw.get("country"))
            row["CIDR"] = _safe(nw.get("cidr"))
        else:
            row["ASN"] = "N/A"
            row["CIDR"] = "N/A"

    elif target_type == "asn":
        row["ASN"] = f"AS{normalized}"
        row["Organization"] = _safe(nw.get("organization"))

    # VirusTotal (IP + domain)
    vt = providers.get("virustotal") or {}
    if vt and not vt.get("error") and not vt.get("unsupported_target_type"):
        stats = vt.get("last_analysis_stats") or {}
        mal = stats.get("malicious")
        if mal is not None:
            row["VT Malicious"] = str(mal)
        rep = vt.get("reputation")
        if rep is not None:
            row["VT Reputation"] = str(rep)

    # AbuseIPDB (IP only)
    abuse = providers.get("abuseipdb") or {}
    if abuse and not abuse.get("error") and not abuse.get("unsupported_target_type"):
        score = abuse.get("abuse_confidence_score")
        if score is not None:
            row["AbuseIPDB Score"] = str(score)
        row["AbuseIPDB Risk"] = _safe(abuse.get("risk_level"))

    # GreyNoise (IP: classification + risk, ASN: total host count)
    gn = providers.get("greynoise") or {}
    if gn and not gn.get("error") and not gn.get("unsupported_target_type"):
        if target_type == "asn":
            total = gn.get("total")
            row["GreyNoise"] = f"{total} hosts" if total is not None else ""
        else:
            cls = _safe(gn.get("classification"))
            risk = _safe(gn.get("risk_level"))
            row["GreyNoise"] = f"{cls} ({risk})" if cls else ""

    # Shodan (IP: open port count, ASN: total host count)
    shodan = providers.get("shodan") or {}
    if shodan and not shodan.get("error") and not shodan.get("unsupported_target_type"):
        if target_type == "asn":
            total = shodan.get("total_matches")
            row["Shodan"] = f"{total} hosts" if total is not None else ""
        else:
            ports = shodan.get("open_port_count")
            row["Shodan"] = f"{ports} open ports" if ports is not None else ""

    # ipinfo (IP only — city, and ASN/Org fallback for RIPE/APNIC/LACNIC ranges
    # where RDAP omits origin ASN)
    ipinfo = providers.get("ipinfo") or {}
    if ipinfo and not ipinfo.get("error") and not ipinfo.get("unsupported_target_type"):
        row["City"] = _safe(ipinfo.get("city"))
        if target_type == "ip":
            if not row["ASN"]:
                row["ASN"] = _safe(ipinfo.get("asn"))
            if not row["Organization"]:
                row["Organization"] = _safe(ipinfo.get("org"))

    # AlienVault OTX (IP + domain — threat feed pulse count)
    otx = providers.get("otx") or {}
    if otx and not otx.get("error") and not otx.get("unsupported_target_type"):
        count = otx.get("pulse_count")
        if count is not None:
            row["OTX Pulses"] = str(count)

    # BGPView (ASN only — prefix count signals network size)
    bgpview = providers.get("bgpview") or {}
    if bgpview and not bgpview.get("error") and not bgpview.get("unsupported_target_type"):
        pfx = bgpview.get("ipv4_prefix_count")
        if pfx is not None:
            row["IPv4 Prefixes"] = str(pfx)

    row["Notes"] = "; ".join(errors)
    return row


def write_csv(rows: list[dict], filepath: Path) -> Path:
    """Write triage rows to a CSV file (UTF-8 with BOM for Excel). Returns path written."""
    filepath = Path(filepath)
    with filepath.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=TRIAGE_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return filepath


def write_csv_bytes(rows: list[dict]) -> bytes:
    """Return CSV content as UTF-8 bytes (for in-memory download)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=TRIAGE_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8-sig")


def bulk_query(
    targets: list[str],
    query_engine: object,
    enrich_mgr: object,
    enrich_selection: str = "off",
    force_refresh: bool = False,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[dict]:
    """Run a core query (+ optional enrichment) per target sequentially.

    Uses the existing cache layer for both core results and per-provider enrichment.
    Returns a list of flat triage row dicts matching TRIAGE_COLUMNS.
    """
    CACHE_TTL = _cache_module._TTL_DEFAULT
    rows: list[dict] = []
    total = len(targets)

    for i, target in enumerate(targets, 1):
        try:
            cached_core = (
                None if force_refresh
                else _cache_module.get(target, "core", ttl=CACHE_TTL)
            )
            if cached_core is not None:
                result: dict = dict(cached_core[0])
            else:
                result = query_engine.run_all(target, include_headers=False)
                _cache_module.put(
                    target, "core",
                    {k: v for k, v in result.items() if k != "enrichment"},
                )

            if parse_enrichment_selection(enrich_selection):
                providers_out: dict = {}
                resolved = enrich_mgr.resolve_requested(enrich_selection)
                for pname in resolved:
                    cached_p = (
                        None if force_refresh
                        else _cache_module.get(target, pname, ttl=CACHE_TTL)
                    )
                    if cached_p is not None:
                        providers_out[pname] = cached_p[0]
                    else:
                        payload = enrich_mgr.run_one(target, pname)
                        _cache_module.put(target, pname, payload)
                        providers_out[pname] = payload
                if providers_out:
                    result["enrichment"] = {
                        "enabled": True,
                        "providers": providers_out,
                    }

            rows.append(flatten_result(target, result))

        except Exception as exc:
            error_row: dict = {col: "" for col in TRIAGE_COLUMNS}
            error_row["Target"] = target
            error_row["Notes"] = f"error: {exc}"
            rows.append(error_row)

        if on_progress:
            on_progress(i, total)

    return rows
