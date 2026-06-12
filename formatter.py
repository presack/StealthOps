"""CLI output formatting for StealthOps."""

from __future__ import annotations

import ctypes
import os
import sys
from datetime import datetime, timezone
from typing import Callable

_ANSI_READY: bool | None = None


# ---------------------------------------------------------------------------
# ANSI / color helpers
# ---------------------------------------------------------------------------

def _c(enabled: bool, text: str, code: str) -> str:
    if not enabled:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def _enable_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import colorama  # type: ignore
        colorama.just_fix_windows_console()
        return True
    except Exception:
        pass
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
    handles = (-11, -12)
    kernel32 = ctypes.windll.kernel32
    ok_any = False
    for handle_id in handles:
        handle = kernel32.GetStdHandle(handle_id)
        if handle in (0, -1):
            continue
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            continue
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if kernel32.SetConsoleMode(handle, new_mode):
            ok_any = True
    return ok_any


def interactive_stdio() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def color_enabled(no_color: bool) -> bool:
    global _ANSI_READY
    if no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if not interactive_stdio():
        return False
    if _ANSI_READY is None:
        _ANSI_READY = _enable_ansi()
    return bool(_ANSI_READY)


def truncate_text(value: str, max_len: int = 64) -> str:
    text = value.strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def colorize_report(report: str, use_color: bool) -> str:
    if not use_color:
        return report
    out = []
    for line in report.splitlines():
        if line.startswith("==="):
            out.append(_c(True, line, "96"))
        elif line.startswith("error:"):
            out.append(_c(True, line, "91"))
        else:
            out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Human-readable field labels
# ---------------------------------------------------------------------------

def human_label(key: str) -> str:
    labels = {
        "domain_name": "Domain Name",
        "creation_date": "Creation Date",
        "expiration_date": "Expiration Date",
        "updated_date": "Updated Date",
        "whois_server": "WHOIS Server",
        "canonical_name": "Canonical Name",
        "derived_domain": "Derived Domain",
        "aliases": "Aliases",
        "addresses": "Addresses",
        "address_lookup_error": "Address Lookup Error",
        "status_code": "Status Code",
        "final_url": "Final URL",
        "tor_routed": "Tor Routed",
        "whois_error": "WHOIS Error",
        "network_whois_error": "Network WHOIS Error",
        "network_whois_warning": "Network WHOIS Warning",
        "net_name": "Net Name",
        "asn": "ASN",
        "net_type": "Net Type",
        "start_address": "Start Address",
        "end_address": "End Address",
        "ip_version": "IP Version",
        "abuse_email": "Abuse Email",
        "abuse_phone": "Abuse Phone",
        "rdap_url": "RDAP URL",
    }
    if key in labels:
        return labels[key]
    return key.replace("_", " ").strip().title()


# ---------------------------------------------------------------------------
# Main CLI report
# ---------------------------------------------------------------------------

def format_cli_report(result: dict, full: bool = False) -> str:
    address_data = result.get("address", {})
    dns_data = result.get("dns", {})
    mx_data = result.get("mx", {})
    whois_data = result.get("whois", {})
    network_whois_data = result.get("network_whois", {})
    headers_data = result.get("headers", {})
    enrichment_data = result.get("enrichment", {})

    if result.get("asn_query"):
        asn_num = result.get("asn_query", "")
        asn_rdap = result.get("asn_rdap", {})
        asn_lines: list[str] = []
        asn_lines.append(f"=== ASN LOOKUP ===  [source: RDAP autnum/{asn_num}]")
        for field, label in (
            ("handle", "Handle"),
            ("name", "Name"),
            ("org_name", "Organization"),
            ("type", "Type"),
            ("country", "Country"),
            ("autnum_range", "Autnum Range"),
            ("creation_date", "Registered"),
            ("updated_date", "Last Updated"),
            ("abuse_email", "Abuse Email"),
            ("abuse_phone", "Abuse Phone"),
            ("rdap_url", "RDAP Source"),
        ):
            value = asn_rdap.get(field)
            if value not in (None, ""):
                asn_lines.append(f"{label}: {value}")
        if asn_rdap.get("asn_rdap_error"):
            asn_lines.append(f"error: {asn_rdap['asn_rdap_error']}")
        rdap_record = str(asn_rdap.get("asn_rdap_record", "")).strip()
        if rdap_record:
            asn_lines.append("")
            asn_lines.append("=== ASN RDAP RECORD ===")
            asn_lines.extend(rdap_record.splitlines())
        if enrichment_data.get("enabled"):
            asn_lines.append("")
            enrich_block = format_enrichment_report(dict(enrichment_data), full=full).splitlines()
            if enrich_block:
                enrich_block[0] = "=== ENRICHMENT ===  [source: optional provider APIs]"
            asn_lines.extend(enrich_block)
            consensus_lines = build_enrichment_consensus(enrichment_data)
            if consensus_lines:
                asn_lines.append("")
                asn_lines.extend(consensus_lines)
        return "\n".join(asn_lines)

    lines: list[str] = []
    lines.append("=== ADDRESS LOOKUP ===  [source: resolver + DNS records]")
    for field in ["query", "canonical_name", "derived_domain", "aliases", "addresses", "address_lookup_error"]:
        if field in address_data:
            value = address_data[field]
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "-"
            lines.append(f"{human_label(field)}: {value}")

    lines.append("")
    lines.append("=== WHOIS ===  [source: whois <domain>]")
    whois_record = str(whois_data.get("domain_whois_record", "")).strip()
    whois_error = str(whois_data.get("whois_error", "")).strip()
    if whois_record:
        lines.extend(whois_record.splitlines())
    elif whois_error:
        lines.append(f"WHOIS Error: {whois_error}")
    else:
        lines.append("Awaiting data...")

    lines.append("")
    lines.append("=== DNS SUMMARY ===  [source: dns query A/AAAA]")
    lines.append(f"domain: {dns_data.get('domain', '-')}")
    lines.append(f"A: {', '.join(dns_data.get('a', [])) or '-'}")
    lines.append(f"AAAA: {', '.join(dns_data.get('aaaa', [])) or '-'}")

    lines.append("")
    lines.append("=== MX RECORDS ===  [source: dns query MX]")
    lines.append(f"Domain: {mx_data.get('domain', '-')}")
    mx_records = mx_data.get("mx", [])
    if mx_records:
        for entry in mx_records:
            lines.append(f"- {entry.get('priority', '-')}: {entry.get('host', '-')}")
    else:
        lines.append("- none")
    if "mx_warning" in mx_data:
        lines.append(f"mx_warning: {mx_data.get('mx_warning')}")
    if "mx_error" in mx_data:
        lines.append(f"mx_error: {mx_data.get('mx_error')}")

    lines.append("")
    lines.append("=== NETWORK WHOIS ===  [source: RDAP]")
    asn_present = "asn" in network_whois_data
    asn_reason = str(network_whois_data.get("asn_unavailable_reason", "")).strip()
    if asn_present:
        lines.append(f"ASN: {network_whois_data.get('asn')}")
    else:
        fallback = asn_reason or "unavailable (origin ASN was not returned by the RDAP response)"
        lines.append(f"ASN: {fallback}")
    for field in [
        "ip", "organization", "net_name", "cidr", "start_address", "end_address",
        "country", "ip_version", "net_type", "abuse_email", "abuse_phone", "rdap_url",
        "network_whois_warning", "network_whois_error",
    ]:
        if field in network_whois_data:
            value = network_whois_data[field]
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "-"
            lines.append(f"{human_label(field)}: {value}")

    lines.append("")
    lines.append("=== NS RECORDS ===  [source: dns query NS]")
    ns_records = dns_data.get("ns", [])
    if ns_records:
        for value in ns_records:
            lines.append(f"- {value}")
    else:
        lines.append("- none")

    lines.append("")
    lines.append("=== TXT RECORDS ===  [source: dns query TXT]")
    txt_records = dns_data.get("txt", [])
    if txt_records:
        for value in txt_records:
            lines.append(f"- {value}")
    else:
        lines.append("- none")

    lines.append("")
    lines.append("=== HTTP HEADERS ===  [source: GET + response headers]")
    if headers_data.get("skipped"):
        lines.append("Skipped (use --headers to enable)")
    elif "header_error" in headers_data:
        lines.append(f"URL: {headers_data.get('url', '-')}")
        lines.append(f"Tor Routed: {headers_data.get('tor_routed', '-')}")
        lines.append(f"header_error: {headers_data.get('header_error')}")
    else:
        lines.append(f"URL: {headers_data.get('url', '-')}")
        lines.append(f"Status Code: {headers_data.get('status_code', '-')}")
        lines.append(f"Final URL: {headers_data.get('final_url', '-')}")
        lines.append(f"Tor Routed: {headers_data.get('tor_routed', '-')}")
        lines.append("headers:")
        for key, value in headers_data.get("headers", {}).items():
            lines.append(f"- {key}: {value}")

    extra_dns = []
    for field in ("cname", "caa", "soa", "ptr"):
        vals = dns_data.get(field, [])
        if vals:
            extra_dns.append(f"{field.upper()}: {', '.join(vals)}")
    dns_notes = [f"{k}: {dns_data.get(k)}" for k in sorted(k for k in dns_data.keys() if k.endswith(("_error", "_warning")))]
    if extra_dns or dns_notes:
        lines.append("")
        lines.append("=== ADDITIONAL DNS ===")
        lines.extend(extra_dns)
        lines.extend(dns_notes)

    if enrichment_data.get("enabled"):
        lines.append("")
        enrich_block = format_enrichment_report(dict(enrichment_data), full=full).splitlines()
        if enrich_block:
            enrich_block[0] = "=== ENRICHMENT ===  [source: optional provider APIs]"
        lines.extend(enrich_block)
        consensus_lines = build_enrichment_consensus(enrichment_data)
        if consensus_lines:
            lines.append("")
            lines.extend(consensus_lines)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Enrichment consensus
# ---------------------------------------------------------------------------

def build_enrichment_consensus(enrichment_data: dict) -> list[str]:
    providers = enrichment_data.get("providers", {})
    if not isinstance(providers, dict) or not providers:
        return []

    def provider_risk(provider: str, payload: dict) -> tuple[str, str]:
        if not isinstance(payload, dict):
            return "unknown", "non-dict payload"
        if payload.get("error"):
            return "unknown", f"{provider}: error present"
        explicit = str(payload.get("risk_level", "")).strip().lower()
        if explicit in {"high", "medium", "low"}:
            return explicit, f"{provider}: risk_level={explicit}"

        if provider == "virustotal":
            stats = payload.get("last_analysis_stats", {})
            mal = int(stats.get("malicious", 0) or 0) if isinstance(stats, dict) else 0
            susp = int(stats.get("suspicious", 0) or 0) if isinstance(stats, dict) else 0
            rep = int(payload.get("reputation", 0) or 0)
            if mal > 0 or rep < 0:
                return "high", f"{provider}: malicious={mal}, reputation={rep}"
            if susp > 0:
                return "medium", f"{provider}: suspicious={susp}"
            return "low", f"{provider}: no malicious/suspicious detections"

        if provider == "abuseipdb":
            score = int(payload.get("abuse_confidence_score", 0) or 0)
            if score >= 70:
                return "high", f"{provider}: abuse_confidence_score={score}"
            if score >= 20:
                return "medium", f"{provider}: abuse_confidence_score={score}"
            return "low", f"{provider}: abuse_confidence_score={score}"

        if provider == "greynoise":
            if str(payload.get("target_type")) == "asn":
                risk = str(payload.get("risk_level", "low")).lower()
                if risk in {"high", "medium", "low"}:
                    return risk, f"{provider}: asn risk_level={risk}"
                return "unknown", f"{provider}: asn stats incomplete"
            cls = str(payload.get("classification", "")).lower()
            if cls == "malicious":
                return "high", f"{provider}: classification=malicious"
            if bool(payload.get("noise")) and not bool(payload.get("riot")):
                return "medium", f"{provider}: noise=true riot=false"
            return "low", f"{provider}: no malicious/noise flags"

        if provider == "censys":
            if str(payload.get("target_type")) == "asn":
                matches = int(payload.get("match_count", 0) or 0)
                if matches >= 500:
                    return "high", f"{provider}: asn match_count={matches}"
                if matches >= 100:
                    return "medium", f"{provider}: asn match_count={matches}"
                return "low", f"{provider}: asn match_count={matches}"
            services = int(payload.get("service_count", 0) or 0)
            if services >= 20:
                return "high", f"{provider}: service_count={services}"
            if services >= 5:
                return "medium", f"{provider}: service_count={services}"
            return "low", f"{provider}: service_count={services}"

        if provider == "shodan":
            if str(payload.get("target_type")) == "asn":
                total = int(payload.get("total_matches", 0) or 0)
                if total >= 500:
                    return "high", f"{provider}: asn total_matches={total}"
                if total >= 100:
                    return "medium", f"{provider}: asn total_matches={total}"
                return "low", f"{provider}: asn total_matches={total}"
            vulns = int(payload.get("vuln_count", 0) or 0)
            open_ports = int(payload.get("open_port_count", 0) or 0)
            if vulns > 0 or open_ports >= 20:
                return "high", f"{provider}: vuln_count={vulns}, open_port_count={open_ports}"
            if open_ports >= 5:
                return "medium", f"{provider}: open_port_count={open_ports}"
            return "low", f"{provider}: open_port_count={open_ports}"

        if provider == "mxtoolbox":
            failed = int(payload.get("failed_count", 0) or 0)
            warns = int(payload.get("warning_count", 0) or 0)
            if failed > 0:
                return "high", f"{provider}: failed_count={failed}"
            if warns > 0:
                return "medium", f"{provider}: warning_count={warns}"
            return "low", f"{provider}: no failed/warning checks"

        if provider == "spur":
            risks = payload.get("risks", [])
            count = len(risks) if isinstance(risks, list) else 0
            if count >= 2:
                return "high", f"{provider}: risks={count}"
            if count == 1:
                return "medium", f"{provider}: risks=1"
            return "low", f"{provider}: no risks flagged"

        if provider == "spamhaus":
            listed = bool(payload.get("listed"))
            asn = payload.get("asn")
            if listed:
                return "high", f"{provider}: ASN AS{asn} is listed in ASN-DROP"
            return "low", f"{provider}: ASN AS{asn} not listed in ASN-DROP"

        return "unknown", f"{provider}: insufficient scoring metadata"

    assessed: list[tuple[str, str, str]] = []
    for provider in sorted(providers.keys()):
        payload = providers.get(provider, {})
        level, reason = provider_risk(provider, payload if isinstance(payload, dict) else {})
        assessed.append((provider, level, reason))

    high = sum(1 for _, level, _ in assessed if level == "high")
    medium = sum(1 for _, level, _ in assessed if level == "medium")
    low = sum(1 for _, level, _ in assessed if level == "low")
    unknown = sum(1 for _, level, _ in assessed if level == "unknown")

    overall = "low"
    if high >= 3:
        overall = "critical"
    elif high >= 1:
        overall = "high"
    elif medium >= 2:
        overall = "medium"

    use_color = bool(enrichment_data.get("_use_color"))

    def risk_color(level: str) -> str:
        if level in {"critical", "high"}:
            return "91"
        if level == "medium":
            return "93"
        if level == "low":
            return "92"
        return "97"

    def colorize(text: str, level: str) -> str:
        if not use_color:
            return text
        return _c(True, text, risk_color(level))

    lines: list[str] = []
    lines.append("=== ENRICHMENT CONSENSUS ===")
    lines.append(f"Overall Risk: {colorize(overall, overall)}")
    lines.append(
        "Votes: "
        + f"high={colorize(str(high), 'high')}, "
        + f"medium={colorize(str(medium), 'medium')}, "
        + f"low={colorize(str(low), 'low')}, "
        + f"unknown={colorize(str(unknown), 'unknown')}"
    )
    lines.append("Drivers:")
    drivers = [reason for _, level, reason in assessed if level in {"high", "medium"}]
    if not drivers:
        drivers = [reason for _, _, reason in assessed if reason]
    for reason in drivers[:5]:
        lines.append(f"- {reason}")
    lines.append("Provider Votes:")
    for provider, level, _ in assessed:
        lines.append(f"- {provider}: {colorize(level, level)}")
    return lines


# ---------------------------------------------------------------------------
# Enrichment report
# ---------------------------------------------------------------------------

def format_enrichment_report(enrichment_data: dict, full: bool = False) -> str:
    def ts_to_iso(value: object) -> str:
        try:
            ts = int(value)
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        except Exception:
            return str(value)

    def color_severity(text: str, severity: str, use_color: bool) -> str:
        if not use_color:
            return text
        if severity == "high":
            return _c(True, text, "91")
        if severity == "medium":
            return _c(True, text, "93")
        if severity == "low":
            return _c(True, text, "92")
        return text

    def append_summary(payload: dict, lines: list[str]) -> None:
        summary = payload.get("summary")
        if summary:
            lines.append(f"- summary: {summary}")

    def is_list_of_dicts(value: object) -> bool:
        return isinstance(value, list) and bool(value) and all(isinstance(v, dict) for v in value)

    def select_table_columns(rows: list[dict], provider: str = "", label: str = "") -> list[str]:
        provider_key = provider.strip().lower()
        label_key = label.strip().lower()
        provider_specific: dict[tuple[str, str], list[str]] = {
            ("virustotal", "findings"): ["engine", "category", "result", "method"],
            ("urlscan", "recent_scans"): ["time", "domain", "ip", "score", "result_url", "uuid"],
            ("securitytrails", "current_ns_records"): ["nameserver", "nameserver_organization", "nameserver_count"],
            ("securitytrails", "current_mx_records"): ["priority", "hostname", "hostname_organization"],
            ("securitytrails", "current_txt_records"): ["value"],
            ("viewdns", "ip_history"): ["ip", "date", "lastseen"],
            ("viewdns", "subdomains"): ["name", "subdomain", "ip"],
            ("viewdns", "reverseip_domains"): ["domain", "last_resolved"],
            ("viewdns", "reverse_mx_domains"): ["mx", "domain", "last_resolved"],
            ("viewdns", "reverse_ns_domains"): ["ns", "domain", "last_resolved"],
            ("viewdns", "reverse_whois_domains"): ["query", "domain", "last_resolved"],
            ("viewdns", "spam_db_hits"): ["name", "host", "ip", "lastseen", "type"],
            ("dnsdb", "rrsets"): ["rrname", "rrtype", "rdata", "count", "first_seen", "last_seen"],
            ("dnsdb", "subdomain_rrsets"): ["rrname", "rrtype", "rdata", "count", "first_seen", "last_seen"],
            ("dnsdb", "rdata_records"): ["rrname", "rrtype", "rdata", "count", "first_seen", "last_seen"],
            ("dnsdumpster", "a"): ["host", "ip", "asn", "asn_name", "country"],
            ("dnsdumpster", "ns"): ["host", "ip", "asn", "asn_name", "country"],
            ("dnsdumpster", "mx"): ["host", "ip", "asn", "asn_name", "country"],
            ("ripestat", "announced_prefixes"): ["prefix", "first_seen", "last_seen", "events"],
        }
        preferred = provider_specific.get((provider_key, label_key), [
            "engine", "category", "result", "command", "hostname", "nameserver", "priority",
            "ip", "domain", "time", "score", "value", "type", "port", "protocol", "service", "error",
        ])
        seen: set[str] = set()
        keys: list[str] = []
        for row in rows:
            for key in row.keys():
                if isinstance(key, str) and key not in seen:
                    seen.add(key)
                    keys.append(key)
        ordered = [k for k in preferred if k in seen]
        extras = sorted([k for k in keys if k not in ordered])
        cols = ordered + extras
        return cols[:6]

    def render_dict_list_table(lines: list[str], label: str, rows: list[dict], cap: int = 25, provider: str = "") -> None:
        if not rows:
            return
        if full:
            cap = 10_000
        shown = rows[:cap]
        cols = select_table_columns(shown, provider=provider, label=label)
        if not cols:
            return
        widths: dict[str, int] = {}
        for col in cols:
            widths[col] = min(28, max(len(col), *(len(str(r.get(col, "-"))) for r in shown)))
        lines.append(f"- {label} ({len(rows)}):")
        header = "  " + " | ".join(f"{col[:widths[col]]:<{widths[col]}}" for col in cols)
        sep = "  " + "-+-".join("-" * widths[col] for col in cols)
        lines.append(header)
        lines.append(sep)
        for row in shown:
            cells = []
            for col in cols:
                value = str(row.get(col, "-"))
                if len(value) > widths[col]:
                    value = value[: widths[col] - 3] + "..."
                cells.append(f"{value:<{widths[col]}}")
            lines.append("  " + " | ".join(cells))
        if len(rows) > cap:
            lines.append(f"  ... (+{len(rows)-cap} more)")

    def render_list_field(lines: list[str], label: str, value: list, cap: int = 30, provider: str = "") -> None:
        if not isinstance(value, list) or not value:
            return
        if full:
            cap = 10_000
        if is_list_of_dicts(value):
            render_dict_list_table(lines, label, value, cap=cap, provider=provider)
            return
        display = [str(v) for v in value[:cap]]
        tail = f" ... (+{len(value)-cap} more)" if len(value) > cap else ""
        lines.append(f"- {label}: {', '.join(display)}{tail}")

    def provider_header(name: str, use_color: bool) -> str:
        if not use_color:
            return f"[{name}]"
        palette = {
            "virustotal": "91", "abuseipdb": "31;103", "greynoise": "30;107", "censys": "96",
            "shodan": "94", "spur": "95", "mxtoolbox": "92", "viewdns": "93",
            "dnsdb": "96;44", "dnsdumpster": "36", "securitytrails": "34;103",
            "spamhaus": "97;41", "ripestat": "36;44",
        }
        return _c(True, f"[{name}]", palette.get(name, "97"))

    def vt_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        for key in ("target_type", "id", "as_owner", "country", "network"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        tags = payload.get("tags", [])
        if isinstance(tags, list) and tags:
            lines.append(f"- tags: {', '.join(str(v) for v in tags)}")
        reputation = payload.get("reputation")
        if reputation is not None:
            rep_sev = "high" if int(reputation) < 0 else ("low" if int(reputation) > 0 else "medium")
            rep_text = color_severity(str(reputation), rep_sev, use_color)
            lines.append(f"- reputation: {rep_text}")
        stats = payload.get("last_analysis_stats", {})
        if isinstance(stats, dict) and stats:
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            undetected = int(stats.get("undetected", 0) or 0)
            timeout = int(stats.get("timeout", 0) or 0)
            lines.append("- detection summary:")
            lines.append(f"  malicious: {color_severity(str(malicious), 'high', use_color)}")
            lines.append(f"  suspicious: {color_severity(str(suspicious), 'medium', use_color)}")
            lines.append(f"  harmless: {color_severity(str(harmless), 'low', use_color)}")
            lines.append(f"  undetected: {undetected}")
            lines.append(f"  timeout: {timeout}")
        votes = payload.get("total_votes", {})
        if isinstance(votes, dict) and votes:
            mal_votes = int(votes.get("malicious", 0) or 0)
            harmless_votes = int(votes.get("harmless", 0) or 0)
            lines.append("- community votes:")
            lines.append(f"  malicious: {color_severity(str(mal_votes), 'high', use_color)}")
            lines.append(f"  harmless: {color_severity(str(harmless_votes), 'low', use_color)}")
        mal_count = int(stats.get("malicious", 0) or 0) if isinstance(stats, dict) else 0
        susp_count = int(stats.get("suspicious", 0) or 0) if isinstance(stats, dict) else 0
        rep_num = int(reputation) if reputation is not None else 0
        vt_risk = "high" if mal_count > 0 or rep_num < 0 else ("medium" if susp_count > 0 else "low")
        lines.append(
            f"- risk: {color_severity(vt_risk, 'high' if vt_risk == 'high' else ('medium' if vt_risk == 'medium' else 'low'), use_color)} "
            f"(malicious={mal_count}, suspicious={susp_count}, reputation={rep_num})"
        )
        findings = payload.get("malicious_or_suspicious_findings", [])
        if isinstance(findings, list) and findings:
            render_dict_list_table(lines, "findings", [v for v in findings if isinstance(v, dict)], cap=30, provider=provider)
        if payload.get("whois_date") not in (None, ""):
            lines.append(f"- whois_date: {ts_to_iso(payload.get('whois_date'))}")
        handled = {
            "target_type", "id", "as_owner", "country", "network", "tags", "reputation",
            "last_analysis_stats", "total_votes", "malicious_or_suspicious_findings",
            "whois_date", "finding_count", "source",
        }
        for key in sorted(payload.keys()):
            if key in handled:
                continue
            value = payload.get(key)
            if value in (None, "", []):
                continue
            if isinstance(value, dict):
                lines.append("- " + key + ": " + ", ".join(f"{k}={v}" for k, v in sorted(value.items())))
            else:
                lines.append(f"- {key}: {value}")

    def censys_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
            if payload.get("fallback_reason"):
                lines.append(f"- fallback_reason: {payload.get('fallback_reason')}")
            for key in ("target_type", "auth_model", "asn", "query"):
                value = payload.get(key)
                if value not in (None, "", []):
                    lines.append(f"- {key}: {value}")
            return
        if str(payload.get("target_type")) == "asn":
            for key in ("target_type", "auth_model", "asn", "query", "match_count", "organization_id_used"):
                value = payload.get(key)
                if value in (None, "", []):
                    continue
                lines.append(f"- {key}: {value}")
            render_list_field(lines, "sample_hosts", payload.get("sample_hosts", []), cap=20, provider=provider)
            render_list_field(lines, "sample_orgs", payload.get("sample_orgs", []), cap=20, provider=provider)
            render_list_field(lines, "sample_countries", payload.get("sample_countries", []), cap=20, provider=provider)
            return
        for key in ("target_type", "auth_model", "ip", "reverse_dns", "organization", "asn", "autonomous_system", "location_city", "location_country"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        service_count = int(payload.get("service_count", 0) or 0)
        sev = "high" if service_count >= 20 else ("medium" if service_count >= 5 else "low")
        lines.append(f"- service_count: {color_severity(str(service_count), sev, use_color)}")
        top_services = payload.get("top_services", [])
        if isinstance(top_services, list) and top_services:
            lines.append("- top_services:")
            for svc in (top_services if full else top_services[:12]):
                lines.append(f"  - {svc}")
        sample_ports = payload.get("sample_ports", [])
        if isinstance(sample_ports, list) and sample_ports:
            lines.append(f"- sample_ports: {', '.join(str(p) for p in sample_ports)}")
        result_keys = payload.get("result_keys", [])
        if isinstance(result_keys, list) and result_keys:
            lines.append(f"- result_keys: {', '.join(str(k) for k in result_keys)}")

    def shodan_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
        if str(payload.get("target_type")) == "asn":
            for key in ("target_type", "asn", "query", "total_matches", "sample_count"):
                value = payload.get(key)
                if value in (None, "", []):
                    continue
                lines.append(f"- {key}: {value}")
            render_list_field(lines, "top_orgs", payload.get("top_orgs", []), cap=10, provider=provider)
            render_list_field(lines, "top_countries", payload.get("top_countries", []), cap=10, provider=provider)
            render_list_field(lines, "top_ports", payload.get("top_ports", []), cap=10, provider=provider)
            render_list_field(lines, "sample_hosts", payload.get("sample_hosts", []), cap=12, provider=provider)
            return
        for key in ("target_type", "ip_str", "org", "isp", "country_name", "os", "last_update"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        ports = payload.get("ports", [])
        if isinstance(ports, list) and ports:
            lines.append(f"- ports ({len(ports)}): {', '.join(str(p) for p in (ports if full else ports[:20]))}")
        open_count = int(payload.get("open_port_count", 0) or 0)
        lines.append(
            f"- open_port_count: {color_severity(str(open_count), 'high' if open_count >= 20 else ('medium' if open_count >= 5 else 'low'), use_color)}"
        )
        vuln_count = int(payload.get("vuln_count", 0) or 0)
        lines.append(f"- vuln_count: {color_severity(str(vuln_count), 'high' if vuln_count > 0 else 'low', use_color)}")
        hostnames = payload.get("hostnames", [])
        if isinstance(hostnames, list) and hostnames:
            lines.append(f"- hostnames: {', '.join(str(v) for v in hostnames)}")
        tags = payload.get("tags", [])
        if isinstance(tags, list) and tags:
            lines.append(f"- tags: {', '.join(str(v) for v in tags)}")
        preview = payload.get("service_preview", [])
        if isinstance(preview, list) and preview:
            lines.append("- service_preview:")
            for item in (preview if full else preview[:8]):
                lines.append(f"  - {item}")

    def spur_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        risk_level = str(payload.get("risk_level", "low"))
        sev = "high" if risk_level == "high" else ("medium" if risk_level == "medium" else "low")
        lines.append(f"- risk_level: {color_severity(risk_level, sev, use_color)}")
        for key in (
            "target_type", "ip", "organization", "as_number", "as_organization",
            "location_city", "location_state", "location_country", "infrastructure",
            "tunnel_operator", "tunnel_type", "client_count",
        ):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        for key in ("client_types", "client_behaviors", "client_proxies", "risks"):
            value = payload.get(key)
            if isinstance(value, list) and value:
                lines.append(f"- {key}: {', '.join(str(v) for v in value)}")

    def abuseipdb_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        score = int(payload.get("abuse_confidence_score", 0) or 0)
        risk_level = str(payload.get("risk_level", "low"))
        sev = "high" if risk_level == "high" else ("medium" if risk_level == "medium" else "low")
        lines.append(f"- risk_level: {color_severity(risk_level, sev, use_color)}")
        lines.append(f"- abuse_confidence_score: {color_severity(str(score), sev, use_color)}")
        for key in ("target_type", "ip_address", "country_code", "usage_type", "isp", "domain", "total_reports", "last_reported_at", "is_whitelisted"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")

    def greynoise_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
            if payload.get("plan_limited"):
                lines.append("- plan_limited: true")
            for key in ("target_type", "asn", "query", "api_model", "fallback_error"):
                value = payload.get(key)
                if value in (None, "", []):
                    continue
                lines.append(f"- {key}: {value}")
            return
        risk_level = str(payload.get("risk_level", "low"))
        sev = "high" if risk_level == "high" else ("medium" if risk_level == "medium" else "low")
        lines.append(f"- risk_level: {color_severity(risk_level, sev, use_color)}")
        if str(payload.get("target_type")) == "asn":
            for key in ("target_type", "asn", "query", "api_model", "total"):
                value = payload.get(key)
                if value in (None, "", []):
                    continue
                lines.append(f"- {key}: {value}")
            for key in ("classifications", "actors", "tags", "countries", "organizations", "operating_systems"):
                render_list_field(lines, key, payload.get(key, []), cap=20, provider=provider)
            if payload.get("fallback_error"):
                lines.append(f"- fallback_error: {payload.get('fallback_error')}")
            return
        for key in ("target_type", "ip", "classification", "noise", "riot", "name", "last_seen", "message"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")

    def dnsdumpster_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
        for key in ("target_type", "domain", "total_a_recs"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        for key in ("a_count", "ns_count", "mx_count", "cname_count", "txt_count"):
            value = payload.get(key)
            if value in (None, ""):
                continue
            lines.append(f"- {key}: {value}")
        if payload.get("pages_fetched") not in (None, ""):
            lines.append(f"- pages_fetched: {payload.get('pages_fetched')}")
        if payload.get("api_record_limit_hit") is True:
            lines.append(f"- api_record_limit_hit: {payload.get('api_record_limit_hit')}")
        if payload.get("limit_note"):
            lines.append(f"- limit_note: {payload.get('limit_note')}")
        for key, label in (
            ("a_hosts", "a_hosts"), ("ns_hosts", "ns_hosts"), ("mx_hosts", "mx_hosts"),
            ("resolved_ips", "resolved_ips"), ("txt_records", "txt_records"),
        ):
            value = payload.get(key)
            if isinstance(value, list) and value:
                render_list_field(lines, label, value, cap=40, provider=provider)
        result_keys = payload.get("result_keys", [])
        if isinstance(result_keys, list) and result_keys:
            lines.append(f"- result_keys: {', '.join(str(v) for v in result_keys)}")

    def dnsdb_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
        for key in ("target_type", "domain", "ip", "api_mode", "rrset_count", "rrname_count", "subdomain_count", "subdomain_rrset_count"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        for key, label, cap in (
            ("a_records", "a_records", 20), ("aaaa_records", "aaaa_records", 20),
            ("ns_records", "ns_records", 20), ("mx_records", "mx_records", 20),
            ("txt_records", "txt_records", 20), ("rrtypes", "rrtypes", 20),
            ("subdomains", "subdomains", 40), ("rrnames", "rrnames", 40),
            ("rrsets", "rrsets", 25), ("subdomain_rrsets", "subdomain_rrsets", 25),
            ("rdata_records", "rdata_records", 25),
        ):
            value = payload.get(key)
            if isinstance(value, list) and value:
                render_list_field(lines, label, value, cap=cap, provider=provider)
        if payload.get("subdomain_error"):
            lines.append(f"- subdomain_error: {payload.get('subdomain_error')}")

    def urlscan_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        def trunc(text: object, max_len: int) -> str:
            value = str(text or "")
            if len(value) <= max_len:
                return value
            return value[: max_len - 3] + "..."

        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
        risk_level = str(payload.get("risk_level", "low")).lower()
        sev = "high" if risk_level == "high" else ("medium" if risk_level == "medium" else "low")
        lines.append(f"- risk_level: {color_severity(risk_level, sev, use_color)}")
        for key in ("target_type", "query", "result_count", "total_available", "max_results_used", "truncated", "malicious_hits", "suspicious_hits", "submitted_scan", "submitted_uuid", "submitted_result"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        scans = payload.get("recent_scans", [])
        if isinstance(scans, list) and scans:
            lines.append("- recent_scans:")
            lines.append("  time                 score  domain                           ip               result")
            lines.append("  -------------------  -----  -------------------------------  ---------------  ----------------------------")
            max_rows = len(scans) if full else 20
            for scan in scans[:max_rows]:
                if not isinstance(scan, dict):
                    continue
                t = trunc(scan.get("time") or "-", 19)
                d = trunc(scan.get("domain") or "-", 31)
                ip = trunc(scan.get("ip") or "-", 15)
                score = trunc(scan.get("score") if scan.get("score") is not None else "-", 5)
                result_url = trunc(scan.get("result_url") or "", 28)
                lines.append(f"  {t:<19}  {score:>5}  {d:<31}  {ip:<15}  {result_url}")
            if len(scans) > max_rows:
                lines.append(f"  ... (+{len(scans)-max_rows} more shown in API payload)")

    def securitytrails_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        def as_list(value: object) -> list:
            return value if isinstance(value, list) else []

        def txt_val(item: object) -> str:
            if isinstance(item, dict):
                return str(item.get("value") or "").strip()
            return str(item or "").strip()

        def ns_name(item: object) -> str:
            if isinstance(item, dict):
                return str(item.get("nameserver") or item.get("hostname") or "").strip()
            return str(item or "").strip()

        def mx_name(item: object) -> str:
            if isinstance(item, dict):
                host = str(item.get("hostname") or item.get("exchange") or "").strip()
                prio = item.get("priority")
                if host and prio not in (None, ""):
                    return f"{prio} {host}"
                return host
            return str(item or "").strip()

        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
        for key in ("target_type", "domain", "apex_domain", "hostname", "subdomain_count", "ip_history_count"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")

        a_records = [str(v).strip() for v in as_list(payload.get("current_a_records")) if str(v).strip()]
        ns_records = [ns_name(v) for v in as_list(payload.get("current_ns_records")) if ns_name(v)]
        mx_records = [mx_name(v) for v in as_list(payload.get("current_mx_records")) if mx_name(v)]
        txt_records = [txt_val(v) for v in as_list(payload.get("current_txt_records")) if txt_val(v)]

        if a_records or ns_records or mx_records or txt_records:
            lines.append("- current_dns:")
            _a_cap, _ns_cap, _mx_cap, _txt_cap = (10_000, 10_000, 10_000, 10_000) if full else (12, 10, 10, 8)
            if a_records:
                lines.append(f"  A ({len(a_records)}): {', '.join(a_records[:_a_cap])}" + (f" ... (+{len(a_records)-_a_cap} more)" if len(a_records) > _a_cap else ""))
            if ns_records:
                lines.append(f"  NS ({len(ns_records)}): {', '.join(ns_records[:_ns_cap])}" + (f" ... (+{len(ns_records)-_ns_cap} more)" if len(ns_records) > _ns_cap else ""))
            if mx_records:
                lines.append(f"  MX ({len(mx_records)}): {', '.join(mx_records[:_mx_cap])}" + (f" ... (+{len(mx_records)-_mx_cap} more)" if len(mx_records) > _mx_cap else ""))
            if txt_records:
                shown_txt = txt_records if full else txt_records[:_txt_cap]
                preview = [v if len(v) <= 90 else v[:87] + "..." for v in shown_txt]
                lines.append(f"  TXT ({len(txt_records)}): " + " | ".join(preview) + (f" ... (+{len(txt_records)-_txt_cap} more)" if not full and len(txt_records) > _txt_cap else ""))

        subdomains = [str(v).strip() for v in as_list(payload.get("subdomains")) if str(v).strip()]
        if subdomains:
            high_signal_tokens = (
                "www", "api", "app", "auth", "login", "sso", "vpn", "portal", "mail", "webmail",
                "mx", "ns", "admin", "dev", "stage", "staging", "test", "prod", "cdn", "edge", "gateway",
            )
            high_signal: list[str] = []
            for host in subdomains:
                left = host.split(".", 1)[0].lower()
                left_root = left.split("-", 1)[0]
                if left in high_signal_tokens or left_root in high_signal_tokens:
                    if host not in high_signal:
                        high_signal.append(host)
            if high_signal:
                cap_hs = 10_000 if full else 20
                lines.append("- high_signal_subdomains:")
                for item in high_signal[:cap_hs]:
                    lines.append(f"  - {item}")
                if len(high_signal) > cap_hs:
                    lines.append(f"  ... (+{len(high_signal)-cap_hs} more)")
            cap = 10_000 if full else 30
            lines.append("- subdomains:")
            for item in subdomains[:cap]:
                lines.append(f"  - {item}")
            if len(subdomains) > cap:
                lines.append(f"  ... (+{len(subdomains)-cap} more)")

        ip_history = [str(v).strip() for v in as_list(payload.get("ip_history")) if str(v).strip()]
        if ip_history:
            cap = 10_000 if full else 20
            lines.append("- ip_history:")
            for item in ip_history[:cap]:
                lines.append(f"  - {item}")
            if len(ip_history) > cap:
                lines.append(f"  ... (+{len(ip_history)-cap} more)")
        for key in ("subdomains_error", "ip_history_error"):
            value = payload.get(key)
            if value:
                lines.append(f"- {key}: {value}")

    def viewdns_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
        if payload.get("partial_whois_error"):
            lines.append(f"- partial_whois_error: {payload.get('partial_whois_error')}")
        for key in (
            "target_type", "domain", "domain_name", "registrar_name", "created_date", "updated_date",
            "expires_date", "abuse_email", "country_name", "region_name", "city", "latitude", "longitude",
            "record_count", "fallback_used", "subdomain_count", "ip_history_count", "reverseip_domain_count",
            "reverse_mx_domain_count", "reverse_ns_domain_count", "reverse_whois_query",
            "reverse_whois_domain_count", "registrant_name", "registrant_organization", "registrant_email",
            "abuse_contact_count", "spam_db_hit_count", "spam_db_listed", "pivot_lookups_skipped",
            "key_fallback_used", "key_attempts",
        ):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        for key, label, cap in (
            ("a_records", "a_records", 20), ("ns_records", "ns_records", 20),
            ("mx_records", "mx_records", 20), ("txt_records", "txt_records", 20),
            ("subdomains", "subdomains", 40), ("ip_history", "ip_history", 25),
            ("reverseip_domains", "reverseip_domains", 25), ("reverse_mx_domains", "reverse_mx_domains", 25),
            ("reverse_ns_domains", "reverse_ns_domains", 25), ("reverse_whois_domains", "reverse_whois_domains", 25),
            ("reverse_dns_hostnames", "reverse_dns_hostnames", 20), ("abuse_contacts", "abuse_contacts", 15),
            ("key_errors", "key_errors", 10), ("spam_db_hits", "spam_db_hits", 20),
        ):
            value = payload.get(key)
            if isinstance(value, list) and value:
                render_list_field(lines, label, value, cap=cap, provider=provider)
        for key in (
            "subdomains_error", "ip_history_error", "reverseip_error", "dnsrecord_error",
            "abuse_contact_error", "spam_db_error", "reverse_whois_error",
        ):
            value = payload.get(key)
            if value:
                lines.append(f"- {key}: {value}")

    def mxtoolbox_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(f"[{provider}]")
        append_summary(payload, lines)
        for key in ("target_type", "command", "argument", "reporting_nameserver"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            lines.append(f"- {key}: {value}")
        commands_run = payload.get("commands_run", [])
        if isinstance(commands_run, list) and commands_run:
            lines.append(f"- commands_run: {', '.join(str(v) for v in commands_run)}")
        failed = int(payload.get("failed_count", 0) or 0)
        warnings = int(payload.get("warning_count", 0) or 0)
        passed = int(payload.get("passed_count", 0) or 0)
        lines.append(f"- failed_count: {color_severity(str(failed), 'high' if failed else 'low', use_color)}")
        lines.append(f"- warning_count: {color_severity(str(warnings), 'medium' if warnings else 'low', use_color)}")
        lines.append(f"- passed_count: {color_severity(str(passed), 'low', use_color)}")
        checks = payload.get("checks", [])
        if isinstance(checks, list) and checks:
            lines.append("- checks:")
            for check in checks:
                if not isinstance(check, dict):
                    continue
                cmd = str(check.get("command") or "-")
                if check.get("error"):
                    lines.append(f"  - {cmd}: error={check.get('error')}")
                    continue
                fc = int(check.get("failed_count", 0) or 0)
                wc = int(check.get("warning_count", 0) or 0)
                pc = int(check.get("passed_count", 0) or 0)
                lines.append(
                    "  - " + cmd
                    + f": failed={color_severity(str(fc), 'high' if fc else 'low', use_color)}, "
                    + f"warning={color_severity(str(wc), 'medium' if wc else 'low', use_color)}, "
                    + f"passed={color_severity(str(pc), 'low', use_color)}"
                )
        for field, label, sev in (
            ("failed_details", "failed_details", "high"),
            ("warning_details", "warning_details", "medium"),
            ("passed_details", "passed_details", "low"),
        ):
            value = payload.get(field, [])
            if isinstance(value, list) and value:
                lines.append(f"- {label}:")
                for item in value:
                    lines.append(f"  - {color_severity(str(item), sev, use_color)}")

    def spamhaus_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        listed = bool(payload.get("listed"))
        listed_text = color_severity("yes" if listed else "no", "high" if listed else "low", use_color)
        for key in ("target_type", "asn", "listed", "as_name", "domain", "country_code", "rir"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            if key == "asn":
                lines.append(f"- {key}: AS{value}")
            elif key == "listed":
                lines.append(f"- {key}: {listed_text}")
            else:
                lines.append(f"- {key}: {value}")
        if payload.get("match_count") not in (None, ""):
            lines.append(f"- match_count: {payload.get('match_count')}")

    def ripestat_render(provider: str, payload: dict, lines: list[str], use_color: bool) -> None:
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        if payload.get("error"):
            lines.append(f"- error: {payload.get('error')}")
            return
        risk_level = str(payload.get("risk_level", "low"))
        sev = "high" if risk_level == "high" else ("medium" if risk_level == "medium" else "low")
        lines.append(f"- risk_level: {color_severity(risk_level, sev, use_color)}")
        for key in ("target_type", "asn", "resource", "holder", "country", "rir", "is_announced", "is_visible", "originating", "observed_upstreams", "announced_prefix_count"):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            if key == "asn":
                lines.append(f"- {key}: AS{value}")
            else:
                lines.append(f"- {key}: {value}")
        render_list_field(lines, "abuse_contacts", payload.get("abuse_contacts", []), cap=15, provider=provider)
        render_list_field(lines, "announced_prefixes", payload.get("announced_prefixes", []), cap=25, provider=provider)
        for key in ("abuse_contacts_error", "routing_status_error", "announced_prefixes_error"):
            if payload.get(key):
                lines.append(f"- {key}: {payload.get(key)}")

    use_color = bool(enrichment_data.get("_use_color"))
    lines: list[str] = []
    lines.append("=== ENRICHMENT ONLY ===  [source: optional provider APIs]")
    lines.append(f"Selection: {', '.join(enrichment_data.get('selection', [])) or '-'}")
    lines.append(f"Resolved: {', '.join(enrichment_data.get('resolved', [])) or '-'}")
    for skipped in enrichment_data.get("skipped", []):
        provider = skipped.get("provider", "-")
        reason = skipped.get("reason", "-")
        lines.append(f"- skipped {provider}: {reason}")
    providers = enrichment_data.get("providers", {})
    if not providers:
        lines.append("No provider results.")
        return "\n".join(lines)
    for provider in sorted(providers.keys()):
        payload = providers.get(provider, {})
        if not isinstance(payload, dict):
            lines.append(provider_header(provider, use_color))
            lines.append(f"- {payload}")
            continue
        renderers: dict[str, Callable[[str, dict, list[str], bool], None]] = {
            "virustotal": vt_render,
            "censys": censys_render,
            "shodan": shodan_render,
            "mxtoolbox": mxtoolbox_render,
            "spur": spur_render,
            "abuseipdb": abuseipdb_render,
            "greynoise": greynoise_render,
            "dnsdumpster": dnsdumpster_render,
            "dnsdb": dnsdb_render,
            "viewdns": viewdns_render,
            "urlscan": urlscan_render,
            "securitytrails": securitytrails_render,
            "spamhaus": spamhaus_render,
            "ripestat": ripestat_render,
        }
        renderer = renderers.get(provider)
        if renderer:
            renderer(provider, payload, lines, use_color)
            continue
        lines.append(provider_header(provider, use_color))
        append_summary(payload, lines)
        for key in sorted(payload.keys()):
            value = payload.get(key)
            if value in (None, "", []):
                continue
            if isinstance(value, dict):
                lines.append("- " + key + ": " + ", ".join(f"{k}={v}" for k, v in sorted(value.items())))
            elif isinstance(value, list):
                render_list_field(lines, key, value, cap=30, provider=provider)
            else:
                lines.append(f"- {key}: {value}")
    return "\n".join(lines)
