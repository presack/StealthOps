"""FastAPI web application for StealthOps."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import uuid
from datetime import datetime

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from core_ops import QueryConfig, StealthQueryEngine, internet_available
from enrichment import EnrichmentManager, PROVIDER_SPECS, parse_enrichment_selection, selection_to_csv
from tor_engine import TorEngine


TAILWIND_CDN = "https://cdn.tailwindcss.com"


def human_label(key: str) -> str:
    labels = {
        "domain_name": "Domain Name",
        "creation_date": "Creation Date",
        "expiration_date": "Expiration Date",
        "updated_date": "Updated Date",
        "whois_server": "WHOIS Server",
        "name_servers": "Name Servers",
        "canonical_name": "Canonical Name",
        "derived_domain": "Derived Domain",
        "aliases": "Aliases",
        "addresses": "Addresses",
        "address_lookup_error": "Address Lookup Error",
        "registrar_iana_id": "Registrar IANA ID",
        "status": "Domain Status",
        "whois_error": "WHOIS Error",
        "network_whois_error": "Network WHOIS Error",
        "network_whois_warning": "Network WHOIS Warning",
        "asn": "ASN",
        "net_name": "Net Name",
        "net_handle": "Net Handle",
        "net_type": "Net Type",
        "parent_handle": "Parent Handle",
        "ip_version": "IP Version",
        "start_address": "Start Address",
        "end_address": "End Address",
        "rdap_url": "RDAP URL",
        "abuse_email": "Abuse Email",
        "abuse_phone": "Abuse Phone",
        "tor_routed": "Tor Routed",
        "status_code": "Status Code",
        "final_url": "Final URL",
    }
    if key in labels:
        return labels[key]
    return key.replace("_", " ").strip().title()


def build_app(
    tor_update_mode: str = "auto",
    tor_update_manifest: str | None = None,
    prefer_system_tor: bool = False,
) -> FastAPI:
    app = FastAPI(title="StealthOps")

    tor_engine = TorEngine(
        tor_update_mode=tor_update_mode,
        tor_update_manifest=tor_update_manifest,
        prefer_system_tor=prefer_system_tor,
    )
    query_engine = StealthQueryEngine(tor_engine, QueryConfig(block_non_tor=False, route_mode="public"))
    enrichment_manager = EnrichmentManager()
    jobs_lock = threading.Lock()
    jobs: dict[str, dict] = {}
    request_hits: dict[str, list[float]] = {}
    RATE_LIMIT_WINDOW_SECONDS = 60.0
    RATE_LIMIT_MAX_REQUESTS = 20
    MAX_ACTIVE_JOBS = 8

    def client_ip(request: Request) -> str:
        if request.client and request.client.host:
            return str(request.client.host)
        return "unknown"

    def enforce_rate_limit(ip: str) -> str:
        now = time.time()
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        with jobs_lock:
            hits = [ts for ts in request_hits.get(ip, []) if ts >= cutoff]
            if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
                request_hits[ip] = hits
                return "rate limit exceeded; please retry shortly"
            hits.append(now)
            request_hits[ip] = hits
        return ""

    def active_job_count() -> int:
        with jobs_lock:
            return sum(1 for job in jobs.values() if not bool(job.get("done")))

    def get_tor_ok() -> bool:
        if tor_engine.is_proxy_running():
            return tor_engine.verify_circuit()
        return False

    def render_kv_rows(data: dict) -> str:
        rows = []
        for key, value in data.items():
            if isinstance(value, list):
                value_str = ", ".join(str(v) for v in value) if value else "-"
            elif isinstance(value, dict):
                value_str = json.dumps(value, ensure_ascii=True)
            else:
                value_str = str(value) if value not in (None, "") else "-"
            rows.append(
                f"<tr><td class='py-1 pr-3 align-top w-56 text-slate-400'>{html.escape(human_label(str(key)))}:</td>"
                f"<td class='py-1 pl-2 align-top text-slate-100 break-all'>{html.escape(value_str)}</td></tr>"
            )
        return "".join(rows)

    def render_record_lines(record_text: str) -> str:
        if not record_text.strip():
            return "<p class='text-slate-400 text-sm'>Awaiting data...</p>"
        rows = []
        for raw_line in record_text.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                rows.append("<tr><td class='py-1' colspan='2'>&nbsp;</td></tr>")
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                rows.append(
                    "<tr>"
                    f"<td class='py-1 pr-3 align-top w-56 text-slate-400'>{html.escape(key.strip())}:</td>"
                    f"<td class='py-1 pl-2 align-top text-slate-100 break-all'>{html.escape(value.strip())}</td>"
                    "</tr>"
                )
            else:
                rows.append(
                    "<tr>"
                    f"<td class='py-1 text-slate-100 break-words' colspan='2'>{html.escape(line)}</td>"
                    "</tr>"
                )
        return f"<table class='text-sm w-full'><tbody>{''.join(rows)}</tbody></table>"

    def render_pre_block(record_text: str, compact: bool = False) -> str:
        if not record_text.strip():
            return "<p class='text-slate-400 text-sm'>Awaiting data...</p>"
        leading = " leading-tight" if compact else ""
        return (
            "<pre class='text-sm whitespace-pre-wrap break-words text-slate-100"
            + leading
            + "'>"
            + html.escape(record_text)
            + "</pre>"
        )

    def render_results(results: dict, show_json: bool, job_id: str = "") -> str:
        address_data = results.get("address", {})
        dns_data = results.get("dns", {})
        mx_data = results.get("mx", {})
        whois_data = results.get("whois", {})
        network_whois_data = results.get("network_whois", {})
        header_data = results.get("headers", {})
        enrichment_data = results.get("enrichment", {})

        address_summary = {
            key: address_data.get(key)
            for key in [
                "query",
                "canonical_name",
                "derived_domain",
                "aliases",
                "addresses",
                "address_lookup_error",
            ]
            if key in address_data
        }
        def compact_notice(value: str, max_len: int = 120) -> str:
            text = str(value or "").strip()
            if not text:
                return ""
            line = text.splitlines()[0].strip()
            lower_line = line.lower()
            if "connection reset by peer" in lower_line:
                return "WHOIS server reset the connection."
            if line.lower().startswith("no a/aaaa record available for network whois"):
                return "No IP address available for network WHOIS lookup."
            if len(line) > max_len:
                return line[: max_len - 3].rstrip() + "..."
            return line

        whois_record = str(whois_data.get("domain_whois_record", "")).strip()
        whois_error = compact_notice(whois_data.get("whois_error", ""))
        whois_warning = compact_notice(whois_data.get("whois_warning", ""))
        network_whois_record = str(network_whois_data.get("network_whois_record", "")).strip()
        network_notice = compact_notice(
            network_whois_data.get("network_whois_warning")
            or network_whois_data.get("network_whois_error")
            or ""
        )
        query_value = str(address_data.get("query", "")).strip()
        is_ip_query = False
        try:
            ipaddress.ip_address(query_value)
            is_ip_query = True
        except Exception:
            is_ip_query = False

        address_error = compact_notice(address_data.get("address_lookup_error", ""))
        canonical_name = str(address_data.get("canonical_name", "")).strip()
        ip_reverse_lookup_failed = bool(
            is_ip_query and address_error and (not canonical_name or canonical_name == query_value)
        )

        dns_notices = []
        for key in sorted(k for k in dns_data.keys() if k.endswith("_error") and k != "ptr_error"):
            dns_notices.append(f"{key.replace('_', ' ').strip()}: {compact_notice(dns_data.get(key, ''))}")
        ptr_error = compact_notice(dns_data.get("ptr_error", ""))
        if ptr_error:
            if is_ip_query and "." in query_value:
                ptr_name = ".".join(reversed(query_value.split("."))) + ".in-addr.arpa"
                ptr_kind = "NameError" if "does not exist" in ptr_error.lower() or "nxdomain" in ptr_error.lower() else ptr_error
                dns_notices.append(f"DNS query for {ptr_name} returned an error from the server: {ptr_kind}")
            else:
                dns_notices.append(f"ptr error: {ptr_error}")
        if mx_data.get("mx_error"):
            dns_notices.append(f"mx error: {compact_notice(mx_data.get('mx_error', ''))}")

        def format_soa_data(value: str) -> str:
            parts = str(value).split()
            if len(parts) < 7:
                return str(value)
            mname, rname, serial, refresh, retry, expire, minimum = parts[:7]
            return (
                f"mname={mname}; rname={rname}; serial={serial}; "
                f"refresh={refresh}; retry={retry}; expire={expire}; minimum={minimum}"
            )

        dns_rows = []
        domain = str(dns_data.get("domain", "-"))
        for rtype, key in (
            ("A", "a"),
            ("AAAA", "aaaa"),
            ("PTR", "ptr"),
            ("NS", "ns"),
            ("TXT", "txt"),
            ("CNAME", "cname"),
            ("CAA", "caa"),
            ("SOA", "soa"),
        ):
            values = dns_data.get(key, [])
            for value in values:
                data_value = format_soa_data(str(value)) if rtype == "SOA" else str(value)
                dns_rows.append(
                    "<tr>"
                    f"<td class='py-1 pr-3 align-top whitespace-nowrap'>{html.escape(domain)}</td>"
                    "<td class='py-1 pr-3 align-top whitespace-nowrap'>IN</td>"
                    f"<td class='py-1 pr-3 align-top whitespace-nowrap'>{rtype}</td>"
                    f"<td class='py-1 align-top break-all'>{html.escape(data_value)}</td>"
                    "<td class='py-1 pl-3 align-top text-slate-400 whitespace-nowrap'>-</td>"
                    "</tr>"
                )
        for mx in mx_data.get("mx", []):
            priority = mx.get("priority")
            host = mx.get("host", "-")
            data_value = f"preference={priority}; exchange={host}" if priority is not None else f"exchange={host}"
            dns_rows.append(
                "<tr>"
                f"<td class='py-1 pr-3 align-top whitespace-nowrap'>{html.escape(domain)}</td>"
                "<td class='py-1 pr-3 align-top whitespace-nowrap'>IN</td>"
                "<td class='py-1 pr-3 align-top whitespace-nowrap'>MX</td>"
                f"<td class='py-1 align-top break-all'>{html.escape(data_value)}</td>"
                "<td class='py-1 pl-3 align-top text-slate-400 whitespace-nowrap'>-</td>"
                "</tr>"
            )
        dns_records_html = "".join(dns_rows) if dns_rows else "<tr><td class='py-1 pr-3' colspan='5'>No records to display</td></tr>"

        headers_rows = ""
        for key, value in header_data.get("headers", {}).items():
            headers_rows += (
                "<tr>"
                f"<td class='py-1 pr-3 text-slate-400'>{html.escape(str(key))}</td>"
                f"<td class='py-1 text-slate-100 break-all'>{html.escape(str(value))}</td>"
                "</tr>"
            )
        if not headers_rows:
            headers_rows = "<tr><td class='py-1 pr-3' colspan='2'>No headers</td></tr>"

        def classify_risk(payload: dict) -> str:
            risk = str(payload.get("risk_level", "")).strip().lower()
            if risk in {"high", "medium", "low"}:
                return risk
            if "error" in payload:
                return "unknown"
            if "abuse_confidence_score" in payload:
                score = int(payload.get("abuse_confidence_score", 0) or 0)
                if score >= 75:
                    return "high"
                if score >= 25:
                    return "medium"
                return "low"
            if "last_analysis_stats" in payload and isinstance(payload.get("last_analysis_stats"), dict):
                stats = payload.get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                if malicious > 0:
                    return "high"
                if suspicious > 0:
                    return "medium"
                return "low"
            return "unknown"

        def risk_chip(level: str) -> str:
            if level == "high":
                return "<span class='text-[10px] px-2 py-0.5 rounded-full bg-red-900/40 text-red-300 border border-red-700'>high</span>"
            if level == "medium":
                return "<span class='text-[10px] px-2 py-0.5 rounded-full bg-amber-900/40 text-amber-300 border border-amber-700'>medium</span>"
            if level == "low":
                return "<span class='text-[10px] px-2 py-0.5 rounded-full bg-emerald-900/40 text-emerald-300 border border-emerald-700'>low</span>"
            return "<span class='text-[10px] px-2 py-0.5 rounded-full bg-slate-900 text-slate-300 border border-slate-700'>unknown</span>"

        def render_enrichment_value(provider_name: str, field_key: str, value: object) -> str:
            if value is None or value == "":
                return "<span class='text-slate-500'>-</span>"
            if isinstance(value, bool):
                return "true" if value else "false"

            def render_dict_list_table(dict_list: list[dict], cap: int = 30) -> str:
                provider_key = provider_name.strip().lower()
                field_key_l = field_key.strip().lower()
                provider_specific: dict[tuple[str, str], list[str]] = {
                    ("virustotal", "malicious_or_suspicious_findings"): ["engine", "category", "result", "method"],
                    ("urlscan", "recent_scans"): ["time", "domain", "ip", "score", "result_url", "uuid"],
                    ("securitytrails", "current_ns_records"): ["nameserver", "nameserver_organization", "nameserver_count"],
                    ("securitytrails", "current_mx_records"): ["priority", "hostname", "hostname_organization"],
                    ("securitytrails", "current_txt_records"): ["value"],
                    ("viewdns", "ip_history"): ["ip", "date", "lastseen"],
                    ("viewdns", "subdomains"): ["name", "subdomain", "ip"],
                    ("viewdns", "reverseip_domains"): ["domain", "last_resolved"],
                    ("dnsdb", "rrsets"): ["rrname", "rrtype", "rdata", "count", "first_seen", "last_seen"],
                    ("dnsdb", "subdomain_rrsets"): ["rrname", "rrtype", "rdata", "count", "first_seen", "last_seen"],
                    ("dnsdb", "rdata_records"): ["rrname", "rrtype", "rdata", "count", "first_seen", "last_seen"],
                    ("dnsdumpster", "a"): ["host", "ip", "asn", "asn_name", "country"],
                    ("dnsdumpster", "ns"): ["host", "ip", "asn", "asn_name", "country"],
                    ("dnsdumpster", "mx"): ["host", "ip", "asn", "asn_name", "country"],
                    ("ripestat", "announced_prefixes"): ["prefix", "first_seen", "last_seen", "events"],
                }
                preferred = provider_specific.get((provider_key, field_key_l), [
                    "engine",
                    "category",
                    "result",
                    "command",
                    "hostname",
                    "nameserver",
                    "priority",
                    "ip",
                    "domain",
                    "time",
                    "score",
                    "value",
                    "type",
                    "port",
                    "protocol",
                    "service",
                    "error",
                ])
                keys_seen: list[str] = []
                for item in dict_list:
                    for key in item.keys():
                        if isinstance(key, str) and key not in keys_seen:
                            keys_seen.append(key)
                ordered = [k for k in preferred if k in keys_seen]
                extras = sorted([k for k in keys_seen if k not in ordered])
                columns = (ordered + extras)[:6]
                if not columns:
                    return "<span class='text-slate-500'>-</span>"

                preview = dict_list[:cap]
                body_rows = []
                for item in preview:
                    cells: list[str] = []
                    for col in columns:
                        raw = item.get(col, "-")
                        if col == "category":
                            category = str(raw).strip().lower()
                            if category == "malicious":
                                cell = "<span class='text-red-300'>malicious</span>"
                            elif category == "suspicious":
                                cell = "<span class='text-amber-300'>suspicious</span>"
                            else:
                                cell = html.escape(str(raw))
                        else:
                            cell = html.escape(str(raw))
                        cells.append(f"<td class='py-1 align-top break-all'>{cell}</td>")
                    body_rows.append(
                        "<tr>"
                        + "".join(cells)
                        + "</tr>"
                    )
                more = ""
                if len(dict_list) > len(preview):
                    more = (
                        "<p class='text-slate-500 text-[11px] mt-1'>"
                        f"... (+{len(dict_list) - len(preview)} more)"
                        "</p>"
                    )
                header_cells = "".join(
                    f"<th class='text-left py-1 pr-3 text-slate-400'>{html.escape(str(col))}</th>"
                    for col in columns
                )
                return (
                    "<div class='overflow-x-auto'>"
                    "<table class='w-full text-xs'>"
                    "<thead><tr>" + header_cells + "</tr></thead>"
                    f"<tbody>{''.join(body_rows)}</tbody>"
                    "</table>"
                    + more
                    + "</div>"
                )

            if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                return render_dict_list_table(value)
            if isinstance(value, dict):
                keys = sorted(value.keys())
                rows = []
                for key in keys[:8]:
                    rows.append(
                        "<div class='flex gap-2'>"
                        f"<span class='text-slate-400'>{html.escape(str(key))}:</span>"
                        f"<span class='text-slate-100 break-all'>{html.escape(str(value.get(key)))}</span>"
                        "</div>"
                    )
                if len(keys) > 8:
                    rows.append(f"<div class='text-slate-500'>... (+{len(keys) - 8} more)</div>")
                return "<div class='space-y-1'>" + "".join(rows) + "</div>"
            if isinstance(value, list):
                if not value:
                    return "<span class='text-slate-500'>-</span>"
                preview = value[:12]
                items = []
                for entry in preview:
                    items.append(f"<li class='break-all'>{html.escape(str(entry))}</li>")
                tail = ""
                if len(value) > len(preview):
                    tail = f"<li class='text-slate-500'>... (+{len(value) - len(preview)} more)</li>"
                return "<ul class='list-disc ml-4 space-y-1'>" + "".join(items) + tail + "</ul>"
            return html.escape(str(value))

        enrichment_html = ""
        if enrichment_data.get("enabled"):
            providers = enrichment_data.get("providers", {})
            skipped = enrichment_data.get("skipped", [])
            risk_counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
            for _, payload in providers.items():
                level = classify_risk(payload if isinstance(payload, dict) else {})
                risk_counts[level] = risk_counts.get(level, 0) + 1

            tab_buttons: list[str] = []
            tab_panels: list[str] = []
            tab_buttons.append(
                "<button type='button' data-enrich-tab-btn='consensus' "
                "class='px-3 py-1.5 text-xs rounded-md border border-cyan-600 bg-cyan-900/40 text-cyan-200'>Consensus</button>"
            )
            selection_text = ", ".join(enrichment_data.get("selection", []) or ["-"])
            resolved_text = ", ".join(enrichment_data.get("resolved", []) or ["-"])
            skipped_lines = ""
            if skipped:
                skipped_lines = (
                    "<div class='mt-2 space-y-1'>"
                    + "".join(
                        "<p class='text-xs text-amber-300'>Skipped "
                        + html.escape(str(item.get("provider", "-")))
                        + ": "
                        + html.escape(str(item.get("reason", "-")))
                        + "</p>"
                        for item in skipped
                    )
                    + "</div>"
                )
            tab_panels.append(
                "<div data-enrich-tab-panel='consensus'>"
                "<div class='grid grid-cols-2 md:grid-cols-4 gap-2 text-xs'>"
                f"<div class='rounded-md border border-red-700 bg-red-900/30 p-2'><p class='text-red-300'>high</p><p class='text-lg font-semibold'>{risk_counts.get('high', 0)}</p></div>"
                f"<div class='rounded-md border border-amber-700 bg-amber-900/30 p-2'><p class='text-amber-300'>medium</p><p class='text-lg font-semibold'>{risk_counts.get('medium', 0)}</p></div>"
                f"<div class='rounded-md border border-emerald-700 bg-emerald-900/30 p-2'><p class='text-emerald-300'>low</p><p class='text-lg font-semibold'>{risk_counts.get('low', 0)}</p></div>"
                f"<div class='rounded-md border border-slate-700 bg-slate-900/60 p-2'><p class='text-slate-300'>unknown</p><p class='text-lg font-semibold'>{risk_counts.get('unknown', 0)}</p></div>"
                "</div>"
                "<div class='mt-3 text-xs text-slate-300'>"
                f"<p><span class='text-slate-400'>Selection:</span> {html.escape(selection_text)}</p>"
                f"<p><span class='text-slate-400'>Resolved:</span> {html.escape(resolved_text)}</p>"
                "</div>"
                + skipped_lines
                + "</div>"
            )

            for provider in sorted(providers.keys()):
                payload = providers.get(provider, {})
                risk = classify_risk(payload if isinstance(payload, dict) else {})
                tab_buttons.append(
                    "<button type='button' "
                    f"data-enrich-tab-btn='{html.escape(provider)}' "
                    "class='px-3 py-1.5 text-xs rounded-md border border-slate-700 bg-slate-900/60 text-slate-200'>"
                    + html.escape(provider)
                    + "</button>"
                )
                rows = []
                if isinstance(payload, dict):
                    for key in sorted(payload.keys()):
                        if key.startswith("_"):
                            continue
                        value = payload.get(key)
                        if value in (None, "", []):
                            continue
                        rows.append(
                            "<tr>"
                            f"<td class='py-1.5 pr-3 align-top text-slate-400 whitespace-nowrap'>{html.escape(str(key))}</td>"
                            "<td class='py-1.5 align-top text-slate-100 text-xs'>"
                            + render_enrichment_value(provider, str(key), value)
                            + "</td>"
                            "</tr>"
                        )
                panel_body = (
                    "<table class='w-full text-xs'><tbody>" + "".join(rows) + "</tbody></table>"
                    if rows
                    else "<p class='text-xs text-slate-400'>No data returned.</p>"
                )
                tab_panels.append(
                    "<div data-enrich-tab-panel='"
                    + html.escape(provider)
                    + "' class='hidden'>"
                    "<div class='flex items-center gap-2 mb-2'>"
                    f"<p class='text-sm font-semibold'>{html.escape(provider)}</p>{risk_chip(risk)}"
                    "</div>"
                    "<div class='p-3 rounded-lg bg-slate-900/60 border border-slate-700'>"
                    + panel_body
                    + "</div></div>"
                )

            enrichment_html = (
                "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>"
                "<h3 class='font-semibold mb-2'>Enrichment</h3>"
                "<div data-enrich-tabs class='space-y-3'>"
                "<div class='flex flex-wrap gap-2'>"
                + "".join(tab_buttons)
                + "</div>"
                "<div class='space-y-3'>"
                + "".join(tab_panels)
                + "</div></div></section>"
            )

        json_panel = ""
        if show_json:
            json_panel = (
                "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>"
                "<h3 class='font-semibold mb-2'>Raw JSON</h3>"
                f"<pre class='bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-xs'>{html.escape(json.dumps(results, indent=2))}</pre>"
                "</section>"
            )

        whois_cmd = html.escape(f"whois {dns_data.get('domain', '<domain>')}")
        http_cmd = html.escape(f"curl -I {header_data.get('url', '<url>')}")
        whois_missing_domain = (
            is_ip_query
            and whois_error.lower().startswith("unable to derive domain for whois from ip target")
            and not whois_record
        )

        if ip_reverse_lookup_failed:
            address_panel_html = (
                "<p class='text-slate-100 text-sm'><span class='text-amber-300'>lookup failed</span> "
                + html.escape(query_value)
                + "</p>"
                "<p class='text-slate-300 text-sm mt-1'>Could not find a domain name corresponding to this IP address.</p>"
            )
        elif address_summary:
            address_panel_html = f"<table class='text-sm w-full'><tbody>{render_kv_rows(address_summary)}</tbody></table>"
        else:
            address_panel_html = "<p class='text-slate-400 text-sm'>Awaiting data...</p>"

        if whois_missing_domain:
            whois_panel_html = "<p class='text-slate-300 text-sm'>Don't have a domain name for which to get a record</p>"
        elif whois_record:
            whois_panel_html = render_pre_block(whois_record, compact=True)
        elif whois_error:
            whois_panel_html = "<p class='text-slate-300 text-sm'>No WHOIS record returned.</p>"
        elif whois_warning:
            whois_panel_html = "<p class='text-slate-300 text-sm'>Attempting WHOIS lookup...</p>"
        else:
            whois_panel_html = "<p class='text-slate-400 text-sm'>Awaiting data...</p>"

        if network_whois_record:
            network_panel_html = render_record_lines(network_whois_record)
            network_panel_min_h = "min-h-[12rem]"
        elif network_notice:
            network_panel_html = "<p class='text-slate-300 text-sm'>No network WHOIS record to display.</p>"
            network_panel_min_h = "min-h-[4rem]"
        else:
            network_panel_html = "<p class='text-slate-400 text-sm'>Awaiting data...</p>"
            network_panel_min_h = "min-h-[12rem]"

        download_bar = (
            "<div class='flex justify-end mt-4 mb-1'>"
            f"<a href='/query/report/{html.escape(job_id)}' "
            "class='px-3 py-1.5 text-xs rounded-md border border-slate-600 bg-slate-800 hover:bg-slate-700 text-slate-200'>"
            "&#8595; Download PDF</a></div>"
            if job_id else ""
        )

        return download_bar + f"""
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-2'>
  <h3 class='font-semibold mb-2'>Address lookup</h3>
  <div class='min-h-[4rem]'>
    {address_panel_html}
  </div>
</section>
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
  <h3 class='font-semibold mb-2' title='{whois_cmd}'>Domain Whois summary</h3>
  <div class='min-h-[4rem]'>
    {("<p class='text-amber-300 text-xs mb-2 break-words'>" + html.escape(whois_warning) + "</p>") if whois_warning else ""}
    {("<p class='text-amber-300 text-xs mb-2 break-words'>" + html.escape(whois_error) + "</p>") if whois_error and not whois_missing_domain else ""}
    {whois_panel_html}
  </div>
</section>
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
  <h3 class='font-semibold mb-2'>Network Whois record</h3>
  {"<p class='text-amber-300 text-xs mb-2'>" + html.escape(network_notice) + "</p>" if network_notice else ""}
  <div class='{network_panel_min_h}'>
    {network_panel_html}
  </div>
</section>
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
  <h3 class='font-semibold mb-2'>DNS records</h3>
  {"".join("<p class='text-amber-300 text-xs mb-2 break-words'>" + html.escape(note) + "</p>" for note in dns_notices)}
  <table class='text-sm w-full table-auto'>
    <thead><tr><th class='text-left py-1 pr-3 text-slate-400'>Name</th><th class='text-left py-1 pr-3 text-slate-400'>Class</th><th class='text-left py-1 pr-3 text-slate-400'>Type</th><th class='text-left py-1 text-slate-400'>Data</th><th class='text-left py-1 pl-3 text-slate-400'>TTL</th></tr></thead>
    <tbody>{dns_records_html}</tbody>
  </table>
</section>
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
  <h3 class='font-semibold mb-2' title='{http_cmd}'>HTTP Headers</h3>
  <table class='text-sm w-full'>
    <tbody>
      <tr><td class='py-1 pr-3 text-slate-400'>URL</td><td class='py-1 break-all'>{html.escape(str(header_data.get('url', '-')))}</td></tr>
      <tr><td class='py-1 pr-3 text-slate-400'>Status Code</td><td class='py-1'>{html.escape(str(header_data.get('status_code', '-')))}</td></tr>
      <tr><td class='py-1 pr-3 text-slate-400'>Final URL</td><td class='py-1 break-all'>{html.escape(str(header_data.get('final_url', '-')))}</td></tr>
      <tr><td class='py-1 pr-3 text-slate-400'>Tor Routed</td><td class='py-1'>{html.escape(str(header_data.get('tor_routed', '-')))}</td></tr>
    </tbody>
  </table>
  <table class='text-sm w-full mt-3'>
    <thead><tr><th class='text-left py-1 pr-3 text-slate-400'>Header</th><th class='text-left py-1 text-slate-400'>Value</th></tr></thead>
    <tbody>{headers_rows}</tbody>
  </table>
</section>
{enrichment_html}
{json_panel}
"""

    def render_enrichment_pending(enrich_selection: str) -> str:
        selected = parse_enrichment_selection(enrich_selection)
        if not selected:
            return ""
        selected_text = ", ".join(selected)
        return (
            "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>"
            "<h3 class='font-semibold mb-2'>Enrichment</h3>"
            "<div class='rounded-lg border border-cyan-700/60 bg-cyan-900/20 p-3'>"
            "<p class='text-cyan-200 text-sm'>Gathering enrichment data for "
            + html.escape(selected_text)
            + "...</p>"
            "</div>"
            "</section>"
        )

    def render_page(
        results: dict | None = None,
        target: str = "",
        route_mode: str = "public",
        error: str = "",
        notice: str = "",
        update_source: str = "",
        enrich_selection: str = "off",
    ) -> str:
        stealth_ready = get_tor_ok()
        shield_class = "bg-cyan-600" if route_mode == "public" else ("bg-emerald-600" if stealth_ready else "bg-red-600")
        shield_text = "PUBLIC MODE" if route_mode == "public" else ("STEALTH MODE READY" if stealth_ready else "STEALTH MODE UNAVAILABLE")
        warning = ""
        if route_mode == "stealth" and not stealth_ready:
            warning = (
                "<p class='text-red-400 text-sm mt-2'>Warning: "
                + html.escape(str(tor_engine.last_error or "Tor unavailable"))
                + ".</p>"
            )
        runtime_note = (
            "<p class='text-slate-300 text-xs mt-2'>Runtime: "
            + html.escape(str(tor_engine.last_update_message))
            + "</p>"
            if tor_engine.last_update_message
            else ""
        )
        notice_html = f"<p class='text-cyan-300 mt-3'>{html.escape(str(notice))}</p>" if notice else ""

        result_html = render_results(results, False) if results else ""

        error_html = f"<p class='text-red-400 mt-3'>{html.escape(str(error))}</p>" if error else ""
        stealth_active = "bg-emerald-600 text-white" if route_mode == "stealth" else "bg-slate-700 text-slate-200"
        public_active = "bg-cyan-600 text-white" if route_mode == "public" else "bg-slate-700 text-slate-200"
        switch_to = "stealth" if route_mode == "public" else "public"
        switch_label = "Switch to Stealth Mode" if route_mode == "public" else "Switch to Public Mode"
        tor_manage = ""
        if route_mode == "stealth" and not stealth_ready:
            tor_manage = f"""
    <section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
      <h2 class='text-lg font-semibold'>Tor Setup</h2>
      <p class='text-sm text-slate-300 mt-1'>No verified Tor route detected for Stealth Mode. You can bootstrap or update managed Tor runtime now.</p>
      <p class='text-xs text-slate-400 mt-1'>Download can take 1-2 minutes depending on connection speed.</p>
      <p class='text-xs text-slate-400 mt-2 break-all'>{html.escape(update_source)}</p>
      <form method='post' action='/tor/manage' class='mt-3 space-y-3' onsubmit="const btn=this.querySelector('button[type=submit]'); if (btn) {{ btn.disabled=true; btn.textContent='Downloading Tor...'; btn.classList.add('opacity-70','cursor-not-allowed'); }}">
        <label class='flex items-center gap-2 text-sm'>
          <input type='checkbox' name='confirm_download' />
          Confirm download from the source above
        </label>
        <button type='submit' name='force_update' value='1' class='bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg font-semibold'>Install / Update Managed Tor</button>
      </form>
    </section>
"""
        run_button_label = "Run Query (Stealth)" if route_mode == "stealth" else "Run Query (Public)"
        run_button_class = "bg-emerald-600 hover:bg-emerald-500" if route_mode == "stealth" else "bg-cyan-600 hover:bg-cyan-500"
        parsed_selection = parse_enrichment_selection(enrich_selection)
        all_enabled_selected = parsed_selection == ["all-enabled"]
        selected_enrich = set(parsed_selection)
        providers = enrichment_manager.provider_status()
        provider_labels: list[str] = []
        for name in sorted(PROVIDER_SPECS.keys()):
            item = providers.get(name, {})
            has_key = bool(item.get("has_key"))
            adapter_ready = bool(item.get("adapter_ready"))
            checked = "checked" if (all_enabled_selected and has_key and adapter_ready) or (name in selected_enrich) else ""
            disabled = "" if has_key and adapter_ready else "disabled"
            chip_class = (
                "border-emerald-500 bg-emerald-900/30 text-emerald-200"
                if has_key and adapter_ready
                else ("border-amber-500 bg-amber-900/20 text-amber-200" if has_key else "border-slate-700 bg-slate-900/50 text-slate-400")
            )
            provider_labels.append(
                "<label data-provider-chip='1' class='inline-flex items-center gap-2 px-2 py-1 rounded-md border transition "
                + chip_class
                + "'>"
                + f"<input type='checkbox' name='enrich' value='{html.escape(name)}' {checked} {disabled} class='accent-cyan-500' />"
                + f"<span class='text-xs'>{html.escape(name)}</span>"
                + "</label>"
            )

        provider_strip = (
            "<div class='mt-3 flex flex-wrap gap-2'>"
            + "".join(provider_labels)
            + "</div>"
        )

        return f"""
<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>StealthOps</title>
  <script src='{TAILWIND_CDN}'></script>
</head>
<body class='bg-slate-950 text-slate-100 min-h-screen'>
  <main class='max-w-6xl mx-auto p-6'>
    <header class='flex items-center justify-between mb-8'>
      <div>
        <h1 class='text-3xl font-bold tracking-tight'>StealthOps</h1>
        <p class='text-slate-400 text-xs mt-1'>Privacy-centric network intelligence</p>
      </div>
      <div class='flex items-center gap-3'>
        <div class='px-4 py-2 rounded-full {shield_class} text-white text-sm font-semibold'>
          Privacy Shield: {shield_text}
        </div>
        <form method='post' action='/mode'>
          <input type='hidden' name='route_mode' value='{html.escape(switch_to)}' />
          <button class='text-sm underline text-slate-300 hover:text-white'>{html.escape(switch_label)}</button>
        </form>
      </div>
    </header>

    {warning}
    {runtime_note}

    <section class='bg-slate-800/70 rounded-xl p-5 shadow-xl'>
      <form id='query-form' method='post' action='/query' class='space-y-4'>
        <div>
          <label class='block text-sm mb-1'>Domain or URL</label>
          <input name='target' value='{html.escape(target)}' required class='w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2' />
        </div>
        {provider_strip}
        <input type='hidden' name='route_mode' value='{html.escape(route_mode)}' />
        <div class='flex gap-3'>
          <button class='px-4 py-2 rounded-lg font-semibold text-white {run_button_class}'>{html.escape(run_button_label)}</button>
          <span class='self-center text-xs text-slate-400'>{"Tor-routed where available." if route_mode == "stealth" else "Fast public route."}</span>
        </div>
      </form>
      {error_html}
      {notice_html}
    </section>

    {tor_manage}

    <section class='mt-2'>
      <div id='results-panel'>{result_html}</div>
    </section>
  </main>
  <script>
    (function() {{
      const form = document.getElementById('query-form');
      const panel = document.getElementById('results-panel');
      if (!form || !panel) return;

      function initEnrichmentTabs(root) {{
        const scope = root || document;
        const groups = scope.querySelectorAll('[data-enrich-tabs]');
        groups.forEach(function(group) {{
          const buttons = Array.from(group.querySelectorAll('[data-enrich-tab-btn]'));
          const panels = Array.from(group.querySelectorAll('[data-enrich-tab-panel]'));
          if (!buttons.length || !panels.length) return;

          function activate(name) {{
            buttons.forEach(function(btn) {{
              const active = btn.getAttribute('data-enrich-tab-btn') === name;
              if (active) {{
                btn.classList.remove('border-slate-700', 'bg-slate-900/60', 'text-slate-200');
                btn.classList.add('border-cyan-600', 'bg-cyan-900/40', 'text-cyan-200');
              }} else {{
                btn.classList.remove('border-cyan-600', 'bg-cyan-900/40', 'text-cyan-200');
                btn.classList.add('border-slate-700', 'bg-slate-900/60', 'text-slate-200');
              }}
            }});
            panels.forEach(function(p) {{
              const show = p.getAttribute('data-enrich-tab-panel') === name;
              p.classList.toggle('hidden', !show);
            }});
          }}

          let active = '';
          buttons.forEach(function(btn) {{
            btn.addEventListener('click', function() {{
              const name = btn.getAttribute('data-enrich-tab-btn') || '';
              activate(name);
            }});
            if (!active) active = btn.getAttribute('data-enrich-tab-btn') || '';
          }});
          if (active) activate(active);
        }});
      }}

      async function pollJob(jobId) {{
        while (true) {{
          const res = await fetch(`/query/status/${{jobId}}`);
          if (!res.ok) {{
            panel.innerHTML = "<p class='text-red-400'>Failed to load query status.</p>";
            return;
          }}
          const data = await res.json();
          if (typeof data.html === 'string') {{
            panel.innerHTML = data.html;
            initEnrichmentTabs(panel);
          }}
          if (data.done) {{
            return;
          }}
          await new Promise(r => setTimeout(r, 400));
        }}
      }}

      form.addEventListener('submit', async function(ev) {{
        ev.preventDefault();
        const selectedEnrich = Array.from(form.querySelectorAll('input[name="enrich"]:checked')).map(function(i) {{ return i.value; }});
        const pendingEnrichment = selectedEnrich.length
          ? "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'><h3 class='font-semibold mb-2'>Enrichment</h3><div class='rounded-lg border border-cyan-700/60 bg-cyan-900/20 p-3'><p class='text-cyan-200 text-sm'>Gathering enrichment data for "
            + selectedEnrich.join(", ")
            + "...</p></div></section>"
          : "";
        panel.innerHTML = ""
          + "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-6'><h3 class='font-semibold mb-2'>Address lookup</h3><div class='min-h-[9rem] text-slate-400 text-sm'>Collecting...</div></section>"
          + "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'><h3 class='font-semibold mb-2'>Domain Whois summary</h3><div class='min-h-[18rem] text-slate-400 text-sm'>Collecting...</div></section>"
          + "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'><h3 class='font-semibold mb-2'>Network Whois record</h3><div class='min-h-[12rem] text-slate-400 text-sm'>Collecting...</div></section>"
          + pendingEnrichment;
        const body = new FormData(form);
        const res = await fetch('/query/start', {{ method: 'POST', body }});
        if (!res.ok) {{
          let msg = "Failed to start query.";
          try {{
            const errData = await res.json();
            if (errData && errData.error) msg = errData.error;
          }} catch (_) {{}}
          panel.innerHTML = "<p class='text-red-400'>" + msg + "</p>";
          return;
        }}
        const data = await res.json();
        if (!data.job_id) {{
          panel.innerHTML = "<p class='text-red-400'>Query did not return a job id.</p>";
          return;
        }}
        pollJob(data.job_id);
      }});

      initEnrichmentTabs(document);
    }})();
  </script>
</body>
</html>
"""

    @app.get("/", response_class=HTMLResponse)
    async def home() -> HTMLResponse:
        return HTMLResponse(
            render_page(
                route_mode=query_engine.config.route_mode,
                update_source=tor_engine.preview_update_source(),
                enrich_selection="off",
            )
        )

    @app.post("/mode", response_class=HTMLResponse)
    async def set_mode(route_mode: str = Form("public")) -> HTMLResponse:
        selected = "stealth" if route_mode == "stealth" else "public"
        query_engine.config.route_mode = selected
        notice = f"Routing mode set to {selected}."
        if selected == "stealth":
            tor_ok = tor_engine.ensure_tor()
            if tor_ok:
                notice = "Routing mode set to stealth. Tor route verified."
            else:
                notice = f"Routing mode set to stealth, but Tor is unavailable: {tor_engine.last_error or 'unknown error'}"
        return HTMLResponse(
            render_page(
                route_mode=selected,
                notice=notice,
                update_source=tor_engine.preview_update_source(),
                enrich_selection="off",
            )
        )

    @app.post("/query", response_class=HTMLResponse)
    async def query(
        request: Request,
        target: str = Form(...),
        route_mode: str = Form("public"),
    ) -> HTMLResponse:
        form = await request.form()
        enrich_all = str(form.get("enrich_all", "")).strip().lower() in {"1", "true", "on", "yes"}
        enrich_values = [str(v) for v in form.getlist("enrich")]
        enrich_selection = "all-enabled" if enrich_all else selection_to_csv(enrich_values)
        ip = client_ip(request)
        rate_limit_error = enforce_rate_limit(ip)
        if rate_limit_error:
            return HTMLResponse(
                render_page(
                    target=target,
                    route_mode="stealth" if route_mode == "stealth" else "public",
                    error=rate_limit_error,
                    update_source=tor_engine.preview_update_source(),
                    enrich_selection=enrich_selection,
                )
            )
        query_engine.config.route_mode = "stealth" if route_mode == "stealth" else "public"
        query_engine.config.block_non_tor = query_engine.config.route_mode == "stealth"
        if query_engine.config.route_mode == "stealth":
            tor_engine.ensure_tor()
        try:
            results = query_engine.run_all(target.strip())
            if parse_enrichment_selection(enrich_selection):
                results["enrichment"] = enrichment_manager.run(target.strip(), enrich_selection)
            notice = ""
            if query_engine.config.route_mode == "stealth" and not tor_engine.verify_circuit():
                notice = f"Stealth mode selected, but Tor is not verified: {tor_engine.last_error or 'unknown error'}"
            return HTMLResponse(
                render_page(
                    results=results,
                    target=target,
                    route_mode=query_engine.config.route_mode,
                    notice=notice,
                    update_source=tor_engine.preview_update_source(),
                    enrich_selection=enrich_selection,
                )
            )
        except Exception as exc:
            return HTMLResponse(
                render_page(
                    target=target,
                    route_mode=query_engine.config.route_mode,
                    error=str(exc),
                    update_source=tor_engine.preview_update_source(),
                    enrich_selection=enrich_selection,
                )
            )

    @app.post("/query/start", response_class=JSONResponse)
    async def query_start(
        request: Request,
        target: str = Form(...),
        route_mode: str = Form("public"),
    ) -> JSONResponse:
        form = await request.form()
        enrich_all = str(form.get("enrich_all", "")).strip().lower() in {"1", "true", "on", "yes"}
        enrich_values = [str(v) for v in form.getlist("enrich")]
        enrich_selection = "all-enabled" if enrich_all else selection_to_csv(enrich_values)
        ip = client_ip(request)
        rate_limit_error = enforce_rate_limit(ip)
        if rate_limit_error:
            return JSONResponse({"error": rate_limit_error, "job_id": ""}, status_code=429)
        if active_job_count() >= MAX_ACTIVE_JOBS:
            return JSONResponse(
                {"error": "server is busy; too many concurrent queries", "job_id": ""},
                status_code=503,
            )
        if not internet_available(timeout=1.0):
            return JSONResponse(
                {
                    "error": "internet connectivity check failed (no network route detected)",
                    "job_id": "",
                },
                status_code=503,
            )
        selected_mode = "stealth" if route_mode == "stealth" else "public"
        target_value = target.strip()
        job_id = uuid.uuid4().hex

        with jobs_lock:
            jobs[job_id] = {
                "done": False,
                "error": "",
                "results": {},
                "target": target_value,
                "route_mode": selected_mode,
                "enrich_selection": enrich_selection,
                "updated_at": time.time(),
            }

        def worker() -> None:
            local_engine = StealthQueryEngine(
                tor_engine,
                QueryConfig(
                    block_non_tor=selected_mode == "stealth",
                    route_mode=selected_mode,
                ),
            )
            if selected_mode == "stealth":
                tor_engine.ensure_tor()

            def on_update(snapshot: dict) -> None:
                with jobs_lock:
                    if job_id not in jobs:
                        return
                    jobs[job_id]["results"] = snapshot
                    jobs[job_id]["updated_at"] = time.time()

            try:
                final = local_engine.run_all_staged(target_value, on_update=on_update)
                if parse_enrichment_selection(enrich_selection):
                    final["enrichment"] = enrichment_manager.run(target_value, enrich_selection)
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]["results"] = final
                        jobs[job_id]["done"] = True
                        jobs[job_id]["updated_at"] = time.time()
            except Exception as exc:
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]["error"] = str(exc)
                        jobs[job_id]["done"] = True
                        jobs[job_id]["updated_at"] = time.time()

        threading.Thread(target=worker, daemon=True).start()
        return JSONResponse({"job_id": job_id})

    @app.get("/query/status/{job_id}", response_class=JSONResponse)
    async def query_status(job_id: str) -> JSONResponse:
        with jobs_lock:
            job = jobs.get(job_id)
            if not job:
                return JSONResponse({"done": True, "error": "job not found", "html": "<p class='text-red-400'>Query job not found.</p>"}, status_code=404)
            results = job.get("results", {})
            done = bool(job.get("done"))
            error = str(job.get("error") or "")
            enrich_selection = str(job.get("enrich_selection") or "off")

        html_fragment = ""
        if error:
            html_fragment = f"<p class='text-red-400'>{html.escape(error)}</p>"
        elif results:
            html_fragment = render_results(results, False, job_id=job_id if done else "")
            enrichment_ready = bool(
                isinstance(results, dict)
                and isinstance(results.get("enrichment"), dict)
                and results.get("enrichment", {}).get("enabled")
            )
            if parse_enrichment_selection(enrich_selection) and not enrichment_ready:
                html_fragment += render_enrichment_pending(enrich_selection)
        else:
            html_fragment = "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'><p class='text-slate-300'>Collecting results...</p></section>"
            html_fragment += render_enrichment_pending(enrich_selection)

        return JSONResponse({"done": done, "error": error, "html": html_fragment})

    @app.get("/query/report/{job_id}")
    async def query_report(job_id: str) -> Response:
        with jobs_lock:
            job = jobs.get(job_id)
        if not job:
            return JSONResponse({"error": "job not found"}, status_code=404)
        if not job.get("done"):
            return JSONResponse({"error": "query not yet complete"}, status_code=409)
        results = job.get("results", {})
        target = str(job.get("target", "unknown"))
        route_mode = str(job.get("route_mode", "public"))
        try:
            from report import generate_report
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(tmp_fd)
            try:
                generate_report(target, results, out_path=tmp_path, route_mode=route_mode)
                with open(tmp_path, "rb") as f:
                    pdf_bytes = f.read()
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            safe_target = re.sub(r"[^\w.\-]", "_", target)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"stealthops-{safe_target}-{ts}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    @app.post("/tor/manage", response_class=HTMLResponse)
    async def tor_manage(
        force_update: str | None = Form(None),
        confirm_download: str | None = Form(None),
    ) -> HTMLResponse:
        if not confirm_download:
            message = "Confirm download checked was not selected. Review source and confirm to proceed."
        else:
            message = tor_engine.manage_tor_runtime(force_update=bool(force_update))
        return HTMLResponse(
            render_page(
                route_mode="stealth",
                notice=message,
                update_source=tor_engine.preview_update_source(),
            )
        )

    return app
