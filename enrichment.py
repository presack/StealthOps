"""Optional enrichment provider management for StealthOps."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import threading
import time
from datetime import datetime
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import requests

ENRICHMENT_TIMEOUT_SECONDS = 8


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    display_name: str
    env_vars: tuple[str, ...]
    adapter_ready: bool
    target_types: tuple[str, ...]


PROVIDER_SPECS: dict[str, ProviderSpec] = {
    "virustotal": ProviderSpec("virustotal", "VirusTotal", ("VIRUSTOTAL_API_KEY", "VT_API_KEY"), True, ("ip", "domain", "url")),
    "shodan": ProviderSpec("shodan", "Shodan", ("SHODAN_API_KEY",), True, ("ip", "asn")),
    "censys": ProviderSpec("censys", "Censys", ("CENSYS_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET"), True, ("ip", "asn")),
    "spur": ProviderSpec("spur", "Spur", ("SPUR_API_KEY",), True, ("ip",)),
    "viewdns": ProviderSpec("viewdns", "ViewDNS", ("VIEWDNS_API_KEY",), True, ("ip", "domain", "url")),
    "mxtoolbox": ProviderSpec("mxtoolbox", "MXToolbox", ("MXTOOLBOX_API_KEY",), True, ("ip", "domain", "url")),
    "abuseipdb": ProviderSpec("abuseipdb", "AbuseIPDB", ("ABUSEIPDB_API_KEY",), True, ("ip",)),
    "greynoise": ProviderSpec("greynoise", "GreyNoise", ("GREYNOISE_API_KEY",), True, ("ip", "asn")),
    "dnsdumpster": ProviderSpec("dnsdumpster", "DNSDumpster", ("DNSDUMPSTER_API_KEY",), True, ("domain", "url")),
    "dnsdb": ProviderSpec("dnsdb", "DNSDB", ("DNSDB_API_KEY",), True, ("ip", "domain", "url")),
    "urlscan": ProviderSpec("urlscan", "urlscan.io", ("URLSCAN_API_KEY",), True, ("ip", "domain", "url")),
    "securitytrails": ProviderSpec("securitytrails", "SecurityTrails", ("SECURITYTRAILS_API_KEY",), True, ("domain", "url")),
    "spamhaus": ProviderSpec("spamhaus", "Spamhaus ASN-DROP", (), True, ("asn",)),
    "ripestat": ProviderSpec("ripestat", "RIPEstat", (), True, ("asn",)),
}


PROVIDER_ALIASES: dict[str, str] = {
    "vt": "virustotal",
    "virustotal": "virustotal",
    "shodan": "shodan",
    "censys": "censys",
    "cs": "censys",
    "spur": "spur",
    "viewdns": "viewdns",
    "vd": "viewdns",
    "mxtoolbox": "mxtoolbox",
    "mx": "mxtoolbox",
    "abuseipdb": "abuseipdb",
    "ab": "abuseipdb",
    "greynoise": "greynoise",
    "gn": "greynoise",
    "dnsdumpster": "dnsdumpster",
    "dd": "dnsdumpster",
    "dnsdb": "dnsdb",
    "ddb": "dnsdb",
    "urlscan": "urlscan",
    "us": "urlscan",
    "securitytrails": "securitytrails",
    "st": "securitytrails",
    "spamhaus": "spamhaus",
    "ripestat": "ripestat",
    "rs": "ripestat",
    "allip": "allip",
    "all-ip": "allip",
    "alldns": "alldns",
    "all-dns": "alldns",
    "allasn": "allasn",
    "all-asn": "allasn",
}

SELECTION_ALIAS_TOKENS = {"all-enabled", "allip", "alldns", "allasn"}


def parse_enrichment_selection(raw: str) -> list[str]:
    text = str(raw or "").strip().lower()
    if not text or text in {"off", "none"}:
        return []
    if text in {"all", "all-enabled"}:
        return ["all-enabled"]
    if text in {"allip", "all-ip"}:
        return ["allip"]
    if text in {"alldns", "all-dns"}:
        return ["alldns"]
    if text in {"allasn", "all-asn"}:
        return ["allasn"]
    tokens: list[str] = []
    for part in text.replace(";", ",").split(","):
        candidate = part.strip()
        if not candidate:
            continue
        mapped = PROVIDER_ALIASES.get(candidate, candidate)
        if (mapped in PROVIDER_SPECS or mapped in SELECTION_ALIAS_TOKENS) and mapped not in tokens:
            tokens.append(mapped)
    return tokens


def selection_to_csv(values: list[str]) -> str:
    out: list[str] = []
    for value in values:
        mapped = PROVIDER_ALIASES.get(str(value).strip().lower(), str(value).strip().lower())
        if (mapped in PROVIDER_SPECS or mapped in SELECTION_ALIAS_TOKENS) and mapped not in out:
            out.append(mapped)
    return ",".join(out) if out else "off"


class EnrichmentManager:
    def __init__(self) -> None:
        self._keys = self._load_keys()
        self._usage_lock = threading.Lock()
        self._usage: dict[str, dict[str, int]] = {
            name: {"attempts": 0, "success": 0, "errors": 0}
            for name in PROVIDER_SPECS
        }

    @staticmethod
    def _split_env_values(raw: str) -> list[str]:
        values: list[str] = []
        for item in str(raw or "").split(","):
            candidate = item.strip()
            if candidate and candidate not in values:
                values.append(candidate)
        return values

    @staticmethod
    def _env_flag(name: str, default: bool = False) -> bool:
        value = str(os.environ.get(name, "")).strip().lower()
        if not value:
            return default
        return value in {"1", "true", "yes", "on"}

    @classmethod
    def _load_keys(cls) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for name, spec in PROVIDER_SPECS.items():
            if name == "censys":
                api_key = str(os.environ.get("CENSYS_API_KEY", "")).strip()
                api_id = str(os.environ.get("CENSYS_API_ID", "")).strip()
                api_secret = str(os.environ.get("CENSYS_API_SECRET", "")).strip()
                if api_key:
                    out[name] = [f"pat:{value}" for value in cls._split_env_values(api_key)]
                elif api_id and api_secret:
                    # Compatibility fallback for older keypairs.
                    out[name] = [f"basic:{api_id}:{api_secret}"]
                continue
            for env_name in spec.env_vars:
                values = cls._split_env_values(os.environ.get(env_name, ""))
                if values:
                    out[name] = values
                    break
        return out

    def usage_snapshot(self) -> dict[str, dict[str, int]]:
        with self._usage_lock:
            return {name: dict(counters) for name, counters in self._usage.items()}

    def provider_status(self) -> dict[str, dict[str, Any]]:
        usage = self.usage_snapshot()
        status: dict[str, dict[str, Any]] = {}
        for name, spec in PROVIDER_SPECS.items():
            env_var = ""
            for env_name in spec.env_vars:
                if os.environ.get(env_name):
                    env_var = env_name
                    break
            status[name] = {
                "display_name": spec.display_name,
                "has_key": self._provider_accessible(name),
                "source": env_var or (spec.env_vars[0] if spec.env_vars else ""),
                "adapter_ready": spec.adapter_ready,
                "target_types": list(spec.target_types),
                "usage": usage.get(name, {"attempts": 0, "success": 0, "errors": 0}),
            }
        return status

    def format_provider_status_lines(self) -> list[str]:
        lines = ["Enrichment Providers:"]
        status_map = self.provider_status()
        for name in sorted(PROVIDER_SPECS.keys()):
            item = status_map.get(name, {})
            state = "available" if item.get("has_key") else "no-key"
            adapter = "ready" if item.get("adapter_ready") else "planned"
            usage = item.get("usage", {})
            lines.append(
                f"- {item.get('display_name', name)} ({name}): {state}, adapter={adapter}, "
                f"attempts={usage.get('attempts', 0)}, success={usage.get('success', 0)}, errors={usage.get('errors', 0)}"
            )
        return lines

    def format_quota_lines(self) -> list[str]:
        lines = ["Enrichment Usage (session):"]
        for name in sorted(PROVIDER_SPECS.keys()):
            usage = self.usage_snapshot().get(name, {})
            lines.append(
                f"- {name}: attempts={usage.get('attempts', 0)}, success={usage.get('success', 0)}, errors={usage.get('errors', 0)}"
            )
        lines.append("Note: counts are local session counters, not provider account totals.")
        return lines

    def resolve_requested(self, raw: str) -> list[str]:
        parsed = parse_enrichment_selection(raw)
        if not parsed:
            return []
        resolved: list[str] = []
        for token in parsed:
            if token == "all-enabled":
                candidates = [name for name in sorted(PROVIDER_SPECS.keys()) if self._provider_accessible(name)]
            elif token == "allip":
                candidates = [
                    name for name in sorted(PROVIDER_SPECS.keys())
                    if self._provider_accessible(name) and "ip" in PROVIDER_SPECS[name].target_types
                ]
            elif token == "alldns":
                candidates = [
                    name for name in sorted(PROVIDER_SPECS.keys())
                    if self._provider_accessible(name)
                    and ("domain" in PROVIDER_SPECS[name].target_types or "url" in PROVIDER_SPECS[name].target_types)
                ]
            elif token == "allasn":
                candidates = [
                    name for name in sorted(PROVIDER_SPECS.keys())
                    if self._provider_accessible(name) and "asn" in PROVIDER_SPECS[name].target_types
                ]
            elif self._provider_accessible(token):
                candidates = [token]
            else:
                candidates = []
            for name in candidates:
                if name not in resolved:
                    resolved.append(name)
        return resolved

    def run(self, target: str, raw_selection: str) -> dict[str, Any]:
        requested = parse_enrichment_selection(raw_selection)
        if not requested:
            return {"enabled": False, "selection": [], "providers": {}}
        target_type, _ = self._classify_target(target)

        resolved = self.resolve_requested(raw_selection)
        out: dict[str, Any] = {
            "enabled": True,
            "selection": requested,
            "resolved": resolved,
            "target_type": target_type,
            "providers": {},
            "skipped": [],
        }
        for provider in requested:
            if provider in SELECTION_ALIAS_TOKENS:
                continue
            if provider not in resolved:
                out["skipped"].append({"provider": provider, "reason": "missing_api_key"})
                continue

        for provider in resolved:
            if not self._provider_supports_target(provider, target_type):
                out["skipped"].append(
                    {
                        "provider": provider,
                        "reason": "unsupported_target_type",
                        "target_type": target_type,
                    }
                )
                continue
            keys = self._keys.get(provider, [])
            if self._provider_requires_key(provider) and not keys:
                out["skipped"].append({"provider": provider, "reason": "missing_api_key"})
                continue
            try:
                payload = self._run_provider_with_fallback(provider, target, keys)
                payload = self._with_summary(provider, payload)
                out["providers"][provider] = payload
                self._record_usage(provider, error=bool(payload.get("error")))
            except Exception as exc:
                out["providers"][provider] = {"error": str(exc)}
                self._record_usage(provider, error=True)
        return out

    @staticmethod
    def _provider_supports_target(provider: str, target_type: str) -> bool:
        spec = PROVIDER_SPECS.get(provider)
        if not spec:
            return False
        return target_type in spec.target_types

    @staticmethod
    def _provider_requires_key(provider: str) -> bool:
        spec = PROVIDER_SPECS.get(provider)
        if not spec:
            return True
        return bool(spec.env_vars)

    def _provider_accessible(self, provider: str) -> bool:
        if not self._provider_requires_key(provider):
            return True
        return bool(self._keys.get(provider))

    def _with_summary(self, provider: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return payload
        if payload.get("summary"):
            return payload
        if payload.get("error"):
            payload["summary"] = f"{provider}: error"
            return payload

        if provider == "virustotal":
            stats = payload.get("last_analysis_stats", {})
            mal = int(stats.get("malicious", 0) or 0) if isinstance(stats, dict) else 0
            susp = int(stats.get("suspicious", 0) or 0) if isinstance(stats, dict) else 0
            rep = int(payload.get("reputation", 0) or 0)
            payload["summary"] = f"vt malicious={mal} suspicious={susp} reputation={rep}"
            return payload
        if provider == "shodan":
            if str(payload.get("target_type")) == "asn":
                total = payload.get("total_matches")
                asn = payload.get("asn")
                payload["summary"] = f"shodan asn={asn} matches={total}"
                return payload
            ports = int(payload.get("open_port_count", 0) or 0)
            vulns = int(payload.get("vuln_count", 0) or 0)
            payload["summary"] = f"shodan ports={ports} vulns={vulns}"
            return payload
        if provider == "censys":
            if str(payload.get("target_type")) == "asn":
                asn = payload.get("asn")
                matches = payload.get("match_count", 0)
                payload["summary"] = f"censys asn={asn} matches={matches}"
                return payload
            svc = int(payload.get("service_count", 0) or 0)
            asn = payload.get("asn")
            payload["summary"] = f"censys services={svc} asn={asn}"
            return payload
        if provider == "spur":
            risk = payload.get("risk_level", "low")
            count = len(payload.get("risks", [])) if isinstance(payload.get("risks"), list) else 0
            payload["summary"] = f"spur risk={risk} markers={count}"
            return payload
        if provider == "abuseipdb":
            score = payload.get("abuse_confidence_score")
            risk = payload.get("risk_level", "low")
            payload["summary"] = f"abuseipdb score={score} risk={risk}"
            return payload
        if provider == "greynoise":
            if str(payload.get("target_type")) == "asn":
                total = payload.get("total")
                risk = payload.get("risk_level", "low")
                payload["summary"] = f"greynoise asn={payload.get('asn')} total={total} risk={risk}"
                return payload
            cls = payload.get("classification")
            risk = payload.get("risk_level", "low")
            payload["summary"] = f"greynoise classification={cls} risk={risk}"
            return payload
        if provider == "viewdns":
            domain = payload.get("domain") or "-"
            sub_count = payload.get("subdomain_count") or 0
            payload["summary"] = f"viewdns domain={domain} subdomains={sub_count}"
            return payload
        if provider == "dnsdumpster":
            domain = payload.get("domain") or "-"
            total = payload.get("total_a_recs") or payload.get("a_count") or 0
            payload["summary"] = f"dnsdumpster domain={domain} a_records={total}"
            return payload
        if provider == "dnsdb":
            if str(payload.get("target_type")) == "ip":
                ip = payload.get("ip") or "-"
                count = payload.get("rrname_count") or 0
                payload["summary"] = f"dnsdb ip={ip} rrnames={count}"
                return payload
            domain = payload.get("domain") or "-"
            sub_count = payload.get("subdomain_count") or 0
            payload["summary"] = f"dnsdb domain={domain} subdomains={sub_count}"
            return payload
        if provider == "urlscan":
            count = payload.get("result_count") or 0
            risk = payload.get("risk_level", "low")
            payload["summary"] = f"urlscan results={count} risk={risk}"
            return payload
        if provider == "securitytrails":
            domain = payload.get("domain") or "-"
            sub_count = payload.get("subdomain_count") or 0
            payload["summary"] = f"securitytrails domain={domain} subdomains={sub_count}"
            return payload
        if provider == "mxtoolbox":
            fail = payload.get("failed_count") or 0
            warn = payload.get("warning_count") or 0
            cmds = payload.get("commands_run", [])
            cmd_text = ",".join(str(c) for c in cmds[:4]) if isinstance(cmds, list) and cmds else "single"
            payload["summary"] = f"mxtoolbox cmds={cmd_text} failed={fail} warning={warn}"
            return payload
        if provider == "spamhaus":
            listed = bool(payload.get("listed"))
            asn = payload.get("asn")
            payload["summary"] = f"spamhaus asn=AS{asn} listed={'yes' if listed else 'no'}"
            return payload
        if provider == "ripestat":
            asn = payload.get("asn")
            holder = payload.get("holder") or payload.get("resource")
            cc = payload.get("country") or "-"
            payload["summary"] = f"ripestat asn=AS{asn} holder={holder} country={cc}"
            return payload

        payload["summary"] = f"{provider}: ok"
        return payload

    def _record_usage(self, provider: str, error: bool) -> None:
        with self._usage_lock:
            if provider not in self._usage:
                return
            self._usage[provider]["attempts"] += 1
            if error:
                self._usage[provider]["errors"] += 1
            else:
                self._usage[provider]["success"] += 1

    def _run_provider(self, provider: str, target: str, key: str) -> dict[str, Any]:
        handlers: dict[str, Any] = {
            "virustotal": self._run_virustotal,
            "shodan": self._run_shodan,
            "censys": self._run_censys,
            "spur": self._run_spur,
            "viewdns": self._run_viewdns,
            "mxtoolbox": self._run_mxtoolbox,
            "abuseipdb": self._run_abuseipdb,
            "greynoise": self._run_greynoise,
            "dnsdumpster": self._run_dnsdumpster,
            "dnsdb": self._run_dnsdb,
            "urlscan": self._run_urlscan,
            "securitytrails": self._run_securitytrails,
            "spamhaus": self._run_spamhaus,
            "ripestat": self._run_ripestat,
        }
        handler = handlers.get(provider)
        if handler:
            return handler(target, key)
        return {"error": "adapter_not_implemented"}

    @staticmethod
    def _should_retry_with_next_key(error_text: str) -> bool:
        text = str(error_text or "").strip().lower()
        if not text:
            return False
        retry_markers = (
            "http 401",
            "http 403",
            "http 429",
            "unauthorized",
            "forbidden",
            "invalid api",
            "invalid key",
            "bad api key",
            "rate limit",
            "quota",
            "credits",
            "key exhausted",
            "account limit",
        )
        return any(marker in text for marker in retry_markers)

    def _run_provider_with_fallback(self, provider: str, target: str, keys: list[str]) -> dict[str, Any]:
        if not self._provider_requires_key(provider):
            return self._run_provider(provider, target, "")

        candidates = keys or [""]
        errors: list[str] = []
        for index, key in enumerate(candidates):
            payload = self._run_provider(provider, target, key)
            error_text = str(payload.get("error") or "").strip()
            if not error_text:
                if index > 0:
                    payload["key_fallback_used"] = True
                    payload["key_attempts"] = index + 1
                return payload
            errors.append(error_text)
            if index >= len(candidates) - 1 or not self._should_retry_with_next_key(error_text):
                if index > 0:
                    payload["key_fallback_used"] = True
                    payload["key_attempts"] = index + 1
                    payload["key_errors"] = errors
                return payload

        return {"error": errors[-1] if errors else "missing_api_key"}

    @staticmethod
    def _classify_target(target: str) -> tuple[str, str]:
        value = str(target or "").strip()
        if value.startswith(("http://", "https://")):
            return "url", value
        if "/" in value:
            value = value.split("/", 1)[0]
        try:
            ipaddress.ip_address(value)
            return "ip", value
        except ValueError:
            pass
        asn = EnrichmentManager._normalize_asn(value)
        if asn:
            return "asn", asn
        return "domain", value.lower()

    @staticmethod
    def _normalize_asn(value: str) -> str | None:
        text = str(value or "").strip().upper()
        if not text:
            return None
        if text.startswith("AS"):
            text = text[2:].strip()
        if not text.isdigit():
            return None
        try:
            number = int(text)
        except Exception:
            return None
        if number <= 0 or number > 4294967295:
            return None
        return str(number)

    @staticmethod
    def _short_http_error(response: requests.Response) -> str:
        body = response.text.strip().replace("\n", " ")
        if len(body) > 140:
            body = body[:137].rstrip() + "..."
        return f"http {response.status_code}: {body or 'request failed'}"

    @staticmethod
    def _vt_detection_findings(last_results: Any, limit: int = 20) -> list[dict[str, str]]:
        if not isinstance(last_results, dict):
            return []
        findings: list[dict[str, str]] = []
        for engine_name, verdict in last_results.items():
            if not isinstance(verdict, dict):
                continue
            category = str(verdict.get("category", "")).strip().lower()
            if category not in {"malicious", "suspicious"}:
                continue
            result = str(verdict.get("result", "")).strip() or category
            findings.append(
                {
                    "engine": str(engine_name),
                    "category": category,
                    "result": result,
                }
            )
        findings.sort(key=lambda item: (item.get("category", ""), item.get("engine", "")))
        return findings[:limit]

    @staticmethod
    def _extract_domain_from_url(value: str) -> str:
        parsed = urlparse(value)
        return str(parsed.hostname or "").strip().lower()

    def _run_virustotal(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        headers = {"x-apikey": api_key}
        if target_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{normalized}"
            response = requests.get(url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)
        elif target_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{normalized}"
            response = requests.get(url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)
        else:
            url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)

        if response.status_code >= 400:
            return {"source": "virustotal", "target_type": target_type, "error": self._short_http_error(response)}

        payload = response.json()
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
        last_results = attrs.get("last_analysis_results", {}) if isinstance(attrs, dict) else {}
        findings = self._vt_detection_findings(last_results)
        total_votes = attrs.get("total_votes", {}) if isinstance(attrs, dict) else {}
        return {
            "source": "virustotal",
            "target_type": target_type,
            "id": payload.get("data", {}).get("id"),
            "reputation": attrs.get("reputation"),
            "last_analysis_stats": stats,
            "malicious_or_suspicious_findings": findings,
            "finding_count": len(findings),
            "total_votes": total_votes,
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "network": attrs.get("network"),
            "whois_date": attrs.get("whois_date"),
            "tags": attrs.get("tags"),
        }

    def _run_shodan(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type not in {"ip", "asn"}:
            return {"source": "shodan", "target_type": target_type, "error": "shodan_lookup_requires_ip_or_asn_target"}

        if target_type == "asn":
            query = f"asn:AS{normalized}"
            base = {
                "source": "shodan",
                "target_type": target_type,
                "asn": f"AS{normalized}",
                "query": query,
            }
            count_resp = requests.get(
                "https://api.shodan.io/shodan/host/count",
                params={"key": api_key, "query": query, "facets": "org:10,country:10,port:10"},
                headers={"accept": "application/json"},
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
            if count_resp.status_code >= 400:
                if count_resp.status_code in {401, 403}:
                    auth_msg = self._shodan_auth_diagnostic(api_key)
                    base["error"] = self._short_http_error(count_resp)
                    base["auth_hint"] = auth_msg
                    return base
                base["error"] = self._short_http_error(count_resp)
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
                params={"key": api_key, "query": query, "page": 1, "minify": "true"},
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
                        sample_hosts.append(
                            {
                                "ip": item.get("ip_str") or item.get("ip"),
                                "port": item.get("port"),
                                "transport": item.get("transport"),
                                "org": item.get("org"),
                                "isp": item.get("isp"),
                                "country": location.get("country_name") if isinstance(location, dict) else None,
                            }
                        )
                out["sample_hosts"] = sample_hosts
                out["sample_count"] = len(sample_hosts)
            return out

        url = f"https://api.shodan.io/shodan/host/{normalized}"
        response = requests.get(
            url,
            params={"key": api_key},
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            if response.status_code in {401, 403}:
                auth_msg = self._shodan_auth_diagnostic(api_key)
                return {
                    "source": "shodan",
                    "target_type": target_type,
                    "error": self._short_http_error(response),
                    "auth_hint": auth_msg,
                }
            return {"source": "shodan", "target_type": target_type, "error": self._short_http_error(response)}

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

    def _shodan_auth_diagnostic(self, api_key: str) -> str:
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

    def _run_censys(self, target: str, credentials: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if credentials.startswith("pat:"):
            token = credentials[len("pat:") :]
            if target_type == "asn":
                organization_id = str(os.environ.get("CENSYS_ORGANIZATION_ID", "")).strip()
                hits, query_used, error = self._censys_platform_asn_search(token, normalized, organization_id)
                if error:
                    # Common free-plan case: platform ASN endpoint requires org_id.
                    legacy_hits = self._censys_legacy_asn_fallback(token, normalized)
                    if legacy_hits:
                        sample_hosts: list[dict[str, Any]] = []
                        for item in legacy_hits[:20]:
                            if not isinstance(item, dict):
                                continue
                            sample_hosts.append(
                                {
                                    "ip": item.get("ip"),
                                    "name": item.get("name"),
                                    "services": item.get("services"),
                                }
                            )
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
                sample_hosts: list[dict[str, Any]] = []
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
            url = f"https://api.platform.censys.io/v3/global/asset/host/{normalized}"
            organization_id = str(os.environ.get("CENSYS_ORGANIZATION_ID", "")).strip()
            params = {"organization_id": organization_id} if organization_id else None
            response = requests.get(
                url,
                headers={
                    "accept": "application/vnd.censys.api.v3.host.v1+json",
                    "authorization": token,
                },
                params=params,
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
            if response.status_code in {401, 403}:
                response = requests.get(
                    url,
                    headers={
                        "accept": "application/vnd.censys.api.v3.host.v1+json",
                        "authorization": f"Bearer {token}",
                    },
                    params=params,
                    timeout=ENRICHMENT_TIMEOUT_SECONDS,
                )
            if response.status_code >= 400:
                return {"source": "censys", "target_type": target_type, "error": self._short_http_error(response)}
            payload = response.json().get("result", {})
            host_view = self._censys_select_host_view(payload)
            services = self._extract_censys_services(host_view)
            if not services:
                fallback_services = self._censys_search_services_fallback(token, normalized, organization_id)
                if fallback_services:
                    services = fallback_services
            if not services:
                legacy_host = self._censys_legacy_host_fallback(token, normalized)
                legacy_services = self._extract_censys_services(legacy_host)
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
                "organization": self._censys_extract_org(host_view),
                "location_city": location.get("city") if isinstance(location, dict) else None,
                "location_country": location.get("country") if isinstance(location, dict) else None,
                "service_count": len(services) if isinstance(services, list) else 0,
                "sample_ports": self._extract_censys_ports(services),
                "top_services": self._censys_top_services(services),
                "organization_id_used": organization_id or None,
                "result_keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
            }

        if credentials.startswith("basic:"):
            # Compatibility fallback for older legacy-style credentials.
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
                    return {"source": "censys", "target_type": target_type, "error": self._short_http_error(response)}
                payload = response.json().get("result", {})
                hits = payload.get("hits", []) if isinstance(payload, dict) else []
                sample_hosts: list[dict[str, Any]] = []
                if isinstance(hits, list):
                    for item in hits[:20]:
                        if not isinstance(item, dict):
                            continue
                        sample_hosts.append(
                            {
                                "ip": item.get("ip"),
                                "name": item.get("name"),
                                "services": item.get("services"),
                            }
                        )
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
                response = requests.get(
                    url,
                    auth=auth,
                    headers={"accept": "application/json"},
                    timeout=ENRICHMENT_TIMEOUT_SECONDS,
                )
                if response.status_code >= 400:
                    return {"source": "censys", "target_type": target_type, "error": self._short_http_error(response)}
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
                return {"source": "censys", "target_type": target_type, "error": self._short_http_error(response)}
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

    @staticmethod
    def _extract_censys_services(payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        for key in ("services", "host_services", "matched_services"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        # Recursive fallback for slightly different response shapes.
        for value in payload.values():
            if isinstance(value, dict):
                nested = EnrichmentManager._extract_censys_services(value)
                if nested:
                    return nested
            if isinstance(value, list):
                # Look for list of service-like dict objects with a port field.
                as_dicts = [item for item in value if isinstance(item, dict)]
                if as_dicts and any("port" in item for item in as_dicts):
                    return as_dicts
        return []

    @staticmethod
    def _censys_select_host_view(payload: Any) -> dict[str, Any]:
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

    @staticmethod
    def _extract_censys_ports(services: list[dict[str, Any]], limit: int = 12) -> list[int]:
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

    @staticmethod
    def _censys_top_services(services: list[dict[str, Any]], limit: int = 12) -> list[str]:
        out: list[str] = []
        for item in services:
            if not isinstance(item, dict):
                continue
            port = item.get("port")
            transport = str(item.get("transport_protocol") or item.get("transport") or "tcp")
            service_name = str(
                item.get("service_name")
                or item.get("extended_service_name")
                or item.get("banner_hash")
                or "unknown"
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

    @staticmethod
    def _censys_extract_org(host_view: dict[str, Any]) -> str | None:
        if not isinstance(host_view, dict):
            return None
        candidates = [
            host_view.get("organization"),
            host_view.get("registered_owner"),
            host_view.get("whois_organization"),
        ]
        network = host_view.get("network")
        if isinstance(network, dict):
            candidates.append(network.get("name"))
            candidates.append(network.get("organization"))
        for value in candidates:
            text = str(value or "").strip()
            if text:
                return text
        return None

    def _censys_search_services_fallback(self, token: str, ip: str, organization_id: str) -> list[dict[str, Any]]:
        # Platform search fallback to fetch service preview when direct host view returns sparse payload.
        url = "https://api.platform.censys.io/v3/global/search/query"
        params = {"organization_id": organization_id} if organization_id else None
        body = {
            "query": f'host.ip="{ip}"',
            "per_page": 1,
        }
        headers_base = {
            "accept": "application/json",
            "content-type": "application/json",
        }
        auth_values = [token, f"Bearer {token}"]
        for auth_value in auth_values:
            try:
                response = requests.post(
                    url,
                    params=params,
                    json=body,
                    headers={**headers_base, "authorization": auth_value},
                    timeout=ENRICHMENT_TIMEOUT_SECONDS,
                )
                if response.status_code >= 400:
                    continue
                payload = response.json().get("result", {})
                hits = payload.get("hits", []) if isinstance(payload, dict) else []
                if not isinstance(hits, list) or not hits:
                    continue
                first = hits[0]
                if not isinstance(first, dict):
                    continue
                services = first.get("services", [])
                if isinstance(services, list):
                    return [item for item in services if isinstance(item, dict)]
            except Exception:
                continue
        return []

    def _censys_platform_asn_search(
        self,
        token: str,
        asn: str,
        organization_id: str,
    ) -> tuple[list[dict[str, Any]], str, str]:
        url = "https://api.platform.censys.io/v3/global/search/query"
        params = {"organization_id": organization_id} if organization_id else None
        query_candidates = [
            f"host.autonomous_system.asn={asn}",
            f"autonomous_system.asn: {asn}",
        ]
        headers_base = {
            "accept": "application/json",
            "content-type": "application/json",
        }
        auth_values = [token, f"Bearer {token}"]
        last_error = ""
        for query in query_candidates:
            for auth_value in auth_values:
                try:
                    response = requests.post(
                        url,
                        params=params,
                        json={"query": query, "per_page": 25},
                        headers={**headers_base, "authorization": auth_value},
                        timeout=ENRICHMENT_TIMEOUT_SECONDS,
                    )
                    if response.status_code >= 400:
                        last_error = self._short_http_error(response)
                        continue
                    payload = response.json().get("result", {})
                    hits = payload.get("hits", []) if isinstance(payload, dict) else []
                    if isinstance(hits, list):
                        return [item for item in hits if isinstance(item, dict)], query, ""
                except Exception as exc:
                    last_error = str(exc)
                    continue
        return [], "", (last_error or "censys_asn_search_failed_for_all_query_variants")

    def _censys_legacy_asn_fallback(self, token: str, asn: str) -> list[dict[str, Any]]:
        # Free PAT users may still have access to search.censys.io host search.
        url = "https://search.censys.io/api/v2/hosts/search"
        query = f"autonomous_system.asn: {asn}"
        auth_headers = (
            {"accept": "application/json", "authorization": f"Bearer {token}"},
            {"accept": "application/json", "authorization": token},
        )
        for headers in auth_headers:
            try:
                response = requests.get(
                    url,
                    params={"q": query, "per_page": 25},
                    headers=headers,
                    timeout=ENRICHMENT_TIMEOUT_SECONDS,
                )
                if response.status_code >= 400:
                    continue
                payload = response.json().get("result", {})
                hits = payload.get("hits", []) if isinstance(payload, dict) else []
                if isinstance(hits, list):
                    return [item for item in hits if isinstance(item, dict)]
            except Exception:
                continue
        return []

    def _censys_legacy_host_fallback(self, token: str, ip: str) -> dict[str, Any]:
        # Search-host fallback path; some accounts expose richer host docs here.
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        for headers in (
            {"accept": "application/json", "authorization": f"Bearer {token}"},
            {"accept": "application/json", "authorization": token},
        ):
            try:
                response = requests.get(url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)
                if response.status_code >= 400:
                    continue
                payload = response.json()
                result = payload.get("result", {}) if isinstance(payload, dict) else {}
                if isinstance(result, dict) and result:
                    return result
            except Exception:
                continue
        return {}

    def _run_spur(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type != "ip":
            return {"source": "spur", "target_type": target_type, "error": "spur_context_lookup_requires_ip_target"}

        url = f"https://api.spur.us/v2/context/{normalized}"
        response = requests.get(
            url,
            headers={"token": api_key, "accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {"source": "spur", "target_type": target_type, "error": self._short_http_error(response)}
        payload = response.json()

        tunnels = payload.get("tunnels", {}) if isinstance(payload, dict) else {}
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
            "tunnel_operator": tunnels.get("operator") if isinstance(tunnels, dict) else None,
            "tunnel_type": tunnels.get("type") if isinstance(tunnels, dict) else None,
            "risks": risks,
            "risk_level": risk_level,
        }

    def _run_viewdns(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type == "ip":
            out: dict[str, Any] = {
                "source": "viewdns",
                "target_type": target_type,
            }
            payload, error = self._viewdns_get("iplocation", {"ip": normalized}, api_key)
            if error:
                out["error"] = error
            else:
                node = payload.get("response", {}) if isinstance(payload, dict) else {}
                if isinstance(node, dict):
                    out.update(
                        {
                            "country_name": node.get("country_name"),
                            "region_name": node.get("region_name"),
                            "city": node.get("city"),
                            "latitude": node.get("latitude"),
                            "longitude": node.get("longitude"),
                        }
                    )

            reverse_dns_payload, reverse_dns_error = self._viewdns_get("reversedns", {"ip": normalized}, api_key)
            if not reverse_dns_error and isinstance(reverse_dns_payload, dict):
                response_node = reverse_dns_payload.get("response", {})
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

            reverse_ip_payload, reverse_ip_error = self._viewdns_get("reverseip", {"host": normalized}, api_key)
            if not reverse_ip_error and isinstance(reverse_ip_payload, dict):
                domains = self._viewdns_extract_domains(reverse_ip_payload)
                if domains:
                    out["reverseip_domains"] = domains
                    out["reverseip_domain_count"] = len(domains)

            spam_payload, spam_error = self._viewdns_get("spamdblookup", {"host": normalized}, api_key)
            if not spam_error and isinstance(spam_payload, dict):
                spam_rows = self._viewdns_extract_rows(spam_payload, ("spams", "spamdb", "records", "entries"))
                out["spam_db_listed"] = bool(spam_rows)
                if spam_rows:
                    out["spam_db_hits"] = spam_rows
                    out["spam_db_hit_count"] = len(spam_rows)
            elif spam_error:
                out["spam_db_error"] = spam_error

            abuse_payload, abuse_error = self._viewdns_get("abuselookup", {"domain": normalized}, api_key)
            if not abuse_error and isinstance(abuse_payload, dict):
                contacts = self._viewdns_extract_contact_emails(abuse_payload)
                if contacts:
                    out["abuse_contacts"] = contacts
                    out["abuse_contact_count"] = len(contacts)
            elif abuse_error:
                out["abuse_contact_error"] = abuse_error

            return out

        domain = normalized if target_type == "domain" else self._extract_domain_from_url(normalized)
        if not domain:
            return {"source": "viewdns", "target_type": target_type, "error": "unable_to_extract_domain"}

        out: dict[str, Any] = {
            "source": "viewdns",
            "target_type": target_type,
            "domain": domain,
        }
        whois_payload, whois_error = self._viewdns_get("whois/v2", {"domain": domain}, api_key)
        if whois_error:
            fallback = self._viewdns_domain_dnsrecord_fallback(domain, api_key, target_type)
            if fallback:
                out.update(fallback)
                out["partial_whois_error"] = whois_error
            else:
                out["error"] = whois_error
        else:
            node = whois_payload.get("response", {}) if isinstance(whois_payload, dict) else {}
            reg = node.get("registryData", {}) if isinstance(node, dict) else {}
            out.update(
                {
                    "domain_name": node.get("domainName") if isinstance(node, dict) else None,
                    "registrar_name": node.get("registrarName") if isinstance(node, dict) else None,
                    "created_date": reg.get("standardCreatedDate") or reg.get("createdDate") if isinstance(reg, dict) else None,
                    "updated_date": reg.get("standardUpdatedDate") or reg.get("updatedDate") if isinstance(reg, dict) else None,
                    "expires_date": reg.get("standardExpiresDate") or reg.get("expiresDate") if isinstance(reg, dict) else None,
                    "abuse_email": reg.get("abuseEmail") if isinstance(reg, dict) else None,
                    "registrant_name": self._viewdns_pick_value(node, reg, keys=("registrantName", "registrant_name", "name")),
                    "registrant_organization": self._viewdns_pick_value(node, reg, keys=("registrantOrganization", "registrant_organization", "organization")),
                    "registrant_email": self._viewdns_pick_value(node, reg, keys=("registrantEmail", "registrant_email", "email")),
                }
            )

        dnsrecord_payload, dnsrecord_error = self._viewdns_get("dnsrecord", {"domain": domain}, api_key)
        if not dnsrecord_error and isinstance(dnsrecord_payload, dict):
            out.update(self._viewdns_extract_dns_records(dnsrecord_payload))
        elif dnsrecord_error:
            out["dnsrecord_error"] = dnsrecord_error

        sub_payload, sub_error = self._viewdns_get("subdomains", {"domain": domain}, api_key)
        if not sub_error and isinstance(sub_payload, dict):
            subs = self._viewdns_extract_subdomains(sub_payload)
            if subs:
                out["subdomain_count"] = len(subs)
                out["subdomains"] = subs
        elif sub_error:
            out["subdomains_error"] = sub_error

        ip_hist_payload, ip_hist_error = self._viewdns_get("iphistory", {"domain": domain}, api_key)
        if not ip_hist_error and isinstance(ip_hist_payload, dict):
            ip_history = self._viewdns_extract_ip_history(ip_hist_payload)
            if ip_history:
                out["ip_history_count"] = len(ip_history)
                out["ip_history"] = ip_history
        elif ip_hist_error:
            out["ip_history_error"] = ip_hist_error

        rev_payload, rev_error = self._viewdns_get("reverseip", {"host": domain}, api_key)
        if not rev_error and isinstance(rev_payload, dict):
            related = self._viewdns_extract_domains(rev_payload)
            if related:
                out["reverseip_domain_count"] = len(related)
                out["reverseip_domains"] = related
        elif rev_error:
            out["reverseip_error"] = rev_error

        spam_payload, spam_error = self._viewdns_get("spamdblookup", {"host": domain}, api_key)
        if not spam_error and isinstance(spam_payload, dict):
            spam_rows = self._viewdns_extract_rows(spam_payload, ("spams", "spamdb", "records", "entries"))
            out["spam_db_listed"] = bool(spam_rows)
            if spam_rows:
                out["spam_db_hits"] = spam_rows
                out["spam_db_hit_count"] = len(spam_rows)
        elif spam_error:
            out["spam_db_error"] = spam_error

        abuse_payload, abuse_error = self._viewdns_get("abuselookup", {"domain": domain}, api_key)
        if not abuse_error and isinstance(abuse_payload, dict):
            contacts = self._viewdns_extract_contact_emails(abuse_payload)
            if contacts:
                out["abuse_contacts"] = contacts
                out["abuse_contact_count"] = len(contacts)
        elif abuse_error:
            out["abuse_contact_error"] = abuse_error

        if self._env_flag("VIEWDNS_ENABLE_PIVOTS", default=False):
            mx_hosts = [str(v).strip() for v in out.get("mx_records", []) if str(v).strip()]
            if mx_hosts:
                reverse_mx_rows: list[dict[str, Any]] = []
                for host in mx_hosts[:3]:
                    mx_payload, mx_error = self._viewdns_get("reversemx", {"mx": host}, api_key)
                    if mx_error:
                        continue
                    for row in self._viewdns_extract_domains_with_context(mx_payload, "mx", host):
                        if row not in reverse_mx_rows:
                            reverse_mx_rows.append(row)
                if reverse_mx_rows:
                    out["reverse_mx_domains"] = reverse_mx_rows
                    out["reverse_mx_domain_count"] = len(reverse_mx_rows)

            ns_hosts = [str(v).strip() for v in out.get("ns_records", []) if str(v).strip()]
            if ns_hosts:
                reverse_ns_rows: list[dict[str, Any]] = []
                for host in ns_hosts[:3]:
                    ns_payload, ns_error = self._viewdns_get("reversens", {"ns": host}, api_key)
                    if ns_error:
                        continue
                    for row in self._viewdns_extract_domains_with_context(ns_payload, "ns", host):
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
                rw_payload, rw_error = self._viewdns_get("reversewhois", {"q": reverse_whois_query}, api_key)
                if not rw_error and isinstance(rw_payload, dict):
                    rw_rows = self._viewdns_extract_domains_with_context(rw_payload, "query", reverse_whois_query)
                    if rw_rows:
                        out["reverse_whois_query"] = reverse_whois_query
                        out["reverse_whois_domains"] = rw_rows
                        out["reverse_whois_domain_count"] = len(rw_rows)
                elif rw_error:
                    out["reverse_whois_error"] = rw_error
        else:
            out["pivot_lookups_skipped"] = True

        return out

    def _viewdns_get(self, endpoint: str, params: dict[str, Any], api_key: str) -> tuple[dict[str, Any], str]:
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
            return {}, self._short_http_error(response)
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

    @staticmethod
    def _viewdns_extract_subdomains(payload: dict[str, Any]) -> list[str]:
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
            "www",
            "api",
            "app",
            "mail",
            "mx",
            "ns",
            "vpn",
            "sso",
            "portal",
            "login",
            "auth",
            "owa",
            "webmail",
            "cdn",
            "edge",
            "gateway",
            "admin",
            "prod",
            "staging",
            "stage",
            "dev",
            "test",
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

    @staticmethod
    def _viewdns_extract_ip_history(payload: dict[str, Any]) -> list[str]:
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
                if first_seen == last_seen:
                    summary = f"{ip} ({last_seen}, hits={count})"
                else:
                    summary = f"{ip} ({first_seen}..{last_seen}, hits={count})"
                summaries.append((last_seen_dt, summary))
            else:
                summaries.append((datetime.min, ip))

        summaries.sort(key=lambda item: item[0], reverse=True)
        return [summary for _, summary in summaries]

    @staticmethod
    def _viewdns_extract_domains(payload: dict[str, Any]) -> list[str]:
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

    @staticmethod
    def _viewdns_pick_value(*sources: object, keys: tuple[str, ...]) -> str | None:
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

    @staticmethod
    def _viewdns_extract_rows(payload: dict[str, Any], keys: tuple[str, ...]) -> list[dict[str, Any]]:
        response_node = payload.get("response", {})
        if not isinstance(response_node, dict):
            return []
        for key in keys:
            rows = response_node.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        return []

    @classmethod
    def _viewdns_extract_contact_emails(cls, payload: dict[str, Any]) -> list[str]:
        rows = cls._viewdns_extract_rows(payload, ("contacts", "abusecontacts", "abuse_contacts", "records"))
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

    @classmethod
    def _viewdns_extract_domains_with_context(cls, payload: dict[str, Any], label: str, label_value: str) -> list[dict[str, Any]]:
        rows = cls._viewdns_extract_rows(payload, ("domains", "records", "results"))
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

    @staticmethod
    def _viewdns_extract_dns_records(payload: dict[str, Any]) -> dict[str, Any]:
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

    def _viewdns_domain_dnsrecord_fallback(self, domain: str, api_key: str, target_type: str) -> dict[str, Any] | None:
        response = requests.get(
            "https://api.viewdns.info/dnsrecord/",
            params={"apikey": api_key, "domain": domain, "output": "json"},
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return None
        payload = response.json()
        out = {
            "source": "viewdns",
            "target_type": target_type,
            "domain": domain,
            "fallback_used": "dnsrecord",
        }
        out.update(self._viewdns_extract_dns_records(payload))
        return out

    def _run_mxtoolbox(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type == "ip":
            commands = ["ptr"]
            argument = normalized
        else:
            default_commands = "dns,mx,spf,dmarc"
            raw_commands = str(os.environ.get("MXTOOLBOX_DOMAIN_COMMANDS", default_commands)).strip()
            commands = [c.strip().lower() for c in raw_commands.split(",") if c.strip()]
            if not commands:
                commands = ["dns", "mx", "spf", "dmarc"]
            argument = normalized if target_type == "domain" else self._extract_domain_from_url(normalized)

        if not argument:
            return {"source": "mxtoolbox", "target_type": target_type, "error": "unable_to_extract_lookup_argument"}

        def mxt_lookup(command: str, argument: str) -> tuple[dict[str, Any], str]:
            base_url = f"https://api.mxtoolbox.com/api/v1/Lookup/{command}/{argument}/"
            headers = {"accept": "application/json", "Authorization": api_key}
            response = requests.get(base_url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)

            # Compatibility fallback for account formats that expect apikey query parameter.
            if response.status_code in {401, 403}:
                response = requests.get(
                    base_url,
                    params={"apikey": api_key},
                    headers={"accept": "application/json"},
                    timeout=ENRICHMENT_TIMEOUT_SECONDS,
                )
            if response.status_code >= 400:
                return {}, self._short_http_error(response)
            payload = response.json()
            if not isinstance(payload, dict):
                return {}, "unexpected_non_json_response"
            return payload, ""

        checks: list[dict[str, Any]] = []
        total_failed = 0
        total_warnings = 0
        total_passed = 0
        reporting_nameservers: list[str] = []
        failed_details: list[str] = []
        warning_details: list[str] = []
        passed_details: list[str] = []

        for command in commands:
            payload, err = mxt_lookup(command, argument)
            if err:
                checks.append({"command": command, "error": err})
                continue

            failed = payload.get("Failed", [])
            warnings = payload.get("Warnings", [])
            passed = payload.get("Passed", [])

            failed_count = len(failed) if isinstance(failed, list) else 0
            warning_count = len(warnings) if isinstance(warnings, list) else 0
            passed_count = len(passed) if isinstance(passed, list) else 0

            total_failed += failed_count
            total_warnings += warning_count
            total_passed += passed_count

            reporting_ns = str(payload.get("ReportingNameServer") or "").strip()
            if reporting_ns and reporting_ns not in reporting_nameservers:
                reporting_nameservers.append(reporting_ns)

            local_failed_details: list[str] = []
            local_warning_details: list[str] = []
            local_passed_details: list[str] = []
            if isinstance(failed, list):
                for item in failed[:5]:
                    if isinstance(item, dict):
                        name = str(item.get("Name") or "").strip()
                        info = str(item.get("Info") or "").strip()
                        if name or info:
                            entry = f"{name}: {info}".strip(": ")
                            local_failed_details.append(entry)
                            if entry not in failed_details and len(failed_details) < 12:
                                failed_details.append(entry)
            if isinstance(warnings, list):
                for item in warnings[:5]:
                    if isinstance(item, dict):
                        name = str(item.get("Name") or "").strip()
                        info = str(item.get("Info") or "").strip()
                        if name or info:
                            entry = f"{name}: {info}".strip(": ")
                            local_warning_details.append(entry)
                            if entry not in warning_details and len(warning_details) < 12:
                                warning_details.append(entry)
            if isinstance(passed, list):
                for item in passed[:5]:
                    if isinstance(item, dict):
                        name = str(item.get("Name") or "").strip()
                        info = str(item.get("Info") or "").strip()
                        if name or info:
                            entry = f"{name}: {info}".strip(": ")
                            local_passed_details.append(entry)
                            if entry not in passed_details and len(passed_details) < 12:
                                passed_details.append(entry)

            checks.append(
                {
                    "command": payload.get("Command") or command,
                    "argument": payload.get("CommandArgument") or argument,
                    "reporting_nameserver": reporting_ns or None,
                    "failed_count": failed_count,
                    "warning_count": warning_count,
                    "passed_count": passed_count,
                    "failed_details": local_failed_details,
                    "warning_details": local_warning_details,
                    "passed_details": local_passed_details,
                }
            )

        if not checks:
            return {"source": "mxtoolbox", "target_type": target_type, "error": "no_mxtoolbox_checks_executed"}

        primary = next((c for c in checks if not c.get("error")), checks[0])
        return {
            "source": "mxtoolbox",
            "target_type": target_type,
            "command": "multi" if len(commands) > 1 else primary.get("command"),
            "argument": argument,
            "commands_run": [str(c) for c in commands],
            "checks": checks,
            "reporting_nameserver": reporting_nameservers[0] if reporting_nameservers else None,
            "reporting_nameservers": reporting_nameservers,
            "failed_count": total_failed,
            "warning_count": total_warnings,
            "passed_count": total_passed,
            "failed_details": failed_details,
            "warning_details": warning_details,
            "passed_details": passed_details,
        }

    def _run_abuseipdb(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type != "ip":
            return {"source": "abuseipdb", "target_type": target_type, "error": "abuseipdb_check_requires_ip_target"}
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": normalized, "maxAgeInDays": 90, "verbose": ""},
            headers={"accept": "application/json", "Key": api_key},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {"source": "abuseipdb", "target_type": target_type, "error": self._short_http_error(response)}
        data = response.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        risk_level = "high" if score >= 70 else ("medium" if score >= 20 else "low")
        return {
            "source": "abuseipdb",
            "target_type": target_type,
            "ip_address": data.get("ipAddress"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_whitelisted": data.get("isWhitelisted"),
            "abuse_confidence_score": score,
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "risk_level": risk_level,
        }

    def _run_greynoise(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type == "asn":
            query = f"asn:{normalized}"
            # Prefer v3 metadata; fallback to legacy v2 experimental stats.
            last_error = ""
            response = requests.get(
                "https://api.greynoise.io/v3/gnql/metadata",
                params={"query": query},
                headers={"accept": "application/json", "key": api_key},
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
            if response.status_code < 400:
                data = response.json()
                metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
                stats = data.get("stats", {}) if isinstance(data, dict) else {}
                total = stats.get("total") if isinstance(stats, dict) else data.get("total")
                classifications = data.get("classifications", []) if isinstance(data, dict) else []
                malicious_count = 0
                if isinstance(classifications, list):
                    for row in classifications:
                        if not isinstance(row, dict):
                            continue
                        label = str(row.get("value") or row.get("name") or "").strip().lower()
                        if label == "malicious":
                            malicious_count = int(row.get("count", 0) or 0)
                            break
                risk_level = "high" if malicious_count > 0 else "low"
                return {
                    "source": "greynoise",
                    "target_type": target_type,
                    "asn": int(normalized),
                    "query": query,
                    "total": total,
                    "classifications": classifications if isinstance(classifications, list) else [],
                    "actors": metadata.get("actors") if isinstance(metadata, dict) else None,
                    "tags": metadata.get("tags") if isinstance(metadata, dict) else None,
                    "countries": metadata.get("countries") if isinstance(metadata, dict) else None,
                    "organizations": metadata.get("organizations") if isinstance(metadata, dict) else None,
                    "operating_systems": metadata.get("operating_systems") if isinstance(metadata, dict) else None,
                    "risk_level": risk_level,
                    "api_model": "v3_gnql_metadata",
                }
            last_error = self._short_http_error(response)

            response = requests.get(
                "https://api.greynoise.io/v2/experimental/gnql/stats",
                params={"query": query},
                headers={"accept": "application/json", "key": api_key},
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
            if response.status_code >= 400:
                message = self._short_http_error(response)
                return {
                    "source": "greynoise",
                    "target_type": target_type,
                    "asn": int(normalized),
                    "query": query,
                    "error": message,
                    "fallback_error": last_error,
                    "plan_limited": response.status_code in {401, 403},
                }
            data = response.json()
            classifications = data.get("classifications", []) if isinstance(data, dict) else []
            malicious_count = 0
            if isinstance(classifications, list):
                for row in classifications:
                    if not isinstance(row, dict):
                        continue
                    label = str(row.get("value") or row.get("name") or "").strip().lower()
                    if label == "malicious":
                        malicious_count = int(row.get("count", 0) or 0)
                        break
            risk_level = "high" if malicious_count > 0 else "low"
            return {
                "source": "greynoise",
                "target_type": target_type,
                "asn": int(normalized),
                "query": query,
                "total": data.get("total") if isinstance(data, dict) else None,
                "classifications": classifications if isinstance(classifications, list) else [],
                "actors": data.get("actors") if isinstance(data, dict) else None,
                "tags": data.get("tags") if isinstance(data, dict) else None,
                "countries": data.get("countries") if isinstance(data, dict) else None,
                "organizations": data.get("organizations") if isinstance(data, dict) else None,
                "operating_systems": data.get("operating_systems") if isinstance(data, dict) else None,
                "risk_level": risk_level,
                "api_model": "v2_experimental_gnql_stats",
            }
        if target_type != "ip":
            return {"source": "greynoise", "target_type": target_type, "error": "greynoise_check_requires_ip_or_asn_target"}
        response = requests.get(
            f"https://api.greynoise.io/v3/community/{normalized}",
            headers={"accept": "application/json", "key": api_key},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {"source": "greynoise", "target_type": target_type, "error": self._short_http_error(response)}
        data = response.json()
        noise = bool(data.get("noise"))
        riot = bool(data.get("riot"))
        classification = str(data.get("classification") or "").strip().lower()
        risk_level = "high" if classification == "malicious" else ("low" if riot else ("medium" if noise else "low"))
        return {
            "source": "greynoise",
            "target_type": target_type,
            "ip": data.get("ip"),
            "noise": noise,
            "riot": riot,
            "classification": data.get("classification"),
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
            "risk_level": risk_level,
        }

    def _run_dnsdumpster(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type == "ip":
            return {"source": "dnsdumpster", "target_type": target_type, "error": "dnsdumpster_domain_lookup_requires_domain_or_url"}
        domain = normalized if target_type == "domain" else self._extract_domain_from_url(normalized)
        if not domain:
            return {"source": "dnsdumpster", "target_type": target_type, "error": "unable_to_extract_domain"}

        base_url = f"https://api.dnsdumpster.com/domain/{domain}"
        response = requests.get(
            base_url,
            headers={"accept": "application/json", "X-API-Key": api_key},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            return {
                "source": "dnsdumpster",
                "target_type": target_type,
                "domain": domain,
                "error": "http 429: rate limit exceeded (DNSDumpster allows 1 request per 2 seconds)",
            }
        if response.status_code >= 400:
            return {"source": "dnsdumpster", "target_type": target_type, "error": self._short_http_error(response)}

        data = response.json()
        if not isinstance(data, dict):
            return {"source": "dnsdumpster", "target_type": target_type, "error": "unexpected_non_json_response"}
        if data.get("error"):
            return {
                "source": "dnsdumpster",
                "target_type": target_type,
                "domain": domain,
                "error": str(data.get("error")),
                "result_keys": sorted(data.keys()),
            }

        def list_for(payload: dict[str, Any], *keys: str) -> list[Any]:
            for key in keys:
                value = payload.get(key)
                if isinstance(value, list):
                    return value
            return []

        def unique_extend_strings(existing: list[str], incoming: list[str]) -> list[str]:
            out = list(existing)
            for value in incoming:
                text = str(value).strip()
                if text and text not in out:
                    out.append(text)
            return out

        def merge_record_rows(primary: list[Any], secondary: list[Any]) -> list[Any]:
            out = list(primary)
            seen_hosts = {
                str(item.get("host")).strip().lower()
                for item in out
                if isinstance(item, dict) and str(item.get("host")).strip()
            }
            for row in secondary:
                if not isinstance(row, dict):
                    continue
                host = str(row.get("host") or "").strip().lower()
                if host and host in seen_hosts:
                    continue
                out.append(row)
                if host:
                    seen_hosts.add(host)
            return out

        a_rows = list_for(data, "a", "A")
        ns_rows = list_for(data, "ns", "NS")
        mx_rows = list_for(data, "mx", "MX")
        cname_rows = list_for(data, "cname", "CNAME")
        txt_rows = list_for(data, "txt", "TXT")

        total_a_recs_raw = data.get("total_a_recs") or data.get("total_A_recs")
        try:
            total_a_recs = int(total_a_recs_raw) if total_a_recs_raw not in (None, "") else 0
        except Exception:
            total_a_recs = 0

        # DNSDumpster allows page traversal; free tiers may still cap total retrievable records.
        max_pages_raw = str(os.environ.get("DNSDUMPSTER_MAX_PAGES", "5")).strip()
        try:
            max_pages = max(1, int(max_pages_raw))
        except Exception:
            max_pages = 5
        pages_fetched = 1
        for page in range(2, max_pages + 1):
            # Avoid paging when we already have enough host records.
            if total_a_recs and len(a_rows) >= total_a_recs:
                break
            time.sleep(2.1)  # API limit: 1 request per 2 seconds.
            page_resp = requests.get(
                base_url,
                params={"page": page},
                headers={"accept": "application/json", "X-API-Key": api_key},
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
            if page_resp.status_code == 429:
                break
            if page_resp.status_code >= 400:
                break
            page_data = page_resp.json()
            if not isinstance(page_data, dict):
                break
            page_a = list_for(page_data, "a", "A")
            page_ns = list_for(page_data, "ns", "NS")
            page_mx = list_for(page_data, "mx", "MX")
            page_cname = list_for(page_data, "cname", "CNAME")
            page_txt = list_for(page_data, "txt", "TXT")
            prev_count = len(a_rows)
            a_rows = merge_record_rows(a_rows, page_a)
            ns_rows = merge_record_rows(ns_rows, page_ns)
            mx_rows = merge_record_rows(mx_rows, page_mx)
            cname_rows = merge_record_rows(cname_rows, page_cname)
            txt_rows = unique_extend_strings(
                [str(v) for v in txt_rows if str(v).strip()],
                [str(v) for v in page_txt if str(v).strip()],
            )
            pages_fetched = page
            # Stop if no growth, implying no more paginated data for this account.
            if len(a_rows) == prev_count:
                break

        def count_records(rows: list[Any]) -> int:
            value = rows
            return len(value) if isinstance(value, list) else 0

        def sample_hosts(rows: list[Any], limit: int = 250) -> list[str]:
            out: list[str] = []
            value = rows
            if not isinstance(value, list):
                return out
            for row in value:
                if not isinstance(row, dict):
                    continue
                host = str(row.get("host") or "").strip()
                if host and host not in out:
                    out.append(host)
                if len(out) >= limit:
                    break
            return out

        def sample_ips_from_records(rows: list[Any], limit: int = 120) -> list[str]:
            out: list[str] = []
            value = rows
            if not isinstance(value, list):
                return out
            for row in value:
                if not isinstance(row, dict):
                    continue
                ips = row.get("ips", [])
                if not isinstance(ips, list):
                    continue
                for ip_row in ips:
                    if not isinstance(ip_row, dict):
                        continue
                    ip = str(ip_row.get("ip") or "").strip()
                    if ip and ip not in out:
                        out.append(ip)
                    if len(out) >= limit:
                        return out
            return out

        txt_values = [str(v) for v in txt_rows if str(v).strip()]
        api_record_limit_hit = bool(total_a_recs and len(a_rows) < total_a_recs)
        limit_note = ""
        if api_record_limit_hit:
            limit_note = (
                f"returned {len(a_rows)} of {total_a_recs} A records; "
                "account/API limits or pagination cap may apply"
            )

        return {
            "source": "dnsdumpster",
            "target_type": target_type,
            "domain": domain,
            "a_count": count_records(a_rows),
            "ns_count": count_records(ns_rows),
            "mx_count": count_records(mx_rows),
            "cname_count": count_records(cname_rows),
            "txt_count": len(txt_values),
            "total_a_recs": total_a_recs or total_a_recs_raw,
            "pages_fetched": pages_fetched,
            "api_record_limit_hit": api_record_limit_hit,
            "limit_note": limit_note,
            "a_hosts": sample_hosts(a_rows),
            "ns_hosts": sample_hosts(ns_rows),
            "mx_hosts": sample_hosts(mx_rows),
            "resolved_ips": sample_ips_from_records(a_rows),
            "txt_records": txt_values,
            "result_keys": sorted(data.keys()),
        }

    @staticmethod
    def _dnsdb_limit(name: str, default: int, minimum: int = 1, maximum: int = 500) -> int:
        raw = str(os.environ.get(name, "")).strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except Exception:
            return default
        return max(minimum, min(maximum, value))

    @staticmethod
    def _dnsdb_timestamp(value: object) -> str | None:
        try:
            ts = int(value)
            return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%SZ")
        except Exception:
            text = str(value or "").strip()
            return text or None

    @staticmethod
    def _dnsdb_root_config() -> tuple[str, str]:
        raw = (
            str(os.environ.get("DNSDB_API_ROOT", "")).strip()
            or str(os.environ.get("DNSDB_BASE_URL", "")).strip()
            or "https://api.dnsdb.info/dnsdb/v2"
        )
        raw = raw.rstrip("/")
        lower = raw.lower()
        if "/dnsdb/v2" in lower:
            idx = lower.index("/dnsdb/v2") + len("/dnsdb/v2")
            return raw[:idx], "v2"
        if lower.endswith("/lookup_api"):
            return raw[: -len("/lookup_api")], "legacy"
        return raw, "legacy"

    @classmethod
    def _dnsdb_lookup_url(cls, section: str, mode_key: str, value: str, rrtype: str = "ANY") -> tuple[str, str]:
        root, api_mode = cls._dnsdb_root_config()
        safe_value = quote(str(value or "").strip(), safe="*._:-/")
        url = f"{root.rstrip('/')}/lookup/{section}/{mode_key}/{safe_value}/{rrtype}"
        return url, api_mode

    @staticmethod
    def _dnsdb_parse_response(response: requests.Response) -> tuple[list[dict[str, Any]], str]:
        body = str(response.text or "").strip()
        if not body:
            return [], ""
        try:
            payload = json.loads(body)
            if isinstance(payload, list):
                return [row for row in payload if isinstance(row, dict)], ""
            if isinstance(payload, dict):
                if isinstance(payload.get("results"), list):
                    return [row for row in payload.get("results", []) if isinstance(row, dict)], ""
                return [payload], ""
        except Exception:
            pass

        rows: list[dict[str, Any]] = []
        for line in body.splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                item = json.loads(text)
            except Exception:
                return [], "unexpected_non_json_response"
            if isinstance(item, dict):
                rows.append(item)
        return rows, ""

    def _dnsdb_lookup(self, section: str, mode_key: str, value: str, api_key: str, limit: int) -> tuple[list[dict[str, Any]], str, str]:
        url, api_mode = self._dnsdb_lookup_url(section, mode_key, value)
        try:
            response = requests.get(
                url,
                headers={
                    "accept": "application/x-ndjson, application/json;q=0.9",
                    "X-API-Key": api_key,
                },
                params={"limit": limit},
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            return [], str(exc), api_mode
        if response.status_code >= 400:
            return [], self._short_http_error(response), api_mode
        rows, parse_error = self._dnsdb_parse_response(response)
        return rows, parse_error, api_mode

    @classmethod
    def _dnsdb_row_preview(cls, row: dict[str, Any]) -> dict[str, Any]:
        rdata_values = row.get("rdata", [])
        if not isinstance(rdata_values, list):
            rdata_values = [rdata_values] if rdata_values not in (None, "") else []
        preview_values = [str(v).strip() for v in rdata_values if str(v).strip()]
        rdata_preview = ", ".join(preview_values[:3])
        if len(preview_values) > 3:
            rdata_preview += f" ... (+{len(preview_values)-3} more)"
        out: dict[str, Any] = {
            "rrname": str(row.get("rrname") or row.get("owner") or "").strip(),
            "rrtype": str(row.get("rrtype") or row.get("type") or "").strip(),
            "rdata": rdata_preview,
        }
        count = row.get("count")
        if count not in (None, ""):
            out["count"] = count
        first_seen = cls._dnsdb_timestamp(row.get("time_first"))
        last_seen = cls._dnsdb_timestamp(row.get("time_last"))
        if first_seen:
            out["first_seen"] = first_seen
        if last_seen:
            out["last_seen"] = last_seen
        bailiwick = str(row.get("bailiwick") or "").strip()
        if bailiwick:
            out["bailiwick"] = bailiwick
        return out

    @staticmethod
    def _dnsdb_extract_record_sets(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
        buckets: dict[str, list[str]] = {
            "a_records": [],
            "aaaa_records": [],
            "ns_records": [],
            "mx_records": [],
            "txt_records": [],
        }
        for row in rows:
            if not isinstance(row, dict):
                continue
            rrtype = str(row.get("rrtype") or row.get("type") or "").strip().upper()
            rdata_values = row.get("rdata", [])
            if not isinstance(rdata_values, list):
                rdata_values = [rdata_values] if rdata_values not in (None, "") else []
            for item in rdata_values:
                value = str(item or "").strip()
                if not value:
                    continue
                if rrtype == "A" and value not in buckets["a_records"]:
                    buckets["a_records"].append(value)
                elif rrtype == "AAAA" and value not in buckets["aaaa_records"]:
                    buckets["aaaa_records"].append(value)
                elif rrtype == "NS":
                    host = value.rstrip(".")
                    if host and host not in buckets["ns_records"]:
                        buckets["ns_records"].append(host)
                elif rrtype == "MX":
                    parts = value.split()
                    host = (parts[-1] if parts else value).rstrip(".")
                    if host and host not in buckets["mx_records"]:
                        buckets["mx_records"].append(host)
                elif rrtype == "TXT" and value not in buckets["txt_records"]:
                    buckets["txt_records"].append(value)
        return buckets

    @classmethod
    def _dnsdb_extract_subdomains(cls, rows: list[dict[str, Any]], apex: str) -> list[str]:
        out: list[str] = []
        suffix = "." + apex.lower()
        for row in rows:
            rrname = str(row.get("rrname") or row.get("owner") or "").strip().rstrip(".")
            if not rrname:
                continue
            lowered = rrname.lower()
            if lowered == apex.lower():
                continue
            if lowered.endswith(suffix) and rrname not in out:
                out.append(rrname)
        return out

    @classmethod
    def _dnsdb_extract_rrnames(cls, rows: list[dict[str, Any]]) -> list[str]:
        out: list[str] = []
        for row in rows:
            rrname = str(row.get("rrname") or row.get("owner") or "").strip().rstrip(".")
            if rrname and rrname not in out:
                out.append(rrname)
        return out

    def _run_dnsdb(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        rr_limit = self._dnsdb_limit("DNSDB_RRSET_LIMIT", 25)
        sub_limit = self._dnsdb_limit("DNSDB_SUBDOMAIN_LIMIT", 60)

        if target_type == "ip":
            rows, error, api_mode = self._dnsdb_lookup("rdata", "ip", normalized, api_key, limit=sub_limit)
            out: dict[str, Any] = {
                "source": "dnsdb",
                "target_type": target_type,
                "ip": normalized,
                "api_mode": api_mode,
            }
            if error:
                out["error"] = error
                return out
            rrnames = self._dnsdb_extract_rrnames(rows)
            out["rrname_count"] = len(rrnames)
            out["rrnames"] = rrnames[:60]
            out["rdata_records"] = [self._dnsdb_row_preview(row) for row in rows[:40] if isinstance(row, dict)]
            return out

        domain = normalized if target_type == "domain" else self._extract_domain_from_url(normalized)
        if not domain:
            return {"source": "dnsdb", "target_type": target_type, "error": "unable_to_extract_domain"}

        apex_rows, apex_error, api_mode = self._dnsdb_lookup("rrset", "name", domain, api_key, limit=rr_limit)
        wildcard_rows, sub_error, _ = self._dnsdb_lookup("rrset", "name", f"*.{domain}", api_key, limit=sub_limit)
        out: dict[str, Any] = {
            "source": "dnsdb",
            "target_type": target_type,
            "domain": domain,
            "api_mode": api_mode,
        }
        if apex_error:
            out["error"] = apex_error
            return out

        out.update(self._dnsdb_extract_record_sets(apex_rows))
        out["rrset_count"] = len(apex_rows)
        rrtypes = sorted({str(row.get("rrtype") or row.get("type") or "").strip().upper() for row in apex_rows if isinstance(row, dict)})
        if rrtypes:
            out["rrtypes"] = rrtypes
        out["rrsets"] = [self._dnsdb_row_preview(row) for row in apex_rows[:30] if isinstance(row, dict)]

        subdomains = self._dnsdb_extract_subdomains(wildcard_rows, domain)
        if subdomains:
            out["subdomain_count"] = len(subdomains)
            out["subdomains"] = subdomains[:60]
        if wildcard_rows:
            out["subdomain_rrset_count"] = len(wildcard_rows)
            out["subdomain_rrsets"] = [self._dnsdb_row_preview(row) for row in wildcard_rows[:40] if isinstance(row, dict)]
        if sub_error:
            out["subdomain_error"] = sub_error
        return out

    def _run_urlscan(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        search_query = ""
        raw_target = str(target or "").strip()
        # If user supplies urlscan-style query syntax (wildcards/operators), pass through as-is.
        if any(token in raw_target for token in ("*", " AND ", " OR ", ":", "(", ")")) and "://" not in raw_target:
            search_query = raw_target
        elif target_type == "ip":
            search_query = f"ip:{normalized}"
        elif target_type == "domain":
            search_query = f"domain:{normalized}"
        else:
            search_query = f'page.url:"{normalized}"'

        headers = {"accept": "application/json", "API-Key": api_key}
        max_results_raw = str(os.environ.get("URLSCAN_MAX_RESULTS", "50")).strip()
        try:
            max_results = max(1, min(100, int(max_results_raw)))
        except Exception:
            max_results = 50
        response = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": search_query, "size": max_results},
            headers=headers,
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {"source": "urlscan", "target_type": target_type, "error": self._short_http_error(response)}

        payload = response.json()
        results = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(results, list):
            results = []
        total = payload.get("total") if isinstance(payload, dict) else None

        scans: list[dict[str, Any]] = []
        malicious_votes = 0
        suspicious_votes = 0
        for row in results[:max_results]:
            if not isinstance(row, dict):
                continue
            page = row.get("page", {}) if isinstance(row.get("page"), dict) else {}
            task = row.get("task", {}) if isinstance(row.get("task"), dict) else {}
            verdicts = row.get("verdicts", {}) if isinstance(row.get("verdicts"), dict) else {}
            overall = verdicts.get("overall", {}) if isinstance(verdicts.get("overall"), dict) else {}
            score = overall.get("score")
            categories = overall.get("categories", [])
            brands = overall.get("brands", [])
            if isinstance(score, (int, float)):
                if score >= 50:
                    malicious_votes += 1
                elif score > 0:
                    suspicious_votes += 1
            scans.append(
                {
                    "time": task.get("time"),
                    "country": page.get("country"),
                    "ip": page.get("ip"),
                    "domain": page.get("domain"),
                    "url": page.get("url"),
                    "uuid": row.get("_id"),
                    "score": score,
                    "categories": categories if isinstance(categories, list) else [],
                    "brands": brands if isinstance(brands, list) else [],
                    "result_url": row.get("result"),
                }
            )

        risk_level = "low"
        if malicious_votes > 0:
            risk_level = "high"
        elif suspicious_votes > 0:
            risk_level = "medium"

        out: dict[str, Any] = {
            "source": "urlscan",
            "target_type": target_type,
            "query": search_query,
            "result_count": len(scans),
            "total_available": total,
            "max_results_used": max_results,
            "truncated": bool(isinstance(total, int) and total > len(scans)),
            "risk_level": risk_level,
            "malicious_hits": malicious_votes,
            "suspicious_hits": suspicious_votes,
            "recent_scans": scans,
        }

        submit_on_miss = str(os.environ.get("URLSCAN_SUBMIT_ON_MISS", "")).strip().lower() in {"1", "true", "yes"}
        if not scans and submit_on_miss and target_type == "url":
            submit_resp = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers={**headers, "content-type": "application/json"},
                json={"url": normalized, "visibility": "unlisted"},
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
            if submit_resp.status_code < 400:
                submit_payload = submit_resp.json() if submit_resp.headers.get("content-type", "").startswith("application/json") else {}
                out["submitted_scan"] = True
                out["submitted_uuid"] = submit_payload.get("uuid")
                out["submitted_result"] = submit_payload.get("result")
            else:
                out["submitted_scan"] = False
                out["submit_error"] = self._short_http_error(submit_resp)

        return out

    def _run_spamhaus(self, target: str, _api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type != "asn":
            return {"source": "spamhaus", "target_type": target_type, "error": "spamhaus_asndrop_requires_asn_target"}

        response = requests.get(
            "https://www.spamhaus.org/drop/asndrop.json",
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            return {"source": "spamhaus", "target_type": target_type, "asn": int(normalized), "error": self._short_http_error(response)}

        rows: list[dict[str, Any]] = []
        feed_type = None
        feed_generated = None
        text = str(response.text or "").strip()
        if text:
            # Spamhaus ASN-DROP currently returns NDJSON (one JSON object per line).
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = requests.models.complexjson.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
            if not rows:
                # Fallback for possible future payload shape changes.
                try:
                    payload = requests.models.complexjson.loads(text)
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    feed_type = payload.get("type")
                    feed_generated = payload.get("generated")
                    records = payload.get("records")
                    if isinstance(records, list):
                        rows = [row for row in records if isinstance(row, dict)]
                elif isinstance(payload, list):
                    rows = [row for row in payload if isinstance(row, dict)]

        matches: list[dict[str, Any]] = []
        for row in rows:
            asn_raw = str(row.get("asn") or row.get("asn_number") or row.get("autonomous_system_number") or "").strip().upper()
            if asn_raw.startswith("AS"):
                asn_raw = asn_raw[2:].strip()
            if asn_raw == normalized:
                matches.append(row)

        listed = bool(matches)
        first = matches[0] if matches else {}
        return {
            "source": "spamhaus",
            "target_type": target_type,
            "asn": int(normalized),
            "listed": listed,
            "risk_level": "high" if listed else "low",
            "match_count": len(matches),
            "as_name": first.get("asname") if isinstance(first, dict) else None,
            "domain": first.get("domain") if isinstance(first, dict) else None,
            "country_code": first.get("cc") if isinstance(first, dict) else None,
            "rir": first.get("rir") if isinstance(first, dict) else None,
            "feed_type": feed_type or "ndjson",
        }

    def _ripestat_get(self, endpoint: str, resource: str) -> tuple[dict[str, Any], str]:
        url = f"https://stat.ripe.net/data/{endpoint}/data.json"
        try:
            response = requests.get(
                url,
                params={"resource": resource},
                headers={"accept": "application/json"},
                timeout=ENRICHMENT_TIMEOUT_SECONDS,
            )
            if response.status_code >= 400:
                return {}, self._short_http_error(response)
            payload = response.json()
            data = payload.get("data", {}) if isinstance(payload, dict) else {}
            if isinstance(data, dict):
                return data, ""
            return {}, "unexpected_non_json_response"
        except Exception as exc:
            return {}, str(exc)

    def _run_ripestat(self, target: str, _api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type != "asn":
            return {"source": "ripestat", "target_type": target_type, "error": "ripestat_asn_lookup_requires_asn_target"}

        resource = f"AS{normalized}"
        out: dict[str, Any] = {
            "source": "ripestat",
            "target_type": target_type,
            "asn": int(normalized),
            "resource": resource,
        }

        overview, overview_err = self._ripestat_get("as-overview", resource)
        if overview_err:
            out["error"] = overview_err
            return out
        out["holder"] = overview.get("holder")
        out["country"] = overview.get("country")
        out["rir"] = overview.get("rir")

        abuse_data, abuse_err = self._ripestat_get("abuse-contact-finder", resource)
        if not abuse_err:
            emails = abuse_data.get("abuse_contacts")
            if isinstance(emails, list):
                out["abuse_contacts"] = [str(v).strip() for v in emails if str(v).strip()][:15]
        else:
            out["abuse_contacts_error"] = abuse_err

        routing_data, routing_err = self._ripestat_get("routing-status", resource)
        if not routing_err:
            for key in ("is_announced", "is_visible", "originating", "observed_upstreams"):
                value = routing_data.get(key)
                if value not in (None, "", []):
                    out[key] = value
            if routing_data.get("less_specifics") not in (None, "", []):
                out["less_specifics"] = routing_data.get("less_specifics")
            if routing_data.get("more_specifics") not in (None, "", []):
                out["more_specifics"] = routing_data.get("more_specifics")
        else:
            out["routing_status_error"] = routing_err

        prefixes_data, prefixes_err = self._ripestat_get("announced-prefixes", resource)
        if not prefixes_err:
            prefixes = prefixes_data.get("prefixes")
            if isinstance(prefixes, list):
                prefix_rows: list[dict[str, Any]] = []
                for item in prefixes[:40]:
                    if not isinstance(item, dict):
                        continue
                    timelines = item.get("timelines")
                    first_seen = None
                    last_seen = None
                    events = 0
                    if isinstance(timelines, list):
                        starts: list[str] = []
                        ends: list[str] = []
                        for t in timelines:
                            if not isinstance(t, dict):
                                continue
                            start = str(t.get("starttime") or "").strip()
                            end = str(t.get("endtime") or "").strip()
                            if start:
                                starts.append(start)
                            if end:
                                ends.append(end)
                        events = len(timelines)
                        if starts:
                            first_seen = min(starts)
                        if ends:
                            last_seen = max(ends)
                        elif starts:
                            last_seen = max(starts)
                    prefix_rows.append(
                        {
                            "prefix": item.get("prefix"),
                            "first_seen": first_seen,
                            "last_seen": last_seen,
                            "events": events if events else None,
                        }
                    )
                out["announced_prefix_count"] = len(prefixes)
                out["announced_prefixes"] = prefix_rows
        else:
            out["announced_prefixes_error"] = prefixes_err

        # Simple RIPEstat signal: announced+visible -> low baseline, otherwise medium unknown.
        visible = out.get("is_visible")
        announced = out.get("is_announced")
        if visible is False or announced is False:
            out["risk_level"] = "medium"
        else:
            out["risk_level"] = "low"
        return out

    def _run_securitytrails(self, target: str, api_key: str) -> dict[str, Any]:
        target_type, normalized = self._classify_target(target)
        if target_type == "ip":
            return {"source": "securitytrails", "target_type": target_type, "error": "securitytrails_domain_lookup_requires_domain_or_url"}
        domain = normalized if target_type == "domain" else self._extract_domain_from_url(normalized)
        if not domain:
            return {"source": "securitytrails", "target_type": target_type, "error": "unable_to_extract_domain"}

        headers = {"accept": "application/json", "APIKEY": api_key}
        out: dict[str, Any] = {
            "source": "securitytrails",
            "target_type": target_type,
            "domain": domain,
        }

        # Current domain snapshot
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
                "error": self._short_http_error(domain_resp),
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
            out.update(
                {
                    "apex_domain": domain_payload.get("apex_domain"),
                    "hostname": domain_payload.get("hostname"),
                    "current_a_records": a_records,
                    "current_ns_records": (
                        current_dns.get("ns", {}).get("values", [])
                        if isinstance(current_dns.get("ns"), dict)
                        else []
                    ),
                    "current_mx_records": (
                        current_dns.get("mx", {}).get("values", [])
                        if isinstance(current_dns.get("mx"), dict)
                        else []
                    ),
                    "current_txt_records": (
                        current_dns.get("txt", {}).get("values", [])
                        if isinstance(current_dns.get("txt"), dict)
                        else []
                    ),
                }
            )

        # Subdomains
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
            out["subdomains_error"] = self._short_http_error(sub_resp)

        # Historical A records
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
            out["ip_history_error"] = self._short_http_error(hist_resp)

        return out
