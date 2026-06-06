"""EnrichmentManager and provider registry for StealthOps."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Any

from .providers import (
    abuseipdb,
    censys,
    dnsdb,
    dnsdumpster,
    greynoise,
    mxtoolbox,
    ripestat,
    securitytrails,
    shodan,
    spamhaus,
    spur,
    urlscan,
    viewdns,
    virustotal,
)
from .providers._shared import classify_target

_PROVIDER_ADAPTERS = {
    "virustotal": virustotal,
    "shodan": shodan,
    "censys": censys,
    "spur": spur,
    "viewdns": viewdns,
    "mxtoolbox": mxtoolbox,
    "abuseipdb": abuseipdb,
    "greynoise": greynoise,
    "dnsdumpster": dnsdumpster,
    "dnsdb": dnsdb,
    "urlscan": urlscan,
    "securitytrails": securitytrails,
    "spamhaus": spamhaus,
    "ripestat": ripestat,
}


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
        target_type, _ = classify_target(target)

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

        for provider in resolved:
            if not self._provider_supports_target(provider, target_type):
                out["skipped"].append({
                    "provider": provider,
                    "reason": "unsupported_target_type",
                    "target_type": target_type,
                })
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
        adapter = _PROVIDER_ADAPTERS.get(provider)
        if adapter and hasattr(adapter, "summary"):
            s = adapter.summary(payload)
            if s:
                payload["summary"] = s
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
        adapter = _PROVIDER_ADAPTERS.get(provider)
        if adapter:
            return adapter.run(target, key)
        return {"error": "adapter_not_implemented"}

    @staticmethod
    def _should_retry_with_next_key(error_text: str) -> bool:
        text = str(error_text or "").strip().lower()
        if not text:
            return False
        retry_markers = (
            "http 401", "http 403", "http 429", "unauthorized", "forbidden",
            "invalid api", "invalid key", "bad api key", "rate limit",
            "quota", "credits", "key exhausted", "account limit",
        )
        return any(marker in text for marker in retry_markers)

    def run_one(self, target: str, provider: str) -> dict[str, Any]:
        """Run a single named provider and return its payload dict."""
        keys = self._keys.get(provider, [])
        target_type, _ = classify_target(target)
        if not self._provider_supports_target(provider, target_type):
            return {"error": f"unsupported_target_type:{target_type}"}
        if self._provider_requires_key(provider) and not keys:
            return {"error": "missing_api_key"}
        try:
            payload = self._run_provider_with_fallback(provider, target, keys)
            payload = self._with_summary(provider, payload)
            self._record_usage(provider, error=bool(payload.get("error")))
            return payload
        except Exception as exc:
            self._record_usage(provider, error=True)
            return {"error": str(exc)}

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
