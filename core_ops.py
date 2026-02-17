"""Core investigative operations for StealthOps."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import dns.resolver
import requests
import whois

from tor_engine import TorEngine


@dataclass
class QueryConfig:
    block_non_tor: bool = False
    route_mode: str = "stealth"


class StealthQueryEngine:
    def __init__(self, tor_engine: TorEngine, config: QueryConfig | None = None) -> None:
        self.tor_engine = tor_engine
        self.config = config or QueryConfig()

    def _proxies(self) -> dict[str, str] | None:
        if self.config.route_mode == "public":
            return None

        if self.tor_engine.verify_circuit():
            proxy = self.tor_engine.proxy_url
            return {"http": proxy, "https": proxy}

        if self.config.block_non_tor:
            raise RuntimeError("Tor routing required but unavailable (Block Non-Tor Traffic enabled)")
        return None

    def _doh_query(self, domain: str, record_type: str) -> list[str]:
        proxies = self._proxies()
        if not proxies:
            raise RuntimeError("DoH query over Tor unavailable")

        response = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": record_type},
            headers={"accept": "application/dns-json"},
            proxies=proxies,
            timeout=12,
        )
        response.raise_for_status()
        payload = response.json()

        answers = payload.get("Answer", [])
        return [str(item.get("data", "")).rstrip(".") for item in answers if item.get("data")]

    def _resolver_fallback(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.port = 53
        return resolver

    def dns_lookup(self, domain: str) -> dict[str, Any]:
        out: dict[str, Any] = {"domain": domain, "a": [], "aaaa": [], "ns": []}

        for rtype, key in (("A", "a"), ("AAAA", "aaaa"), ("NS", "ns")):
            try:
                out[key] = self._doh_query(domain, rtype)
            except Exception as doh_exc:
                if self.config.block_non_tor:
                    out[f"{key}_error"] = str(doh_exc)
                    continue

                # Controlled fallback when user allows non-Tor traffic.
                try:
                    answers = self._resolver_fallback().resolve(domain, rtype, lifetime=8)
                    out[key] = [str(record).rstrip(".") for record in answers]
                    out[f"{key}_warning"] = "non-tor fallback used"
                except Exception as dns_exc:
                    out[f"{key}_error"] = f"doh={doh_exc}; resolver={dns_exc}"

        return out

    def mx_lookup(self, domain: str) -> dict[str, Any]:
        result: dict[str, Any] = {"domain": domain, "mx": []}

        try:
            records = self._doh_query(domain, "MX")
            parsed = []
            for record in records:
                parts = record.split(maxsplit=1)
                if len(parts) == 2 and parts[0].isdigit():
                    parsed.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
                else:
                    parsed.append({"priority": None, "host": record})
            result["mx"] = sorted(
                parsed,
                key=lambda item: item["priority"] if item["priority"] is not None else 65535,
            )
            return result
        except Exception as doh_exc:
            if self.config.block_non_tor:
                result["mx_error"] = str(doh_exc)
                return result

        try:
            answers = self._resolver_fallback().resolve(domain, "MX", lifetime=8)
            result["mx"] = [
                {"priority": r.preference, "host": str(r.exchange).rstrip(".")}
                for r in sorted(answers, key=lambda x: x.preference)
            ]
            result["mx_warning"] = "non-tor fallback used"
        except Exception as dns_exc:
            result["mx_error"] = str(dns_exc)

        return result

    def whois_lookup(self, domain: str) -> dict[str, Any]:
        # python-whois does not support SOCKS directly; this remains best-effort.
        try:
            data = whois.whois(domain)
        except Exception as exc:
            return {"domain": domain, "whois_error": str(exc)}

        normalized = {}
        for key, value in data.items():
            if isinstance(value, list):
                normalized[key] = [str(v) for v in value]
            elif value is None:
                normalized[key] = None
            else:
                normalized[key] = str(value)
        normalized["domain"] = domain
        return normalized

    def header_inspect(self, url: str) -> dict[str, Any]:
        target = url if url.startswith(("http://", "https://")) else f"https://{url}"
        proxies = self._proxies()

        try:
            response = requests.get(
                target,
                timeout=12,
                proxies=proxies,
                allow_redirects=True,
            )
            return {
                "url": target,
                "status_code": response.status_code,
                "final_url": response.url,
                "headers": dict(response.headers),
                "tor_routed": bool(proxies),
            }
        except Exception as exc:
            return {"url": target, "header_error": str(exc), "tor_routed": bool(proxies)}

    def run_all(self, target: str) -> dict[str, Any]:
        return {
            "dns": self.dns_lookup(target),
            "mx": self.mx_lookup(target),
            "whois": self.whois_lookup(target),
            "headers": self.header_inspect(target),
        }
