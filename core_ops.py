"""Core investigative operations for StealthOps."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

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
        out: dict[str, Any] = {
            "domain": domain,
            "a": [],
            "aaaa": [],
            "ns": [],
            "txt": [],
            "cname": [],
            "caa": [],
            "soa": [],
        }

        for rtype, key in (
            ("A", "a"),
            ("AAAA", "aaaa"),
            ("NS", "ns"),
            ("TXT", "txt"),
            ("CNAME", "cname"),
            ("CAA", "caa"),
            ("SOA", "soa"),
        ):
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
        raw_chunks: list[str] = []
        for key, value in data.items():
            if key == "raw":
                if isinstance(value, list):
                    raw_chunks.extend(str(v) for v in value if v)
                elif value:
                    raw_chunks.append(str(value))
                continue
            if isinstance(value, list):
                normalized[key] = [str(v) for v in value]
            elif value is None:
                normalized[key] = None
            else:
                normalized[key] = str(value)
        if "status" in normalized:
            statuses = normalized["status"]
            if not isinstance(statuses, list):
                statuses = [str(statuses)]
            compact = []
            for item in statuses:
                # Keep EPP status token and drop trailing help URL noise.
                token = str(item).strip().split()[0] if item else ""
                if token:
                    compact.append(token)
            if compact:
                normalized["status"] = sorted(set(compact))
        if raw_chunks:
            normalized["raw_whois"] = "\n\n".join(raw_chunks)
            normalized["domain_whois_record"] = normalized["raw_whois"]
        else:
            lines: list[str] = []
            ordered_fields = [
                ("Domain Name", "domain_name"),
                ("Registry Domain ID", "registry_domain_id"),
                ("Registrar WHOIS Server", "whois_server"),
                ("Registrar URL", "registrar_url"),
                ("Updated Date", "updated_date"),
                ("Creation Date", "creation_date"),
                ("Registry Expiry Date", "expiration_date"),
                ("Registrar", "registrar"),
                ("Registrar IANA ID", "registrar_iana_id"),
                ("Registrar Abuse Contact Email", "registrar_abuse_contact_email"),
                ("Registrar Abuse Contact Phone", "registrar_abuse_contact_phone"),
                ("Registrant Organization", "org"),
                ("Registrant Country", "country"),
                ("DNSSEC", "dnssec"),
            ]
            for label, key in ordered_fields:
                value = normalized.get(key)
                if value in (None, "", []):
                    continue
                if isinstance(value, list):
                    lines.append(f"{label}: {', '.join(str(v) for v in value)}")
                else:
                    lines.append(f"{label}: {value}")
            statuses = normalized.get("status")
            if isinstance(statuses, list):
                for status in statuses:
                    lines.append(f"Domain Status: {status}")
            elif statuses:
                lines.append(f"Domain Status: {statuses}")
            name_servers = normalized.get("name_servers")
            if isinstance(name_servers, list):
                for ns in name_servers:
                    lines.append(f"Name Server: {ns}")
            elif name_servers:
                lines.append(f"Name Server: {name_servers}")
            normalized["domain_whois_record"] = "\n".join(lines).strip()
        normalized["domain"] = domain
        return normalized

    def address_lookup(self, domain: str, dns_data: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "query": domain,
            "canonical_name": "",
            "aliases": [],
            "addresses": [],
        }
        try:
            canonical, aliases, addresses = socket.gethostbyname_ex(domain)
            result["canonical_name"] = canonical.rstrip(".")
            result["aliases"] = [str(v).rstrip(".") for v in aliases if v]
            result["addresses"] = [str(v) for v in addresses if v]
        except Exception as exc:
            result["address_lookup_error"] = str(exc)

        # Merge in DNS answers to avoid empty or incomplete address sets.
        merged = []
        for value in result.get("addresses", []):
            if value not in merged:
                merged.append(value)
        for value in dns_data.get("a", []):
            if value not in merged:
                merged.append(value)
        for value in dns_data.get("aaaa", []):
            if value not in merged:
                merged.append(value)
        result["addresses"] = merged

        if not result.get("canonical_name"):
            cname = dns_data.get("cname", [])
            if cname:
                result["canonical_name"] = str(cname[0]).rstrip(".")
            else:
                result["canonical_name"] = domain

        return result

    @staticmethod
    def _first_ip(dns_data: dict[str, Any]) -> str | None:
        for key in ("a", "aaaa"):
            values = dns_data.get(key, [])
            for value in values:
                try:
                    ipaddress.ip_address(str(value))
                    return str(value)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _extract_vcard_field(entity: dict[str, Any], field_name: str) -> str | None:
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            return None
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and str(item[0]).lower() == field_name:
                value = item[3]
                if isinstance(value, list):
                    return " ".join(str(v) for v in value if v)
                return str(value)
        return None

    @staticmethod
    def _format_network_whois_record(payload: dict[str, Any], source_url: str) -> str:
        lines: list[str] = []
        lines.append(f"Source: {source_url}")
        lines.append("")

        def add(label: str, key: str) -> None:
            value = payload.get(key)
            if value not in (None, ""):
                lines.append(f"{label}: {value}")

        add("Handle", "handle")
        add("Net Name", "name")
        add("Start Address", "startAddress")
        add("End Address", "endAddress")
        add("IP Version", "ipVersion")
        add("Type", "type")
        add("Country", "country")
        add("Parent Handle", "parentHandle")

        cidr_values: list[str] = []
        for cidr_item in payload.get("cidr0_cidrs", []):
            if not isinstance(cidr_item, dict):
                continue
            prefix = cidr_item.get("v4prefix") or cidr_item.get("v6prefix")
            length = cidr_item.get("length")
            if prefix and length is not None:
                cidr_values.append(f"{prefix}/{length}")
        if cidr_values:
            lines.append(f"CIDR: {', '.join(cidr_values)}")

        events = payload.get("events", [])
        if isinstance(events, list) and events:
            lines.append("")
            lines.append("Events:")
            for event in events:
                if not isinstance(event, dict):
                    continue
                action = event.get("eventAction", "event")
                date = event.get("eventDate", "")
                actor = event.get("eventActor", "")
                suffix = f" ({actor})" if actor else ""
                lines.append(f"- {action}: {date}{suffix}")

        entities = payload.get("entities", [])
        if isinstance(entities, list) and entities:
            lines.append("")
            lines.append("Entities:")
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                handle = str(entity.get("handle", "")).strip() or "-"
                roles = ", ".join(str(r) for r in entity.get("roles", []) if r) or "-"
                name = (
                    StealthQueryEngine._extract_vcard_field(entity, "fn")
                    or StealthQueryEngine._extract_vcard_field(entity, "org")
                    or "-"
                )
                email = StealthQueryEngine._extract_vcard_field(entity, "email") or "-"
                phone = StealthQueryEngine._extract_vcard_field(entity, "tel") or "-"
                lines.append(f"- Handle: {handle}")
                lines.append(f"  Name: {name}")
                lines.append(f"  Roles: {roles}")
                lines.append(f"  Email: {email}")
                lines.append(f"  Phone: {phone}")

        return "\n".join(lines).strip()

    def network_whois_lookup(self, dns_data: dict[str, Any]) -> dict[str, Any]:
        ip_value = self._first_ip(dns_data)
        if not ip_value:
            return {"network_whois_error": "no A/AAAA record available for network whois"}

        proxies = self._proxies()
        result: dict[str, Any] = {"ip": ip_value}
        if not proxies:
            result["network_whois_warning"] = "non-tor fallback used"

        urls = [
            f"https://rdap.org/ip/{ip_value}",
            f"https://rdap.arin.net/registry/ip/{ip_value}",
        ]
        last_error: str | None = None
        payload: dict[str, Any] | None = None
        used_url: str | None = None

        for url in urls:
            try:
                response = requests.get(
                    url,
                    headers={"accept": "application/rdap+json, application/json"},
                    proxies=proxies,
                    timeout=15,
                )
                response.raise_for_status()
                payload = response.json()
                used_url = url
                break
            except Exception as exc:
                last_error = str(exc)

        if payload is None:
            result["network_whois_error"] = last_error or "network whois lookup failed"
            return result

        result["rdap_url"] = used_url
        result["network_whois_record"] = self._format_network_whois_record(payload, used_url or "unknown")
        for src_key, dst_key in (
            ("name", "net_name"),
            ("handle", "net_handle"),
            ("startAddress", "start_address"),
            ("endAddress", "end_address"),
            ("ipVersion", "ip_version"),
            ("type", "net_type"),
            ("country", "country"),
            ("parentHandle", "parent_handle"),
        ):
            value = payload.get(src_key)
            if value:
                result[dst_key] = str(value)

        cidr_values = []
        for cidr_item in payload.get("cidr0_cidrs", []):
            if isinstance(cidr_item, dict):
                v4pref = cidr_item.get("v4prefix")
                v4len = cidr_item.get("length")
                v6pref = cidr_item.get("v6prefix")
                v6len = cidr_item.get("length")
                if v4pref and v4len is not None:
                    cidr_values.append(f"{v4pref}/{v4len}")
                elif v6pref and v6len is not None:
                    cidr_values.append(f"{v6pref}/{v6len}")
        if cidr_values:
            result["cidr"] = ", ".join(cidr_values)

        entities = payload.get("entities", [])
        if isinstance(entities, list):
            chosen_org = None
            abuse_email = None
            abuse_phone = None
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                roles = [str(r).lower() for r in entity.get("roles", [])]
                org_name = (
                    self._extract_vcard_field(entity, "fn")
                    or self._extract_vcard_field(entity, "org")
                    or entity.get("handle")
                )
                email = self._extract_vcard_field(entity, "email")
                phone = self._extract_vcard_field(entity, "tel")
                if not chosen_org and org_name:
                    chosen_org = str(org_name)
                if "abuse" in roles:
                    if email:
                        abuse_email = str(email)
                    if phone:
                        abuse_phone = str(phone)
            if chosen_org:
                result["organization"] = chosen_org
            if abuse_email:
                result["abuse_email"] = abuse_email
            if abuse_phone:
                result["abuse_phone"] = abuse_phone

        return result

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
        lookup_target = self._normalize_lookup_target(target)
        dns_data = self.dns_lookup(lookup_target)
        address_data = self.address_lookup(lookup_target, dns_data)
        return {
            "address": address_data,
            "dns": dns_data,
            "mx": self.mx_lookup(lookup_target),
            "whois": self.whois_lookup(lookup_target),
            "network_whois": self.network_whois_lookup(dns_data),
            "headers": self.header_inspect(target),
        }
    @staticmethod
    def _normalize_lookup_target(target: str) -> str:
        value = target.strip()
        if not value:
            return value
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            return parsed.hostname or value
        if "/" in value:
            return value.split("/", 1)[0]
        return value
