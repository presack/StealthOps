"""Core investigative operations for StealthOps."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Any, Callable
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

    def _resolver_query(self, name: str, rtype: str, lifetime: float = 8) -> list[str]:
        try:
            answers = self._resolver_fallback().resolve(name, rtype, lifetime=lifetime)
            return [str(record).rstrip(".") for record in answers]
        except dns.resolver.NoAnswer:
            return []

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _empty_dns_payload(name: str) -> dict[str, Any]:
        return {
            "domain": name,
            "a": [],
            "aaaa": [],
            "ns": [],
            "txt": [],
            "cname": [],
            "caa": [],
            "soa": [],
            "ptr": [],
        }

    @staticmethod
    def _merge_unique(existing: list[str], incoming: list[str]) -> list[str]:
        out = list(existing)
        for item in incoming:
            if item not in out:
                out.append(item)
        return out

    @staticmethod
    def _guess_domain_from_host(host: str) -> str:
        labels = [label for label in host.strip(".").split(".") if label]
        if len(labels) < 2:
            return host
        second_level_tokens = {"co", "com", "net", "org", "gov", "edu", "ac"}
        if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in second_level_tokens:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    @staticmethod
    def _first_non_empty(data: dict[str, Any], keys: list[str]) -> str:
        for key in keys:
            if key not in data:
                continue
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    text = str(item).strip()
                    if text:
                        return text
                continue
            text = str(value).strip() if value is not None else ""
            if text:
                return text
        return ""

    @staticmethod
    def _list_non_empty(data: dict[str, Any], keys: list[str]) -> list[str]:
        out: list[str] = []
        for key in keys:
            if key not in data:
                continue
            value = data.get(key)
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    text = str(item).strip()
                    if text and text not in out:
                        out.append(text)
            elif value is not None:
                text = str(value).strip()
                if text and text not in out:
                    out.append(text)
        return out

    @staticmethod
    def _format_whois_date(value: Any) -> str:
        if isinstance(value, list):
            value = value[0] if value else ""
        text = str(value).strip() if value is not None else ""
        if not text:
            return ""
        # python-whois may return datelike strings; convert to Central Ops-style DD-Mon-YYYY when possible.
        candidates = [text]
        if " " in text:
            candidates.append(text.split(" ", 1)[0])
        for candidate in candidates:
            try:
                dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                return dt.strftime("%d-%b-%Y")
            except ValueError:
                pass
            for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%b-%Y", "%d-%B-%Y"):
                try:
                    dt = datetime.strptime(candidate, fmt)
                    return dt.strftime("%d-%b-%Y")
                except ValueError:
                    continue
        return text

    @staticmethod
    def _raw_lines(raw_whois: str) -> list[str]:
        return [line.rstrip() for line in str(raw_whois or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")]

    @classmethod
    def _raw_first_value(cls, raw_whois: str, labels: list[str]) -> str:
        if not raw_whois:
            return ""
        labels_lc = [label.strip().lower() for label in labels if label.strip()]
        for line in cls._raw_lines(raw_whois):
            text = line.strip()
            if ":" not in text:
                continue
            key, value = text.split(":", 1)
            if key.strip().lower() in labels_lc:
                out = value.strip()
                if out:
                    return out
        return ""

    @classmethod
    def _raw_all_values(cls, raw_whois: str, labels: list[str]) -> list[str]:
        if not raw_whois:
            return []
        labels_lc = [label.strip().lower() for label in labels if label.strip()]
        out: list[str] = []
        for line in cls._raw_lines(raw_whois):
            text = line.strip()
            if ":" not in text:
                continue
            key, value = text.split(":", 1)
            if key.strip().lower() in labels_lc:
                candidate = value.strip()
                if candidate and candidate not in out:
                    out.append(candidate)
        return out

    @classmethod
    def _raw_section_lines(cls, raw_whois: str, headers: list[str]) -> list[str]:
        if not raw_whois:
            return []

        def is_header(line: str) -> bool:
            text = line.strip().rstrip(":")
            if not text:
                return False
            return bool(re.match(r"^[A-Za-z][A-Za-z0-9 /&_-]{1,80}$", text))

        lines = cls._raw_lines(raw_whois)
        headers_lc = [h.lower().rstrip(":") for h in headers]
        for i, line in enumerate(lines):
            text = line.strip()
            if not text.endswith(":"):
                continue
            candidate = text[:-1].strip().lower()
            if candidate not in headers_lc:
                continue

            out: list[str] = []
            j = i + 1
            started = False
            while j < len(lines):
                nxt = lines[j].rstrip()
                stripped = nxt.strip()
                if not stripped:
                    if started:
                        break
                    j += 1
                    continue
                if is_header(stripped) and stripped.endswith(":"):
                    break
                started = True
                out.append(stripped)
                j += 1
            if out:
                return out
        return []

    @classmethod
    def _raw_name_servers(cls, raw_whois: str) -> list[str]:
        out = cls._raw_all_values(raw_whois, ["Name Server", "nserver"])
        section_values = cls._raw_section_lines(raw_whois, ["Name Servers"])
        for value in section_values:
            candidate = value.split()[0].strip()
            if candidate and candidate not in out:
                out.append(candidate)
        return out

    @classmethod
    def _build_contact_block(
        cls,
        data: dict[str, Any],
        title: str,
        prefixes: list[str],
        raw_whois: str,
        raw_headers: list[str],
        raw_label_roots: list[str],
        contact_role: str,
    ) -> list[str]:
        def k(name: str) -> list[str]:
            out = [name]
            for prefix in prefixes:
                out.append(f"{prefix}{name}")
                if prefix and not prefix.endswith("_"):
                    out.append(f"{prefix}_{name}")
            return out

        section_values = cls._raw_section_lines(raw_whois, raw_headers)
        if section_values:
            lines = [f"{title}:"]
            for value in section_values:
                lines.append(f"\t{value}")
            lines.append("")
            return lines

        contact = {}
        contacts_obj = data.get("contacts")
        if isinstance(contacts_obj, dict):
            candidate = contacts_obj.get(contact_role)
            if isinstance(candidate, dict):
                contact = candidate

        def raw_labels(suffixes: list[str]) -> list[str]:
            labels: list[str] = []
            for root in raw_label_roots:
                for suffix in suffixes:
                    labels.append(f"{root} {suffix}".strip())
            return labels

        name = cls._first_non_empty(contact, ["name"]) or cls._first_non_empty(data, k("name"))
        if not name:
            name = cls._raw_first_value(raw_whois, raw_labels(["Name", "Contact", "Contact Name"]))
        org = cls._first_non_empty(contact, ["organization", "org"]) or cls._first_non_empty(data, k("organization") + k("org"))
        if not org:
            org = cls._raw_first_value(raw_whois, raw_labels(["Organization", "Org"]))
        street = cls._first_non_empty(contact, ["street", "address", "address1"]) or cls._first_non_empty(data, k("street") + k("address"))
        if not street:
            street = cls._raw_first_value(raw_whois, raw_labels(["Street", "Address", "Address1"]))
        city = cls._first_non_empty(contact, ["city"]) or cls._first_non_empty(data, k("city"))
        if not city:
            city = cls._raw_first_value(raw_whois, raw_labels(["City"]))
        state = cls._first_non_empty(contact, ["state", "province"]) or cls._first_non_empty(data, k("state") + k("province"))
        if not state:
            state = cls._raw_first_value(raw_whois, raw_labels(["State", "Province", "State/Province"]))
        postal = (
            cls._first_non_empty(contact, ["postal_code", "postcode", "zipcode", "zip"])
            or cls._first_non_empty(data, k("postal_code") + k("postcode") + k("zipcode"))
        )
        if not postal:
            postal = cls._raw_first_value(raw_whois, raw_labels(["Postal Code", "Postcode", "Zip Code", "Zip"]))
        country = cls._first_non_empty(contact, ["country"]) or cls._first_non_empty(data, k("country"))
        if not country:
            country = cls._raw_first_value(raw_whois, raw_labels(["Country"]))
        phone = cls._first_non_empty(contact, ["phone"]) or cls._first_non_empty(data, k("phone"))
        if not phone:
            phone = cls._raw_first_value(raw_whois, raw_labels(["Phone"]))
        email = cls._first_non_empty(contact, ["email", "emails"]) or cls._first_non_empty(data, k("email") + k("emails"))
        if not email:
            email = cls._raw_first_value(raw_whois, raw_labels(["Email"]))

        lines: list[str] = [f"{title}:"]
        rendered = []
        for part in (name, org, street):
            if part:
                rendered.append(part)

        city_line = ""
        if city and state and postal:
            city_line = f"{city}, {state} {postal}"
        elif city and state:
            city_line = f"{city}, {state}"
        elif city and postal:
            city_line = f"{city} {postal}"
        else:
            city_line = city or state or postal
        if city_line:
            rendered.append(city_line)

        for part in (country, phone, email):
            if part:
                rendered.append(part)

        if not rendered:
            lines.append("\t")
        else:
            for part in rendered:
                lines.append(f"\t{part}")
        lines.append("")
        return lines

    @classmethod
    def _build_domain_whois_record(cls, data: dict[str, Any], domain_fallback: str) -> str:
        raw_whois = str(data.get("raw_whois", "") or "")
        domain_name = cls._first_non_empty(data, ["domain_name", "domain"]) or domain_fallback
        if not domain_name:
            domain_name = cls._raw_first_value(raw_whois, ["Domain Name"]) or domain_fallback
        name_servers = cls._list_non_empty(data, ["name_servers"])
        if not name_servers:
            name_servers = cls._raw_name_servers(raw_whois)
        creation = cls._format_whois_date(data.get("creation_date"))
        if not creation:
            creation = cls._format_whois_date(
                cls._raw_first_value(raw_whois, ["Creation Date", "Registered On", "Domain record activated"])
            )
        updated = cls._format_whois_date(data.get("updated_date"))
        if not updated:
            updated = cls._format_whois_date(
                cls._raw_first_value(raw_whois, ["Updated Date", "Last Updated On", "Domain record last updated"])
            )
        expiration = cls._format_whois_date(data.get("expiration_date"))
        if not expiration:
            expiration = cls._format_whois_date(
                cls._raw_first_value(raw_whois, ["Registry Expiry Date", "Expiration Date", "Domain expires"])
            )

        lines: list[str] = []
        lines.append(f"Domain Name: {str(domain_name).upper()}")
        lines.append("")
        lines.extend(
            cls._build_contact_block(
                data,
                "Registrant",
                ["registrant_", ""],
                raw_whois,
                ["Registrant", "Registrant Contact"],
                ["Registrant"],
                "registrant",
            )
        )
        lines.extend(
            cls._build_contact_block(
                data,
                "Administrative Contact",
                ["admin_", "administrative_", ""],
                raw_whois,
                ["Administrative Contact", "Admin Contact"],
                ["Admin", "Administrative Contact", "Administrative"],
                "admin",
            )
        )
        lines.extend(
            cls._build_contact_block(
                data,
                "Technical Contact",
                ["tech_", "technical_", ""],
                raw_whois,
                ["Technical Contact", "Tech Contact"],
                ["Tech", "Technical Contact", "Technical"],
                "tech",
            )
        )

        lines.append("Name Servers:")
        if name_servers:
            for ns in name_servers:
                lines.append(f"\t{ns}")
        else:
            lines.append("\t")
        lines.append("")

        if creation:
            lines.append(f"{'Domain record activated:':<28} {creation}")
        if updated:
            lines.append(f"{'Domain record last updated:':<28} {updated}")
        if expiration:
            lines.append(f"{'Domain expires:':<28} {expiration}")

        return "\n".join(lines).strip()

    def dns_lookup(self, domain: str) -> dict[str, Any]:
        out = self._empty_dns_payload(domain)

        # In public mode, avoid Tor-first DoH attempts and query resolver directly.
        if self.config.route_mode == "public":
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
                    out[key] = self._resolver_query(domain, rtype, lifetime=8)
                except Exception as dns_exc:
                    out[f"{key}_error"] = str(dns_exc)
            return out

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
                    out[key] = self._resolver_query(domain, rtype, lifetime=8)
                    out[f"{key}_warning"] = "non-tor fallback used"
                except Exception as dns_exc:
                    out[f"{key}_error"] = f"doh={doh_exc}; resolver={dns_exc}"

        return out

    def mx_lookup(self, domain: str) -> dict[str, Any]:
        result: dict[str, Any] = {"domain": domain, "mx": []}

        if self.config.route_mode == "public":
            try:
                answers = self._resolver_fallback().resolve(domain, "MX", lifetime=8)
                result["mx"] = [
                    {"priority": r.preference, "host": str(r.exchange).rstrip(".")}
                    for r in sorted(answers, key=lambda x: x.preference)
                ]
            except dns.resolver.NoAnswer:
                result["mx"] = []
            except Exception as dns_exc:
                result["mx_error"] = str(dns_exc)
            return result

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
        except dns.resolver.NoAnswer:
            result["mx"] = []
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
            if isinstance(value, (list, tuple, set)):
                normalized[key] = [str(v) for v in value]
            elif isinstance(value, dict):
                normalized[key] = value
            elif value is None:
                normalized[key] = None
            else:
                normalized[key] = str(value)
        if not raw_chunks:
            text_value = getattr(data, "text", None)
            if text_value:
                raw_chunks.append(str(text_value))
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
        normalized["domain_whois_record"] = self._build_domain_whois_record(normalized, domain)
        normalized["domain"] = domain
        return normalized

    def address_lookup(self, domain: str, dns_data: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "query": domain,
            "canonical_name": "",
            "aliases": [],
            "addresses": [],
        }
        if self._is_ip(domain):
            try:
                canonical, aliases, addresses = socket.gethostbyaddr(domain)
                result["canonical_name"] = canonical.rstrip(".")
                result["aliases"] = [str(v).rstrip(".") for v in aliases if v]
                result["addresses"] = [str(v) for v in addresses if v]
            except Exception as exc:
                result["address_lookup_error"] = str(exc)
                result["addresses"] = [domain]
        else:
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

    def network_whois_lookup(self, dns_data: dict[str, Any], ip_override: str | None = None) -> dict[str, Any]:
        ip_value = ip_override or self._first_ip(dns_data)
        if not ip_value:
            return {"network_whois_error": "no A/AAAA record available for network whois"}

        proxies = self._proxies()
        result: dict[str, Any] = {"ip": ip_value}
        if not proxies and self.config.route_mode != "public":
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
        return self.run_all_staged(target)

    def run_all_staged(self, target: str, on_update: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
        def emit(snapshot: dict[str, Any]) -> None:
            if not on_update:
                return
            try:
                on_update(dict(snapshot))
            except Exception:
                pass

        lookup_target = self._normalize_lookup_target(target)
        is_ip = self._is_ip(lookup_target)
        out: dict[str, Any] = {}

        dns_target = lookup_target
        whois_target = lookup_target
        network_ip = lookup_target if is_ip else None

        if is_ip:
            # For IP targets, use reverse DNS host for DNS/WHOIS context when available.
            placeholder_dns = self._empty_dns_payload(lookup_target)
            address_data = self.address_lookup(lookup_target, placeholder_dns)
            canonical = str(address_data.get("canonical_name", "")).strip().rstrip(".")
            if canonical and canonical != lookup_target:
                dns_target = canonical
                whois_target = self._guess_domain_from_host(canonical)
                address_data["derived_domain"] = whois_target
            else:
                dns_target = lookup_target
                whois_target = ""
        else:
            dns_target = lookup_target
            whois_target = lookup_target
            address_data = {}

        emit({"address": address_data} if address_data else {})

        with ThreadPoolExecutor(max_workers=4) as pool:
            dns_future = pool.submit(self.dns_lookup, dns_target) if not self._is_ip(dns_target) else None
            mx_future = pool.submit(self.mx_lookup, whois_target or dns_target) if not self._is_ip(whois_target or dns_target) else None
            whois_future = pool.submit(self.whois_lookup, whois_target) if whois_target else None
            header_future = pool.submit(self.header_inspect, target)

            future_map = {}
            if dns_future:
                future_map[dns_future] = "dns"
            if mx_future:
                future_map[mx_future] = "mx"
            if whois_future:
                future_map[whois_future] = "whois"
            future_map[header_future] = "headers"

            if not dns_future:
                out["dns"] = self._empty_dns_payload(dns_target)
                emit(out)
            if not mx_future:
                out["mx"] = {"domain": dns_target, "mx": []}
                emit(out)
            if not whois_future:
                out["whois"] = {"whois_error": "unable to derive domain for whois from IP target"}
                emit(out)

            for future in as_completed(list(future_map.keys())):
                key = future_map[future]
                try:
                    out[key] = future.result()
                except Exception as exc:
                    if key == "headers":
                        out[key] = {"url": target, "header_error": str(exc), "tor_routed": self.config.route_mode == "stealth"}
                    elif key == "whois":
                        out[key] = {"whois_error": str(exc)}
                    elif key == "mx":
                        out[key] = {"domain": dns_target, "mx_error": str(exc), "mx": []}
                    else:
                        out[key] = self._empty_dns_payload(dns_target)
                        out[key]["dns_error"] = str(exc)
                emit(out)

        dns_data = out.get("dns", self._empty_dns_payload(dns_target))
        mx_data = out.get("mx", {"domain": dns_target, "mx": []})
        whois_data = out.get("whois", {"whois_error": "unable to derive domain for whois from IP target"})
        headers_data = out.get("headers", {"url": target, "tor_routed": self.config.route_mode == "stealth"})

        if is_ip:
            try:
                reverse_name = ".".join(reversed(lookup_target.split("."))) + ".in-addr.arpa"
                if self.config.route_mode == "public":
                    dns_data["ptr"] = self._resolver_query(reverse_name, "PTR", lifetime=8)
                else:
                    dns_data["ptr"] = self._doh_query(reverse_name, "PTR")
            except Exception as ptr_exc:
                dns_data["ptr_error"] = str(ptr_exc)

            # Pull authoritative context from derived registrable domain where possible.
            if whois_target:
                root_dns = self.dns_lookup(whois_target)
                for key in ("ns", "soa", "txt", "caa"):
                    dns_data[key] = self._merge_unique(dns_data.get(key, []), root_dns.get(key, []))
                for err_key in (k for k in root_dns.keys() if k.endswith("_error")):
                    dns_data.setdefault(err_key, root_dns[err_key])
            out["dns"] = dns_data
            emit(out)

        if not address_data:
            address_data = self.address_lookup(lookup_target, dns_data)
            out["address"] = address_data
            emit(out)

        network_whois_data = self.network_whois_lookup(dns_data, ip_override=network_ip)
        out["network_whois"] = network_whois_data
        emit(out)

        final = {
            "address": address_data,
            "dns": dns_data,
            "mx": mx_data,
            "whois": whois_data,
            "network_whois": network_whois_data,
            "headers": headers_data,
        }
        emit(final)
        return final
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
