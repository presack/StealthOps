"""Shared utilities used across enrichment provider adapters."""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

import requests

ENRICHMENT_TIMEOUT_SECONDS = 8


def classify_target(target: str) -> tuple[str, str]:
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
    asn = normalize_asn(value)
    if asn:
        return "asn", asn
    return "domain", value.lower()


def normalize_asn(value: str) -> str | None:
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


def short_http_error(response: requests.Response) -> str:
    body = response.text.strip().replace("\n", " ")
    if len(body) > 140:
        body = body[:137].rstrip() + "..."
    return f"http {response.status_code}: {body or 'request failed'}"


def extract_domain_from_url(value: str) -> str:
    parsed = urlparse(value)
    return str(parsed.hostname or "").strip().lower()


def env_flag(name: str, default: bool = False) -> bool:
    value = str(os.environ.get(name, "")).strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}
