"""MXToolbox enrichment adapter."""

from __future__ import annotations

import os
from typing import Any

import requests

from ._shared import ENRICHMENT_TIMEOUT_SECONDS, classify_target, extract_domain_from_url, short_http_error


def run(target: str, key: str) -> dict[str, Any]:
    target_type, normalized = classify_target(target)
    if target_type == "ip":
        commands = ["ptr"]
        argument = normalized
    else:
        default_commands = "dns,mx,spf,dmarc"
        raw_commands = str(os.environ.get("MXTOOLBOX_DOMAIN_COMMANDS", default_commands)).strip()
        commands = [c.strip().lower() for c in raw_commands.split(",") if c.strip()]
        if not commands:
            commands = ["dns", "mx", "spf", "dmarc"]
        argument = normalized if target_type == "domain" else extract_domain_from_url(normalized)

    if not argument:
        return {"source": "mxtoolbox", "target_type": target_type, "error": "unable_to_extract_lookup_argument"}

    checks: list[dict[str, Any]] = []
    total_failed = 0
    total_warnings = 0
    total_passed = 0
    reporting_nameservers: list[str] = []
    failed_details: list[str] = []
    warning_details: list[str] = []
    passed_details: list[str] = []

    for command in commands:
        payload, err = _lookup(command, argument, key)
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

        local_failed: list[str] = []
        local_warnings: list[str] = []
        local_passed: list[str] = []
        for group, local, global_ in (
            (failed, local_failed, failed_details),
            (warnings, local_warnings, warning_details),
            (passed, local_passed, passed_details),
        ):
            if isinstance(group, list):
                for item in group[:5]:
                    if isinstance(item, dict):
                        name = str(item.get("Name") or "").strip()
                        info = str(item.get("Info") or "").strip()
                        if name or info:
                            entry = f"{name}: {info}".strip(": ")
                            local.append(entry)
                            if entry not in global_ and len(global_) < 12:
                                global_.append(entry)

        checks.append({
            "command": payload.get("Command") or command,
            "argument": payload.get("CommandArgument") or argument,
            "reporting_nameserver": reporting_ns or None,
            "failed_count": failed_count,
            "warning_count": warning_count,
            "passed_count": passed_count,
            "failed_details": local_failed,
            "warning_details": local_warnings,
            "passed_details": local_passed,
        })

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


def summary(payload: dict[str, Any]) -> str:
    fail = payload.get("failed_count") or 0
    warn = payload.get("warning_count") or 0
    cmds = payload.get("commands_run", [])
    cmd_text = ",".join(str(c) for c in cmds[:4]) if isinstance(cmds, list) and cmds else "single"
    return f"mxtoolbox cmds={cmd_text} failed={fail} warning={warn}"


def _lookup(command: str, argument: str, api_key: str) -> tuple[dict[str, Any], str]:
    base_url = f"https://api.mxtoolbox.com/api/v1/Lookup/{command}/{argument}/"
    headers = {"accept": "application/json", "Authorization": api_key}
    response = requests.get(base_url, headers=headers, timeout=ENRICHMENT_TIMEOUT_SECONDS)
    if response.status_code in {401, 403}:
        response = requests.get(
            base_url,
            params={"apikey": api_key},
            headers={"accept": "application/json"},
            timeout=ENRICHMENT_TIMEOUT_SECONDS,
        )
    if response.status_code >= 400:
        return {}, short_http_error(response)
    payload = response.json()
    if not isinstance(payload, dict):
        return {}, "unexpected_non_json_response"
    return payload, ""
