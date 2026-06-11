"""Shared utility functions for StealthOps."""

from __future__ import annotations

import re


def refang(indicator: str) -> str:
    """Strip common defanging characters from an indicator string.

    Handles: [.] (.) [dot] (dot) [:] hxxp:// hxxps://
    """
    s = indicator.strip()
    # Protocol defanging — must run before dot replacement
    s = re.sub(r"^hxxps://", "https://", s, flags=re.IGNORECASE)
    s = re.sub(r"^hxxp://", "http://", s, flags=re.IGNORECASE)
    # Colon defanging
    s = s.replace("[:]", ":")
    # Dot defanging
    s = s.replace("[.]", ".")
    s = s.replace("(.)", ".")
    s = re.sub(r"\[dot\]", ".", s, flags=re.IGNORECASE)
    s = re.sub(r"\(dot\)", ".", s, flags=re.IGNORECASE)
    return s
