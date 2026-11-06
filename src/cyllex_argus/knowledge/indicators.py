"""Local, offline helpers for indicators and identities: freshness, indicator kind and sector hint."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from datetime import date
from typing import Literal

Freshness = Literal["active", "dormant", "historical", "unknown"]
IndicatorKind = Literal["domain", "ipv4", "ipv6", "url", "sha1", "sha256", "md5", "other"]

_ACTIVE_DAYS = 90
_DORMANT_DAYS = 365
_URL = re.compile(r"^https?://", re.IGNORECASE)
_HEX = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_HASH_LENGTHS: dict[int, IndicatorKind] = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_SECTORS = (
    "finance", "financial services", "healthcare", "government", "energy",
    "retail", "telecommunications", "education", "manufacturing", "technology",
)


def freshness_for(last_seen: date | None, today: date | None = None) -> Freshness:
    if last_seen is None:
        return "unknown"
    age = ((today or date.today()) - last_seen).days
    if age <= _ACTIVE_DAYS:
        return "active"
    if age <= _DORMANT_DAYS:
        return "dormant"
    return "historical"


def indicator_kind(value: str) -> IndicatorKind:
    text = value.strip()
    if _URL.match(text):
        return "url"
    try:
        return "ipv4" if ipaddress.ip_address(text).version == 4 else "ipv6"
    except ValueError:
        pass
    if _HEX.match(text) and len(text) in _HASH_LENGTHS:
        return _HASH_LENGTHS[len(text)]
    # A purely numeric last label is a malformed IP (300.1.1.1), never a TLD.
    if _DOMAIN.match(text.casefold()) and not text.rsplit(".", 1)[-1].isdigit():
        return "domain"
    return "other"


def sector_hint(names: Iterable[str]) -> str | None:
    """The first sector (in list order) that any of the names mentions, case-insensitively."""
    lowered = [n.casefold() for n in names]
    for sector in _SECTORS:
        if any(sector in name for name in lowered):
            return sector
    return None
