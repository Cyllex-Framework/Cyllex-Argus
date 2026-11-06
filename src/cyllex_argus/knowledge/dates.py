"""Lenient date parsing for dates written by sources and by the LLM."""

from __future__ import annotations

import re
from datetime import date

_DATE = re.compile(r"^(\d{4})(?:-(\d{1,2})(?:-(\d{1,2}))?)?(?:$|[T ])")


def parse_loose_date(value: str | None) -> date | None:
    """Parse YYYY, YYYY-MM, YYYY-MM-DD or an ISO datetime. Returns None if unparseable."""
    if not value:
        return None
    match = _DATE.match(value.strip())
    if not match:
        return None
    year = int(match.group(1))
    month = int(match.group(2) or 1)
    day = int(match.group(3) or 1)
    try:
        return date(year, month, day)
    except ValueError:
        return None
