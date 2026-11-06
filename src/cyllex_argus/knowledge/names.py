"""Name normalization and alias matching."""

from __future__ import annotations

import re
from collections.abc import Iterable

_SEPARATORS = re.compile(r"[\W_]+", re.UNICODE)


def normalize_name(value: str) -> str:
    """Casefold and collapse punctuation/whitespace: 'Octo-Tempest' -> 'octo tempest'."""
    return _SEPARATORS.sub(" ", value.casefold()).strip()


def _whole_words(alias: str) -> str:
    return rf"(?<!\S){re.escape(alias)}(?!\S)"


def count_mentions(text: str, aliases: Iterable[str]) -> int:
    """Count whole-word occurrences of any alias in text, after normalization."""
    haystack = normalize_name(text)
    total = 0
    for alias in {normalize_name(a) for a in aliases}:
        if alias:
            total += len(re.findall(_whole_words(alias), haystack))
    return total


def mentions_any(normalized_text: str, aliases: Iterable[str]) -> bool:
    """Same match as count_mentions(...) > 0, on a text already passed through normalize_name.

    Normalizing a long document once, instead of once per name, keeps many lookups cheap.
    """
    return any(
        alias and re.search(_whole_words(alias), normalized_text)
        for alias in {normalize_name(a) for a in aliases}
    )
