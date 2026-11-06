"""Deterministic quote verification: the main guard against hallucinated or injected claims."""

from __future__ import annotations

import re
import unicodedata
from array import array

from rapidfuzz import fuzz

from cyllex_argus.knowledge.models import QuoteStatus

MIN_QUOTE_CHARS = 20
MAX_LOCATE_CHARS = 2000
_MAX_SNAP = 40  # longest run of non-whitespace a highlight is widened over to reach a word boundary

_TRANSLATION = str.maketrans({
    "‘": "'",  # LEFT SINGLE QUOTATION MARK
    "’": "'",  # RIGHT SINGLE QUOTATION MARK
    "‚": "'",  # SINGLE LOW-9 QUOTATION MARK
    "‛": "'",  # SINGLE HIGH-REVERSED-9 QUOTATION MARK
    "“": '"',  # LEFT DOUBLE QUOTATION MARK
    "”": '"',  # RIGHT DOUBLE QUOTATION MARK
    "„": '"',  # DOUBLE LOW-9 QUOTATION MARK
    "–": "-",  # EN DASH
    "—": "-",  # EM DASH
    "−": "-",  # MINUS SIGN
    "\u00ad": "",   # SOFT HYPHEN
})
_WHITESPACE = re.compile(r"\s+")
_EDGE_PUNCTUATION = " .,;:\"'"


def normalize_text(value: str) -> str:
    """NFKC, ASCII quotes and dashes, casefold, single spaces."""
    text = unicodedata.normalize("NFKC", value).translate(_TRANSLATION).casefold()
    return _WHITESPACE.sub(" ", text).strip()


def verify_quote(
    quote: str, text: str, fuzzy_threshold: float = 95, *,
    normalized_haystack: str | None = None,
) -> QuoteStatus:
    """Check that the quote really appears in the document text.

    `normalized_haystack` is a fast path for callers that verify many quotes against the same
    document: pass `normalize_text(text)` once, hand it in on every call, and skip the per-call
    `normalize_text(text)` which was the dominant cost (`validator.process` loop over N claims).
    When None, we normalize `text` ourselves — behaviour unchanged for all existing callers.
    """
    needle = normalize_text(quote).strip(_EDGE_PUNCTUATION)
    if len(needle) < MIN_QUOTE_CHARS:
        return QuoteStatus.REJECTED
    haystack = normalized_haystack if normalized_haystack is not None else normalize_text(text)
    if not haystack:
        return QuoteStatus.REJECTED
    if len(needle) > len(haystack):
        return QuoteStatus.REJECTED
    if needle in haystack:
        return QuoteStatus.VERIFIED
    if fuzz.partial_ratio(needle, haystack) >= fuzzy_threshold:
        return QuoteStatus.VERIFIED_FUZZY
    return QuoteStatus.REJECTED


def _is_mark(char: str) -> bool:
    """A combining mark, or another Unicode mark such as an Indic vowel sign (combining class 0)."""
    return bool(unicodedata.combining(char)) or unicodedata.category(char).startswith("M")


def _normalize_cluster(cluster: str) -> str:
    """normalize_text without the whitespace step: NFKC, ASCII quotes and dashes, casefold."""
    return unicodedata.normalize("NFKC", cluster).translate(_TRANSLATION).casefold()


class QuoteLocator:
    """Finds where quotes sit in ONE document's original text, for highlighting.

    Builds once a normalized copy of the text, normalized exactly like verify_quote does, plus a map from
    every normalized character back to the range of original characters it came from. Build one
    instance per document and reuse it for all of that document's quotes.
    """

    def __init__(self, text: str) -> None:
        self._text = text
        chars: list[str] = []
        starts = array("q")
        ends = array("q")
        size = len(text)
        index = 0
        while index < size:
            # A cluster is a base character plus its combining marks: NFKC may compose them into one character.
            end = index + 1
            while end < size and unicodedata.combining(text[end]):
                end += 1
            for char in _normalize_cluster(text[index:end]):
                if char.isspace():
                    if chars and chars[-1] == " ":
                        ends[-1] = end  # collapse a whitespace run into one space
                        continue
                    if not chars:
                        continue  # leading whitespace is stripped
                    char = " "
                chars.append(char)
                starts.append(index)
                ends.append(end)
            index = end
        if chars and chars[-1] == " ":
            chars.pop()
            starts.pop()
            ends.pop()
        self._normalized = "".join(chars)
        self._starts = starts
        self._ends = ends

    def locate(self, quote: str, fuzzy_threshold: float = 95) -> tuple[int, int] | None:
        """Return (start, end) offsets of the quote in the original text, or None if it is not there."""
        needle = normalize_text(quote).strip(_EDGE_PUNCTUATION)
        if not needle or len(needle) > MAX_LOCATE_CHARS or len(needle) > len(self._normalized):
            return None
        found = self._normalized.find(needle)
        if found >= 0:
            start, end = self._original_span(found, found + len(needle))
        else:
            span = self._fuzzy_span(needle, fuzzy_threshold)
            if span is None:
                return None
            start, end = self._snap_to_words(*self._original_span(*span))
        return (start, end) if 0 <= start < end <= len(self._text) else None

    def _original_span(self, start: int, end: int) -> tuple[int, int]:
        """Original offsets of the normalized half-open range [start, end)."""
        return self._starts[start], self._ends[end - 1]

    def _fuzzy_span(self, needle: str, fuzzy_threshold: float) -> tuple[int, int] | None:
        """Normalized range of the best fuzzy match, with both ends anchored on the quote's first and last word."""
        normalized = self._normalized
        alignment = fuzz.partial_ratio_alignment(needle, normalized, score_cutoff=fuzzy_threshold)
        if alignment is None:
            return None
        start, end = alignment.dest_start, alignment.dest_end
        slack = max(10, len(needle) // 5)
        low, high = max(0, start - slack), min(len(normalized), end + slack)
        words = needle.split() or [needle]
        first = normalized.find(words[0], low, high)
        last = normalized.rfind(words[-1], low, high)
        anchored_start = first if first >= 0 else start
        anchored_end = last + len(words[-1]) if last >= 0 else end
        if anchored_end > anchored_start:
            start, end = anchored_start, anchored_end
        return (start, end) if 0 <= start < end <= len(normalized) else None

    def _snap_to_words(self, start: int, end: int) -> tuple[int, int]:
        """Widen a span outward to whitespace boundaries of the original text, without adding edge punctuation."""
        text = self._text
        left = start
        while left > 0 and not text[left - 1].isspace():
            left -= 1
            if start - left > _MAX_SNAP:  # no word boundary in reach (unspaced script, long blob): leave it
                left = start
                break
        while left < start and not text[left].isalnum():
            left += 1
        right = end
        while right < len(text) and not text[right].isspace():
            right += 1
            if right - end > _MAX_SNAP:
                right = end
                break
        # A mark is not alphanumeric, but it belongs to its base character: peeling it would leave the base bare.
        while right > end and not text[right - 1].isalnum() and not _is_mark(text[right - 1]):
            right -= 1
        return left, right


def locate_quote(quote: str, text: str, fuzzy_threshold: float = 95) -> tuple[int, int] | None:
    """Find where a quote sits in the ORIGINAL text, for highlighting. Returns (start, end) or None.

    Locating many quotes in one document? Build one QuoteLocator and reuse it.
    """
    return QuoteLocator(text).locate(quote, fuzzy_threshold)
