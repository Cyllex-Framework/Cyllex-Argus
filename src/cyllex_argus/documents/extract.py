"""Turn downloaded bytes into clean text, and identify documents by hash and canonical URL."""

from __future__ import annotations

import hashlib
import io
import re
from datetime import date
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pdfplumber
import trafilatura
from pydantic import BaseModel

from cyllex_argus.knowledge.dates import parse_loose_date

_TRACKING_PARAMS = {"fbclid", "gclid", "mc_cid", "mc_eid"}
_BLANK_LINES = re.compile(r"\n\s*\n+")


class ExtractionError(Exception):
    """The document could not be turned into text."""


class Extracted(BaseModel):
    title: str
    text: str
    published_at: date | None = None


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonicalize_url(url: str) -> str:
    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        # Python 3.11+ raises ValueError on malformed IPv6 URLs. Translate into the
        # caller-friendly ValueError the function has always promised to raise so a
        # malformed candidate is skipped in `_identify` instead of aborting the whole
        # investigation document.
        raise ValueError(f"malformed URL {url!r}: {exc}") from exc
    scheme = "https" if parts.scheme.lower() in ("http", "https") else parts.scheme.lower()
    host = (parts.hostname or "").lower().removeprefix("www.")
    port = f":{parts.port}" if parts.port and parts.port not in (80, 443) else ""
    path = parts.path.rstrip("/") or "/"
    query = urlencode(sorted(
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith("utm_") and k.lower() not in _TRACKING_PARAMS
    ))
    return urlunsplit((scheme, host + port, path, query, ""))


def domain_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().removeprefix("www.")
    except ValueError:
        # See canonicalize_url: malformed IPv6 URLs raise ValueError on urlsplit in 3.11+.
        return ""


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


def detect_kind(data: bytes, content_type: str | None, name: str) -> Literal["pdf", "html", "text"]:
    ct = (content_type or "").lower()
    lower = name.lower()
    if "pdf" in ct or lower.endswith(".pdf") or data.startswith(b"%PDF"):
        return "pdf"
    head = data.lstrip()[:100].lower()
    if "html" in ct or lower.endswith((".html", ".htm")) or head.startswith((b"<!doctype html", b"<html")):
        return "html"
    return "text"


def extract(data: bytes, content_type: str | None, name: str) -> Extracted:
    # Reject unsupported content types
    if content_type:
        ct_lower = content_type.lower()
        if ct_lower.startswith(("image/", "audio/", "video/", "font/")):
            raise ExtractionError(f"unsupported content type: {content_type}")

    kind = detect_kind(data, content_type, name)
    if kind == "pdf":
        return _extract_pdf(data, name)
    if kind == "html":
        return _extract_html(data, name)
    return _extract_text(data, name)


def _extract_pdf(data: bytes, name: str) -> Extracted:
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            pages = [(page.extract_text() or "").strip() for page in pdf.pages]
            meta_title = (pdf.metadata or {}).get("Title")
    except Exception as exc:  # pdfplumber raises many unrelated exception types
        raise ExtractionError(f"PDF extraction failed: {exc}") from exc
    text = "\n".join(p for p in pages if p)
    if not text:
        raise ExtractionError("no text extracted from PDF")
    title = meta_title.strip() if isinstance(meta_title, str) and meta_title.strip() else ""
    return Extracted(title=title or _first_line(text) or name, text=text)


class _TextExtractor(HTMLParser):
    """Linear HTML text extractor that skips script, style, and noscript tags."""

    _BLOCK_TAGS = {"p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "section", "article"}
    _SKIP_TAGS = {"script", "style", "noscript"}

    def __init__(self):
        super().__init__()
        self.text_parts: list[str] = []
        self.skip_depth = 0  # Track nesting depth of skip tags

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        if tag_lower in self._SKIP_TAGS:
            self.skip_depth += 1
        elif self.skip_depth == 0 and tag_lower in self._BLOCK_TAGS:
            if self.text_parts and self.text_parts[-1] != "\n":
                self.text_parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in self._SKIP_TAGS:
            self.skip_depth = max(0, self.skip_depth - 1)
        elif self.skip_depth == 0 and tag_lower in self._BLOCK_TAGS:
            if self.text_parts and self.text_parts[-1] != "\n":
                self.text_parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.skip_depth == 0:
            self.text_parts.append(data)

    def get_text(self) -> str:
        text = "".join(self.text_parts)
        lines = (line.strip() for line in text.splitlines())
        return _BLANK_LINES.sub("\n\n", "\n".join(lines)).strip()


def _fallback_html_text(markup: str) -> str:
    extractor = _TextExtractor()
    try:
        extractor.feed(markup)
        extractor.close()
    except Exception:
        # If parsing fails, return empty string rather than raising
        return ""
    return extractor.get_text()


def _check_excessive_replacement_chars(text: str) -> None:
    """Raise ExtractionError if >5% of text is the replacement character U+FFFD."""
    replacement_char = chr(0xFFFD)
    if text and replacement_char in text:
        ratio = text.count(replacement_char) / len(text)
        if ratio > 0.05:
            raise ExtractionError("binary or undecodable content")


def _extract_html(data: bytes, name: str) -> Extracted:
    markup = data.decode("utf-8", errors="replace")
    _check_excessive_replacement_chars(markup)
    text = trafilatura.extract(markup, include_comments=False, include_tables=True, favor_recall=True)
    if not text:
        text = _fallback_html_text(markup)
    if not text.strip():
        raise ExtractionError("no text extracted from HTML")
    meta = trafilatura.extract_metadata(markup)
    title = meta.title if meta is not None and meta.title else ""
    published = parse_loose_date(meta.date) if meta is not None and meta.date else None
    return Extracted(title=title or _first_line(text) or name, text=text, published_at=published)


def _extract_text(data: bytes, name: str) -> Extracted:
    if b"\x00" in data:
        raise ExtractionError("binary content is not supported")
    text = data.decode("utf-8", errors="replace").strip()
    _check_excessive_replacement_chars(text)
    if not text:
        raise ExtractionError("empty text document")
    return Extracted(title=_first_line(text) or name, text=text)
