"""Split long documents at paragraph boundaries, remembering the current section heading."""

from __future__ import annotations

import re

from pydantic import BaseModel

_PARAGRAPH_BREAK = re.compile(r"\n\s*\n")
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+")
_MIN_CHUNK_CHARS = 1000
_OVERLAP_MARKER = "\n…\n"


class Chunk(BaseModel):
    index: int
    heading: str | None = None
    text: str


def _is_heading(paragraph: str) -> bool:
    line = paragraph.strip()
    return "\n" not in line and 0 < len(line) <= 80 and not line.endswith((".", ":", ";", ","))


def _split_long(paragraph: str, max_chars: int) -> list[str]:
    if len(paragraph) <= max_chars:
        return [paragraph]
    parts: list[str] = []
    current = ""
    for sentence in _SENTENCE_BREAK.split(paragraph):
        while len(sentence) > max_chars:
            if current:
                parts.append(current)
                current = ""
            parts.append(sentence[:max_chars])
            sentence = sentence[max_chars:]
        if current and len(current) + 1 + len(sentence) > max_chars:
            parts.append(current)
            current = sentence
        else:
            current = f"{current} {sentence}".strip()
    if current:
        parts.append(current)
    return parts


def chunk_text(text: str, max_chars: int, overlap_chars: int = 0) -> list[Chunk]:
    """Split `text` into chunks capped at `max_chars`.

    When `overlap_chars > 0`, every chunk after the first is prefixed with the trailing
    `overlap_chars` of the previous chunk, separated by a short marker. The overhead counts
    toward `max_chars`, so each chunk still fits under that hard cap. This lets a quote that
    straddles a chunk boundary be extracted whole from the following chunk.
    """
    if max_chars < _MIN_CHUNK_CHARS:
        raise ValueError(f"max_chars must be at least {_MIN_CHUNK_CHARS}")
    if overlap_chars < 0:
        raise ValueError("overlap_chars must be non-negative")
    overhead = overlap_chars + len(_OVERLAP_MARKER) if overlap_chars > 0 else 0
    # Core budget may fall below _MIN_CHUNK_CHARS when overlap is enabled; what we really need is
    # enough room to make progress on long paragraphs.
    core_budget = max_chars - overhead
    if core_budget < 100:
        raise ValueError(
            f"max_chars - overlap_chars leaves no room for content (core budget = {core_budget})"
        )

    # Detect whether text uses blank-line or single-line breaks
    has_blank_lines = bool(_PARAGRAPH_BREAK.search(text))
    if has_blank_lines:
        # Split on blank lines and join with "\n\n"
        paragraph_split = _PARAGRAPH_BREAK.split(text)
        separator = "\n\n"
        separator_len = 2
    else:
        # Split on single newlines and join with "\n"
        paragraph_split = text.split("\n")
        separator = "\n"
        separator_len = 1

    pieces: list[tuple[str | None, str]] = []
    heading: str | None = None
    for paragraph in (p.strip() for p in paragraph_split):
        if not paragraph:
            continue
        if _is_heading(paragraph):
            heading = paragraph
        for part in _split_long(paragraph, core_budget):
            pieces.append((heading, part))

    chunks: list[Chunk] = []
    buffer: list[str] = []
    size = 0
    buffer_heading: str | None = None
    for piece_heading, part in pieces:
        if buffer and size + separator_len + len(part) > core_budget:
            chunks.append(Chunk(index=len(chunks), heading=buffer_heading, text=separator.join(buffer)))
            buffer, size = [], 0
        if not buffer:
            buffer_heading = piece_heading
        size += len(part) + (separator_len if buffer else 0)
        buffer.append(part)
    if buffer:
        chunks.append(Chunk(index=len(chunks), heading=buffer_heading, text=separator.join(buffer)))

    if overlap_chars > 0 and len(chunks) > 1:
        with_overlap: list[Chunk] = [chunks[0]]
        for i in range(1, len(chunks)):
            tail = chunks[i - 1].text[-overlap_chars:]
            with_overlap.append(Chunk(
                index=chunks[i].index, heading=chunks[i].heading,
                text=f"{tail}{_OVERLAP_MARKER}{chunks[i].text}",
            ))
        chunks = with_overlap
    return chunks
