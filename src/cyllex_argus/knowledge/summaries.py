"""Pydantic model for a cached executive summary.

The summary is the one piece of the knowledge base Argus writes in prose rather than in
triples: an LLM reading the consolidated assessments and answering "who is this threat and
how sure are we?". It is cached per entity because it costs an LLM call, and it carries the
fingerprint of the assessments it was written from so a reader can tell a current answer
from an outdated one.

Lives next to the store for the same reason as the other knowledge models: the schema is colocated
with the other knowledge-model schemas.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class StoredSummary(BaseModel):
    """One cached executive summary, as stored."""

    entity_id: str
    summary: str
    fingerprint: str
    fact_count: int
    prompt_version: str
    model: str | None
    created_at: datetime
