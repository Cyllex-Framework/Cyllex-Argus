"""Source connector interface: every source (web, RSS, future feeds) returns candidates."""

from __future__ import annotations

from datetime import date
from typing import Protocol

from pydantic import BaseModel, Field


class ResolvedTarget(BaseModel):
    name: str
    entity_id: str | None = None
    aliases: list[str]
    # Receive-only OPSEC: the only names that may leave the machine in a search query, the main one
    # first. They come from ATT&CK or the user, never from ingested documents (which may hold
    # internal codenames). Empty means "search for `name` only".
    search_aliases: list[str] = Field(default_factory=list)


class CandidateSource(BaseModel):
    url: str
    title: str | None = None
    publisher: str | None = None
    published_at: date | None = None


class SourceConnector(Protocol):
    name: str

    def search(self, target: ResolvedTarget, limit: int | None = None) -> list[CandidateSource]: ...
