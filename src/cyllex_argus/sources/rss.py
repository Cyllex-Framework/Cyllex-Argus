"""Curated vendor RSS feeds: keep entries that mention the target or one of its aliases."""

from __future__ import annotations

from collections.abc import Callable
from datetime import date

import feedparser

from cyllex_argus.config.settings import FeedConfig
from cyllex_argus.documents.fetch import Fetcher, FetchError
from cyllex_argus.knowledge.names import count_mentions
from cyllex_argus.sources.base import CandidateSource, ResolvedTarget


def _entry_date(entry: dict) -> date | None:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    return date(*parsed[:3]) if parsed else None


class RssConnector:
    name = "rss"

    def __init__(
        self,
        feeds: list[FeedConfig],
        fetcher: Fetcher,
        log: Callable[[str], None] = lambda message: None,
    ) -> None:
        self._feeds = feeds
        self._fetcher = fetcher
        self._log = log

    # Per-feed hard cap: a vendor mirror with 500 recent posts × N feeds would otherwise pump
    # straight into memory and the Analyst queue. The orchestrator caps the whole collect pass
    # later, but by then it has already paid the full fetch + parse. Capping per feed is cheap
    # and keeps a chatty feed from starving a quieter one in the final selection.
    MAX_MATCHES_PER_FEED = 50

    def search(self, target: ResolvedTarget, limit: int | None = None) -> list[CandidateSource]:
        found: list[CandidateSource] = []
        for feed in self._feeds:
            try:
                fetched = self._fetcher.fetch(feed.url)
            except FetchError as exc:
                self._log(f"Feed {feed.name} skipped: {exc}")
                continue
            per_feed = 0
            for entry in feedparser.parse(fetched.content).entries:
                if per_feed >= self.MAX_MATCHES_PER_FEED:
                    self._log(f"Feed {feed.name}: capped at {self.MAX_MATCHES_PER_FEED} matches")
                    break
                link = entry.get("link")
                text = f"{entry.get('title', '')} {entry.get('summary', '')}"
                if not link or count_mentions(text, target.aliases) == 0:
                    continue
                found.append(CandidateSource(
                    url=link, title=entry.get("title"), publisher=feed.name,
                    published_at=_entry_date(entry),
                ))
                per_feed += 1
        found.sort(key=lambda c: c.published_at or date.min, reverse=True)
        return found
