"""Find primary sources on the web through the LLM provider's web search tool.

Only Argus-generated queries reach this call; document text never does.

Discovery runs one search *per alias* rather than a single combined query. A web-search tool
returns a bounded, authority-ranked set per call, so one query with every alias jammed together
collapses onto the few highest-authority pages (and misses each vendor's own body of work, since
vendors track an actor under their own name: Cozy Bear → CrowdStrike, Midnight Blizzard →
Microsoft, UNC2452 → Mandiant). Searching each alias separately opens each of those doors, then
the results are merged and de-duplicated. Cost is bounded by `max_queries` (one billed search per
alias) and the total is capped at the effective `max_results`. One alias query that fails is
logged and skipped so it cannot sink the others.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from pydantic import BaseModel

from cyllex_argus.documents.extract import canonicalize_url, domain_of
from cyllex_argus.knowledge.dates import parse_loose_date
from cyllex_argus.llm.base import LLMError, LLMProvider, LLMRequest, LLMUnavailable, RateLimited
from cyllex_argus.pipeline.retry import complete_json_with_retries
from cyllex_argus.sources.base import CandidateSource, ResolvedTarget

_log = logging.getLogger(__name__)

WEB_SEARCH_PROMPT_VERSION = "web-search-v1"
DEFAULT_MAX_QUERIES = 8  # cap on alias queries per run: one billed web search each
MIN_PER_ALIAS = 4  # floor on the per-alias ask, so a big alias set still searches usefully

SYSTEM_PROMPT = """You are a cyber threat intelligence research assistant.
Use web search to find primary sources about the threat named by the user: vendor threat research,
government advisories (CISA, NCSC, national CERTs), incident reports and technical whitepapers.
Prefer original research over news coverage. Exclude marketing pages, product pages, social media
and forum posts. Return only URLs that appeared in your search results. Never invent URLs.
Set published_at (YYYY-MM-DD, YYYY-MM or YYYY) when the result shows a publication date."""


class SearchResult(BaseModel):
    # Every field tolerates omission: the model routinely drops `title`/`publisher` on a result
    # (and occasionally `url`), and a single missing field must not fail-validate the whole batch.
    # A result with no usable URL is dropped in `_search_one`; an empty publisher falls back to the
    # URL's domain; an empty title becomes None on the CandidateSource.
    url: str = ""
    title: str = ""
    publisher: str = ""
    published_at: str | None = None


class SearchResults(BaseModel):
    results: list[SearchResult]


class WebSearchConnector:
    name = "web_search"

    def __init__(self, llm: LLMProvider, max_results: int | None = None, *,
                 default_max_results: int = 15, max_queries: int = DEFAULT_MAX_QUERIES) -> None:
        # `max_results` is the explicit [llm.search] override: when set it pins the fan-out
        # regardless of the run. When None, search() uses the per-run limit (the
        # investigation's max_docs) so the operator's document budget also governs
        # discovery, falling back to `default_max_results` only when neither is given.
        # `max_queries` caps how many aliases get their own search (cost + latency guard).
        self._llm = llm
        self._override = max_results
        self._default = default_max_results
        self._max_queries = max(1, max_queries)

    def _effective_max_results(self, limit: int | None) -> int:
        """Fan-out for one search: config override if set, else the per-run limit
        (the investigation's max_docs), else the built-in default."""
        if self._override is not None:
            return max(1, self._override)
        if limit is not None:
            return max(1, limit)
        return self._default

    def search(self, target: ResolvedTarget, limit: int | None = None) -> list[CandidateSource]:
        # Only search_aliases leave the machine: target.aliases (and the canonical target.name of an
        # entity) may come from internal documents. A target without search_aliases searches its name.
        max_results = self._effective_max_results(limit)
        names = (target.search_aliases or [target.name])[: self._max_queries]
        # Each alias asks for a share of the budget (at least MIN_PER_ALIAS, never more than the whole
        # budget): a per-alias "find up to max_docs" makes the web-search tool run far too many internal
        # searches and stall. The union across aliases still fills the budget, de-duped and trimmed below.
        per_alias = min(max_results, max(MIN_PER_ALIAS, -(-max_results // len(names))))
        seen: set[str] = set()
        candidates: list[CandidateSource] = []
        fatal: LLMError | None = None
        # The alias searches are independent, so run them concurrently: N aliases cost roughly one
        # search of wall-clock instead of N in series. Results are merged in submission (alias) order,
        # so the most-canonical name still takes priority on a de-dup tie.
        with ThreadPoolExecutor(max_workers=len(names)) as pool:
            jobs = [(name, pool.submit(self._search_one, name, names, per_alias)) for name in names]
            for name, future in jobs:
                try:
                    found = future.result()
                except (RateLimited, LLMUnavailable) as exc:
                    fatal = fatal or exc  # fatal for the run: let the pipeline pause / report it
                    continue
                except LLMError as exc:
                    # A bad response for one alias must not discard the others' results.
                    _log.warning("web search for alias %r failed, skipping: %s", name, exc)
                    continue
                for candidate in found:
                    try:
                        key = canonicalize_url(candidate.url)
                    except ValueError:
                        continue
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append(candidate)
        if fatal is not None:
            raise fatal
        return candidates[:max_results]

    def _search_one(self, name: str, names: list[str], max_results: int) -> list[CandidateSource]:
        """Run a single web search centred on one alias. Returns raw candidates (cleaned of
        non-HTTP and unparseable URLs); the caller de-duplicates across aliases."""
        content = (
            f"Threat: {name}\n"
            f"Known aliases: {', '.join(names)}\n"
            f"Find up to {max_results} primary sources about this threat. "
            "Search specifically for this name."
        )
        # One bad JSON from WebSearch used to kill the whole collect pass; Triage and Analyst
        # both wrap through `complete_json_with_retries` for the same reason.
        response = complete_json_with_retries(
            self._llm,
            LLMRequest(
                system=SYSTEM_PROMPT, content=content,
                prompt_version=WEB_SEARCH_PROMPT_VERSION, tools=["WebSearch"],
            ),
            SearchResults,
            max_retries=2,
        )
        out: list[CandidateSource] = []
        for result in response.output.results:
            if not result.url.lower().startswith(("http://", "https://")):
                continue
            try:
                canonicalize_url(result.url)  # validate; the caller keys the global de-dup off this
            except ValueError:
                continue
            try:
                publisher = result.publisher.strip() or domain_of(result.url)
            except ValueError:
                publisher = result.publisher.strip() or ""
            out.append(CandidateSource(
                url=result.url,
                title=result.title or None,
                publisher=publisher,
                published_at=parse_loose_date(result.published_at),
            ))
        return out
