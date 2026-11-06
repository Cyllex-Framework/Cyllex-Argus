"""Investigation orchestration: Collector -> triage -> Analyst -> Validator, resumable."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from cyllex_argus.attack.catalog import AttackCatalog
from cyllex_argus.config.settings import ArgusConfig, Paths
from cyllex_argus.documents.extract import (
    ExtractionError,
    canonicalize_url,
    content_hash,
    domain_of,
    extract,
)
from cyllex_argus.documents.fetch import Fetcher, FetchError, wayback_url_for
from cyllex_argus.exporters.summary import (
    SUMMARY_PROMPT_VERSION,
    profile_fingerprint,
    summarize_profile_detailed,
)
from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Document,
    Investigation,
    InvestigationState,
    NewDocument,
    Publisher,
    Stage,
)
from cyllex_argus.knowledge.names import normalize_name
from cyllex_argus.knowledge.profile import build_profile
from cyllex_argus.knowledge.publisher_identity import organisation_key
from cyllex_argus.knowledge.publisher_ratings import known_rating
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.knowledge.trace import NullRecorder, PipelineEvent, TraceRecorder
from cyllex_argus.llm.base import InvalidOutput, LLMProvider, LLMRefused, LLMUnavailable, RateLimited
from cyllex_argus.pipeline.analyst import ANALYST_PROMPT_VERSION, analyze_document
from cyllex_argus.pipeline.triage import triage
from cyllex_argus.pipeline.validator import ValidationSummary, Validator
from cyllex_argus.sources.base import CandidateSource, ResolvedTarget, SourceConnector

INTERNAL_PUBLISHER = "Internal documents"


def _unexpected(exc: Exception) -> str:
    return f"unexpected error: {type(exc).__name__}: {exc}"


def _refusal_reason(exc: LLMRefused) -> str:
    """Operator-facing reason for a model safety refusal, naming the policy category and the fix
    (switch to a model the classifier does not block). Kept distinct from a generic failure so the
    trace/dashboard can label it and the operator knows it is not a bug in Argus."""
    category = exc.category or "unspecified"
    return (
        f"Blocked by the model's safety policy ({category}). "
        "Try a different model (e.g. Opus 4.6 or Haiku 5.5); set [llm.agents.ttps] / "
        "[llm.agents.analyst] in argus.toml."
    )


def _single_capitalized_tokens(target: str) -> list[str]:
    """Pull out every capitalized token of length >=3 from `target`, preserving order and
    dropping duplicates. Used only to probe `find_by_alias`, never surfaced as a triage
    alias (that would false-match any Microsoft blog). Length>=3 drops English stop
    tokens like 'A'; MITRE group aliases are almost all 4+ chars ("APT29", "NOBELIUM",
    "Lazarus") and the rare 3-char ones ("SVR") are proper nouns worth trying."""
    seen: set[str] = set()
    out: list[str] = []
    for token in target.split():
        head = token[:1]
        if len(token) >= 3 and head.isupper() and head.isalpha() and token not in seen:
            seen.add(token)
            out.append(token)
    return out


_STOP_PREFIX = frozenset({"the", "a", "an"})  # English articles are capitalized at a sentence
# start but are never the first word of a threat group's name; dropping two-word runs that
# begin with one of these avoids "The Microsoft" matching every Microsoft blog.


# Shallow-text thresholds for the "JS-rendered page" rescue. A publisher that serves a
# 50 KB HTML shell with only 500 chars of extracted text is almost certainly rendering
# the real article in JavaScript after page load — Argus's static extractor gets just the
# nav/boilerplate. Both signals must fire together so a legitimately short advisory
# (e.g. a 2 KB CISA alert) does not falsely trigger a Wayback round-trip. Numbers tuned
# against the MSRC blog Jan 2024 postmortem: 50 KB HTML, 1185 chars text, 2.4% ratio.
_SHALLOW_TEXT_MAX_CHARS = 1500
_SHALLOW_TEXT_MIN_BYTES = 10_000
_SHALLOW_TEXT_MAX_RATIO = 0.05


def _looks_shallow(fetched_bytes: int, extracted_chars: int) -> bool:
    """True when the extracted text looks like nav/boilerplate only — the publisher served
    a big HTML shell but the article content isn't in it (classic JS-rendered SPA shape)."""
    if extracted_chars >= _SHALLOW_TEXT_MAX_CHARS:
        return False
    if fetched_bytes < _SHALLOW_TEXT_MIN_BYTES:
        return False  # legitimately short publishers (CISA alerts, PDF-light) stay fine
    return extracted_chars / fetched_bytes < _SHALLOW_TEXT_MAX_RATIO


def _candidate_aliases(target: str) -> list[str]:
    """Build the triage alias list for a brand-new target. Returns the original string plus
    every maximal run of 2+ consecutive capitalized words AND every adjacent two-word subrun
    inside it — threat group names ("Midnight Blizzard", "Scattered Spider", "Cozy Bear")
    fit that shape, so extracting them lets triage match documents that mention the group
    without the exact query phrase.

    Deliberately conservative: single capitalized words ("Microsoft", "January") would cause
    false positives against unrelated articles. All-caps acronyms inside a run ("APT29",
    "SVR", "RDP") pass through unchanged. English articles ("The", "A", "An") at the start
    of a two-word phrase are rejected because they lead to broad false matches.
    """
    original = target.strip()
    aliases: list[str] = [original] if original else []
    tokens = target.split()
    run: list[str] = []

    def _emit(run: list[str]) -> None:
        if len(run) < 2:
            return
        if run[0].lower() not in _STOP_PREFIX:
            aliases.append(" ".join(run))
        # Also emit every adjacent 2-word subrun so a 3+ word proper-noun phrase surfaces
        # its likely group-name chunks ("Midnight Blizzard" out of "Midnight Blizzard
        # Microsoft January"). A two-word run has no proper subrun — the full run is it.
        if len(run) > 2:
            for i in range(len(run) - 1):
                if run[i].lower() in _STOP_PREFIX:
                    continue
                aliases.append(f"{run[i]} {run[i + 1]}")

    for token in tokens:
        # A "capitalized" token: starts with an ASCII uppercase letter. All-caps acronyms
        # qualify. Numbers, lowercase words, and punctuation-only tokens break the run.
        head = token[:1]
        if head.isupper() and head.isalpha():
            run.append(token)
            continue
        _emit(run)
        run = []
    _emit(run)
    # Preserve order, drop duplicates (the original and an extracted run can coincide).
    seen: set[str] = set()
    deduped: list[str] = []
    for alias in aliases:
        if alias and alias not in seen:
            seen.add(alias)
            deduped.append(alias)
    return deduped


def _order_candidates(candidates: list, prefer_recent: bool) -> list:
    """Candidate ordering just before the `max_docs` cut. By default the per-connector order is
    kept (each connector already yields its own results newest-first). A scheduled watcher run
    passes `prefer_recent=True` to globally re-sort by publish date, so the newest material
    across all connectors wins the slots — the point of a watcher is to catch what is new."""
    if not prefer_recent:
        return candidates
    return sorted(candidates, key=lambda c: c.published_at or date.min, reverse=True)


class InvestigationCancelled(Exception):
    """Raised by `_run_pending` when the operator asks to stop the run between docs.

    `_run_investigation` catches it, marks the investigation PAUSED, and returns a report
    with a message that the UI surfaces as 'Stopped by operator'. A later Resume picks up
    exactly where this left off, exactly as a RateLimited-driven pause would."""


def _needs_processing(document: Document) -> bool:
    """False for documents that are finished: failed, irrelevant, or validated by the current prompt."""
    if document.stage in (Stage.FAILED, Stage.IRRELEVANT):
        return False
    return not (document.stage is Stage.VALIDATED and document.analyzed_prompt_version == ANALYST_PROMPT_VERSION)


@dataclass
class InvestigationReport:
    investigation_id: int
    target: str
    state: InvestigationState
    stage_counts: dict[str, int] = field(default_factory=dict)
    claims_accepted: int = 0
    claims_rejected: int = 0
    message: str | None = None


class Pipeline:
    def __init__(
        self,
        store: SQLiteStore,
        config: ArgusConfig,
        paths: Paths,
        llm: LLMProvider,
        fetcher: Fetcher,
        connectors: list[SourceConnector],
        catalog: AttackCatalog,
        trace: TraceRecorder | None = None,
        log: Callable[[str], None] = lambda message: None,
        today: Callable[[], date] = date.today,
        enrichment_factory=None,
        webhook_dispatcher=None,
    ) -> None:
        self._store = store
        self._config = config
        self._paths = paths
        self._llm = llm
        self._fetcher = fetcher
        self._connectors = connectors
        self._trace = trace if trace is not None else NullRecorder()
        self._log = log
        self._webhook_dispatcher = webhook_dispatcher
        self.validator = Validator(
            store, catalog, config.scoring, today,
            enrichment_factory=enrichment_factory,
        )

    # -- public API ----------------------------------------------------------------

    def resolve_target(self, target: str) -> ResolvedTarget:
        name = target.strip()
        entity = self._store.find_by_alias(name)
        if entity is None:
            # First-time target: the full phrase doesn't name a known entity, so try to
            # recognise one inside it. Operators type search-engine-style queries ("APT29
            # Microsoft corporate email breach 2024" / "Midnight Blizzard Microsoft January
            # 2024 OAuth"); any 2+ capitalized-word run or any capitalized word inside such
            # a query might be a MITRE alias we already have in the store. If one of those
            # resolves to an entity, we lift that entity's full MITRE alias set — "APT29"
            # alone pulls in "Midnight Blizzard", "NOBELIUM", "Cozy Bear", "The Dukes" and
            # everything else G0016 ships with, and the triage stops dropping docs for
            # using one of the other brand names. If nothing in the string resolves, we
            # fall back to the extracted phrases themselves so the whole-query failure mode
            # is at worst no worse than typing a plain phrase.
            candidates = _candidate_aliases(name)
            resolved = None
            for phrase in [*candidates, *_single_capitalized_tokens(name)]:
                hit = self._store.find_by_alias(phrase)
                if hit is not None:
                    resolved = hit
                    break
            if resolved is not None:
                entity = resolved
            else:
                return ResolvedTarget(
                    name=name, entity_id=None,
                    aliases=candidates, search_aliases=[name],
                )
        aliases = sorted(set(self._store.aliases_for(entity.id)) | {entity.canonical_name}, key=str.casefold)
        # Names that may leave the machine in a web search: ATT&CK and user aliases only. A name learned
        # from a document (possibly an internal codename) never does, even when it is the canonical name;
        # then the web search looks for what the user typed instead.
        public = {
            normalize_name(alias): alias
            for alias in self._store.aliases_for(entity.id, origins=(AliasOrigin.ATTACK, AliasOrigin.USER))
        }
        primary = entity.canonical_name if normalize_name(entity.canonical_name) in public else name
        others = sorted(
            (alias for key, alias in public.items() if key != normalize_name(primary)), key=str.casefold
        )
        return ResolvedTarget(
            name=entity.canonical_name, entity_id=entity.id, aliases=aliases, search_aliases=[primary, *others],
        )

    def investigate(
        self, target: str, max_docs: int | None = None, concurrency: int = 1, *,
        created_by: int | None = None, prefer_recent: bool = False,
    ) -> InvestigationReport:
        resolved = self.resolve_target(target)
        investigation = self._store.open_investigation(target) or self._store.create_investigation(
            target, resolved.entity_id, created_by=created_by,
        )
        return self._run_investigation(
            investigation, resolved, target, max_docs, concurrency, prefer_recent=prefer_recent,
        )

    def ingest(
        self, files: list[Path], target: str | None = None, *, created_by: int | None = None,
    ) -> InvestigationReport:
        resolved = self.resolve_target(target) if target else None
        label = f"ingest: {target}" if target else "ingest: all"
        investigation = self._store.create_investigation(
            label, resolved.entity_id if resolved else None, created_by=created_by,
        )
        for path in files:
            started = time.perf_counter()
            document = self._ingest_file(path)
            self._store.link_document(investigation.id, document.id)
            self._record_collected(investigation.id, document, started)
        self._store.mark_collected(investigation.id)
        summary = ValidationSummary()
        try:
            self._process_all(investigation.id, resolved, summary)
        except InvestigationCancelled:
            return self._cancelled(investigation.id, label, summary)
        except RateLimited as exc:
            return self._pause(investigation.id, label, summary, exc)
        self._summarize_on_finish(investigation.id)
        self._store.set_investigation_state(investigation.id, InvestigationState.FINISHED)
        return self._report(investigation.id, label, InvestigationState.FINISHED, summary)

    def retry_document(self, document_id: int, user_agent: str | None = None) -> dict:
        """Give a single failed document another chance.

        Two shapes of failure are handled:

        - **Processing failure** (the document has text but its stage is FAILED — triage,
          analyst or validator raised an error). Reset the stage to COLLECTED and re-run
          the per-document pipeline. No network. This is the common 'retry when the LLM
          temporarily rate-limited us' case.
        - **Collection failure** (no text; URL fetch 403/404/timeout). Re-fetch via the
          existing Fetcher, replace the document's text and raw_path, then process. One
          network call to the original URL; if the server still refuses we leave the doc
          FAILED with the fresh reason.

        A document that is not FAILED is left untouched (the caller is likely confused —
        a validated doc has nothing to retry); the return value says so.

        `user_agent`, when given, overrides the default CyllexArgus UA for the re-fetch —
        a last resort for publishers (CISA, Trellix, …) that block anything non-browser-
        shaped. The override is per-call and does not change the global default.

        The target for triage/analyst is pulled from the newest investigation this document
        is linked to; a document ingested outside any investigation is re-processed without a
        target (same semantics as `argus ingest` with no `--target`).
        """
        document = self._store.get_document(document_id)
        if document.stage is not Stage.FAILED:
            return {"status": "skipped", "stage": document.stage.value,
                    "message": f"document {document_id} is not failed (stage={document.stage.value})"}

        if not document.text and document.url:
            label = "with browser UA" if user_agent else "with default UA"
            self._log(f"Re-fetching failed document {document_id} {label}: {document.url}")
            try:
                fetched = self._fetcher.fetch(document.url, user_agent=user_agent)
                extracted = extract(fetched.content, fetched.content_type, document.url)
                fetched, extracted = self._rescue_shallow_text(document.url, fetched, extracted)
            except (FetchError, ExtractionError) as exc:
                reason = f"re-fetch: {exc}"
                self._store.set_stage(document_id, Stage.FAILED, reason)
                return {"status": "fetch-failed", "stage": "failed", "message": reason}
            digest = content_hash(fetched.content)
            raw_path = self._write_raw(digest, fetched.content)
            # update_document_content reuses the slot the failed row occupied, preserving
            # the document id (and therefore all the investigation_documents links) — UNLESS
            # this exact content already belongs to another document, in which case it changes
            # nothing and returns that other row. See `_already_stored`.
            stored = self._store.update_document_content(document_id, NewDocument(
                url=document.url, canonical_url=document.canonical_url,
                title=extracted.title or document.title,
                publisher_id=document.publisher_id,
                published_at=extracted.published_at or document.published_at,
                content_hash=digest, raw_path=str(raw_path), text=extracted.text,
            ))
            duplicate = self._already_stored(document_id, stored, "re-fetch")
            if duplicate is not None:
                return duplicate

        return self._reprocess_document(document_id)

    def supply_document(self, document_id: int, content: bytes, filename: str) -> dict:
        """Replace a failed document's body with a file the operator supplied, then process it.

        The counterpart to `retry_document` for refusals that will not go away: a publisher's
        access policy, a page behind a login, a host that times out. The operator opens it in
        their own browser, saves it, and hands over the file.

        The document row is REUSED (`update_document_content`), so the id, the URL, the
        publisher and every `investigation_documents` link survive. That is the point: the
        dossier's evidence base counts documents per investigation, so a hand-supplied document
        closes the gap instead of appearing as an unrelated record next to it.

        A file that cannot be parsed leaves the document FAILED with that as the new reason —
        the operator needs to know their PDF was the problem, not the publisher.
        """
        document = self._store.get_document(document_id)
        if document.stage is not Stage.FAILED:
            return {"status": "skipped", "stage": document.stage.value,
                    "message": f"document {document_id} is not failed (stage={document.stage.value})"}
        self._log(f"Supplying document {document_id} from {filename!r} ({len(content)} bytes)")
        try:
            extracted = extract(content, None, filename)
        except ExtractionError as exc:
            reason = f"supplied file {filename!r}: {exc}"
            self._store.set_stage(document_id, Stage.FAILED, reason)
            return {"status": "extract-failed", "stage": "failed", "message": reason}
        digest = content_hash(content)
        raw_path = self._write_raw(digest, content)
        stored = self._store.update_document_content(document_id, NewDocument(
            url=document.url, canonical_url=document.canonical_url,
            title=extracted.title or document.title,
            publisher_id=document.publisher_id,
            published_at=extracted.published_at or document.published_at,
            content_hash=digest, raw_path=str(raw_path), text=extracted.text,
        ))
        duplicate = self._already_stored(document_id, stored, f"supplied file {filename!r}")
        if duplicate is not None:
            return duplicate
        return self._reprocess_document(document_id)

    def _already_stored(self, document_id: int, stored: Document, source: str) -> dict | None:
        """None when the content landed on this document; a result to return when it did not.

        `update_document_content` is a no-op that returns the OTHER document when the content
        hash already exists — `documents.content_hash` is UNIQUE, and the same report served at
        two URLs, or re-uploaded after a refused attempt, hits it. Carrying on would reset this
        still-empty row to COLLECTED, run the Analyst over no text, report success, spend the
        operator's tokens, and erase the failure reason they needed. So it stops, names the
        document that already holds the content, and leaves this row failed with a reason that
        is true.
        """
        if stored.id == document_id:
            return None
        reason = f"{source}: this content is already stored as document #{stored.id}"
        self._store.set_stage(document_id, Stage.FAILED, reason)
        self._log(reason)
        return {"status": "duplicate", "stage": "failed", "message": reason,
                "duplicate_of": stored.id}

    def _reprocess_document(self, document_id: int) -> dict:
        """Run triage/analyst/validator over a document whose body is now in place.

        Shared by `retry_document` and `supply_document`: once the bytes exist, where they came
        from makes no difference to the pipeline. The target comes from the newest investigation
        this document is linked to, so a hand-supplied document is analysed for the same threat
        the run that collected it was about.
        """
        self._store.set_stage(document_id, Stage.COLLECTED, None)
        document = self._store.get_document(document_id)

        investigation_ids = self._store.investigations_for_document(document_id)
        investigation_id = investigation_ids[0] if investigation_ids else 0
        target = None
        if investigation_id:
            try:
                investigation = self._store.get_investigation(investigation_id)
                if investigation.target and not investigation.target.startswith("ingest:"):
                    target = self.resolve_target(investigation.target)
            except Exception as exc:  # noqa: BLE001 — target resolution is best-effort for a retry
                self._log(f"Target resolution failed ({exc}); processing without target")
                target = None

        summary = ValidationSummary()
        self._process(investigation_id, document, target, summary)
        fresh = self._store.get_document(document_id)
        return {
            "status": "finished",
            "stage": fresh.stage.value,
            "message": fresh.failure_reason,
            "claims_accepted": summary.accepted,
            "claims_rejected": summary.rejected,
        }

    def resume(
        self, investigation_id: int, force: bool = False, concurrency: int = 1,
    ) -> InvestigationReport:
        """Continue a paused or interrupted investigation or ingest. Raises KeyError for an unknown id.

        `force=True` runs the processing even when the investigation is already FINISHED.
        Useful after the Analyst prompt version bumps: `_needs_processing` already compares
        prompt versions, so a forced resume re-analyses the stored VALIDATED docs with the
        new prompt. FAILED and IRRELEVANT docs still stay as they are — the retry endpoint
        is the path for those.
        """
        investigation = self._store.get_investigation(investigation_id)
        label = investigation.target
        if investigation.state is InvestigationState.FINISHED and not force:
            return self._report(investigation.id, label, InvestigationState.FINISHED, ValidationSummary(),
                                "Investigation already finished.")
        if investigation.state is InvestigationState.FINISHED:
            # Forced path: flip state so `_run_investigation` / `_process_all` take the normal
            # route; the finally-set state at the end rebalances it to FINISHED again.
            self._store.set_investigation_state(investigation_id, InvestigationState.RUNNING)
            investigation = self._store.get_investigation(investigation_id)
        if not label.startswith("ingest: "):
            return self._run_investigation(investigation, self.resolve_target(label), label, None, concurrency)
        name = label.removeprefix("ingest: ")
        resolved = None if name == "all" else self.resolve_target(name)
        self._store.set_investigation_state(investigation.id, InvestigationState.RUNNING)
        summary = ValidationSummary()
        try:
            self._process_all(investigation.id, resolved, summary, concurrency=concurrency)
        except InvestigationCancelled:
            return self._cancelled(investigation.id, label, summary)
        except RateLimited as exc:
            return self._pause(investigation.id, label, summary, exc)
        self._summarize_on_finish(investigation.id)
        self._store.set_investigation_state(investigation.id, InvestigationState.FINISHED)
        return self._report(investigation.id, label, InvestigationState.FINISHED, summary)

    def _run_investigation(
        self, investigation: Investigation, resolved: ResolvedTarget, label: str, max_docs: int | None,
        concurrency: int = 1, *, prefer_recent: bool = False,
    ) -> InvestigationReport:
        """Collect (unless already done) and process the given investigation row, whichever row that is."""
        self._store.set_investigation_state(investigation.id, InvestigationState.RUNNING)
        summary = ValidationSummary()
        try:
            if not investigation.collected:
                limit = max_docs if max_docs is not None else self._config.limits.max_docs
                self._collect(investigation.id, resolved, limit, prefer_recent=prefer_recent)
                self._store.mark_collected(investigation.id)
            self._process_all(investigation.id, resolved, summary, concurrency=concurrency)
        except InvestigationCancelled:
            return self._cancelled(investigation.id, label, summary)
        except RateLimited as exc:
            return self._pause(investigation.id, label, summary, exc)
        # If the target was unknown when this run started but an alias was learned during the run, resolve it
        # now and attach the entity id — otherwise the dashboard keeps saying "Resolving target…" forever.
        if investigation.resolved_entity_id is None:
            fresh = self.resolve_target(label)
            if fresh.entity_id is not None:
                self._store.set_investigation_resolved_entity(investigation.id, fresh.entity_id)
        self._summarize_on_finish(investigation.id)
        self._store.set_investigation_state(investigation.id, InvestigationState.FINISHED)
        return self._report(investigation.id, label, InvestigationState.FINISHED, summary)

    # -- collection ----------------------------------------------------------------

    def _collect(
        self, investigation_id: int, target: ResolvedTarget, max_docs: int, *, prefer_recent: bool = False,
    ) -> None:
        candidates: list[CandidateSource] = []
        seen: set[str] = set()
        for connector in self._connectors:
            try:
                found = connector.search(target, max_docs)
            except (RateLimited, LLMUnavailable):
                raise
            except Exception as exc:  # one broken source must not stop the investigation
                self._log(f"Source {connector.name} failed: {exc}")
                continue
            for candidate in sorted(found, key=lambda c: c.published_at or date.min, reverse=True):
                identity = self._identify(candidate.url)
                if identity is not None and identity[0] not in seen:
                    seen.add(identity[0])
                    candidates.append(candidate)
        selected = _order_candidates(candidates, prefer_recent)[:max_docs]
        dropped = f"; downloading the first {len(selected)}" if len(selected) < len(candidates) else ""
        self._log(f"Collected {len(candidates)} candidate(s){dropped}")
        # A re-investigation reuses documents a previous run already fetched (dedup by canonical
        # URL / content hash), so most candidates cost no network and no LLM the second time
        # round. Say so honestly: logging "Downloading" for a document we never fetch is a lie,
        # and the operator wants to see that re-running is incremental, not a full re-crawl.
        fetched = reused = failed = 0
        for index, candidate in enumerate(selected, start=1):
            identity = self._identify(candidate.url)
            prior = self._store.find_document_by_canonical_url(identity[0]) if identity else None
            is_reuse = prior is not None and prior.stage is not Stage.FAILED
            self._log(f"{'Reusing' if is_reuse else 'Downloading'} {index}/{len(selected)}: {candidate.url}")
            started = time.perf_counter()
            document = self._download(candidate)
            if document is not None:
                if document.stage is Stage.FAILED:
                    failed += 1
                elif is_reuse:
                    reused += 1
                else:
                    fetched += 1
                self._store.link_document(investigation_id, document.id)
                self._record_collected(investigation_id, document, started)
        if selected:
            self._log(f"Documents: {fetched} fetched, {reused} reused, {failed} failed")

    # -- trace ---------------------------------------------------------------------

    def _record(
        self, event: PipelineEvent, investigation_id: int, document_id: int | None = None,
        started: float | None = None,
    ) -> None:
        """Stamp a stage's event with where it happened (and how long the stage took), then record it."""
        update: dict = {"investigation_id": investigation_id, "document_id": document_id}
        if started is not None:
            update["duration_ms"] = round((time.perf_counter() - started) * 1000)
        self._trace.record(event.model_copy(update=update))

    def _record_collected(self, investigation_id: int, document: Document, started: float) -> None:
        failed = document.stage is Stage.FAILED
        self._record(
            PipelineEvent(
                investigation_id=investigation_id, stage="collector", decision="failed" if failed else "collected",
                reason=document.failure_reason if failed else document.title,
            ),
            investigation_id, document.id, started,
        )

    def _identify(self, url: str) -> tuple[str, str] | None:
        """Return the canonical URL and the domain, or None (and log) when the URL cannot be parsed."""
        try:
            return canonicalize_url(url), domain_of(url)
        except ValueError as exc:
            self._log(f"Skipping malformed URL: {url} ({exc})")
            return None

    def _download(self, candidate: CandidateSource) -> Document | None:
        identity = self._identify(candidate.url)
        if identity is None:
            return None
        canonical, domain = identity
        existing = self._store.find_document_by_canonical_url(canonical)
        if existing is not None and existing.stage is not Stage.FAILED:
            return existing  # already downloaded: no network needed
        publisher = self._publisher(candidate.publisher or domain, domain)
        try:
            fetched = self._fetcher.fetch(candidate.url)
            extracted = extract(fetched.content, fetched.content_type, candidate.url)
            fetched, extracted = self._rescue_shallow_text(candidate.url, fetched, extracted)
        except (FetchError, ExtractionError) as exc:
            return self._failed_download(candidate, canonical, publisher, existing, str(exc))
        except Exception as exc:  # last resort: one broken download must not stop the investigation
            return self._failed_download(candidate, canonical, publisher, existing, _unexpected(exc))
        digest = content_hash(fetched.content)
        raw_path = self._write_raw(digest, fetched.content)
        new = NewDocument(
            url=candidate.url, canonical_url=canonical,
            title=extracted.title or candidate.title or candidate.url,
            publisher_id=publisher.id, published_at=extracted.published_at or candidate.published_at,
            content_hash=digest, raw_path=str(raw_path), text=extracted.text,
        )
        if existing is not None:  # a previously failed download that now succeeded
            return self._store.update_document_content(existing.id, new)
        document, _ = self._store.add_document(new)
        return document

    def _rescue_shallow_text(self, url: str, fetched, extracted):
        """When the fetched page produced suspiciously little extracted text relative to its
        byte size, swap in the Wayback snapshot. Catches JS-rendered SPAs (MSRC blog, newer
        vendor pages) where Argus's static extractor pulls only the nav/boilerplate — the
        article itself gets rendered later by JavaScript Argus never runs. Wayback stores
        the FULLY-RENDERED page captured by its own crawler (which does run JS), so the
        snapshot almost always has the real body text.

        Only triggers when the heuristic in `_looks_shallow` says both signals fire: the
        page was heavy on the wire (>10 KB) but the extractor got <1500 chars of actual
        content, less than 5% of the bytes. Legitimately short publishers (CISA alerts,
        thin PDFs) stay below the byte threshold and this is a no-op for them.

        Returns the better (fetched, extracted) pair — original if the rescue didn't help,
        Wayback version if it produced more text. Any Wayback error is swallowed and the
        original (shallow) response propagates.
        """
        if url.startswith("https://web.archive.org/"):
            return fetched, extracted  # already a wayback hop; no recursion
        if not _looks_shallow(len(fetched.content), len(extracted.text or "")):
            return fetched, extracted
        try:
            wb_url = wayback_url_for(url)
            self._log(f"Shallow text ({len(extracted.text or '')} chars from "
                      f"{len(fetched.content)} B) — trying Wayback for {url}")
            wb_fetched = self._fetcher.fetch(wb_url)
            wb_extracted = extract(wb_fetched.content, wb_fetched.content_type, url)
        except (FetchError, ExtractionError) as exc:
            self._log(f"Wayback shallow-rescue failed for {url}: {exc}")
            return fetched, extracted
        if len(wb_extracted.text or "") <= len(extracted.text or ""):
            return fetched, extracted  # Wayback didn't help; keep original
        self._log(f"Wayback shallow-rescue picked up {len(wb_extracted.text)} chars for {url}")
        return wb_fetched, wb_extracted

    def _failed_download(
        self, candidate: CandidateSource, canonical: str, publisher: Publisher, existing: Document | None,
        reason: str,
    ) -> Document:
        if existing is not None:  # a document that failed before failed again
            self._store.set_stage(existing.id, Stage.FAILED, reason)
            return self._store.get_document(existing.id)
        failed = NewDocument(
            url=candidate.url, canonical_url=canonical, title=candidate.title or candidate.url,
            publisher_id=publisher.id, published_at=candidate.published_at,
            content_hash="failed:" + content_hash(canonical.encode()), raw_path="", text="",
        )
        document, _ = self._store.add_document(failed, stage=Stage.FAILED, failure_reason=reason)
        return document

    def _ingest_file(self, path: Path) -> Document:
        publisher = self._publisher(INTERNAL_PUBLISHER)
        resolved = str(path.resolve())
        try:
            data = path.read_bytes()
        except OSError as exc:
            unreadable = NewDocument(
                local_path=resolved, title=path.name, publisher_id=publisher.id,
                content_hash="failed:" + content_hash(resolved.encode()), raw_path="", text="",
            )
            document, _ = self._store.add_document(unreadable, stage=Stage.FAILED, failure_reason=str(exc))
            return document
        digest = content_hash(data)
        try:
            extracted = extract(data, None, path.name)
        except ExtractionError as exc:
            failed = NewDocument(
                local_path=resolved, title=path.name, publisher_id=publisher.id,
                content_hash=digest, raw_path="", text="",
            )
            document, _ = self._store.add_document(failed, stage=Stage.FAILED, failure_reason=str(exc))
            return document
        raw_path = self._write_raw(digest, data)
        document, _ = self._store.add_document(NewDocument(
            local_path=resolved, title=extracted.title, publisher_id=publisher.id,
            published_at=extracted.published_at, content_hash=digest, raw_path=str(raw_path),
            text=extracted.text,
        ))
        return document

    def _write_raw(self, digest: str, data: bytes) -> Path:
        raw_path = self._paths.raw_dir / digest
        if not raw_path.exists():
            temporary = raw_path.with_suffix(".tmp")
            temporary.write_bytes(data)
            os.replace(temporary, raw_path)  # atomic: an interrupted write never leaves a truncated file
        return raw_path

    def _publisher(self, name: str, domain: str | None = None) -> Publisher:
        """Resolve the publisher, with a starting Admiralty grade if anyone can give it one.

        Precedence, weakest to strongest: F (nobody has judged this source), the shipped table
        for organisations with an established track record, then the operator's own
        `config.publishers`. Only `default_reliability` is affected — a grade already on the row,
        set by `argus sources set-reliability`, is never touched.

        F is not a neutral default: it is the floor `scoring.score` multiplies evidence by, so
        leaving a national CERT there suppresses the confidence of everything it reports.
        """
        known = known_rating(organisation_key(domain))
        reliability = known.reliability if known else "F"
        for configured, value in self._config.publishers.items():
            if normalize_name(configured) == normalize_name(name):
                reliability = value
        return self._store.get_or_create_publisher(name, domain, default_reliability=reliability)

    # -- processing ----------------------------------------------------------------

    def _process_all(
        self, investigation_id: int, target: ResolvedTarget | None, summary: ValidationSummary,
        concurrency: int = 1,
    ) -> None:
        """Run Triage+Analyst on every pending document. With `concurrency > 1`, N docs run in
        parallel on a ThreadPoolExecutor — each doc is independent at this layer, so order has
        no effect on the output. The Validator writes land in SQLite WAL mode which serialises
        writers internally, so the result is identical to the sequential case."""
        pending = [d for d in self._store.investigation_documents(investigation_id) if _needs_processing(d)]
        self._run_pending(investigation_id, pending, target, summary, concurrency=concurrency,
                          label_fmt="Analyzing")
        # Second pass: triage once more the docs that were ruled irrelevant with the fresh alias set, in case
        # a later document taught us an alias that would now mark them as on-topic.
        if target is not None and target.entity_id:
            retriable = [
                d for d in self._store.investigation_documents(investigation_id) if d.stage is Stage.IRRELEVANT
            ]
            if retriable:
                fresh = self.resolve_target(target.name)
                if set(fresh.aliases) != set(target.aliases):
                    for document in retriable:
                        self._store.set_stage(document.id, Stage.COLLECTED)
                    self._run_pending(investigation_id, retriable, fresh, summary,
                                      concurrency=concurrency,
                                      label_fmt="Re-triage with updated aliases")

    def _run_pending(
        self, investigation_id: int, pending: list[Document], target: ResolvedTarget | None,
        summary: ValidationSummary, *, concurrency: int, label_fmt: str,
    ) -> None:
        """Shared body for the first-pass and the re-triage pass. `concurrency > 1` runs
        docs on a `ThreadPoolExecutor`: each Analyst call is a `claude -p` subprocess that
        blocks on I/O (the GIL is released during that wait), and the SQLite writes under
        the Validator are serialised by the store's `_LockedConnection` wrapper so they do
        not step on each other. Each doc is independent at this layer, so the output of a
        parallel run is identical to the sequential run.
        """
        if not pending:
            return
        count = len(pending)
        if concurrency <= 1 or count == 1:
            for index, document in enumerate(pending, start=1):
                if self._store.is_investigation_cancel_requested(investigation_id):
                    self._log("Stop requested; halting the run cleanly.")
                    raise InvestigationCancelled()
                self._log(f"{label_fmt} {index}/{count}: {document.title}")
                fresh = self.resolve_target(target.name) if target is not None and target.entity_id else target
                self._process(investigation_id, document, fresh, summary)
            return
        # Parallel path. Resolve the target once up front: the per-doc re-resolve of the
        # sequential path only widens aliases, which with concurrent docs is a nice-to-have
        # we can skip to keep the shared state simple. The ThreadPool is sized to the smaller
        # of the requested concurrency and the pending count, so N=16 against 3 docs does not
        # spin up 13 idle threads.
        from concurrent.futures import ThreadPoolExecutor, as_completed
        fresh = self.resolve_target(target.name) if target is not None and target.entity_id else target
        # The sequential path logs BEFORE processing each doc; the parallel path used to only log
        # on COMPLETION, which hid the in-flight picture (operator sees "4/10 done" without
        # knowing which docs the workers are currently chewing on). Wrap `_process` with a
        # start-log so the live-tree picture matches both execution modes.
        started = [0]  # mutable sentinel for the start counter; threads share it under the GIL
        started_lock = threading.Lock()

        def _wrapped(doc: Document) -> None:
            with started_lock:
                started[0] += 1
                index = started[0]
            self._log(f"{label_fmt} {index}/{count} (started): {doc.title}")
            self._process(investigation_id, doc, fresh, summary)

        with ThreadPoolExecutor(max_workers=min(concurrency, count)) as pool:
            futures = {
                pool.submit(_wrapped, document): document
                for document in pending
            }
            done = 0
            for future in as_completed(futures):
                done += 1
                document = futures[future]
                self._log(f"{label_fmt} {done}/{count} (finished): {document.title}")
                future.result()  # re-raise RateLimited / LLMUnavailable so the run pauses
                # After each worker finishes, check the cancel flag. We cannot preempt the
                # in-flight workers (Python threads do not accept external cancel), so the
                # remaining ones in `futures` keep running until completion — but no new
                # work is dispatched. In practice the pool drains in a doc or two.
                if self._store.is_investigation_cancel_requested(investigation_id):
                    self._log("Stop requested; letting in-flight workers finish, then halting.")
                    # Drain the rest of the futures so we don't lose their claims.
                    for remaining in as_completed(set(futures.keys()) - {future}):
                        try:
                            remaining.result()
                        except Exception:  # noqa: BLE001
                            pass  # already recorded by `_process`
                    raise InvestigationCancelled()

    def _process(
        self, investigation_id: int, document: Document, target: ResolvedTarget | None,
        summary: ValidationSummary,
    ) -> None:
        # Mark the doc as "in flight" so the live-tree UI can tell the operator which
        # documents the parallel workers are currently chewing on (vs the ones still
        # queued). The event is purely a UI signal; the terminal event (analyzed /
        # validated / failed / triaged-out) comes later in the same stage emission.
        # `investigation_id == 0` means the pipeline is running outside an investigation
        # (standalone `retry_document` after an ad-hoc ingest, mainly); the live-tree does
        # not render those anyway, and the pipeline_events FK rejects investigation_id=0.
        if investigation_id:
            self._record(
                PipelineEvent(investigation_id=investigation_id, stage="pipeline", decision="started"),
                investigation_id, document.id,
            )
        try:
            self._triage_and_analyze(investigation_id, document, target, summary)
        except (RateLimited, LLMUnavailable):
            raise
        except Exception as exc:  # last resort: one broken document must not abort the run
            try:
                self.validator.reset_document(document.id)  # drop claims a half-finished validation left
            except Exception:
                pass  # the original error is the one worth reporting
            reason = _unexpected(exc)
            self._store.set_stage(document.id, Stage.FAILED, reason)
            self._record(
                PipelineEvent(investigation_id=investigation_id, stage="pipeline", decision="failed", reason=reason),
                investigation_id, document.id,
            )

    def _triage_and_analyze(
        self, investigation_id: int, document: Document, target: ResolvedTarget | None, summary: ValidationSummary
    ) -> None:
        if not _needs_processing(document):
            return
        if document.stage is Stage.COLLECTED:
            started = time.perf_counter()
            try:
                if target is None:
                    relevant = True
                    event = PipelineEvent(
                        investigation_id=investigation_id, stage="triage", decision="triaged-in",
                        reason="no target: triage skipped",
                    )
                else:
                    relevant, event = triage(document.title, document.text, target.aliases, self._llm)
            except LLMRefused as exc:
                reason = _refusal_reason(exc)
                self._store.set_stage(document.id, Stage.FAILED, f"triage: {reason}")
                self._record(
                    PipelineEvent(investigation_id=investigation_id, stage="triage", decision="refused", reason=reason),
                    investigation_id, document.id, started,
                )
                return
            except InvalidOutput as exc:
                self._store.set_stage(document.id, Stage.FAILED, f"triage: {exc}")
                self._record(
                    PipelineEvent(investigation_id=investigation_id, stage="triage", decision="failed", reason=str(exc)),
                    investigation_id, document.id, started,
                )
                return
            self._record(event, investigation_id, document.id, started)
            if not relevant:
                self._log(f"Irrelevant: {document.title}")
                self._store.set_stage(document.id, Stage.IRRELEVANT)
                return
            self._store.set_stage(document.id, Stage.TRIAGED)

        self.validator.reset_document(document.id)
        publisher = self._store.get_publisher(document.publisher_id)
        limits = self._config.limits
        started = time.perf_counter()
        try:
            result, analyst_event = analyze_document(
                document.title, publisher.name, document.text, target, self._llm,
                limits.chunk_chars, max_chunks=limits.max_chunks_per_document,
            )
        except LLMRefused as exc:
            reason = _refusal_reason(exc)
            self._store.set_stage(document.id, Stage.FAILED, f"analyst: {reason}")
            self._record(
                PipelineEvent(investigation_id=investigation_id, stage="analyst", decision="refused", reason=reason),
                investigation_id, document.id, started,
            )
            return
        except InvalidOutput as exc:
            self._store.set_stage(document.id, Stage.FAILED, f"analyst: {exc}")
            self._record(
                PipelineEvent(investigation_id=investigation_id, stage="analyst", decision="failed", reason=str(exc)),
                investigation_id, document.id, started,
            )
            return
        self._record(analyst_event, investigation_id, document.id, started)
        if result.truncated_chunks:
            analyzed = limits.max_chunks_per_document
            self._log(
                f"Analyzed only the first {analyzed} of {analyzed + result.truncated_chunks} parts of {document.title}"
            )
        primary = self._publisher(result.primary_publisher)
        self._store.set_analysis(document.id, primary.id, ANALYST_PROMPT_VERSION)
        batch = self.validator.process(
            self._store.get_document(document.id), result.claims, ANALYST_PROMPT_VERSION, investigation_id)
        for event in batch.events:
            self._record(event, investigation_id, document.id)
        summary.merge(batch)
        self._store.set_stage(document.id, Stage.VALIDATED)

    # -- reporting -----------------------------------------------------------------

    def _pause(self, investigation_id: int, target: str, summary: ValidationSummary, exc: Exception) -> InvestigationReport:
        self._store.set_investigation_state(investigation_id, InvestigationState.PAUSED)
        return self._report(
            investigation_id, target, InvestigationState.PAUSED, summary,
            f"Paused: {exc}. Re-run the same command to resume.",
        )

    def _cancelled(self, investigation_id: int, target: str, summary: ValidationSummary) -> InvestigationReport:
        """Operator-initiated stop: mark PAUSED (so Resume continues) and surface a
        human-friendly message instead of the generic 'Paused: ...' from RateLimited."""
        # The investigation row may already be gone if the stop came from a DELETE; swallow
        # the KeyError and still return a report so the job handler reports a clean finish.
        try:
            self._store.set_investigation_state(investigation_id, InvestigationState.PAUSED)
        except Exception:  # noqa: BLE001 — the row vanished mid-stop; the report is cosmetic
            pass
        return self._report(
            investigation_id, target, InvestigationState.PAUSED, summary,
            "Stopped by operator. Use Resume to continue.",
        )

    def _summarize_on_finish(self, investigation_id: int) -> None:
        """Write the actor's executive summary as the last step of a finished run, so the
        dashboard answers "what did we learn?" the moment it opens instead of showing an
        empty card and a button.

        Failure-isolated for the same reason the webhook dispatch is: every fact this run
        produced is already on disk, and a provider that rate-limits on this one extra call
        must not turn a finished investigation into a failed one. A skipped summary is not
        hidden from the operator — the UI then offers "Write summary" explicitly.
        """
        if not self._config.pipeline.summary_on_finish:
            return
        try:
            entity_id = self._store.get_investigation(investigation_id).resolved_entity_id
            if entity_id is None:
                return  # target never resolved: there is no actor to summarize
            entity = self._store.get_entity(entity_id)
            if entity is None:
                return
            profile = build_profile(self._store, entity)
            if not profile.facts:
                return  # a run that accepted nothing has nothing to say
            text, usage = summarize_profile_detailed(profile, self._llm)
            self._store.save_entity_summary(
                entity_id=entity_id, summary=text, fingerprint=profile_fingerprint(profile),
                fact_count=len(profile.facts), prompt_version=SUMMARY_PROMPT_VERSION,
                model=usage.model if usage else None,
            )
            # The summary is a billable LLM call like any other stage; record it so its tokens and
            # cost land in the run's trace and the dashboard/`status` cost totals are complete.
            self._record(
                PipelineEvent(
                    investigation_id=investigation_id, stage="summary", decision="written",
                    reason=f"{len(profile.facts)} fact(s)", usage=usage,
                ),
                investigation_id,
            )
            self._log(f"Executive summary written for {entity.canonical_name}.")
        except Exception as exc:  # noqa: BLE001 — defensive: never let the summary break the run
            self._log(f"Executive summary skipped: {type(exc).__name__}: {exc}")

    def _report(
        self, investigation_id: int, target: str, state: InvestigationState,
        summary: ValidationSummary, message: str | None = None,
    ) -> InvestigationReport:
        report = InvestigationReport(
            investigation_id=investigation_id, target=target, state=state,
            stage_counts=self._store.stage_counts(investigation_id),
            claims_accepted=summary.accepted, claims_rejected=summary.rejected, message=message,
        )
        # Fire webhooks on terminal transitions (FINISHED, PAUSED). The dispatcher swallows
        # every failure with a log line — a dead webhook subscriber must not fail an
        # investigation whose work is already stored on disk.
        if self._webhook_dispatcher is not None:
            try:
                self._webhook_dispatcher.dispatch_investigation(report)
            except Exception as exc:  # noqa: BLE001 — defensive: never let notify break the run
                self._log(f"Webhook dispatcher raised: {type(exc).__name__}: {exc}")
        return report
