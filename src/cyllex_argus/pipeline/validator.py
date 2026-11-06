"""Validator: verify claims deterministically, resolve entities and recompute assessments."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date

from cyllex_argus.attack.catalog import AttackCatalog
from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.enrichment import (
    EnrichmentRequest,
    EnrichmentRunner,
    detect_observable_type,
)
from cyllex_argus.knowledge.mistype import is_known_mistype, suggest_retype
from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    ClaimDraft,
    Document,
    Entity,
    Polarity,
    QuoteStatus,
)
from cyllex_argus.knowledge.names import mentions_any, normalize_name
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.knowledge.trace import PipelineEvent
from cyllex_argus.pipeline.quotes import normalize_text, verify_quote
from cyllex_argus.scoring.confidence import score

EnrichmentFactory = Callable[[int | None], EnrichmentRunner]

Key = tuple[str, str, str]
_COMPATIBLE_TYPES = {"malware": {"malware", "tool"}, "tool": {"malware", "tool"}}
# Subject-side STIX types the sector-capture path accepts. Mirrors the shape STIX 2.1
# `threat-actor.sectors[]` is defined on; a `targets` claim with any other subject type
# would not benefit from the capture (an indicator targeting a sector makes no sense).
_ACTOR_SHAPED_TYPES = frozenset({"intrusion-set", "campaign", "malware", "tool"})


@dataclass
class ValidationSummary:
    accepted: int = 0
    rejected: int = 0
    touched: set[Key] = field(default_factory=set)
    events: list[PipelineEvent] = field(default_factory=list)  # one per claim; the pipeline fills in the ids
    # Guards `merge` only. A per-document summary is built on one thread and never shared; the
    # RUN's summary is merged into from every worker in the pool, and `self.accepted +=` is a
    # read-modify-write (LOAD_ATTR, ADD, STORE_ATTR) that drops an increment when two workers
    # land between the load and the store — the run then under-reports what it accepted.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def merge(self, batch: ValidationSummary) -> None:
        """Fold one document's result into the run total. Safe to call from several threads."""
        with self._lock:
            self.accepted += batch.accepted
            self.rejected += batch.rejected
            self.touched |= batch.touched


class Validator:
    def __init__(
        self,
        store: SQLiteStore,
        catalog: AttackCatalog,
        scoring: ScoringConfig,
        today: Callable[[], date] = date.today,
        enrichment_factory: EnrichmentFactory | None = None,
    ) -> None:
        self._store = store
        self._catalog = catalog
        self._scoring = scoring
        self._today = today
        self._enrichment_factory = enrichment_factory

    def process(
        self, document: Document, drafts: list[ClaimDraft], prompt_version: str, investigation_id: int | None = None,
    ) -> ValidationSummary:
        summary = ValidationSummary()
        normalized_text = normalize_name(document.text)
        # Pay normalize_text(document.text) ONCE per doc instead of once per claim: the loop below
        # calls verify_quote N times and the normalization step was the dominant cost.
        normalized_haystack = normalize_text(document.text)
        for draft in drafts:
            status = verify_quote(
                draft.quote, document.text, self._scoring.fuzzy_threshold,
                normalized_haystack=normalized_haystack,
            )
            reason = "the quote is not in the document" if status is QuoteStatus.REJECTED else None
            technique_entity: Entity | None = None
            if status is not QuoteStatus.REJECTED and draft.object_type == "attack-pattern":
                technique_entity = self._technique_entity(draft.technique_id)
                if technique_entity is None:
                    status = QuoteStatus.REJECTED
                    reason = f"unknown ATT&CK technique {draft.technique_id or '(none given)'}"
            if status is not QuoteStatus.REJECTED and not self._names_appear(normalized_text, draft, investigation_id):
                status = QuoteStatus.REJECTED
                reason = "the subject or object is not named in the document"
            captured_decision: str | None = None
            if status is not QuoteStatus.REJECTED:
                mistype_outcome = self._handle_identity_mistype(draft, investigation_id)
                if mistype_outcome is not None:
                    status = QuoteStatus.REJECTED
                    reason, captured_decision = mistype_outcome
            if status is QuoteStatus.REJECTED:
                self._store.add_claim(document.id, draft, status, prompt_version, None, None, investigation_id)
                summary.rejected += 1
                summary.events.append(self._event(
                    document, draft, captured_decision or "rejected", reason,
                ))
                continue
            summary.events.append(self._event(document, draft, "validated", None))

            if draft.predicate == "alias-of":
                target = self._resolve(draft.object, draft.object_type, investigation_id)
                claim = self._store.add_claim(
                    document.id, draft, status, prompt_version, target.id, target.id, investigation_id)
                if draft.polarity is Polarity.ASSERTS:  # "X is not another name for Y" teaches nothing
                    self._store.add_alias(
                        draft.subject, target.id, AliasOrigin.DOCUMENT, claim.id,
                        investigation_id=investigation_id,
                    )
                summary.accepted += 1
                continue

            swapped_actor = self._actor_shaped_subject_if_collision(draft, investigation_id)
            if swapped_actor is not None:
                subject = swapped_actor
                summary.events.append(self._event(
                    document, draft, "swapped-malware-to-actor",
                    f"predicate '{draft.predicate}' belongs to the group, not the malware; "
                    f"routed to intrusion-set '{swapped_actor.canonical_name}' with the same name",
                ))
            else:
                subject = self._resolve(draft.subject, draft.subject_type, investigation_id)
            obj = technique_entity or self._resolve(draft.object, draft.object_type, investigation_id)
            self._store.add_claim(document.id, draft, status, prompt_version, subject.id, obj.id, investigation_id)
            summary.accepted += 1
            summary.touched.add((subject.id, draft.predicate, obj.id))
            if draft.predicate == "attributed-to":
                self._add_sibling_attributions(summary.touched, subject.id)
            self._maybe_enrich(draft, investigation_id)
        self.recompute(summary.touched)
        return summary

    def _maybe_enrich(self, draft: ClaimDraft, investigation_id: int | None) -> None:
        """Fire every enabled enricher that accepts this claim's indicator.

        Does nothing when no enrichment factory was wired (every existing deployment and test
        is in this state until the operator opts in). On an `indicates` claim the IOC is the
        subject; on an `exploits` claim the CVE is the object. Everything else is skipped.
        """
        if self._enrichment_factory is None:
            return
        if draft.predicate == "indicates":
            value = draft.subject
        elif draft.predicate == "exploits" and draft.object_type == "vulnerability":
            value = draft.object
        else:
            return
        observable_type = detect_observable_type(value)
        if observable_type is None:
            return
        runner = self._enrichment_factory(investigation_id)
        if not runner.enrichers_for(observable_type):
            return
        runner.enrich_all(EnrichmentRequest(indicator=value.strip(), indicator_type=observable_type))

    @staticmethod
    def _event(document: Document, draft: ClaimDraft, decision: str, reason: str | None) -> PipelineEvent:
        claim = f"{draft.subject} {draft.predicate} {draft.object}"
        return PipelineEvent(
            investigation_id=0, document_id=document.id, stage="validator", decision=decision,
            reason=f"{claim}: {reason}" if reason else claim,
        )

    def reset_document(self, document_id: int) -> None:
        touched = set(self._store.delete_claims_for_document(document_id))
        # Deleting one attribution changes the competing-publisher set of its siblings, so every
        # remaining attribution of the same subject must be recomputed too (after the delete).
        for subject_id in {subject for subject, predicate, _ in touched if predicate == "attributed-to"}:
            self._add_sibling_attributions(touched, subject_id)
        self.recompute(touched)

    def recompute(self, keys: set[Key]) -> None:
        for subject_id, predicate, object_id in keys:
            # The read (evidence_for) -> score -> write (upsert_assessment) is one critical
            # section: each store call locks on its own, but between them another worker thread
            # can add a corroborating claim and upsert a CORROBORATED verdict that a stale
            # one-supporter write here would then clobber. `atomic()` holds the store lock across
            # the whole sequence so the last recompute always scores the current evidence. `score`
            # and `self._today()` are pure and take microseconds, so they are safe inside the lock.
            with self._store.atomic():
                evidence = self._store.evidence_for(subject_id, predicate, object_id)
                if not evidence:
                    self._store.delete_assessment(subject_id, predicate, object_id)
                    continue
                competing = (
                    self._store.competing_attribution_publishers(subject_id, object_id)
                    if predicate == "attributed-to" else set()
                )
                result = score(evidence, competing, self._scoring, self._today())
                self._store.upsert_assessment(Assessment(
                    subject_entity_id=subject_id, predicate=predicate, object_entity_id=object_id,
                    status=result.status, confidence=result.confidence, admiralty=result.admiralty,
                    first_seen=result.first_seen, last_seen=result.last_seen,
                    analytic_confidence=result.analytic_confidence,
                ))

    def _add_sibling_attributions(self, keys: set[Key], subject_id: str) -> None:
        for other in self._store.object_ids_for(subject_id, "attributed-to"):
            keys.add((subject_id, "attributed-to", other))

    def _technique_entity(self, technique_id: str | None) -> Entity | None:
        if not technique_id:
            return None
        technique = self._catalog.resolve_technique(technique_id)
        if technique is None:
            return None
        existing = self._store.get_entity(technique.stix_id)
        if existing is not None:
            return existing
        return self._store.create_entity(
            "attack-pattern", technique.name, AliasOrigin.ATTACK,
            external_id=technique.technique_id, entity_id=technique.stix_id,
        )

    @staticmethod
    def _identity_mistype_reason(draft: ClaimDraft) -> str | None:
        """Reject identity drafts whose name matches a known tech or sector pattern.

        Determinístic backstop for the Analyst's negative identity rules (SYSTEM_PROMPT v2):
        even when the LLM ignores them, this check marks the claim as `rejected` with a
        clear reason, so the operator sees WHY a mistyped extraction didn't survive.
        """
        if draft.object_type != "identity":
            return None
        if not is_known_mistype(draft.object):
            return None
        suggestion = suggest_retype(draft.object) or "unknown"
        if suggestion == "tool":
            return (
                f"'{draft.object}' is a known technology/platform, not a named organization — "
                f"identity SDOs reserved for legal entities; see analyst-v2 prompt rules"
            )
        return (
            f"'{draft.object}' is a known sector label, not a named organization — "
            f"actor sector attribution belongs on the actor's attributes, not as a targets claim"
        )

    def _actor_shaped_subject_if_collision(
        self, draft: ClaimDraft, investigation_id: int | None,
    ) -> Entity | None:
        """Return the same-name intrusion-set when the Analyst typed a malware subject on a
        predicate that semantically belongs to actors.

        The ATT&CK catalog has several groups whose signature malware shares the group's
        name (Machete / Carbanak / Akira / Evilnum / RTM / AppleJeus). analyst-v3 asks the
        LLM to pick the right type from the quote, but when it still ends up with
        `subject_type: malware` + `predicate: targets` or `attributed-to` — predicates that
        describe INTENT (code does not have intent) — this backstop swaps the resolution to
        the same-name intrusion-set so the claim lands on the real-world object.

        Returns None (no swap) when:
        - the subject is not a malware draft
        - the predicate is anything other than targets / attributed-to
        - no intrusion-set with the same alias exists (defensive — avoids resolving to a
          random same-name actor from a different vendor's naming)
        """
        if draft.subject_type != "malware":
            return None
        if draft.predicate not in {"targets", "attributed-to"}:
            return None
        actor = self._store.find_by_alias(
            draft.subject, stix_types={"intrusion-set"},
            scope_investigation_id=investigation_id,
        )
        return actor

    def _handle_identity_mistype(
        self, draft: ClaimDraft, investigation_id: int | None,
    ) -> tuple[str, str] | None:
        """Decide what to do with an identity-mistyped draft.

        Returns (reason, decision) when the draft should be rejected:
        - `("'AWS' is a known technology/platform…", "rejected")` — a tool mistype.
          Nothing to do beyond logging; the operator can retype the (non-existent)
          entity later via Health, but the claim does not survive.
        - `("sector label 'healthcare' captured on <actor>.sectors", "captured-as-sector")`
          — a sector mistype on a `targets` asserts claim with a resolvable actor-shaped
          subject. The sector label is appended to the actor's attributes.sectors list
          IN PLACE OF the claim, so the signal is kept — just in the STIX 2.1-correct
          shape. The claim itself is still rejected (we do not want a bad identity entity).

        Returns None when the draft is not a mistype and should proceed through the
        normal path.
        """
        base_reason = self._identity_mistype_reason(draft)
        if base_reason is None:
            return None
        suggestion = suggest_retype(draft.object)
        if (
            suggestion == "sector-tag"
            and draft.predicate == "targets"
            and draft.polarity is Polarity.ASSERTS
            and draft.subject_type in _ACTOR_SHAPED_TYPES
        ):
            subject = self._store.find_by_alias(
                draft.subject, stix_types=_COMPATIBLE_TYPES.get(draft.subject_type, {draft.subject_type}),
                scope_investigation_id=investigation_id,
            )
            if subject is not None:
                try:
                    self._store.append_entity_sector(subject.id, draft.object)
                except (KeyError, ValueError):
                    pass  # defensive — a race where the actor got deleted mid-ingest; fall through
                else:
                    return (
                        f"sector label '{draft.object.lower()}' captured on "
                        f"{subject.canonical_name}.attributes.sectors",
                        "captured-as-sector",
                    )
        return (base_reason, "rejected")

    def _names_appear(
        self, normalized_text: str, draft: ClaimDraft, investigation_id: int | None,
    ) -> bool:
        """A real quote is not enough: the document must also name the claim's subject and object.

        A name counts when the document writes it or any alias of the entity it resolves to. The new
        name of an alias-of claim must appear as written, and techniques are left to the ATT&CK check.
        """
        if draft.predicate == "alias-of":
            subject_named = mentions_any(normalized_text, [draft.subject])
        else:
            subject_named = self._named(normalized_text, draft.subject, draft.subject_type, investigation_id)
        if not subject_named:
            return False
        return draft.object_type == "attack-pattern" or self._named(
            normalized_text, draft.object, draft.object_type, investigation_id,
        )

    def _named(
        self, normalized_text: str, name: str, stix_type: str, investigation_id: int | None,
    ) -> bool:
        known = self._store.find_by_alias(
            name, stix_types=_COMPATIBLE_TYPES.get(stix_type, {stix_type}),
            scope_investigation_id=investigation_id,
        )
        names = [name, *(self._store.aliases_for(known.id) if known is not None else [])]
        return mentions_any(normalized_text, names)

    def _resolve(self, name: str, stix_type: str, investigation_id: int | None) -> Entity:
        # One atomic find-or-create, not a find followed by a create: with `--concurrency > 1`
        # two workers resolving the same actor both read "not found" and both inserted it, which
        # split the actor in two and downgraded its corroborated assessment to two single-source
        # ones. See SQLiteStore.find_or_create_entity and tests/pipeline/test_concurrency.py.
        return self._store.find_or_create_entity(
            name, stix_type, AliasOrigin.DOCUMENT,
            stix_types=_COMPATIBLE_TYPES.get(stix_type, {stix_type}),
            scope_investigation_id=investigation_id,
            investigation_id=investigation_id,
        )
