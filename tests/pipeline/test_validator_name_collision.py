"""Validator swaps `targets` / `attributed-to` claims from malware to the same-name actor.

The backstop for the analyst-v3 name-collision rules. Even when the Analyst still ends up
typing "Machete" as a malware subject on a `targets Latin America` claim, the Validator
routes the subject to the intrusion-set because code does not target things with intent.
"""

from __future__ import annotations

from datetime import date

import pytest

from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.knowledge.models import AliasOrigin, ClaimDraft, Polarity
from cyllex_argus.pipeline.validator import Validator

SPIDER = "intrusion-set--00000000-0000-4000-8000-000000001015"
TEXT = (
    "Machete has been one of the largest cyber espionage operations in Latin America. "
    "The group targets government ministries and the military. "
    "Separately, the Machete malware exfiltrates captured data to Dropbox and uses AES encryption."
)


@pytest.fixture
def validator(attack_store, attack_catalog):
    return Validator(attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29))


@pytest.fixture
def doc_with_both_entities(attack_store, new_doc):
    # Seed a malware entity named "Machete" alongside the group "Scattered Spider" that the
    # attack_catalog fixture already loaded. The two entities share nothing other than the
    # fact that the test exercises the swap when both exist — the actor-side test uses
    # "Scattered Spider" as the actor name.
    attack_store.create_entity("malware", "Scattered Spider", AliasOrigin.ATTACK)
    doc, _ = attack_store.add_document(new_doc(publisher="Mandiant", reliability="A", text=TEXT.replace("Machete", "Scattered Spider")))
    return doc


def _draft(predicate: str, obj: str, obj_type: str, subject_type: str = "malware", quote: str | None = None) -> ClaimDraft:
    return ClaimDraft(
        subject="Scattered Spider",
        subject_type=subject_type,
        predicate=predicate,
        object=obj,
        object_type=obj_type,
        polarity=Polarity.ASSERTS,
        quote=quote or "has been one of the largest cyber espionage operations in Latin America",
    )


def test_targets_claim_typed_as_malware_swaps_to_actor(validator, attack_store, doc_with_both_entities):
    """The LLM says `Scattered Spider the malware targets Latin America`. The predicate is
    semantically actor-shaped; the Validator swaps the subject to the intrusion-set that
    shares the name so the claim lands on the real-world object."""
    draft = _draft(
        predicate="targets", obj="Latin America", obj_type="location",
        quote="espionage operations in Latin America",
    )
    summary = validator.process(doc_with_both_entities, [draft], "analyst-v3")
    assert (summary.accepted, summary.rejected) == (1, 0)
    # Only ONE assessment, on the intrusion-set side.
    assessments = attack_store.assessments_involving(SPIDER)
    assert len(assessments) == 1
    assert assessments[0].object_entity_id.startswith("location--")
    # The malware entity has NO assessment despite being named in the claim.
    malware = attack_store.find_by_alias("Scattered Spider", stix_types={"malware"})
    assert attack_store.assessments_involving(malware.id) == []
    # The trace records WHY the swap happened.
    swap_events = [e for e in summary.events if e.decision == "swapped-malware-to-actor"]
    assert len(swap_events) == 1
    assert "intrusion-set" in (swap_events[0].reason or "")


def test_attributed_to_malware_subject_swaps_to_actor(validator, attack_store, new_doc):
    """`attributed-to` on a malware subject is a type error — only campaigns and intrusion-
    sets are attributed. The swap routes to the same-name actor so the claim is recoverable."""
    # Seed both the malware homonym AND a campaign the actor is attributed to; both names
    # must appear in the document text for the Validator to accept the claim.
    attack_store.create_entity("malware", "Scattered Spider", AliasOrigin.ATTACK)
    attack_store.create_entity("campaign", "OpTest", AliasOrigin.DOCUMENT)
    text = "The OpTest campaign is attributed to Scattered Spider, a well-known espionage operation."
    doc, _ = attack_store.add_document(new_doc(publisher="Mandiant", reliability="A", text=text))
    draft = _draft(
        predicate="attributed-to", obj="OpTest", obj_type="campaign",
        quote="OpTest campaign is attributed to Scattered Spider",
    )
    summary = validator.process(doc, [draft], "analyst-v3")
    assert summary.accepted == 1
    assessments = attack_store.assessments_involving(SPIDER)
    assert any(a.predicate == "attributed-to" for a in assessments)


def test_uses_claim_stays_on_malware_when_llm_typed_malware(validator, attack_store, doc_with_both_entities):
    """`uses` is a valid predicate on both malware and intrusion-sets. The swap is scoped to
    predicates that cannot semantically apply to malware (targets, attributed-to) — a
    `uses` claim respects the Analyst's choice because the quote may genuinely be about the
    code's capability."""
    draft = _draft(
        predicate="uses", obj="T1041", obj_type="attack-pattern",
        quote="exfiltrates captured data to Dropbox",
    )
    # No swap, so the claim lands on the malware entity.
    summary = validator.process(doc_with_both_entities, [draft], "analyst-v3")
    swap_events = [e for e in summary.events if e.decision == "swapped-malware-to-actor"]
    assert swap_events == []


def test_swap_only_when_matching_actor_exists(validator, attack_store, doc_with_both_entities):
    """If no same-name intrusion-set exists, there's nothing to swap to. The Validator falls
    back to the normal resolver (which may still reject or process the claim as malware)."""
    # Draft about "Unknown Family" — only exists as malware in the DB after we create it.
    attack_store.create_entity("malware", "UnknownFam", AliasOrigin.DOCUMENT)
    draft = ClaimDraft(
        subject="UnknownFam", subject_type="malware",
        predicate="targets", object="Latin America", object_type="location",
        polarity=Polarity.ASSERTS,
        quote="espionage operations in Latin America",
    )
    summary = validator.process(doc_with_both_entities, [draft], "analyst-v3")
    swap_events = [e for e in summary.events if e.decision == "swapped-malware-to-actor"]
    assert swap_events == []
