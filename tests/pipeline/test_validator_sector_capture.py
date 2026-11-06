"""Validator captures `targets identity:<sector>` claims onto the actor's sectors list.

Nivel 3 of the identity-mistype story: the Validator used to just reject these claims
(0.11), which lost the sector-attribution signal entirely. 0.13 preserves the signal
by appending the sector label to the actor's `attributes.sectors` list in place of a
first-class `targets identity:<sector>` claim. The claim is still rejected (we do not
want a bad identity entity), but the event decision is `captured-as-sector` instead
of plain `rejected` so the trace shows exactly what happened.
"""

from __future__ import annotations

from datetime import date

import pytest

from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.knowledge.models import AliasOrigin, ClaimDraft, Polarity
from cyllex_argus.pipeline.validator import Validator

SPIDER = "intrusion-set--00000000-0000-4000-8000-000000001015"
TEXT = (
    "Scattered Spider targeted healthcare organisations across North America. "
    "The group also focuses on retail during holiday seasons, and has pivoted into AWS "
    "environments as a secondary target. North America remained the primary region."
)


@pytest.fixture
def validator(attack_store, attack_catalog):
    return Validator(attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29))


@pytest.fixture
def add_doc(attack_store, new_doc):
    def factory():
        doc, _ = attack_store.add_document(new_doc(publisher="Mandiant", reliability="A", text=TEXT))
        return doc
    return factory


_QUOTES: dict[str, str] = {
    "healthcare": "targeted healthcare organisations across North America",
    "retail": "focuses on retail during holiday seasons",
    "AWS": "pivoted into AWS environments as a secondary target",
}


def _sector_draft(sector: str, **overrides) -> ClaimDraft:
    data = dict(
        subject="Scattered Spider",
        subject_type="intrusion-set",
        predicate="targets",
        object=sector,
        object_type="identity",
        polarity=Polarity.ASSERTS,
        quote=_QUOTES.get(sector, sector),
    )
    data.update(overrides)
    return ClaimDraft(**data)


def test_sector_claim_captures_to_actor_attributes(validator, attack_store, add_doc):
    summary = validator.process(add_doc(), [_sector_draft("healthcare")], "analyst-v2")
    assert (summary.accepted, summary.rejected) == (0, 1)
    actor = attack_store.get_entity(SPIDER)
    assert actor.attributes.get("sectors") == ["healthcare"]
    [event] = summary.events
    assert event.decision == "captured-as-sector"
    assert "healthcare" in (event.reason or "")
    assert "sectors" in (event.reason or "")


def test_sector_capture_dedupes_across_claims(validator, attack_store, add_doc):
    summary = validator.process(
        add_doc(),
        [_sector_draft("healthcare"), _sector_draft("healthcare"), _sector_draft("retail")],
        "analyst-v2",
    )
    assert summary.rejected == 3  # all three claims still rejected (no bad identity entity)
    actor = attack_store.get_entity(SPIDER)
    assert actor.attributes.get("sectors") == ["healthcare", "retail"]  # deduped, ordered


def test_sector_capture_only_on_asserts_polarity(validator, attack_store, add_doc):
    """`refutes` says the document denies the sector attribution — the capture would be
    silently wrong. The claim is rejected the regular way with the mistype reason."""
    draft = _sector_draft("healthcare", polarity=Polarity.REFUTES)
    summary = validator.process(add_doc(), [draft], "analyst-v2")
    actor = attack_store.get_entity(SPIDER)
    assert actor.attributes.get("sectors") is None  # nothing captured
    [event] = summary.events
    assert event.decision == "rejected"
    assert "sector label" in (event.reason or "")


def test_tool_mistype_still_rejected_not_captured(validator, attack_store, add_doc):
    """A tool-mistype (AWS as identity) does not trigger the capture branch — nothing
    to append to; the operator will retype it from the Health panel."""
    draft = _sector_draft("AWS")
    summary = validator.process(add_doc(), [draft], "analyst-v2")
    actor = attack_store.get_entity(SPIDER)
    assert actor.attributes.get("sectors") is None
    [event] = summary.events
    assert event.decision == "rejected"
    assert "technology" in (event.reason or "").lower()


def test_non_targets_predicate_not_captured(validator, attack_store, add_doc):
    """`uses identity:healthcare` makes no semantic sense but if the LLM emits it, we
    just reject — we do not capture a sector from a `uses` claim."""
    draft = _sector_draft("healthcare", predicate="uses")
    summary = validator.process(add_doc(), [draft], "analyst-v2")
    actor = attack_store.get_entity(SPIDER)
    assert actor.attributes.get("sectors") is None
    [event] = summary.events
    assert event.decision == "rejected"


def test_non_actor_shaped_subject_not_captured(validator, attack_store, add_doc):
    """Only actor-shaped entities (intrusion-set / campaign / malware / tool) carry a
    STIX 2.1 sectors[] list; a `location targets healthcare` claim just gets rejected."""
    draft = _sector_draft(
        "healthcare", subject="North America", subject_type="location",
        quote="targeted healthcare organisations across North America",
    )
    summary = validator.process(add_doc(), [draft], "analyst-v2")
    [event] = summary.events
    assert event.decision == "rejected"
    _ = AliasOrigin  # imported for cross-test convenience
