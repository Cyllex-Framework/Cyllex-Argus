"""TLP labels on publishers: set, clear, list, propagate to citations, cap filter."""

from __future__ import annotations

import pytest

from cyllex_argus.knowledge.models import (
    TLP,
    AliasOrigin,
    ClaimDraft,
    QuoteStatus,
)


def test_publisher_starts_with_no_tlp(store):
    p = store.get_or_create_publisher("Mandiant")
    assert p.tlp is None


def test_set_publisher_tlp_persists_and_reads_back(store):
    store.get_or_create_publisher("Mandiant")
    updated = store.set_publisher_tlp("Mandiant", TLP.AMBER)
    assert updated.tlp is TLP.AMBER
    reread = store.get_publisher(updated.id)
    assert reread.tlp is TLP.AMBER


def test_set_publisher_tlp_can_clear(store):
    store.get_or_create_publisher("Mandiant")
    store.set_publisher_tlp("Mandiant", TLP.AMBER)
    cleared = store.set_publisher_tlp("Mandiant", None)
    assert cleared.tlp is None


def test_set_publisher_tlp_raises_on_unknown(store):
    with pytest.raises(KeyError):
        store.set_publisher_tlp("Unknown Publisher", TLP.CLEAR)


def test_citation_carries_the_publisher_tlp(store, new_doc):
    doc, _ = store.add_document(new_doc(publisher="Mandiant"))
    store.set_publisher_tlp("Mandiant", TLP.AMBER)
    actor = store.create_entity("intrusion-set", "Spider", AliasOrigin.ATTACK)
    tool = store.create_entity("tool", "Mimikatz", AliasOrigin.ATTACK)
    store.add_claim(doc.id, ClaimDraft(
        subject="Spider", subject_type="intrusion-set", predicate="uses",
        object="Mimikatz", object_type="tool", quote="x" * 30,
    ), QuoteStatus.VERIFIED, "p-v1", actor.id, tool.id)
    citations = store.citations(actor.id, "uses", tool.id)
    assert len(citations) == 1
    assert citations[0].publisher_tlp == "amber"


def test_markdown_exporter_filters_citations_above_the_cap(store, new_doc):
    """A fact with only AMBER evidence must be dropped from a CLEAR-cap export."""
    from datetime import date as _date

    from cyllex_argus.exporters.markdown import render_markdown
    from cyllex_argus.knowledge.models import Assessment, AssessmentStatus
    from cyllex_argus.knowledge.profile import build_profile

    # Two docs from two publishers with different TLPs.
    doc_green, _ = store.add_document(new_doc(publisher="GreenPublisher"))
    doc_amber, _ = store.add_document(new_doc(publisher="AmberPublisher"))
    store.set_publisher_tlp("GreenPublisher", TLP.GREEN)
    store.set_publisher_tlp("AmberPublisher", TLP.AMBER)

    actor = store.create_entity("intrusion-set", "Spider", AliasOrigin.ATTACK)
    tool = store.create_entity("tool", "Mimikatz", AliasOrigin.ATTACK)
    other = store.create_entity("malware", "Qakbot", AliasOrigin.ATTACK)
    for doc, obj in ((doc_green, tool), (doc_amber, other)):
        store.add_claim(doc.id, ClaimDraft(
            subject="Spider", subject_type="intrusion-set", predicate="uses",
            object=obj.canonical_name, object_type=obj.stix_type, quote="x" * 30,
        ), QuoteStatus.VERIFIED, "p-v1", actor.id, obj.id)
        store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=obj.id,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=60, admiralty="A3",
        ))

    profile = build_profile(store, actor)
    assert len(profile.facts) == 2
    # Cap at GREEN: the AMBER fact is dropped from the export.
    text = render_markdown(profile, summary=None, generated_on=_date(2026, 10, 1), tlp_cap=TLP.GREEN)
    assert "Mimikatz" in text
    assert "Qakbot" not in text
    assert "tlp:green" in text


def test_markdown_exporter_keeps_facts_with_mixed_sources(store, new_doc):
    """A fact with evidence from both GREEN and AMBER publishers stays, with only the GREEN cite."""
    from datetime import date as _date

    from cyllex_argus.exporters.markdown import render_markdown
    from cyllex_argus.knowledge.models import Assessment, AssessmentStatus
    from cyllex_argus.knowledge.profile import build_profile

    doc_green, _ = store.add_document(new_doc(publisher="GreenPublisher"))
    doc_amber, _ = store.add_document(new_doc(publisher="AmberPublisher"))
    store.set_publisher_tlp("GreenPublisher", TLP.GREEN)
    store.set_publisher_tlp("AmberPublisher", TLP.AMBER)
    actor = store.create_entity("intrusion-set", "Spider", AliasOrigin.ATTACK)
    tool = store.create_entity("tool", "Mimikatz", AliasOrigin.ATTACK)
    for doc, quote in ((doc_green, "green-source quote" + " x" * 10),
                       (doc_amber, "amber-source quote" + " x" * 10)):
        store.add_claim(doc.id, ClaimDraft(
            subject="Spider", subject_type="intrusion-set", predicate="uses",
            object="Mimikatz", object_type="tool", quote=quote,
        ), QuoteStatus.VERIFIED, "p-v1", actor.id, tool.id)
    store.upsert_assessment(Assessment(
        subject_entity_id=actor.id, predicate="uses", object_entity_id=tool.id,
        status=AssessmentStatus.CORROBORATED, confidence=84, admiralty="A2",
    ))
    profile = build_profile(store, actor)
    text = render_markdown(profile, summary=None, generated_on=_date(2026, 10, 1), tlp_cap=TLP.GREEN)
    assert "green-source quote" in text
    assert "amber-source quote" not in text


def test_claim_publisher_ids_above_tlp_identifies_restricted_sources(store):
    """Helper used by the export filter to list publishers above a cap in bulk."""
    store.get_or_create_publisher("ClearPub")
    store.get_or_create_publisher("GreenPub")
    p_amber = store.get_or_create_publisher("AmberPub")
    p_red = store.get_or_create_publisher("RedPub")
    store.set_publisher_tlp("ClearPub", TLP.CLEAR)
    store.set_publisher_tlp("GreenPub", TLP.GREEN)
    store.set_publisher_tlp("AmberPub", TLP.AMBER)
    store.set_publisher_tlp("RedPub", TLP.RED)
    above_green = store.claim_publisher_ids_above_tlp(TLP.GREEN)
    assert above_green == {p_amber.id, p_red.id}
    above_amber = store.claim_publisher_ids_above_tlp(TLP.AMBER)
    assert above_amber == {p_red.id}


def test_unclassified_publisher_is_not_above_any_cap(store):
    store.get_or_create_publisher("Mandiant")  # left without a TLP
    assert store.claim_publisher_ids_above_tlp(TLP.CLEAR) == set()
