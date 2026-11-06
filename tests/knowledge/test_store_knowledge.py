from datetime import date

import pytest

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
    ClaimDraft,
    Polarity,
    QuoteStatus,
)


def test_document_alias_from_one_investigation_does_not_leak_into_another(store):
    """DOCUMENT aliases must be scoped to the investigation that learned them. An alias from
    inv-A must not resolve for inv-B's find_by_alias(scope=B)."""
    spider = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.ATTACK)
    inv_a = store.create_investigation("Target A").id
    inv_b = store.create_investigation("Target B").id
    store.add_alias("FALCON-7", spider.id, AliasOrigin.DOCUMENT, investigation_id=inv_a)

    assert store.find_by_alias("FALCON-7", scope_investigation_id=inv_a).id == spider.id
    assert store.find_by_alias("FALCON-7", scope_investigation_id=inv_b) is None
    # Default (no scope) preserves the global lookup used by CLI and dashboard.
    assert store.find_by_alias("FALCON-7").id == spider.id


def test_merge_entities_moves_claims_aliases_and_recomputes(store, new_doc):
    """Loading ATT&CK after an investigation already extracted a campaign-by-name creates a
    duplicate entity for the same real-world object. `merge_entities` fuses the document-origin
    copy into the ATT&CK-origin canonical one: claims, aliases and assessment keys all follow."""
    doc, _ = store.add_document(new_doc())
    actor = store.create_entity("intrusion-set", "Spider", AliasOrigin.ATTACK)
    old = store.create_entity("campaign", "C0027", AliasOrigin.DOCUMENT)
    new = store.create_entity(
        "campaign", "C0027", AliasOrigin.ATTACK,
        external_id="C0027", entity_id="campaign--mitre-official",
    )
    store.add_alias("Scattered Spider CRM Campaign", new.id, AliasOrigin.ATTACK)
    # A claim written before the merge points at the duplicate.
    store.add_claim(doc.id, ClaimDraft(
        subject="C0027", subject_type="campaign", predicate="attributed-to",
        object="Spider", object_type="intrusion-set", quote="x" * 30,
    ), QuoteStatus.VERIFIED, "p-v1", old.id, actor.id)
    store.add_alias("some narrative alias", old.id, AliasOrigin.DOCUMENT)

    touched = store.merge_entities(old.id, new.id)
    # The claim now points at the official entity, not the duplicate.
    rows = store.connection.execute(
        "SELECT subject_entity_id FROM claims WHERE id > 0 AND subject_entity_id IS NOT NULL"
    ).fetchall()
    assert all(r[0] != old.id for r in rows)
    assert any(r[0] == new.id for r in rows)
    # The duplicate alias merged into the target.
    assert store.find_by_alias("some narrative alias") is not None
    assert store.find_by_alias("some narrative alias").id == new.id
    # The old entity is gone.
    assert store.get_entity(old.id) is None
    # The caller learned which (subj, pred, obj) keys need recompute.
    assert (new.id, "attributed-to", actor.id) in touched


def test_merge_entities_refuses_to_cross_stix_types(store):
    actor = store.create_entity("intrusion-set", "Spider", AliasOrigin.ATTACK)
    camp = store.create_entity("campaign", "C0027", AliasOrigin.ATTACK)
    with pytest.raises(ValueError, match="stix_type"):
        store.merge_entities(actor.id, camp.id)


def test_merge_entities_refuses_self_merge(store):
    e = store.create_entity("campaign", "C0027", AliasOrigin.DOCUMENT)
    with pytest.raises(ValueError, match="differ"):
        store.merge_entities(e.id, e.id)


def test_merge_entities_raises_on_unknown_id(store):
    e = store.create_entity("campaign", "C0027", AliasOrigin.DOCUMENT)
    with pytest.raises(KeyError):
        store.merge_entities("campaign--missing", e.id)
    with pytest.raises(KeyError):
        store.merge_entities(e.id, "campaign--missing")


def test_citations_batch_returns_same_result_as_per_fact_citations(store, new_doc):
    """citations_batch grouped output must equal per-fact `citations()` for each triple."""
    doc, _ = store.add_document(new_doc())
    actor = store.create_entity("intrusion-set", "Spider", AliasOrigin.ATTACK)
    technique = store.create_entity("attack-pattern", "T1", AliasOrigin.ATTACK, external_id="T1")
    tool = store.create_entity("tool", "Mimikatz", AliasOrigin.ATTACK)
    for obj in (technique, tool):
        store.add_claim(
            doc.id,
            ClaimDraft(subject="Spider", subject_type="intrusion-set", predicate="uses",
                       object=obj.canonical_name, object_type=obj.stix_type,
                       quote="x" * 30, technique_id=obj.external_id),
            QuoteStatus.VERIFIED, "p-v1", actor.id, obj.id,
        )
    triples = [(actor.id, "uses", technique.id), (actor.id, "uses", tool.id)]
    batched = store.citations_batch(triples)
    assert len(batched[triples[0]]) == 1 and len(batched[triples[1]]) == 1
    assert batched[triples[0]] == store.citations(*triples[0])
    assert batched[triples[1]] == store.citations(*triples[1])


def test_get_entities_batch_returns_all_requested(store):
    store.create_entity("malware", "A", AliasOrigin.ATTACK, entity_id="malware--a")
    store.create_entity("tool", "B", AliasOrigin.ATTACK, entity_id="tool--b")
    out = store.get_entities(["malware--a", "tool--b", "malware--missing"])
    assert set(out.keys()) == {"malware--a", "tool--b"}
    assert out["malware--a"].canonical_name == "A"
    assert out["tool--b"].canonical_name == "B"


def test_attack_and_user_aliases_resolve_for_every_investigation(store):
    """Scope only filters DOCUMENT aliases; ATTACK and USER aliases must stay globally visible."""
    spider = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.ATTACK)
    store.add_alias("UNC3944", spider.id, AliasOrigin.ATTACK)
    store.add_alias("Spidey", spider.id, AliasOrigin.USER)
    inv_other = store.create_investigation("Unrelated").id
    assert store.find_by_alias("UNC3944", scope_investigation_id=inv_other).id == spider.id
    assert store.find_by_alias("Spidey", scope_investigation_id=inv_other).id == spider.id


def _draft(**overrides) -> ClaimDraft:
    data = dict(
        subject="Scattered Spider", subject_type="intrusion-set", predicate="uses",
        object="Spearphishing Voice", object_type="attack-pattern",
        quote="the actor called the help desk to reset MFA", technique_id="T1566.004",
    )
    data.update(overrides)
    return ClaimDraft(**data)


def test_create_entity_registers_its_name_as_alias(store):
    e = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    assert e.id.startswith("intrusion-set--")
    assert store.find_by_alias("scattered-spider").id == e.id
    assert store.find_by_alias("Scattered Spider", stix_types={"malware"}) is None
    assert store.aliases_for(e.id) == ["Scattered Spider"]


def test_aliases_for_can_filter_by_origin(store):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.ATTACK, entity_id="intrusion-set--1")
    store.add_alias("UNC3944", actor.id, AliasOrigin.ATTACK)
    store.add_alias("Spidey", actor.id, AliasOrigin.USER)
    store.add_alias("PROJECT-FALCON-7", actor.id, AliasOrigin.DOCUMENT)
    assert store.aliases_for(actor.id) == ["PROJECT-FALCON-7", "Scattered Spider", "Spidey", "UNC3944"]
    assert store.aliases_for(actor.id, origins=[AliasOrigin.ATTACK, AliasOrigin.USER]) == [
        "Scattered Spider", "Spidey", "UNC3944",
    ]
    assert store.aliases_for(actor.id, origins=["document"]) == ["PROJECT-FALCON-7"]
    assert store.aliases_for(actor.id, origins=[]) == []


def test_attack_aliases_win_over_document_aliases(store):
    doc_entity = store.create_entity("malware", "Cobalt Strike", AliasOrigin.DOCUMENT)
    attack_entity = store.create_entity(
        "tool", "Cobalt Strike", AliasOrigin.ATTACK, entity_id="tool--aaaa"
    )
    assert doc_entity.id != attack_entity.id
    assert store.find_by_alias("Cobalt Strike").id == "tool--aaaa"


def test_attack_entity_ids_returns_only_entities_with_an_attack_alias(store):
    technique = store.create_entity("attack-pattern", "Phishing", AliasOrigin.ATTACK, external_id="T1566")
    documented = store.create_entity("malware", "Cobalt Strike", AliasOrigin.DOCUMENT)
    added_by_user = store.create_entity("intrusion-set", "Custom Actor", AliasOrigin.USER)
    upgraded = store.create_entity("tool", "Mimikatz", AliasOrigin.DOCUMENT)
    store.add_alias("Mimikatz Tool", upgraded.id, AliasOrigin.ATTACK)
    ids = [technique.id, documented.id, added_by_user.id, upgraded.id, "malware--unknown"]
    assert store.attack_entity_ids(ids) == {technique.id, upgraded.id}
    assert store.attack_entity_ids([]) == set()


def test_find_by_external_id(store):
    store.create_entity(
        "attack-pattern", "Spearphishing Voice", AliasOrigin.ATTACK,
        external_id="T1566.004", entity_id="attack-pattern--1",
    )
    assert store.find_by_external_id("T1566.004").id == "attack-pattern--1"
    assert store.find_by_external_id("T0000") is None


def test_evidence_uses_primary_publisher_and_skips_rejected(store, new_doc):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    tech = store.create_entity("attack-pattern", "Spearphishing Voice", AliasOrigin.ATTACK, external_id="T1566.004")
    doc, _ = store.add_document(new_doc(publisher="News Site", reliability="E"))
    primary = store.get_or_create_publisher("Mandiant", default_reliability="B")
    store.set_analysis(doc.id, primary.id, "analyst-v1")
    ok = store.add_claim(doc.id, _draft(observed_at=date(2023, 9, 1)), QuoteStatus.VERIFIED, "analyst-v1", actor.id, tech.id)
    store.add_claim(doc.id, _draft(quote="made up"), QuoteStatus.REJECTED, "analyst-v1", actor.id, tech.id)
    evidence = store.evidence_for(actor.id, "uses", tech.id)
    assert len(evidence) == 1
    assert evidence[0].claim_id == ok.id
    assert evidence[0].publisher_id == primary.id
    assert evidence[0].reliability == "B"  # effective (primary) publisher
    assert evidence[0].document_reliability == "E"  # the publisher that actually hosts the page
    assert evidence[0].observed_at == date(2023, 9, 1)
    assert evidence[0].published_at == date(2025, 1, 10)
    assert [c.quote for c in store.citations(actor.id, "uses", tech.id)] == [ok.quote]


def test_evidence_carries_both_primary_and_document_publisher_reliability(store, new_doc):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    tech = store.create_entity("attack-pattern", "Spearphishing Voice", AliasOrigin.ATTACK, external_id="T1566.004")
    doc, _ = store.add_document(new_doc(publisher="Trusted Vendor", reliability="A"))
    primary = store.get_or_create_publisher("Weak Source", default_reliability="C")
    store.set_analysis(doc.id, primary.id, "analyst-v1")
    store.add_claim(doc.id, _draft(), QuoteStatus.VERIFIED, "analyst-v1", actor.id, tech.id)
    [evidence] = store.evidence_for(actor.id, "uses", tech.id)
    assert evidence.publisher_id == primary.id
    assert evidence.reliability == "C"
    assert evidence.document_reliability == "A"


def test_competing_attributions(store, new_doc):
    campaign = store.create_entity("campaign", "Op X", AliasOrigin.DOCUMENT)
    actor_a = store.create_entity("intrusion-set", "Actor A", AliasOrigin.DOCUMENT)
    actor_b = store.create_entity("intrusion-set", "Actor B", AliasOrigin.DOCUMENT)
    d1, _ = store.add_document(new_doc(publisher="Vendor One"))
    d2, _ = store.add_document(new_doc(publisher="Vendor Two"))
    attr = dict(subject="Op X", subject_type="campaign", predicate="attributed-to",
                object_type="intrusion-set", technique_id=None)
    store.add_claim(d1.id, _draft(object="Actor A", **attr), QuoteStatus.VERIFIED, "v1", campaign.id, actor_a.id)
    store.add_claim(d2.id, _draft(object="Actor B", **attr), QuoteStatus.VERIFIED, "v1", campaign.id, actor_b.id)
    assert store.competing_attribution_publishers(campaign.id, actor_a.id) == {d2.publisher_id}
    assert store.object_ids_for(campaign.id, "attributed-to") == {actor_a.id, actor_b.id}


def test_upsert_assessment_updates_in_place(store):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    tech = store.create_entity("attack-pattern", "Phishing", AliasOrigin.ATTACK, external_id="T1566")
    first = store.upsert_assessment(Assessment(
        subject_entity_id=actor.id, predicate="uses", object_entity_id=tech.id,
        status=AssessmentStatus.SINGLE_SOURCE, confidence=60, admiralty="A3",
    ))
    second = store.upsert_assessment(first.model_copy(update={
        "status": AssessmentStatus.CORROBORATED, "confidence": 84, "admiralty": "A2",
    }))
    assert second.id == first.id
    assert second.confidence == 84
    assert [a.id for a in store.assessments_involving(tech.id)] == [first.id]
    store.delete_assessment(actor.id, "uses", tech.id)
    assert store.assessments_involving(actor.id) == []


def test_delete_claims_for_document_returns_touched_keys_and_forgets_aliases(store, new_doc):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    tech = store.create_entity("attack-pattern", "Phishing", AliasOrigin.ATTACK, external_id="T1566")
    doc, _ = store.add_document(new_doc())
    store.add_claim(doc.id, _draft(), QuoteStatus.VERIFIED, "v1", actor.id, tech.id)
    alias_claim = store.add_claim(
        doc.id,
        _draft(subject="Muddled Libra", predicate="alias-of", object="Scattered Spider",
               object_type="intrusion-set", technique_id=None),
        QuoteStatus.VERIFIED, "v1", actor.id, actor.id,
    )
    store.add_alias("Muddled Libra", actor.id, AliasOrigin.DOCUMENT, alias_claim.id)
    assert store.find_by_alias("Muddled Libra").id == actor.id
    touched = store.delete_claims_for_document(doc.id)
    assert touched == {(actor.id, "uses", tech.id)}
    assert store.claims_for_document(doc.id) == []
    assert store.find_by_alias("Muddled Libra") is None


def test_refuting_claims_are_evidence_too(store, new_doc):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    tech = store.create_entity("attack-pattern", "Phishing", AliasOrigin.ATTACK, external_id="T1566")
    doc, _ = store.add_document(new_doc())
    store.add_claim(doc.id, _draft(polarity=Polarity.REFUTES), QuoteStatus.VERIFIED_FUZZY, "v1", actor.id, tech.id)
    [evidence] = store.evidence_for(actor.id, "uses", tech.id)
    assert evidence.polarity is Polarity.REFUTES


def test_alias_kept_when_other_document_supports_it(store, new_doc):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    doc1, _ = store.add_document(new_doc(publisher="Vendor One"))
    doc2, _ = store.add_document(new_doc(publisher="Vendor Two"))

    # Both documents have verified alias-of claims for the same alias
    claim1 = store.add_claim(
        doc1.id,
        _draft(subject="Muddled Libra", predicate="alias-of", object="Scattered Spider",
               object_type="intrusion-set", technique_id=None),
        QuoteStatus.VERIFIED, "v1", actor.id, actor.id,
    )
    claim2 = store.add_claim(
        doc2.id,
        _draft(subject="Muddled Libra", predicate="alias-of", object="Scattered Spider",
               object_type="intrusion-set", technique_id=None),
        QuoteStatus.VERIFIED, "v1", actor.id, actor.id,
    )

    # Register both with DOCUMENT origin
    store.add_alias("Muddled Libra", actor.id, AliasOrigin.DOCUMENT, claim1.id)
    store.add_alias("Muddled Libra", actor.id, AliasOrigin.DOCUMENT, claim2.id)

    # Deleting doc1's claims keeps the alias findable (doc2 still supports it)
    assert store.find_by_alias("Muddled Libra").id == actor.id
    store.delete_claims_for_document(doc1.id)
    assert store.find_by_alias("Muddled Libra").id == actor.id

    # Deleting doc2's claims removes the alias
    store.delete_claims_for_document(doc2.id)
    assert store.find_by_alias("Muddled Libra") is None


def test_a_refuting_alias_claim_does_not_keep_the_alias_alive(store, new_doc):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    asserting, _ = store.add_document(new_doc(publisher="Vendor One"))
    refuting, _ = store.add_document(new_doc(publisher="Vendor Two"))
    alias_of = dict(subject="Muddled Libra", predicate="alias-of", object="Scattered Spider",
                    object_type="intrusion-set", technique_id=None)
    claim = store.add_claim(asserting.id, _draft(**alias_of), QuoteStatus.VERIFIED, "v1", actor.id, actor.id)
    store.add_alias("Muddled Libra", actor.id, AliasOrigin.DOCUMENT, claim.id)
    store.add_claim(
        refuting.id, _draft(polarity=Polarity.REFUTES, **alias_of), QuoteStatus.VERIFIED, "v1", actor.id, actor.id,
    )
    store.delete_claims_for_document(asserting.id)
    assert store.find_by_alias("Muddled Libra") is None


def test_alias_upgraded_from_document_to_user_origin(store, new_doc):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.DOCUMENT)
    doc, _ = store.add_document(new_doc())

    # First, learn the alias from a document
    claim = store.add_claim(
        doc.id,
        _draft(subject="Muddled Libra", predicate="alias-of", object="Scattered Spider",
               object_type="intrusion-set", technique_id=None),
        QuoteStatus.VERIFIED, "v1", actor.id, actor.id,
    )
    store.add_alias("Muddled Libra", actor.id, AliasOrigin.DOCUMENT, claim.id)

    # Then register it with USER origin (higher priority)
    store.add_alias("Muddled Libra", actor.id, AliasOrigin.USER)

    # Deleting the document's claims keeps the alias (now owned by USER)
    store.delete_claims_for_document(doc.id)
    assert store.find_by_alias("Muddled Libra").id == actor.id


def test_attack_origin_not_downgraded_by_document(store, new_doc):
    actor = store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.ATTACK, external_id="attack--1")
    doc, _ = store.add_document(new_doc())

    # First, register the alias with ATTACK origin
    store.add_alias("Muddled Libra", actor.id, AliasOrigin.ATTACK)

    # Then try to register the same alias with DOCUMENT origin and a claim id
    claim = store.add_claim(
        doc.id,
        _draft(subject="Muddled Libra", predicate="alias-of", object="Scattered Spider",
               object_type="intrusion-set", technique_id=None),
        QuoteStatus.VERIFIED, "v1", actor.id, actor.id,
    )
    store.add_alias("Muddled Libra", actor.id, AliasOrigin.DOCUMENT, claim.id)

    # The origin should stay ATTACK, not be downgraded to DOCUMENT
    # Deleting the document's claims keeps the alias
    store.delete_claims_for_document(doc.id)
    assert store.find_by_alias("Muddled Libra").id == actor.id
