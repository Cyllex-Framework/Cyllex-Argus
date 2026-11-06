"""Structured attributes on entities (sector/country for identities) and queries over them."""

from __future__ import annotations

import pytest

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
)


def test_new_entity_starts_with_an_empty_attributes_dict(store):
    e = store.create_entity("identity", "Acme Corp", AliasOrigin.DOCUMENT)
    assert e.attributes == {}


def test_set_entity_attributes_merges_and_persists(store):
    e = store.create_entity("identity", "Acme Corp", AliasOrigin.DOCUMENT)
    updated = store.set_entity_attributes(e.id, sector="energy", country="DE")
    assert updated.attributes == {"sector": "energy", "country": "DE"}
    reread = store.get_entity(e.id)
    assert reread.attributes == {"sector": "energy", "country": "DE"}


def test_set_entity_attributes_drops_a_key_on_none_or_empty(store):
    e = store.create_entity("identity", "Acme Corp", AliasOrigin.DOCUMENT)
    store.set_entity_attributes(e.id, sector="energy", country="DE")
    cleared = store.set_entity_attributes(e.id, sector=None, country="")
    assert cleared.attributes == {}


def test_set_entity_attributes_strips_whitespace(store):
    e = store.create_entity("identity", "Acme Corp", AliasOrigin.DOCUMENT)
    updated = store.set_entity_attributes(e.id, sector="  energy  ")
    assert updated.attributes == {"sector": "energy"}


def test_set_entity_attributes_raises_on_unknown_id(store):
    with pytest.raises(KeyError):
        store.set_entity_attributes("identity--does-not-exist", sector="energy")


def test_identities_matching_filters_by_sector_case_insensitively(store):
    a = store.create_entity("identity", "Acme Energy", AliasOrigin.DOCUMENT)
    b = store.create_entity("identity", "Beta Bank", AliasOrigin.DOCUMENT)
    c = store.create_entity("identity", "Gamma Energy", AliasOrigin.DOCUMENT)
    store.set_entity_attributes(a.id, sector="Energy", country="DE")
    store.set_entity_attributes(b.id, sector="financial-services", country="US")
    store.set_entity_attributes(c.id, sector="energy", country="US")
    hit = {e.canonical_name for e in store.identities_matching(sector="ENERGY")}
    assert hit == {"Acme Energy", "Gamma Energy"}


def test_identities_matching_combines_sector_and_country(store):
    a = store.create_entity("identity", "Acme Energy DE", AliasOrigin.DOCUMENT)
    b = store.create_entity("identity", "Gamma Energy US", AliasOrigin.DOCUMENT)
    store.set_entity_attributes(a.id, sector="energy", country="DE")
    store.set_entity_attributes(b.id, sector="energy", country="US")
    assert [e.canonical_name for e in store.identities_matching(sector="energy", country="us")] == [
        "Gamma Energy US",
    ]


def test_actors_targeting_ranks_by_assessment_count(store, new_doc):
    """An actor with more `targets` assessments against matching identities ranks higher."""
    actor_a = store.create_entity("intrusion-set", "Alpha", AliasOrigin.ATTACK)
    actor_b = store.create_entity("intrusion-set", "Beta", AliasOrigin.ATTACK)
    bank_1 = store.create_entity("identity", "Bank One", AliasOrigin.DOCUMENT)
    bank_2 = store.create_entity("identity", "Bank Two", AliasOrigin.DOCUMENT)
    unrelated = store.create_entity("identity", "Hospital", AliasOrigin.DOCUMENT)
    for ident in (bank_1, bank_2):
        store.set_entity_attributes(ident.id, sector="financial-services", country="US")
    store.set_entity_attributes(unrelated.id, sector="healthcare", country="US")

    def _asmt(subj_id: str, obj_id: str) -> None:
        store.upsert_assessment(Assessment(
            subject_entity_id=subj_id, predicate="targets", object_entity_id=obj_id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
    _asmt(actor_a.id, bank_1.id)
    _asmt(actor_a.id, bank_2.id)
    _asmt(actor_b.id, bank_1.id)
    _asmt(actor_a.id, unrelated.id)   # not a bank — must not count under sector='financial-services'

    ranked = store.actors_targeting(sector="financial-services")
    assert [(a.canonical_name, n) for a, n in ranked] == [("Alpha", 2), ("Beta", 1)]


def test_actors_targeting_without_filter_returns_empty_list(store):
    """`identities_matching` with no identities tagged returns []; `actors_targeting` must not crash."""
    assert store.actors_targeting(sector="energy") == []
