"""Store methods for migrating sector-identity entities to actor attributes."""

from __future__ import annotations

import pytest

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
)


def test_append_sector_adds_to_actor_attributes(world):
    svc = world.services()
    try:
        s = svc.store
        actor = s.create_entity("intrusion-set", "ZetaActor", AliasOrigin.ATTACK)
        updated = s.append_entity_sector(actor.id, "healthcare")
        assert updated.attributes.get("sectors") == ["healthcare"]
    finally:
        svc.close()


def test_append_sector_is_case_insensitive_dedupe(world):
    svc = world.services()
    try:
        s = svc.store
        actor = s.create_entity("intrusion-set", "ZetaActor", AliasOrigin.ATTACK)
        s.append_entity_sector(actor.id, "healthcare")
        s.append_entity_sector(actor.id, "Healthcare")  # dupe, dropped
        s.append_entity_sector(actor.id, "retail")      # new
        updated = s.get_entity(actor.id)
        assert updated.attributes.get("sectors") == ["healthcare", "retail"]
    finally:
        svc.close()


def test_append_sector_coexists_with_other_attributes(world):
    svc = world.services()
    try:
        s = svc.store
        identity = s.create_entity("identity", "ACME Health", AliasOrigin.DOCUMENT)
        s.set_entity_attributes(identity.id, country="US")
        s.append_entity_sector(identity.id, "healthcare")
        updated = s.get_entity(identity.id)
        assert updated.attributes == {"country": "US", "sectors": ["healthcare"]}
    finally:
        svc.close()


def test_append_sector_unknown_entity(world):
    svc = world.services()
    try:
        with pytest.raises(KeyError):
            svc.store.append_entity_sector("intrusion-set--does-not-exist", "healthcare")
    finally:
        svc.close()


def test_actors_targeting_returns_only_actor_shaped_entities(world):
    svc = world.services()
    try:
        s = svc.store
        actor = s.create_entity("intrusion-set", "ZetaActor", AliasOrigin.ATTACK)
        malware = s.create_entity("malware", "ZetaBot", AliasOrigin.ATTACK)
        healthcare = s.create_entity("identity", "healthcare", AliasOrigin.DOCUMENT)
        unrelated = s.create_entity("identity", "ACME Corp", AliasOrigin.DOCUMENT)
        s.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="targets", object_entity_id=healthcare.id,
            status=AssessmentStatus.CORROBORATED, confidence=70, admiralty="B2",
        ))
        s.upsert_assessment(Assessment(
            subject_entity_id=malware.id, predicate="targets", object_entity_id=healthcare.id,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3",
        ))
        # A `uses` assessment should NOT make the actor eligible (we only want `targets`).
        s.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=unrelated.id,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3",
        ))
        actors = s.actors_targeting_identity(healthcare.id)
        actor_names = sorted(a.canonical_name for a in actors)
        assert actor_names == ["ZetaActor", "ZetaBot"]
    finally:
        svc.close()


def test_delete_entity_cascading_removes_claims_and_assessments(world):
    svc = world.services()
    try:
        s = svc.store
        actor = s.create_entity("intrusion-set", "ZetaActor", AliasOrigin.ATTACK)
        healthcare = s.create_entity("identity", "healthcare", AliasOrigin.DOCUMENT)
        s.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="targets", object_entity_id=healthcare.id,
            status=AssessmentStatus.CORROBORATED, confidence=70, admiralty="B2",
        ))
        s.add_alias("Healthcare Sector", healthcare.id, AliasOrigin.DOCUMENT, None)
        s.delete_entity_cascading(healthcare.id)
        # Entity gone.
        assert s.get_entity(healthcare.id) is None
        # Assessments gone (the actor still exists but no longer targets healthcare).
        assert s.assessments_involving(actor.id) == []
        # Aliases of the deleted entity gone.
        assert s.aliases_for(healthcare.id) == []
    finally:
        svc.close()


def test_delete_entity_cascading_unknown_raises(world):
    svc = world.services()
    try:
        with pytest.raises(KeyError):
            svc.store.delete_entity_cascading("identity--does-not-exist")
    finally:
        svc.close()
