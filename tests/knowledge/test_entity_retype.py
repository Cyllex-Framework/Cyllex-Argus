"""SQLiteStore.retype_entity() — in-place type change with cascading FK updates."""

from __future__ import annotations

import pytest

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
)
from tests.support import World


def _store(world: World):
    return world.services().store


def test_retype_swaps_type_and_regenerates_id(world):
    svc = world.services()
    try:
        s = svc.store
        # LLM mistyped "AWS" as an identity. Reclassify as tool.
        aws = s.create_entity("identity", "AWS", AliasOrigin.DOCUMENT)
        new = s.retype_entity(aws.id, "tool")
        assert new.stix_type == "tool"
        assert new.canonical_name == "AWS"
        assert new.id.startswith("tool--")
        # Same UUID suffix.
        assert new.id.split("--", 1)[1] == aws.id.split("--", 1)[1]
        assert s.get_entity(aws.id) is None  # old row gone
    finally:
        svc.close()


def test_retype_rewrites_assessment_fks(world):
    svc = world.services()
    try:
        s = svc.store
        actor = s.create_entity("intrusion-set", "ZetaActor", AliasOrigin.ATTACK)
        aws = s.create_entity("identity", "AWS", AliasOrigin.DOCUMENT)
        s.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=aws.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
        new = s.retype_entity(aws.id, "tool")
        # The assessment now points at the new typed id.
        rows = s.assessments_involving(actor.id)
        assert len(rows) == 1
        assert rows[0].object_entity_id == new.id
    finally:
        svc.close()


def test_retype_rewrites_claim_fks(world):
    svc = world.services()
    try:
        s = svc.store
        actor = s.create_entity("intrusion-set", "ZetaActor", AliasOrigin.ATTACK)
        aws = s.create_entity("identity", "AWS", AliasOrigin.DOCUMENT)
        # Seed a document so the claim's FK is satisfied, then a claim pointing at `aws`
        # as the object. Directly SQL-insert to keep the test tight to the FK-rewrite
        # concern rather than the whole validator flow.
        conn = s.connection
        pub = s.get_or_create_publisher("P", default_reliability="C")
        conn.execute(
            "INSERT INTO documents (id, publisher_id, title, content_hash, raw_path, text, stage, retrieved_at) "
            "VALUES (1, ?, 'doc', 'h', '', 't', 'validated', '2026-01-01T00:00:00+00:00')",
            (pub.id,),
        )
        conn.execute(
            "INSERT INTO claims (document_id, subject_ref, subject_type, predicate, object_ref, "
            "object_type, polarity, quote, quote_status, prompt_version, subject_entity_id, "
            "object_entity_id) "
            "VALUES (1, 'ZetaActor', 'intrusion-set', 'uses', 'AWS', 'identity', 'asserts', 'q', "
            "'validated', 'v1', ?, ?)",
            (actor.id, aws.id),
        )
        conn.commit()
        new = s.retype_entity(aws.id, "tool")
        row = conn.execute(
            "SELECT subject_entity_id, object_entity_id FROM claims WHERE object_ref='AWS'",
        ).fetchone()
        assert row[0] == actor.id
        assert row[1] == new.id
    finally:
        svc.close()


def test_retype_rewrites_aliases(world):
    svc = world.services()
    try:
        s = svc.store
        aws = s.create_entity("identity", "AWS", AliasOrigin.DOCUMENT)
        s.add_alias("Amazon Web Services", aws.id, AliasOrigin.DOCUMENT, None)
        new = s.retype_entity(aws.id, "tool")
        aliases = s.aliases_for(new.id)
        assert "Amazon Web Services" in aliases
    finally:
        svc.close()


def test_retype_rejects_identical_type(world):
    svc = world.services()
    try:
        s = svc.store
        e = s.create_entity("identity", "ACME", AliasOrigin.DOCUMENT)
        with pytest.raises(ValueError, match="already"):
            s.retype_entity(e.id, "identity")
    finally:
        svc.close()


def test_retype_rejects_unknown_entity(world):
    svc = world.services()
    try:
        with pytest.raises(KeyError):
            svc.store.retype_entity("identity--does-not-exist", "tool")
    finally:
        svc.close()


def test_retype_rejects_untyped_target(world):
    svc = world.services()
    try:
        s = svc.store
        e = s.create_entity("identity", "ACME", AliasOrigin.DOCUMENT)
        with pytest.raises(ValueError, match="not retype-able"):
            s.retype_entity(e.id, "attack-pattern")  # excluded on purpose
    finally:
        svc.close()


def test_retype_rejects_attack_origin_entity(world):
    """ATT&CK-origin entities must stay as the type MITRE assigned, otherwise their alias
    from the ATT&CK bundle gets mislabelled on the next sync."""
    svc = world.services()
    try:
        s = svc.store
        e = s.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.ATTACK)
        s.add_alias("Octo Tempest", e.id, AliasOrigin.ATTACK, None)
        with pytest.raises(ValueError, match="ATT&CK"):
            s.retype_entity(e.id, "malware")
    finally:
        svc.close()


def test_retype_rewrites_investigation_resolved_entity_id(world):
    svc = world.services()
    try:
        s = svc.store
        aws = s.create_entity("identity", "AWS", AliasOrigin.DOCUMENT)
        inv = s.create_investigation("aws-recon", aws.id)
        new = s.retype_entity(aws.id, "tool")
        fresh = s.get_investigation(inv.id)
        assert fresh.resolved_entity_id == new.id
    finally:
        svc.close()
