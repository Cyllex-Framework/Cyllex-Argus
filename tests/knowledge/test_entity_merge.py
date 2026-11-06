"""Entity ghost → MITRE merge. The feature exists because when an operator ran
investigations BEFORE a complete `attack update`, the Analyst stage created document-
origin entities for every group name it saw (one entity for "Midnight Blizzard", one for
"Nobelium", one for "APT29"). Once `attack update` later populates the canonical G0016
entity, future queries resolve correctly but the historical facts stay stuck on the
ghosts — the Threat profile for G0016 then shows partial data and fractured attribution.
"""

from __future__ import annotations

import pytest

from cyllex_argus.knowledge.entity_merge import find_mergeable
from cyllex_argus.knowledge.models import AliasOrigin
from cyllex_argus.knowledge.sqlite_store import SQLiteStore


@pytest.fixture
def store(tmp_path):
    s = SQLiteStore(tmp_path / "store.db")
    yield s
    s.close()


def _seed_entity(store: SQLiteStore, entity_id: str, name: str, external_id: str | None = None):
    """Insert an entity row with explicit id + external_id, so we can simulate the ghost
    (external_id=NULL) vs catalog (external_id=G0016) shape without going through
    create_entity's auto-id generation."""
    conn = store.connection
    conn.execute(
        "INSERT INTO entities(id, stix_type, canonical_name, external_id) VALUES (?, 'intrusion-set', ?, ?)",
        (entity_id, name, external_id),
    )
    conn.commit()


def _seed_alias(store: SQLiteStore, alias: str, entity_id: str,
                origin: AliasOrigin = AliasOrigin.DOCUMENT) -> None:
    store.add_alias(alias, entity_id, origin)


def _seed_doc_if_missing(store: SQLiteStore, document_id: int = 1) -> None:
    """A claim FK-points at documents; insert a stub row (plus a stub publisher the
    document FK-requires) keyed on the id the caller uses."""
    conn = store.connection
    exists = conn.execute("SELECT 1 FROM documents WHERE id = ?", (document_id,)).fetchone()
    if exists is None:
        pub = conn.execute(
            "INSERT INTO publishers(name, name_key, domain, reliability) "
            "VALUES ('Test', 'test', 'example.test', 'C') RETURNING id"
        ).fetchone()
        conn.execute(
            """INSERT INTO documents(id, url, canonical_url, title, stage, text, publisher_id,
                                     retrieved_at, content_hash, raw_path)
               VALUES (?, 'https://example.test/x', 'https://example.test/x', 'Test',
                       'validated', 'body', ?, '2026-01-01', 'hash', '/tmp/x')""",
            (document_id, pub["id"]),
        )
        conn.commit()


def _seed_claim(store: SQLiteStore, subject_entity_id: str, object_entity_id: str,
                predicate: str = "uses", document_id: int = 1,
                technique_id: str | None = None) -> int:
    """Insert a claim pointing at the given entities. Transparently creates a stub
    document row because the claims table FK-requires it."""
    _seed_doc_if_missing(store, document_id)
    conn = store.connection
    cur = conn.execute(
        """INSERT INTO claims(document_id, subject_ref, subject_type, predicate, object_ref,
                              object_type, polarity, quote, quote_status,
                              subject_entity_id, object_entity_id, prompt_version, technique_id)
           VALUES (?, 'ignored', 'intrusion-set', ?, 'ignored', 'attack-pattern',
                   'asserts', 'q', 'accepted', ?, ?, 'test-v1', ?)""",
        (document_id, predicate, subject_entity_id, object_entity_id, technique_id),
    )
    conn.commit()
    return cur.lastrowid


def _seed_assessment(store: SQLiteStore, subject_entity_id: str, object_entity_id: str,
                     predicate: str = "uses", confidence: int = 30,
                     status: str = "single-source") -> int:
    conn = store.connection
    cur = conn.execute(
        """INSERT INTO assessments(subject_entity_id, predicate, object_entity_id,
                                   status, confidence, admiralty, updated_at)
           VALUES (?, ?, ?, ?, ?, 'F3', '2026-01-01')""",
        (subject_entity_id, predicate, object_entity_id, status, confidence),
    )
    conn.commit()
    return cur.lastrowid


# ---- find_mergeable --------------------------------------------------------------

def test_finds_a_ghost_sharing_an_alias_with_a_catalog_entity(store):
    """The core case the feature exists for: 'Midnight Blizzard' (document origin, no
    external_id) and APT29 (ATT&CK origin, G0016) share the alias 'Midnight Blizzard'.
    find_mergeable should flag the ghost for merging into APT29."""
    _seed_entity(store, "intrusion-set--ghost", "Midnight Blizzard", external_id=None)
    _seed_entity(store, "intrusion-set--canonical", "APT29", external_id="G0016")
    _seed_alias(store, "Midnight Blizzard", "intrusion-set--ghost", AliasOrigin.DOCUMENT)
    _seed_alias(store, "Midnight Blizzard", "intrusion-set--canonical", AliasOrigin.ATTACK)
    _seed_alias(store, "APT29", "intrusion-set--canonical", AliasOrigin.ATTACK)

    candidates = find_mergeable(store.connection)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.ghost_id == "intrusion-set--ghost"
    assert c.canonical_id == "intrusion-set--canonical"
    assert c.canonical_external_id == "G0016"
    assert "midnight blizzard" in c.shared_aliases


def test_no_candidates_when_no_aliases_overlap(store):
    """Two unrelated entities with distinct aliases should not surface — the feature only
    acts on evidence of same-group-ness (alias overlap), not just same stix_type."""
    _seed_entity(store, "intrusion-set--a", "Ghost A", external_id=None)
    _seed_entity(store, "intrusion-set--b", "Canonical B", external_id="G9999")
    _seed_alias(store, "Only here", "intrusion-set--a", AliasOrigin.DOCUMENT)
    _seed_alias(store, "Only there", "intrusion-set--b", AliasOrigin.ATTACK)

    assert find_mergeable(store.connection) == []


def test_two_catalog_entities_sharing_alias_is_ambiguous_and_skipped(store):
    """If a ghost's alias matches TWO different catalog entities (e.g. the Analyst
    extracted "Hidden Cobra" and both Lazarus G0032 AND some other group ship that alias),
    we don't guess — leave the ghost alone so an operator can disambiguate manually."""
    _seed_entity(store, "intrusion-set--ghost", "Shared Name", external_id=None)
    _seed_entity(store, "intrusion-set--cat1", "Group One", external_id="G0001")
    _seed_entity(store, "intrusion-set--cat2", "Group Two", external_id="G0002")
    _seed_alias(store, "Shared Name", "intrusion-set--ghost", AliasOrigin.DOCUMENT)
    _seed_alias(store, "Shared Name", "intrusion-set--cat1", AliasOrigin.ATTACK)
    _seed_alias(store, "Shared Name", "intrusion-set--cat2", AliasOrigin.ATTACK)

    assert find_mergeable(store.connection) == []


def test_ghost_to_ghost_overlap_is_not_a_merge_target(store):
    """Two ghosts sharing an alias isn't a merge opportunity — neither is more authoritative.
    We only merge INTO catalog entities (external_id set), never ghost-to-ghost."""
    _seed_entity(store, "intrusion-set--ghost-a", "Ghost A", external_id=None)
    _seed_entity(store, "intrusion-set--ghost-b", "Ghost B", external_id=None)
    _seed_alias(store, "Same", "intrusion-set--ghost-a", AliasOrigin.DOCUMENT)
    _seed_alias(store, "Same", "intrusion-set--ghost-b", AliasOrigin.DOCUMENT)

    assert find_mergeable(store.connection) == []


def test_candidates_are_sorted_deterministically(store):
    """find_mergeable returns results sorted by canonical_name then ghost_name, so a
    repeated run against the same DB yields the same output — the operator can compare."""
    _seed_entity(store, "intrusion-set--zig", "Zebra Ghost", external_id=None)
    _seed_entity(store, "intrusion-set--zcanon", "Zebra Canonical", external_id="G0999")
    _seed_alias(store, "Zebra", "intrusion-set--zig", AliasOrigin.DOCUMENT)
    _seed_alias(store, "Zebra", "intrusion-set--zcanon", AliasOrigin.ATTACK)
    _seed_entity(store, "intrusion-set--aghost", "Alpha Ghost", external_id=None)
    _seed_entity(store, "intrusion-set--acanon", "Alpha Canonical", external_id="G0001")
    _seed_alias(store, "Alpha", "intrusion-set--aghost", AliasOrigin.DOCUMENT)
    _seed_alias(store, "Alpha", "intrusion-set--acanon", AliasOrigin.ATTACK)

    canonicals = [c.canonical_name for c in find_mergeable(store.connection)]
    assert canonicals == ["Alpha Canonical", "Zebra Canonical"]


