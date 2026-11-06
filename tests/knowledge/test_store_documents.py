import sqlite3
from datetime import date

import pytest

from cyllex_argus.knowledge import sqlite_store
from cyllex_argus.knowledge.models import InvestigationState, Stage
from cyllex_argus.knowledge.schema import MIGRATIONS
from cyllex_argus.knowledge.sqlite_store import SQLiteStore


def test_migrations_are_idempotent(tmp_path):
    db = tmp_path / "argus.db"
    SQLiteStore(db).close()
    with SQLiteStore(db) as again:
        assert again.schema_version() == len(MIGRATIONS)


def test_migration_two_adds_the_lookup_indexes(tmp_path):
    with SQLiteStore(tmp_path / "argus.db") as store:
        names = {r[0] for r in store._conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {"assessments_object", "aliases_entity"} <= names


def test_migrations_are_atomic(tmp_path, monkeypatch):
    """Migrations must be all-or-nothing: failed migration leaves db unchanged."""
    db = tmp_path / "argus.db"

    # A database that only has the first migration applied
    monkeypatch.setattr(sqlite_store, "MIGRATIONS", [MIGRATIONS[0]])
    store = SQLiteStore(db)
    store.close()
    assert sqlite3.connect(str(db)).execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1

    # The second migration of ITS list fails halfway
    bad_migrations = [MIGRATIONS[0], "CREATE TABLE extra_ok (id INTEGER); THIS IS NOT SQL;"]
    monkeypatch.setattr(sqlite_store, "MIGRATIONS", bad_migrations)

    with pytest.raises(sqlite3.Error):
        SQLiteStore(db)

    # extra_ok should NOT exist and version should still be 1
    conn = sqlite3.connect(str(db))
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("SELECT * FROM extra_ok").fetchone()
    assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1
    conn.close()

    # With the real MIGRATIONS restored, the store opens fine and upgrades to the latest version
    monkeypatch.setattr(sqlite_store, "MIGRATIONS", MIGRATIONS)
    store = SQLiteStore(db)
    assert store.schema_version() == len(MIGRATIONS)
    store.close()


def test_publishers_are_matched_by_normalized_name(store):
    a = store.get_or_create_publisher("Mandiant", default_reliability="B")
    b = store.get_or_create_publisher(" mandiant ")
    assert a.id == b.id
    assert b.reliability == "B"


def test_set_publisher_reliability(store):
    store.get_or_create_publisher("Unit 42")
    updated = store.set_publisher_reliability("unit 42", "A")
    assert updated.reliability == "A"
    assert [p.name for p in store.list_publishers()] == ["Unit 42"]
    with pytest.raises(KeyError):
        store.set_publisher_reliability("Nobody", "A")


def test_add_document_deduplicates_by_hash_and_canonical_url(store, new_doc):
    first, created = store.add_document(new_doc(content_hash="h1", canonical_url="https://a.com/x"))
    assert created
    same_hash, created = store.add_document(new_doc(content_hash="h1", canonical_url="https://b.com/y"))
    assert not created and same_hash.id == first.id
    same_url, created = store.add_document(new_doc(content_hash="h2", canonical_url="https://a.com/x"))
    assert not created and same_url.id == first.id
    other, created = store.add_document(new_doc(content_hash="h3", canonical_url=None))
    assert created and other.id != first.id


def test_find_document_by_canonical_url(store, new_doc):
    doc, _ = store.add_document(new_doc(canonical_url="https://a.com/x"))
    assert store.find_document_by_canonical_url("https://a.com/x").id == doc.id
    assert store.find_document_by_canonical_url("https://a.com/missing") is None


def test_update_document_content_revives_a_failed_document(store, new_doc):
    failed, _ = store.add_document(
        new_doc(content_hash="failed:x", canonical_url="https://a.com/x", raw_path="", text=""),
        stage=Stage.FAILED, failure_reason="HTTP 503",
    )
    store.set_analysis(failed.id, store.get_or_create_publisher("Microsoft").id, "analyst-v1")
    publisher = store.get_or_create_publisher("Mandiant")
    fresh = new_doc(
        url="https://a.com/x?utm_source=feed", canonical_url="https://a.com/x", title="Fresh title",
        publisher_id=publisher.id, published_at=date(2026, 2, 3), content_hash="real-hash",
        raw_path="raw/real-hash", text="Fresh text",
    )
    revived = store.update_document_content(failed.id, fresh)
    assert store.get_document(failed.id) == revived
    assert revived.id == failed.id
    assert (revived.url, revived.title, revived.publisher_id) == (fresh.url, "Fresh title", publisher.id)
    assert (revived.published_at, revived.content_hash) == (date(2026, 2, 3), "real-hash")
    assert (revived.raw_path, revived.text) == ("raw/real-hash", "Fresh text")
    assert revived.canonical_url == "https://a.com/x"
    assert revived.stage is Stage.COLLECTED
    assert revived.failure_reason is None and revived.analyzed_prompt_version is None
    assert store.add_document(fresh)[0].id == failed.id


def test_update_document_content_returns_the_other_document_that_owns_the_hash(store, new_doc):
    failed, _ = store.add_document(
        new_doc(content_hash="failed:x"), stage=Stage.FAILED, failure_reason="HTTP 503"
    )
    owner, _ = store.add_document(new_doc(content_hash="shared-hash"))
    result = store.update_document_content(failed.id, new_doc(content_hash="shared-hash", title="Other"))
    assert result.id == owner.id and result.title == owner.title
    untouched = store.get_document(failed.id)
    assert untouched.stage is Stage.FAILED and untouched.failure_reason == "HTTP 503"
    assert untouched.content_hash == "failed:x"


def test_document_stage_and_analysis(store, new_doc):
    doc, _ = store.add_document(new_doc())
    assert doc.stage is Stage.COLLECTED
    store.set_stage(doc.id, Stage.FAILED, "HTTP 404")
    failed = store.get_document(doc.id)
    assert failed.stage is Stage.FAILED and failed.failure_reason == "HTTP 404"
    pub = store.get_or_create_publisher("Microsoft")
    store.set_analysis(doc.id, pub.id, "analyst-v1")
    analyzed = store.get_document(doc.id)
    assert analyzed.primary_publisher_id == pub.id
    assert analyzed.analyzed_prompt_version == "analyst-v1"
    assert analyzed.effective_publisher_id == pub.id


def test_investigation_lifecycle(store, new_doc):
    inv = store.create_investigation("Scattered Spider")
    assert inv.state is InvestigationState.RUNNING and not inv.collected
    assert store.open_investigation("scattered-spider").id == inv.id
    doc, _ = store.add_document(new_doc())
    other, _ = store.add_document(new_doc())
    store.link_document(inv.id, doc.id)
    store.link_document(inv.id, doc.id)
    store.link_document(inv.id, other.id)
    store.set_stage(other.id, Stage.FAILED, "boom")
    assert [d.id for d in store.investigation_documents(inv.id)] == [doc.id, other.id]
    assert store.stage_counts(inv.id) == {"collected": 1, "failed": 1}
    assert store.failures(inv.id) == [(other.title, "boom")]
    store.mark_collected(inv.id)
    assert store.get_investigation(inv.id).collected
    store.set_investigation_state(inv.id, InvestigationState.FINISHED)
    finished = store.get_investigation(inv.id)
    assert finished.finished_at is not None
    assert store.open_investigation("Scattered Spider") is None
    assert store.latest_investigation().id == inv.id


def test_migration_four_links_claims_to_investigations_and_keeps_old_claims_null(tmp_path, monkeypatch):
    db = tmp_path / "argus.db"
    monkeypatch.setattr(sqlite_store, "MIGRATIONS", MIGRATIONS[:3])
    with SQLiteStore(db) as old:
        conn = old.connection
        # In SQL, not through the store: the store's methods target the current schema (today
        # `get_or_create_publisher` also writes the publisher's bylines, which migration 15
        # introduces), and this store is deliberately pinned three migrations back.
        conn.execute("INSERT INTO publishers (id, name, name_key) VALUES (1, 'Mandiant', 'mandiant')")
        conn.execute(
            """INSERT INTO documents (id, title, publisher_id, retrieved_at, content_hash, raw_path, text, stage)
               VALUES (1, 'Old', 1, '2025-01-01', 'h', 'r', 't', 'validated')""")
        conn.execute(
            """INSERT INTO claims (document_id, subject_ref, subject_type, predicate, object_ref, object_type,
                   polarity, quote, quote_status, prompt_version)
               VALUES (1, 'A', 'intrusion-set', 'uses', 'B', 'malware', 'asserts', 'q', 'verified', 'v1')""")
        conn.commit()
    monkeypatch.setattr(sqlite_store, "MIGRATIONS", MIGRATIONS)
    with SQLiteStore(db) as upgraded:
        assert upgraded.schema_version() == len(MIGRATIONS)
        assert upgraded.connection.execute("SELECT investigation_id FROM claims").fetchall()[0][0] is None
        [claim] = upgraded.claims_for_document(1)
        assert claim.investigation_id is None
        names = {r[0] for r in upgraded.connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        assert "claims_investigation" in names


def test_add_claim_records_the_investigation_and_deleting_it_nulls_the_link(store, new_doc):
    from cyllex_argus.knowledge.models import AliasOrigin, ClaimDraft, QuoteStatus

    actor = store.create_entity("intrusion-set", "Actor", AliasOrigin.DOCUMENT)
    malware = store.create_entity("malware", "Bad", AliasOrigin.DOCUMENT)
    doc, _ = store.add_document(new_doc())
    investigation = store.create_investigation("Actor", actor.id)
    draft = ClaimDraft(subject="Actor", subject_type="intrusion-set", predicate="uses",
                       object="Bad", object_type="malware", quote="q")
    linked = store.add_claim(doc.id, draft, QuoteStatus.VERIFIED, "v1", actor.id, malware.id, investigation.id)
    plain = store.add_claim(doc.id, draft, QuoteStatus.VERIFIED, "v1", actor.id, malware.id)
    assert linked.investigation_id == investigation.id and plain.investigation_id is None
    store.connection.execute("DELETE FROM investigations WHERE id = ?", (investigation.id,))
    assert [c.investigation_id for c in store.claims_for_document(doc.id)] == [None, None]
