"""Store methods for watcher snapshots, change events, and per-user seen state."""

from datetime import datetime

from cyllex_argus.knowledge.models import (
    AssessmentStatus,
    ChangeKind,
    Citation,
    Polarity,
    QuoteStatus,
    Role,
    WatcherChange,
)


def _setup(store):
    uid = store.create_user("alice", "h", Role.OPERATOR).id
    w = store.create_watcher(
        target="APT29", cron_expr="0 8 * * *", created_by=uid,
        next_run_at=datetime(2026, 11, 1, 8, 0),
    )
    return uid, w


def _change(kind=ChangeKind.NEW, ref_key="k", citation=None):
    return WatcherChange(
        id=0, watcher_id=0, kind=kind, ref_key=ref_key, citation=citation,
        detected_at=datetime(2026, 10, 31, 10, 0),
    )


def test_snapshot_replace_and_get_roundtrip(store):
    _, w = _setup(store)
    store.replace_snapshot(w.id, {"k1": AssessmentStatus.CORROBORATED, "k2": AssessmentStatus.SINGLE_SOURCE})
    assert store.get_snapshot(w.id) == {
        "k1": AssessmentStatus.CORROBORATED, "k2": AssessmentStatus.SINGLE_SOURCE,
    }
    # A second replace fully supersedes the first.
    store.replace_snapshot(w.id, {"k3": AssessmentStatus.CONTESTED})
    assert store.get_snapshot(w.id) == {"k3": AssessmentStatus.CONTESTED}


def test_add_changes_returns_ids_and_lists_newest_first(store):
    _, w = _setup(store)
    ids = store.add_changes(w.id, [_change(ref_key="a"), _change(ref_key="b"), _change(ref_key="c")])
    assert len(ids) == 3
    listed = store.list_changes(watcher_id=w.id, limit=10)
    assert [c.ref_key for c in listed] == ["c", "b", "a"]  # newest first


def test_citation_roundtrips(store):
    _, w = _setup(store)
    cit = Citation(
        claim_id=1, quote="verbatim", quote_status=QuoteStatus.VERIFIED, polarity=Polarity.ASSERTS,
        document_title="Advisory", publisher="CISA",
    )
    store.add_changes(w.id, [_change(citation=cit)])
    got = store.list_changes(watcher_id=w.id, limit=1)[0]
    assert got.citation is not None
    assert got.citation.quote == "verbatim"
    assert got.citation.publisher == "CISA"


def test_undelivered_and_mark_delivered(store):
    _, w = _setup(store)
    ids = store.add_changes(w.id, [_change(ref_key="a"), _change(ref_key="b")])
    assert {c.id for c in store.undelivered_changes()} == set(ids)
    store.mark_delivered([ids[0]], ["webhook:soc"])
    assert {c.id for c in store.undelivered_changes()} == {ids[1]}


def test_unseen_is_per_user(store):
    a, w = _setup(store)
    b = store.create_user("bob", "h", Role.READER).id
    ids = store.add_changes(w.id, [_change(ref_key="a"), _change(ref_key="b"), _change(ref_key="c")])
    assert store.unseen_count(a, w.id) == 3
    assert store.unseen_count(b, w.id) == 3
    store.set_seen(a, w.id, ids[-1])
    assert store.unseen_count(a, w.id) == 0
    assert store.unseen_count(b, w.id) == 3  # B unaffected
    assert store.unseen_counts(b) == {w.id: 3}
