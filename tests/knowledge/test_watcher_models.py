"""Domain models for Watchers."""

from datetime import datetime

from cyllex_argus.knowledge.models import (
    AssessmentStatus,
    ChangeKind,
    SnapshotEntry,
    Watcher,
    WatcherChange,
)


def test_change_kind_has_exactly_five_members():
    assert {k.value for k in ChangeKind} == {
        "new", "new_source", "verified", "weakened", "contested",
    }


def test_watcher_defaults():
    w = Watcher(
        id=1, target="APT29", cron_expr="0 8 * * *",
        next_run_at=datetime(2026, 11, 1, 8, 0), created_at=datetime(2026, 10, 31, 8, 0),
    )
    assert w.enabled is True
    assert w.entity_id is None
    assert w.created_by is None
    assert w.unseen_count == 0


def test_watcher_change_roundtrip():
    c = WatcherChange(
        id=5, watcher_id=1, entity_id="intrusion-set--abc", kind=ChangeKind.VERIFIED,
        ref_key="APT29|uses|oauth-token-theft", subject="APT29", predicate="uses",
        object="OAuth token theft", from_status=AssessmentStatus.SINGLE_SOURCE,
        to_status=AssessmentStatus.CORROBORATED, detected_at=datetime(2026, 10, 31, 10, 0),
    )
    assert c.kind is ChangeKind.VERIFIED
    assert c.to_status is AssessmentStatus.CORROBORATED
    assert c.citation is None


def test_snapshot_entry():
    e = SnapshotEntry(ref_key="APT29|uses|wellmess", status=AssessmentStatus.CORROBORATED)
    assert e.status is AssessmentStatus.CORROBORATED
