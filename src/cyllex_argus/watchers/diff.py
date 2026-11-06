"""The deterministic watcher diff: compare an entity's current assessed facts against the
watcher's previous snapshot and emit change events. Pure — no store, no network, no LLM."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from cyllex_argus.config.settings import Reliability
from cyllex_argus.knowledge.models import AssessmentStatus, ChangeKind, Citation, Polarity, WatcherChange
from cyllex_argus.knowledge.profile import FactView

_GRADES = "ABCDEF"


def _ref_key(fact: FactView) -> str:
    return f"{fact.subject.id}|{fact.predicate}|{fact.object.id}"


def _reliability(admiralty: str) -> str:
    """The source-reliability letter of an Admiralty code (e.g. 'B2' -> 'B'). Unknown -> 'F'."""
    letter = (admiralty[:1] or "F").upper()
    return letter if letter in _GRADES else "F"


def _passes_floor(fact: FactView, min_reliability: Reliability) -> bool:
    return _GRADES.index(_reliability(fact.admiralty)) <= _GRADES.index(min_reliability.upper())


def snapshot_of(facts: Iterable[FactView]) -> dict[str, AssessmentStatus]:
    """Build the ref_key -> status map this diff compares against."""
    return {_ref_key(f): f.status for f in facts}


def floor_eligible(facts: Iterable[FactView], min_reliability: Reliability) -> list[FactView]:
    """The facts whose source reliability clears the floor. The snapshot is built from these,
    not from every fact: a below-floor fact must stay out of the snapshot so that when it later
    crosses the floor it is reported as NEW instead of being silently treated as already-known."""
    return [f for f in facts if _passes_floor(f, min_reliability)]


def _pick_citation(fact: FactView, kind: ChangeKind) -> Citation | None:
    want = Polarity.REFUTES if kind is ChangeKind.CONTESTED else Polarity.ASSERTS
    for c in fact.citations:
        if c.polarity is want:
            return c
    return fact.citations[0] if fact.citations else None


def _transition_kind(current: AssessmentStatus) -> ChangeKind:
    if current is AssessmentStatus.CONTESTED:
        return ChangeKind.CONTESTED
    if current is AssessmentStatus.CORROBORATED:
        return ChangeKind.VERIFIED
    return ChangeKind.WEAKENED  # moved down to single-source


def _change(fact: FactView, kind: ChangeKind, prev: AssessmentStatus | None, now: datetime) -> WatcherChange:
    return WatcherChange(
        id=0, watcher_id=0, kind=kind, ref_key=_ref_key(fact),
        subject=fact.subject.label, predicate=fact.predicate, object=fact.object.label,
        from_status=prev, to_status=fact.status, citation=_pick_citation(fact, kind), detected_at=now,
    )


def diff(
    previous: dict[str, AssessmentStatus], current_facts: Iterable[FactView], *,
    min_reliability: Reliability, baseline: bool, baseline_cap: int = 25,
    now: datetime | None = None,
) -> list[WatcherChange]:
    """Change events between `previous` (ref_key -> status) and the current facts.

    Only facts whose source reliability clears `min_reliability` are considered. A `baseline`
    run (empty prior snapshot, first time) emits NEW for current facts, capped and ordered
    highest-reliability / most-recent first, and no transitions. NEW_SOURCE is not produced here.
    """
    now = now or datetime.now(UTC)
    eligible = [f for f in current_facts if _passes_floor(f, min_reliability)]

    if baseline:
        news = [f for f in eligible if _ref_key(f) not in previous]
        news.sort(key=lambda f: (
            _GRADES.index(_reliability(f.admiralty)),
            -(f.last_seen.toordinal() if f.last_seen else 0),
        ))
        return [_change(f, ChangeKind.NEW, None, now) for f in news[:baseline_cap]]

    out: list[WatcherChange] = []
    for f in eligible:
        key = _ref_key(f)
        prev = previous.get(key)
        if prev is None:
            out.append(_change(f, ChangeKind.NEW, None, now))
        elif prev != f.status:
            out.append(_change(f, _transition_kind(f.status), prev, now))
    return out
