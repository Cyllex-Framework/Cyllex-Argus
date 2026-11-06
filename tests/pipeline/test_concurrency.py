"""Invariants the `--concurrency > 1` path has to hold.

The store serialises every individual statement (`_LockedConnection`), which is enough to keep
SQLite from tripping `InterfaceError`, but it does NOT make a read-then-write pair atomic. Two
worker threads can both read "this entity does not exist yet" and both insert it. The damage is
not a crash — it is wrong intelligence: the two documents that corroborate each other end up
attached to two different actor entities, so a corroborated assessment is stored as two
single-source ones at confidence 15.

Measured on the pre-fix code: ~4 in 25 full investigations at `concurrency=3` produced a
duplicate `intrusion-set` for the target and split its corroboration.
"""

from __future__ import annotations

import threading
from datetime import date

import pytest

from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.pipeline.validator import ValidationSummary, Validator

THREADS = 8


def _run_together(work, threads: int = THREADS):
    """Run `work(index)` on N threads released from a barrier, so they collide on purpose.

    The barrier is placed BEFORE the call under test, never inside it: a barrier in the middle
    of a critical section would deadlock against the very lock these tests exist to require.
    """
    start = threading.Barrier(threads)
    results: list = [None] * threads
    errors: list[BaseException] = []

    def body(index: int) -> None:
        try:
            start.wait(timeout=10)
            results[index] = work(index)
        except BaseException as exc:  # noqa: BLE001 — surfaced below so the test reports it
            errors.append(exc)

    workers = [threading.Thread(target=body, args=(i,)) for i in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)
    assert not errors, f"worker raised: {errors[0]!r}"
    assert all(worker.is_alive() is False for worker in workers), "a worker did not finish"
    return results


@pytest.fixture
def validator(attack_store, attack_catalog):
    return Validator(attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29))


def test_concurrent_resolve_of_the_same_name_yields_one_entity(validator, attack_store):
    """Find-then-create must be atomic, or corroboration silently splits in two."""
    ids = _run_together(lambda _: validator._resolve("Fresh Actor", "intrusion-set", None).id)

    assert len(set(ids)) == 1, f"the same name resolved to {len(set(ids))} different entities: {set(ids)}"
    rows = attack_store.connection.execute(
        "SELECT id FROM entities WHERE lower(canonical_name) = 'fresh actor'",
    ).fetchall()
    assert len(rows) == 1, f"{len(rows)} duplicate entities were created"


def test_concurrent_resolve_still_finds_an_entity_the_catalog_already_knows(validator, attack_store):
    """The fix must not turn a hit into a miss: an ATT&CK-known actor stays the catalog entity."""
    ids = _run_together(lambda _: validator._resolve("Scattered Spider", "intrusion-set", None).id)
    assert len(set(ids)) == 1
    [known] = set(ids)
    entity = attack_store.get_entity(known)
    assert entity is not None and entity.canonical_name == "Scattered Spider"
    # The catalog entity, not a fresh document-origin duplicate of it.
    assert attack_store.connection.execute(
        "SELECT COUNT(*) FROM entities WHERE lower(canonical_name) = 'scattered spider'",
    ).fetchone()[0] == 1


def test_concurrent_publisher_creation_yields_one_row(store):
    """`get_or_create_publisher` runs on the thread pool (the Analyst reports the primary
    publisher per document), and publisher identity is what independent-source counting —
    and therefore corroboration — is computed from."""
    ids = _run_together(lambda _: store.get_or_create_publisher("Acme Threat Labs").id)

    assert len(set(ids)) == 1, f"one publisher name produced {len(set(ids))} rows: {set(ids)}"
    assert store.connection.execute(
        "SELECT COUNT(*) FROM publishers WHERE name_key = 'acme threat labs'",
    ).fetchone()[0] == 1


def test_merging_validation_summaries_from_threads_loses_no_claim():
    """`summary.accepted += batch.accepted` is a read-modify-write: two threads that merge at
    the same moment lose one of the increments, and the run under-reports what it accepted."""
    total = ValidationSummary()
    batches = []
    for index in range(THREADS):
        batch = ValidationSummary(accepted=2, rejected=1)
        batch.touched.add((f"subject-{index}", "uses", "object-1"))
        batches.append(batch)

    _run_together(lambda index: total.merge(batches[index]))

    assert total.accepted == 2 * THREADS
    assert total.rejected == THREADS
    assert len(total.touched) == THREADS


# -- the recompute lost-update race -------------------------------------------------------------
#
# `Validator.recompute` reads the evidence for a fact, scores it, and writes the assessment. The
# three steps are each locked individually by `_LockedConnection`, but the read-score-write as a
# whole was NOT atomic. Two documents that corroborate the same fact, processed on two worker
# threads, could interleave so the second writer scores a STALE one-supporter read and its upsert
# lands last, clobbering the correct CORROBORATED verdict with SINGLE_SOURCE. Measured ~2 in 12
# full investigations at concurrency=3 on the pre-fix code.

_CORROBORATION_TEXT = (
    "Octo Tempest operators called the IT help desk and impersonated an employee to reset MFA."
)


def _uses_voice_draft():
    from cyllex_argus.knowledge.models import ClaimDraft
    return ClaimDraft(
        subject="Octo Tempest", subject_type="intrusion-set", predicate="uses",
        object="Spearphishing Voice", object_type="attack-pattern",
        quote="called the IT help desk and impersonated an employee", technique_id="T1566.004",
    )


def test_concurrent_corroboration_is_not_lost_to_a_stale_recompute(validator, attack_store, new_doc, monkeypatch):
    """Two publishers corroborate one fact on two threads; the final assessment must be
    CORROBORATED. The failure is a lost update: the slow writer scores a one-supporter read and
    overwrites the correct two-supporter verdict.

    Determinism: the first `score` call signals it has read, then sleeps. In the pre-fix code
    that widens the read->write window so the stale write reliably lands last; in the fixed code
    the sleep happens while `recompute` holds the store lock, so the other thread's `add_claim`
    waits and the last recompute always reads both supporters. No timing luck either way.
    """
    import threading
    import time

    from cyllex_argus.knowledge.models import AssessmentStatus
    from cyllex_argus.pipeline import validator as validator_mod

    doc_a, _ = attack_store.add_document(new_doc(publisher="Mandiant", reliability="A", text=_CORROBORATION_TEXT))
    doc_b, _ = attack_store.add_document(new_doc(publisher="CrowdStrike", reliability="A", text=_CORROBORATION_TEXT))

    real_score = validator_mod.score
    has_read = threading.Event()
    calls = {"n": 0}
    guard = threading.Lock()

    def slow_first_score(*args, **kwargs):
        with guard:
            first = calls["n"] == 0
            calls["n"] += 1
        if first:
            has_read.set()   # thread A has just read its (one-supporter) evidence
            time.sleep(0.4)  # hold the window / the store lock open
        return real_score(*args, **kwargs)

    monkeypatch.setattr(validator_mod, "score", slow_first_score)

    def process_a():
        validator.process(doc_a, [_uses_voice_draft()], "analyst-v1")

    def process_b():
        has_read.wait(timeout=5)  # do not add B's claim until A has read, so A's read sees 1
        validator.process(doc_b, [_uses_voice_draft()], "analyst-v1")

    ta = threading.Thread(target=process_a)
    tb = threading.Thread(target=process_b)
    ta.start()
    tb.start()
    ta.join(timeout=10)
    tb.join(timeout=10)
    assert not ta.is_alive() and not tb.is_alive(), "a worker deadlocked"

    [assessment] = attack_store.assessments_involving(SPIDER)
    assert assessment.status is AssessmentStatus.CORROBORATED, (
        f"corroboration was lost to a stale recompute: status is {assessment.status}"
    )


SPIDER = "intrusion-set--00000000-0000-4000-8000-000000001015"
