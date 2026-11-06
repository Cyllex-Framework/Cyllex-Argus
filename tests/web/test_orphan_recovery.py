"""Startup orphan recovery: RUNNING investigations from a dead process must flip to PAUSED.
Also the sibling catalog-load guard that auto-triggers `attack update` on a fresh install.
"""

from __future__ import annotations

from cyllex_argus.attack.catalog import MIN_LOADED_GROUPS
from cyllex_argus.knowledge.models import InvestigationState
from cyllex_argus.web.app import (
    _ensure_attack_catalog_loaded,
    _recover_orphan_investigations,
)
from tests.support import World


def _state_of(world: World, inv_id: int) -> InvestigationState:
    services = world.services()
    try:
        inv = services.store.get_investigation(inv_id)
    finally:
        services.close()
    assert inv is not None
    return inv.state


def test_running_investigation_is_flipped_to_paused_on_restart(world: World):
    """Core case: a RUNNING row left behind by the previous `argus serve` process gets
    recovered on the next startup. Without this the UI shows "RUNNING 23m" forever."""
    services = world.services()
    try:
        inv = services.store.create_investigation(target="scattered spider")
    finally:
        services.close()
    assert _state_of(world, inv.id) is InvestigationState.RUNNING

    count = _recover_orphan_investigations(world.services)

    assert count == 1
    assert _state_of(world, inv.id) is InvestigationState.PAUSED


def test_recovery_is_idempotent(world: World):
    """Running recovery twice in a row (second serve restart without a new investigation) must
    not count the already-paused row again."""
    services = world.services()
    try:
        services.store.create_investigation(target="x")
    finally:
        services.close()
    assert _recover_orphan_investigations(world.services) == 1
    assert _recover_orphan_investigations(world.services) == 0


def test_recovery_stamps_a_paused_reason(world: World):
    """Core UX win: the row must carry a human-readable paused_reason the UI can show as a
    banner. Without this the operator sees 'Paused' with no context and assumes they paused
    it themselves."""
    services = world.services()
    try:
        inv = services.store.create_investigation(target="scattered spider")
    finally:
        services.close()
    _recover_orphan_investigations(world.services)
    services = world.services()
    try:
        refreshed = services.store.get_investigation(inv.id)
    finally:
        services.close()
    assert refreshed.paused_reason == "Server restart interrupted this run."


def test_resuming_clears_the_paused_reason(world: World):
    """Transitioning back to RUNNING must clear paused_reason — the banner that explained
    WHY the run was paused is no longer true once the operator resumed it."""
    services = world.services()
    try:
        inv = services.store.create_investigation(target="x")
    finally:
        services.close()
    _recover_orphan_investigations(world.services)
    services = world.services()
    try:
        services.store.set_investigation_state(inv.id, InvestigationState.RUNNING)
        refreshed = services.store.get_investigation(inv.id)
    finally:
        services.close()
    assert refreshed.state is InvestigationState.RUNNING
    assert refreshed.paused_reason is None


def test_operator_paused_leaves_reason_null(world: World):
    """A manual Stop (operator-initiated) does not pass a reason; paused_reason stays null and
    the UI treats that as the baseline case (no banner — the operator already knows WHY)."""
    services = world.services()
    try:
        inv = services.store.create_investigation(target="x")
        services.store.set_investigation_state(inv.id, InvestigationState.PAUSED)
        refreshed = services.store.get_investigation(inv.id)
    finally:
        services.close()
    assert refreshed.state is InvestigationState.PAUSED
    assert refreshed.paused_reason is None


def test_finished_and_paused_are_untouched(world: World):
    """Recovery must only flip RUNNING. A paused run that the operator intentionally paused —
    or a finished one that already completed — must not be re-paused (that would be a UX lie
    the other way: "we did work on it we did not")."""
    services = world.services()
    try:
        running = services.store.create_investigation(target="r")
        paused = services.store.create_investigation(target="p")
        finished = services.store.create_investigation(target="f")
        services.store.set_investigation_state(paused.id, InvestigationState.PAUSED)
        services.store.set_investigation_state(finished.id, InvestigationState.FINISHED)
    finally:
        services.close()

    assert _recover_orphan_investigations(world.services) == 1

    assert _state_of(world, running.id) is InvestigationState.PAUSED
    assert _state_of(world, paused.id) is InvestigationState.PAUSED
    assert _state_of(world, finished.id) is InvestigationState.FINISHED


def test_services_factory_failure_is_swallowed(tmp_path, caplog):
    """A missing / corrupt DB on the host must not block `argus serve` from starting; the
    operator still gets a server they can use to re-login and inspect the problem."""
    def bad_factory():
        raise RuntimeError("db file is locked by another process")

    with caplog.at_level("WARNING"):
        count = _recover_orphan_investigations(bad_factory)

    assert count == 0
    assert any("orphan-recovery skipped" in rec.message for rec in caplog.records)


# ---- catalog auto-load ---------------------------------------------------------------

class _FakeJobs:
    """Minimal stand-in for JobManager: records every submit() call."""
    def __init__(self, raises: Exception | None = None):
        self.submitted: list[tuple[str, dict]] = []
        self._raises = raises

    def submit(self, kind: str, params: dict, dedupe_key=()) -> dict:
        if self._raises:
            raise self._raises
        self.submitted.append((kind, params))
        return {"id": "fake-job-id", "kind": kind}


def test_attack_catalog_autoloads_when_empty(world: World, capsys):
    """Fresh install path: the DB has zero intrusion-sets, so the serve process must
    auto-submit an `attack_update` job and tell the operator one is running. Without this,
    a first-time user has to notice the empty catalog and run the command by hand — in
    practice they do not, and the first few investigations return fractured output."""
    # The World fixture loaded the mini test catalog (~5 groups), well under the threshold.
    jobs = _FakeJobs()
    _ensure_attack_catalog_loaded(world.services, jobs)
    assert jobs.submitted == [("attack_update", {})]
    out = capsys.readouterr().out
    assert "ATT&CK catalog not loaded" in out
    assert "auto-submitted" in out


def test_attack_catalog_skips_when_already_loaded(world: World, capsys):
    """When the store already holds a catalog of that size (a prior `attack update` ran), the
    auto-check does nothing — no job submitted, no banner."""
    # Seed enough CATALOG intrusion-sets to pass the threshold. The `attack`-origin alias is what
    # makes each one a catalog entity: bare intrusion-set rows are what the Analyst writes for
    # every group name it reads, and a store full of those has no catalog at all.
    services = world.services()
    try:
        for i in range(MIN_LOADED_GROUPS):
            entity_id = f"intrusion-set--seed-{i:03d}"
            services.store.connection.execute(
                "INSERT INTO entities(id, stix_type, canonical_name) VALUES (?, 'intrusion-set', ?)",
                (entity_id, f"Seeded Group {i}"),
            )
            services.store.connection.execute(
                "INSERT INTO aliases(normalized_alias, alias, entity_id, origin) "
                "VALUES (?, ?, ?, 'attack')",
                (f"seeded group {i}", f"Seeded Group {i}", entity_id),
            )
        services.store.connection.commit()
    finally:
        services.close()

    jobs = _FakeJobs()
    _ensure_attack_catalog_loaded(world.services, jobs)
    assert jobs.submitted == []
    assert capsys.readouterr().out == ""


def test_attack_catalog_check_handles_job_submit_failure(world: World, capsys):
    """When the JobManager refuses the submit (dedup collision, shutdown, …) the check
    must warn the operator with instructions and keep the serve process starting."""
    jobs = _FakeJobs(raises=RuntimeError("queue closed"))
    _ensure_attack_catalog_loaded(world.services, jobs)
    out = capsys.readouterr().out
    assert "Run `argus attack update`" in out
    assert "auto-submit failed" in out


def test_attack_catalog_check_tolerates_broken_services(caplog):
    """A missing / corrupt DB must not block serve startup from here either — the operator
    needs the server up to login and inspect the host."""
    def bad_factory():
        raise RuntimeError("db locked")

    with caplog.at_level("WARNING"):
        _ensure_attack_catalog_loaded(bad_factory, _FakeJobs())
    assert any("attack-catalog check skipped" in rec.message for rec in caplog.records)
