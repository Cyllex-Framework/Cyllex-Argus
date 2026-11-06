"""Investigations record and surface who started them; non-human runs read as "system"."""

from __future__ import annotations

from cyllex_argus.knowledge.models import Role
from cyllex_argus.web.job_handlers import build_handlers
from cyllex_argus.web.jobs import JobManager
from tests.web.conftest import make_client

CSRF = {"X-Argus-CSRF": "1"}


def _inline_client(world, role: Role = Role.ADMIN):
    return make_client(world, role=role, jobs=JobManager(build_handlers(world.services), inline=True))


def test_investigation_is_attributed_to_the_starting_user(world):
    client = _inline_client(world)
    resp = client.post("/api/jobs", json={"kind": "investigate", "target": "Scattered Spider"}, headers=CSRF)
    assert resp.status_code == 202
    rows = client.get("/api/investigations").json()
    assert rows and rows[0]["started_by"] == "admin"


def test_a_run_with_no_user_reads_as_system(world):
    services = world.services()
    try:
        services.store.create_investigation("Lone Target", created_by=None)
    finally:
        services.close()
    rows = make_client(world).get("/api/investigations").json()
    row = next(r for r in rows if r["target"] == "Lone Target")
    assert row["started_by"] == "system"
