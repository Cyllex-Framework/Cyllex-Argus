"""PUT /api/entities/{id}/retype — change an entity's STIX type from HTTP."""

from __future__ import annotations

from cyllex_argus.knowledge.models import AliasOrigin
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _seed_identity(world) -> str:
    svc = world.services()
    try:
        e = svc.store.create_entity("identity", "AWS", AliasOrigin.DOCUMENT)
        return e.id
    finally:
        svc.close()


def test_put_retype_returns_new_id_and_prev(world):
    old_id = _seed_identity(world)
    r = make_client(world).put(f"/api/entities/{old_id}/retype", json={"to": "tool"})
    assert r.status_code == 200
    body = r.json()
    assert body["stix_type"] == "tool"
    assert body["canonical_name"] == "AWS"
    assert body["id"].startswith("tool--")
    assert body["previous_id"] == old_id
    # Same UUID suffix.
    assert body["id"].split("--", 1)[1] == old_id.split("--", 1)[1]


def test_put_retype_404_on_unknown_entity(world):
    r = make_client(world).put(
        "/api/entities/identity--does-not-exist/retype", json={"to": "tool"},
    )
    assert r.status_code == 404


def test_put_retype_400_on_identical_type(world):
    old_id = _seed_identity(world)
    r = make_client(world).put(f"/api/entities/{old_id}/retype", json={"to": "identity"})
    assert r.status_code == 400
    assert "already" in r.json()["error"]


def test_put_retype_422_on_untyped_target(world):
    """The RetypeBody schema restricts `to` to the retype whitelist; attack-pattern is
    excluded. Pydantic rejects at the request-parse boundary with a 400 or 422 depending
    on the error-handler."""
    old_id = _seed_identity(world)
    r = make_client(world).put(f"/api/entities/{old_id}/retype", json={"to": "attack-pattern"})
    assert r.status_code in (400, 422)


def test_put_retype_requires_csrf(world):
    old_id = _seed_identity(world)
    client = _make_client(world)  # no CSRF
    r = client.put(f"/api/entities/{old_id}/retype", json={"to": "tool"})
    assert r.status_code == 403
