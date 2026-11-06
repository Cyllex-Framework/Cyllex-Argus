"""Smoke tests for GET /api/threats/{entity_id}/history — the diff-between-investigations endpoint."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.support import SPIDER, World
from tests.web.conftest import make_client


def test_history_404_on_unknown_entity(seeded_world: World):
    client = make_client(seeded_world)
    r = client.get("/api/threats/does-not-exist/history")
    assert r.status_code == 404


def test_history_returns_the_default_shape(seeded_world: World):
    """A seeded investigation of Scattered Spider: with no `since` filter the endpoint picks
    the start of the second-most-recent run (or epoch) and returns the four buckets."""
    client = make_client(seeded_world)
    r = client.get(f"/api/threats/{SPIDER}/history")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"since", "investigations", "new_assessments", "touched_assessments", "new_aliases"}
    assert isinstance(body["investigations"], list)
    assert isinstance(body["new_assessments"], list)
    assert isinstance(body["touched_assessments"], list)
    assert isinstance(body["new_aliases"], list)
    # since defaults to epoch when there's only one run, so everything so far is "new".
    assert body["since"].startswith("1970-")


def test_history_honours_explicit_since(seeded_world: World):
    """With `since` in the future, every bucket is empty."""
    client = make_client(seeded_world)
    future = (datetime.now(UTC) + timedelta(days=365)).isoformat()
    r = client.get(f"/api/threats/{SPIDER}/history", params={"since": future})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["since"].startswith("20")  # not epoch
    assert body["new_assessments"] == []
    assert body["touched_assessments"] == []
    assert body["investigations"] == []


def test_history_400_on_invalid_since(seeded_world: World):
    client = make_client(seeded_world)
    r = client.get(f"/api/threats/{SPIDER}/history", params={"since": "not-a-date"})
    assert r.status_code == 400
    assert "invalid since" in r.text.lower()
