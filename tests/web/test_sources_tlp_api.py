"""HTTP API for TLP labels on publishers."""

from __future__ import annotations

from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _with_publisher(world, name="Mandiant"):
    svc = world.services()
    try:
        return svc.store.get_or_create_publisher(name)
    finally:
        svc.close()


def test_sources_list_includes_tlp_field(world):
    _with_publisher(world)
    response = make_client(world).get("/api/sources")
    assert response.status_code == 200
    for row in response.json():
        assert "tlp" in row
        assert row["tlp"] in (None, "clear", "green", "amber", "amber-strict", "red")


def test_put_tlp_persists_and_round_trips(world):
    pub = _with_publisher(world)
    client = make_client(world)
    response = client.put(f"/api/sources/{pub.id}/tlp", json={"tlp": "amber"})
    assert response.status_code == 200
    assert response.json()["tlp"] == "amber"
    listing = client.get("/api/sources").json()
    [mandiant] = [p for p in listing if p["name"] == "Mandiant"]
    assert mandiant["tlp"] == "amber"


def test_put_tlp_null_clears_the_label(world):
    pub = _with_publisher(world)
    client = make_client(world)
    client.put(f"/api/sources/{pub.id}/tlp", json={"tlp": "red"})
    response = client.put(f"/api/sources/{pub.id}/tlp", json={"tlp": None})
    assert response.status_code == 200
    assert response.json()["tlp"] is None


def test_put_tlp_404_on_unknown_source(world):
    assert make_client(world).put("/api/sources/99999/tlp", json={"tlp": "amber"}).status_code == 404


def test_put_tlp_rejects_bad_value(world):
    pub = _with_publisher(world)
    assert make_client(world).put(
        f"/api/sources/{pub.id}/tlp", json={"tlp": "neon-purple"},
    ).status_code == 400
