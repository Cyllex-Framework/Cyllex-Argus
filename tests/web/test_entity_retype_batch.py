"""POST /api/entities/retype-batch — bulk retype with per-item success/failure."""

from __future__ import annotations

from cyllex_argus.knowledge.models import AliasOrigin
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _seed(world, *names: str) -> list[str]:
    svc = world.services()
    try:
        return [svc.store.create_entity("identity", n, AliasOrigin.DOCUMENT).id for n in names]
    finally:
        svc.close()


def test_batch_retype_all_succeed(world):
    ids = _seed(world, "AWS", "Azure", "Cloudflare")
    r = make_client(world).post(
        "/api/entities/retype-batch",
        json={"items": [{"entity_id": i, "to": "tool"} for i in ids]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert len(body["ok"]) == 3
    assert body["failed"] == []
    for item in body["ok"]:
        assert item["stix_type"] == "tool"
        assert item["new_id"].startswith("tool--")


def test_batch_retype_mixes_success_and_failure(world):
    aws_id, = _seed(world, "AWS")
    bogus_id = "identity--does-not-exist"
    r = make_client(world).post(
        "/api/entities/retype-batch",
        json={"items": [
            {"entity_id": aws_id, "to": "tool"},
            {"entity_id": bogus_id, "to": "tool"},
            {"entity_id": aws_id, "to": "tool"},  # already retyped — second attempt fails
        ]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert len(body["ok"]) == 1
    assert len(body["failed"]) == 2
    assert body["ok"][0]["canonical_name"] == "AWS"
    failed_reasons = {f["entity_id"]: f["reason"] for f in body["failed"]}
    assert "unknown" in failed_reasons[bogus_id].lower()


def test_batch_retype_rejects_empty_list(world):
    r = make_client(world).post("/api/entities/retype-batch", json={"items": []})
    assert r.status_code in (400, 422)


def test_batch_retype_rejects_too_many_items(world):
    """Hard cap at 100 to keep the operation bounded — a bigger clean-up should run as a
    series of batches so each one can be audited independently."""
    r = make_client(world).post(
        "/api/entities/retype-batch",
        json={"items": [
            {"entity_id": f"identity--{i:032d}", "to": "tool"} for i in range(101)
        ]},
    )
    assert r.status_code in (400, 422)


def test_batch_retype_requires_csrf(world):
    aws_id, = _seed(world, "AWS")
    client = _make_client(world)  # no CSRF
    r = client.post(
        "/api/entities/retype-batch",
        json={"items": [{"entity_id": aws_id, "to": "tool"}]},
    )
    assert r.status_code == 403
