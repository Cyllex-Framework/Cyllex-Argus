"""HTTP API for STIX 2.1 bundle ingest."""

from __future__ import annotations

import json

from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


BUNDLE = {
    "type": "bundle",
    "id": "bundle--00000000-0000-4000-8000-000000000099",
    "created": "2024-06-01T00:00:00Z",
    "objects": [
        {"type": "intrusion-set", "id": "intrusion-set--z1", "name": "ZetaGroup",
         "aliases": ["ZetaGroup", "Z-Collective"]},
        {"type": "malware", "id": "malware--z2", "name": "ZetaBot"},
        {"type": "relationship", "id": "relationship--z3",
         "relationship_type": "uses",
         "source_ref": "intrusion-set--z1", "target_ref": "malware--z2"},
    ],
}


def test_stix_import_accepts_a_valid_bundle(world):
    files = {"bundle": ("test.json", json.dumps(BUNDLE), "application/json")}
    response = make_client(world).post("/api/import/stix", files=files)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["bundle_id"] == "bundle--00000000-0000-4000-8000-000000000099"
    assert body["entities_added"] >= 2
    assert body["claims_added"] == 1


def test_stix_import_rejects_non_bundle_body(world):
    files = {"bundle": ("junk.json", json.dumps({"not": "a bundle"}), "application/json")}
    response = make_client(world).post("/api/import/stix", files=files)
    assert response.status_code == 400


def test_stix_import_rejects_empty_body(world):
    files = {"bundle": ("empty.json", "", "application/json")}
    response = make_client(world).post("/api/import/stix", files=files)
    assert response.status_code == 400
    assert "empty" in response.json()["error"].lower()
