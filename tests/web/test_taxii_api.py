"""TAXII 2.1 server: discovery, collection, objects + pagination + added_after + write."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
)
from tests.web.conftest import TOKEN
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    # The served TAXII endpoint authenticates with the machine token (not a user session), so
    # present it here. TAXII clients may also use the OASIS `Authorization: Bearer` header.
    if "X-Argus-Token" in client.headers:
        client.headers["X-Argus-Token"] = TOKEN
    return client


def _seed_two_assessments(world):
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "ZetaActor", AliasOrigin.ATTACK)
        mal = svc.store.create_entity("malware", "ZetaBot", AliasOrigin.ATTACK)
        tgt = svc.store.create_entity("identity", "ZetaBank", AliasOrigin.DOCUMENT)
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=mal.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="targets", object_entity_id=tgt.id,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3",
        ))
        return actor.id, mal.id, tgt.id
    finally:
        svc.close()


def test_discovery_returns_api_root(world):
    client = make_client(world)
    response = client.get("/taxii2/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/taxii+json")
    body = response.json()
    assert "api_roots" in body and len(body["api_roots"]) == 1
    assert body["api_roots"][0].endswith("/taxii2/api1/")


def test_api_root_info_announces_taxii_2_1(world):
    body = make_client(world).get("/taxii2/api1/").json()
    assert "application/taxii+json;version=2.1" in body["versions"]


def test_collections_lists_the_single_argus_collection(world):
    body = make_client(world).get("/taxii2/api1/collections/").json()
    [collection] = body["collections"]
    assert collection["id"] == "argus"
    assert collection["can_read"] is True and collection["can_write"] is True
    assert "application/stix+json;version=2.1" in collection["media_types"]


def test_collection_404_on_unknown_id(world):
    assert make_client(world).get("/taxii2/api1/collections/nope/").status_code == 404


def test_objects_envelope_contains_sdos_and_relationships(world):
    actor_id, mal_id, tgt_id = _seed_two_assessments(world)
    body = make_client(world).get("/taxii2/api1/collections/argus/objects/").json()
    assert "objects" in body
    types = {obj["type"] for obj in body["objects"]}
    # ZetaBank is DOCUMENT origin → emitted as identity; actor + malware are ATT&CK → referenced only.
    assert "identity" in types
    assert "relationship" in types
    rel_targets = [obj["target_ref"] for obj in body["objects"] if obj["type"] == "relationship"]
    assert mal_id in rel_targets and tgt_id in rel_targets


def test_objects_pagination_returns_more_and_next(world):
    _seed_two_assessments(world)
    body = make_client(world).get("/taxii2/api1/collections/argus/objects/?limit=1").json()
    assert len(body["objects"]) == 1
    assert body["more"] is True
    # `next` is opaque — treat as a token the server minted, pass it back verbatim.
    assert isinstance(body["next"], str) and body["next"]
    first_id = body["objects"][0]["id"]
    body2 = make_client(world).get(
        f"/taxii2/api1/collections/argus/objects/?limit=1&next={body['next']}",
    ).json()
    assert len(body2["objects"]) == 1
    assert body2["objects"][0]["id"] != first_id  # the cursor advanced

    # Keep walking until exhausted; the final page has `more: false` and no `next`.
    cursor = body2["next"]
    seen = {first_id, body2["objects"][0]["id"]}
    while True:
        page = make_client(world).get(
            f"/taxii2/api1/collections/argus/objects/?limit=1&next={cursor}",
        ).json()
        if not page["objects"]:
            break
        seen.add(page["objects"][0]["id"])
        if not page["more"]:
            break
        cursor = page["next"]
    # No duplicates across pages — the per-id cursor guarantees it.
    assert len(seen) >= 3


def test_bad_cursor_returns_400(world):
    _seed_two_assessments(world)
    # Any non-UTF-8 base64 input: the server surfaces the parse error as 400 rather than
    # silently falling back to the top of the list.
    assert make_client(world).get(
        "/taxii2/api1/collections/argus/objects/?next=!!!not-valid-base64!!!",
    ).status_code == 400


def test_cursor_survives_an_insertion_mid_pagination(world):
    """Core correctness win over offset-based: a new object landing at an earlier position
    between page fetches must not shift what the current client sees."""
    _seed_two_assessments(world)
    body = make_client(world).get("/taxii2/api1/collections/argus/objects/?limit=1").json()
    first_id = body["objects"][0]["id"]
    cursor = body["next"]
    # Simulate an insertion between page fetches. _seed adds extra assessments which show up
    # as new relationships; some will sort before the current cursor position, but the client
    # must still receive each distinct id exactly once.
    _seed_two_assessments(world)
    seen = {first_id}
    while True:
        page = make_client(world).get(
            f"/taxii2/api1/collections/argus/objects/?limit=1&next={cursor}",
        ).json()
        if not page["objects"]:
            break
        obj_id = page["objects"][0]["id"]
        assert obj_id not in seen  # the cursor-based scheme never re-emits a previous id
        seen.add(obj_id)
        if not page["more"]:
            break
        cursor = page["next"]


def test_added_after_filter_excludes_older_assessments(world):
    _seed_two_assessments(world)
    # Use the `Z` suffix so the query string survives URL encoding without the `+` becoming a space.
    future = datetime.now(UTC).replace(year=datetime.now().year + 10).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = make_client(world).get(
        f"/taxii2/api1/collections/argus/objects/?added_after={future}",
    ).json()
    assert body["objects"] == []


def test_added_after_rejects_bad_input(world):
    assert make_client(world).get(
        "/taxii2/api1/collections/argus/objects/?added_after=not-a-timestamp",
    ).status_code == 400


def test_manifest_mirrors_objects_but_is_lighter(world):
    _seed_two_assessments(world)
    manifest = make_client(world).get("/taxii2/api1/collections/argus/manifest/").json()
    for item in manifest["objects"]:
        assert set(item.keys()) == {"id", "date_added", "version", "media_type"}
        assert item["media_type"] == "application/stix+json;version=2.1"


def test_get_object_by_id_returns_single_item_envelope(world):
    _seed_two_assessments(world)
    objects = make_client(world).get("/taxii2/api1/collections/argus/objects/").json()["objects"]
    identity = next(o for o in objects if o["type"] == "identity")
    body = make_client(world).get(
        f"/taxii2/api1/collections/argus/objects/{identity['id']}/",
    ).json()
    assert len(body["objects"]) == 1
    assert body["objects"][0]["id"] == identity["id"]


def test_get_object_404_on_unknown_id(world):
    assert make_client(world).get(
        "/taxii2/api1/collections/argus/objects/identity--does-not-exist/",
    ).status_code == 404


def test_taxii_accepts_authorization_bearer_header(world):
    """TAXII clients use `Authorization: Bearer <token>`; the middleware must accept it."""
    from tests.web.conftest import TOKEN
    client = _make_client(world, authenticated=False)
    client.headers["Authorization"] = f"Bearer {TOKEN}"
    response = client.get("/taxii2/")
    assert response.status_code == 200


def test_taxii_rejects_requests_without_a_token(world):
    client = _make_client(world, authenticated=False)
    assert client.get("/taxii2/").status_code == 401


def test_taxii_envelope_reemits_attack_actors_with_sectors(world):
    """TAXII subscribers get the actor SDO with x_argus_sectors when the actor is an
    ATT&CK entity that carries Argus-specific sector attribution. Without the re-emit
    the sectors would be invisible to anyone pulling via TAXII."""
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "AttackActor", AliasOrigin.ATTACK)
        malware = svc.store.create_entity("malware", "AttackBot", AliasOrigin.ATTACK)
        svc.store.append_entity_sector(actor.id, "healthcare")
        svc.store.append_entity_sector(actor.id, "retail")
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=malware.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
    finally:
        svc.close()
    body = make_client(world).get(
        "/taxii2/api1/collections/argus/objects/?match%5Btype%5D=intrusion-set",
    ).json()
    [emitted] = body["objects"]
    assert emitted["name"] == "AttackActor"
    assert emitted["x_argus_sectors"] == ["healthcare", "retail"]


def test_taxii_envelope_keeps_pure_attack_actors_reference_only(world):
    """The default pass-through case: ATT&CK actor WITHOUT custom attributes stays
    reference-only (consumers hold the catalog), so the envelope is lean."""
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "PureAttack", AliasOrigin.ATTACK)
        malware = svc.store.create_entity("malware", "AttackBot", AliasOrigin.ATTACK)
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=malware.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
    finally:
        svc.close()
    body = make_client(world).get("/taxii2/api1/collections/argus/objects/").json()
    # Neither the ATT&CK actor nor the ATT&CK malware are re-emitted; only the
    # relationship between them is.
    types = {obj["type"] for obj in body["objects"]}
    assert "intrusion-set" not in types
    assert "malware" not in types
    assert "relationship" in types


# -- match[type|id|spec_version] filters (OASIS §3.4) --------------------------------------


def test_match_type_narrows_to_a_single_sdo_kind(world):
    _seed_two_assessments(world)
    body = make_client(world).get(
        "/taxii2/api1/collections/argus/objects/?match%5Btype%5D=relationship",
    ).json()
    assert body["objects"]
    assert all(obj["type"] == "relationship" for obj in body["objects"])


def test_match_type_accepts_comma_list(world):
    _seed_two_assessments(world)
    body = make_client(world).get(
        "/taxii2/api1/collections/argus/objects/?match%5Btype%5D=identity,relationship",
    ).json()
    kinds = {obj["type"] for obj in body["objects"]}
    assert kinds == {"identity", "relationship"}


def test_match_id_narrows_to_single_object(world):
    _seed_two_assessments(world)
    all_objects = make_client(world).get("/taxii2/api1/collections/argus/objects/").json()["objects"]
    target_id = next(o["id"] for o in all_objects if o["type"] == "identity")
    body = make_client(world).get(
        f"/taxii2/api1/collections/argus/objects/?match%5Bid%5D={target_id}",
    ).json()
    assert [o["id"] for o in body["objects"]] == [target_id]


def test_match_spec_version_filters_too(world):
    _seed_two_assessments(world)
    body = make_client(world).get(
        "/taxii2/api1/collections/argus/objects/?match%5Bspec_version%5D=2.1",
    ).json()
    assert all(obj.get("spec_version") == "2.1" for obj in body["objects"])


def test_match_filters_apply_to_manifest_too(world):
    _seed_two_assessments(world)
    body = make_client(world).get(
        "/taxii2/api1/collections/argus/manifest/?match%5Btype%5D=identity",
    ).json()
    assert body["objects"]


def test_match_filters_combine_with_pagination(world):
    _seed_two_assessments(world)
    body = make_client(world).get(
        "/taxii2/api1/collections/argus/objects/?match%5Btype%5D=relationship&limit=1",
    ).json()
    assert len(body["objects"]) == 1
    assert body["objects"][0]["type"] == "relationship"
    assert body["more"] is True


# -- POST /objects/  (TAXII §5.4 write path) --------------------------------------------


def _taxii_bundle():
    """Minimal envelope with one indicator + one actor + a relationship."""
    return {
        "objects": [
            {
                "type": "intrusion-set",
                "spec_version": "2.1",
                "id": "intrusion-set--posted-0001",
                "created": "2026-10-03T00:00:00.000Z",
                "modified": "2026-10-03T00:00:00.000Z",
                "name": "PostedActor",
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--posted-ip",
                "created": "2026-10-03T00:00:00.000Z",
                "modified": "2026-10-03T00:00:00.000Z",
                "name": "198.51.100.42",
                "pattern": "[ipv4-addr:value = '198.51.100.42']",
                "pattern_type": "stix",
                "valid_from": "2026-10-03T00:00:00.000Z",
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--posted-rel",
                "created": "2026-10-03T00:00:00.000Z",
                "modified": "2026-10-03T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--posted-0001",
                "target_ref": "indicator--posted-ip",
            },
        ],
    }


def test_collection_now_advertises_can_write_true(world):
    body = make_client(world).get("/taxii2/api1/collections/argus/").json()
    assert body["can_write"] is True


def test_post_envelope_returns_202_with_status_resource(world):
    client = make_client(world)
    r = client.post(
        "/taxii2/api1/collections/argus/objects/",
        content=json.dumps(_taxii_bundle()),
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "complete"
    assert body["total_count"] == 3
    # intrusion-set + indicator + relationship are all accepted shapes.
    assert body["success_count"] >= 1
    assert "x_argus_report" in body
    assert body["x_argus_report"]["entities_added"] >= 1


def test_post_populates_the_store(world):
    make_client(world).post(
        "/taxii2/api1/collections/argus/objects/",
        content=json.dumps(_taxii_bundle()),
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    svc = world.services()
    try:
        found = svc.store.find_by_alias("PostedActor")
        assert found is not None
    finally:
        svc.close()


def test_post_returns_location_header_for_status_resource(world):
    client = make_client(world)
    r = client.post(
        "/taxii2/api1/collections/argus/objects/",
        content=json.dumps(_taxii_bundle()),
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    assert "location" in {h.lower() for h in r.headers}
    assert "/taxii2/api1/status/" in r.headers["location"]


def test_get_status_returns_the_stored_resource(world):
    client = make_client(world)
    r = client.post(
        "/taxii2/api1/collections/argus/objects/",
        content=json.dumps(_taxii_bundle()),
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    status_id = r.json()["id"]
    status = client.get(f"/taxii2/api1/status/{status_id}/").json()
    assert status["id"] == status_id
    assert status["status"] == "complete"


def test_get_status_404_on_unknown_id(world):
    assert make_client(world).get("/taxii2/api1/status/does-not-exist/").status_code == 404


def test_post_rejects_wrong_content_type(world):
    r = make_client(world).post(
        "/taxii2/api1/collections/argus/objects/",
        content=json.dumps(_taxii_bundle()),
        headers={"content-type": "text/plain"},
    )
    assert r.status_code == 415


def test_post_rejects_empty_body(world):
    r = make_client(world).post(
        "/taxii2/api1/collections/argus/objects/",
        content=b"",
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    assert r.status_code == 400


def test_post_rejects_malformed_json(world):
    r = make_client(world).post(
        "/taxii2/api1/collections/argus/objects/",
        content=b"not json",
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    assert r.status_code == 400


def test_post_rejects_envelope_without_objects_array(world):
    r = make_client(world).post(
        "/taxii2/api1/collections/argus/objects/",
        content=json.dumps({"not": "an envelope"}),
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    assert r.status_code == 400


def test_post_404_on_unknown_collection(world):
    r = make_client(world).post(
        "/taxii2/api1/collections/other/objects/",
        content=json.dumps(_taxii_bundle()),
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    assert r.status_code == 404


def test_post_without_token_is_rejected(world):
    client = _make_client(world, authenticated=False)
    r = client.post(
        "/taxii2/api1/collections/argus/objects/",
        content=json.dumps(_taxii_bundle()),
        headers={"content-type": "application/stix+json;version=2.1"},
    )
    assert r.status_code == 401
