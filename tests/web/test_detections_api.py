"""Sigma generation endpoint."""

from __future__ import annotations

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
)
from tests.web.conftest import make_client


def _seed(world):
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "SigmaActor", AliasOrigin.ATTACK)
        ip = svc.store.create_entity("indicator", "185.220.101.5", AliasOrigin.DOCUMENT)
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=ip.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
        return actor.id
    finally:
        svc.close()


def test_sigma_endpoint_returns_rules_for_known_iocs(world):
    actor_id = _seed(world)
    body = make_client(world).get(f"/api/threats/{actor_id}/detections/sigma").json()
    assert body["entity"] == "SigmaActor"
    assert body["count"] == 1
    rule = body["rules"][0]
    assert rule["logsource"] == {"category": "firewall", "product": "any"}
    assert rule["level"] == "high"
    assert "title:" in rule["yaml"]
    assert "dst_ip: 185.220.101.5" in rule["yaml"]
    assert body["references"] == []  # no techniques seeded, so no SigmaHQ references


def test_sigma_endpoint_404_on_unknown_entity(world):
    r = make_client(world).get("/api/threats/intrusion-set--nope/detections/sigma")
    assert r.status_code == 404


def test_sigma_endpoint_empty_when_no_iocs(world):
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "NoIocsActor", AliasOrigin.ATTACK)
        actor_id = actor.id
    finally:
        svc.close()
    body = make_client(world).get(f"/api/threats/{actor_id}/detections/sigma").json()
    assert body["count"] == 0
    assert body["rules"] == []
    assert body["references"] == []


def _seed_with_technique(world):
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "RefActor", AliasOrigin.ATTACK)
        ip = svc.store.create_entity("indicator", "185.220.101.5", AliasOrigin.DOCUMENT)
        tech = svc.store.create_entity("attack-pattern", "LSASS Memory", AliasOrigin.ATTACK, external_id="T1003.001")
        for obj in (ip.id, tech.id):
            svc.store.upsert_assessment(Assessment(
                subject_entity_id=actor.id, predicate="uses", object_entity_id=obj,
                status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
            ))
        return actor.id
    finally:
        svc.close()


def test_sigma_endpoint_references_observed_techniques(world):
    actor_id = _seed_with_technique(world)
    body = make_client(world).get(f"/api/threats/{actor_id}/detections/sigma").json()
    assert body["count"] == 1                         # the IOC only; the technique is not a rule
    refs = body["references"]
    assert [r["technique_id"] for r in refs] == ["T1003.001"]
    assert refs[0]["technique_name"] == "LSASS Memory"
    assert refs[0]["count"] > 0 and refs[0]["rules"]                       # the bundled index has rules
    assert refs[0]["rules"][0]["url"].startswith("https://github.com/SigmaHQ/sigma/blob/")
    assert "attack.t1003.001" in refs[0]["browse_url"]


def test_sigma_zip_bundles_rules_and_references(world):
    import io
    import zipfile

    actor_id = _seed_with_technique(world)
    r = make_client(world).get(f"/api/threats/{actor_id}/detections/sigma.zip")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert any(n.endswith(".yml") for n in names)     # the IOC rule file
    assert "SIGMAHQ-REFERENCES.md" in names           # the technique references
