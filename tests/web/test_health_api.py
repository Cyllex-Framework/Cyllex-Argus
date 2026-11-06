"""`GET /api/health` — the operator's data-quality shortlist."""

from __future__ import annotations

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    InvestigationState,
    NewDocument,
    Stage,
)
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    return _make_client(world, **kwargs)


def test_live_returns_ok_without_authentication(world):
    """`/api/live` is the systemd liveness probe: anonymous access is REQUIRED, or the service
    manager would mark the service unhealthy forever."""
    r = make_client(world, authenticated=False).get("/api/live")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_health_empty_store_returns_zero_totals(world):
    body = make_client(world).get("/api/health").json()
    assert body["totals"] == {
        "failed_documents": 0,
        "untagged_identities": 0,
        "unrated_publishers": 0,
        "gradeable_publishers": 0,
        "duplicate_publisher_rows": 0,
        "stuck_investigations": 0,
        "likely_mistyped_identities": 0,
        "name_collisions": 0,
    }
    assert body["failed_documents"] == []
    assert body["untagged_identities"] == []
    assert body["likely_mistyped_identities"] == []
    assert body["name_collisions"] == []


def test_health_detects_actor_malware_name_collisions(world):
    """ATT&CK catalog has several groups whose signature malware shares the group's name.
    The detector lists them so the operator knows which actors are at risk of
    misattribution BEFORE running an investigation."""
    svc = world.services()
    try:
        svc.store.create_entity("intrusion-set", "Machete", AliasOrigin.ATTACK, external_id="G0095")
        svc.store.create_entity("malware", "Machete", AliasOrigin.ATTACK, external_id="S0409")
        svc.store.create_entity("intrusion-set", "SoloActor", AliasOrigin.ATTACK)  # no collision
    finally:
        svc.close()
    body = make_client(world).get("/api/health").json()
    assert body["totals"]["name_collisions"] == 1
    [collision] = body["name_collisions"]
    assert collision["name"] == "Machete"
    types = {e["stix_type"] for e in collision["entities"]}
    assert types == {"intrusion-set", "malware"}


def test_health_name_collisions_ignore_single_type_dupes(world):
    """Two entities of the SAME type (e.g. a bulk-retype duplicate like two `tool--Azure`)
    don't count as a name collision — the collision concept is cross-type (actor vs
    malware). Same-type duplicates are a separate dedup concern."""
    svc = world.services()
    try:
        svc.store.create_entity("tool", "Azure", AliasOrigin.ATTACK)
        svc.store.create_entity("tool", "Azure", AliasOrigin.DOCUMENT)
    finally:
        svc.close()
    body = make_client(world).get("/api/health").json()
    assert body["totals"]["name_collisions"] == 0


def test_health_detects_tool_identities(world):
    """The LLM typed cloud providers and vendor platforms as `identity`; the detector
    suggests retyping them to `tool`."""
    svc = world.services()
    try:
        svc.store.create_entity("identity", "AWS", AliasOrigin.DOCUMENT)
        svc.store.create_entity("identity", "Cloudflare", AliasOrigin.DOCUMENT)
        svc.store.create_entity("identity", "Mahak Rayan Afraz", AliasOrigin.DOCUMENT)  # real org — not flagged
    finally:
        svc.close()
    body = make_client(world).get("/api/health").json()
    flagged = {(e["name"], e["suggest"]) for e in body["likely_mistyped_identities"]}
    assert ("AWS", "tool") in flagged
    assert ("Cloudflare", "tool") in flagged
    assert all(name != "Mahak Rayan Afraz" for name, _ in flagged)
    assert body["totals"]["likely_mistyped_identities"] == 2


def test_health_detects_sector_identities(world):
    """Sector labels should not be identity SDOs; the detector suggests `sector-tag`."""
    svc = world.services()
    try:
        svc.store.create_entity("identity", "Aerospace and Defense", AliasOrigin.DOCUMENT)
        svc.store.create_entity("identity", "Logistics", AliasOrigin.DOCUMENT)
    finally:
        svc.close()
    body = make_client(world).get("/api/health").json()
    suggestions = {e["name"]: e["suggest"] for e in body["likely_mistyped_identities"]}
    assert suggestions["Aerospace and Defense"] == "sector-tag"
    assert suggestions["Logistics"] == "sector-tag"


def test_health_surfaces_failed_documents(world):
    svc = world.services()
    try:
        pub = svc.store.get_or_create_publisher("Example", default_reliability="C")
        svc.store.add_document(NewDocument(
            url="https://example.test/f", canonical_url="https://example.test/f",
            title="Blocked by WAF", publisher_id=pub.id,
            content_hash="h", raw_path="", text="",
        ), stage=Stage.FAILED, failure_reason="HTTP 403")
    finally:
        svc.close()
    body = make_client(world).get("/api/health").json()
    assert body["totals"]["failed_documents"] == 1
    [row] = body["failed_documents"]
    assert row["title"] == "Blocked by WAF"
    assert row["failure_reason"] == "HTTP 403"
    assert row["publisher"] == "Example"


def test_health_surfaces_untagged_identities(world):
    svc = world.services()
    try:
        # Tagged identity should NOT appear.
        tagged = svc.store.create_entity("identity", "ACME Health System", AliasOrigin.DOCUMENT)
        svc.store.set_entity_attributes(tagged.id, sector="healthcare", country="US")
        # Untagged identity should.
        svc.store.create_entity("identity", "Unknown Corp", AliasOrigin.DOCUMENT)
    finally:
        svc.close()
    body = make_client(world).get("/api/health").json()
    assert body["totals"]["untagged_identities"] == 1
    [row] = body["untagged_identities"]
    assert row["name"] == "Unknown Corp"


def test_health_surfaces_unrated_publishers(world):
    svc = world.services()
    try:
        # One rated, one unrated (the default placeholder is 'F').
        svc.store.get_or_create_publisher("CISA", default_reliability="A")
        svc.store.get_or_create_publisher("Random blog")  # defaults to 'F' = unrated
    finally:
        svc.close()
    body = make_client(world).get("/api/health").json()
    unrated_names = {p["name"] for p in body["unrated_publishers"]}
    assert "Random blog" in unrated_names
    assert "CISA" not in unrated_names


def test_health_lists_investigations_stuck_in_running_or_paused(world):
    svc = world.services()
    try:
        running = svc.store.create_investigation("still running", None)
        paused = svc.store.create_investigation("rate limited", None)
        finished = svc.store.create_investigation("done", None)
        svc.store.set_investigation_state(running.id, InvestigationState.RUNNING)
        svc.store.set_investigation_state(paused.id, InvestigationState.PAUSED)
        svc.store.set_investigation_state(finished.id, InvestigationState.FINISHED)
    finally:
        svc.close()
    body = make_client(world).get("/api/health").json()
    assert body["totals"]["stuck_investigations"] == 2
    targets = {i["target"] for i in body["stuck_investigations"]}
    assert targets == {"still running", "rate limited"}


def test_health_names_the_publisher_work_that_is_one_click_away(world):
    """"38 unrated publishers" states a problem and offers nothing. These two totals are what to
    DO about it, and the dashboard is where the operator lands — so they belong here, not only in
    a CLI nobody runs."""
    from datetime import date

    from cyllex_argus.knowledge.models import NewDocument

    svc = world.services()
    try:
        for index, name in enumerate(("CISA", "US-CERT")):
            publisher = svc.store.get_or_create_publisher(name)
            url = f"https://www.cisa.gov/advisory-{index}"
            svc.store.add_document(NewDocument(
                url=url, canonical_url=url, title=f"Advisory {index}", publisher_id=publisher.id,
                published_at=date(2025, 1, 10), content_hash=f"h{index}", raw_path=f"r{index}",
                text="Some text",
            ))
        svc.store.get_or_create_publisher("Some Person's Blog", domain="https://medium.com/@p/x")
    finally:
        svc.close()

    totals = make_client(world).get("/api/health").json()["totals"]

    assert totals["unrated_publishers"] == 3
    # Two of the three are recognised sources sitting on the confidence floor...
    assert totals["gradeable_publishers"] == 2
    # ...and one of those two is REDUNDANT: they are one organisation, so one row duplicates the
    # other. The count is the rows to remove, not the rows involved — counting the survivor made
    # the dashboard chip overstate by one per organisation.
    assert totals["duplicate_publisher_rows"] == 1


def test_a_wiped_store_reports_attack_as_missing_even_with_the_file_on_disk(world):
    """The bug a database wipe exposed.

    `enterprise-attack.json` survives a wipe; the ~2,000 catalog rows loaded from it do not. Five
    prerequisite checks gated on the FILE existing, so on a wiped store all five said yes, the
    dashboard showed no setup notice, and investigate and ingest were both allowed — against an
    empty catalog. That run does not fail. It resolves nothing, so the Analyst writes a
    document-origin entity for every group name it reads and no alias ties any of them together.
    """
    from tests.web.conftest import make_client as plain

    svc = world.services()
    try:
        assert svc.paths.attack_file.exists(), "the fixture keeps the reference file on disk"
        assert svc.attack_ready(), "the fixture's catalog is sparse but loaded, so it is usable"
        # Wipe only the catalog rows, exactly as `admin_db.wipe_db` does to the whole store.
        svc.store.connection.execute("DELETE FROM aliases")
        svc.store.connection.execute("DELETE FROM entities")
        svc.store.connection.commit()
        assert not svc.attack_ready(), "a file on disk is not a loaded catalog"
    finally:
        svc.close()

    settings = plain(world).get("/api/settings").json()

    # Which is what the setup notice reads, so the dashboard offers the Update ATT&CK button.
    assert settings["attack"]["present"] is False
    assert settings["attack"]["groups"] == 0
