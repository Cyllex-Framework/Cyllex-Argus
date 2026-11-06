import json

import h11
import pytest

from cyllex_argus.knowledge.models import AliasOrigin
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.llm.base import InvalidOutput
from cyllex_argus.llm.fake import FakeLLMProvider
from tests.support import SPIDER
from tests.web.conftest import make_client

VOICE = "attack-pattern--00000000-0000-4000-8000-000015660004"


@pytest.fixture
def client(seeded_world):
    return make_client(seeded_world)


def test_overview(client):
    data = client.get("/api/overview").json()
    assert data["counts"]["threats"] == 1
    assert data["recent_investigations"][0]["target"] == "Scattered Spider"


def test_threat_search(client):
    assert {r["id"] for r in client.get("/api/threats").json()} == {SPIDER, VOICE}
    assert [r["id"] for r in client.get("/api/threats", params={"q": "octo"}).json()] == [SPIDER]
    assert len(client.get("/api/threats", params={"catalog": 1}).json()) > 2
    # Backward compat: the short `?type=` alias still works.
    typed = client.get("/api/threats", params={"type": "attack-pattern"}).json()
    assert [r["id"] for r in typed] == [VOICE]
    # New: `?stix_type=` is the obvious guess (same field name the response uses) and
    # must also work.
    typed_alt = client.get("/api/threats", params={"stix_type": "attack-pattern"}).json()
    assert [r["id"] for r in typed_alt] == [VOICE]
    # When both are present the explicit `stix_type=` wins over the short alias.
    both = client.get("/api/threats", params={"stix_type": "attack-pattern", "type": "intrusion-set"}).json()
    assert [r["id"] for r in both] == [VOICE]
    assert client.get("/api/threats", params={"limit": 0}).status_code == 400


def test_threat_profile(client):
    data = client.get(f"/api/threats/{SPIDER}").json()
    assert data["entity"]["label"] == "Scattered Spider (G1015)" and data["entity"]["attack"] is True
    assert {"alias": "UNC3944", "origin": "attack"} in data["aliases"]
    [fact] = data["facts"]
    assert fact["status"] == "corroborated" and fact["source_count"] == 2
    assert fact["object"]["label"] == "Spearphishing Voice (T1566.004)"
    assert len(fact["citations"]) == 2 and fact["citations"][0]["quote"]
    missing = client.get("/api/threats/intrusion-set--nope")
    assert missing.status_code == 404 and missing.json() == {"error": "unknown threat"}


def test_threat_graph(client):
    graph = client.get(f"/api/threats/{SPIDER}/graph").json()
    assert {n["id"] for n in graph["nodes"]} == {SPIDER, VOICE}
    assert graph["truncated"] is False
    assert client.get(f"/api/threats/{SPIDER}/graph", params={"depth": 3}).status_code == 200
    for bad in ({"depth": 4}, {"depth": 0}, {"limit": 0}, {"limit": 201}):
        assert client.get(f"/api/threats/{SPIDER}/graph", params=bad).status_code == 400
    assert client.get(f"/api/threats/{SPIDER}/graph", params={"limit": 200}).status_code == 200
    cut = client.get(f"/api/threats/{SPIDER}/graph", params={"limit": 1, "depth": 3})
    assert cut.status_code == 200 and cut.json()["truncated"] is False  # one edge fits exactly
    assert client.get("/api/threats/intrusion-set--nope/graph").status_code == 404


def test_export_markdown_and_stix(client):
    md = client.get(f"/api/threats/{SPIDER}/export", params={"format": "markdown"})
    assert md.status_code == 200
    assert md.headers["content-disposition"] == 'attachment; filename="Scattered_Spider.md"'
    assert md.text.startswith("# Scattered Spider")
    assert "Executive summary" not in md.text
    with_summary = client.get(f"/api/threats/{SPIDER}/export", params={"format": "markdown", "summary": 1})
    assert "financially motivated" in with_summary.text
    stix = client.get(f"/api/threats/{SPIDER}/export", params={"format": "stix"})
    assert stix.headers["content-disposition"] == 'attachment; filename="Scattered_Spider.stix.json"'
    assert json.loads(stix.text)["type"] == "bundle"
    assert client.get(f"/api/threats/{SPIDER}/export", params={"format": "pdf"}).status_code == 400
    assert client.get("/api/threats/intrusion-set--nope/export").status_code == 404


def test_export_warning_header_stays_a_single_line(seeded_world):
    # Real provider errors span several lines (validation errors, stderr) and can hold control or non-ASCII characters.
    message = "line1\nline2\r\nX-Evil: 1" + chr(0) + chr(0x7F) + chr(0x2603) + " tail" + "x" * 300
    seeded_world.llm = FakeLLMProvider(lambda request: InvalidOutput(message))
    response = make_client(seeded_world).get(f"/api/threats/{SPIDER}/export", params={"format": "markdown", "summary": 1})
    assert response.status_code == 200
    assert response.text.startswith("# Scattered Spider") and "financially motivated" not in response.text
    warning = response.headers["x-argus-warning"]
    assert warning.startswith("summary skipped: line1 line2 X-Evil: 1")
    assert len(warning) <= 200 and all(0x20 <= ord(char) < 0x7F for char in warning)
    assert "x-evil" not in {name.lower() for name in response.headers if name.lower() != "x-argus-warning"}
    h11.Response(status_code=200, headers=[(b"x-argus-warning", warning.encode("ascii"))])  # what uvicorn will send
    # A browser download cannot read headers, so the file itself must say the summary is missing.
    assert "## Executive summary" in response.text
    [notice] = [line for line in response.text.split("\n") if "Summary unavailable:" in line]
    assert notice == f"_Summary unavailable: {warning.removeprefix('summary skipped: ')}_"
    assert notice.startswith("_Summary unavailable: line1 line2 X-Evil: 1") and "\r" not in notice


def test_export_filename_is_capped_and_never_empty(seeded_world):
    with SQLiteStore(seeded_world.paths.db_file) as store:
        long_name = store.create_entity("intrusion-set", "Long" * 100, AliasOrigin.USER).id
        symbols = store.create_entity("intrusion-set", "!!!", AliasOrigin.USER).id
    client = make_client(seeded_world)
    long_export = client.get(f"/api/threats/{long_name}/export")
    assert long_export.headers["content-disposition"] == f'attachment; filename="{"Long" * 25}.md"'
    symbol_export = client.get(f"/api/threats/{symbols}/export", params={"format": "stix"})
    assert symbol_export.headers["content-disposition"] == 'attachment; filename="threat.stix.json"'


def test_documents(client):
    documents = client.get("/api/documents").json()
    assert len(documents) == 4
    [failed] = client.get("/api/documents", params={"stage": "failed"}).json()
    detail = client.get(f"/api/documents/{documents[-1]['id']}").json()
    assert "text" in detail and "claims" in detail
    assert failed["title"] == "Gone"
    assert client.get("/api/documents/999999").status_code == 404
    assert client.get("/api/documents/not-a-number").status_code == 400


def test_investigations(client):
    [inv] = client.get("/api/investigations").json()
    detail = client.get(f"/api/investigations/{inv['id']}").json()
    assert detail["stage_counts"]["validated"] == 2 and len(detail["documents"]) == 4
    assert client.get("/api/investigations/999").status_code == 404


@pytest.mark.parametrize("path", ["/api/documents", "/api/investigations"])
def test_ids_beyond_sqlite_integer_range_are_rejected(client, path):
    for too_large in (2**63, -(2**63) - 1):
        response = client.get(f"{path}/{too_large}")
        assert response.status_code == 400 and response.json()["error"].startswith("invalid request")
    for extreme in (2**63 - 1, -(2**63), -1):
        assert client.get(f"{path}/{extreme}").status_code == 404


def test_sources_and_settings(client, seeded_world):
    names = {s["name"] for s in client.get("/api/sources").json()}
    assert {"Mandiant", "Microsoft"} <= names
    settings = client.get("/api/settings").json()
    assert settings["attack"] == {"present": True, "techniques": 2, "groups": 1, "software": 2}
    assert settings["claude"] == {"found": True}
    assert settings["config"]["limits"]["max_docs"] == 25
    assert settings["home"] == str(seeded_world.paths.home)
    assert settings["llm"] == {
        "provider": "claude-code-cli", "model": None, "timeout_seconds": 600, "claude_binary": "claude",
        "ollama": {"base_url": "http://127.0.0.1:11434", "model": "qwen2.5:32b-instruct", "keep_alive": "10m"},
        "anthropic": {"api_key": "", "model": "claude-sonnet-5-5",
                      "base_url": "https://api.anthropic.com", "anthropic_version": "2023-06-01"},
        "openai": {"api_key": "", "model": "gpt-4o",
                   "base_url": "https://api.openai.com/v1", "organization": ""},
        "agents": {
            "triage": {"provider": "", "model": ""},
            "analyst": {"provider": "", "model": ""},
            "summary": {"provider": "", "model": ""},
        },
        "search_provider": "claude-code-cli", "restart_required": False,
    }


@pytest.mark.parametrize("path", [
    "/api/overview", "/api/threats", f"/api/threats/{SPIDER}", f"/api/threats/{SPIDER}/graph",
    f"/api/threats/{SPIDER}/export?format=markdown", "/api/documents", "/api/documents/1",
    "/api/investigations", "/api/investigations/1", "/api/sources", "/api/settings",
])
def test_read_endpoints_require_a_session(seeded_world, path):
    assert make_client(seeded_world, authenticated=False).get(path).status_code == 401


def _scoped_client(client, seeded_world):
    from tests.scope_support import BLACKCAT, RCLONE, add_scoped_claim, add_second_investigation

    second = add_second_investigation(seeded_world)
    add_scoped_claim(seeded_world, second, BLACKCAT, object_name="BlackCat")
    add_scoped_claim(seeded_world, second, RCLONE, object_name="Rclone", object_type="tool")
    return second


def test_threat_profile_scope(client, seeded_world):
    from tests.scope_support import BLACKCAT, RCLONE

    second = _scoped_client(client, seeded_world)
    everything = client.get(f"/api/threats/{SPIDER}").json()
    assert everything["scope"] == "everything" and len(everything["facts"]) == 3
    first = client.get(f"/api/threats/{SPIDER}", params={"scope": "investigation:1"}).json()
    assert first["scope"] == "investigation:1"
    [fact] = first["facts"]
    assert fact["object"]["id"] == VOICE and len(fact["citations"]) == 2
    other = client.get(f"/api/threats/{SPIDER}", params={"scope": f"investigation:{second}"}).json()
    assert {f["object"]["id"] for f in other["facts"]} == {BLACKCAT, RCLONE}


def test_threat_graph_scope_recomputes_truncated_after_the_filter(client, seeded_world):
    second = _scoped_client(client, seeded_world)
    pooled = client.get(f"/api/threats/{SPIDER}/graph", params={"limit": 1}).json()
    assert pooled["truncated"] is True and pooled["scope"] == "everything"
    first = client.get(f"/api/threats/{SPIDER}/graph", params={"limit": 1, "scope": "investigation:1"}).json()
    assert first["truncated"] is False and {n["id"] for n in first["nodes"]} == {SPIDER, VOICE}
    assert first["scope"] == "investigation:1"
    other = client.get(f"/api/threats/{SPIDER}/graph", params={"limit": 1, "scope": f"investigation:{second}"}).json()
    assert other["truncated"] is True and len(other["edges"]) == 1


@pytest.mark.parametrize("path", [f"/api/threats/{SPIDER}", f"/api/threats/{SPIDER}/graph"])
def test_threat_endpoints_reject_an_invalid_scope_and_unknown_investigation(client, path):
    assert client.get(path, params={"scope": "everything"}).status_code == 400
    assert client.get(path, params={"scope": "investigation:x"}).status_code == 400
    missing = client.get(path, params={"scope": "investigation:999"})
    assert missing.status_code == 404 and missing.json() == {"error": "unknown investigation"}


def _add_entity(world, stix_type, name, external_id=None):
    with SQLiteStore(world.paths.db_file) as store:
        return store.create_entity(stix_type, name, AliasOrigin.DOCUMENT, external_id=external_id).id


def _link(world, subject, obj, last_seen):
    from datetime import date

    from cyllex_argus.knowledge.models import Assessment, AssessmentStatus

    with SQLiteStore(world.paths.db_file) as store:
        store.upsert_assessment(Assessment(
            subject_entity_id=subject, predicate="indicates", object_entity_id=obj,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3", last_seen=date.fromisoformat(last_seen)))


def test_threat_profile_serves_the_detail_block_per_type(client, seeded_world):
    from datetime import date

    ioc = _add_entity(seeded_world, "indicator", "evil.example")
    _link(seeded_world, SPIDER, ioc, date.today().isoformat())
    cve = _add_entity(seeded_world, "vulnerability", "Some bug", "CVE-2024-1234")
    victim = _add_entity(seeded_world, "identity", "Acme Healthcare")
    plain = _add_entity(seeded_world, "identity", "Globex")
    indicator = client.get(f"/api/threats/{ioc}").json()["detail"]
    assert indicator["kind"] == "domain" and indicator["value"] == "evil.example"
    assert indicator["freshness"] == "active" and indicator["last_seen"] == date.today().isoformat()
    assert client.get(f"/api/threats/{cve}").json()["detail"] == {"cve_id": "CVE-2024-1234"}
    assert client.get(f"/api/threats/{victim}").json()["detail"] == {"sector_hint": "healthcare"}
    assert "detail" not in client.get(f"/api/threats/{plain}").json()
    assert "detail" not in client.get(f"/api/threats/{SPIDER}").json()


def test_threat_graph_serves_freshness_on_indicator_nodes_only(client, seeded_world):
    ioc = _add_entity(seeded_world, "indicator", "203.0.113.7")
    _link(seeded_world, SPIDER, ioc, "2020-01-01")
    nodes = {n["id"]: n for n in client.get(f"/api/threats/{SPIDER}/graph").json()["nodes"]}
    assert nodes[ioc]["freshness"] == "historical"
    assert "freshness" not in nodes[SPIDER]


def test_the_web_markdown_export_declares_its_coverage(seeded_world):
    """The finding: the CLI export stated the evidence base and this one did not — and this is
    the path almost every operator uses. A profile built from part of the collection downloaded
    from here read exactly like a complete one, with nothing in the file to say otherwise."""
    from cyllex_argus.knowledge.models import NewDocument, Stage

    svc = seeded_world.services()
    try:
        investigation = svc.store.create_investigation("Scattered Spider", SPIDER)
        publisher = svc.store.get_or_create_publisher("CISA", default_reliability="A")
        failed, _ = svc.store.add_document(NewDocument(
            url="https://www.cisa.gov/unreachable", canonical_url="https://www.cisa.gov/unreachable",
            title="Could not be fetched", publisher_id=publisher.id,
            content_hash="hash-unreachable", raw_path="", text="",
        ), stage=Stage.FAILED, failure_reason="HTTP 403")
        svc.store.link_document(investigation.id, failed.id)
    finally:
        svc.close()

    body = make_client(seeded_world).get(f"/api/threats/{SPIDER}/export?format=markdown").text

    assert "## Evidence base" in body
    assert "could not be retrieved or parsed" in body
    # And the sentence a reader cannot derive from the findings themselves.
    assert "may be absent from the reporting" in body
