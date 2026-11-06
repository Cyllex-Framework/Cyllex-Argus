import sqlite3
from datetime import date

import pytest

from cyllex_argus.knowledge import browse as browse_module
from cyllex_argus.knowledge.browse import BrowseQueries
from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
    ClaimDraft,
    NewDocument,
    QuoteStatus,
)
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.pipeline.quotes import QuoteLocator
from tests.support import SPIDER

VOICE = "attack-pattern--00000000-0000-4000-8000-000015660004"
PHISHING = "attack-pattern--00000000-0000-4000-8000-000000001566"
BLACKCAT = "malware--00000000-0000-4000-8000-000000001068"
RCLONE = "tool--00000000-0000-4000-8000-000000001040"


def add_assessment(world, subject, predicate, obj):
    with SQLiteStore(world.paths.db_file) as store:
        store.upsert_assessment(Assessment(
            subject_entity_id=subject, predicate=predicate, object_entity_id=obj,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3"))


def test_overview_counts_and_recent(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        data = browse.overview()
    assert data["counts"]["threats"] == 1
    assert data["counts"]["documents"] == {"failed": 1, "irrelevant": 1, "validated": 2}
    assert data["counts"]["assessments"] == {"corroborated": 1}
    assert data["counts"]["investigations"] == 1
    [recent] = data["recent_investigations"]
    assert recent["target"] == "Scattered Spider" and recent["state"] == "finished"
    assert recent["stage_counts"]["validated"] == 2
    assert {p["name"] for p in data["unrated_publishers"]} >= {"Mandiant", "Microsoft"}


def test_list_threats_defaults_to_entities_with_facts(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        results = browse.list_threats()
        by_alias = browse.list_threats(q="octo")
        catalog = browse.list_threats(include_catalog=True)
        typed = browse.list_threats(stix_type="attack-pattern")
    ids = [r["id"] for r in results]
    assert SPIDER in ids and VOICE in ids
    spider = next(r for r in results if r["id"] == SPIDER)
    assert spider["facts"] == 1 and spider["attack"] is True and spider["label"] == "Scattered Spider (G1015)"
    assert [r["id"] for r in by_alias] == [SPIDER]
    assert len(catalog) > len(results)
    assert all(r["stix_type"] == "attack-pattern" for r in typed)
    voice = next(r for r in typed if r["id"] == VOICE)
    assert voice["label"] == "Spearphishing Voice (T1566.004)"


def test_list_threats_query_is_not_a_like_wildcard(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        assert browse.list_threats(q="%") == browse.list_threats(q="")
        assert browse.list_threats(q="_") == browse.list_threats(q="")


def test_aliases_with_origin(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        aliases = browse.aliases_with_origin(SPIDER)
    assert {"alias": "UNC3944", "origin": "attack"} in aliases


def test_graph_depth_one(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        graph = browse.graph(SPIDER, depth=1)
        missing = browse.graph("intrusion-set--nope")
    node_ids = {n["id"] for n in graph["nodes"]}
    assert node_ids == {SPIDER, VOICE}
    [edge] = graph["edges"]
    assert (edge["source"], edge["target"], edge["predicate"]) == (SPIDER, VOICE, "uses")
    assert edge["status"] == "corroborated" and edge["id"] == f"{SPIDER}|uses|{VOICE}"
    spider = next(n for n in graph["nodes"] if n["id"] == SPIDER)
    assert spider["type"] == "intrusion-set" and spider["attack"] is True
    assert missing == {"nodes": [], "edges": [], "truncated": False}


def test_graph_respects_max_nodes(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        graph = browse.graph(SPIDER, depth=2, max_nodes=1)
    assert [n["id"] for n in graph["nodes"]] == [SPIDER]
    assert graph["edges"] == []


def test_attack_counts_and_sources(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        counts = browse.attack_counts()
        sources = browse.list_sources()
    assert counts == {"techniques": 2, "groups": 1, "software": 2}
    mandiant = next(s for s in sources if s["name"] == "Mandiant")
    assert mandiant["reliability"] == "F" and mandiant["documents"] >= 1


def test_graph_second_hop_only_appears_at_depth_two(seeded_world):
    add_assessment(seeded_world, BLACKCAT, "uses", VOICE)  # BLACKCAT is reachable from SPIDER only via VOICE
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        one = browse.graph(SPIDER, depth=1)
        two = browse.graph(SPIDER, depth=2)
    assert {n["id"] for n in one["nodes"]} == {SPIDER, VOICE}
    assert {n["id"] for n in two["nodes"]} == {SPIDER, VOICE, BLACKCAT}
    assert {e["id"] for e in two["edges"]} == {f"{SPIDER}|uses|{VOICE}", f"{BLACKCAT}|uses|{VOICE}"}
    blackcat = next(n for n in two["nodes"] if n["id"] == BLACKCAT)
    assert blackcat["label"] == "BlackCat (S1068)" and blackcat["type"] == "malware"


def test_graph_depth_is_clamped_to_three(seeded_world):
    add_assessment(seeded_world, BLACKCAT, "uses", VOICE)
    add_assessment(seeded_world, BLACKCAT, "uses", PHISHING)  # third hop from SPIDER
    add_assessment(seeded_world, PHISHING, "uses", RCLONE)  # fourth hop
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        two = browse.graph(SPIDER, depth=2)
        five = browse.graph(SPIDER, depth=5)
        three = browse.graph(SPIDER, depth=3)
        zero = browse.graph(SPIDER, depth=0)
        one = browse.graph(SPIDER, depth=1)
    assert PHISHING not in {n["id"] for n in two["nodes"]}
    assert PHISHING in {n["id"] for n in three["nodes"]}
    assert RCLONE not in {n["id"] for n in five["nodes"]}
    assert five == three
    assert zero == one


def test_graph_from_an_entity_that_is_only_ever_an_assessment_object(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        graph = browse.graph(VOICE, depth=1)
        threats = browse.list_threats()
    assert {n["id"] for n in graph["nodes"]} == {SPIDER, VOICE}
    [edge] = graph["edges"]
    assert (edge["source"], edge["target"]) == (SPIDER, VOICE)
    assert next(t for t in threats if t["id"] == VOICE)["facts"] == 1


def test_graph_max_nodes_cap_leaves_no_dangling_edges(seeded_world):
    add_assessment(seeded_world, SPIDER, "uses", BLACKCAT)
    add_assessment(seeded_world, SPIDER, "uses", RCLONE)
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        capped = browse.graph(SPIDER, depth=1, max_nodes=2)
        uncapped = browse.graph(SPIDER, depth=1)
        floor = browse.graph(SPIDER, depth=2, max_nodes=0)
        huge = browse.graph(SPIDER, depth=2, max_nodes=10**9)
    assert len(capped["nodes"]) == 2 and capped["nodes"][0]["id"] == SPIDER
    kept = {n["id"] for n in capped["nodes"]}
    assert capped["edges"] and all(e["source"] in kept and e["target"] in kept for e in capped["edges"])
    assert len(uncapped["nodes"]) == 4 and len(uncapped["edges"]) == 3
    assert [n["id"] for n in floor["nodes"]] == [SPIDER] and floor["edges"] == []
    assert huge == uncapped


def test_list_threats_counts_a_self_referencing_assessment_once(seeded_world):
    add_assessment(seeded_world, RCLONE, "variant-of", RCLONE)
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        rclone = next(t for t in browse.list_threats() if t["id"] == RCLONE)
    assert rclone["facts"] == 1


def test_list_threats_orders_by_facts_then_name_then_id(seeded_world):
    add_assessment(seeded_world, BLACKCAT, "uses", VOICE)
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        results = browse.list_threats()
        catalog = browse.list_threats(include_catalog=True)
    assert [r["id"] for r in results] == [VOICE, BLACKCAT, SPIDER]  # 2 facts, then 1 fact by name
    assert [r["facts"] for r in catalog] == sorted((r["facts"] for r in catalog), reverse=True)
    assert catalog == sorted(catalog, key=lambda r: (-r["facts"], r["name"].casefold(), r["id"]))


def test_list_threats_survives_injection_like_queries(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        for q in ["'; DROP TABLE entities; --", "%", "_", "\\", '" OR 1=1 --', "octo' OR '1'='1"]:
            results = browse.list_threats(q=q, include_catalog=True)
            assert isinstance(results, list)
        assert browse.list_threats(q="'; DROP TABLE entities; --") == []
        assert browse.list_threats(q="%") == browse.list_threats()
        assert [r["id"] for r in browse.list_threats(q="octo' OR '1'='1")] == []
        assert browse.list_threats() != []
        assert browse._conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0] > 0


def test_browse_connection_is_read_only(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        with pytest.raises(sqlite3.OperationalError):
            browse._conn.execute("INSERT INTO publishers (name, name_key) VALUES ('X', 'x')")
        with pytest.raises(sqlite3.OperationalError):
            browse._conn.execute("DELETE FROM assessments")
        assert browse.overview()["counts"]["threats"] == 1


def test_list_documents_and_filters(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        everything = browse.list_documents()
        failed = browse.list_documents(stage="failed")
        searched = browse.list_documents(q="deep dive")
    assert len(everything) == 4
    [gone] = failed
    assert gone["title"] == "Gone" and "404" in gone["failure_reason"]
    assert gone["location"] == "https://gone.example/404"
    assert [d["title"] for d in searched] == ["Scattered Spider deep dive"]
    assert everything[0]["id"] > everything[-1]["id"]


def test_list_documents_search_matches_the_publisher_too(world):
    # The Documents page promises "Search by title or publisher"; here the publisher is in neither title nor path.
    with SQLiteStore(world.paths.db_file) as store:
        publisher = store.get_or_create_publisher("Local files")
        store.add_document(NewDocument(
            local_path="memo.txt", title="Memo", publisher_id=publisher.id, content_hash="memo-hash",
            raw_path="raw/memo-hash", text="Memo text."))
    with BrowseQueries(world.paths.db_file) as browse:
        by_publisher = browse.list_documents(q="LOCAL FILES")
    assert [d["title"] for d in by_publisher] == ["Memo"]


def test_document_detail_with_quote_spans(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        doc_id = browse.list_documents(q="deep dive")[0]["id"]
        detail = browse.document_detail(doc_id)
        assert browse.document_detail(999_999) is None
    assert "Scattered Spider" in detail["text"]
    [claim] = detail["claims"]
    assert claim["predicate"] == "uses" and claim["quote_status"] == "verified"
    start, end = claim["span"]
    assert detail["text"][start:end].lower() == claim["quote"].lower()


def test_local_documents_expose_only_the_file_name(world, tmp_path):
    memo = tmp_path / "private" / "memo.txt"
    memo.parent.mkdir()
    memo.write_text("Memo\n\nScattered Spider operators called the IT help desk and impersonated an employee "
                    "to reset MFA.", encoding="utf-8")
    services = world.services()
    try:
        services.pipeline().ingest([memo])
    finally:
        services.close()
    with BrowseQueries(world.paths.db_file) as browse:
        [doc] = browse.list_documents()
    assert doc["location"] == "memo.txt"


@pytest.mark.parametrize("local_path", [
    r"C:\Users\x\memo.txt",  # ingested on Windows, browsed anywhere: os.path.basename would keep all of this on POSIX
    "C:/Users/x/memo.txt",
    "/home/x/memo.txt",
    r"C:\Users\x/private\memo.txt",
    "memo.txt",
])
def test_local_document_location_is_the_bare_file_name_for_any_path_style(world, local_path):
    with SQLiteStore(world.paths.db_file) as store:
        publisher = store.get_or_create_publisher("Local files")
        store.add_document(NewDocument(
            local_path=local_path, title="Memo", publisher_id=publisher.id, content_hash="memo-hash",
            raw_path="raw/memo-hash", text="Memo text."))
    with BrowseQueries(world.paths.db_file) as browse:
        [doc] = browse.list_documents()
    assert doc["location"] == "memo.txt"


def test_investigations_list_and_detail(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        [inv] = browse.list_investigations()
        detail = browse.investigation_detail(inv["id"])
        assert browse.investigation_detail(999) is None
    assert inv["state"] == "finished" and inv["stage_counts"]["validated"] == 2
    assert len(detail["documents"]) == 4
    assert detail["failures"][0]["title"] == "Gone"


# No trailing period: the locator trims edge punctuation from the quote.
QUOTED = "Operators called the IT help desk and impersonated an employee to reset MFA"


def add_claims(world, text, *claims):
    """Store one document holding `text` and one claim per (quote, quote_status) pair; return the document id."""
    with SQLiteStore(world.paths.db_file) as store:
        publisher = store.get_or_create_publisher("Example Labs")
        doc, _ = store.add_document(NewDocument(
            url="https://example.test/report", title="Report", publisher_id=publisher.id,
            content_hash="spans-hash", raw_path="raw/spans-hash", text=text))
        for quote, status in claims:
            store.add_claim(
                doc.id, ClaimDraft(subject="Scattered Spider", subject_type="intrusion-set", predicate="uses",
                                   object="Spearphishing Voice", object_type="attack-pattern", quote=quote),
                status, "analyst-v1", None, None)
        return doc.id


def test_rejected_claims_never_get_a_span_even_when_the_quote_is_in_the_text(world):
    text = f"Intro paragraph.\n\n{QUOTED}. Then they moved laterally."
    doc_id = add_claims(world, text, (QUOTED, QuoteStatus.VERIFIED), (QUOTED, QuoteStatus.REJECTED))
    with BrowseQueries(world.paths.db_file) as browse:
        verified, rejected = browse.document_detail(doc_id)["claims"]
    assert verified["quote_status"] == "verified" and text[slice(*verified["span"])] == QUOTED
    assert rejected["quote_status"] == "rejected" and rejected["span"] is None


def test_verified_fuzzy_claims_get_a_span(world):
    text = f"Intro paragraph.\n\n{QUOTED}. Then they moved laterally."
    fuzzy_quote = QUOTED.replace("impersonated", "impersonating")
    doc_id = add_claims(world, text, (fuzzy_quote, QuoteStatus.VERIFIED_FUZZY))
    with BrowseQueries(world.paths.db_file) as browse:
        [claim] = browse.document_detail(doc_id)["claims"]
    assert claim["quote_status"] == "verified_fuzzy"
    assert text[slice(*claim["span"])] == QUOTED


def test_document_detail_builds_one_locator_per_document(world, monkeypatch):
    builds = []

    class CountingLocator(QuoteLocator):
        def __init__(self, text):
            builds.append(text)
            super().__init__(text)

    monkeypatch.setattr(browse_module, "QuoteLocator", CountingLocator)
    text = f"{QUOTED} And later: {QUOTED.lower()}"
    doc_id = add_claims(world, text, (QUOTED, QuoteStatus.VERIFIED), (QUOTED.lower(), QuoteStatus.VERIFIED),
                        (QUOTED, QuoteStatus.REJECTED))
    with BrowseQueries(world.paths.db_file) as browse:
        detail = browse.document_detail(doc_id)
    assert builds == [text]
    assert [c["span"] is not None for c in detail["claims"]] == [True, True, False]


def test_document_detail_skips_the_locator_when_no_claim_can_be_located(world, monkeypatch):
    monkeypatch.setattr(browse_module, "QuoteLocator", lambda text: pytest.fail("locator built needlessly"))
    doc_id = add_claims(world, QUOTED, (QUOTED, QuoteStatus.REJECTED))
    with BrowseQueries(world.paths.db_file) as browse:
        [claim] = browse.document_detail(doc_id)["claims"]
    assert claim["span"] is None


def test_graph_limit_truncates_edges_and_flags_it(seeded_world):
    add_assessment(seeded_world, SPIDER, "uses", BLACKCAT)
    add_assessment(seeded_world, SPIDER, "uses", RCLONE)
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        full = browse.graph(SPIDER, depth=1)
        cut = browse.graph(SPIDER, depth=1, limit=1)
        exact = browse.graph(SPIDER, depth=1, limit=3)
    assert full["truncated"] is False and exact == full
    assert cut["truncated"] is True and len(cut["edges"]) == 1
    assert cut["edges"] == full["edges"][:1]
    referenced = {cut["edges"][0]["source"], cut["edges"][0]["target"]} | {SPIDER}
    assert {n["id"] for n in cut["nodes"]} == referenced


def test_graph_unknown_entity_is_not_truncated(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        assert browse.graph("intrusion-set--nope") == {"nodes": [], "edges": [], "truncated": False}


# -- investigation dashboard ------------------------------------------------------


@pytest.fixture
def tactic_catalog():
    import json

    from cyllex_argus.attack.catalog import AttackCatalog
    from tests.conftest import FIXTURES

    bundle = json.loads((FIXTURES / "attack_mini.json").read_text(encoding="utf-8"))
    for obj in bundle["objects"]:
        if obj["id"] == VOICE:
            obj["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
    return AttackCatalog(bundle)


def dashboard(world, investigation_id, catalog, **kwargs):
    with BrowseQueries(world.paths.db_file) as browse:
        return browse.investigation_dashboard(investigation_id, catalog, **kwargs)


def set_investigation(world, investigation_id, **columns):
    conn = sqlite3.connect(str(world.paths.db_file))
    try:
        sets = ", ".join(f"{name} = ?" for name in columns)
        conn.execute(f"UPDATE investigations SET {sets} WHERE id = ?", (*columns.values(), investigation_id))
        conn.commit()
    finally:
        conn.close()


def test_dashboard_of_an_unknown_investigation_is_none(seeded_world, tactic_catalog):
    assert dashboard(seeded_world, 999, tactic_catalog) is None


def test_dashboard_of_an_unresolved_investigation_has_no_entity_and_14_empty_tactics(seeded_world, tactic_catalog):
    from cyllex_argus.knowledge.attack_matrix import TACTICS

    set_investigation(seeded_world, 1, resolved_entity_id=None)
    data = dashboard(seeded_world, 1, tactic_catalog)
    assert data["entity"] is None
    tactics = data["attack_matrix"]["tactics"]
    assert [t["id"] for t in tactics] == [tid for tid, _ in TACTICS] and len(tactics) == 14
    assert all(t["techniques"] == [] for t in tactics)


def test_dashboard_of_a_resolved_investigation_has_entity_matrix_and_counts(seeded_world, tactic_catalog):
    data = dashboard(seeded_world, 1, tactic_catalog)
    header = data["investigation"]
    assert header["id"] == 1 and header["target"] == "Scattered Spider" and header["state"] == "finished"
    assert header["finished_at"] and header["failure_reason"] is None
    assert header["counts"] == {"failed": 1, "irrelevant": 1, "validated": 2}
    entity = data["entity"]
    assert entity["id"] == SPIDER and entity["name"] == "Scattered Spider" and entity["attack"] is True
    assert {"alias": "UNC3944", "origin": "attack"} in entity["aliases"]
    initial = next(t for t in data["attack_matrix"]["tactics"] if t["id"] == "initial-access")
    [technique] = initial["techniques"]
    assert technique["id"] == VOICE and technique["external_id"] == "T1566.004"
    assert technique["status"] == "corroborated"


def test_dashboard_without_a_catalog_still_lists_the_14_tactics(seeded_world):
    data = dashboard(seeded_world, 1, None)
    assert data["entity"]["id"] == SPIDER
    assert len(data["attack_matrix"]["tactics"]) == 14
    assert all(t["techniques"] == [] for t in data["attack_matrix"]["tactics"])


def test_dashboard_of_a_running_investigation(seeded_world, tactic_catalog):
    set_investigation(seeded_world, 1, state="running", finished_at=None)
    header = dashboard(seeded_world, 1, tactic_catalog)["investigation"]
    assert header["state"] == "running" and header["finished_at"] is None


def test_dashboard_of_a_failed_investigation_carries_the_failure_reason(seeded_world, tactic_catalog):
    set_investigation(seeded_world, 1, state="failed")
    header = dashboard(seeded_world, 1, tactic_catalog, failure_reason="usage limit reached")["investigation"]
    assert header["state"] == "failed" and header["failure_reason"] == "usage limit reached"


# -- investigation scope ----------------------------------------------------------------------------------------

def _facts(world, entity_id, investigation_id=None):
    from cyllex_argus.knowledge.profile import build_profile

    with SQLiteStore(world.paths.db_file) as store:
        profile = build_profile(store, store.get_entity(entity_id), investigation_id)
        return {(f.object.id, tuple(c.claim_id for c in f.citations)) for f in profile.facts}


def _matrix_ids(matrix):
    return {tech["id"] for tactic in matrix["attack_matrix"]["tactics"] for tech in tactic["techniques"]}


def test_scoped_view_of_each_investigation_shows_only_its_own_claims(seeded_world, tactic_catalog):
    from tests.scope_support import BLACKCAT, add_scoped_claim, add_second_investigation

    second = add_second_investigation(seeded_world)
    add_scoped_claim(seeded_world, second, VOICE, object_name="Spearphishing Voice", object_type="attack-pattern")
    add_scoped_claim(seeded_world, second, BLACKCAT, object_name="BlackCat")
    first_view = _facts(seeded_world, SPIDER, 1)
    second_view = _facts(seeded_world, SPIDER, second)
    everything = _facts(seeded_world, SPIDER)
    assert {obj for obj, _ in first_view} == {VOICE}
    assert {obj for obj, _ in second_view} == {VOICE, BLACKCAT}
    assert {obj for obj, _ in everything} == {VOICE, BLACKCAT}
    voice_citations = {obj: ids for obj, ids in everything}[VOICE]
    assert set(dict(first_view)[VOICE]) < set(voice_citations)  # each view cites only its own claims
    assert set(dict(first_view)[VOICE]).isdisjoint(dict(second_view)[VOICE])
    assert set(dict(first_view)[VOICE]) | set(dict(second_view)[VOICE]) == set(voice_citations)


def test_claims_without_an_investigation_never_appear_in_the_scoped_view(seeded_world):
    from tests.scope_support import BLACKCAT, add_scoped_claim

    add_scoped_claim(seeded_world, None, BLACKCAT, object_name="BlackCat")
    assert BLACKCAT in {obj for obj, _ in _facts(seeded_world, SPIDER)}
    assert BLACKCAT not in {obj for obj, _ in _facts(seeded_world, SPIDER, 1)}


def test_refuting_and_rejected_claims_do_not_contribute(seeded_world):
    from cyllex_argus.knowledge.models import Polarity
    from tests.scope_support import BLACKCAT, RCLONE, add_scoped_claim

    add_scoped_claim(seeded_world, 1, BLACKCAT, object_name="BlackCat", polarity=Polarity.REFUTES)
    add_scoped_claim(seeded_world, 1, RCLONE, object_name="Rclone", object_type="tool",
                     status=QuoteStatus.REJECTED)
    assert {obj for obj, _ in _facts(seeded_world, SPIDER, 1)} == {VOICE}


def test_scoped_matrix_and_dashboard_echo_the_scope(seeded_world, tactic_catalog):
    from tests.scope_support import add_scoped_claim, add_second_investigation

    second = add_second_investigation(seeded_world)
    everything = dashboard(seeded_world, 1, tactic_catalog)
    assert everything["scope"] == "everything" and _matrix_ids(everything) == {VOICE}
    scoped_first = dashboard(seeded_world, 1, tactic_catalog, scope_investigation_id=1)
    assert scoped_first["scope"] == "investigation:1" and _matrix_ids(scoped_first) == {VOICE}
    scoped_second = dashboard(seeded_world, 1, tactic_catalog, scope_investigation_id=second)
    assert scoped_second["scope"] == f"investigation:{second}" and _matrix_ids(scoped_second) == set()
    assert len(scoped_second["attack_matrix"]["tactics"]) == 14
    add_scoped_claim(seeded_world, second, VOICE, object_name="Spearphishing Voice", object_type="attack-pattern")
    assert _matrix_ids(dashboard(seeded_world, 1, tactic_catalog, scope_investigation_id=second)) == {VOICE}


def test_scoped_graph_keeps_only_supported_edges_and_recomputes_truncation(seeded_world):
    from tests.scope_support import BLACKCAT, RCLONE, add_scoped_claim, add_second_investigation

    second = add_second_investigation(seeded_world)
    add_scoped_claim(seeded_world, second, BLACKCAT, object_name="BlackCat")
    add_scoped_claim(seeded_world, second, RCLONE, object_name="Rclone", object_type="tool")
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        pooled = browse.graph(SPIDER, limit=1)
        first = browse.graph(SPIDER, limit=1, scope_investigation_id=1)
        both = browse.graph(SPIDER, limit=2, scope_investigation_id=second)
        empty = browse.graph(SPIDER, scope_investigation_id=999)
    assert pooled["truncated"] is True
    assert first["truncated"] is False and {n["id"] for n in first["nodes"]} == {SPIDER, VOICE}
    assert both["truncated"] is False and {n["id"] for n in both["nodes"]} == {SPIDER, BLACKCAT, RCLONE}
    assert empty == {"nodes": [{"id": SPIDER, "label": "Scattered Spider (G1015)", "type": "intrusion-set",
                                "attack": True}], "edges": [], "truncated": False}


TODAY = date(2026, 9, 30)


def add_entity(world, stix_type, name, external_id=None, aliases=()):
    with SQLiteStore(world.paths.db_file) as store:
        entity = store.create_entity(stix_type, name, AliasOrigin.DOCUMENT, external_id=external_id)
        for alias in aliases:
            store.add_alias(alias, entity.id, AliasOrigin.DOCUMENT)
    return entity.id


def add_seen(world, subject, obj, last_seen, predicate="uses"):
    with SQLiteStore(world.paths.db_file) as store:
        store.upsert_assessment(Assessment(
            subject_entity_id=subject, predicate=predicate, object_entity_id=obj,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3", last_seen=last_seen))


def test_indicator_detail_uses_the_latest_last_seen_as_subject_or_object(seeded_world):
    ioc = add_entity(seeded_world, "indicator", "evil.example")
    add_seen(seeded_world, SPIDER, ioc, date(2026, 1, 1), "indicates")
    add_seen(seeded_world, ioc, VOICE, date(2026, 9, 5), "indicates")
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        detail = browse.entity_detail(ioc, today=TODAY)
    assert detail == {"kind": "domain", "value": "evil.example", "freshness": "active", "last_seen": "2026-09-05"}


def test_indicator_without_dated_assessments_is_unknown(seeded_world):
    ioc = add_entity(seeded_world, "indicator", "203.0.113.7")
    add_seen(seeded_world, SPIDER, ioc, None, "indicates")
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        detail = browse.entity_detail(ioc, today=TODAY)
    assert detail == {"kind": "ipv4", "value": "203.0.113.7", "freshness": "unknown", "last_seen": None}


def test_identity_detail_has_a_sector_hint_only_when_a_name_matches(seeded_world):
    bank = add_entity(seeded_world, "identity", "Acme Corp", aliases=["Acme Healthcare"])
    plain = add_entity(seeded_world, "identity", "Globex")
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        assert browse.entity_detail(bank) == {"sector_hint": "healthcare"}
        assert browse.entity_detail(plain) is None


def test_vulnerability_detail_is_the_external_id_when_present(seeded_world):
    cve = add_entity(seeded_world, "vulnerability", "Some bug", external_id="CVE-2024-1234")
    bare = add_entity(seeded_world, "vulnerability", "Other bug")
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        assert browse.entity_detail(cve) == {"cve_id": "CVE-2024-1234"}
        assert browse.entity_detail(bare) is None


def test_other_types_and_unknown_entities_have_no_detail(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        assert browse.entity_detail(SPIDER) is None
        assert browse.entity_detail("indicator--nope") is None


def test_token_usage_sums_pipeline_events_by_stage(seeded_world):
    import sqlite3
    conn = sqlite3.connect(str(seeded_world.paths.db_file))
    conn.executemany(
        "INSERT INTO pipeline_events (investigation_id, stage, decision, created_at, input_tokens, output_tokens, cost_usd, model)"
        " VALUES (?, ?, 'ok', '2026-10-01T10:00:00Z', ?, ?, ?, ?)",
        [
            (1, 'triage', 100, 50, 0.0015, 'claude-sonnet-5-5'),
            (1, 'triage', 200, 80, 0.003, 'claude-sonnet-5-5'),
            (1, 'analyst', 1000, 400, 0.02, 'claude-sonnet-5-5'),
            (1, 'validator', None, None, None, None),  # deterministic, no model → ignored
            (1, 'analyst', 500, 200, 0.0, 'ollama/qwen2.5:32b-instruct'),  # local, free
        ],
    )
    conn.commit()
    conn.close()
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        usage = browse.token_usage(1)
    assert set(usage["by_stage"]) == {"triage", "analyst"}
    assert usage["by_stage"]["triage"] == {
        "calls": 2, "input_tokens": 300, "output_tokens": 130, "total_tokens": 430, "cost_usd": 0.0045,
    }
    assert usage["by_stage"]["analyst"] == {
        "calls": 2, "input_tokens": 1500, "output_tokens": 600, "total_tokens": 2100, "cost_usd": 0.02,
    }
    assert usage["total"] == {
        "calls": 4, "input_tokens": 1800, "output_tokens": 730, "total_tokens": 2530, "cost_usd": 0.0245,
    }


def test_token_usage_returns_zeros_when_no_llm_was_called(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        usage = browse.token_usage(1)
    assert usage["total"]["calls"] == 0 and usage["total"]["total_tokens"] == 0
    assert usage["by_stage"] == {} or all(v["total_tokens"] == 0 for v in usage["by_stage"].values())


def test_campaigns_for_returns_empty_list_when_no_campaign_is_linked(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        assert browse.campaigns_for(SPIDER) == []


def test_campaigns_for_lists_linked_campaigns_with_their_direct_technique_count_and_dates(seeded_world):
    camp = add_entity(seeded_world, "campaign", "Operation Flytrap", external_id="C0001")
    add_seen(seeded_world, camp, SPIDER, date(2024, 2, 1), "attributed-to")
    # The campaign carries two 'uses' edges to attack-patterns; one to another type that must not count.
    add_entity(seeded_world, "attack-pattern", "Make-believe", external_id="T9000")
    add_seen(seeded_world, camp, VOICE, date(2024, 3, 1), "uses")
    add_seen(seeded_world, camp, PHISHING, date(2024, 4, 1), "uses")
    add_seen(seeded_world, camp, BLACKCAT, date(2024, 5, 1), "uses")  # malware → ignored
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        campaigns = browse.campaigns_for(SPIDER)
    assert len(campaigns) == 1
    [row] = campaigns
    assert row["id"] == camp and row["name"] == "Operation Flytrap"
    assert row["external_id"] == "C0001" and row["label"] == "Operation Flytrap (C0001)"
    # The seeded world already has SPIDER→uses→VOICE, and the campaign is attributed-to SPIDER, so
    # VOICE is reachable both directly from the campaign and via the group. Count still de-duplicates.
    assert row["techniques"] == 2  # VOICE and PHISHING, not BLACKCAT
    assert row["first_seen"] == "2024-02-01" and row["last_seen"] == "2024-05-01"


def test_campaigns_for_counts_techniques_reachable_through_the_attributed_group(seeded_world):
    # The Analyst usually attaches `uses` to the actor, not to the campaign. The badge must still show
    # the campaign's effective TTPs: those its attributed actor is known to use.
    camp = add_entity(seeded_world, "campaign", "Op Silent", external_id="C0002")
    add_seen(seeded_world, camp, SPIDER, date(2024, 1, 1), "attributed-to")
    # The seeded world already has SPIDER uses VOICE; add one more so there are two.
    add_seen(seeded_world, SPIDER, PHISHING, date(2024, 1, 2), "uses")
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        [row] = browse.campaigns_for(SPIDER)
    assert row["id"] == camp
    # No direct 'uses' from the campaign; both TTPs are reached through SPIDER.
    assert row["techniques"] == 2


def test_campaigns_for_hides_the_entity_itself(seeded_world):
    # Even if the entity is of type 'campaign' and self-referenced, it does not show up as its own campaign.
    camp = add_entity(seeded_world, "campaign", "Self-ref")
    add_seen(seeded_world, camp, camp, date(2024, 1, 1), "uses")
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        assert browse.campaigns_for(camp) == []


def test_graph_indicator_nodes_carry_freshness_and_other_nodes_do_not(seeded_world):
    ioc = add_entity(seeded_world, "indicator", "evil.example")
    add_seen(seeded_world, SPIDER, ioc, date(2025, 1, 1), "indicates")
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        graph = browse.graph(SPIDER, depth=1, today=TODAY)
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert nodes[ioc]["freshness"] == "historical"
    assert "freshness" not in nodes[SPIDER] and "freshness" not in nodes[VOICE]
