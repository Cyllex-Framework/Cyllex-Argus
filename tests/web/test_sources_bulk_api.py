"""HTTP API for the two bulk publisher actions: grade the recognised ones, merge the duplicates.

These exist in the API because the operator lives in the UI, and they are the two highest-leverage
things anyone can do to this knowledge base — one lifts every assessment off the confidence floor,
the other stops a source corroborating itself. The contract these tests hold: a GET proposes and
explains, a POST applies, and nothing a human decided is ever quietly undone.
"""

from __future__ import annotations

from datetime import date

from cyllex_argus.knowledge.models import NewDocument
from tests.web.conftest import make_client as _make_client

CISA = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _publisher(world, name: str, tag: str | None = None, url: str = CISA) -> int:
    """A publisher with, optionally, a document that reveals which organisation it belongs to."""
    svc = world.services()
    try:
        publisher = svc.store.get_or_create_publisher(name)
        if tag is not None:
            svc.store.add_document(NewDocument(
                url=f"{url}-{tag}", canonical_url=f"{url}-{tag}", title=f"Advisory {tag}",
                publisher_id=publisher.id, published_at=date(2025, 1, 10),
                content_hash=f"hash-{tag}", raw_path=f"raw/{tag}", text="Some text",
            ))
        return publisher.id
    finally:
        svc.close()


def _reliabilities(world) -> dict[str, str]:
    svc = world.services()
    try:
        return {p.name: p.reliability for p in svc.store.list_publishers()}
    finally:
        svc.close()


# -- grading ---------------------------------------------------------------------------------


def test_gradeable_explains_every_proposal(world):
    _publisher(world, "CISA", "a")
    _publisher(world, "Some Person's Blog", "b", url="https://medium.com/@p/post")

    body = make_client(world).get("/api/sources/gradeable").json()

    [proposal] = body["proposals"]
    assert (proposal["name"], proposal["current"], proposal["proposed"]) == ("CISA", "F", "A")
    # The reason travels with the proposal: the operator is being asked to accept an analytic
    # judgement, not a software default.
    assert "primary incident access" in proposal["rationale"]
    assert proposal["organisation"] == "cisa.gov"
    # And the UI must be able to say what is NOT covered, rather than implying the job is done.
    assert body["unjudged"] == 2
    assert body["unrecognised"] == 1
    assert body["publishers"] == 2


def test_gradeable_is_read_only(world):
    _publisher(world, "CISA", "a")
    make_client(world).get("/api/sources/gradeable")
    assert _reliabilities(world) == {"CISA": "F"}


def test_rate_known_grades_and_queues_the_rescore(world):
    _publisher(world, "CISA", "a")
    _publisher(world, "Some Person's Blog", "b", url="https://medium.com/@p/post")

    body = make_client(world).post("/api/sources/rate-known").json()

    assert body["graded"] == 1
    assert body["job"]["id"]
    grades = _reliabilities(world)
    assert grades["CISA"] == "A"
    # A publisher Argus cannot speak to stays unjudged, which is the accurate answer.
    assert grades["Some Person's Blog"] == "F"


def test_rate_known_never_undoes_a_human_grade(world):
    publisher_id = _publisher(world, "CISA", "a")
    client = make_client(world)
    client.put(f"/api/sources/{publisher_id}", json={"reliability": "C"})

    body = client.get("/api/sources/gradeable").json()
    assert body["proposals"] == []
    # It is still reported, so the UI can show that the shipped table disagrees — but under a
    # separate key, so no button can apply it by accident.
    [override] = body["would_override"]
    assert (override["current"], override["proposed"]) == ("C", "A")

    assert client.post("/api/sources/rate-known").json()["graded"] == 0
    assert _reliabilities(world)["CISA"] == "C"


def test_nothing_to_grade_is_a_valid_answer(world):
    body = make_client(world).get("/api/sources/gradeable").json()
    assert body == {"proposals": [], "would_override": [], "unjudged": 0,
                    "unrecognised": 0, "publishers": 0}


# -- merging ---------------------------------------------------------------------------------


def test_duplicates_are_reported_with_what_each_row_holds(world):
    keep = _publisher(world, "CISA", "a")
    _publisher(world, "CISA", "b")  # same byline, same row — not a duplicate
    other = _publisher(world, "US-CERT", "c")

    body = make_client(world).get("/api/sources/duplicates").json()

    [group] = body["groups"]
    assert group["org_key"] == "cisa.gov"
    assert body["rows"] == 2
    assert {group["keep"]["id"]} | {row["id"] for row in group["drop"]} == {keep, other}
    # Document counts are shown because they are how the surviving byline was chosen.
    assert group["keep"]["documents"] == 2


def test_duplicates_is_read_only(world):
    _publisher(world, "CISA", "a")
    _publisher(world, "US-CERT", "b")
    client = make_client(world)
    client.get("/api/sources/duplicates")
    assert len(client.get("/api/sources").json()) == 2


def test_merge_folds_the_rows_and_keeps_every_byline(world):
    _publisher(world, "CISA", "a")
    _publisher(world, "US-CERT", "b")
    client = make_client(world)

    body = client.post("/api/sources/merge-duplicates", json={"org_keys": []}).json()

    assert (body["groups"], body["rows_merged"]) == (1, 1)
    assert body["documents_moved"] == 1
    assert body["job"]["id"]
    [row] = client.get("/api/sources").json()
    # Nothing about who reported what is lost: the folded byline is still on the row.
    assert sorted([row["name"], *row["also_known_as"]]) == ["CISA", "US-CERT"]


def test_merge_can_take_one_organisation_at_a_time(world):
    """The grouping rules are conservative, but an operator who disagrees with one organisation
    should not have to accept or reject the whole scan."""
    _publisher(world, "CISA", "a")
    _publisher(world, "US-CERT", "b")
    _publisher(world, "NCSC-UK", "c", url="https://www.ncsc.gov.uk/report")
    _publisher(world, "UK NCSC", "d", url="https://www.ncsc.gov.uk/report")
    client = make_client(world)

    body = client.post("/api/sources/merge-duplicates", json={"org_keys": ["cisa.gov"]}).json()

    assert body["groups"] == 1
    remaining = client.get("/api/sources/duplicates").json()
    assert [group["org_key"] for group in remaining["groups"]] == ["ncsc.gov.uk"]


def test_merging_an_already_merged_organisation_says_so(world):
    _publisher(world, "CISA", "a")
    _publisher(world, "US-CERT", "b")
    client = make_client(world)
    client.post("/api/sources/merge-duplicates", json={"org_keys": ["cisa.gov"]})

    response = client.post("/api/sources/merge-duplicates", json={"org_keys": ["cisa.gov"]})

    # Not a silent success: a stale UI must learn that its view is out of date.
    assert response.status_code == 409
    assert "already be merged" in response.json()["error"]


def test_both_actions_require_authentication(world):
    client = _make_client(world, authenticated=False)
    client.headers["X-Argus-CSRF"] = "1"
    for method, path in (
        ("get", "/api/sources/gradeable"),
        ("get", "/api/sources/duplicates"),
        ("post", "/api/sources/rate-known"),
        ("post", "/api/sources/merge-duplicates"),
    ):
        response = getattr(client, method)(path, **({"json": {}} if method == "post" else {}))
        assert response.status_code == 401, (method, path, response.status_code)


def test_the_duplicates_endpoint_still_reports_every_row_in_a_group(world):
    """`/api/health` counts the rows to REMOVE; this endpoint reports the rows INVOLVED, because
    the Sources page says "N rows are M organisations". Both numbers are right for their
    sentence, which is why the two are computed differently and this pins the difference."""
    _publisher(world, "CISA", "a")
    _publisher(world, "US-CERT", "b")
    client = make_client(world)

    duplicates = client.get("/api/sources/duplicates").json()
    health = client.get("/api/health").json()["totals"]

    assert duplicates["rows"] == 2            # two rows are one organisation
    assert health["duplicate_publisher_rows"] == 1   # one of them is redundant
