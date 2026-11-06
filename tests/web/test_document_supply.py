"""The operator supplies a document the collector could not fetch.

Some refusals never go away — a publisher's access policy, a page behind a login, a host that
times out — so "Retry" is a dead end for them, and the document stays a hole in an evidence base
the dossier now has to declare. This is the way out: open the page in your own browser, save it,
hand Argus the file.

What these tests hold is that it repairs the SAME document. Reusing the row is the whole point:
the URL, the publisher and the `investigation_documents` links are what make the supplied
document close the coverage gap instead of becoming a second, unlinked record beside it.
"""

from __future__ import annotations

from cyllex_argus.knowledge.models import NewDocument, Stage
from tests.web.conftest import make_client as _make_client

HTML = b"<html><head><title>The Saved Advisory</title></head><body><p>" + b"body text " * 40 + b"</p></body></html>"


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _seed(world, *, stage: Stage = Stage.FAILED, investigation: bool = False) -> int:
    svc = world.services()
    try:
        publisher = svc.store.get_or_create_publisher("CISA", default_reliability="A")
        doc, _ = svc.store.add_document(
            NewDocument(
                url="https://www.cisa.gov/advisory", canonical_url="https://www.cisa.gov/advisory",
                title="Advisory that could not be fetched", publisher_id=publisher.id,
                content_hash="hash-empty", raw_path="", text="",
            ),
            stage=stage, failure_reason="HTTP 403 for https://www.cisa.gov/advisory",
        )
        if investigation:
            inv = svc.store.create_investigation("Scattered Spider")
            svc.store.link_document(inv.id, doc.id)
        return doc.id
    finally:
        svc.close()


def _document(world, document_id: int):
    svc = world.services()
    try:
        return svc.store.get_document(document_id)
    finally:
        svc.close()


def test_supply_404_on_unknown_document(world):
    response = make_client(world).post("/api/documents/99999/supply", files={"file": ("a.html", HTML)})
    assert response.status_code == 404


def test_supply_400_on_a_document_that_is_not_failed(world):
    """A validated document has nothing to repair, and quietly replacing its body from an upload
    would be a way to rewrite evidence without saying so."""
    document_id = _seed(world, stage=Stage.VALIDATED)
    response = make_client(world).post(
        f"/api/documents/{document_id}/supply", files={"file": ("a.html", HTML)}
    )
    assert response.status_code == 400
    assert "only failed documents" in response.json()["error"]


def test_supply_400_on_an_empty_file(world):
    document_id = _seed(world)
    response = make_client(world).post(
        f"/api/documents/{document_id}/supply", files={"file": ("a.html", b"")}
    )
    assert response.status_code == 400
    assert "empty" in response.json()["error"]


def test_supply_hands_the_work_to_a_job_rather_than_doing_it_in_the_request(world):
    """202 with a job id: the long write belongs to the single job worker, as it does for retry.

    This asserted the document was still FAILED right after the response, which was a race
    against the worker thread, not a contract — it passed four runs in five. The job id IS the
    evidence that the work was handed over; that the handover produces the right result is
    `test_supplied_content_repairs_the_same_document`.
    """
    document_id = _seed(world)
    response = make_client(world).post(
        f"/api/documents/{document_id}/supply", files={"file": ("saved.html", HTML)}
    )
    assert response.status_code == 202
    assert response.json()["job_id"]


def test_supply_requires_authentication(world):
    client = _make_client(world, authenticated=False)
    client.headers["X-Argus-CSRF"] = "1"
    document_id = _seed(world)
    response = client.post(f"/api/documents/{document_id}/supply", files={"file": ("a.html", HTML)})
    assert response.status_code == 401


# -- the pipeline half, where the repair actually happens -------------------------------------


def test_supplied_content_repairs_the_same_document(world):
    """The row is reused, so everything that made it part of an investigation survives."""
    document_id = _seed(world, investigation=True)
    before = _document(world, document_id)

    svc = world.services()
    try:
        result = svc.pipeline().supply_document(document_id, HTML, "saved.html")
        links = svc.store.investigations_for_document(document_id)
    finally:
        svc.close()

    after = _document(world, document_id)
    assert result["status"] == "finished"
    assert after.id == before.id
    # The URL and the publisher are the publisher's, not the operator's filename.
    assert after.url == before.url
    assert after.publisher_id == before.publisher_id
    # And the link to the run that collected it: this is what makes the coverage gap close.
    assert links, "a supplied document must stay in its investigation"
    assert "body text" in after.text
    assert after.title == "The Saved Advisory"
    assert after.stage is not Stage.FAILED


def test_an_unreadable_upload_blames_the_file_not_the_publisher(world):
    """The operator needs to know their own file was the problem; the old 403 would mislead."""
    document_id = _seed(world)
    svc = world.services()
    try:
        result = svc.pipeline().supply_document(document_id, b"%PDF-1.4 not really a pdf", "broken.pdf")
    finally:
        svc.close()

    after = _document(world, document_id)
    assert result["status"] == "extract-failed"
    assert after.stage is Stage.FAILED
    assert "broken.pdf" in (after.failure_reason or "")


def test_supplying_a_document_that_is_not_failed_changes_nothing(world):
    document_id = _seed(world, stage=Stage.VALIDATED)
    svc = world.services()
    try:
        result = svc.pipeline().supply_document(document_id, HTML, "saved.html")
    finally:
        svc.close()
    assert result["status"] == "skipped"
    assert _document(world, document_id).text == ""


def test_a_second_upload_while_one_is_processing_is_refused(world):
    """Two uploads for one document are two different files. Answering the second with the job
    that already holds the first would analyse the wrong body and say nothing about it — and the
    refusal has to clean up, or every rejected upload leaks a file into ~/.cyllex-argus/uploads.
    """
    from cyllex_argus.web.jobs import DuplicateJobError

    class _Busy:
        def submit(self, *args, **kwargs):
            raise DuplicateJobError("busy")

        def shutdown(self):
            pass

    document_id = _seed(world)
    client = make_client(world, jobs=_Busy())

    response = client.post(f"/api/documents/{document_id}/supply", files={"file": ("a.html", HTML)})

    assert response.status_code == 409
    assert "already being processed" in response.json()["error"]
    uploads = world.paths.home / "uploads"
    assert not uploads.exists() or list(uploads.iterdir()) == [], "a refused upload must leave no file behind"


def test_content_already_in_the_store_is_refused_not_reprocessed(world):
    """The finding that would have cost the operator tokens and their failure reason.

    `update_document_content` is a no-op returning the OTHER document when the content hash
    already exists — `documents.content_hash` is UNIQUE, and the same report served at two URLs
    or re-uploaded after a refused attempt hits it. Carrying on reset this still-empty row to
    COLLECTED, ran the Analyst over no text, and reported success.
    """
    svc = world.services()
    try:
        publisher = svc.store.get_or_create_publisher("CISA", default_reliability="A")
        # The same body, already stored under a different URL.
        from cyllex_argus.documents.extract import content_hash
        twin, _ = svc.store.add_document(NewDocument(
            url="https://www.cisa.gov/elsewhere", canonical_url="https://www.cisa.gov/elsewhere",
            title="The Saved Advisory", publisher_id=publisher.id,
            content_hash=content_hash(HTML), raw_path="raw/twin", text="body text",
        ), stage=Stage.VALIDATED)
    finally:
        svc.close()
    document_id = _seed(world)

    svc = world.services()
    try:
        result = svc.pipeline().supply_document(document_id, HTML, "saved.html")
    finally:
        svc.close()

    after = _document(world, document_id)
    assert result["status"] == "duplicate"
    assert result["duplicate_of"] == twin.id
    # Still failed, with a reason that is true and names where the content already lives.
    assert after.stage is Stage.FAILED
    assert f"#{twin.id}" in (after.failure_reason or "")
    assert after.text == "", "the row must not have been reprocessed with no content"


def test_supply_refuses_when_the_attack_catalog_is_not_loaded(world):
    """A supply runs Triage and the Analyst, so it needs the prerequisite every other pipeline
    entry point checks. Against an empty catalog it resolves nothing and writes one entity per
    group name it reads."""
    document_id = _seed(world)
    svc = world.services()
    try:
        svc.store.connection.execute("DELETE FROM aliases")
        svc.store.connection.execute("DELETE FROM entities")
        svc.store.connection.commit()
    finally:
        svc.close()

    response = make_client(world).post(
        f"/api/documents/{document_id}/supply", files={"file": ("a.html", HTML)}
    )

    assert response.status_code == 409
    assert "ATT&CK data is missing" in response.json()["error"]
