"""Retry endpoint for failed documents."""

from __future__ import annotations

from cyllex_argus.knowledge.models import NewDocument, Stage
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _seed_failed_doc(world, *, with_text: bool = True) -> int:
    """Create a failed document directly in the store and return its id."""
    svc = world.services()
    try:
        publisher = svc.store.get_or_create_publisher("Retry Test Publisher", default_reliability="C")
        doc, _ = svc.store.add_document(
            NewDocument(
                url="https://example.test/retry-me",
                canonical_url="https://example.test/retry-me",
                title="Example that failed",
                publisher_id=publisher.id,
                content_hash="hash-" + ("full" if with_text else "empty"),
                raw_path="",
                text=("plenty of body text to work with" if with_text else ""),
            ),
            stage=Stage.FAILED, failure_reason="HTTP 503 at collection time",
        )
        return doc.id
    finally:
        svc.close()


class _QueuedJobs:
    """A JobManager stand-in that records each submit and keeps every job QUEUED; it never runs a
    handler. The real async worker would run a submitted retry at once, reset the document out of
    FAILED, and make the second request see a non-failed doc (400), which is the race this test
    used to lose under some run orders. Holding the job queued preserves the rule under test: the
    same (kind, dedupe_key) coalesces to one job, a different key does not."""

    def __init__(self):
        self._ids = {}

    def submit(self, kind, params, *, dedupe_key=None, coalesce=False):
        key = (kind, dedupe_key)
        if coalesce and key in self._ids:
            return {"id": self._ids[key], "state": "queued"}
        self._ids[key] = f"job-{len(self._ids) + 1}"
        return {"id": self._ids[key], "state": "queued"}

    def shutdown(self):
        pass


def test_retry_404_on_unknown_document(world):
    r = make_client(world).post("/api/documents/99999/retry")
    assert r.status_code == 404


def test_retry_400_on_non_failed_document(world):
    """Only failed documents can be retried — a validated one has nothing to recover."""
    svc = world.services()
    try:
        pub = svc.store.get_or_create_publisher("P", default_reliability="C")
        doc, _ = svc.store.add_document(
            NewDocument(
                url="https://example.test/ok", canonical_url="https://example.test/ok",
                title="OK", publisher_id=pub.id, content_hash="h", raw_path="", text="t",
            ),
            stage=Stage.VALIDATED,
        )
        doc_id = doc.id
    finally:
        svc.close()
    r = make_client(world).post(f"/api/documents/{doc_id}/retry")
    assert r.status_code == 400
    assert "stage=validated" in r.json()["error"]


def test_retry_returns_202_with_job_id_for_failed_doc(world):
    doc_id = _seed_failed_doc(world)
    r = make_client(world).post(f"/api/documents/{doc_id}/retry")
    assert r.status_code == 202
    assert "job_id" in r.json()


def test_retry_requires_csrf(world):
    """SecurityMiddleware blocks POST without the CSRF header, same as every other write."""
    doc_id = _seed_failed_doc(world)
    client = _make_client(world)  # NO CSRF header
    r = client.post(f"/api/documents/{doc_id}/retry")
    assert r.status_code == 403


def test_retry_requires_auth(world):
    doc_id = _seed_failed_doc(world)
    client = _make_client(world, authenticated=False)
    client.headers["X-Argus-CSRF"] = "1"
    r = client.post(f"/api/documents/{doc_id}/retry")
    assert r.status_code == 401


def test_retry_as_browser_queues_a_separate_job(world):
    """The two UA variants dedupe independently: Retry then Retry-as-browser must produce two
    jobs, not coalesce into one, because the endpoint folds `as_browser` into the dedupe key. A
    queued-jobs double holds the first retry so it cannot reset the document out of FAILED before
    the later requests (the real async worker would, racing the test)."""
    doc_id = _seed_failed_doc(world)
    client = make_client(world, jobs=_QueuedJobs())
    default_resp = client.post(f"/api/documents/{doc_id}/retry")
    browser_resp = client.post(f"/api/documents/{doc_id}/retry?as_browser=1")
    again_resp = client.post(f"/api/documents/{doc_id}/retry")
    assert default_resp.status_code == 202
    assert browser_resp.status_code == 202
    assert again_resp.status_code == 202
    # different dedupe key (as_browser) means a separate job
    assert default_resp.json()["job_id"] != browser_resp.json()["job_id"]
    # same dedupe key as the default retry coalesces to the one queued job, not a third
    assert again_resp.json()["job_id"] == default_resp.json()["job_id"]


def test_fetcher_fetch_accepts_user_agent_override():
    """Direct Fetcher test: the override replaces the default UA on the one request without
    mutating the client's long-lived headers."""
    from contextlib import contextmanager
    from unittest.mock import MagicMock

    from cyllex_argus.documents.fetch import Fetcher

    captured_headers: list[dict | None] = []

    @contextmanager
    def fake_stream(method, url, headers=None):
        captured_headers.append(headers)
        response = MagicMock()
        response.status_code = 200
        response.headers = {"content-length": "4"}
        response.iter_bytes = lambda chunk_size=65536: iter([b"body"])
        yield response

    client = MagicMock()
    client.stream = fake_stream

    fetcher = Fetcher(
        client=client, max_bytes=10 * 1024 * 1024,
        resolve_host=lambda host: [__import__("ipaddress").ip_address("8.8.8.8")],
    )
    fetcher.fetch("https://example.test/a")
    fetcher.fetch("https://example.test/b", user_agent="Mozilla/5.0")

    assert captured_headers == [None, {"User-Agent": "Mozilla/5.0"}]


def test_pipeline_retry_document_skips_non_failed(world):
    """The pipeline method itself returns status=skipped (not a crash) when asked to retry a
    document that is not failed. This mirrors the API's 400 but at the Python layer, so a
    scripted caller gets a clean message instead of an exception."""
    svc = world.services()
    try:
        pub = svc.store.get_or_create_publisher("P", default_reliability="C")
        doc, _ = svc.store.add_document(
            NewDocument(
                url="https://example.test/ok", canonical_url="https://example.test/ok",
                title="OK", publisher_id=pub.id, content_hash="h", raw_path="", text="t",
            ),
            stage=Stage.VALIDATED,
        )
        result = svc.pipeline().retry_document(doc.id)
        assert result["status"] == "skipped"
        assert "not failed" in result["message"]
    finally:
        svc.close()


def test_pipeline_retry_fetch_failure_leaves_doc_failed_with_fresh_reason(world):
    """When a failed-at-collection doc has its URL re-fetched and the server still refuses,
    the doc stays FAILED and the failure_reason reflects the NEW attempt — not the stale
    original one. A noisy third-party transient becomes evidence that the resource is really
    gone, not a mysterious old 503."""
    doc_id = _seed_failed_doc(world, with_text=False)
    svc = world.services()
    try:
        # Replace the fetcher with one that raises FetchError, deterministically.
        from cyllex_argus.documents.fetch import FetchError
        pipeline = svc.pipeline()

        class RefusingFetcher:
            def fetch(self, url, user_agent=None):  # noqa: ARG002 — matches the real signature
                raise FetchError(f"HTTP 410 for {url}")

        pipeline._fetcher = RefusingFetcher()
        result = pipeline.retry_document(doc_id)
        assert result["status"] == "fetch-failed"
        assert "HTTP 410" in result["message"]
        # Doc stays failed with the fresh reason, not the stale "HTTP 503 at collection time".
        fresh = svc.store.get_document(doc_id)
        assert fresh.stage is Stage.FAILED
        assert "HTTP 410" in (fresh.failure_reason or "")
    finally:
        svc.close()
