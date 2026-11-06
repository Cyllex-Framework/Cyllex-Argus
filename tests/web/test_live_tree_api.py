"""GET /api/investigations/{id}/live-tree — snapshot shape consumed by the Threat
profile's live pipeline card. Covers 404, the finished-run shape, and the active-run
expansion of docs under the Analyst stage."""

from __future__ import annotations

import sqlite3

from tests.web.conftest import make_client


def _run_one(world):
    """Seed one finished investigation on Scattered Spider via the real pipeline."""
    world.investigate()


def _seed_doc(world, *, title: str, url: str, stage: str = "triaged") -> int:
    """Attach a document to investigation #1 in the given Stage. Returns the doc id.

    The pipeline-driven investigation seeds one doc already (see tests/support.py);
    this helper gives us a second doc with a specific stage so the live-tree shape
    exercises both the "queued" and "done" paths under Analyst.
    """
    conn = sqlite3.connect(str(world.paths.db_file))
    try:
        # Minimum columns required by the documents + investigation_documents schemas.
        cursor = conn.execute(
            "SELECT COALESCE(MAX(id), 0) + 1 FROM publishers",
        )
        publisher_id = cursor.fetchone()[0]
        conn.execute(
            "INSERT OR IGNORE INTO publishers (id, name, name_key) VALUES (?, ?, ?)",
            (publisher_id, "lab-publisher", "lab-publisher"),
        )
        cursor = conn.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM documents")
        doc_id = cursor.fetchone()[0]
        conn.execute(
            """INSERT INTO documents (id, title, canonical_url, publisher_id, stage,
                                       retrieved_at, content_hash, raw_path, text)
               VALUES (?, ?, ?, ?, ?, datetime('now'), ?, ?, ?)""",
            (doc_id, title, url, publisher_id, stage, f"hash-{doc_id}", f"/tmp/doc-{doc_id}", "lab body"),
        )
        conn.execute(
            "INSERT INTO investigation_documents (investigation_id, document_id) VALUES (1, ?)",
            (doc_id,),
        )
        conn.commit()
        return doc_id
    finally:
        conn.close()


def test_unknown_investigation_is_404(seeded_world):
    client = make_client(seeded_world)
    assert client.get("/api/investigations/99999/live-tree").status_code == 404


def test_finished_investigation_has_shape_and_no_active_docs(seeded_world):
    """A finished run returns the full shape with every stage either `done` or `queued`
    — none active — and an empty `docs` list (the Analyst drill-in is only for active runs)."""
    _run_one(seeded_world)
    client = make_client(seeded_world)
    body = client.get("/api/investigations/1/live-tree").json()
    assert body["investigation_id"] == 1
    assert body["target"].lower() == "scattered spider"
    assert body["state"] == "finished"
    assert body["elapsed_secs"] >= 0
    assert body["prompt_version"].startswith("analyst-v")
    assert {s["key"] for s in body["stages"]} == {"collect", "triage", "analyze", "validate"}
    assert all(s["state"] in ("done", "queued") for s in body["stages"])
    assert body["docs"] == []
    assert body["totals"]["claims"] >= 1  # one claim lands in the seeded run
    assert body["validator"]["accepted"] == body["totals"]["claims"]


def test_in_flight_docs_render_as_running_not_queued(seeded_world):
    """When a parallel worker has picked up a doc (pipeline_events has a `started` event
    without a terminal after it), the live-tree marks it `running` so the UI paints the
    parallel pelotón at work. A `started` followed by a terminal collapses back to
    queued/done per the terminal's own semantics."""
    _run_one(seeded_world)
    conn = sqlite3.connect(str(seeded_world.paths.db_file))
    try:
        conn.execute("UPDATE investigations SET state = 'running', finished_at = NULL WHERE id = 1")
        conn.commit()
    finally:
        conn.close()
    # Two queued docs so we can mark one as in-flight and one as pure queued.
    flying_id = _seed_doc(seeded_world, title="Flying doc", url="https://lab.example/flying", stage="triaged")
    _seed_doc(seeded_world, title="Still queued", url="https://lab.example/queued", stage="triaged")
    # Simulate the Analyst/pipeline emitting the `started` marker for only the first.
    conn = sqlite3.connect(str(seeded_world.paths.db_file))
    try:
        conn.execute(
            """INSERT INTO pipeline_events (investigation_id, document_id, stage, decision, created_at)
               VALUES (1, ?, 'pipeline', 'started', datetime('now'))""",
            (flying_id,),
        )
        conn.commit()
    finally:
        conn.close()

    client = make_client(seeded_world)
    body = client.get("/api/investigations/1/live-tree").json()
    by_title = {d["title"]: d for d in body["docs"]}
    assert by_title["Flying doc"]["state"] == "running"
    assert by_title["Still queued"]["state"] == "queued"


def test_active_investigation_expands_analyst_docs(seeded_world):
    """When the pipeline is still running (state=running), the Analyst stage is `active`
    and the `docs` array lists the attached documents with their state (done/queued),
    URL and facts count. The queued doc shows 0 facts; the done one carries its claims."""
    _run_one(seeded_world)
    queued_id = _seed_doc(seeded_world, title="Queued doc", url="https://lab.example/queued", stage="triaged")

    client = make_client(seeded_world)
    # Flip the finished investigation back to running AFTER make_client — the startup
    # orphan-recovery sweep would otherwise paused this row (it is designed to catch exactly
    # a RUNNING investigation that is nobody's live job). Here we are faking a live run just
    # to exercise the live-tree view, so we hand-set the state once the sweep is past.
    conn = sqlite3.connect(str(seeded_world.paths.db_file))
    try:
        conn.execute("UPDATE investigations SET state = 'running', finished_at = NULL WHERE id = 1")
        conn.commit()
    finally:
        conn.close()
    body = client.get("/api/investigations/1/live-tree").json()
    assert body["state"] == "running"
    analyze = next(s for s in body["stages"] if s["key"] == "analyze")
    assert analyze["state"] == "active"
    # Docs list includes both the done (validated) seed doc AND the queued one.
    titles = {d["title"]: d for d in body["docs"]}
    assert "Queued doc" in titles
    assert titles["Queued doc"]["state"] == "queued"
    assert titles["Queued doc"]["url"] == "https://lab.example/queued"
    assert titles["Queued doc"]["facts_count"] == 0
    assert titles["Queued doc"]["document_id"] == queued_id
    # The seeded VALIDATED doc shows up as done with its claims.
    done_docs = [d for d in body["docs"] if d["state"] == "done"]
    assert len(done_docs) >= 1
    assert done_docs[0]["facts_count"] >= 1
    # Totals reflect analyzed vs remaining.
    assert body["totals"]["docs_remaining"] == 1
    assert body["totals"]["docs_analyzed"] >= 1
