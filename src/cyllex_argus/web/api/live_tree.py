"""Live pipeline tree for the Threat profile.

A compact snapshot of a running (or just-finished) investigation shaped for the UI:
one summary line per pipeline stage (Collect, Triage, Analyze, Validate), the docs
under the active stage with their state and facts count, Validator decision counters,
and a totals footer. The data comes entirely from the local store:

- `investigations` row — target + state + started_at + elapsed.
- `investigation_documents` ⋈ `documents` — docs attached, each with its `Stage` and
  URL/title. The active Analyst stage expands those; the earlier stages collapse to
  a count summary.
- `claims` filtered by investigation + grouped by document — the per-doc facts count.
- `pipeline_events` filtered by investigation + stage='validator' — the decision
  counters (accepted / rejected / captured-as-sector / swapped) and the latest
  reason of each kind.

The endpoint is read-only and cheap: a handful of indexed queries, no joins beyond
the pre-indexed ones. The client polls it on an interval (TanStack Query
`refetchInterval`); SSE is a 0.19 story.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from cyllex_argus.web.deps import RowId, open_services

router = APIRouter()


# Which doc.stage values map to which pipeline stage having "touched" the doc.
# A doc in TRIAGED has passed Collect+Triage and is waiting for the Analyst.
# A doc in VALIDATED has passed all four. IRRELEVANT docs stopped at Triage.
# A FAILED doc stopped wherever it failed; we count it as having passed through
# everything up to and including the stage that failed, which pipeline_events logs.
_STAGE_ORDER: tuple[str, ...] = ("collect", "triage", "analyze", "validate")

# Validator decisions we care to count. Everything else is noise for this view.
_VALIDATOR_DECISIONS_ACCEPTED = {"accepted", "swapped-malware-to-actor", "captured-as-sector"}
_VALIDATOR_DECISIONS_REJECTED = {"rejected"}


class StageSummary(BaseModel):
    key: Literal["collect", "triage", "analyze", "validate"]
    state: Literal["done", "active", "queued"]
    summary: str  # One-line human readable rendering of this stage's counts
    latest_reason: str | None = None  # The most recent pipeline_events.reason for this stage


class DocProgress(BaseModel):
    document_id: int
    title: str
    url: str | None
    state: Literal["done", "running", "queued", "failed", "irrelevant"]
    facts_count: int
    elapsed_secs: float | None  # Analyst-stage elapsed, from the event duration_ms


class ValidatorCounters(BaseModel):
    accepted: int
    rejected: int
    captured_as_sector: int
    swapped: int
    latest_reject: str | None = None
    latest_capture: str | None = None


class Totals(BaseModel):
    claims: int
    docs_analyzed: int  # VALIDATED
    docs_remaining: int  # TRIAGED (queued for Analyst)


class LivePipelineTree(BaseModel):
    investigation_id: int
    target: str
    state: Literal["running", "paused", "finished"]
    elapsed_secs: int
    prompt_version: str | None  # the Analyst prompt the Analyst is currently using
    stages: list[StageSummary]
    docs: list[DocProgress]  # under the active stage; empty when all stages are done
    validator: ValidatorCounters
    totals: Totals


def _elapsed_seconds(started_at: datetime, finished_at: datetime | None) -> int:
    """Seconds between started_at and now (or finished_at if the run is over).

    Clamped at 0 so a clock skew between the DB write and the API read never produces
    a negative render that the UI then has to defend against.
    """
    end = finished_at or datetime.now(UTC)
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    return max(0, int((end - started_at).total_seconds()))


def _docs_by_stage(conn, investigation_id: int) -> dict[str, list[dict]]:
    """One list per Stage value for docs attached to this investigation. Carries
    enough columns per doc for the Analyst-stage expansion below."""
    rows = conn.execute(
        """SELECT d.id AS id, d.title AS title, d.canonical_url AS url, d.stage AS stage
           FROM documents d
           JOIN investigation_documents l ON l.document_id = d.id
           WHERE l.investigation_id = ?
           ORDER BY d.id""",
        (investigation_id,),
    ).fetchall()
    buckets: dict[str, list[dict]] = {"collected": [], "triaged": [], "validated": [],
                                       "irrelevant": [], "failed": []}
    for r in rows:
        buckets.setdefault(r["stage"], []).append(dict(r))
    return buckets


def _facts_by_doc(conn, investigation_id: int) -> dict[int, int]:
    rows = conn.execute(
        """SELECT document_id, COUNT(*) AS n FROM claims
           WHERE investigation_id = ? AND quote_status != 'rejected'
           GROUP BY document_id""",
        (investigation_id,),
    ).fetchall()
    return {r["document_id"]: int(r["n"]) for r in rows}


def _analyst_elapsed_by_doc(conn, investigation_id: int) -> dict[int, float]:
    """Latest Analyst-stage duration (seconds) recorded per document."""
    rows = conn.execute(
        """SELECT document_id, duration_ms FROM pipeline_events
           WHERE investigation_id = ? AND stage = 'analyst' AND decision != 'failed'
           ORDER BY id DESC""",
        (investigation_id,),
    ).fetchall()
    out: dict[int, float] = {}
    for r in rows:
        if r["document_id"] not in out and r["duration_ms"] is not None:
            out[r["document_id"]] = float(r["duration_ms"]) / 1000.0
    return out


def _in_flight_docs(conn, investigation_id: int) -> set[int]:
    """Docs the pipeline has started but not yet finished — i.e. their last pipeline_event
    is `stage=pipeline, decision=started` with no terminal event after it.

    Used by the live tree to paint "running" chips on the N documents that the
    parallel workers are currently chewing on. On a sequential run (concurrency=1)
    this set has at most one doc at a time; on `--concurrency=5` it has up to five.
    """
    rows = conn.execute(
        """SELECT document_id, decision FROM pipeline_events
           WHERE investigation_id = ? AND document_id IS NOT NULL
             AND (stage = 'pipeline' OR decision IN ('analyzed', 'validated', 'triaged-out',
                                                      'irrelevant', 'failed'))
           ORDER BY id ASC""",
        (investigation_id,),
    ).fetchall()
    # Walk the stream per doc: `started` opens the flag, any decision we consider terminal
    # closes it. The doc id stays in the set only if its last relevant event was `started`.
    in_flight: set[int] = set()
    for r in rows:
        doc_id = r["document_id"]
        if r["decision"] == "started":
            in_flight.add(doc_id)
        else:
            in_flight.discard(doc_id)
    return in_flight


def _validator_counters(conn, investigation_id: int) -> ValidatorCounters:
    """Counters from pipeline_events (stage='validator') + latest reason per kind.

    Note on `accepted`: the Validator does not emit a separate accepted event today — it
    just writes the claim to the store. So accepted = claims count minus rejects/captures.
    We compute that in the caller where we already have the claims count.
    """
    rows = conn.execute(
        """SELECT decision, reason, created_at FROM pipeline_events
           WHERE investigation_id = ? AND stage = 'validator'
           ORDER BY id DESC""",
        (investigation_id,),
    ).fetchall()
    rejected = captured = swapped = 0
    latest_reject = latest_capture = None
    for r in rows:
        d = r["decision"]
        if d == "rejected":
            rejected += 1
            if latest_reject is None:
                latest_reject = r["reason"]
        elif d == "captured-as-sector":
            captured += 1
            if latest_capture is None:
                latest_capture = r["reason"]
        elif d == "swapped-malware-to-actor":
            swapped += 1
    return ValidatorCounters(
        accepted=0,  # filled in by the caller
        rejected=rejected,
        captured_as_sector=captured,
        swapped=swapped,
        latest_reject=latest_reject,
        latest_capture=latest_capture,
    )


def _latest_reason(conn, investigation_id: int, stage: str) -> str | None:
    row = conn.execute(
        """SELECT reason FROM pipeline_events
           WHERE investigation_id = ? AND stage = ? AND reason IS NOT NULL
           ORDER BY id DESC LIMIT 1""",
        (investigation_id, stage),
    ).fetchone()
    return row["reason"] if row is not None else None


def _pick_active_stage(docs: dict[str, list[dict]], inv_state: str) -> str | None:
    """The stage the UI should expand with its docs.

    If the investigation is still running: the Analyst/Validator loop is where docs
    are moving, so we expand `analyze` whenever any doc is still TRIAGED (queued for
    analyst) OR we have docs in VALIDATED but the run has not finished yet (so the
    last few just arrived).

    If the investigation is finished: no stage is active, we return None.
    """
    if inv_state == "finished":
        return None
    if docs.get("triaged") or docs.get("validated"):
        return "analyze"
    if docs.get("collected"):
        return "triage"
    # No docs collected yet: we are still in the Collector pass.
    return "collect"


def build_live_tree(services, investigation_id: int) -> LivePipelineTree | None:
    """Return the LivePipelineTree, or None if the investigation does not exist."""
    try:
        inv = services.store.get_investigation(investigation_id)
    except KeyError:
        return None

    from cyllex_argus.pipeline.analyst import ANALYST_PROMPT_VERSION

    conn = services.store.connection
    docs = _docs_by_stage(conn, investigation_id)
    facts = _facts_by_doc(conn, investigation_id)
    analyst_times = _analyst_elapsed_by_doc(conn, investigation_id)
    counters = _validator_counters(conn, investigation_id)
    in_flight = _in_flight_docs(conn, investigation_id)

    # Total claims kept + fill in the "accepted" field now that we have the number.
    total_claims = sum(facts.values())
    counters.accepted = total_claims

    # Stage summaries. "done" vs "active" vs "queued" is determined per stage.
    inv_state = inv.state.value
    active = _pick_active_stage(docs, inv_state)

    collected_total = sum(len(v) for v in docs.values())
    triaged_in = len(docs.get("triaged", [])) + len(docs.get("validated", [])) + len(docs.get("failed", []))
    irrelevant = len(docs.get("irrelevant", []))
    analyzed = len(docs.get("validated", []))
    remaining = len(docs.get("triaged", []))

    def _state_of(key: str) -> Literal["done", "active", "queued"]:
        if key == active:
            return "active"
        order_idx = _STAGE_ORDER.index(key)
        active_idx = _STAGE_ORDER.index(active) if active in _STAGE_ORDER else len(_STAGE_ORDER)
        return "done" if order_idx < active_idx else "queued"

    stages = [
        StageSummary(
            key="collect", state=_state_of("collect"),
            summary=f"{collected_total} docs collected",
            latest_reason=_latest_reason(conn, investigation_id, "collector"),
        ),
        StageSummary(
            key="triage", state=_state_of("triage"),
            summary=f"{triaged_in} kept · {irrelevant} off-topic" if triaged_in or irrelevant else "waiting on Collect",
            latest_reason=_latest_reason(conn, investigation_id, "triage"),
        ),
        StageSummary(
            key="analyze", state=_state_of("analyze"),
            summary=f"{analyzed} / {analyzed + remaining} docs"
                    if (analyzed + remaining) > 0 else "waiting on Triage",
            latest_reason=_latest_reason(conn, investigation_id, "analyst"),
        ),
        StageSummary(
            key="validate", state=_state_of("validate"),
            summary=f"{counters.accepted} accepted · {counters.rejected} rejected"
                    if (counters.accepted + counters.rejected) > 0 else "waiting on Analyst",
            latest_reason=_latest_reason(conn, investigation_id, "validator"),
        ),
    ]

    # The docs list expands only the active Analyst stage (collect/triage/validate
    # collapse to the summary line — nothing to drill into for the operator). Order:
    # done first (VALIDATED), then running (none in V1), then queued (TRIAGED), then
    # failed, then irrelevant. The frontend sorts by state for display.
    doc_entries: list[DocProgress] = []
    if active == "analyze":
        for row in docs.get("validated", []):
            doc_entries.append(DocProgress(
                document_id=row["id"], title=row["title"], url=row["url"],
                state="done", facts_count=facts.get(row["id"], 0),
                elapsed_secs=analyst_times.get(row["id"]),
            ))
        for row in docs.get("triaged", []):
            # TRIAGED docs waiting for the Analyst — if a worker already picked this one up
            # (started event seen without a terminal event after) the UI should show it as
            # running, not queued, so the operator sees the parallel pelotón at work.
            is_running = row["id"] in in_flight
            doc_entries.append(DocProgress(
                document_id=row["id"], title=row["title"], url=row["url"],
                state="running" if is_running else "queued",
                facts_count=0,
                elapsed_secs=analyst_times.get(row["id"]) if is_running else None,
            ))
        for row in docs.get("failed", []):
            doc_entries.append(DocProgress(
                document_id=row["id"], title=row["title"], url=row["url"],
                state="failed", facts_count=facts.get(row["id"], 0),
                elapsed_secs=analyst_times.get(row["id"]),
            ))

    return LivePipelineTree(
        investigation_id=inv.id, target=inv.target, state=inv_state,
        elapsed_secs=_elapsed_seconds(inv.started_at, inv.finished_at),
        prompt_version=ANALYST_PROMPT_VERSION,
        stages=stages,
        docs=doc_entries,
        validator=counters,
        totals=Totals(claims=total_claims, docs_analyzed=analyzed, docs_remaining=remaining),
    )


@router.get("/investigations/{investigation_id}/live-tree")
def live_tree(investigation_id: RowId, request: Request) -> LivePipelineTree:
    with open_services(request) as services:
        tree = build_live_tree(services, investigation_id)
    if tree is None:
        raise HTTPException(status_code=404, detail="unknown investigation")
    return tree
