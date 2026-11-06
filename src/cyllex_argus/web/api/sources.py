from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from cyllex_argus.knowledge.models import TLP
from cyllex_argus.knowledge.names import normalize_name
from cyllex_argus.knowledge.publisher_merge import find_duplicate_publishers, organisation_keys
from cyllex_argus.knowledge.publisher_ratings import known_rating
from cyllex_argus.web.deps import RowId, open_services

router = APIRouter()

_TLP_VALUES = ("clear", "green", "amber", "amber-strict", "red")


class ReliabilityUpdate(BaseModel):
    reliability: Literal["A", "B", "C", "D", "E", "F"]


class TlpUpdate(BaseModel):
    tlp: Literal["clear", "green", "amber", "amber-strict", "red"] | None = None


class MergeRequest(BaseModel):
    """Which duplicate groups to fold. Empty means every group the scan found.

    Explicit keys exist so the UI can offer the groups one at a time: the grouping rules are
    conservative, but an operator who disagrees with one organisation should not have to accept
    or reject the whole scan.
    """
    org_keys: list[str] = []


def _other_bylines(services, publisher_id: int, name: str) -> list[str]:
    """The names this row has published under, other than the one it currently carries.

    The row is the unit of independence, so an operator rating it needs to see whose reporting
    it speaks for — especially after a merge folded several bylines into one.
    """
    return [
        byline for byline in services.store.publisher_names(publisher_id)
        if normalize_name(byline) != normalize_name(name)
    ]


def _publisher_view(services, publisher_id: int) -> dict:
    """Shape a publisher row for the sources table, including documents count and TLP label."""
    publisher = services.store.get_publisher(publisher_id)
    documents = services.store.connection.execute(
        "SELECT COUNT(*) FROM documents WHERE publisher_id = ? OR primary_publisher_id = ?",
        (publisher_id, publisher_id),
    ).fetchone()[0]
    return {
        "id": publisher.id, "name": publisher.name, "domain": publisher.domain,
        "reliability": publisher.reliability, "documents": documents,
        "tlp": publisher.tlp.value if publisher.tlp else None,
        "org_key": publisher.org_key,
        "also_known_as": _other_bylines(services, publisher.id, publisher.name),
    }


@router.get("/sources")
def list_sources(request: Request) -> list[dict]:
    """List publishers with their reliability, document count and TLP label (if set)."""
    with open_services(request) as services:
        rows = services.store.connection.execute(
            """SELECT p.id, p.name, p.domain, p.reliability, p.tlp,
                      (SELECT COUNT(*) FROM documents d
                       WHERE d.publisher_id = p.id OR d.primary_publisher_id = p.id) AS documents
               FROM publishers p ORDER BY p.name COLLATE NOCASE""").fetchall()
        # One query for every byline, not one per row: this list is read on each page load.
        bylines: dict[int, list[str]] = {}
        for row in services.store.connection.execute(
            """SELECT n.publisher_id AS publisher_id, n.name AS name
                 FROM publisher_names n ORDER BY n.name COLLATE NOCASE"""
        ).fetchall():
            bylines.setdefault(row["publisher_id"], []).append(row["name"])
        return [
            {"id": r["id"], "name": r["name"], "domain": r["domain"],
             "reliability": r["reliability"], "documents": r["documents"],
             "tlp": r["tlp"],
             "also_known_as": [
                 byline for byline in bylines.get(r["id"], [])
                 if normalize_name(byline) != normalize_name(r["name"])
             ]}
            for r in rows
        ]


@router.put("/sources/{source_id}")
def update_source(source_id: RowId, body: ReliabilityUpdate, request: Request) -> dict:
    """Save the reliability here (one row, so the UI shows it at once) and leave the recompute to the job worker.

    Recomputing rewrites every assessment, so it runs as a job: the single worker stays SQLite's only long writer.
    Changes made while a recompute is still queued join it; one made while it runs gets another run after it.
    """
    with open_services(request) as services:
        try:
            publisher = services.store.get_publisher(source_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown source") from None
        # By id: the byline path is for an operator typing a name, and resolving the row we
        # already hold back through its names can only lose.
        updated = services.store.grade_publisher(publisher.id, body.reliability)
    job = request.app.state.jobs.submit("recompute", {}, dedupe_key=(), coalesce=True)
    return {"id": updated.id, "name": updated.name, "domain": updated.domain,
            "reliability": updated.reliability, "job": job}


@router.put("/sources/{source_id}/tlp")
def update_source_tlp(source_id: RowId, body: TlpUpdate, request: Request) -> dict:
    """Attach (or clear) a TLP 2.0 label on a publisher. Pass `tlp: null` to clear.

    Does NOT trigger a recompute; the TLP only affects what gets filtered on export, not the
    scoring of what sits in the store.
    """
    with open_services(request) as services:
        try:
            publisher = services.store.get_publisher(source_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown source") from None
        new_tlp = TLP(body.tlp) if body.tlp else None
        services.store.set_publisher_tlp(publisher.name, new_tlp)
        return _publisher_view(services, publisher.id)


# -- the two bulk actions ---------------------------------------------------------------------
#
# Why these exist as their own endpoints rather than 38 uses of the dropdown above: in the
# Admiralty system F means "reliability cannot be judged", and it is the FLOOR that
# `scoring.score` multiplies evidence by — not a neutral middle. A store that has never used the
# axis therefore files every national CERT and vendor TI team as unjudgeable and pins everything
# they report to the bottom of the scale. And because corroboration is counted per publisher
# row, one organisation spread over several bylines corroborates itself. Both are one-click
# problems that were previously only reachable from a terminal.


def _proposals(services) -> list[dict]:
    """Publishers Argus ships a grade for that do not carry it yet, with the reason for each.

    The reason travels with the proposal because the operator is being asked to accept an
    analytic judgement, not a software default.
    """
    keys = organisation_keys(services.store.connection)
    out = []
    for publisher in services.store.list_publishers():
        known = known_rating(keys.get(publisher.id))
        if known is None or known.reliability == publisher.reliability:
            continue
        out.append({
            "id": publisher.id, "name": publisher.name,
            "current": publisher.reliability, "proposed": known.reliability,
            "rationale": known.rationale, "organisation": known.domain,
            # An existing grade is somebody's judgement: it is shown, but not applied over
            # unless the caller asks.
            "overrides_analyst": publisher.reliability != "F",
        })
    return out


@router.get("/sources/gradeable")
def gradeable_sources(request: Request) -> dict:
    """What `rate-known` would propose, and how much of the store is still unjudged."""
    with open_services(request) as services:
        proposals = _proposals(services)
        publishers = services.store.list_publishers()
        unjudged = [p for p in publishers if p.reliability == "F"]
        return {
            "proposals": [p for p in proposals if not p["overrides_analyst"]],
            # Kept separate so the UI never silently offers to undo a human's grade.
            "would_override": [p for p in proposals if p["overrides_analyst"]],
            "unjudged": len(unjudged),
            # Publishers nobody can grade from the shipped table. F is the accurate answer for
            # them until an analyst judges them, and the UI says so rather than implying the
            # job is finished.
            "unrecognised": len(unjudged) - len([p for p in proposals if not p["overrides_analyst"]]),
            "publishers": len(publishers),
        }


@router.post("/sources/rate-known")
def rate_known_sources(request: Request) -> dict:
    """Apply the shipped grade to every recognised publisher that is still unjudged.

    Never touches a row that already carries a grade other than F — that is an analyst's
    judgement and it outranks the table. Expect confidence to go UP on facts from graded
    sources; it was suppressed by the F floor, not by the evidence.
    """
    with open_services(request) as services:
        proposals = [p for p in _proposals(services) if not p["overrides_analyst"]]
        for proposal in proposals:
            services.store.grade_publisher(proposal["id"], proposal["proposed"])
    job = request.app.state.jobs.submit("recompute", {}, dedupe_key=(), coalesce=True)
    return {"graded": len(proposals), "job": job}


@router.get("/sources/duplicates")
def duplicate_sources(request: Request) -> dict:
    """Publisher rows that are the same organisation under different bylines.

    Read-only and derived fresh (`publisher_merge.organisation_keys`), so a store that has never
    run the backfill still reports its duplicates.
    """
    with open_services(request) as services:
        groups = find_duplicate_publishers(services.store.connection)
        return {
            "groups": [
                {
                    "org_key": group.org_key,
                    "keep": {"id": group.keep.id, "name": group.keep.name,
                             "documents": group.keep.documents},
                    "drop": [{"id": row.id, "name": row.name, "documents": row.documents}
                             for row in group.drop],
                }
                for group in groups
            ],
            "rows": sum(group.rows for group in groups),
        }


@router.post("/sources/merge-duplicates")
def merge_duplicate_sources(body: MergeRequest, request: Request) -> dict:
    """Fold each named group (or all of them) into one source row, then rescore.

    Every byline survives in `publisher_names`, so nothing about who reported what is lost and
    the old name still resolves the row. Expect confidence to go DOWN on the facts this touches:
    a merge can only remove supporters, and the scores it lowers were overstated.
    """
    with open_services(request) as services:
        groups = find_duplicate_publishers(services.store.connection)
        if body.org_keys:
            wanted = set(body.org_keys)
            groups = [group for group in groups if group.org_key in wanted]
            missing = wanted - {group.org_key for group in groups}
            if missing:
                raise HTTPException(
                    status_code=409,
                    detail=f"no duplicate group for {sorted(missing)[0]!r} — it may already be merged",
                )
        moved = 0
        for group in groups:
            moved += services.store.merge_publishers(
                group.keep.id, [row.id for row in group.drop]
            )
        services.store.backfill_publisher_org_keys()
        merged_rows = sum(len(group.drop) for group in groups)
    job = request.app.state.jobs.submit("recompute", {}, dedupe_key=(), coalesce=True)
    return {"groups": len(groups), "rows_merged": merged_rows, "documents_moved": moved, "job": job}
