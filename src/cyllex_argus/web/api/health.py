"""Data health endpoint: what the operator should fix next.

The audit tool surfaces repair-worthy state that the main pages otherwise leave scattered —
failed documents, identity entities without a sector/country, publishers without a
reliability rating, investigations stuck mid-run, and identity entities whose names
suggest the LLM mistyped a technology/sector as an organisation. Everything exposed here
is already visible on some other page; this card is a *shortcut* for the opener's
checklist, not a new source of truth.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from cyllex_argus.knowledge.mistype import suggest_retype
from cyllex_argus.knowledge.models import InvestigationState, Stage
from cyllex_argus.knowledge.publisher_merge import find_duplicate_publishers, organisation_keys
from cyllex_argus.knowledge.publisher_ratings import known_rating
from cyllex_argus.web.deps import open_services

router = APIRouter()


@router.get("/live")
def live() -> dict:
    """Lightweight liveness probe for systemd or an orchestrator.

    Does not touch the database and does not require authentication (it is in
    `_PUBLIC_API_PATHS`). Returning 200 means the HTTP server loop is up; it does NOT mean
    the LLM is reachable or the DB is healthy — use /api/health for the operator-facing
    picture.
    """
    return {"status": "ok"}


@router.get("/health")
def health(request: Request) -> dict:
    with open_services(request) as services:
        conn = services.store.connection

        failed_docs = conn.execute(
            """SELECT d.id, d.title, d.failure_reason, p.name AS publisher
               FROM documents d
               LEFT JOIN publishers p ON p.id = COALESCE(d.primary_publisher_id, d.publisher_id)
               WHERE d.stage = ? ORDER BY d.id DESC LIMIT 20""",
            (Stage.FAILED.value,),
        ).fetchall()

        untagged_identities = conn.execute(
            """SELECT e.id, e.canonical_name
               FROM entities e
               WHERE e.stix_type = 'identity'
                 AND (e.attributes_json IS NULL OR e.attributes_json = '' OR e.attributes_json = '{}')
               ORDER BY e.canonical_name
               LIMIT 20"""
        ).fetchall()

        # The mistype detector scans every identity (not just untagged ones) because a tagged
        # identity can still be wrongly typed. We cap at 500 names to keep the heuristic
        # bounded on huge stores; it is a hint, not a query result.
        candidate_rows = conn.execute(
            "SELECT id, canonical_name FROM entities WHERE stix_type = 'identity' LIMIT 500",
        ).fetchall()
        likely_mistyped = []
        for r in candidate_rows:
            suggestion = suggest_retype(r["canonical_name"])
            if suggestion is not None:
                likely_mistyped.append({
                    "id": r["id"], "name": r["canonical_name"], "suggest": suggestion,
                })
        likely_mistyped.sort(key=lambda r: r["name"].lower())

        # "Unrated" matches the dashboard's semantic: `reliability = 'F'` is the default
        # placeholder a publisher gets at creation time until the analyst assigns it. Treat
        # both NULL and 'F' as unrated so a store seeded by either path shows the same list.
        # Derived read-only, so a store that never ran the backfill still reports its state.
        org_keys = organisation_keys(conn)
        unrated_ids = conn.execute(
            "SELECT id, reliability FROM publishers WHERE reliability IS NULL OR reliability = 'F'"
        ).fetchall()
        unrated_ids = [(row["id"], row["reliability"]) for row in unrated_ids]
        unrated_publishers = conn.execute(
            """SELECT id, name FROM publishers
               WHERE reliability IS NULL OR reliability = 'F'
               ORDER BY name COLLATE NOCASE LIMIT 20"""
        ).fetchall()

        stuck_investigations = conn.execute(
            """SELECT id, target, state, started_at FROM investigations
               WHERE state IN (?, ?)
               ORDER BY started_at DESC LIMIT 10""",
            (InvestigationState.RUNNING.value, InvestigationState.PAUSED.value),
        ).fetchall()

        # Actor + malware name collisions. ATT&CK catalog has several groups whose
        # signature malware shares the group's name (Machete, Carbanak, Akira, Evilnum,
        # RTM, AppleJeus, …). The Analyst sometimes anchors on the wrong interpretation
        # and types every claim with that subject_type; v3 prompt + Validator swap fix
        # future ingests but existing stores keep the mis-attributed facts until
        # `argus resume` re-runs them. The panel lists the pairs so the operator sees
        # which investigations are at risk BEFORE opening them.
        collision_rows = conn.execute(
            """SELECT LOWER(canonical_name) AS key, canonical_name
               FROM entities WHERE stix_type IN ('intrusion-set', 'malware', 'campaign', 'tool')
               GROUP BY key
               HAVING COUNT(DISTINCT stix_type) >= 2
               ORDER BY canonical_name"""
        ).fetchall()
        name_collisions: list[dict] = []
        for r in collision_rows:
            members = conn.execute(
                """SELECT id, stix_type, canonical_name, external_id FROM entities
                   WHERE LOWER(canonical_name) = ? AND stix_type IN
                     ('intrusion-set', 'malware', 'campaign', 'tool')""",
                (r["key"],),
            ).fetchall()
            name_collisions.append({
                "name": r["canonical_name"],
                "entities": [
                    {"id": m["id"], "stix_type": m["stix_type"],
                     "external_id": m["external_id"]}
                    for m in members
                ],
            })

        totals = {
            "failed_documents": conn.execute(
                "SELECT COUNT(*) FROM documents WHERE stage = ?", (Stage.FAILED.value,),
            ).fetchone()[0],
            "untagged_identities": conn.execute(
                "SELECT COUNT(*) FROM entities WHERE stix_type = 'identity' "
                "AND (attributes_json IS NULL OR attributes_json = '' OR attributes_json = '{}')"
            ).fetchone()[0],
            "unrated_publishers": conn.execute(
                "SELECT COUNT(*) FROM publishers WHERE reliability IS NULL OR reliability = 'F'"
            ).fetchone()[0],
            "stuck_investigations": conn.execute(
                "SELECT COUNT(*) FROM investigations WHERE state IN (?, ?)",
                (InvestigationState.RUNNING.value, InvestigationState.PAUSED.value),
            ).fetchone()[0],
            "likely_mistyped_identities": len(likely_mistyped),
            "name_collisions": len(name_collisions),
            # Of the unrated publishers, how many Argus ships a grade for. This is the
            # actionable half of `unrated_publishers`: F is the floor of the confidence scale,
            # so a recognised first-tier source sitting there is suppressing its own reporting.
            "gradeable_publishers": sum(
                1 for publisher_id, reliability in unrated_ids
                if known_rating(org_keys.get(publisher_id)) is not None
            ) if unrated_ids else 0,
            # Publisher rows that are the same organisation. Corroboration is counted per row,
            # so until these are merged a source can corroborate itself.
            # The REDUNDANT rows, not every row in a group: `group.rows` counts the
            # surviving one too, so a chip reading "duplicate publisher rows" overstated by one
            # per organisation. The Sources page phrases the same scan as "N rows are M
            # organisations", which wants the total — which is why the endpoint keeps both.
            "duplicate_publisher_rows": sum(
                len(group.drop) for group in find_duplicate_publishers(conn, org_keys)
            ),
        }

    return {
        "totals": totals,
        "failed_documents": [
            {"id": r["id"], "title": r["title"], "publisher": r["publisher"], "failure_reason": r["failure_reason"]}
            for r in failed_docs
        ],
        "untagged_identities": [
            {"id": r["id"], "name": r["canonical_name"]} for r in untagged_identities
        ],
        "unrated_publishers": [
            {"id": r["id"], "name": r["name"]} for r in unrated_publishers
        ],
        "stuck_investigations": [
            {"id": r["id"], "target": r["target"], "state": r["state"], "started_at": r["started_at"]}
            for r in stuck_investigations
        ],
        "likely_mistyped_identities": likely_mistyped[:20],
        "name_collisions": name_collisions[:20],
    }
