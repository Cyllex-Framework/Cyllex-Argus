"""Threat search, consolidated profile, relationship graph and exports."""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime

from fastapi import APIRouter, HTTPException, Query, Request, Response

from cyllex_argus.exporters.markdown import render_markdown
from cyllex_argus.exporters.stix import to_stix_bundle
from cyllex_argus.exporters.summary import (
    SUMMARY_PROMPT_VERSION,
    profile_fingerprint,
    summarize_profile,
    summarize_profile_detailed,
)
from cyllex_argus.knowledge.browse import BrowseQueries
from cyllex_argus.knowledge.profile import EntityRef, FactView, Profile, build_profile
from cyllex_argus.knowledge.summaries import StoredSummary
from cyllex_argus.llm.base import InvalidOutput, LLMUnavailable, RateLimited
from cyllex_argus.services import Services
from cyllex_argus.web.deps import open_browse, open_services, parse_scope, scope_label

router = APIRouter()
_SKIPPED = "summary skipped:"


def _ref(ref: EntityRef) -> dict:
    return {**ref.model_dump(mode="json"), "label": ref.label}


def _fact(fact: FactView) -> dict:
    data = fact.model_dump(mode="json")
    data["subject"] = _ref(fact.subject)
    data["object"] = _ref(fact.object)
    data["source_count"] = fact.source_count
    return data


def _warning_header(message: str) -> str:
    """One printable-ASCII line: provider errors span several lines, and h11 rejects CR, LF and control bytes."""
    line = " ".join(message.split())[:200]
    return "".join(c for c in line.encode("ascii", "replace").decode() if " " <= c < "\x7f").strip()


def _download_name(entity_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", entity_name).strip("_.")[:100].rstrip("_.") or "threat"


def _profile(services: Services, entity_id: str, investigation_id: int | None = None) -> Profile:
    entity = services.store.get_entity(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="unknown threat")
    return build_profile(services.store, entity, investigation_id)


def _require_investigation(browse: BrowseQueries, investigation_id: int | None) -> None:
    if investigation_id is not None and not browse.investigation_exists(investigation_id):
        raise HTTPException(status_code=404, detail="unknown investigation")


@router.get("/threats")
def list_threats(
    request: Request,
    q: str = Query("", max_length=200),
    stix_type: str = Query("", max_length=40),
    type_alias: str = Query("", alias="type", max_length=40),
    catalog: int = Query(0, ge=0, le=1),
    limit: int = Query(50, ge=1, le=500),
) -> list[dict]:
    # Accept both `?stix_type=…` (matches the response field name — the obvious guess) and
    # the shorter `?type=…` kept for backward compatibility. The former wins on conflict,
    # since it names itself unambiguously.
    kind = stix_type or type_alias
    with open_browse(request) as browse:
        return browse.list_threats(q=q, stix_type=kind, include_catalog=bool(catalog), limit=limit)


@router.get("/threats/{entity_id}")
def threat_profile(entity_id: str, request: Request, scope: str | None = Query(None, max_length=40)) -> dict:
    scope_id = parse_scope(scope)
    with open_services(request) as services:
        catalog = services.attack_catalog()
        with BrowseQueries(services.paths.db_file) as browse:
            _require_investigation(browse, scope_id)
        profile = _profile(services, entity_id, scope_id)
        with BrowseQueries(services.paths.db_file) as browse:
            aliases = browse.aliases_with_origin(entity_id)
            detail = browse.entity_detail(entity_id)
            # The ATT&CK matrix here is the "everything known about this threat" view; the scoped view lives
            # on the investigation dashboard. Empty tactics arrive so the frontend renders every column.
            tactics: list[dict] = []
            if catalog is not None:
                from cyllex_argus.knowledge.attack_matrix import build_matrix
                tactics = build_matrix(browse._conn, catalog, entity_id)
    payload = {
        "entity": _ref(profile.entity), "aliases": aliases, "facts": [_fact(f) for f in profile.facts],
        "attack_matrix": {"tactics": tactics},
        "scope": scope_label(scope_id),
    }
    if detail is not None:  # absent for types without one
        payload["detail"] = detail
    return payload


@router.get("/threats/{entity_id}/graph")
def threat_graph(
    entity_id: str, request: Request, depth: int = Query(1, ge=1, le=3), limit: int = Query(60, ge=1, le=200),
    scope: str | None = Query(None, max_length=40),
) -> dict:
    scope_id = parse_scope(scope)
    with open_services(request) as services:
        catalog = services.attack_catalog()
        with BrowseQueries(services.paths.db_file) as browse:
            _require_investigation(browse, scope_id)
            graph = browse.graph(
                entity_id, depth=depth, limit=limit, scope_investigation_id=scope_id, catalog=catalog,
            )
    if not graph["nodes"]:
        raise HTTPException(status_code=404, detail="unknown threat")
    return {**graph, "scope": scope_label(scope_id)}


@router.get("/threats/{entity_id}/campaigns")
def threat_campaigns(entity_id: str, request: Request, scope: str | None = Query(None, max_length=40)) -> dict:
    """List the campaigns Argus has linked to this entity, with technique counts and date range.

    Click on the UI opens the campaign in its own kill-chain graph (that reuses /threats/{id}/graph).
    """
    scope_id = parse_scope(scope)
    with open_services(request) as services:
        with BrowseQueries(services.paths.db_file) as browse:
            _require_investigation(browse, scope_id)
            if services.store.get_entity(entity_id) is None:
                raise HTTPException(status_code=404, detail="unknown threat")
            campaigns = browse.campaigns_for(entity_id, scope_id)
    return {"campaigns": campaigns, "scope": scope_label(scope_id)}


@router.get("/campaigns/{campaign_id}/matrix")
def campaign_matrix(campaign_id: str, request: Request) -> dict:
    """ATT&CK matrix filtered to the techniques this campaign uses (direct + via attributed actor)."""
    with open_services(request) as services:
        catalog = services.attack_catalog()
        entity = services.store.get_entity(campaign_id)
        if entity is None or entity.stix_type != "campaign":
            raise HTTPException(status_code=404, detail="unknown campaign")
        if catalog is None:
            raise HTTPException(status_code=503, detail="ATT&CK catalog is not loaded")
        with BrowseQueries(services.paths.db_file) as browse:
            from cyllex_argus.knowledge.attack_matrix import build_campaign_matrix
            tactics = build_campaign_matrix(browse._conn, catalog, campaign_id)
    return {"tactics": tactics}


@router.get("/threats/{entity_id}/history")
def get_threat_history(entity_id: str, since: str | None = None, request: Request = None) -> dict:
    """What has changed about this threat since `since` (ISO-8601 datetime).

    Default `since`: the start of the most recent investigation BEFORE the latest one
    for this entity. First-time investigators get everything since 1970-01-01 so the page
    is never empty. The response shape mirrors what the /threats/<id>/history page needs,
    one query batch — no per-row round-trip.
    """
    with open_services(request) as services:
        entity = services.store.get_entity(entity_id)
        if entity is None:
            raise HTTPException(status_code=404, detail="unknown threat")
        if since is None:
            # Default: the start of the SECOND-most-recent investigation for this entity, so the
            # page shows "what this latest run added over the previous one". Fallback to epoch when
            # there is only one (or zero) runs on record — operators get everything, not an empty
            # page they have to debug.
            rows = services.store._conn.execute(  # noqa: SLF001 — scoped read-only query, no public helper yet
                """SELECT started_at FROM investigations
                   WHERE resolved_entity_id = ? ORDER BY started_at DESC LIMIT 2""",
                (entity_id,),
            ).fetchall()
            if len(rows) >= 2:
                since_dt = datetime.fromisoformat(rows[1]["started_at"].replace("Z", "+00:00"))
                if since_dt.tzinfo is None:
                    since_dt = since_dt.replace(tzinfo=UTC)
            else:
                since_dt = datetime(1970, 1, 1, tzinfo=UTC)
        else:
            try:
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"invalid since: {exc}") from exc
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=UTC)
        batch = services.store.history_batch(entity_id, since_dt)
    return {
        "since": since_dt.isoformat(),
        "investigations": [
            {"id": i.id, "target": i.target, "state": i.state.value,
             "started_at": i.started_at.isoformat(),
             "finished_at": i.finished_at.isoformat() if i.finished_at else None}
            for i in batch["investigations"]
        ],
        "new_assessments": [_assessment_dict(a) for a in batch["new_assessments"]],
        "touched_assessments": [_assessment_dict(a) for a in batch["touched_assessments"]],
        "new_aliases": batch["new_aliases"],
    }


def _assessment_dict(a) -> dict:
    return {
        "id": a.id,
        "subject_entity_id": a.subject_entity_id,
        "object_entity_id": a.object_entity_id,
        "predicate": a.predicate,
        "status": a.status.value,
        "confidence": a.confidence,
        "admiralty": a.admiralty,
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


def _summary_body(profile: Profile, stored: StoredSummary | None) -> dict:
    """The summary as the UI needs it: the prose, when it was written, and whether the
    knowledge has moved since. `stale` is the whole point of caching with a fingerprint —
    an outdated summary stays readable and visibly marked, because a slightly-old answer
    beats a blank card while the operator decides whether to spend a regeneration."""
    facts = len(profile.facts)
    if stored is None:
        return {
            "summary": None, "generated_at": None, "stale": False,
            "fact_count": facts, "written_from_fact_count": None,
            "prompt_version": None, "model": None, "can_generate": facts > 0,
        }
    return {
        "summary": stored.summary,
        "generated_at": stored.created_at.isoformat(),
        "stale": stored.fingerprint != profile_fingerprint(profile)
        or stored.prompt_version != SUMMARY_PROMPT_VERSION,
        "fact_count": facts,
        "written_from_fact_count": stored.fact_count,
        "prompt_version": stored.prompt_version,
        "model": stored.model,
        "can_generate": facts > 0,
    }


@router.get("/threats/{entity_id}/summary")
def threat_summary(entity_id: str, request: Request) -> dict:
    """The cached executive summary. Never calls the LLM — a page load must not bill the
    operator; writing one is an explicit POST (or the pipeline's end-of-run step)."""
    with open_services(request) as services:
        profile = _profile(services, entity_id)
        return _summary_body(profile, services.store.get_entity_summary(entity_id))


@router.post("/threats/{entity_id}/summary")
def write_threat_summary(entity_id: str, request: Request) -> dict:
    """Write (or rewrite) the executive summary now. Costs one LLM call, so it is only ever
    operator- or pipeline-initiated."""
    with open_services(request) as services:
        profile = _profile(services, entity_id)
        if not profile.facts:
            raise HTTPException(
                status_code=409,
                detail="No facts to summarize yet — investigate this threat first.",
            )
        try:
            text, usage = summarize_profile_detailed(profile, services.llm)
        except (LLMUnavailable, RateLimited, InvalidOutput) as exc:
            # 503, not 500: the knowledge base is fine, the provider is the thing that failed,
            # and the operator's fix is to retry or to check the provider in Settings.
            raise HTTPException(
                status_code=503,
                detail=_warning_header(str(exc)) or "the LLM provider could not write a summary",
            ) from exc
        stored = services.store.save_entity_summary(
            entity_id=entity_id, summary=text, fingerprint=profile_fingerprint(profile),
            fact_count=len(profile.facts), prompt_version=SUMMARY_PROMPT_VERSION,
            model=usage.model if usage else None,
        )
        return _summary_body(profile, stored)


@router.get("/threats/{entity_id}/export")
def export_threat(
    entity_id: str,
    request: Request,
    fmt: str = Query("markdown", alias="format", pattern="^(markdown|stix)$"),
    summary: int = Query(0, ge=0, le=1),
    tlp_cap: str | None = Query(None, pattern="^(clear|green|amber|amber-strict|red)$"),
) -> Response:
    """Export the profile. `tlp_cap` filters citations from publishers whose TLP exceeds the cap
    and omits facts left with no evidence — the file header reports the cap applied."""
    from cyllex_argus.knowledge.models import TLP
    cap = TLP(tlp_cap) if tlp_cap else None
    headers: dict[str, str] = {}
    with open_services(request) as services:
        profile = _profile(services, entity_id)
        if fmt == "markdown":
            text_summary, unavailable = None, None
            if summary and profile.facts:
                try:
                    text_summary = summarize_profile(profile, services.llm)
                except (LLMUnavailable, RateLimited, InvalidOutput) as exc:
                    warning = _warning_header(f"{_SKIPPED} {exc}")
                    headers["X-Argus-Warning"] = warning
                    # A browser download cannot read headers: the file itself must say the summary is missing.
                    unavailable = warning.removeprefix(_SKIPPED).strip() or "no reason given"
            body = render_markdown(
                profile, text_summary, date.today(),
                summary_unavailable=unavailable, tlp_cap=cap,
                # The CLI export declared the evidence base and this one did not, and this is
                # the path almost every operator uses. A 25-of-40 profile downloaded here read
                # exactly like a complete one.
                coverage=services.store.coverage_for_entity(entity_id),
            )
            media_type, extension = "text/markdown; charset=utf-8", "md"
        else:
            body = json.dumps(
                to_stix_bundle(profile, datetime.now(UTC), tlp_cap=cap),
                indent=2,
            ) + "\n"
            media_type, extension = "application/json", "stix.json"
    headers["Content-Disposition"] = f'attachment; filename="{_download_name(profile.entity.name)}.{extension}"'
    return Response(body, media_type=media_type, headers=headers)
