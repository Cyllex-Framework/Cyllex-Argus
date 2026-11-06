"""Watchers: standing monitors over a target.

A watcher is a scheduled investigation with an owner, plus a change feed. Authorization is
central (web/authz.py): listing and the feed are reader+, create is operator+, marking changes
seen is any live session. The manage routes (enable/disable, delete) add an owner-or-admin rule
the central policy cannot express — a watcher is managed by the person who created it (or an
admin), though everyone on the server can see every watcher and every change.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from cyllex_argus.knowledge.models import Role
from cyllex_argus.pipeline.scheduler import is_valid_cron, next_fire
from cyllex_argus.web.deps import current_user, open_services

router = APIRouter()

DEFAULT_CRON = "0 8 * * *"  # daily at 08:00


class WatcherCreate(BaseModel):
    target: str = Field(min_length=1, max_length=200)
    cron_expr: str = Field(default=DEFAULT_CRON, min_length=1, max_length=200)
    max_docs: int | None = Field(default=None, ge=1, le=200)
    concurrency: int = Field(default=1, ge=1, le=16)


class WatcherEnabled(BaseModel):
    enabled: bool


class SeenBody(BaseModel):
    last_change_id: int = Field(ge=0)


def _watcher_dto(w, unseen: int) -> dict:
    return {
        "id": w.id, "target": w.target, "entity_id": w.entity_id, "cron_expr": w.cron_expr,
        "enabled": w.enabled, "created_by": w.created_by,
        "max_docs": w.max_docs, "concurrency": w.concurrency,
        "last_run_at": w.last_run_at.isoformat() if w.last_run_at else None,
        "next_run_at": w.next_run_at.isoformat(), "created_at": w.created_at.isoformat(),
        "unseen_count": unseen,
    }


def _change_dto(c, target: str | None) -> dict:
    citation = None
    if c.citation is not None:
        citation = {
            "quote": c.citation.quote, "publisher": c.citation.publisher,
            "document_title": c.citation.document_title, "location": c.citation.location,
            "published_at": c.citation.published_at.isoformat() if c.citation.published_at else None,
        }
    return {
        "id": c.id, "watcher_id": c.watcher_id, "target": target, "entity_id": c.entity_id,
        "kind": c.kind.value, "subject": c.subject, "predicate": c.predicate, "object": c.object,
        "from_status": c.from_status.value if c.from_status else None,
        "to_status": c.to_status.value if c.to_status else None,
        "citation": citation, "detected_at": c.detected_at.isoformat(), "run_job_id": c.run_job_id,
    }


def _require_manage(services, request: Request, watcher_id: int):
    """404 if the watcher is unknown, 403 unless the caller owns it or is an admin."""
    watcher = services.store.get_watcher(watcher_id)
    if watcher is None:
        raise HTTPException(status_code=404, detail="unknown watcher")
    actor = current_user(request)
    if actor is None:
        raise HTTPException(status_code=401, detail="session required")
    if actor.role is not Role.ADMIN and services.store.watcher_owner(watcher_id) != actor.id:
        raise HTTPException(status_code=403, detail="forbidden: not the owner")
    return watcher


@router.get("/watchers")
def list_watchers(request: Request) -> list[dict]:
    actor = current_user(request)
    with open_services(request) as services:
        unseen = services.store.unseen_counts(actor.id) if actor else {}
        return [_watcher_dto(w, unseen.get(w.id, 0)) for w in services.store.list_watchers()]


@router.post("/watchers", status_code=201)
def create_watcher(body: WatcherCreate, request: Request) -> dict:
    cron = body.cron_expr.strip()
    if not is_valid_cron(cron):
        raise HTTPException(status_code=400, detail=f"invalid cron expression: {cron!r}")
    actor = current_user(request)
    with open_services(request) as services:
        created = services.store.create_watcher(
            target=body.target.strip(), cron_expr=cron,
            created_by=actor.id if actor else None, next_run_at=next_fire(cron, datetime.now(UTC)),
            max_docs=body.max_docs, concurrency=body.concurrency,
        )
        unseen = services.store.unseen_count(actor.id, created.id) if actor else 0
    return _watcher_dto(created, unseen)


@router.put("/watchers/{watcher_id}/enabled")
def set_enabled(watcher_id: int, body: WatcherEnabled, request: Request) -> dict:
    actor = current_user(request)
    with open_services(request) as services:
        _require_manage(services, request, watcher_id)
        services.store.set_watcher_enabled(watcher_id, body.enabled)
        w = services.store.get_watcher(watcher_id)
        unseen = services.store.unseen_count(actor.id, watcher_id) if actor else 0
        return _watcher_dto(w, unseen)


@router.delete("/watchers/{watcher_id}", status_code=204)
def delete_watcher(watcher_id: int, request: Request) -> Response:
    with open_services(request) as services:
        _require_manage(services, request, watcher_id)
        services.store.delete_watcher(watcher_id)
    return Response(status_code=204)


@router.post("/watchers/{watcher_id}/run-now")
def run_now(watcher_id: int, request: Request) -> dict:
    """Fire the watcher's investigation immediately (operator+, owner-or-admin). The run is tagged
    with `watcher_id` and the owner's `user_id`, so the finished run reconciles the change feed
    and dispatches alerts exactly as a scheduled tick would. The cron cadence is untouched."""
    from cyllex_argus.web.jobs import DuplicateJobError

    with open_services(request) as services:
        watcher = _require_manage(services, request, watcher_id)
        params: dict = {
            "target": watcher.target, "concurrency": watcher.concurrency,
            "watcher_id": watcher.id,
        }
        if watcher.max_docs is not None:
            params["max_docs"] = watcher.max_docs
        if watcher.created_by is not None:
            params["user_id"] = watcher.created_by
        try:
            job = request.app.state.jobs.submit(
                "investigate", params, dedupe_key=(watcher.target.casefold(), watcher.max_docs),
            )
        except DuplicateJobError:
            raise HTTPException(
                status_code=409, detail="an identical investigation is already queued or running",
            ) from None
    return {"job_id": job["id"]}


@router.get("/watchers/changes")
def list_changes(request: Request, watcher_id: int | None = None, before_id: int | None = None,
                 limit: int = 100) -> list[dict]:
    limit = max(1, min(limit, 500))
    with open_services(request) as services:
        targets = {w.id: w.target for w in services.store.list_watchers()}
        changes = services.store.list_changes(watcher_id=watcher_id, before_id=before_id, limit=limit)
        return [_change_dto(c, targets.get(c.watcher_id)) for c in changes]


@router.post("/watchers/{watcher_id}/seen", status_code=204)
def mark_seen(watcher_id: int, body: SeenBody, request: Request) -> Response:
    actor = current_user(request)
    if actor is None:
        raise HTTPException(status_code=401, detail="session required")
    with open_services(request) as services:
        if services.store.get_watcher(watcher_id) is None:
            raise HTTPException(status_code=404, detail="unknown watcher")
        services.store.set_seen(actor.id, watcher_id, body.last_change_id)
    return Response(status_code=204)
