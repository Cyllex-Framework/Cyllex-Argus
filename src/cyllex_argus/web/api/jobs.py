"""Run long operations as jobs, stream their progress, and accept document uploads for ingest."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Iterator
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from cyllex_argus.web.deps import current_user, open_services
from cyllex_argus.web.jobs import TERMINAL_STATES, DuplicateJobError

router = APIRouter()
MAX_FILES = 20
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_CHUNK = 1024 * 1024
_KEEPALIVE_SECONDS = 5.0  # a stream whose client left only notices on its next write, and holds a thread until then
# Each refusal names its fix: the web UI shows these when its own prerequisite check was out of date.
MISSING_ATTACK = "ATT&CK data is missing; run the ATT&CK update first (Settings → Update ATT&CK)"
MISSING_CLAUDE = "Claude Code CLI not found; install it, log in, then restart argus serve"


def safe_upload_name(name: str | None) -> str:
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = _UNSAFE.sub("_", base)[:100].strip(".")
    return cleaned or "upload"


class JobRequest(BaseModel):
    kind: Literal["investigate", "resume", "attack_update"]
    target: str | None = Field(default=None, max_length=200)
    max_docs: int | None = Field(default=None, ge=1, le=200)
    # SQLite cannot bind an integer outside the signed 64-bit range; reject it as a 400, not a 500.
    investigation_id: int | None = Field(default=None, ge=-(2**63), le=2**63 - 1)
    # Number of documents the Triage+Analyst stages process in parallel. Default 1 keeps
    # the pre-0.19 sequential behaviour. The CLI accepts the same values; see
    # `argus investigate --help`.
    concurrency: int = Field(default=1, ge=1, le=16)


def _require_llm_ready(request: Request) -> None:
    with open_services(request) as services:
        if not services.attack_ready():
            raise HTTPException(status_code=409, detail=MISSING_ATTACK)
    if not request.app.state.claude_available():
        raise HTTPException(status_code=503, detail=MISSING_CLAUDE)


@router.post("/jobs", status_code=202)
def create_job(body: JobRequest, request: Request) -> dict:
    params: dict = {}
    dedupe_key: tuple = ()  # attack_update has no parameters: it is always identical to itself
    if body.kind == "investigate":
        target = (body.target or "").strip()
        if not target:
            raise HTTPException(status_code=400, detail="target is required")
        _require_llm_ready(request)
        params = {"target": target, "max_docs": body.max_docs, "concurrency": body.concurrency}
        dedupe_key = (target.casefold(), body.max_docs)
    elif body.kind == "resume":
        if body.investigation_id is None:
            raise HTTPException(status_code=400, detail="investigation_id is required")
        with open_services(request) as services:
            try:
                services.store.get_investigation(body.investigation_id)
            except KeyError:
                raise HTTPException(status_code=404, detail="unknown investigation") from None
        _require_llm_ready(request)
        params = {"investigation_id": body.investigation_id, "concurrency": body.concurrency}
        dedupe_key = (body.investigation_id,)
    actor = current_user(request)
    if actor is not None:
        params["user_id"] = actor.id  # attribute the run to whoever started it
    try:
        return request.app.state.jobs.submit(body.kind, params, dedupe_key=dedupe_key)
    except DuplicateJobError:
        raise HTTPException(status_code=409, detail="an identical job is already queued or running") from None


@router.get("/jobs")
def list_jobs(request: Request) -> list[dict]:
    return request.app.state.jobs.list()


@router.get("/jobs/{job_id}")
def get_job(job_id: str, request: Request) -> dict:
    job = request.app.state.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job")
    return job


@router.get("/jobs/{job_id}/events")
def job_events(job_id: str, request: Request, after: int = 0) -> StreamingResponse:
    jobs = request.app.state.jobs
    if jobs.get(job_id) is None:
        raise HTTPException(status_code=404, detail="unknown job")

    def stream() -> Iterator[str]:
        seq = max(0, after)
        while True:
            events, state = jobs.events_after(job_id, seq)
            for event in events:
                seq = event["seq"]
                yield f"id: {seq}\ndata: {json.dumps(event)}\n\n"
            if state is None or state in TERMINAL_STATES:
                yield f"event: end\ndata: {json.dumps(jobs.get(job_id))}\n\n"
                return
            if not events:
                jobs.wait(job_id, seq, timeout=_KEEPALIVE_SECONDS)
                if not jobs.events_after(job_id, seq)[0]:
                    yield ": keepalive\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# A plain def, so it runs in the threadpool: writing uploads to disk must not stall the event loop and its SSE streams.
@router.post("/ingest", status_code=202)
def ingest(
    request: Request,
    files: list[UploadFile] = File(...),
    target: str | None = Form(None, max_length=200),
) -> dict:
    if not files:
        raise HTTPException(status_code=400, detail="no files uploaded")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=400, detail=f"at most {MAX_FILES} files per upload")
    services = request.app.state.services_factory()
    try:
        if not services.attack_ready():
            raise HTTPException(status_code=409, detail=MISSING_ATTACK)
        limit = services.config.limits.max_download_bytes
        uploads = services.paths.home / "uploads"
    finally:
        services.close()
    if not request.app.state.claude_available():
        raise HTTPException(status_code=503, detail=MISSING_CLAUDE)
    uploads.mkdir(parents=True, exist_ok=True)
    saved = []
    try:
        for upload in files:
            name = safe_upload_name(upload.filename)
            destination = uploads / f"{secrets.token_hex(8)}-{name}"
            saved.append(destination)
            size = 0
            with destination.open("wb") as out:
                while chunk := upload.file.read(_CHUNK):
                    size += len(chunk)
                    if size > limit:
                        raise HTTPException(status_code=400, detail=f"{name} exceeds the size limit")
                    out.write(chunk)
        clean_target = (target or "").strip() or None
        actor = current_user(request)
        ingest_params = {"files": [str(p) for p in saved], "target": clean_target}
        if actor is not None:
            ingest_params["user_id"] = actor.id
        return request.app.state.jobs.submit("ingest", ingest_params)
    except BaseException:
        # Whatever went wrong (size limit, a full disk, a job manager that refuses the job), no request leaves files behind.
        for path in saved:
            path.unlink(missing_ok=True)
        raise
