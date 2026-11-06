import secrets

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile

from cyllex_argus.knowledge.models import Stage
from cyllex_argus.web.api.jobs import MISSING_ATTACK, MISSING_CLAUDE, safe_upload_name
from cyllex_argus.web.deps import RowId, open_services
from cyllex_argus.web.jobs import DuplicateJobError

router = APIRouter()

_CHUNK = 1024 * 1024


@router.get("/documents")
def list_documents(
    request: Request,
    stage: str = Query("", max_length=20),
    q: str = Query("", max_length=200),
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict]:
    from cyllex_argus.web.deps import open_browse
    with open_browse(request) as browse:
        return browse.list_documents(stage=stage, q=q, limit=limit)


@router.get("/documents/{document_id}")
def document_detail(document_id: RowId, request: Request) -> dict:
    from cyllex_argus.web.deps import open_browse
    with open_browse(request) as browse:
        detail = browse.document_detail(document_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="unknown document")
    return detail


@router.post("/documents/{document_id}/retry", status_code=202)
def retry_document(
    document_id: RowId, request: Request,
    as_browser: int = Query(0, ge=0, le=1),
) -> dict:
    """Queue a `retry_document` job for a failed doc. 400 for a doc that is not failed.

    Returns `{job_id}` so the UI can watch the standard job event stream, exactly as it does
    for an investigation or an ingest. Dedupe-key includes `as_browser` so a user who first
    tried the default UA and then clicked "Retry as browser" gets both attempts — the UA
    choice is part of the retry's identity, not an orthogonal setting.
    """
    with open_services(request) as services:
        try:
            doc = services.store.get_document(document_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown document") from None
        if doc.stage is not Stage.FAILED:
            raise HTTPException(
                status_code=400,
                detail=f"only failed documents can be retried (stage={doc.stage.value})",
            )
        # A retry runs Triage and the Analyst, so it needs the same prerequisite every other
        # pipeline entry point checks. Without it a retry against a wiped catalog resolves
        # nothing and writes one entity per group name it reads.
        if not services.attack_ready():
            raise HTTPException(status_code=409, detail=MISSING_ATTACK)
    job = request.app.state.jobs.submit(
        "retry_document",
        {"document_id": document_id, "as_browser": bool(as_browser)},
        dedupe_key=("retry_document", document_id, bool(as_browser)),
        coalesce=True,
    )
    return {"job_id": job}


# A plain def, so it runs in the threadpool: writing the upload to disk must not stall the event
# loop and the SSE streams it is serving.
@router.post("/documents/{document_id}/supply", status_code=202)
def supply_document(
    document_id: RowId, request: Request, file: UploadFile = File(...),
) -> dict:
    """Repair a failed document from a file the operator supplies.

    Some refusals are permanent and correct — a publisher's access policy, a page behind a
    login, a host that times out — and `retry` will never fix those. The operator opens the page
    in their own browser, saves it, and hands over the file.

    The document row is reused, so the URL, the publisher and the investigations that collected
    it all survive, and the coverage statement on the dossier improves instead of gaining a
    second unlinked record. 400 for a document that is not failed: there is nothing to repair,
    and silently replacing a validated document's body from an upload would be a quiet way to
    rewrite evidence.

    Returns `{job_id}` so the UI watches the standard job event stream, as retry and ingest do.
    """
    with open_services(request) as services:
        try:
            document = services.store.get_document(document_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown document") from None
        if document.stage is not Stage.FAILED:
            raise HTTPException(
                status_code=400,
                detail=f"only failed documents can be supplied (stage={document.stage.value})",
            )
        if not services.attack_ready():
            raise HTTPException(status_code=409, detail=MISSING_ATTACK)
        limit = services.config.limits.max_download_bytes
        uploads = services.paths.home / "uploads"
    if not request.app.state.claude_available():
        raise HTTPException(status_code=503, detail=MISSING_CLAUDE)
    uploads.mkdir(parents=True, exist_ok=True)
    name = safe_upload_name(file.filename)
    destination = uploads / f"{secrets.token_hex(8)}-{name}"
    try:
        size = 0
        with destination.open("wb") as out:
            while chunk := file.file.read(_CHUNK):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=400, detail=f"{name} exceeds the size limit")
                out.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail=f"{name} is empty")
        try:
            job = request.app.state.jobs.submit(
                "supply_document",
                {"document_id": document_id, "path": str(destination), "filename": name},
                dedupe_key=("supply_document", document_id),
                # Not coalesced: each upload is a distinct file, and quietly answering with the
                # job that holds somebody else's file would process the wrong document body.
                coalesce=False,
            )
        except DuplicateJobError:
            raise HTTPException(
                status_code=409,
                detail=f"a file for document {document_id} is already being processed",
            ) from None
    except BaseException:
        # Whatever went wrong, no request leaves a file behind. The job owns it from here.
        destination.unlink(missing_ok=True)
        raise
    return {"job_id": job}
