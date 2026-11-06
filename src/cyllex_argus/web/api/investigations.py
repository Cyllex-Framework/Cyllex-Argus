from fastapi import APIRouter, HTTPException, Query, Request, Response

from cyllex_argus.knowledge.browse import BrowseQueries
from cyllex_argus.web.deps import RowId, open_browse, open_services, parse_scope

router = APIRouter()


@router.get("/investigations")
def list_investigations(request: Request, limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    with open_browse(request) as browse:
        return browse.list_investigations(limit=limit)


@router.get("/investigations/{investigation_id}")
def investigation_detail(investigation_id: RowId, request: Request) -> dict:
    with open_browse(request) as browse:
        detail = browse.investigation_detail(investigation_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="unknown investigation")
    return detail


@router.delete("/investigations/{investigation_id}", status_code=204)
def delete_investigation(investigation_id: RowId, request: Request) -> Response:
    with open_services(request) as services:
        # Flag cancel first so any pipeline worker still processing this investigation sees
        # the stop signal on its next between-docs check and exits before touching stage/claim
        # rows that CASCADE would otherwise pull from under it. No-op when the row is already
        # gone (another concurrent delete).
        services.store.request_investigation_cancel(investigation_id)
        try:
            services.store.delete_investigation(investigation_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown investigation") from None
    return Response(status_code=204)


@router.post("/investigations/{investigation_id}/cancel", status_code=202)
def cancel_investigation(investigation_id: RowId, request: Request) -> dict:
    """Ask the pipeline to stop the running investigation at the next between-docs check.

    The run marks itself PAUSED (not FINISHED) so a later Resume continues from where
    the stop landed. In-flight workers on the parallel path finish their current doc
    before the pipeline exits — Python threads do not accept external preemption."""
    with open_services(request) as services:
        try:
            services.store.get_investigation(investigation_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown investigation") from None
        services.store.request_investigation_cancel(investigation_id)
    return {"status": "stop_requested"}


def _failed_job_message(request: Request, investigation_id: int, target: str) -> str | None:
    """The message of the job that concerns this investigation, when that job failed.

    Matches like the frontend: by the investigation id a job carries first, then by target for an investigate job.
    """
    jobs = [job for job in request.app.state.jobs.list() if job["kind"] in ("investigate", "resume")]  # newest first
    mine = next((job for job in jobs if (job["result"] or {}).get("investigation_id") == investigation_id), None)
    if mine is None:
        mine = next((job for job in jobs if _by_params(job, investigation_id, target)), None)
    if mine is not None and mine["state"] == "failed":
        return mine["message"] or "job failed"
    return None


def _by_params(job: dict, investigation_id: int, target: str) -> bool:
    params = job["params"]
    if job["kind"] == "resume":
        return params.get("investigation_id") == investigation_id
    return str(params.get("target", "")).casefold() == target.casefold()


@router.get("/investigations/{investigation_id}/dashboard")
def investigation_dashboard(
    investigation_id: RowId, request: Request, scope: str | None = Query(None, max_length=40),
) -> dict:
    scope_id = parse_scope(scope)
    with open_services(request) as services:
        catalog = services.attack_catalog()
        with BrowseQueries(services.paths.db_file) as browse:
            if scope_id is not None and not browse.investigation_exists(scope_id):
                raise HTTPException(status_code=404, detail="unknown investigation")
            data = browse.investigation_dashboard(investigation_id, catalog, scope_investigation_id=scope_id)
    if data is None:
        raise HTTPException(status_code=404, detail="unknown investigation")
    header = data["investigation"]
    if header["state"] != "finished":  # the store has no failed state: a crashed job leaves it running or paused
        reason = _failed_job_message(request, investigation_id, header["target"])
        if reason is not None:
            header["state"], header["failure_reason"] = "failed", reason
    return data
