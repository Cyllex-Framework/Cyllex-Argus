from fastapi import APIRouter, HTTPException, Request

from cyllex_argus.knowledge.browse import BrowseQueries
from cyllex_argus.web.deps import RowId, open_services

router = APIRouter()


@router.get("/investigations/{investigation_id}/trace")
def investigation_trace(investigation_id: RowId, request: Request) -> dict:
    with open_services(request) as services:
        # browse.trace_summary expects a bool "is raw readable right now?" — `off` is the
        # only mode where it is not. `errors` and `full` both let the raw endpoint answer,
        # so events whose raw survived should show `has_raw: true`.
        raw_allowed = services.config.logging.retain_raw_llm != "off"
        with BrowseQueries(services.paths.db_file) as browse:
            data = browse.trace_summary(investigation_id, raw_allowed)
    if data is None:
        raise HTTPException(status_code=404, detail="unknown investigation")
    return data


@router.get("/investigations/{investigation_id}/trace/{event_id}/raw")
def investigation_trace_raw(investigation_id: RowId, event_id: RowId, request: Request) -> dict:
    """Flipping the retention mode to `off` hides EXISTING raw rows too — that's the privacy
    guarantee the switch is supposed to make. `errors` and `full` both reveal; the caller
    gets 404 either way for events whose raw was never persisted or was later purged."""
    with open_services(request) as services:
        raw = None
        if services.config.logging.retain_raw_llm != "off":
            with BrowseQueries(services.paths.db_file) as browse:
                raw = browse.trace_raw(investigation_id, event_id)
    if raw is None:
        raise HTTPException(status_code=404, detail="no raw text for this event")
    return {"prompt": raw[0], "response": raw[1]}


@router.delete("/investigations/{investigation_id}/trace")
def delete_investigation_trace(investigation_id: RowId, request: Request) -> dict:
    with open_services(request) as services:
        try:
            services.store.get_investigation(investigation_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown investigation") from None
        return {"deleted": services.trace_recorder().delete_for(investigation_id)}
