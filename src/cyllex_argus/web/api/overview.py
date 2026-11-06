from fastapi import APIRouter, Request

from cyllex_argus.web.deps import open_browse

router = APIRouter()


@router.get("/overview")
def overview(request: Request) -> dict:
    with open_browse(request) as browse:
        return browse.overview()
