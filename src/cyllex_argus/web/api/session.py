"""Session probe: a cheap authenticated call that tells whether a token still opens the API (a restarted server
issues a new one). The UI learns the same from any 401; tools and tests use this."""

from __future__ import annotations

from fastapi import APIRouter, Response

router = APIRouter()


@router.get("/session/check", status_code=204)
def check_session() -> Response:
    """Reached only with a valid token header (the middleware enforces it)."""
    return Response(status_code=204)
