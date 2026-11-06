"""Per-request resources. SQLite connections are opened and closed inside the handler's own thread."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated

from fastapi import HTTPException, Path, Request

from cyllex_argus.knowledge.browse import BrowseQueries
from cyllex_argus.knowledge.models import User
from cyllex_argus.services import Services


def current_user(request: Request) -> User | None:
    """The user the security middleware resolved from the session token, or None if unauthenticated.

    The middleware attaches it to the ASGI scope before routing; read it back here so handlers and
    the authorization layer share one source of truth for who is calling.
    """
    return request.scope.get("state", {}).get("user")

# A path id outside the signed 64-bit range cannot be bound to an SQLite INTEGER; reject it as a 400, not a 500.
RowId = Annotated[int, Path(ge=-(2**63), le=2**63 - 1)]


_SCOPE = re.compile(r"investigation:(\d{1,18})")


def parse_scope(scope: str | None) -> int | None:
    """The investigation id a `scope` query value selects, or None for the default "everything" view.

    Anything but `investigation:<id>` is a 400; the raw string never goes past this function.
    """
    if scope is None:
        return None
    match = _SCOPE.fullmatch(scope)
    if match is None:
        raise HTTPException(status_code=400, detail="invalid scope: expected investigation:<id>")
    return int(match.group(1))


def scope_label(investigation_id: int | None) -> str:
    return "everything" if investigation_id is None else f"investigation:{investigation_id}"


@contextmanager
def open_services(request: Request) -> Iterator[Services]:
    services: Services = request.app.state.services_factory()
    try:
        yield services
    finally:
        services.close()


@contextmanager
def open_browse(request: Request) -> Iterator[BrowseQueries]:
    with open_services(request) as services:
        browse = BrowseQueries(services.paths.db_file, services.config.scoring.fuzzy_threshold)
        try:
            yield browse
        finally:
            browse.close()
