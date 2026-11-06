"""Central role authorization for the /api surface.

One policy decides the minimum role for every route, so a new endpoint cannot be born unprotected:
reads are reader+, writes are operator+ by default, an explicit admin-only set covers user and
database management, and a small any-session set covers the things every logged-in user must do
(log out, change own password, read own identity). The default for an unsafe method with no other
rule is operator — writes fail closed.
"""

from __future__ import annotations

from fastapi import HTTPException, Request

from cyllex_argus.knowledge.models import Role
from cyllex_argus.web.deps import current_user
from cyllex_argus.web.security import _PUBLIC_API_PATHS

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Pre-auth routes the middleware lets through without a session; the guard skips them too.
PUBLIC_PATHS = frozenset(_PUBLIC_API_PATHS)

# Exact (method, path) pairs any live session may call, exempt from the writes→operator default.
ANY_SESSION: frozenset[tuple[str, str]] = frozenset({
    ("POST", "/api/auth/logout"),
    ("GET", "/api/auth/me"),
    ("PUT", "/api/users/me/password"),
})

# Path prefixes only an admin may touch (user management and the destructive DB admin routes).
ADMIN_PREFIXES: tuple[str, ...] = ("/api/admin", "/api/users")

# Reads raised above reader: configuration can carry secrets even when masked, and a reader has
# no reason to see it.
OPERATOR_READ_PREFIXES: tuple[str, ...] = ("/api/settings",)


def required_role(method: str, path: str) -> Role:
    """The minimum role allowed to call `method path`. Total: every route maps to a role."""
    method = method.upper()
    if (method, path) in ANY_SESSION:
        return Role.READER  # any live session suffices
    # Marking a watcher's changes as seen is personal read-state, so any live session may do it,
    # including a reader — it is not an operation on the watcher itself.
    if method == "POST" and path.startswith("/api/watchers/") and path.endswith("/seen"):
        return Role.READER
    if path.startswith(ADMIN_PREFIXES):
        return Role.ADMIN
    if method in SAFE_METHODS:
        if path.startswith(OPERATOR_READ_PREFIXES):
            return Role.OPERATOR
        return Role.READER
    return Role.OPERATOR  # fail closed: an unclassified write needs at least operator


def enforce(request: Request) -> None:
    """FastAPI dependency: 401 without a session, 403 when the session's role is too low."""
    path = request.scope["path"]
    if path in PUBLIC_PATHS:
        return
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="session required")
    need = required_role(request.method, path)
    if user.role.rank < need.rank:
        raise HTTPException(status_code=403, detail=f"forbidden: requires {need.value}")
