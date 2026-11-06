"""Local-only guard: Host allowlist, token header, CSRF header and security headers (pure ASGI)."""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable

from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSRF_HEADER = "x-argus-csrf"
# The token travels in a header, never a cookie: browsers send 127.0.0.1 cookies to every local port, and a page on
# another port counts as same-site, so a cookie would hand the token to any local server and let its pages call us.
TOKEN_HEADER = "x-argus-token"
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
_SAFE_METHODS = {"GET", "HEAD"}
_WS_POLICY_VIOLATION = 1008

log = logging.getLogger(__name__)


def _is_api(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


# Public API routes that must work BEFORE the client has a session token (otherwise login is
# impossible). CSRF + Host check still apply. Keep this list tiny on purpose — every entry here
# is pre-auth attack surface.
_PUBLIC_API_PATHS = frozenset({"/api/auth/login", "/api/auth/status", "/api/live"})


def _is_public_api(path: str) -> bool:
    return path in _PUBLIC_API_PATHS


def _is_taxii(path: str) -> bool:
    """Routes under /taxii2/ expose the TAXII 2.1 server. They are token-gated like /api/, but
    use TAXII's standard Authorization: Bearer header in addition to X-Argus-Token."""
    return path == "/taxii2" or path.startswith("/taxii2/")


class SecurityMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        token: str,
        port: int,
        extra_hosts: list[str] | None = None,
        token_max_age_seconds: int | None = None,
        now: Callable[[], float] = time.monotonic,
        session_resolver: Callable[[str], object | None] | None = None,
    ) -> None:
        self._app = app
        self._token = token.encode("utf-8")
        # Resolves a presented `/api` token to a user (or None). When set, `/api` auth is
        # per-user sessions; `/taxii2/` keeps comparing against the machine token above.
        self._session_resolver = session_resolver
        # Loopback names are always accepted so the server responds on the machine it runs on, no matter what
        # additional interfaces are opened. `extra_hosts` names LAN/other bindings passed by `argus serve`.
        self._hosts = {f"127.0.0.1:{port}", f"localhost:{port}", *(extra_hosts or [])}
        self._now = now
        self._issued_at = now()
        self._max_age = token_max_age_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            # The app has no websocket routes; refuse instead of letting them skip the Host and token checks.
            await send({"type": "websocket.close", "code": _WS_POLICY_VIOLATION})
            return
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        path: str = scope["path"]
        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if _is_api(path) and "cache-control" not in headers:  # a route may opt in to caching
                    headers["Cache-Control"] = "no-store"
            await send(message)

        refusal = self._refusal(HTTPConnection(scope), scope["method"], path)
        if refusal is not None:
            status, message = refusal
            await JSONResponse({"error": message}, status_code=status)(scope, receive, send_with_headers)
            return
        try:
            await self._app(scope, receive, send_with_headers)
        except Exception:
            # Starlette's ServerErrorMiddleware sits outside this one and would answer without our headers.
            if started:
                raise
            log.exception("unhandled error while serving %s %s", scope["method"], path)
            await JSONResponse({"error": "internal error"}, status_code=500)(scope, receive, send_with_headers)

    def _refusal(self, connection: HTTPConnection, method: str, path: str) -> tuple[int, str] | None:
        if connection.headers.get("host", "") not in self._hosts:
            return 403, "forbidden host"
        if _is_taxii(path):
            # TAXII clients speak the OASIS standard: Authorization: Bearer <token>, no CSRF.
            # They also accept X-Argus-Token so a browser session that opened a TAXII preview
            # tab works without further plumbing.
            if not self._valid_token(connection):
                return 401, "session required"
            if self._expired():
                return 401, "session expired"
            return None
        if not _is_api(path):
            return None
        if method not in _SAFE_METHODS and connection.headers.get(CSRF_HEADER) != "1":
            return 403, "missing CSRF header"
        if _is_public_api(path):
            # /api/auth/login and /api/auth/status must work BEFORE the client holds a token.
            # Host check (above) + CSRF check (above) already apply; no token here on purpose.
            return None
        # /api is per-user sessions: resolve the token to a user and attach it to the scope so
        # the authorization layer and handlers can read `request.state.user`.
        if self._session_resolver is not None:
            presented = self._presented_token(connection)
            user = self._session_resolver(presented) if presented else None
            if user is None:
                return 401, "session required"
            connection.scope.setdefault("state", {})["user"] = user
            return None
        # No resolver wired (e.g. a bare test app): fall back to the machine-token comparison.
        if not self._valid_token(connection):
            return 401, "session required"
        if self._expired():
            return 401, "session expired"
        return None

    def _expired(self) -> bool:
        return self._max_age is not None and self._now() - self._issued_at > self._max_age

    @staticmethod
    def _presented_token(connection: HTTPConnection) -> str | None:
        """The token the client presented, from `X-Argus-Token` or a standard `Authorization:
        Bearer <token>` header (TAXII clients — OpenCTI, MISP, Sentinel — use the latter)."""
        presented = connection.headers.get(TOKEN_HEADER)
        if not presented:
            auth = connection.headers.get("authorization", "")
            if auth.lower().startswith("bearer "):
                presented = auth[7:]
        return presented or None

    def _valid_token(self, connection: HTTPConnection) -> bool:
        presented = self._presented_token(connection)
        if not presented:
            return False
        return secrets.compare_digest(presented.encode("utf-8", "surrogatepass"), self._token)
