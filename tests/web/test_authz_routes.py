"""Route-coverage guard: every registered /api write is at least operator, admin routes are admin.

This fails when a new endpoint is added whose method/path the policy would leave reader-writable,
forcing an explicit decision instead of a silently-unprotected write.
"""

from __future__ import annotations

from starlette.routing import Route

from cyllex_argus.knowledge.models import Role
from cyllex_argus.web.authz import ANY_SESSION, PUBLIC_PATHS, required_role
from tests.web.conftest import make_client


def _api_routes(world):
    app = make_client(world).app
    for route in app.routes:
        if not isinstance(route, Route):
            continue
        path = route.path
        if not path.startswith("/api"):
            continue
        for method in sorted(route.methods or set()):
            yield method, path


def test_every_api_write_requires_at_least_operator(world):
    offenders = []
    for method, path in _api_routes(world):
        if method in {"GET", "HEAD", "OPTIONS"}:
            continue
        if path in PUBLIC_PATHS or (method, path) in ANY_SESSION:
            continue
        if required_role(method, path).rank < Role.OPERATOR.rank:
            offenders.append(f"{method} {path}")
    assert not offenders, f"writes reachable below operator: {offenders}"


def test_user_and_admin_routes_are_admin(world):
    for method, path in _api_routes(world):
        if (method, path) in ANY_SESSION:
            continue
        if path.startswith(("/api/admin", "/api/users")):
            assert required_role(method, path) is Role.ADMIN, f"{method} {path} not admin-gated"


def test_every_api_route_carries_the_enforce_dependency(world):
    from cyllex_argus.web.authz import enforce
    app = make_client(world).app
    for route in app.routes:
        if not isinstance(route, Route) or not route.path.startswith("/api"):
            continue
        if route.path in ("/api", "/api/{rest:path}"):  # the catch-all only 404s
            continue
        calls = [d.call for d in route.dependant.dependencies]
        assert enforce in calls, f"{route.path} is missing the enforce dependency"
