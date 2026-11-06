from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from cyllex_argus.knowledge.models import Role
from cyllex_argus.web import auth_core
from cyllex_argus.web.app import create_app
from tests.support import World

# The machine token for the served TAXII endpoint (/taxii2/). /api now uses per-user sessions.
TOKEN = "test-token-0123456789"
PORT = 8765
BASE_URL = f"http://127.0.0.1:{PORT}"


def session_token(world: World, role: Role = Role.ADMIN) -> str:
    """Open a real session for a user of the given role and return its token. The admin is reused
    from the boot seed; other roles get a dedicated `test-<role>` user."""
    services = world.services()
    try:
        store = services.store
        if role is Role.ADMIN:
            user = store.get_user_by_username("admin") or store.create_user(
                "admin", auth_core.hash_password("x"), Role.ADMIN)
        else:
            username = f"test-{role.value}"
            user = store.get_user_by_username(username) or store.create_user(
                username, auth_core.hash_password("x"), role)
        token, hashed = auth_core.new_session_token()
        store.create_session(user.id, hashed, datetime.now(UTC) + timedelta(days=1))
        return token
    finally:
        services.close()


def make_client(world: World, *, authenticated: bool = True, role: Role = Role.ADMIN,
                static_dir: Path | None = None, extra_hosts: list[str] | None = None, jobs=None,
                claude: bool = True, http_transport=None, token_max_age_seconds=None, now=None) -> TestClient:
    kwargs = {}
    if token_max_age_seconds is not None:
        kwargs["token_max_age_seconds"] = token_max_age_seconds
    if now is not None:
        kwargs["now"] = now
    # Tests pre-load deliberately-sparse catalogs (3 attack-patterns, 1 group) that the
    # production auto-update guard would mistake for a half-installed catalog and submit
    # an attack_update job for. Disable it: tests set exactly what they want in the DB.
    app = create_app(world.services, token=TOKEN, port=PORT, static_dir=static_dir, jobs=jobs,
                     claude_available=lambda: claude, extra_hosts=extra_hosts, http_transport=http_transport,
                     auto_update_attack=False, **kwargs)
    client = TestClient(app, base_url=BASE_URL)
    if authenticated:
        client.headers["X-Argus-Token"] = session_token(world, role)
    return client
