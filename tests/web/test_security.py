import logging
from pathlib import Path

import pytest
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
from starlette.testclient import WebSocketDisconnect

from cyllex_argus.web.app import create_app
from cyllex_argus.web.security import SecurityMiddleware
from tests.web.conftest import BASE_URL, PORT, TOKEN, make_client, session_token

CSRF = {"X-Argus-CSRF": "1"}


def assert_security_headers(response, *, api: bool) -> None:
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    if api:
        assert response.headers["cache-control"] == "no-store"
    else:
        assert "cache-control" not in response.headers


def add_route(client, path, endpoint) -> None:
    """Register a GET route ahead of the catch-alls (Starlette matches routes in order)."""
    client.app.router.routes.insert(0, APIRoute(path, endpoint, methods=["GET"]))


def test_the_token_header_opens_the_api(world):
    token = session_token(world)
    client = make_client(world, authenticated=False)
    assert client.get("/api/session/check", headers={"X-Argus-Token": token}).status_code == 204


def test_api_requires_the_token_header(world):
    client = make_client(world, authenticated=False)
    response = client.get("/api/session/check")
    assert response.status_code == 401
    assert response.json() == {"error": "session required"}
    assert_security_headers(response, api=True)


@pytest.mark.parametrize("token", ["nope", TOKEN + "x", TOKEN[:-1], TOKEN.upper(), f" {TOKEN}"])
def test_a_wrong_token_is_refused(world, token):
    client = make_client(world, authenticated=False)
    response = client.get("/api/session/check", headers={"X-Argus-Token": token})
    assert response.status_code == 401
    assert response.json() == {"error": "session required"}


def test_a_non_ascii_token_header_is_a_clean_401(world):
    client = make_client(world, authenticated=False)
    response = client.get("/api/session/check", headers=[(b"x-argus-token", b"t\xc3\xa9st\xff\xfe")])
    assert response.status_code == 401
    assert response.json() == {"error": "session required"}


def test_machine_token_expires_after_max_age(world):
    """max_age gates the machine (TAXII) token: once the server has run longer than it, the token
    is refused and the operator must re-run `argus serve`. /api uses per-user sessions, which carry
    their own expiry in the database."""
    clock = [1000.0]
    client = make_client(world, authenticated=False, token_max_age_seconds=60, now=lambda: clock[0])
    headers = {"X-Argus-Token": TOKEN}
    assert client.get("/taxii2/api1/", headers=headers).status_code == 200
    clock[0] += 61  # past expiry
    response = client.get("/taxii2/api1/", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"error": "session expired"}


def test_no_expiry_by_default(world):
    """Backward-compat: when the operator does not opt in, the token has no expiry."""
    clock = [1000.0]
    client = make_client(world, authenticated=True, now=lambda: clock[0])
    assert client.get("/api/session/check").status_code == 204
    clock[0] += 10 * 365 * 24 * 3600  # ten years in the future
    assert client.get("/api/session/check").status_code == 204


def test_a_cookie_no_longer_authenticates(world):
    # Browsers send 127.0.0.1 cookies to every local port, so a cookie can never prove the caller is this app's page.
    client = make_client(world, authenticated=False)
    for name in (f"argus_session_{PORT}", "argus_session", "argus_token"):
        assert client.get("/api/session/check", headers={"cookie": f"{name}={TOKEN}"}).status_code == 401, name


def test_the_token_is_never_set_as_a_cookie(world):
    client = make_client(world)
    for path in ("/", "/api/session/check", "/api/overview", "/api/nope"):
        assert "set-cookie" not in client.get(path).headers, path
    assert "set-cookie" not in make_client(world, authenticated=False).get("/api/session/check").headers


def test_there_is_no_token_exchange_route(world):
    response = make_client(world).post("/api/session", json={"token": TOKEN}, headers=CSRF)
    assert response.status_code in (404, 405)
    assert "set-cookie" not in response.headers


def test_an_empty_token_is_refused_at_startup(world):
    with pytest.raises(ValueError):
        create_app(world.services, token="", port=PORT)


def test_a_missing_or_empty_token_header_is_never_valid_even_with_an_empty_token():
    async def ok(scope, receive, send):
        await JSONResponse({"ok": True})(scope, receive, send)

    client = TestClient(SecurityMiddleware(ok, token="", port=PORT), base_url=BASE_URL)
    assert client.get("/api/anything").status_code == 401
    assert client.get("/api/anything", headers={"X-Argus-Token": ""}).status_code == 401


def test_mutating_requests_require_the_csrf_header(world):
    for client in (make_client(world), make_client(world, authenticated=False)):
        response = client.post("/api/jobs", json={"kind": "attack_update"})
        assert response.status_code == 403
        assert response.json() == {"error": "missing CSRF header"}


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_every_mutating_method_needs_the_csrf_header_even_with_a_valid_session(world, method):
    client = make_client(world)
    refused = client.request(method, "/api/anything")
    assert refused.status_code == 403
    assert refused.json() == {"error": "missing CSRF header"}
    assert client.request(method, "/api/anything", headers=CSRF).status_code == 404


def test_foreign_host_is_refused(world):
    client = make_client(world)
    for host in ("evil.example", f"evil.example:{PORT}", "127.0.0.1:9999", ""):
        response = client.get("/api/session/check", headers={"host": host})
        assert response.status_code == 403, host
        assert response.json() == {"error": "forbidden host"}
        assert_security_headers(response, api=True)
    page = client.get("/", headers={"host": "evil.example"})
    assert page.status_code == 403
    assert_security_headers(page, api=False)
    assert client.get("/api/session/check", headers={"host": f"localhost:{PORT}"}).status_code == 204


def test_security_headers_and_no_cors(world):
    client = make_client(world)
    response = client.get("/api/session/check", headers={"Origin": "https://evil.example"})
    assert_security_headers(response, api=True)
    assert "access-control-allow-origin" not in response.headers


def test_unknown_api_route_is_json_404(world):
    client = make_client(world)
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert "error" in response.json()
    assert_security_headers(response, api=True)


def test_bare_api_path_is_guarded_like_any_api_path(world):
    client = make_client(world)
    found = client.get("/api")
    assert found.status_code == 404
    assert found.json() == {"error": "not found"}
    assert found.headers["cache-control"] == "no-store"
    refused = client.post("/api")
    assert refused.status_code == 403
    assert refused.json() == {"error": "missing CSRF header"}
    anonymous = make_client(world, authenticated=False).get("/api")
    assert anonymous.status_code == 401


@pytest.mark.parametrize(("path", "api"), [("/api/boom", True), ("/boom", False)])
def test_unhandled_errors_are_a_generic_json_500_with_security_headers(world, caplog, path, api):
    def boom():
        raise RuntimeError("secret internals")

    client = make_client(world)
    add_route(client, path, boom)
    with caplog.at_level(logging.ERROR):
        response = client.get(path)
    assert response.status_code == 500
    assert response.json() == {"error": "internal error"}
    assert "secret internals" not in response.text
    assert_security_headers(response, api=api)
    logged = [r for r in caplog.records if r.name == "cyllex_argus.web.security" and r.exc_info]
    assert logged and "secret internals" in str(logged[0].exc_info[1])


def test_an_error_after_the_response_started_is_not_swallowed(world):
    def stream():
        def chunks():
            yield b"first"
            raise RuntimeError("mid-stream")

        return StreamingResponse(chunks())

    client = make_client(world)
    add_route(client, "/api/stream", stream)
    with pytest.raises(RuntimeError, match="mid-stream"):
        client.get("/api/stream")


def test_websocket_connections_are_refused(world):
    client = make_client(world)
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect("/api/ws"):
            pass
    assert refused.value.code == 1008


def test_spa_placeholder_when_frontend_is_not_built(world, tmp_path):
    client = make_client(world, static_dir=tmp_path / "missing")
    response = client.get("/threats/abc")
    assert response.status_code == 200
    assert "Frontend not built" in response.text
    assert response.headers["content-security-policy"].startswith("default-src 'self'")


def test_spa_serves_index_assets_and_blocks_traversal(world, tmp_path):
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>Argus</title>", encoding="utf-8")
    (static / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (static / "favicon.png").write_bytes(b"\x89PNG")
    (tmp_path / "secret.txt").write_text("secret", encoding="utf-8")
    client = make_client(world, static_dir=static)
    assert "Argus" in client.get("/").text
    assert "Argus" in client.get("/threats/intrusion-set--1").text
    assert client.get("/assets/app.js").text == "console.log(1)"
    assert client.get("/favicon.png").content == b"\x89PNG"
    for path in ("/..%2fsecret.txt", "/assets/..%2f..%2fsecret.txt", "/%2e%2e/secret.txt"):
        response = client.get(path)
        assert response.status_code in (200, 404), path
        assert response.content != b"secret", path
        assert "secret" not in response.text, path
        if response.status_code == 200:
            assert "<title>Argus</title>" in response.text, path  # fell back to the SPA index
    assert client.get("/assets/missing.js").status_code == 404


def test_extra_hosts_extend_the_allowlist_but_loopback_still_works(world):
    # `argus serve --host 0.0.0.0` uses this to accept the LAN IP without dropping loopback access.
    token = session_token(world)
    client = make_client(world, authenticated=False, extra_hosts=["192.168.1.5:8765", "argus.local:8765"])
    for allowed in (f"127.0.0.1:{PORT}", "192.168.1.5:8765", "argus.local:8765"):
        assert client.get("/api/session/check", headers={"host": allowed, "X-Argus-Token": token}).status_code == 204, allowed
    assert client.get("/api/session/check", headers={"host": "attacker.example:8765", "X-Argus-Token": token}).status_code == 403


def test_spa_never_touches_the_filesystem_with_a_request_derived_unc_path(world, tmp_path, monkeypatch):
    # On Windows `static_dir / "//host/share/x"` is a UNC path: resolving or stat-ing it opens an SMB connection
    # and leaks the user's NTLM credentials to that host. Any web page can send such a request with an <img>.
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>Argus</title>", encoding="utf-8")
    client = make_client(world, static_dir=static)
    touched: list[str] = []
    real_resolve, real_is_file = Path.resolve, Path.is_file

    def guard(real):
        def wrapper(self, *args, **kwargs):
            if "attacker" in str(self):
                touched.append(str(self))
                raise AssertionError(f"filesystem touched with {self}")
            return real(self, *args, **kwargs)
        return wrapper

    monkeypatch.setattr(Path, "resolve", guard(real_resolve))
    monkeypatch.setattr(Path, "is_file", guard(real_is_file))
    for path in ("///attacker/share/x", "/%2F%2Fattacker/share/x", "/%5C%5Cattacker%5Cshare%5Cx", "/C:%5Cattacker.txt"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "<title>Argus</title>" in response.text, path  # fell back to the SPA index
    assert touched == []


def test_spa_index_is_never_cached_so_a_rebuilt_app_never_points_at_deleted_assets(world, tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>Argus</title>", encoding="utf-8")
    (static / "favicon.png").write_bytes(b"\x89PNG")
    client = make_client(world, static_dir=static)
    for path in ("/", "/threats/intrusion-set--1", "/index.html"):
        response = client.get(path)
        assert "Argus" in response.text and response.headers["cache-control"] == "no-cache", path
    assert "no-cache" not in client.get("/favicon.png").headers.get("cache-control", "")


def test_spa_answers_head_requests(world, tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>Argus</title>", encoding="utf-8")
    built = make_client(world, static_dir=static).head("/")
    assert built.status_code == 200 and built.content == b"" and built.headers["cache-control"] == "no-cache"
    placeholder = make_client(world, static_dir=tmp_path / "missing").head("/")
    assert placeholder.status_code == 200 and placeholder.headers["cache-control"] == "no-cache"
    client = make_client(world, static_dir=static)
    for api_path in ("/api/nope", "/api/overview"):  # HEAD under /api must never fall through to the SPA index
        response = client.head(api_path)
        assert response.status_code == 404 and "text/html" not in response.headers["content-type"], api_path
