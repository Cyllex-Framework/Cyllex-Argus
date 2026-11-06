"""PUT /api/settings/logging — toggle the retention mode at runtime."""

from __future__ import annotations

from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def test_put_logging_rejects_unknown_mode(world):
    r = make_client(world).put("/api/settings/logging", json={"retain_raw_llm": "whatever"})
    # Server's error-handler maps the Pydantic validation error to a 400 with a message —
    # either code tells the client the mode is invalid; what matters is that it is NOT 200.
    assert r.status_code in (400, 422)


def test_put_logging_accepts_off(world):
    r = make_client(world).put("/api/settings/logging", json={"retain_raw_llm": "off"})
    assert r.status_code == 200
    assert r.json()["retain_raw_llm"] == "off"


def test_put_logging_accepts_errors_and_persists_to_argus_toml(world):
    r = make_client(world).put("/api/settings/logging", json={"retain_raw_llm": "errors"})
    assert r.status_code == 200
    assert r.json()["retain_raw_llm"] == "errors"
    # Verify argus.toml survived the write.
    svc = world.services()
    try:
        assert svc.config.logging.retain_raw_llm == "errors"
    finally:
        svc.close()


def test_put_logging_accepts_full(world):
    r = make_client(world).put("/api/settings/logging", json={"retain_raw_llm": "full"})
    assert r.status_code == 200
    assert r.json()["retain_raw_llm"] == "full"


def test_put_logging_requires_csrf(world):
    client = _make_client(world)  # no CSRF
    r = client.put("/api/settings/logging", json={"retain_raw_llm": "errors"})
    assert r.status_code == 403
