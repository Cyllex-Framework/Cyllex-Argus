import threading
import webbrowser

import pytest
from typer.testing import CliRunner

from cyllex_argus.cli import app as cli_module
from cyllex_argus.cli.app import app

runner = CliRunner(env={"COLUMNS": "200"})
narrow_runner = CliRunner(env={"COLUMNS": "60"})


@pytest.fixture(autouse=True)
def no_real_browser(monkeypatch):
    """No test may open a real browser tab; the launch itself is patched out at `_open_browser_later`."""
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(args)
        pytest.fail("webbrowser.open must not be called from tests")

    monkeypatch.setattr(webbrowser, "open", forbidden)
    yield
    assert calls == [], "a test launched a real browser"


class SpyTimer:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


def test_serve_binds_loopback_and_opens_browser(monkeypatch):
    """The printed and auto-opened URL is a plain `http://host:port/` — no `#token=` fragment.
    The login screen is the only path to the dashboard; the session token lives on `app.state`
    and only reaches the client as the response body of a successful POST /api/auth/login."""
    calls = {}

    def fake_run(app_, host, port, log_level, timeout_graceful_shutdown):
        calls.update(app=app_, host=host, port=port, log_level=log_level, timeout=timeout_graceful_shutdown)

    monkeypatch.setattr(cli_module.uvicorn, "run", fake_run)
    opened = []
    monkeypatch.setattr(cli_module, "_open_browser_later", opened.append)
    result = runner.invoke(app, ["serve", "--port", "8799"])
    assert result.exit_code == 0, result.output
    assert calls["host"] == "127.0.0.1" and calls["port"] == 8799
    # "warning" keeps uvicorn's access log, and with it any URL, out of the output.
    assert calls["log_level"] == "warning"
    # An open SSE stream must not keep Ctrl+C hanging until the running job ends.
    assert calls["timeout"] == 3
    [url] = opened
    assert url == "http://127.0.0.1:8799/"
    # The session token lives on app.state (for the middleware) and never leaks into the URL.
    assert "token" not in url
    assert len(calls["app"].state.token) >= 40
    assert url in result.output


def test_serve_prints_the_url_unwrapped_in_a_narrow_terminal(monkeypatch):
    calls = {}
    monkeypatch.setattr(cli_module.uvicorn, "run", lambda app_, **kwargs: calls.update(app=app_))
    result = narrow_runner.invoke(app, ["serve", "--no-browser", "--port", "8799"])
    assert result.exit_code == 0, result.output
    url = "http://127.0.0.1:8799/"
    assert any(url in line for line in result.output.splitlines()), result.output
    # URL must not carry a token fragment under any terminal width.
    assert "#token=" not in result.output


def test_open_browser_later_returns_a_cancellable_daemon_timer():
    timer = cli_module._open_browser_later("http://127.0.0.1:8799/")
    try:
        assert isinstance(timer, threading.Timer)
        assert timer.daemon and timer.is_alive()
        assert timer.args == ("http://127.0.0.1:8799/",)
    finally:
        timer.cancel()
        timer.join(timeout=2)


def test_serve_cancels_the_browser_timer_after_run_returns(monkeypatch):
    timer = SpyTimer()
    monkeypatch.setattr(cli_module.uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setattr(cli_module, "_open_browser_later", lambda url: timer)
    result = runner.invoke(app, ["serve"])
    assert result.exit_code == 0, result.output
    assert timer.cancelled


def test_serve_cancels_the_browser_timer_when_run_fails(monkeypatch):
    timer = SpyTimer()

    def failing_run(*args, **kwargs):
        raise OSError("address already in use")

    monkeypatch.setattr(cli_module.uvicorn, "run", failing_run)
    monkeypatch.setattr(cli_module, "_open_browser_later", lambda url: timer)
    result = runner.invoke(app, ["serve"])
    assert result.exit_code != 0
    assert timer.cancelled


def test_serve_stops_the_job_manager_after_run_returns(monkeypatch):
    events = []

    def fake_run(app_, **kwargs):
        app_.state.jobs.shutdown = lambda: events.append("shutdown")
        events.append("run")

    monkeypatch.setattr(cli_module.uvicorn, "run", fake_run)
    monkeypatch.setattr(cli_module, "_open_browser_later", lambda url: None)
    result = runner.invoke(app, ["serve", "--no-browser"])
    assert result.exit_code == 0, result.output
    assert events == ["run", "shutdown"]


def test_serve_stops_the_job_manager_when_run_fails(monkeypatch):
    events = []

    def fake_run(app_, **kwargs):
        app_.state.jobs.shutdown = lambda: events.append("shutdown")
        raise OSError("address already in use")

    monkeypatch.setattr(cli_module.uvicorn, "run", fake_run)
    result = runner.invoke(app, ["serve", "--no-browser"])
    assert result.exit_code != 0
    assert events == ["shutdown"]


def test_serve_without_browser(monkeypatch):
    monkeypatch.setattr(cli_module.uvicorn, "run", lambda *a, **k: None)
    opened = []
    monkeypatch.setattr(cli_module, "_open_browser_later", opened.append)
    result = runner.invoke(app, ["serve", "--no-browser"])
    assert result.exit_code == 0 and opened == []
    assert "http://127.0.0.1:8765/" in result.output
    assert "#token=" not in result.output


def test_serve_warns_when_default_password_is_in_use(monkeypatch):
    """A first-run operator (no env, no toml hash) sees a yellow line nudging them to change
    the shipped default — otherwise LAN mode would silently accept 'admin' / 'Argus123'."""
    monkeypatch.setattr(cli_module.uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setattr(cli_module, "_open_browser_later", lambda url: None)
    monkeypatch.setattr(cli_module, "_default_password_in_use", lambda: True)
    result = runner.invoke(app, ["serve", "--no-browser"])
    assert result.exit_code == 0, result.output
    assert "Default admin credentials in use" in result.output
    assert "Argus123" in result.output
    assert "reset-admin-password" in result.output


def test_serve_does_not_warn_when_admin_is_configured(monkeypatch):
    """Opposite case: operator has set env or toml → no default-password banner. The green
    "login screen gates every page" line appears instead."""
    monkeypatch.setattr(cli_module.uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setattr(cli_module, "_open_browser_later", lambda url: None)
    monkeypatch.setattr(cli_module, "_default_password_in_use", lambda: False)
    result = runner.invoke(app, ["serve", "--no-browser"])
    assert result.exit_code == 0, result.output
    assert "Default admin credentials" not in result.output
    assert "Login screen gates every page" in result.output


def test_serve_rejects_privileged_ports():
    assert runner.invoke(app, ["serve", "--port", "80"]).exit_code != 0
