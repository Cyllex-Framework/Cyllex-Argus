"""Tests for the webhook dispatcher.

Covers the payload shape (stable public contract), the HMAC-SHA256 signature header, the
`on_states` filter, the fire-on-terminal-state semantics (RUNNING never fires), the error
isolation (one dead subscriber does not stop the others), and the secret resolution
precedence (env > toml).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

import httpx

from cyllex_argus.config.settings import WebhookConfig
from cyllex_argus.knowledge.models import InvestigationState
from cyllex_argus.notify.webhook import (
    WebhookDispatcher,
    build_investigation_payload,
    sign_payload,
)
from cyllex_argus.pipeline.investigation import InvestigationReport

NOW = datetime(2026, 10, 22, 14, 17, 3, 422000, tzinfo=UTC)


def _report(**over) -> InvestigationReport:
    base = dict(
        investigation_id=42,
        target="APT29 Microsoft January 2024 OAuth",
        state=InvestigationState.FINISHED,
        stage_counts={"collected": 10, "triaged": 8, "validated": 6, "irrelevant": 2},
        claims_accepted=23,
        claims_rejected=5,
        message=None,
    )
    base.update(over)
    return InvestigationReport(**base)


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ---- Payload shape (stable contract) ------------------------------------------------


def test_payload_shape_is_stable():
    """Subscribers bind to the key names. The test pins them."""
    payload = build_investigation_payload("investigation.finished", _report(), now=lambda: NOW)
    assert payload == {
        "event": "investigation.finished",
        "investigation_id": 42,
        "target": "APT29 Microsoft January 2024 OAuth",
        "state": "finished",
        "stage_counts": {"collected": 10, "triaged": 8, "validated": 6, "irrelevant": 2},
        "claims_accepted": 23,
        "claims_rejected": 5,
        "message": None,
        "timestamp": "2026-10-22T14:17:03.422000Z",
    }


def test_payload_for_paused_investigation_carries_the_message():
    """A paused investigation (rate-limit or operator stop) has a human-friendly message that
    the webhook subscriber may want to echo into Slack."""
    report = _report(state=InvestigationState.PAUSED, message="Paused: rate-limited.")
    payload = build_investigation_payload("investigation.paused", report, now=lambda: NOW)
    assert payload["event"] == "investigation.paused"
    assert payload["state"] == "paused"
    assert payload["message"] == "Paused: rate-limited."


# ---- Signature header ---------------------------------------------------------------


def test_signature_header_is_hmac_sha256_of_timestamp_dot_body():
    """Stripe / GitHub pattern: subscriber verifies with `HMAC(secret, timestamp + "." + body)`."""
    timestamp = "2026-10-22T14:17:03.422000Z"
    body = b'{"event": "investigation.finished"}'
    expected = "sha256=" + hmac.new(
        b"supersecret", f"{timestamp}.".encode() + body, hashlib.sha256,
    ).hexdigest()
    assert sign_payload("supersecret", timestamp, body) == expected


def test_dispatcher_signs_the_request_when_secret_is_set():
    captured = {}

    def handler(request):
        captured["sig"] = request.headers.get("x-argus-signature")
        captured["ts"] = request.headers.get("x-argus-timestamp")
        captured["body"] = request.read()
        return httpx.Response(200, text="ok")

    cfg = WebhookConfig(url="https://hooks.example/x", secret="supersecret")
    dispatcher = WebhookDispatcher([cfg], client=_mock_client(handler), now=lambda: NOW)
    dispatcher.dispatch_investigation(_report())
    assert captured["sig"] is not None
    assert captured["sig"].startswith("sha256=")
    assert captured["ts"] == "2026-10-22T14:17:03.422000Z"
    # Verify the signature matches
    expected = sign_payload("supersecret", captured["ts"], captured["body"])
    assert captured["sig"] == expected


def test_dispatcher_does_not_sign_when_secret_is_empty():
    """Internal webhooks on trusted LANs often skip signing (ngrok to localhost, k8s svc)."""
    captured = {}

    def handler(request):
        captured["sig"] = request.headers.get("x-argus-signature")
        return httpx.Response(200)

    cfg = WebhookConfig(url="https://hooks.example/x")
    WebhookDispatcher([cfg], client=_mock_client(handler), now=lambda: NOW).dispatch_investigation(_report())
    assert captured["sig"] is None


def test_env_secret_wins_over_toml_secret(monkeypatch):
    monkeypatch.setenv("MY_HOOK_SECRET", "env-wins")
    captured = {}

    def handler(request):
        captured["body"] = request.read()
        captured["sig"] = request.headers.get("x-argus-signature")
        captured["ts"] = request.headers.get("x-argus-timestamp")
        return httpx.Response(200)

    cfg = WebhookConfig(url="https://hooks.example/x", secret="toml-value", env_secret="MY_HOOK_SECRET")
    WebhookDispatcher([cfg], client=_mock_client(handler), now=lambda: NOW).dispatch_investigation(_report())
    expected = sign_payload("env-wins", captured["ts"], captured["body"])
    assert captured["sig"] == expected


# ---- Terminal-state semantics -------------------------------------------------------


def test_running_investigation_does_not_fire_any_webhook():
    """RUNNING is a transition state, not terminal. The dispatcher is called at every state
    transition in the pipeline; a RUNNING entry must be a silent no-op."""
    called = {"count": 0}

    def handler(_request):
        called["count"] += 1
        return httpx.Response(200)

    cfg = WebhookConfig(url="https://hooks.example/x")
    report = _report(state=InvestigationState.RUNNING)
    results = WebhookDispatcher([cfg], client=_mock_client(handler)).dispatch_investigation(report)
    assert results == []
    assert called["count"] == 0


def test_on_states_filter_fires_only_on_matching_state():
    """`on_states = ["finished"]` means do NOT fire on paused."""
    called = {"count": 0}

    def handler(_request):
        called["count"] += 1
        return httpx.Response(200)

    cfg = WebhookConfig(url="https://hooks.example/x", on_states=["finished"])
    disp = WebhookDispatcher([cfg], client=_mock_client(handler))
    disp.dispatch_investigation(_report(state=InvestigationState.PAUSED))
    assert called["count"] == 0
    disp.dispatch_investigation(_report(state=InvestigationState.FINISHED))
    assert called["count"] == 1


def test_empty_on_states_fires_on_every_terminal_state():
    called = {"count": 0}

    def handler(_request):
        called["count"] += 1
        return httpx.Response(200)

    cfg = WebhookConfig(url="https://hooks.example/x")  # on_states defaults to []
    disp = WebhookDispatcher([cfg], client=_mock_client(handler))
    disp.dispatch_investigation(_report(state=InvestigationState.FINISHED))
    disp.dispatch_investigation(_report(state=InvestigationState.PAUSED,
                                        message="Paused: rate-limited."))
    assert called["count"] == 2


def test_disabled_webhook_is_skipped():
    called = {"count": 0}

    def handler(_request):
        called["count"] += 1
        return httpx.Response(200)

    cfg = WebhookConfig(url="https://hooks.example/x", enabled=False)
    results = WebhookDispatcher([cfg], client=_mock_client(handler)).dispatch_investigation(_report())
    assert called["count"] == 0
    assert results[0].status == "skipped"


# ---- Error isolation ----------------------------------------------------------------


def test_a_broken_webhook_does_not_stop_the_others():
    """A dead subscriber must not fail an investigation whose work is already on disk."""
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if "broken" in str(request.url):
            return httpx.Response(500, text="server error")
        return httpx.Response(200, text="ok")

    cfg_broken = WebhookConfig(url="https://broken.example/hook")
    cfg_ok = WebhookConfig(url="https://ok.example/hook")
    disp = WebhookDispatcher([cfg_broken, cfg_ok], client=_mock_client(handler))
    results = disp.dispatch_investigation(_report())
    assert len(results) == 2
    assert any(r.status == "failed" for r in results)
    assert any(r.status == "sent" for r in results)


def test_connection_error_surfaces_as_a_failed_result_not_an_exception():
    def handler(_request):
        raise httpx.ConnectError("unreachable")

    cfg = WebhookConfig(url="https://offline.example/hook")
    disp = WebhookDispatcher([cfg], client=_mock_client(handler))
    results = disp.dispatch_investigation(_report())
    assert len(results) == 1
    assert results[0].status == "failed"
    assert "ConnectError" in (results[0].detail or "")


def test_payload_body_is_valid_json():
    """The content-type is application/json; the body must parse."""
    captured = {}

    def handler(request):
        captured["ct"] = request.headers.get("content-type")
        captured["body"] = request.read()
        return httpx.Response(200)

    cfg = WebhookConfig(url="https://ok.example/hook")
    WebhookDispatcher([cfg], client=_mock_client(handler)).dispatch_investigation(_report())
    assert captured["ct"] == "application/json"
    parsed = json.loads(captured["body"])
    assert parsed["investigation_id"] == 42
