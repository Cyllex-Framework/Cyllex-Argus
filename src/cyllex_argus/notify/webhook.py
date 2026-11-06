"""Webhook dispatcher: POST a JSON event to each configured `[[webhook]]` when an
investigation reaches a terminal state (FINISHED or PAUSED).

The dispatcher is deliberately narrow: it signs with HMAC-SHA256 when `secret` is set,
POSTs the payload with a short timeout, and swallows every failure (connection, timeout,
non-2xx) with a log line. A webhook subscriber being down must not fail an investigation
whose work is already stored on disk.

Payload shape (small, stable, documented so operators can bind it to Slack / Discord /
in-house routers):

    {
      "event": "investigation.finished" | "investigation.paused",
      "investigation_id": 42,
      "target": "APT29 Microsoft January 2024 OAuth",
      "state": "finished",
      "stage_counts": {"collected": 10, "triaged": 8, "validated": 6, "irrelevant": 2},
      "claims_accepted": 23,
      "claims_rejected": 5,
      "message": "Paused: rate-limited. Re-run the same command to resume.",
      "timestamp": "2026-10-22T14:17:03.422Z"
    }

Signature header (when `secret` is non-empty):

    X-Argus-Signature: sha256=<hex digest>
    X-Argus-Timestamp: <ISO 8601 UTC, same as payload.timestamp>

The subscriber verifies by concatenating `timestamp + "." + raw_body` and HMAC-SHA256ing
with the shared secret. Matches the Stripe / GitHub pattern; standard enough to be a
drop-in.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from cyllex_argus.config.settings import WebhookConfig
from cyllex_argus.knowledge.models import InvestigationState, Watcher, WatcherChange
from cyllex_argus.pipeline.investigation import InvestigationReport

_log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RETRIES = 1  # one retry per webhook: enough to survive a transient 503, cheap otherwise


_STATE_TO_EVENT = {
    InvestigationState.FINISHED: "investigation.finished",
    InvestigationState.PAUSED: "investigation.paused",
}


def _event_name(state: InvestigationState) -> str | None:
    """The dispatcher only fires on terminal transitions; RUNNING is not a terminal state."""
    return _STATE_TO_EVENT.get(state)


def _resolve_secret(cfg: WebhookConfig) -> str:
    """Env wins over toml, same precedence as every other secret in the project. An empty
    secret means the dispatcher sends an unsigned payload (useful for internal webhooks on
    a trusted LAN)."""
    if cfg.env_secret:
        from_env = os.environ.get(cfg.env_secret, "").strip()
        if from_env:
            return from_env
    return cfg.secret.strip()


def build_investigation_payload(
    event: str,
    report: InvestigationReport,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """Shape the webhook payload for an investigation report. Pure function, no I/O; the
    tests pin the exact JSON keys and ordering so a subscriber contract is stable."""
    return {
        "event": event,
        "investigation_id": report.investigation_id,
        "target": report.target,
        "state": report.state.value,
        "stage_counts": dict(report.stage_counts),
        "claims_accepted": report.claims_accepted,
        "claims_rejected": report.claims_rejected,
        "message": report.message,
        "timestamp": now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


def build_watcher_change_payload(
    watcher: Watcher, change: WatcherChange, *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """Shape the webhook payload for one watcher change event. Pure; the tests pin the keys."""
    citation = None
    if change.citation is not None:
        c = change.citation
        citation = {
            "quote": c.quote, "publisher": c.publisher,
            "document_title": c.document_title, "location": c.location,
        }
    return {
        "event": "watcher.change",
        "watcher_id": change.watcher_id or watcher.id,
        "target": watcher.target,
        "kind": change.kind.value,
        "subject": change.subject,
        "predicate": change.predicate,
        "object": change.object,
        "from_status": change.from_status.value if change.from_status else None,
        "to_status": change.to_status.value if change.to_status else None,
        "citation": citation,
        "detected_at": change.detected_at.isoformat(),
        "timestamp": now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


def sign_payload(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over `timestamp + "." + body`. Returns the `sha256=<hex>` string the
    subscriber compares against the header verbatim."""
    mac = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode() + body,
        hashlib.sha256,
    )
    return f"sha256={mac.hexdigest()}"


@dataclass
class _DispatchResult:
    url: str
    status: str      # "sent" | "skipped" | "failed"
    detail: str | None = None


class WebhookDispatcher:
    """One instance per Pipeline. `dispatch_investigation` is called from the terminal
    transitions in `pipeline/investigation.py`."""

    def __init__(
        self,
        webhooks: list[WebhookConfig],
        client: httpx.Client | None = None,
        log: Callable[[str], None] = lambda message: None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._webhooks = webhooks
        self._client = client if client is not None else httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS)
        self._log = log
        self._now = now

    def dispatch_investigation(self, report: InvestigationReport) -> list[_DispatchResult]:
        """Fan out `report` to every enabled webhook whose `on_states` list contains the
        report's state. Returns a per-webhook result list; the pipeline ignores it (fire
        and forget), the tests assert on it. Exceptions are caught and surfaced as
        'failed' entries so a single broken webhook does not stop the others."""
        results: list[_DispatchResult] = []
        event = _event_name(report.state)
        if event is None:
            return results
        for cfg in self._webhooks:
            if not cfg.enabled:
                results.append(_DispatchResult(cfg.url, "skipped", "disabled"))
                continue
            if cfg.on_states and report.state.value not in cfg.on_states:
                results.append(_DispatchResult(cfg.url, "skipped", f"state {report.state.value} not in on_states"))
                continue
            payload = build_investigation_payload(event, report, now=self._now)
            results.append(self._send(cfg, payload))
        return results

    def dispatch_watcher_change(self, watcher: Watcher, change: WatcherChange) -> list[_DispatchResult]:
        """Fan a watcher change event out to every enabled webhook. Unlike investigation
        events, `on_states` does not apply (a change has no investigation terminal state), so
        every enabled webhook receives it."""
        results: list[_DispatchResult] = []
        for cfg in self._webhooks:
            if not cfg.enabled:
                results.append(_DispatchResult(cfg.url, "skipped", "disabled"))
                continue
            payload = build_watcher_change_payload(watcher, change, now=self._now)
            results.append(self._send(cfg, payload))
        return results

    def _send(self, cfg: WebhookConfig, payload: dict[str, Any]) -> _DispatchResult:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "cyllex-argus/webhook"}
        secret = _resolve_secret(cfg)
        if secret:
            headers["X-Argus-Timestamp"] = payload["timestamp"]
            headers["X-Argus-Signature"] = sign_payload(secret, payload["timestamp"], body)
        last_error: str | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self._client.post(cfg.url, content=body, headers=headers)
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < MAX_RETRIES:
                    # Linear backoff — a 1s nap is plenty for a flaky Slack webhook. We
                    # intentionally don't exponential-backoff: the pipeline is on this
                    # thread and the operator wants to see the terminal transition fast.
                    time.sleep(1.0)
                    continue
                self._log(f"Webhook {cfg.url} failed: {last_error}")
                return _DispatchResult(cfg.url, "failed", last_error)
            if 200 <= response.status_code < 300:
                return _DispatchResult(cfg.url, "sent", f"HTTP {response.status_code}")
            # 4xx is a config problem; retry won't help. 5xx might.
            if response.status_code < 500 or attempt >= MAX_RETRIES:
                detail = f"HTTP {response.status_code}: {response.text[:200]}"
                self._log(f"Webhook {cfg.url} rejected: {detail}")
                return _DispatchResult(cfg.url, "failed", detail)
            last_error = f"HTTP {response.status_code}"
            time.sleep(1.0)
        return _DispatchResult(cfg.url, "failed", last_error or "unknown error")
