"""Webhook dispatch for watcher change events + runner de-dup."""

from datetime import UTC, datetime
from types import SimpleNamespace

import httpx

from cyllex_argus.config.settings import WebhookConfig
from cyllex_argus.knowledge.models import (
    AssessmentStatus,
    ChangeKind,
    Citation,
    Polarity,
    QuoteStatus,
    Role,
    Watcher,
    WatcherChange,
)
from cyllex_argus.notify.webhook import WebhookDispatcher, build_watcher_change_payload
from cyllex_argus.watchers import runner

NOW = datetime(2026, 10, 31, 10, 0, 0, tzinfo=UTC)


def _watcher():
    return Watcher(id=7, target="APT29", cron_expr="0 8 * * *", next_run_at=NOW, created_at=NOW)


def _change(kind=ChangeKind.VERIFIED):
    return WatcherChange(
        id=1, watcher_id=7, entity_id="intrusion-set--apt29", kind=kind,
        ref_key="apt29|uses|oauth", subject="APT29", predicate="uses", object="OAuth token theft",
        from_status=AssessmentStatus.SINGLE_SOURCE, to_status=AssessmentStatus.CORROBORATED,
        citation=Citation(claim_id=1, quote="verbatim", quote_status=QuoteStatus.VERIFIED,
                          polarity=Polarity.ASSERTS, document_title="Advisory", publisher="Mandiant"),
        detected_at=NOW,
    )


def _mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_watcher_payload_carries_the_change():
    payload = build_watcher_change_payload(_watcher(), _change(), now=lambda: NOW)
    assert payload["event"] == "watcher.change"
    assert payload["target"] == "APT29"
    assert payload["watcher_id"] == 7
    assert payload["kind"] == "verified"
    assert payload["object"] == "OAuth token theft"
    assert payload["from_status"] == "single-source"
    assert payload["to_status"] == "corroborated"
    assert payload["citation"]["publisher"] == "Mandiant"
    assert payload["citation"]["quote"] == "verbatim"


def test_dispatch_goes_to_all_enabled_ignoring_on_states():
    posts = []

    def handler(request):
        posts.append(str(request.url))
        return httpx.Response(200)

    cfgs = [
        WebhookConfig(url="https://a/x", on_states=["finished"]),  # on_states must not block watcher events
        WebhookConfig(url="https://b/x"),
        WebhookConfig(url="https://c/x", enabled=False),
    ]
    results = WebhookDispatcher(cfgs, client=_mock_client(handler), now=lambda: NOW)\
        .dispatch_watcher_change(_watcher(), _change())
    sent = [r for r in results if r.status == "sent"]
    assert len(sent) == 2
    assert set(posts) == {"https://a/x", "https://b/x"}  # disabled not posted


def _seed_change(store):
    uid = store.create_user("alice", "h", Role.OPERATOR).id
    w = store.create_watcher(target="APT29", cron_expr="0 8 * * *", created_by=uid, next_run_at=NOW)
    store.add_changes(w.id, [WatcherChange(id=0, watcher_id=0, kind=ChangeKind.NEW, ref_key="k", detected_at=NOW)])
    return w


def test_dispatch_pending_marks_delivered_and_dedups(store):
    _seed_change(store)
    calls = []

    class FakeDispatcher:
        def dispatch_watcher_change(self, watcher, change):
            calls.append(change.id)
            return [SimpleNamespace(url="https://soc/x", status="sent")]

    runner.dispatch_pending(store, FakeDispatcher())
    assert store.undelivered_changes() == []       # marked delivered
    assert len(calls) == 1

    runner.dispatch_pending(store, FakeDispatcher())  # nothing left
    assert len(calls) == 1                           # not re-dispatched


def test_dispatch_pending_leaves_undelivered_on_failure(store):
    _seed_change(store)

    class FailingDispatcher:
        def dispatch_watcher_change(self, watcher, change):
            return [SimpleNamespace(url="https://soc/x", status="failed")]

    runner.dispatch_pending(store, FailingDispatcher())
    assert len(store.undelivered_changes()) == 1  # stays for the next pass


def test_partial_failure_stays_undelivered(store):
    _seed_change(store)

    class PartialDispatcher:
        def dispatch_watcher_change(self, watcher, change):
            return [
                SimpleNamespace(url="https://a/x", status="sent"),
                SimpleNamespace(url="https://b/x", status="failed"),
            ]

    runner.dispatch_pending(store, PartialDispatcher())
    # One webhook failed, so the change is NOT marked delivered — it retries next pass rather
    # than silently dropping the failed channel.
    assert len(store.undelivered_changes()) == 1


def test_no_webhooks_marks_delivered(store):
    _seed_change(store)

    class NoWebhooks:
        def dispatch_watcher_change(self, watcher, change):
            return []  # no enabled webhooks

    runner.dispatch_pending(store, NoWebhooks())
    # Nothing to deliver to: mark delivered so it does not retry forever.
    assert store.undelivered_changes() == []
