"""Outbound notifications on investigation terminal state (FINISHED / PAUSED).

Default-off: an operator who never writes `[[webhook]]` in argus.toml never fires one. The
runner is the only place a notification can leave the machine, same discipline as enrichers."""

from cyllex_argus.notify.webhook import (
    WebhookDispatcher,
    build_investigation_payload,
    sign_payload,
)

__all__ = ["WebhookDispatcher", "build_investigation_payload", "sign_payload"]
