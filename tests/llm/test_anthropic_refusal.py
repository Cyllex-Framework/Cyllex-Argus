"""A cyber-safety refusal from the Anthropic API must surface as a distinct LLMRefused, not as
the generic "no tool_use block" InvalidOutput, so the pipeline can report it and suggest another
model. Reuses the MockTransport harness from test_anthropic_api."""

from __future__ import annotations

import httpx
import pytest

from cyllex_argus.llm.anthropic_api import AnthropicApiProvider
from cyllex_argus.llm.base import InvalidOutput, LLMRefused
from tests.llm.test_anthropic_api import OutShape, _cfg, _client_from, _request


def test_refusal_stop_reason_raises_llm_refused(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    refusal = httpx.Response(200, json={
        "id": "msg_r", "model": "claude-sonnet-5-5", "role": "assistant", "content": [],
        "stop_reason": "refusal",
        "stop_details": {"type": "refusal", "category": "cyber",
                         "explanation": "blocked under Anthropic's Usage Policy"},
    })
    provider = AnthropicApiProvider(_cfg(), client=_client_from(lambda r: refusal))
    with pytest.raises(LLMRefused) as exc:
        provider.complete_json(_request(), OutShape)
    assert exc.value.category == "cyber"
    assert "Policy" in (exc.value.explanation or "")
    # A refusal is NOT an InvalidOutput — the retry helper must not retry it.
    assert not isinstance(exc.value, InvalidOutput)


def test_missing_tool_use_without_refusal_is_still_invalid_output(monkeypatch):
    """A missing tool_use with any OTHER stop_reason is a malformed answer, not a refusal, so it
    stays InvalidOutput (retryable)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    bad = httpx.Response(200, json={
        "id": "m", "model": "claude-sonnet-5-5", "role": "assistant",
        "content": [{"type": "text", "text": "no tool here"}], "stop_reason": "end_turn",
    })
    provider = AnthropicApiProvider(_cfg(), client=_client_from(lambda r: bad))
    with pytest.raises(InvalidOutput):
        provider.complete_json(_request(), OutShape)
