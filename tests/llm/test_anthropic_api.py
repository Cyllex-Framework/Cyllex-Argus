"""Tests for the Anthropic Messages API adapter.

Covers the end-to-end happy path (tool_use block → schema instance + usage), key resolution
(env wins over toml, missing key raises LLMUnavailable), and the HTTP error map (401 → auth,
429 → RateLimited, 5xx → LLMUnavailable, invalid-JSON → InvalidOutput).
"""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel

from cyllex_argus.config.settings import AnthropicApiConfig, LLMConfig
from cyllex_argus.llm.anthropic_api import TOOL_NAME, AnthropicApiProvider
from cyllex_argus.llm.base import (
    InvalidOutput,
    LLMRequest,
    LLMTimeout,
    LLMUnavailable,
    RateLimited,
)


class OutShape(BaseModel):
    verdict: str
    confidence: int


def _cfg(api_key: str = "sk-stored", model: str | None = None) -> LLMConfig:
    return LLMConfig(
        provider="anthropic-api",
        model=model,
        anthropic=AnthropicApiConfig(api_key=api_key, model="claude-sonnet-5-5"),
    )


def _request() -> LLMRequest:
    return LLMRequest(system="be strict", content="hello", prompt_version="v1")


def _tool_use_response(verdict: str = "on-topic", confidence: int = 90) -> httpx.Response:
    return httpx.Response(200, json={
        "id": "msg_1",
        "model": "claude-sonnet-5-5",
        "role": "assistant",
        "content": [
            {"type": "tool_use", "id": "tu_1", "name": TOOL_NAME, "input": {"verdict": verdict, "confidence": confidence}},
        ],
        "usage": {"input_tokens": 42, "output_tokens": 17},
    })


def _client_from(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_happy_path_returns_schema_instance_and_usage(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sent: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["url"] = str(request.url)
        sent["headers"] = {k.lower(): v for k, v in request.headers.items()}
        sent["body"] = request.read().decode("utf-8")
        return _tool_use_response()

    provider = AnthropicApiProvider(_cfg(), client=_client_from(handler))
    response = provider.complete_json(_request(), OutShape)
    assert response.output == OutShape(verdict="on-topic", confidence=90)
    assert response.usage is not None
    assert response.usage.input_tokens == 42 and response.usage.output_tokens == 17
    assert response.usage.model == "claude-sonnet-5-5"
    assert sent["url"].endswith("/v1/messages")
    # Correct headers reach Anthropic — key, version, content-type.
    assert sent["headers"]["x-api-key"] == "sk-stored"
    assert sent["headers"]["anthropic-version"] == "2023-06-01"
    # The schema travels as the only tool's input_schema. tool_choice must be "auto": the Claude
    # 5 family rejects a forced {"type": "tool"} with a 400, so forcing it would break every
    # current model (see test_tool_choice_is_auto_not_forced).
    body = sent["body"]
    assert '"name": "emit"' in body or '"name":"emit"' in body
    assert '"tool_choice"' in body


def test_tool_choice_is_auto_not_forced(monkeypatch):
    """Regression: the adapter must send tool_choice "auto". A forced {"type": "tool"} (or
    "any") is rejected with HTTP 400 by the Claude 5 family — the bug that made every Analyst
    call fail once an API key finally worked."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sent: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["body"] = json.loads(request.read().decode("utf-8"))
        return _tool_use_response()

    AnthropicApiProvider(_cfg(), client=_client_from(handler)).complete_json(_request(), OutShape)
    assert sent["body"]["tool_choice"] == {"type": "auto"}


def test_tool_is_strict_with_a_tightened_schema(monkeypatch):
    """The emit tool must be strict: the API then guarantees tool_use.input matches the schema,
    so a weaker model cannot drop a required field and fail the document (the schema-validation
    failures Haiku hit on key sources). Strict requires additionalProperties:false + required."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sent: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["body"] = json.loads(request.read().decode("utf-8"))
        return _tool_use_response()

    AnthropicApiProvider(_cfg(), client=_client_from(handler)).complete_json(_request(), OutShape)
    tool = sent["body"]["tools"][0]
    assert tool["strict"] is True
    schema = tool["input_schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"verdict", "confidence"}


def test_env_wins_over_toml_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
    seen_key = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_key["x-api-key"] = request.headers["x-api-key"]
        return _tool_use_response()

    provider = AnthropicApiProvider(_cfg("sk-from-toml"), client=_client_from(handler))
    provider.complete_json(_request(), OutShape)
    assert seen_key["x-api-key"] == "sk-from-env"


def test_missing_key_raises_llm_unavailable(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicApiProvider(_cfg(api_key=""))
    with pytest.raises(LLMUnavailable, match="API key is not configured"):
        provider.complete_json(_request(), OutShape)


def test_401_is_llm_unavailable_with_rotate_hint(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicApiProvider(
        _cfg(), client=_client_from(lambda r: httpx.Response(401, text="bad key"))
    )
    with pytest.raises(LLMUnavailable, match="rejected the API key"):
        provider.complete_json(_request(), OutShape)


def test_429_is_rate_limited(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicApiProvider(
        _cfg(), client=_client_from(lambda r: httpx.Response(429, text="slow down"))
    )
    with pytest.raises(RateLimited, match="rate-limited"):
        provider.complete_json(_request(), OutShape)


def test_5xx_is_llm_unavailable(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicApiProvider(
        _cfg(), client=_client_from(lambda r: httpx.Response(503, text="overloaded"))
    )
    with pytest.raises(LLMUnavailable, match="Anthropic error 503"):
        provider.complete_json(_request(), OutShape)


def test_timeout_raises_llm_timeout(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("too slow")

    provider = AnthropicApiProvider(_cfg(), client=_client_from(handler))
    with pytest.raises(LLMTimeout):
        provider.complete_json(_request(), OutShape)


def test_response_without_tool_use_block_is_invalid_output(monkeypatch):
    """Operators report this as a prompt-engineering issue (model answered with free text
    instead of calling the tool). The adapter must surface it, not silently return garbage."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicApiProvider(
        _cfg(),
        client=_client_from(lambda r: httpx.Response(200, json={
            "content": [{"type": "text", "text": "I think the answer is 42."}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        })),
    )
    with pytest.raises(InvalidOutput, match="no tool_use"):
        provider.complete_json(_request(), OutShape)


def test_response_with_schema_mismatch_is_invalid_output(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicApiProvider(
        _cfg(),
        client=_client_from(lambda r: httpx.Response(200, json={
            "content": [{"type": "tool_use", "name": TOOL_NAME, "input": {"wrong": "shape"}}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        })),
    )
    with pytest.raises(InvalidOutput, match="did not match schema"):
        provider.complete_json(_request(), OutShape)


def test_llm_config_model_override_wins_over_anthropic_model_default(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        seen["model"] = json.loads(request.read().decode("utf-8"))["model"]
        return _tool_use_response()

    provider = AnthropicApiProvider(_cfg(model="claude-opus-5-5"), client=_client_from(handler))
    provider.complete_json(_request(), OutShape)
    assert seen["model"] == "claude-opus-5-5"
