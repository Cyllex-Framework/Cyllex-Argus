"""Tests for the OpenAI Chat Completions adapter.

Covers happy path (strict json_schema response → schema instance + usage), key resolution
(env > toml, missing key → LLMUnavailable), the OpenAI-strict schema-tightening helper
(every object gets `additionalProperties: false` + full `required`), and the HTTP error map.
"""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel

from cyllex_argus.config.settings import LLMConfig, OpenAIApiConfig
from cyllex_argus.llm.base import (
    InvalidOutput,
    LLMRequest,
    LLMTimeout,
    LLMUnavailable,
    RateLimited,
)
from cyllex_argus.llm.openai_api import SCHEMA_NAME, OpenAIApiProvider, _tighten_for_openai_strict


class OutShape(BaseModel):
    verdict: str
    confidence: int


def _cfg(api_key: str = "sk-stored", model: str | None = None, organization: str = "") -> LLMConfig:
    return LLMConfig(
        provider="openai-api",
        model=model,
        openai=OpenAIApiConfig(api_key=api_key, model="gpt-4o", organization=organization),
    )


def _request() -> LLMRequest:
    return LLMRequest(system="be strict", content="hello", prompt_version="v1")


def _happy_response(verdict: str = "on-topic", confidence: int = 90) -> httpx.Response:
    content = json.dumps({"verdict": verdict, "confidence": confidence})
    return httpx.Response(200, json={
        "id": "chatcmpl_1",
        "model": "gpt-4o-2024-11-20",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 42, "completion_tokens": 17, "total_tokens": 59},
    })


def _client_from(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_happy_path_returns_schema_instance_and_usage(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    sent: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["url"] = str(request.url)
        sent["headers"] = {k.lower(): v for k, v in request.headers.items()}
        sent["body"] = json.loads(request.read().decode("utf-8"))
        return _happy_response()

    provider = OpenAIApiProvider(_cfg(), client=_client_from(handler))
    response = provider.complete_json(_request(), OutShape)
    assert response.output == OutShape(verdict="on-topic", confidence=90)
    assert response.usage is not None
    assert response.usage.input_tokens == 42 and response.usage.output_tokens == 17
    # The adapter reports the server-side model id, not the configured one.
    assert response.usage.model == "gpt-4o-2024-11-20"
    assert sent["url"].endswith("/chat/completions")
    assert sent["headers"]["authorization"] == "Bearer sk-stored"
    # Structured outputs via response_format json_schema, strict on.
    rf = sent["body"]["response_format"]
    assert rf["type"] == "json_schema"
    assert rf["json_schema"]["name"] == SCHEMA_NAME and rf["json_schema"]["strict"] is True
    # Deterministic output for citation extraction.
    assert sent["body"]["temperature"] == 0


def test_env_wins_over_toml_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers["authorization"]
        return _happy_response()

    provider = OpenAIApiProvider(_cfg("sk-from-toml"), client=_client_from(handler))
    provider.complete_json(_request(), OutShape)
    assert seen["authorization"] == "Bearer sk-from-env"


def test_organization_header_is_set_when_configured(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["org"] = request.headers.get("openai-organization")
        return _happy_response()

    provider = OpenAIApiProvider(_cfg(organization="org_abc"), client=_client_from(handler))
    provider.complete_json(_request(), OutShape)
    assert seen["org"] == "org_abc"


def test_missing_key_raises_llm_unavailable(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIApiProvider(_cfg(api_key=""))
    with pytest.raises(LLMUnavailable, match="API key is not configured"):
        provider.complete_json(_request(), OutShape)


def test_401_is_llm_unavailable_with_rotate_hint(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIApiProvider(
        _cfg(), client=_client_from(lambda r: httpx.Response(401, text="bad key"))
    )
    with pytest.raises(LLMUnavailable, match="rejected the API key"):
        provider.complete_json(_request(), OutShape)


def test_429_is_rate_limited(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIApiProvider(
        _cfg(), client=_client_from(lambda r: httpx.Response(429, text="slow down"))
    )
    with pytest.raises(RateLimited):
        provider.complete_json(_request(), OutShape)


def test_5xx_is_llm_unavailable(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIApiProvider(
        _cfg(), client=_client_from(lambda r: httpx.Response(503, text="busy"))
    )
    with pytest.raises(LLMUnavailable, match="OpenAI error 503"):
        provider.complete_json(_request(), OutShape)


def test_timeout_raises_llm_timeout(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("too slow")

    provider = OpenAIApiProvider(_cfg(), client=_client_from(handler))
    with pytest.raises(LLMTimeout):
        provider.complete_json(_request(), OutShape)


def test_refusal_path_raises_llm_refused(monkeypatch):
    """OpenAI's safety stack can refuse: `choices[0].message.content = null` and `.refusal` set.
    That is a policy refusal, not a malformed answer — it must raise LLMRefused (not retryable),
    carrying the reason, so the pipeline can report it distinctly."""
    from cyllex_argus.llm.base import LLMRefused
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIApiProvider(
        _cfg(),
        client=_client_from(lambda r: httpx.Response(200, json={
            "choices": [{"message": {"content": None, "refusal": "I cannot help with that."}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 0},
        })),
    )
    with pytest.raises(LLMRefused) as exc:
        provider.complete_json(_request(), OutShape)
    assert "cannot help" in (exc.value.explanation or "")
    # A refusal is NOT an InvalidOutput (which the retry helper would retry).
    assert not isinstance(exc.value, InvalidOutput)


# --- schema tightening ---------------------------------------------------------------------


def test_tighten_adds_additional_properties_false_to_every_object():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "meta": {"type": "object", "properties": {"author": {"type": "string"}}},
        },
    }
    _tighten_for_openai_strict(schema)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"name", "meta"}
    assert schema["properties"]["meta"]["additionalProperties"] is False
    assert schema["properties"]["meta"]["required"] == ["author"]


def test_tighten_descends_into_arrays_and_unions():
    schema = {
        "type": "object",
        "properties": {
            "items": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}}}},
            "either": {"anyOf": [{"type": "object", "properties": {"a": {"type": "string"}}}, {"type": "null"}]},
        },
    }
    _tighten_for_openai_strict(schema)
    assert schema["properties"]["items"]["items"]["additionalProperties"] is False
    assert schema["properties"]["either"]["anyOf"][0]["additionalProperties"] is False
