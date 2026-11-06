"""Web search wiring for the Anthropic Messages API adapter.

When a request carries tools=["WebSearch"], the adapter must add Anthropic's server-side
web_search tool (type picked by model) alongside the structured-output `emit` tool, keep
tool_choice "auto" so the model searches and then emits, parse the `emit` block out of a
response that also contains server_tool_use / web_search_tool_result blocks, count the
billed searches from usage.server_tool_use.web_search_requests, and continue a pause_turn.
"""

from __future__ import annotations

import json

import httpx
from pydantic import BaseModel

from cyllex_argus.config.settings import AnthropicApiConfig, LLMConfig
from cyllex_argus.llm.anthropic_api import TOOL_NAME, AnthropicApiProvider
from cyllex_argus.llm.base import LLMRequest


class OutShape(BaseModel):
    verdict: str
    confidence: int


def _cfg(model: str = "claude-sonnet-5-5") -> LLMConfig:
    return LLMConfig(provider="anthropic-api", model=None,
                     anthropic=AnthropicApiConfig(api_key="sk-stored", model=model))


def _request(tools=()) -> LLMRequest:
    return LLMRequest(system="s", content="c", prompt_version="v1", agent="web_search", tools=list(tools))


def _client_from(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _emit_with_search(requests: int = 2, model: str = "claude-sonnet-5-5") -> httpx.Response:
    return httpx.Response(200, json={
        "id": "m", "model": model, "role": "assistant", "stop_reason": "tool_use",
        "content": [
            {"type": "server_tool_use", "id": "s1", "name": "web_search", "input": {"query": "x"}},
            {"type": "web_search_tool_result", "tool_use_id": "s1",
             "content": [{"type": "web_search_result", "url": "http://a", "title": "A"}]},
            {"type": "tool_use", "id": "tu", "name": TOOL_NAME, "input": {"verdict": "ok", "confidence": 1}},
        ],
        "usage": {"input_tokens": 10, "output_tokens": 5, "server_tool_use": {"web_search_requests": requests}},
    })


def _capture(response: httpx.Response):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return response

    return captured, handler


def test_websearch_tool_added_for_modern_model():
    captured, handler = _capture(_emit_with_search())
    provider = AnthropicApiProvider(_cfg("claude-sonnet-5-5"), client=_client_from(handler))
    provider.complete_json(_request(tools=["WebSearch"]), OutShape)
    tools = captured["payload"]["tools"]
    types = [t.get("type") for t in tools]
    names = [t.get("name") for t in tools]
    assert "web_search_20260209" in types          # modern variant for sonnet 4.6+/5
    assert TOOL_NAME in names                        # the emit tool is still there
    assert captured["payload"]["tool_choice"] == {"type": "auto"}


def test_websearch_tool_type_is_basic_for_old_model():
    captured, handler = _capture(_emit_with_search(model="claude-haiku-4-5-20251001"))
    provider = AnthropicApiProvider(_cfg("claude-haiku-4-5-20251001"), client=_client_from(handler))
    provider.complete_json(_request(tools=["WebSearch"]), OutShape)
    types = [t.get("type") for t in captured["payload"]["tools"]]
    assert "web_search_20250305" in types            # pre-4.6 models keep the basic variant
    assert "web_search_20260209" not in types


def test_no_websearch_tool_when_not_requested():
    captured, handler = _capture(_emit_with_search())
    provider = AnthropicApiProvider(_cfg(), client=_client_from(handler))
    provider.complete_json(_request(tools=[]), OutShape)
    types = [t.get("type") for t in captured["payload"]["tools"]]
    assert not any(t and t.startswith("web_search") for t in types)


def test_parses_emit_amid_search_blocks_and_counts_requests():
    _captured, handler = _capture(_emit_with_search(requests=2))
    provider = AnthropicApiProvider(_cfg(), client=_client_from(handler))
    result = provider.complete_json(_request(tools=["WebSearch"]), OutShape)
    assert result.output.verdict == "ok"
    assert result.usage.web_search_requests == 2


def test_pause_turn_is_continued_and_usage_accumulates():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json={
                "id": "m", "model": "claude-sonnet-5-5", "role": "assistant", "stop_reason": "pause_turn",
                "content": [{"type": "server_tool_use", "id": "s1", "name": "web_search", "input": {"query": "x"}}],
                "usage": {"input_tokens": 5, "output_tokens": 2, "server_tool_use": {"web_search_requests": 1}},
            })
        return _emit_with_search(requests=1)

    provider = AnthropicApiProvider(_cfg(), client=_client_from(handler))
    result = provider.complete_json(_request(tools=["WebSearch"]), OutShape)
    assert calls["n"] == 2                           # it re-posted after pause_turn
    assert result.output.verdict == "ok"
    assert result.usage.web_search_requests == 2     # 1 (paused leg) + 1 (final leg)
