"""LLMProvider backed by the Anthropic Messages API (bring-your-own-key).

Uses tool-use to force structured output: a single tool named `emit` carries the request's
JSON schema as `input_schema`, and `tool_choice: {type: "tool", name: "emit"}` forces Claude
to answer with exactly one `tool_use` block whose `input` matches the schema. This is the
Anthropic-recommended way to get strict JSON out of the Messages API — more reliable than
asking the model to "respond with JSON".

API key is read from the `ANTHROPIC_API_KEY` env var first; the `[llm.anthropic] api_key` toml
field is only consulted when the env is empty. The env route is preferred because the key never
touches disk. Both routes land at the same `x-api-key` header.
"""

from __future__ import annotations

import json
import os
import time

import httpx
from pydantic import ValidationError

from cyllex_argus.config.settings import LLMConfig
from cyllex_argus.llm.base import (
    InvalidOutput,
    LLMRefused,
    LLMRequest,
    LLMResponse,
    LLMTimeout,
    LLMUnavailable,
    LLMUsage,
    RateLimited,
    T,
)
from cyllex_argus.llm.schema import inline_strict_schema

TOOL_NAME = "emit"
TOOL_DESCRIPTION = (
    "Return the result as a structured JSON object matching the provided schema. "
    "Call this tool exactly once; do not include free-form text in the response."
)
# A generous default; the pipeline keeps content well below 100k tokens per request even on
# the Analyst's largest chunks. Set explicitly because `max_tokens` is REQUIRED by the API.
DEFAULT_MAX_TOKENS = 8192

# Anthropic's server-side web search tool. The Collector asks for it by passing
# `tools=["WebSearch"]`; we translate that to the API's real tool here. The tool type is
# model-gated: the dynamic-filtering `_20260209` variant needs Opus 4.6+/Sonnet 4.6+/Fable 5,
# older models keep the basic `_20250305`. `max_uses` bounds cost — each search is billed at
# $10 / 1000, and a handful of queries is enough to find primary sources on one threat.
WEB_SEARCH_TOOL_NAME = "web_search"
WEB_SEARCH_TOOL_MODERN = "web_search_20260209"
WEB_SEARCH_TOOL_BASIC = "web_search_20250305"
_MODERN_WEB_SEARCH_MODELS = ("opus-4-6", "opus-4-7", "opus-4-8", "opus-5", "sonnet-4-6", "sonnet-5", "fable-5")
WEB_SEARCH_MAX_USES = 5
# The web_search tool runs server-side; a long search turn can come back as stop_reason
# "pause_turn", which we continue by re-posting the accumulated assistant content. Bound the
# number of continuations so a stuck turn fails loudly instead of looping forever.
_MAX_SERVER_TOOL_ROUNDS = 8


def _web_search_tool(model: str) -> dict:
    m = model.lower()
    tool_type = WEB_SEARCH_TOOL_MODERN if any(frag in m for frag in _MODERN_WEB_SEARCH_MODELS) else WEB_SEARCH_TOOL_BASIC
    return {"type": tool_type, "name": WEB_SEARCH_TOOL_NAME, "max_uses": WEB_SEARCH_MAX_USES}


class AnthropicApiProvider:
    def __init__(self, cfg: LLMConfig, client: httpx.Client | None = None) -> None:
        self._cfg = cfg
        self._client = client or httpx.Client(timeout=cfg.timeout_seconds)

    def _api_key(self) -> str:
        env = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if env:
            return env
        return self._cfg.anthropic.api_key.strip()

    def complete_json(self, request: LLMRequest, schema: type[T]) -> LLMResponse[T]:
        key = self._api_key()
        if not key:
            raise LLMUnavailable(
                "Anthropic API key is not configured. Set ANTHROPIC_API_KEY (preferred) "
                "or [llm.anthropic] api_key in argus.toml."
            )
        api = self._cfg.anthropic
        from cyllex_argus.llm.router import resolve_model_for_request
        model = resolve_model_for_request(self._cfg, request, provider_default=api.model or "claude-sonnet-5-5")
        tool_schema = inline_strict_schema(schema)
        # strict: the API guarantees tool_use.input validates against the schema exactly, so a
        # weaker model (e.g. Haiku) cannot omit a required field and fail the whole document.
        # Compatible with tool_choice "auto" — strict constrains the input, not whether the tool
        # is called. Needs the tightened schema (additionalProperties:false + required).
        tools: list[dict] = [{"name": TOOL_NAME, "description": TOOL_DESCRIPTION, "input_schema": tool_schema, "strict": True}]
        # A request tagged with WebSearch (the Collector's web_search connector) also gets the
        # server-side web_search tool. With tool_choice "auto" the model searches first, then
        # calls `emit` with the structured result; `_find_tool_use` picks the emit block out of
        # the server_tool_use / web_search_tool_result blocks that precede it.
        if "WebSearch" in request.tools:
            tools.append(_web_search_tool(model))
        base_payload = {
            "model": model,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "system": request.system,
            "tools": tools,
            # Must be "auto", not a forced {"type": "tool"}: the Claude 5 family (sonnet-5-5,
            # opus-5-5) rejects forced tool_choice with HTTP 400 ("type 'tool' and 'any' are not
            # supported for this model") because those models think before acting. "auto" is
            # accepted by every model and, with the extraction prompt, the model calls emit anyway;
            # a stray text-only answer is caught as InvalidOutput and retried.
            "tool_choice": {"type": "auto"},
        }
        headers = {
            "x-api-key": key,
            "anthropic-version": api.anthropic_version,
            "content-type": "application/json",
        }
        url = api.base_url.rstrip("/") + "/v1/messages"
        # One POST for an ordinary extraction; several when web_search pauses the turn. Usage is
        # summed across the legs (each leg is billed), so the trace charges the whole search.
        messages: list[dict] = [{"role": "user", "content": request.content}]
        totals = {"input": 0, "output": 0, "searches": 0}
        reported_model = model
        started = time.perf_counter()
        for _ in range(_MAX_SERVER_TOOL_ROUNDS):
            try:
                response = self._client.post(
                    url, json={**base_payload, "messages": messages},
                    headers=headers, timeout=self._cfg.timeout_seconds,
                )
            except httpx.ConnectError as exc:
                raise LLMUnavailable(f"could not reach Anthropic at {api.base_url}: {exc}") from exc
            except httpx.TimeoutException as exc:
                raise LLMTimeout(f"Anthropic request timed out after {self._cfg.timeout_seconds}s") from exc
            except httpx.HTTPError as exc:
                raise LLMUnavailable(f"HTTP error talking to Anthropic: {exc}") from exc

            data = _decode(response)
            usage_block = data.get("usage") or {}
            totals["input"] += int(usage_block.get("input_tokens") or 0)
            totals["output"] += int(usage_block.get("output_tokens") or 0)
            server_tool_use = usage_block.get("server_tool_use") or {}
            totals["searches"] += int(server_tool_use.get("web_search_requests") or 0)
            reported_model = str(data.get("model") or model)
            if data.get("stop_reason") == "pause_turn":
                # The server tool is mid-run; hand its own output back so it can finish the turn.
                messages.append({"role": "assistant", "content": data.get("content") or []})
                continue
            duration_ms = round((time.perf_counter() - started) * 1000)
            return _parse_final(data, schema, reported_model, duration_ms, totals)
        raise InvalidOutput(
            f"Anthropic web search did not converge after {_MAX_SERVER_TOOL_ROUNDS} pause_turn continuations"
        )


def _decode(response: httpx.Response) -> dict:
    """Map HTTP status to the exception taxonomy, parse the JSON body, and raise on a safety
    refusal. Returns the response dict for a 200 that is not a refusal."""
    status = response.status_code
    body_text = response.text
    if status == 401:
        raise LLMUnavailable("Anthropic rejected the API key (401). Rotate ANTHROPIC_API_KEY or your toml value.")
    if status == 429:
        raise RateLimited(f"Anthropic rate-limited (429): {body_text[:300]}")
    if status >= 500:
        raise LLMUnavailable(f"Anthropic error {status}: {body_text[:300]}")
    if status != 200:
        raise InvalidOutput(f"Anthropic error {status}: {body_text[:300]}")

    try:
        data = response.json()
    except ValueError as exc:
        raise InvalidOutput(f"Anthropic returned non-JSON: {body_text[:300]}") from exc

    # A safety refusal (stop_reason "refusal") is a distinct, non-retryable condition — the model
    # declined on policy grounds (e.g. the cyber classifier on offensive TTP content). Surface it
    # as LLMRefused so the pipeline reports "blocked by safety policy" and can suggest another
    # model, rather than burying it in the generic "no tool_use block" InvalidOutput below.
    if data.get("stop_reason") == "refusal":
        details = data.get("stop_details") or {}
        raise LLMRefused(category=details.get("category"), explanation=details.get("explanation"))
    return data


def _parse_final(data: dict, schema: type[T], model: str, duration_ms: int, totals: dict) -> LLMResponse[T]:
    """Validate the `emit` tool_use block into the schema and build usage from the summed totals."""
    tool_block = _find_tool_use(data)
    if tool_block is None:
        raise InvalidOutput(f"Anthropic returned no tool_use block: {json.dumps(data)[:400]}")
    try:
        output = schema.model_validate(tool_block.get("input") or {})
    except ValidationError as exc:
        raise InvalidOutput(f"Anthropic tool_use input did not match schema: {exc}") from exc

    usage = LLMUsage(
        input_tokens=totals["input"],
        output_tokens=totals["output"],
        model=model,
        duration_ms=duration_ms,
        web_search_requests=totals["searches"],
    )
    return LLMResponse(output=output, usage=usage)


def _find_tool_use(data: dict) -> dict | None:
    """Return the first content block of type tool_use with name=emit, or None."""
    for block in data.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == TOOL_NAME:
            return block
    return None
