"""LLMProvider backed by the OpenAI Chat Completions API (bring-your-own-key).

Uses structured outputs via `response_format: {"type": "json_schema", "json_schema": {...,
"strict": true}}`. OpenAI enforces the schema server-side: the model cannot answer with a
blob that fails `strict` validation, so the parser only has to deserialise.

API key is read from the `OPENAI_API_KEY` env var first; the `[llm.openai] api_key` toml field
is only consulted when the env is empty. Both routes land at the same `Authorization: Bearer`
header. If `[llm.openai] organization` is set, it is passed as `OpenAI-Organization`.
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
from cyllex_argus.llm.schema import inline_schema

SCHEMA_NAME = "argus_output"


class OpenAIApiProvider:
    def __init__(self, cfg: LLMConfig, client: httpx.Client | None = None) -> None:
        self._cfg = cfg
        self._client = client or httpx.Client(timeout=cfg.timeout_seconds)

    def _api_key(self) -> str:
        env = os.environ.get("OPENAI_API_KEY", "").strip()
        if env:
            return env
        return self._cfg.openai.api_key.strip()

    def complete_json(self, request: LLMRequest, schema: type[T]) -> LLMResponse[T]:
        key = self._api_key()
        if not key:
            raise LLMUnavailable(
                "OpenAI API key is not configured. Set OPENAI_API_KEY (preferred) or "
                "[llm.openai] api_key in argus.toml."
            )
        api = self._cfg.openai
        from cyllex_argus.llm.router import resolve_model_for_request
        model = resolve_model_for_request(self._cfg, request, provider_default=api.model or "gpt-4o")
        json_schema = inline_schema(schema)
        _tighten_for_openai_strict(json_schema)
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.content},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": SCHEMA_NAME, "schema": json_schema, "strict": True},
            },
            # Deterministic for citation-exact extraction, same as the other providers.
            "temperature": 0,
        }
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        if api.organization.strip():
            headers["OpenAI-Organization"] = api.organization.strip()
        url = api.base_url.rstrip("/") + "/chat/completions"
        started = time.perf_counter()
        try:
            response = self._client.post(url, json=payload, headers=headers, timeout=self._cfg.timeout_seconds)
        except httpx.ConnectError as exc:
            raise LLMUnavailable(f"could not reach OpenAI at {api.base_url}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise LLMTimeout(f"OpenAI request timed out after {self._cfg.timeout_seconds}s") from exc
        except httpx.HTTPError as exc:
            raise LLMUnavailable(f"HTTP error talking to OpenAI: {exc}") from exc

        duration_ms = round((time.perf_counter() - started) * 1000)
        return _parse_response(response, model, schema, duration_ms)


def _parse_response(response: httpx.Response, model: str, schema: type[T], duration_ms: int) -> LLMResponse[T]:
    status = response.status_code
    body_text = response.text
    if status == 401:
        raise LLMUnavailable("OpenAI rejected the API key (401). Rotate OPENAI_API_KEY or your toml value.")
    if status == 429:
        raise RateLimited(f"OpenAI rate-limited (429): {body_text[:300]}")
    if status >= 500:
        raise LLMUnavailable(f"OpenAI error {status}: {body_text[:300]}")
    if status != 200:
        raise InvalidOutput(f"OpenAI error {status}: {body_text[:300]}")

    try:
        data = response.json()
    except ValueError as exc:
        raise InvalidOutput(f"OpenAI returned non-JSON: {body_text[:300]}") from exc

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise InvalidOutput(f"OpenAI response missing choices[0].message.content: {body_text[:300]}") from exc
    if content is None:
        # Strict refusal path: `message.refusal` carries the reason. This is a policy refusal,
        # not a malformed answer, so raise LLMRefused (non-retryable) for the pipeline to report.
        refusal = (data.get("choices") or [{}])[0].get("message", {}).get("refusal")
        raise LLMRefused(explanation=refusal or "no content")
    try:
        parsed = json.loads(content)
        output = schema.model_validate(parsed)
    except (ValueError, ValidationError) as exc:
        raise InvalidOutput(f"OpenAI content did not match schema: {exc}") from exc

    usage_block = data.get("usage") or {}
    reported_model = str(data.get("model") or model)
    usage = LLMUsage(
        input_tokens=int(usage_block.get("prompt_tokens") or 0),
        output_tokens=int(usage_block.get("completion_tokens") or 0),
        model=reported_model,
        duration_ms=duration_ms,
    )
    return LLMResponse(output=output, usage=usage)


def _tighten_for_openai_strict(schema: dict) -> None:
    """OpenAI's `strict: true` requires every object schema to declare `additionalProperties:
    false` AND include every property in `required`. Pydantic's JSON schema already does the
    latter for required fields, but it does NOT emit `additionalProperties: false` by default,
    and `strict` rejects the schema without it. Walk the schema in-place and add the flag to
    every object node. Lists and primitives are untouched.
    """
    if not isinstance(schema, dict):
        return
    if schema.get("type") == "object":
        schema.setdefault("additionalProperties", False)
        props = schema.get("properties")
        if isinstance(props, dict):
            # OpenAI strict requires `required` to list EVERY property; Pydantic's schema omits
            # optional fields. Force every property name in.
            schema["required"] = list(props.keys())
            for value in props.values():
                _tighten_for_openai_strict(value)
    for key in ("items", "additionalItems"):
        child = schema.get(key)
        if isinstance(child, dict):
            _tighten_for_openai_strict(child)
    for arr_key in ("anyOf", "oneOf", "allOf"):
        for child in schema.get(arr_key) or []:
            if isinstance(child, dict):
                _tighten_for_openai_strict(child)
