"""LLMProvider backed by a local Ollama server (`/api/chat` with a JSON-schema `format`).

Nothing leaves the machine. Ollama has no web search tool, so `request.tools` is ignored.
The reported model id is prefixed with `ollama/` so the price table treats it as free.
"""

from __future__ import annotations

import json
import re

import httpx
from pydantic import ValidationError

from cyllex_argus.config.settings import LLMConfig
from cyllex_argus.llm.base import (
    InvalidOutput,
    LLMRequest,
    LLMResponse,
    LLMTimeout,
    LLMUnavailable,
    LLMUsage,
    T,
)
from cyllex_argus.llm.schema import inline_schema

MODEL_PREFIX = "ollama/"


class OllamaProvider:
    def __init__(self, cfg: LLMConfig, client: httpx.Client | None = None) -> None:
        self._cfg = cfg
        self._client = client or httpx.Client(timeout=cfg.timeout_seconds)

    def complete_json(self, request: LLMRequest, schema: type[T]) -> LLMResponse[T]:
        from cyllex_argus.llm.router import resolve_model_for_request
        ollama = self._cfg.ollama
        base_url = ollama.base_url.rstrip("/")
        # Per-agent override wins over the base model; falls back to [llm.ollama] model.
        resolved_model = resolve_model_for_request(self._cfg, request, provider_default=ollama.model)
        payload = {
            "model": resolved_model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.content},
            ],
            "format": inline_schema(schema),
            "stream": False,
            "keep_alive": ollama.keep_alive,
        }
        try:
            response = self._client.post(base_url + "/api/chat", json=payload, timeout=self._cfg.timeout_seconds)
        except httpx.ConnectError as exc:
            raise LLMUnavailable(f"Ollama is not running at {base_url} (start it with `ollama serve`).") from exc
        except httpx.TimeoutException as exc:
            raise LLMTimeout(f"Ollama timed out after {self._cfg.timeout_seconds}s") from exc
        except httpx.HTTPError as exc:
            raise LLMUnavailable(f"could not reach Ollama at {base_url}: {exc}") from exc

        if response.status_code == 404 and re.search(r"does not exist", response.text, re.IGNORECASE):
            raise LLMUnavailable(f"Model '{resolved_model}' not found. Pull it with `ollama pull {resolved_model}`.")
        if response.status_code >= 500:
            raise LLMUnavailable(f"Ollama error {response.status_code}: {response.text[:500]}")
        if response.status_code != 200:
            raise InvalidOutput(f"Ollama error {response.status_code}: {response.text[:500]}")

        try:
            data = response.json()
            output = schema.model_validate(json.loads(data["message"]["content"]))
        except (ValueError, KeyError, TypeError) as exc:  # JSONDecodeError is a ValueError; so is ValidationError
            detail = str(exc) if isinstance(exc, ValidationError) else f"{type(exc).__name__}: {exc}"
            raise InvalidOutput(f"Ollama returned invalid structured output: {detail[:500]}") from exc
        usage = LLMUsage(
            input_tokens=int(data.get("prompt_eval_count") or 0),
            output_tokens=int(data.get("eval_count") or 0),
            model=MODEL_PREFIX + resolved_model,
            duration_ms=round(int(data.get("total_duration") or 0) / 1_000_000),
        )
        return LLMResponse(output=output, usage=usage)
