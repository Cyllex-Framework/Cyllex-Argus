"""LLMProvider backed by headless Claude Code (`claude -p`) on the user's Claude subscription.

Verified contract (Claude Code 2.1.284): `--output-format json` prints one JSON object with
`is_error`, `subtype`, `api_error_status`, `result` and `structured_output`; `--tools ""` disables
every built-in tool. Never pass `--bare`: it disables subscription (OAuth) authentication.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ValidationError

from cyllex_argus.config.settings import LLMConfig
from cyllex_argus.llm.base import (
    InvalidOutput,
    LLMError,
    LLMRequest,
    LLMResponse,
    LLMTimeout,
    LLMUnavailable,
    LLMUsage,
    RateLimited,
    T,
)
from cyllex_argus.llm.schema import inline_schema

Runner = Callable[[list[str], str, Path, float], "subprocess.CompletedProcess[str]"]

_RATE_LIMIT_MARKERS = (
    "rate limit", "usage limit", "limit reached", "too many requests", "overloaded",
    "hit your", "resets", "spend limit",
)
_AUTH_MARKERS = (
    "not logged in", "/login", "invalid api key", "authentication", "unauthorized",
    "login expired", "oauth token", "token has expired", "token revoked",
)


def _child_env() -> dict[str, str]:
    """Return a copy of os.environ without API credentials to avoid accidental API billing."""
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("ANTHROPIC_AUTH_TOKEN", None)
    return env


def run_subprocess(cmd: list[str], stdin: str, cwd: Path, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd, input=stdin, capture_output=True, text=True, encoding="utf-8",
        errors="replace", cwd=cwd, timeout=timeout, env=_child_env(),
    )


class ClaudeCodeCLIProvider:
    def __init__(
        self,
        cfg: LLMConfig,
        runner: Runner = run_subprocess,
        resolve_binary: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self._cfg = cfg
        self._runner = runner
        self._resolve_binary = resolve_binary

    def build_command(self, binary: str, request: LLMRequest, schema: type[BaseModel]) -> list[str]:
        tools = ",".join(request.tools)
        cmd = [
            binary, "-p",
            "--output-format", "json",
            "--no-session-persistence",
            "--safe-mode",
            "--strict-mcp-config",
            "--tools", tools,
            "--system-prompt", request.system,
            "--json-schema", json.dumps(inline_schema(schema)),
        ]
        if request.tools:
            cmd += ["--allowedTools", tools]
        # Per-agent override first, then base `cfg.model`, else leave --model unset so the
        # CLI picks its own default. Import inline to avoid a cycle with the router module.
        from cyllex_argus.llm.router import resolve_model_for_request
        resolved = resolve_model_for_request(self._cfg, request, provider_default="")
        if resolved:
            cmd += ["--model", resolved]
        return cmd

    def complete_json(self, request: LLMRequest, schema: type[T]) -> LLMResponse[T]:
        binary = self._resolve_binary(self._cfg.claude_binary)
        if not binary:
            raise LLMUnavailable(
                f"'{self._cfg.claude_binary}' was not found. Install Claude Code and run `claude` once to log in."
            )
        cmd = self.build_command(binary, request, schema)
        # On Windows a lingering child process can keep a file open; that must not fail the call.
        with tempfile.TemporaryDirectory(prefix="argus-llm-", ignore_cleanup_errors=True) as workdir:
            started = time.perf_counter()
            try:
                proc = self._runner(cmd, request.content, Path(workdir), self._cfg.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                raise LLMTimeout(f"claude timed out after {self._cfg.timeout_seconds}s") from exc
            except OSError as exc:
                raise LLMUnavailable(f"could not start '{binary}': {exc}") from exc
        duration_ms = round((time.perf_counter() - started) * 1000)
        return self._parse(proc, schema, duration_ms)

    def _parse(
        self, proc: subprocess.CompletedProcess[str], schema: type[T], duration_ms: int = 0
    ) -> LLMResponse[T]:
        try:
            data = json.loads(proc.stdout)
        except (json.JSONDecodeError, TypeError):
            message = (proc.stderr or proc.stdout or "no output").strip()[:500]
            raise self._classify(message, None, default=LLMUnavailable) from None
        if not isinstance(data, dict):
            raise InvalidOutput("unexpected output from claude")
        if data.get("is_error") or data.get("subtype") != "success":
            message = str(data.get("result") or data.get("subtype") or "unknown error")[:500]
            raise self._classify(message, data.get("api_error_status"), default=InvalidOutput)
        payload = data.get("structured_output")
        if payload is None:
            raise InvalidOutput("claude returned no structured output")
        try:
            output = schema.model_validate(payload)
        except ValidationError as exc:
            raise InvalidOutput(str(exc)) from exc
        return LLMResponse(output=output, usage=self._usage(data, duration_ms))

    def _usage(self, data: dict, duration_ms: int) -> LLMUsage | None:
        """Build the usage record Argus stores. Claude Code's JSON output has shifted around which
        top-level fields it carries (sometimes `model`, sometimes `modelUsage: {<model>: {...}}`),
        so we try the known locations and fall back to the configured model so the row is at least
        ``claude-code-cli/<model>``. If no tokens are reported at all, we return None."""
        raw = data.get("usage") or data.get("message", {}).get("usage")
        if not isinstance(raw, dict):
            # Some versions put per-model counts under modelUsage: {<model>: {inputTokens, outputTokens, ...}}
            model_usage = data.get("modelUsage")
            if isinstance(model_usage, dict) and model_usage:
                model_name, bucket = next(iter(model_usage.items()))
                if isinstance(bucket, dict):
                    input_tokens = bucket.get("inputTokens") or bucket.get("input_tokens")
                    output_tokens = bucket.get("outputTokens") or bucket.get("output_tokens")
                    if isinstance(input_tokens, int) and isinstance(output_tokens, int):
                        return LLMUsage(
                            input_tokens=input_tokens, output_tokens=output_tokens,
                            model=str(model_name), duration_ms=duration_ms,
                        )
            return None
        input_tokens, output_tokens = raw.get("input_tokens"), raw.get("output_tokens")
        if not isinstance(input_tokens, int) or not isinstance(output_tokens, int):
            return None
        model = data.get("model") or data.get("message", {}).get("model") or self._cfg.model or "claude-code-cli"
        return LLMUsage(
            input_tokens=input_tokens, output_tokens=output_tokens, model=str(model), duration_ms=duration_ms
        )

    @staticmethod
    def _classify(message: str, status: object, default: type[LLMError]) -> LLMError:
        lowered = message.lower()
        if str(status) == "429" or any(m in lowered for m in _RATE_LIMIT_MARKERS):
            return RateLimited(message)
        if str(status) == "401" or any(m in lowered for m in _AUTH_MARKERS):
            return LLMUnavailable(message)
        return default(message)
