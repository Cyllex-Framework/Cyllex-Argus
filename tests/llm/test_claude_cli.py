import json
import os
import shutil
import subprocess

import pytest
from pydantic import BaseModel

from cyllex_argus.config.settings import LLMConfig
from cyllex_argus.llm.base import InvalidOutput, LLMRequest, LLMTimeout, LLMUnavailable, RateLimited
from cyllex_argus.llm.claude_cli import ClaudeCodeCLIProvider, _child_env
from cyllex_argus.llm.schema import inline_schema


class Item(BaseModel):
    name: str


class Answer(BaseModel):
    items: list[Item]


REQUEST = LLMRequest(system="You extract.", content="<document>hello</document>", prompt_version="t-v1")


def _completed(stdout: str, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _success(payload: dict) -> str:
    return json.dumps({"type": "result", "subtype": "success", "is_error": False,
                       "api_error_status": None, "result": json.dumps(payload),
                       "structured_output": payload,
                       "usage": {"input_tokens": 120, "output_tokens": 45}, "model": "claude-opus-5-5"})


def _provider(stdout=None, raise_exc=None, seen=None, **cfg):
    def runner(cmd, stdin, cwd, timeout):
        if seen is not None:
            seen.update(cmd=cmd, stdin=stdin, cwd_listing=os.listdir(cwd), timeout=timeout)
        if raise_exc:
            raise raise_exc
        return _completed(stdout)
    return ClaudeCodeCLIProvider(LLMConfig(**cfg), runner=runner, resolve_binary=lambda name: "C:/bin/claude.exe")


def test_inline_schema_has_no_refs():
    schema = inline_schema(Answer)
    text = json.dumps(schema)
    assert "$ref" not in text and "$defs" not in text
    assert schema["properties"]["items"]["items"]["properties"]["name"]["type"] == "string"


def test_command_disables_tools_and_passes_content_on_stdin():
    seen = {}
    result = _provider(stdout=_success({"items": [{"name": "a"}]}), seen=seen).complete_json(REQUEST, Answer)
    assert result.output == Answer(items=[Item(name="a")])
    cmd = seen["cmd"]
    assert cmd[:2] == ["C:/bin/claude.exe", "-p"]
    assert cmd[cmd.index("--tools") + 1] == ""
    assert "--allowedTools" not in cmd
    assert "--bare" not in cmd
    assert cmd[cmd.index("--output-format") + 1] == "json"
    assert cmd[cmd.index("--system-prompt") + 1] == "You extract."
    assert json.loads(cmd[cmd.index("--json-schema") + 1]) == inline_schema(Answer)
    assert "--model" not in cmd
    assert seen["stdin"] == REQUEST.content
    assert seen["cwd_listing"] == []
    assert seen["timeout"] == 600


def test_tools_and_model_are_forwarded():
    seen = {}
    request = REQUEST.model_copy(update={"tools": ["WebSearch"]})
    _provider(stdout=_success({"items": []}), seen=seen, model="opus").complete_json(request, Answer)
    cmd = seen["cmd"]
    assert cmd[cmd.index("--tools") + 1] == "WebSearch"
    assert cmd[cmd.index("--allowedTools") + 1] == "WebSearch"
    assert cmd[cmd.index("--model") + 1] == "opus"


@pytest.mark.parametrize("payload", [
    {"is_error": True, "subtype": "success", "api_error_status": 429, "result": "API Error"},
    {"is_error": True, "subtype": "success", "api_error_status": None,
     "result": "Claude AI usage limit reached|1759140000"},
])
def test_rate_limits(payload):
    with pytest.raises(RateLimited):
        _provider(stdout=json.dumps(payload)).complete_json(REQUEST, Answer)


def test_missing_structured_output_is_invalid():
    stdout = json.dumps({"is_error": False, "subtype": "success", "result": "no json"})
    with pytest.raises(InvalidOutput):
        _provider(stdout=stdout).complete_json(REQUEST, Answer)


def test_schema_mismatch_is_invalid():
    with pytest.raises(InvalidOutput):
        _provider(stdout=_success({"items": [{"nope": 1}]})).complete_json(REQUEST, Answer)


def test_other_errors_are_invalid_output():
    stdout = json.dumps({"is_error": True, "subtype": "error_max_turns", "result": "stopped"})
    with pytest.raises(InvalidOutput):
        _provider(stdout=stdout).complete_json(REQUEST, Answer)


def test_not_logged_in_is_unavailable():
    with pytest.raises(LLMUnavailable):
        _provider(stdout="Invalid API key · Please run /login").complete_json(REQUEST, Answer)


def test_missing_binary_is_unavailable():
    provider = ClaudeCodeCLIProvider(LLMConfig(), runner=lambda *a: None, resolve_binary=lambda name: None)
    with pytest.raises(LLMUnavailable, match="not found"):
        provider.complete_json(REQUEST, Answer)


@pytest.mark.parametrize("result", [
    "You've hit your session limit · resets 3:45pm",
    "You've hit your weekly limit · resets Mon 12:00am",
    "You've hit your Opus limit · resets 5pm",
    "You've hit your monthly spend limit · raise it in settings",
])
def test_current_usage_limits_are_rate_limited(result):
    with pytest.raises(RateLimited):
        _provider(stdout=json.dumps({"is_error": True, "subtype": "success", "api_error_status": None, "result": result})).complete_json(REQUEST, Answer)


@pytest.mark.parametrize("result", [
    "Claude.ai login expired",
    "OAuth token has expired",
    "OAuth token revoked",
])
def test_auth_expiry_is_unavailable(result):
    with pytest.raises(LLMUnavailable):
        _provider(stdout=json.dumps({"is_error": True, "subtype": "success", "api_error_status": None, "result": result})).complete_json(REQUEST, Answer)


def test_child_env_removes_api_credentials(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "test-token")
    env = _child_env()
    assert "ANTHROPIC_API_KEY" not in env
    assert "ANTHROPIC_AUTH_TOKEN" not in env


def test_timeout_is_invalid_output():
    exc = subprocess.TimeoutExpired(cmd="claude", timeout=600)
    with pytest.raises(InvalidOutput, match="timed out"):
        _provider(raise_exc=exc).complete_json(REQUEST, Answer)


@pytest.mark.parametrize("error", [FileNotFoundError(2, "No such file"), PermissionError(13, "Access is denied")])
def test_a_binary_that_cannot_start_is_unavailable(error):
    with pytest.raises(LLMUnavailable, match="could not start"):
        _provider(raise_exc=error).complete_json(REQUEST, Answer)


def test_a_file_left_locked_in_the_work_directory_does_not_fail_the_call():
    left_open = []

    def runner(cmd, stdin, cwd, timeout):
        left_open.append((open(cwd / "session.lock", "w"), cwd))  # e.g. a child process still holds it
        return _completed(_success({"items": []}))

    provider = ClaudeCodeCLIProvider(LLMConfig(), runner=runner, resolve_binary=lambda name: "claude")
    try:
        assert provider.complete_json(REQUEST, Answer).output == Answer(items=[])
    finally:
        for handle, workdir in left_open:
            handle.close()
            shutil.rmtree(workdir, ignore_errors=True)


def test_timeout_is_an_llm_timeout():
    exc = subprocess.TimeoutExpired(cmd="claude", timeout=600)
    with pytest.raises(LLMTimeout, match="timed out after 600s"):
        _provider(raise_exc=exc).complete_json(REQUEST, Answer)


def test_usage_is_read_from_the_cli_output():
    response = _provider(stdout=_success({"items": []})).complete_json(REQUEST, Answer)
    assert response.usage.input_tokens == 120
    assert response.usage.output_tokens == 45
    assert response.usage.model == "claude-opus-5-5"
    assert response.usage.duration_ms >= 0


def test_usage_is_none_when_the_cli_does_not_report_it():
    stdout = json.dumps({"subtype": "success", "is_error": False, "structured_output": {"items": []}})
    assert _provider(stdout=stdout).complete_json(REQUEST, Answer).usage is None
