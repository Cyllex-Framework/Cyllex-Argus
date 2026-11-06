import json

import httpx
import pytest
from pydantic import BaseModel

from cyllex_argus.config.settings import LLMConfig
from cyllex_argus.llm.base import InvalidOutput, LLMRequest, LLMTimeout, LLMUnavailable
from cyllex_argus.llm.ollama import OllamaProvider


class Verdict(BaseModel):
    relevant: bool
    reason: str


REQUEST = LLMRequest(system="be brief", content="is it relevant?", prompt_version="triage-v1")


def chat_reply(content: str, **extra) -> dict:
    return {
        "model": "qwen2.5:32b-instruct", "message": {"role": "assistant", "content": content},
        "prompt_eval_count": 120, "eval_count": 30, "total_duration": 2_500_000_000, **extra,
    }


def provider(handler) -> tuple[OllamaProvider, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = httpx.Client(transport=httpx.MockTransport(wrapped))
    return OllamaProvider(LLMConfig(provider="ollama"), client=client), seen


def test_successful_call_returns_parsed_output_and_usage():
    ollama, seen = provider(lambda r: httpx.Response(200, json=chat_reply('{"relevant": true, "reason": "ok"}')))
    response = ollama.complete_json(REQUEST, Verdict)
    assert response.output == Verdict(relevant=True, reason="ok")
    usage = response.usage
    assert (usage.input_tokens, usage.output_tokens, usage.duration_ms) == (120, 30, 2500)
    assert usage.model == "ollama/qwen2.5:32b-instruct"
    body = json.loads(seen[0].content)
    assert str(seen[0].url) == "http://127.0.0.1:11434/api/chat"
    assert body["model"] == "qwen2.5:32b-instruct"
    assert body["stream"] is False and body["keep_alive"] == "10m"
    assert body["messages"] == [
        {"role": "system", "content": "be brief"}, {"role": "user", "content": "is it relevant?"},
    ]
    assert body["format"]["properties"].keys() == {"relevant", "reason"}


def test_missing_model_names_the_pull_command():
    ollama, _ = provider(lambda r: httpx.Response(404, json={"error": "model 'x' does not exist"}))
    with pytest.raises(LLMUnavailable, match="ollama pull qwen2.5:32b-instruct"):
        ollama.complete_json(REQUEST, Verdict)


def test_connection_error_names_ollama_serve():
    def refuse(request):
        raise httpx.ConnectError("refused")

    ollama, _ = provider(refuse)
    with pytest.raises(LLMUnavailable, match="ollama serve"):
        ollama.complete_json(REQUEST, Verdict)


def test_timeout_raises_llm_timeout():
    def slow(request):
        raise httpx.ReadTimeout("slow")

    ollama, _ = provider(slow)
    with pytest.raises(LLMTimeout):
        ollama.complete_json(REQUEST, Verdict)


@pytest.mark.parametrize("content", ["not json", '{"relevant": "maybe"}', '{"relevant": true}'])
def test_malformed_content_is_invalid_output(content):
    ollama, _ = provider(lambda r: httpx.Response(200, json=chat_reply(content)))
    with pytest.raises(InvalidOutput):
        ollama.complete_json(REQUEST, Verdict)


def test_server_error_body_is_truncated():
    ollama, _ = provider(lambda r: httpx.Response(500, text="x" * 2000))
    with pytest.raises(LLMUnavailable) as info:
        ollama.complete_json(REQUEST, Verdict)
    assert str(info.value).count("x") == 500
