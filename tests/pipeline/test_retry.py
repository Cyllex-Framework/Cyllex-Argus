"""complete_json_with_retries retries malformed output but must NOT retry a policy refusal:
a refusal will not go away on retry, so it propagates immediately for the pipeline to report."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from cyllex_argus.llm.base import InvalidOutput, LLMRefused, LLMRequest
from cyllex_argus.pipeline.retry import complete_json_with_retries


class _Out(BaseModel):
    ok: bool


class _CountingLLM:
    """Raises the same error on every call and counts how many times it was called."""

    def __init__(self, exc: Exception) -> None:
        self.calls = 0
        self._exc = exc

    def complete_json(self, request, schema):  # noqa: ANN001
        self.calls += 1
        raise self._exc


def _req() -> LLMRequest:
    return LLMRequest(system="s", content="c", prompt_version="v1")


def test_refusal_is_not_retried():
    llm = _CountingLLM(LLMRefused(category="cyber"))
    with pytest.raises(LLMRefused):
        complete_json_with_retries(llm, _req(), _Out, max_retries=3, sleep=lambda _s: None)
    assert llm.calls == 1, "a refusal must propagate immediately, not burn retries"


def test_invalid_output_is_retried():
    llm = _CountingLLM(InvalidOutput("bad json"))
    with pytest.raises(InvalidOutput):
        complete_json_with_retries(llm, _req(), _Out, max_retries=2, sleep=lambda _s: None)
    assert llm.calls == 3, "InvalidOutput should retry max_retries+1 times"
