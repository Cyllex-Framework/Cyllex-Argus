from pydantic import BaseModel

from cyllex_argus.llm.base import LLMResponse, LLMUsage


class Foo(BaseModel):
    value: int


def test_response_carries_output_and_optional_usage():
    response = LLMResponse[Foo](output=Foo(value=1), usage=None)
    assert response.output == Foo(value=1)
    assert response.usage is None


def test_response_carries_usage():
    usage = LLMUsage(input_tokens=1, output_tokens=2, model="m", duration_ms=3)
    assert LLMResponse[Foo](output=Foo(value=1), usage=usage).usage == usage
