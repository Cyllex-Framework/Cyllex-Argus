import pytest
from pydantic import BaseModel

from cyllex_argus.llm.base import InvalidOutput, LLMRequest, RateLimited
from cyllex_argus.llm.fake import FakeLLMProvider


class Out(BaseModel):
    value: int


def test_fake_validates_and_records():
    fake = FakeLLMProvider(lambda req: {"value": len(req.content)})
    out = fake.complete_json(LLMRequest(system="s", content="abc", prompt_version="x-v1"), Out)
    assert out.output.value == 3
    assert out.usage is None
    assert [c.prompt_version for c in fake.calls_for("x-")] == ["x-v1"]


def test_fake_raises_exceptions():
    fake = FakeLLMProvider(lambda req: RateLimited("limit"))
    with pytest.raises(RateLimited):
        fake.complete_json(LLMRequest(system="s", content="c", prompt_version="x-v1"), Out)


def test_fake_wraps_validation_error():
    fake = FakeLLMProvider(lambda req: {"value": "not an int"})
    with pytest.raises(InvalidOutput):
        fake.complete_json(LLMRequest(system="s", content="c", prompt_version="x-v1"), Out)
