"""Deterministic LLMProvider for tests: a handler maps each request to a response."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ValidationError

from cyllex_argus.llm.base import InvalidOutput, LLMRequest, LLMResponse, T

Handler = Callable[[LLMRequest], "dict | BaseModel | Exception"]


class FakeLLMProvider:
    def __init__(self, handler: Handler) -> None:
        self._handler = handler
        self.calls: list[LLMRequest] = []

    def complete_json(self, request: LLMRequest, schema: type[T]) -> LLMResponse[T]:
        self.calls.append(request)
        result = self._handler(request)
        if isinstance(result, Exception):
            raise result
        if isinstance(result, BaseModel):
            result = result.model_dump(mode="json")
        try:
            return LLMResponse(output=schema.model_validate(result), usage=None)
        except ValidationError as exc:
            raise InvalidOutput(str(exc)) from exc

    def calls_for(self, prompt_prefix: str) -> list[LLMRequest]:
        return [c for c in self.calls if c.prompt_version.startswith(prompt_prefix)]
