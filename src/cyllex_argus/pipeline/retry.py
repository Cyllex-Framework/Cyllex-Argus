"""Shared retry helper for LLM JSON calls — used by the Analyst and the Triage.

On InvalidOutput the request is re-sent with an error-feedback appendix so the model can
correct itself. Between retries the helper sleeps with exponential backoff so a 429 burst
does not hammer the provider. LLMTimeout propagates immediately (retrying a timeout only
burns more quota), as do non-InvalidOutput LLM errors — those are not parse problems and
must bubble up to the pipeline.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import TypeVar

from pydantic import BaseModel

from cyllex_argus.llm.base import InvalidOutput, LLMProvider, LLMRequest, LLMResponse, LLMTimeout

T = TypeVar("T", bound=BaseModel)

DEFAULT_BACKOFF: tuple[float, ...] = (1.0, 3.0, 9.0)


def complete_json_with_retries[T: BaseModel](
    llm: LLMProvider,
    request: LLMRequest,
    schema: type[T],
    max_retries: int,
    sleep: Callable[[float], None] = time.sleep,
    backoff_seconds: Sequence[float] = DEFAULT_BACKOFF,
) -> LLMResponse[T]:
    last_error: InvalidOutput | None = None
    for attempt in range(max_retries + 1):
        if attempt:
            delay = backoff_seconds[min(attempt - 1, len(backoff_seconds) - 1)]
            sleep(delay)
        try:
            return llm.complete_json(request, schema)
        except LLMTimeout:
            raise
        except InvalidOutput as exc:
            last_error = exc
            # Pydantic validation errors can be hundreds of lines; appending them verbatim on
            # retry grows the content linearly across attempts (triage/analyst can retry 2-3
            # times). Cap at ~500 chars — enough for the LLM to see what went wrong, bounded
            # enough that retries don't balloon.
            hint = str(exc)
            if len(hint) > 500:
                hint = hint[:500].rstrip() + " ... (truncated)"
            request = request.model_copy(update={
                "content": (
                    f"{request.content}\n\nYour previous answer was invalid: {hint}. "
                    "Return output that matches the schema exactly."
                )
            })
    raise last_error or InvalidOutput("llm call failed after retries")
