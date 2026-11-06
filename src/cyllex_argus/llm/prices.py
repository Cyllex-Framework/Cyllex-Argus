"""Static LLM price table, used to estimate the cost of a pipeline run."""

from __future__ import annotations

import warnings

PRICES_USD_PER_MTOK: dict[str, dict[str, float]] = {
    # As of 2026-11-02 (Anthropic first-party API rates). Update when Anthropic changes pricing.
    "claude-opus-5-5":         {"input":  4.00, "output": 20.00},
    # 1M-context variant: Anthropic prices Opus 5.5 flat across its 1M window, so kept at parity.
    "claude-opus-5-5[1m]":     {"input":  4.00, "output": 20.00},
    # Prior Opus generations (5 / 4.8 / 4.7 / 4.6) all shared the $5 / $25 tier. Kept so a
    # per-agent override pinned to one of them — or a base model left at 4.7 — still shows a cost.
    "claude-opus-5":           {"input":  5.00, "output": 25.00},
    "claude-opus-4-8":         {"input":  5.00, "output": 25.00},
    "claude-opus-4-7":         {"input":  5.00, "output": 25.00},
    "claude-opus-4-6":         {"input":  5.00, "output": 25.00},
    "claude-fable-5-1":        {"input": 10.00, "output": 50.00},
    "claude-fable-5":          {"input": 10.00, "output": 50.00},
    "claude-sonnet-5-5":       {"input":  2.00, "output": 10.00},
    "claude-sonnet-5":         {"input":  2.00, "output": 10.00},
    "claude-sonnet-4-6":       {"input":  3.00, "output": 15.00},
    # Haiku 5.5 rates are for prompts up to 100K tokens; above that it is $0.50 / $2.50. Argus
    # keeps content well under 100K per request, so the <=100K tier is the right flat rate here.
    "claude-haiku-5-5":        {"input":  0.10, "output":  0.50},
    "claude-haiku-4-5":        {"input":  1.00, "output":  5.00},
    "claude-haiku-4-5-20251001": {"input": 1.00, "output":  5.00},
    # OpenAI pricing — update when it changes. These feed the trace cost column for the
    # BYO-key OpenAI provider; unknown model ids will emit a RuntimeWarning once.
    "gpt-4o":                  {"input":  2.50, "output": 10.00},
    "gpt-4o-mini":             {"input":  0.15, "output":  0.60},
    "gpt-4o-2024-11-20":       {"input":  2.50, "output": 10.00},
    "gpt-4.1":                 {"input":  2.00, "output":  8.00},
    "gpt-4.1-mini":            {"input":  0.40, "output":  1.60},
    "gpt-4-turbo":             {"input": 10.00, "output": 30.00},
    "gpt-5":                   {"input":  3.00, "output": 15.00},
    "gpt-5-mini":              {"input":  0.25, "output":  2.00},
    "o1":                      {"input": 15.00, "output": 60.00},
    "o1-mini":                 {"input":  3.00, "output": 12.00},
}

# Local models (Ollama) are free. OllamaProvider reports its model id as "ollama/<model>", so the prefix alone
# marks a call as zero-cost while the trace keeps aggregating tokens and duration.
LOCAL_MODEL_PREFIX = "ollama/"

# Anthropic bills the server-side web_search tool at $10 per 1000 searches, independent of
# tokens. Only the Anthropic API search path produces these; every other call has 0.
WEB_SEARCH_USD_PER_REQUEST = 0.01

_WARNED_UNKNOWN: set[str] = set()


def known_models_by_provider() -> dict[str, list[str]]:
    """Selectable model ids grouped by direct-API provider, derived from the price table.

    Feeds the Settings model picker so every suggested id is one this table can price — and
    therefore one the dashboard can show a cost for. Short CLI aliases such as ``opus`` are
    deliberately absent: they are valid for the ``claude-code-cli`` provider, which resolves the
    alias, but rejected by the direct Anthropic/OpenAI APIs, which require a full dated id. The
    list is a suggestion, not a whitelist — the operator may still type a newer id by hand.
    """
    anthropic: list[str] = []
    openai: list[str] = []
    for model in PRICES_USD_PER_MTOK:
        if "[" in model:  # context-window variants like "claude-opus-5-5[1m]" are not selectable ids
            continue
        (anthropic if model.startswith("claude-") else openai).append(model)
    return {"anthropic-api": anthropic, "openai-api": openai}


def cost_usd(model: str, input_tokens: int, output_tokens: int, web_search_requests: int = 0) -> float | None:
    """Cost in USD of one call, or None when the model is not in the price table.

    Token cost comes from the per-million table; `web_search_requests` (Anthropic's server-side
    web_search tool) is billed separately at $10 / 1000 and added on top.

    An unknown model emits a one-shot RuntimeWarning so operators notice that a cost column is
    silently empty — most often a new Claude model id that this table has not caught up with.
    """
    if model.startswith(LOCAL_MODEL_PREFIX):
        return 0.0
    price = PRICES_USD_PER_MTOK.get(model)
    if price is None:
        if model not in _WARNED_UNKNOWN:
            _WARNED_UNKNOWN.add(model)
            warnings.warn(
                f"no price configured for model {model!r}; add it to PRICES_USD_PER_MTOK "
                "or the dashboard cost column will stay empty",
                RuntimeWarning,
                stacklevel=2,
            )
        return None
    tokens = (input_tokens * price["input"] + output_tokens * price["output"]) / 1_000_000
    return tokens + web_search_requests * WEB_SEARCH_USD_PER_REQUEST
