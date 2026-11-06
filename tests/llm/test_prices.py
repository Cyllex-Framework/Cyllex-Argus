from cyllex_argus.llm.prices import PRICES_USD_PER_MTOK, cost_usd


def test_cost_is_computed_per_million_tokens():
    assert cost_usd("claude-opus-5-5", 1_000_000, 1_000_000) == 24.0
    assert cost_usd("claude-sonnet-5-5", 500_000, 100_000) == 2.0
    assert cost_usd("claude-haiku-5-5", 1_000_000, 1_000_000) == 0.60


def test_unknown_model_has_no_cost():
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert cost_usd("unknown", 1, 1) is None


def test_unknown_model_warns_once_per_model():
    """Operators must be told the cost column is empty because the model is not priced yet."""
    import warnings

    from cyllex_argus.llm import prices as prices_mod
    # Reset the dedup set so the test is deterministic even after other tests ran.
    prices_mod._WARNED_UNKNOWN.discard("brand-new-model")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cost_usd("brand-new-model", 1, 1)
        cost_usd("brand-new-model", 1, 1)  # second call must not re-warn
    messages = [str(w.message) for w in caught if "brand-new-model" in str(w.message)]
    assert len(messages) == 1
    assert "no price configured" in messages[0]


def test_price_table_is_locked():
    assert PRICES_USD_PER_MTOK == {
        "claude-opus-5-5": {"input": 4.00, "output": 20.00},
        "claude-opus-5-5[1m]": {"input": 4.00, "output": 20.00},
        "claude-opus-5": {"input": 5.00, "output": 25.00},
        "claude-opus-4-8": {"input": 5.00, "output": 25.00},
        "claude-opus-4-7": {"input": 5.00, "output": 25.00},
        "claude-opus-4-6": {"input": 5.00, "output": 25.00},
        "claude-fable-5-1": {"input": 10.00, "output": 50.00},
        "claude-fable-5": {"input": 10.00, "output": 50.00},
        "claude-sonnet-5-5": {"input": 2.00, "output": 10.00},
        "claude-sonnet-5": {"input": 2.00, "output": 10.00},
        "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
        "claude-haiku-5-5": {"input": 0.10, "output": 0.50},
        "claude-haiku-4-5": {"input": 1.00, "output": 5.00},
        "claude-haiku-4-5-20251001": {"input": 1.00, "output": 5.00},
        # OpenAI entries feed the trace cost column for the BYO-key OpenAI provider.
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "gpt-4o-2024-11-20": {"input": 2.50, "output": 10.00},
        "gpt-4.1": {"input": 2.00, "output": 8.00},
        "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
        "gpt-4-turbo": {"input": 10.00, "output": 30.00},
        "gpt-5": {"input": 3.00, "output": 15.00},
        "gpt-5-mini": {"input": 0.25, "output": 2.00},
        "o1": {"input": 15.00, "output": 60.00},
        "o1-mini": {"input": 3.00, "output": 12.00},
    }


def test_local_models_are_free():
    assert cost_usd("ollama/qwen2.5:32b-instruct", 1_000_000, 1_000_000) == 0.0


def test_current_anthropic_models_are_priced():
    """Models that were emitting the 'no price configured' warning are now in the table."""
    assert cost_usd("claude-opus-4-7", 1_000_000, 0) == 5.0
    assert cost_usd("claude-sonnet-4-6", 0, 1_000_000) == 15.0


def test_cost_includes_web_search_requests():
    """Anthropic bills server-side web searches at $10 / 1000, on top of the token cost."""
    assert cost_usd("claude-sonnet-5-5", 0, 0, web_search_requests=3) == 0.03
    # Combined with tokens: 24.0 (opus 5.5 at 1M in/out) + 0.02 (two searches).
    assert cost_usd("claude-opus-5-5", 1_000_000, 1_000_000, web_search_requests=2) == 24.02
