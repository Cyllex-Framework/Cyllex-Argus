"""Tests for the per-agent LLMRouter.

Covers the dispatch contract: a tagged request lands on the agent-specific provider when the
config declares one, falls back to the base provider when it doesn't, and surfaces an
actionable error when an agent targets a provider that has no credentials.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from cyllex_argus.config.settings import (
    AgentModelConfig,
    AnthropicApiConfig,
    LLMConfig,
    OpenAIApiConfig,
    PerAgentModelsConfig,
)
from cyllex_argus.llm.base import (
    LLMRequest,
    LLMResponse,
    LLMUnavailable,
    LLMUsage,
)
from cyllex_argus.llm.router import LLMRouter, resolve_model_for_request


class Dummy(BaseModel):
    ok: bool = True


def _usage(model: str) -> LLMUsage:
    return LLMUsage(input_tokens=1, output_tokens=1, model=model, duration_ms=0)


class FakeProvider:
    """Captures every call and lets a test assert which provider was picked."""
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[LLMRequest] = []

    def complete_json(self, request: LLMRequest, schema):  # noqa: ANN001
        self.calls.append(request)
        return LLMResponse(output=schema(), usage=_usage(f"{self.name}/model"))


class FailingProvider:
    """Simulates a provider whose credentials are missing — the usual way to end up here is to
    point an agent at anthropic-api without `ANTHROPIC_API_KEY` set."""
    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self.reason = reason

    def complete_json(self, request: LLMRequest, schema):  # noqa: ANN001
        raise LLMUnavailable(self.reason)


def _factories(**instances) -> dict:
    """Build a factories dict for LLMRouter — each entry is a nullary callable that returns
    the pre-built instance (so the router's lazy-init path still runs)."""
    def factory(instance):
        # A named function, not a lambda closing over the comprehension variable: the latter
        # works only because of a default-argument trick, and reads like a bug either way.
        return lambda _cfg: instance
    return {name: factory(instance) for name, instance in instances.items()}


def _cfg(provider: str = "claude-code-cli", agents: PerAgentModelsConfig | None = None,
         model: str | None = None) -> LLMConfig:
    return LLMConfig(
        provider=provider,
        model=model,
        agents=agents or PerAgentModelsConfig(),
        anthropic=AnthropicApiConfig(api_key="sk-fake"),
        openai=OpenAIApiConfig(api_key="sk-fake"),
    )


def test_untagged_request_goes_to_the_base_provider():
    """A legacy LLMRequest with no `agent` field lands on the base provider, as before the router."""
    base = FakeProvider("claude-code-cli")
    other = FakeProvider("openai-api")
    router = LLMRouter(_cfg(), factories=_factories(**{"claude-code-cli": base, "openai-api": other}))
    router.complete_json(LLMRequest(system="s", content="c", prompt_version="v"), Dummy)
    assert len(base.calls) == 1
    assert len(other.calls) == 0


def test_tagged_request_without_override_still_goes_to_base():
    """Having an `agent` field alone does not route anywhere special — the operator must have
    set a provider override for the dispatch to differ from the base."""
    base = FakeProvider("claude-code-cli")
    openai = FakeProvider("openai-api")
    router = LLMRouter(_cfg(), factories=_factories(**{"claude-code-cli": base, "openai-api": openai}))
    router.complete_json(LLMRequest(system="s", content="c", prompt_version="v", agent="triage"), Dummy)
    assert len(base.calls) == 1
    assert len(openai.calls) == 0


def test_tagged_request_with_provider_override_lands_on_the_override():
    """The sweet spot: Triage runs on openai-api (cheap/fast) while the rest keeps whatever the
    base provider is. Analyst-tagged request still goes to base because its override is empty."""
    base = FakeProvider("anthropic-api")
    openai = FakeProvider("openai-api")
    cfg = _cfg(provider="anthropic-api", agents=PerAgentModelsConfig(
        triage=AgentModelConfig(provider="openai-api", model="gpt-4o-mini"),
    ))
    router = LLMRouter(cfg, factories=_factories(**{"anthropic-api": base, "openai-api": openai}))
    router.complete_json(LLMRequest(system="s", content="c", prompt_version="v", agent="triage"), Dummy)
    router.complete_json(LLMRequest(system="s", content="c", prompt_version="v", agent="analyst"), Dummy)
    assert [c.agent for c in openai.calls] == ["triage"]
    assert [c.agent for c in base.calls] == ["analyst"]


def test_unknown_agent_override_falls_through_to_base():
    """A request with an agent name the config does not declare (e.g. a brand-new call site
    added before the config schema catches up) still lands somewhere — on the base provider."""
    base = FakeProvider("claude-code-cli")
    router = LLMRouter(_cfg(), factories=_factories(**{"claude-code-cli": base}))
    router.complete_json(LLMRequest(system="s", content="c", prompt_version="v", agent="not_in_schema"), Dummy)
    assert len(base.calls) == 1


def test_provider_override_pointing_at_unknown_provider_is_llm_unavailable():
    """A toml typo like `provider = "anthropic"` (missing the `-api`) must surface as
    a readable LLMUnavailable at dispatch time — the alternative is a silent cast to base."""
    cfg = _cfg(provider="claude-code-cli", agents=PerAgentModelsConfig(
        triage=AgentModelConfig(provider="anthropic", model="claude-sonnet-5-5"),  # missing the -api
    ))
    router = LLMRouter(cfg, factories=_factories(**{"claude-code-cli": FakeProvider("x")}))
    with pytest.raises(LLMUnavailable, match="unknown provider 'anthropic'"):
        router.complete_json(LLMRequest(system="s", content="c", prompt_version="v", agent="triage"), Dummy)


def test_missing_credentials_on_override_names_the_agent_in_the_error():
    """The provider itself raises LLMUnavailable when the API key is empty. The router rewrites
    the message so the operator knows WHICH agent surfaced the failure — otherwise they see
    "OpenAI API key not configured" and start debugging Analyst while Triage is the actual culprit."""
    cfg = _cfg(provider="claude-code-cli", agents=PerAgentModelsConfig(
        triage=AgentModelConfig(provider="openai-api"),
    ))
    router = LLMRouter(cfg, factories=_factories(**{
        "claude-code-cli": FakeProvider("x"),
        "openai-api": FailingProvider("openai-api", "OpenAI API key is not configured."),
    }))
    with pytest.raises(LLMUnavailable, match="Agent 'triage'.*OpenAI API key"):
        router.complete_json(LLMRequest(system="s", content="c", prompt_version="v", agent="triage"), Dummy)


def test_router_rejects_unknown_base_provider_at_construction():
    """A `cfg.provider = "garbage"` must fail fast — the router cannot pick a default dispatch
    target. Guarantees the error surfaces at serve startup, not on the first request."""
    with pytest.raises(ValueError, match="Unknown base provider"):
        LLMRouter(LLMConfig(provider="garbage"))


def test_router_instantiates_providers_lazily():
    """A config that never names openai-api must not spin up its adapter. Keeps 'I only use
    Claude' installations from loading the OpenAI client code at all."""
    calls_to_openai_factory = []

    def openai_factory(_cfg):
        calls_to_openai_factory.append(1)
        return FakeProvider("openai-api")

    router = LLMRouter(_cfg(), factories={
        "claude-code-cli": lambda _cfg: FakeProvider("claude"),
        "openai-api": openai_factory,
        "anthropic-api": lambda _cfg: FakeProvider("anthropic"),
        "ollama": lambda _cfg: FakeProvider("ollama"),
    })
    router.complete_json(LLMRequest(system="s", content="c", prompt_version="v"), Dummy)
    assert calls_to_openai_factory == []  # OpenAI factory never called


# --- resolve_model_for_request -------------------------------------------------------------


def test_resolve_model_prefers_the_agent_override():
    cfg = _cfg(model="opus", agents=PerAgentModelsConfig(
        triage=AgentModelConfig(model="haiku"),
    ))
    model = resolve_model_for_request(
        cfg, LLMRequest(system="s", content="c", prompt_version="v", agent="triage"),
        provider_default="sonnet",
    )
    assert model == "haiku"


def test_resolve_model_falls_back_to_base_model():
    cfg = _cfg(model="opus")
    model = resolve_model_for_request(
        cfg, LLMRequest(system="s", content="c", prompt_version="v", agent="triage"),
        provider_default="sonnet",
    )
    assert model == "opus"


def test_resolve_model_falls_back_to_provider_default_when_nothing_is_set():
    cfg = _cfg(model=None)
    model = resolve_model_for_request(
        cfg, LLMRequest(system="s", content="c", prompt_version="v", agent="triage"),
        provider_default="sonnet",
    )
    assert model == "sonnet"


def test_resolve_model_ignores_an_agent_name_not_in_the_schema():
    cfg = _cfg(model="opus")
    model = resolve_model_for_request(
        cfg, LLMRequest(system="s", content="c", prompt_version="v", agent="unknown_agent"),
        provider_default="sonnet",
    )
    assert model == "opus"  # untouched: unknown agents go straight to base
