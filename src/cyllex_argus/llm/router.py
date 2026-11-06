"""Per-agent LLM router.

Argus runs five LLM-backed agents — Triage, Analyst, Summary, TTPs, STIX import. Each one
earns a different cost/quality trade-off: Triage is a yes/no decision that a cheap model
answers well, Analyst does citation-exact extraction and wants the good model. Rather than
force a single provider+model on every call, the router reads `cfg.agents.<name>` and dispatches
to the right provider; empty override means "use the base `[llm]` provider verbatim".

The router owns at most one instance per provider kind (claude-code-cli / ollama /
anthropic-api / openai-api) and lazily instantiates them on first use — if an operator's config
never touches OpenAI, the OpenAI adapter never loads. Each call's model is resolved per-request
by looking up the agent override, falling back to the base `cfg.model`, and finally to the
provider's own default.

Dispatch failures that an operator can act on (a missing API key for the provider that an agent
targets) raise `LLMUnavailable` with a message naming the agent and the fix.
"""

from __future__ import annotations

from collections.abc import Callable

from cyllex_argus.config.settings import AgentModelConfig, LLMConfig
from cyllex_argus.llm.anthropic_api import AnthropicApiProvider
from cyllex_argus.llm.base import LLMProvider, LLMRequest, LLMResponse, LLMUnavailable, T
from cyllex_argus.llm.claude_cli import ClaudeCodeCLIProvider
from cyllex_argus.llm.ollama import OllamaProvider
from cyllex_argus.llm.openai_api import OpenAIApiProvider

ProviderName = str  # "claude-code-cli" | "ollama" | "anthropic-api" | "openai-api"
KNOWN_PROVIDERS: frozenset[ProviderName] = frozenset(
    {"claude-code-cli", "ollama", "anthropic-api", "openai-api"}
)

ProviderFactory = Callable[[LLMConfig], LLMProvider]
_DEFAULT_FACTORIES: dict[ProviderName, ProviderFactory] = {
    "claude-code-cli": ClaudeCodeCLIProvider,
    "ollama": OllamaProvider,
    "anthropic-api": AnthropicApiProvider,
    "openai-api": OpenAIApiProvider,
}


def resolve_model_for_request(cfg: LLMConfig, request: LLMRequest, provider_default: str) -> str:
    """The model string the provider should send on this call.

    Precedence: agent override (if set) → base `cfg.model` → provider's own default. The
    adapters call this (or implement the same precedence inline) to pick the model id without
    needing to know about per-agent overrides themselves.
    """
    override = _agent_override(cfg, request.agent)
    if override and override.model.strip():
        return override.model.strip()
    if cfg.model and cfg.model.strip():
        return cfg.model.strip()
    return provider_default


def _agent_override(cfg: LLMConfig, agent: str) -> AgentModelConfig | None:
    """The override block for `agent` if the agent name is one of the configured slots; None
    otherwise. Unknown or empty agent names cleanly fall through to the base provider."""
    if not agent:
        return None
    return getattr(cfg.agents, agent, None)


class LLMRouter:
    """Routes each request to the provider configured for its agent.

    - `base_provider` is the `cfg.provider` string ("claude-code-cli" by default) — all requests
      without an agent override go there.
    - Provider instances are lazy: a config that never names "openai-api" never instantiates
      the OpenAI adapter. Instantiation lives behind `factories` so tests can inject fakes.
    - The router also exposes `is_base_provider_claude_cli` so `build_search_llm` can tell
      "same instance" vs "spin up a new Claude CLI just for web search".
    """

    def __init__(
        self,
        cfg: LLMConfig,
        *,
        factories: dict[ProviderName, ProviderFactory] | None = None,
    ) -> None:
        self._cfg = cfg
        self._factories = factories or _DEFAULT_FACTORIES
        self._instances: dict[ProviderName, LLMProvider] = {}
        if cfg.provider not in KNOWN_PROVIDERS:
            raise ValueError(
                f"Unknown base provider '{cfg.provider}' (expected one of {sorted(KNOWN_PROVIDERS)})."
            )

    def complete_json(self, request: LLMRequest, schema: type[T]) -> LLMResponse[T]:
        provider_name = self._provider_for(request)
        provider = self._get_or_build(provider_name)
        try:
            return provider.complete_json(request, schema)
        except LLMUnavailable as exc:
            # Rewrite the message so the operator can see which agent surfaced the failure.
            # Base-provider calls (agent="" or no override) keep the original wording; a per-
            # agent dispatch gets a prefix naming the agent, which is the actionable context.
            override = _agent_override(self._cfg, request.agent)
            if override and override.provider.strip():
                raise LLMUnavailable(
                    f"Agent '{request.agent}' is configured for provider '{provider_name}' "
                    f"but it is not available: {exc}"
                ) from exc
            raise

    def _provider_for(self, request: LLMRequest) -> ProviderName:
        override = _agent_override(self._cfg, request.agent)
        if override and override.provider.strip():
            name = override.provider.strip()
            if name not in KNOWN_PROVIDERS:
                raise LLMUnavailable(
                    f"Agent '{request.agent}' points at unknown provider '{name}' "
                    f"(expected one of {sorted(KNOWN_PROVIDERS)})."
                )
            return name
        return self._cfg.provider

    def _get_or_build(self, name: ProviderName) -> LLMProvider:
        instance = self._instances.get(name)
        if instance is None:
            factory = self._factories.get(name)
            if factory is None:
                raise LLMUnavailable(f"No factory registered for provider '{name}'.")
            instance = factory(self._cfg)
            self._instances[name] = instance
        return instance

    @property
    def base_provider_name(self) -> ProviderName:
        return self._cfg.provider

    def base_provider(self) -> LLMProvider:
        """The provider instance that serves un-tagged / un-overridden requests. `build_search_llm`
        uses this to decide whether a Claude-CLI search provider can share state with the content
        provider, or needs a fresh instance."""
        return self._get_or_build(self._cfg.provider)
