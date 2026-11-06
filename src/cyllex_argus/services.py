"""Wires configuration, storage, LLM, HTTP and pipeline together. The CLI builds one per command."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from cyllex_argus.attack.catalog import AttackCatalog, catalog_loaded
from cyllex_argus.config.settings import ArgusConfig, ConfigError, LLMConfig, Paths, get_paths, load_config
from cyllex_argus.documents.fetch import Fetcher, build_client, curl_cffi_impersonate_fetch
from cyllex_argus.enrichment import EnrichmentRunner, available_enrichers
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.knowledge.trace import SQLiteTraceRecorder
from cyllex_argus.llm.anthropic_api import AnthropicApiProvider
from cyllex_argus.llm.base import LLMProvider
from cyllex_argus.llm.claude_cli import ClaudeCodeCLIProvider
from cyllex_argus.llm.router import KNOWN_PROVIDERS, LLMRouter
from cyllex_argus.notify.webhook import WebhookDispatcher
from cyllex_argus.pipeline.investigation import Pipeline
from cyllex_argus.pipeline.validator import Validator
from cyllex_argus.sources.base import SourceConnector
from cyllex_argus.sources.misp import MispConnector
from cyllex_argus.sources.rss import RssConnector
from cyllex_argus.sources.taxii import TaxiiConnector
from cyllex_argus.sources.web_search import WebSearchConnector

_CATALOG_CACHE: dict[Path, tuple[int, int, AttackCatalog]] = {}  # path -> (mtime_ns, size, catalog)


class MissingAttackData(Exception):
    """ATT&CK reference data has not been downloaded yet, or cannot be read."""


_SAME_AS_LLM: Any = object()  # search_llm default: the content provider also runs the web search


def build_llm(cfg: LLMConfig) -> LLMProvider:
    """The provider for every call that sees document content (Triage, Analyst, summary, TTPs,
    STIX import). Returns an `LLMRouter` that dispatches per-agent based on `cfg.agents.*`
    and falls back to `cfg.provider` for anything without an override. The router implements
    the same `LLMProvider` protocol as a single adapter, so callers do not need to change."""
    if cfg.provider not in KNOWN_PROVIDERS:
        raise ConfigError(
            f"Unknown [llm] provider '{cfg.provider}' "
            f"(expected one of: {', '.join(sorted(KNOWN_PROVIDERS))})."
        )
    return LLMRouter(cfg)


SEARCH_TIMEOUT_SECONDS = 180  # a web search should never block the run (or Stop) for the full
# content timeout; a stalled one fails fast and the per-alias loop moves on.


def _search_cfg(cfg: LLMConfig) -> LLMConfig:
    """The config a search provider runs under: the base config with a shorter timeout."""
    return cfg.model_copy(update={"timeout_seconds": min(cfg.timeout_seconds, SEARCH_TIMEOUT_SECONDS)})


def build_search_llm(cfg: LLMConfig, content_llm: LLMProvider) -> LLMProvider | None:
    """The provider for the Collector's web search, or None when web search is disabled.

    Two providers expose a web-search tool: Claude Code CLI (its agentic WebSearch tool) and the
    Anthropic API (its server-side web_search tool). Ollama and the OpenAI-compatible provider
    have no search wired in and map to "disabled" here, as does "disabled" itself. The search
    provider is independent of the content provider, so e.g. Ollama can run the extraction while
    the Anthropic API runs the discovery.
    """
    provider = cfg.search.provider
    if provider in ("disabled", "ollama", "openai-api"):
        return None
    if provider == "anthropic-api":
        # A dedicated adapter (not the content router) keeps the search request —
        # agent="web_search", tools=["WebSearch"] — on the Anthropic provider whatever the content
        # provider is; the adapter adds the server-side web_search tool for that request.
        return AnthropicApiProvider(_search_cfg(cfg))
    if provider == "claude-code-cli":
        # The router routes agent="" / agent="web_search" to the base provider by default. If
        # the base is Claude CLI, we hand it back as the search provider; otherwise we build
        # a dedicated Claude CLI adapter so WebSearch has somewhere to run.
        if isinstance(content_llm, LLMRouter) and content_llm.base_provider_name == "claude-code-cli":
            return content_llm
        return ClaudeCodeCLIProvider(_search_cfg(cfg))
    raise ConfigError(
        f"Unknown [llm.search] provider '{provider}' "
        "(expected 'claude-code-cli', 'anthropic-api' or 'disabled')."
    )


@dataclass
class Services:
    paths: Paths
    config: ArgusConfig
    store: SQLiteStore
    llm: LLMProvider
    http: httpx.Client
    fetcher: Fetcher
    log: Callable[[str], None] = field(default=lambda message: None)
    search_llm: LLMProvider | None = _SAME_AS_LLM  # None: web search disabled

    def __post_init__(self) -> None:
        if self.search_llm is _SAME_AS_LLM:
            self.search_llm = self.llm

    def catalog(self) -> AttackCatalog:
        """Load the ATT&CK catalog, reusing the parsed instance between calls when the file has not
        changed on disk. Earlier revisions re-parsed on every call, which showed up as per-request
        latency on the web API (Validator and Pipeline construction both touch it)."""
        path = self.paths.attack_file
        try:
            stat = path.stat()
        except OSError as exc:
            raise MissingAttackData(str(path)) from exc
        cached = _CATALOG_CACHE.get(path)
        if cached is not None and cached[:2] == (stat.st_mtime_ns, stat.st_size):
            return cached[2]
        try:
            catalog = AttackCatalog.from_file(path)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise MissingAttackData(f"unreadable ATT&CK data: {exc}") from exc
        _CATALOG_CACHE[path] = (stat.st_mtime_ns, stat.st_size, catalog)
        return catalog

    def attack_ready(self) -> bool:
        """True when the pipeline can map what it reads to MITRE ATT&CK.

        Both halves, because they fail independently: the reference file has to be on disk AND
        its catalog has to be loaded into this store. `argus attack update` does both; wiping the
        database undoes only the second, and gating on the file alone let a run proceed against
        an empty catalog — which does not fail, it quietly produces fractured entities.
        """
        if not self.paths.attack_file.exists():
            return False
        return catalog_loaded(self.store.connection)

    def attack_catalog(self) -> AttackCatalog | None:
        """The catalog when the ATT&CK file is present and readable, else None. Parsed once per file version."""
        try:
            return self.catalog()
        except MissingAttackData:
            return None

    def validator(self) -> Validator:
        return Validator(
            self.store, self.catalog(), self.config.scoring,
            enrichment_factory=self.enrichment_runner,
        )

    def trace_recorder(self) -> SQLiteTraceRecorder:
        return SQLiteTraceRecorder(
            self.store.connection, retain_raw=self.config.logging.retain_raw_llm,
        )

    def enrichment_runner(
        self, investigation_id: int | None = None, enrichers: dict | None = None,
    ) -> EnrichmentRunner:
        """Build an EnrichmentRunner gated by `config.enrichment`. All enrichers are disabled by
        default; a call to a disabled one raises EnrichmentDisabledError and never touches the
        network. Pass `enrichers` to inject fakes in tests.

        Reads the enrichment section from argus.toml on disk when the file exists, so a toggle
        made through the HTTP API or by editing the file by hand takes effect immediately.
        """
        enrichment_config = self.config.enrichment
        if self.paths.config_file.exists():
            try:
                enrichment_config = load_config(self.paths.config_file).enrichment
            except ConfigError:
                pass  # keep the in-memory config; a broken file does not disable enrichment silently
        # Pull the per-enricher stored API key (if any) so key-gated enrichers (VirusTotal)
        # can be instantiated against the toml-stored key when the env var is not set.
        vt_cfg = enrichment_config.enrichers.get("virustotal")
        vt_api_key = vt_cfg.api_key if vt_cfg is not None else ""
        vt_env_api_key = vt_cfg.env_api_key if vt_cfg is not None else ""
        return EnrichmentRunner(
            config=enrichment_config,
            enrichers=enrichers if enrichers is not None else available_enrichers(vt_api_key, vt_env_api_key),
            trace=self.trace_recorder() if investigation_id is not None else None,
            investigation_id=investigation_id,
            log=self.log,
        )

    def pipeline(self) -> Pipeline:
        connectors: list[SourceConnector] = []
        if self.search_llm is not None:
            connectors.append(WebSearchConnector(self.search_llm, max_results=self.config.llm.search.max_results))
        else:
            self.log("Web search disabled by config; using RSS and ingested documents only.")
        connectors.append(RssConnector(self.config.feeds, self.fetcher, log=self.log))
        # External TAXII 2.1 servers. Each one is a disabled-by-default extra Collector source
        # that pulls STIX `report` objects whose name/description mentions the target. A server
        # that fails (auth, unreachable, bad collection) logs and skips without aborting the
        # whole collect pass.
        for taxii_cfg in self.config.taxii:
            if taxii_cfg.enabled:
                connectors.append(TaxiiConnector(taxii_cfg, self.http, log=self.log))
        # External MISP servers. Each one pulls Events whose `info` mentions the target and
        # emits every link-shaped Attribute (type in link/url/uri) as a candidate. Failures
        # degrade gracefully — the rest of the Collector line-up keeps running.
        for misp_cfg in self.config.misp:
            if misp_cfg.enabled:
                connectors.append(MispConnector(misp_cfg, self.http, log=self.log))
        return Pipeline(
            self.store, self.config, self.paths, self.llm, self.fetcher, connectors,
            self.catalog(), trace=self.trace_recorder(), log=self.log,
            enrichment_factory=self.enrichment_runner,
            webhook_dispatcher=self.webhook_dispatcher(),
        )

    def webhook_dispatcher(self) -> WebhookDispatcher | None:
        """Build a WebhookDispatcher gated by `config.webhooks`. Returns None when no
        webhook is configured — the pipeline then skips the whole terminal-transition
        notification path."""
        if not self.config.webhooks:
            return None
        return WebhookDispatcher(self.config.webhooks, client=self.http, log=self.log)

    def close(self) -> None:
        self.http.close()
        self.store.close()


def build_services(home: Path | None = None) -> Services:
    paths = get_paths(home)
    paths.ensure()
    config = load_config(paths.config_file)
    http = build_client(config.limits.download_timeout_seconds)
    llm = build_llm(config.llm)
    return Services(
        paths=paths,
        config=config,
        store=SQLiteStore(paths.db_file),
        llm=llm,
        search_llm=build_search_llm(config.llm, llm),
        http=http,
        fetcher=Fetcher(
            http, config.limits.max_download_bytes,
            tls_impersonator=curl_cffi_impersonate_fetch,
        ),
    )
