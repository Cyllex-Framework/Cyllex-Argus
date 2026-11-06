import httpx
import pytest

from cyllex_argus.config.settings import ArgusConfig, ConfigError, LLMConfig
from cyllex_argus.llm.anthropic_api import AnthropicApiProvider
from cyllex_argus.llm.claude_cli import ClaudeCodeCLIProvider
from cyllex_argus.llm.ollama import OllamaProvider
from cyllex_argus.llm.router import LLMRouter
from cyllex_argus.services import build_llm, build_search_llm, build_services


def llm_config(provider="claude-code-cli", search="claude-code-cli") -> LLMConfig:
    return ArgusConfig.model_validate({"llm": {"provider": provider, "search": {"provider": search}}}).llm


def test_ollama_provider_is_selected():
    router = build_llm(llm_config("ollama"))
    assert isinstance(router, LLMRouter)
    assert router.base_provider_name == "ollama"
    assert isinstance(router.base_provider(), OllamaProvider)


def test_claude_provider_is_shared_with_search():
    cfg = llm_config()
    llm = build_llm(cfg)
    assert isinstance(llm, LLMRouter)
    assert llm.base_provider_name == "claude-code-cli"
    assert isinstance(llm.base_provider(), ClaudeCodeCLIProvider)
    # When the base provider is Claude CLI, build_search_llm returns the SAME router so
    # `request.tools=["WebSearch"]` keeps routing through the right adapter.
    assert build_search_llm(cfg, llm) is llm


def test_hybrid_uses_a_dedicated_claude_search_provider():
    cfg = llm_config("ollama")
    llm = build_llm(cfg)
    search = build_search_llm(cfg, llm)
    assert isinstance(search, ClaudeCodeCLIProvider)


def test_anthropic_api_search_provider_is_wired():
    """search=anthropic-api gives the Collector the Anthropic web_search tool, whatever the
    content provider is (here Ollama runs the extraction, Anthropic API runs the search)."""
    cfg = llm_config("ollama", search="anthropic-api")
    search = build_search_llm(cfg, build_llm(cfg))
    assert isinstance(search, AnthropicApiProvider)


@pytest.mark.parametrize("search", ["disabled", "ollama"])
def test_disabled_search_is_none(search):
    cfg = llm_config("ollama", search)
    assert build_search_llm(cfg, build_llm(cfg)) is None


def test_unknown_provider_is_a_config_error():
    with pytest.raises(ConfigError):
        build_llm(llm_config("nope"))
    with pytest.raises(ConfigError):
        build_search_llm(llm_config(search="nope"), build_llm(llm_config()))


def test_catalog_is_cached_across_calls(tmp_path):
    """services.catalog() should reuse the parsed ATT&CK instance when the file has not changed."""
    import shutil

    from cyllex_argus.config.settings import get_paths
    from cyllex_argus.services import _CATALOG_CACHE
    from tests.conftest import FIXTURES

    paths = get_paths(tmp_path)
    paths.ensure()
    shutil.copy(FIXTURES / "attack_mini.json", paths.attack_file)
    _CATALOG_CACHE.pop(paths.attack_file, None)  # don't inherit from an earlier test

    from cyllex_argus.documents.fetch import Fetcher
    from cyllex_argus.knowledge.sqlite_store import SQLiteStore
    from cyllex_argus.llm.fake import FakeLLMProvider
    from cyllex_argus.services import Services
    http = httpx.Client()
    services = Services(
        paths=paths, config=ArgusConfig(feeds=[]), store=SQLiteStore(paths.db_file),
        llm=FakeLLMProvider(lambda r: {}), http=http,
        fetcher=Fetcher(http, max_bytes=100_000, sleep=lambda s: None),
    )
    try:
        first = services.catalog()
        second = services.catalog()
        assert first is second   # same cached object, no reparse
    finally:
        services.close() if hasattr(services, "close") else http.close()


def test_build_services_reads_the_config(tmp_path):
    (tmp_path / "argus.toml").write_text(
        '[llm]\nprovider = "ollama"\n[llm.search]\nprovider = "disabled"\n', encoding="utf-8")
    services = build_services(tmp_path)
    try:
        assert isinstance(services.llm, LLMRouter)
        assert services.llm.base_provider_name == "ollama"
        assert isinstance(services.llm.base_provider(), OllamaProvider)
        assert services.search_llm is None
    finally:
        services.close()


FEED = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Vendor</title>
<item><title>Scattered Spider deep dive</title><link>https://mandiant.example/spider</link>
<description>Scattered Spider tradecraft.</description></item></channel></rss>"""


def test_pipeline_without_search_llm_skips_web_search_and_uses_rss(tmp_path):
    from cyllex_argus.config.settings import FeedConfig
    from cyllex_argus.documents.fetch import Fetcher
    from cyllex_argus.knowledge.models import InvestigationState
    from tests.support import World, _public_resolver, web_transport

    pages = web_transport()

    def handler(request):
        if request.url.host == "feed.example":
            return httpx.Response(200, content=FEED, headers={"content-type": "application/rss+xml"})
        return pages.handler(request)

    world = World(tmp_path)
    world.config = ArgusConfig(feeds=[FeedConfig(name="Vendor", url="https://feed.example/rss")])
    services = world.services()
    services.http = httpx.Client(transport=httpx.MockTransport(handler))
    services.fetcher = Fetcher(
        services.http, max_bytes=100_000, sleep=lambda s: None, resolve_host=_public_resolver,
    )
    services.search_llm = None
    logs: list[str] = []
    services.log = logs.append
    try:
        report = services.pipeline().investigate("Scattered Spider")
    finally:
        services.close()
    assert world.llm.calls_for("web-search") == []
    assert any("Web search disabled by config" in line for line in logs)
    assert report.state == InvestigationState.FINISHED
    assert world.llm.analyst_calls == 1


def test_pipeline_routes_web_search_through_search_llm(tmp_path):
    from tests.support import ScriptedLLM, World

    world = World(tmp_path)
    search = ScriptedLLM()
    services = world.services()
    services.search_llm = search
    try:
        services.pipeline().investigate("Scattered Spider")
    finally:
        services.close()
    # One search per alias, all routed through the dedicated search_llm (not the content llm).
    assert len(search.calls_for("web-search")) >= 1
    assert world.llm.calls_for("web-search") == []
