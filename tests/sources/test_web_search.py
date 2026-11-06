from datetime import date

from cyllex_argus.llm.base import InvalidOutput
from cyllex_argus.llm.fake import FakeLLMProvider
from cyllex_argus.sources.base import ResolvedTarget
from cyllex_argus.sources.web_search import WEB_SEARCH_PROMPT_VERSION, WebSearchConnector

TARGET = ResolvedTarget(
    name="Scattered Spider", entity_id=None, aliases=["Scattered Spider", "UNC3944"],
    search_aliases=["Scattered Spider", "UNC3944"],
)


def test_web_search_uses_only_the_search_tool_and_cleans_results():
    fake = FakeLLMProvider(lambda req: {"results": [
        {"url": "https://vendor.example/a?utm_source=x", "title": "A", "publisher": "Vendor", "published_at": "2024-05"},
        {"url": "https://vendor.example/a", "title": "A again", "publisher": "Vendor"},
        {"url": "ftp://files.example/a.pdf", "title": "FTP", "publisher": "X"},
        {"url": "https://www.cisa.gov/aa23-320a", "title": "Advisory", "publisher": ""},
    ]})
    results = WebSearchConnector(fake).search(TARGET)
    assert [r.url for r in results] == ["https://vendor.example/a?utm_source=x", "https://www.cisa.gov/aa23-320a"]
    assert results[0].published_at == date(2024, 5, 1)
    assert results[1].publisher == "cisa.gov"
    assert len(fake.calls) == 2  # one search per alias (Scattered Spider, UNC3944)
    assert all(c.tools == ["WebSearch"] for c in fake.calls)
    assert all(c.prompt_version == WEB_SEARCH_PROMPT_VERSION for c in fake.calls)
    assert all("UNC3944" in c.content for c in fake.calls)


def test_web_search_respects_max_results():
    fake = FakeLLMProvider(lambda req: {"results": [
        {"url": f"https://vendor.example/{i}", "title": str(i), "publisher": "Vendor"} for i in range(5)
    ]})
    assert len(WebSearchConnector(fake, max_results=2).search(TARGET)) == 2


def test_web_search_skips_malformed_urls():
    fake = FakeLLMProvider(lambda req: {"results": [
        {"url": "https://vendor.example/good1", "title": "Good 1", "publisher": "Vendor"},
        {"url": "https://host:abc/x", "title": "Bad Port", "publisher": "Vendor"},
        {"url": "http://[bad/x", "title": "Bad IPv6", "publisher": "Vendor"},
        {"url": "https://vendor.example/good2", "title": "Good 2", "publisher": "Vendor"},
    ]})
    results = WebSearchConnector(fake).search(TARGET)
    assert [r.url for r in results] == ["https://vendor.example/good1", "https://vendor.example/good2"]


def test_web_search_sends_only_search_aliases():
    fake = FakeLLMProvider(lambda req: {"results": []})
    target = ResolvedTarget(
        name="Scattered Spider", entity_id="intrusion-set--1",
        aliases=["PROJECT-FALCON-7", "Scattered Spider", "UNC3944"],
        search_aliases=["Scattered Spider", "UNC3944"],
    )
    WebSearchConnector(fake).search(target)
    assert len(fake.calls) == 2
    for call in fake.calls:
        assert "UNC3944" in call.content
        assert "PROJECT-FALCON-7" not in call.content


def test_web_search_falls_back_to_the_target_name():
    fake = FakeLLMProvider(lambda req: {"results": []})
    target = ResolvedTarget(name="New Actor", aliases=["New Actor", "Internal Codename"])
    WebSearchConnector(fake).search(target)
    [call] = fake.calls
    assert "Known aliases: New Actor\n" in call.content
    assert "Internal Codename" not in call.content


def test_web_search_per_run_limit_governs_without_override():
    """With no config override, the per-run limit (the investigation's max_docs) sets the fan-out."""
    fake = FakeLLMProvider(lambda req: {"results": [
        {"url": f"https://vendor.example/{i}", "title": str(i), "publisher": "Vendor"} for i in range(50)
    ]})
    results = WebSearchConnector(fake).search(TARGET, limit=40)
    assert len(results) == 40
    # TARGET has 2 aliases; each asks for a share of the 40-doc budget (ceil(40/2) = 20), in parallel.
    assert len(fake.calls) == 2
    assert all("Find up to 20 primary sources" in c.content for c in fake.calls)


def test_web_search_config_override_beats_per_run_limit():
    """An explicit [llm.search] max_results pins the fan-out regardless of the run's max_docs."""
    fake = FakeLLMProvider(lambda req: {"results": [
        {"url": f"https://vendor.example/{i}", "title": str(i), "publisher": "Vendor"} for i in range(50)
    ]})
    results = WebSearchConnector(fake, max_results=3).search(TARGET, limit=40)
    assert len(results) == 3
    # the override pins the total to 3; with only 2 aliases each still asks for the whole 3
    # (per-alias ask is capped at the total budget), and the union is de-duped and trimmed to 3.
    assert len(fake.calls) == 2
    assert all("Find up to 3 primary sources" in c.content for c in fake.calls)


def test_web_search_defaults_to_fifteen_without_override_or_limit():
    """Direct construction with neither an override nor a per-run limit keeps the old default of 15."""
    fake = FakeLLMProvider(lambda req: {"results": [
        {"url": f"https://vendor.example/{i}", "title": str(i), "publisher": "Vendor"} for i in range(50)
    ]})
    assert len(WebSearchConnector(fake).search(TARGET)) == 15


def test_web_search_runs_one_search_per_alias_and_merges():
    """Each alias gets its own search (vendors index an actor under their own name); the unique
    results are merged. One combined query would collapse onto the top authority pages."""
    target = ResolvedTarget(
        name="APT29", entity_id="intrusion-set--apt29",
        aliases=["APT29", "Cozy Bear", "Midnight Blizzard"],
        search_aliases=["APT29", "Cozy Bear", "Midnight Blizzard"],
    )

    def responder(req):
        alias = req.content.split("Threat: ", 1)[1].split("\n", 1)[0]
        slug = alias.lower().replace(" ", "-")
        return {"results": [{"url": f"https://vendor.example/{slug}", "title": alias, "publisher": "V"}]}

    fake = FakeLLMProvider(responder)
    results = WebSearchConnector(fake).search(target, limit=20)
    assert len(fake.calls) == 3
    assert sorted(r.url for r in results) == [
        "https://vendor.example/apt29",
        "https://vendor.example/cozy-bear",
        "https://vendor.example/midnight-blizzard",
    ]


def test_web_search_caps_the_number_of_alias_queries():
    """Cost guard: an actor with many aliases must not fire an unbounded number of billed
    searches. `max_queries` caps it; the first N aliases (most-canonical first) are used."""
    aliases = [f"name{i}" for i in range(20)]
    target = ResolvedTarget(name="name0", aliases=aliases, search_aliases=aliases)

    def responder(req):
        alias = req.content.split("Threat: ", 1)[1].split("\n", 1)[0]
        return {"results": [{"url": f"https://vendor.example/{alias}", "title": alias, "publisher": "V"}]}

    fake = FakeLLMProvider(responder)
    WebSearchConnector(fake, max_queries=5).search(target, limit=50)
    assert len(fake.calls) == 5


def test_web_search_tolerates_results_with_missing_fields():
    """The model omits fields on some results (title/publisher, occasionally url). A missing
    field must not sink the whole batch — that is what killed a live multi-query run."""
    fake = FakeLLMProvider(lambda req: {"results": [
        {"url": "https://a.example/x", "publisher": "Vendor"},  # no title
        {"url": "https://b.example/y"},                          # no title, no publisher
        {"title": "no url here", "publisher": "V"},              # no url -> skipped
    ]})
    results = WebSearchConnector(fake).search(TARGET)
    assert [r.url for r in results] == ["https://a.example/x", "https://b.example/y"]
    assert results[0].title is None
    assert results[1].publisher == "b.example"


def test_web_search_one_failing_alias_query_does_not_sink_the_others():
    """Multi-query resilience: if one alias search returns unparseable output, the other aliases'
    results still come through instead of the whole web search failing."""
    target = ResolvedTarget(
        name="APT29", aliases=["APT29", "Cozy Bear"], search_aliases=["APT29", "Cozy Bear"],
    )

    def responder(req):
        alias = req.content.split("Threat: ", 1)[1].split("\n", 1)[0]
        if alias == "APT29":
            return InvalidOutput("boom")  # the first alias query fails hard
        return {"results": [{"url": "https://cs.example/cozy", "title": "Cozy", "publisher": "CS"}]}

    fake = FakeLLMProvider(responder)
    results = WebSearchConnector(fake).search(target)
    assert [r.url for r in results] == ["https://cs.example/cozy"]
