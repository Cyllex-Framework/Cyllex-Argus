"""Shared fake world for pipeline and CLI tests: canned web pages and a scripted LLM."""

from __future__ import annotations

import ipaddress
import re
import shutil
from pathlib import Path

import httpx

from cyllex_argus.attack.catalog import AttackCatalog, load_catalog_into_store
from cyllex_argus.config.settings import ArgusConfig, get_paths
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.llm.base import LLMRequest, RateLimited
from cyllex_argus.llm.fake import FakeLLMProvider
from cyllex_argus.services import Services


def _public_resolver(_host: str) -> list:
    """Pretend every hostname resolves to a public IP; keeps fixtures hermetic (no real DNS)."""
    return [ipaddress.ip_address("93.184.216.34")]

FIXTURES = Path(__file__).parent / "fixtures"
SPIDER = "intrusion-set--00000000-0000-4000-8000-000000001015"
QUOTE = "operators called the IT help desk and impersonated an employee to reset MFA"
PAGES = {
    "https://mandiant.example/spider": f"Scattered Spider deep dive\n\nScattered Spider {QUOTE}. Scattered Spider is persistent.",
    "https://microsoft.example/octo": f"Octo Tempest update\n\nOcto Tempest {QUOTE}. It remains active.",
    "https://news.example/other": "Weekly news\n\nNothing relevant here at all.",
}
SEARCH_RESULTS = [
    {"url": "https://mandiant.example/spider", "title": "Deep dive", "publisher": "Mandiant"},
    {"url": "https://microsoft.example/octo", "title": "Update", "publisher": "Microsoft"},
    {"url": "https://news.example/other", "title": "News", "publisher": "News"},
    {"url": "https://gone.example/404", "title": "Gone", "publisher": "Gone"},
]
# URLs that canonicalize_url accepts but httpx refuses: a NUL byte, and a zero-width space as the host.
INVALID_URLS = ["https://a" + chr(0) + "b.com/x", "https://" + chr(0x200B) + ".com/x"]
CLAIM = {
    "subject": "Scattered Spider", "subject_type": "intrusion-set", "predicate": "uses",
    "object": "Spearphishing Voice", "object_type": "attack-pattern", "polarity": "asserts",
    "quote": QUOTE, "technique_id": "T1566.004",
}


TTP_BODY = "id: T1566.004-01\nexecutor:\n  command: whoami\n"


class ScriptedLLM(FakeLLMProvider):
    """Answers every Argus prompt; optionally returns RateLimited on the Nth Analyst call."""

    def __init__(self, analyst_error_on_call: int | None = None) -> None:
        self.analyst_calls = 0
        self.claims = [CLAIM]
        self._error_on = analyst_error_on_call
        super().__init__(self._handle)

    def _handle(self, request: LLMRequest):
        if request.prompt_version.startswith("web-search"):
            return {"results": SEARCH_RESULTS}
        if request.prompt_version.startswith("triage"):
            return {"relevant": True, "reason": "test"}
        if request.prompt_version.startswith("summary"):
            return {"summary": "Scattered Spider is a financially motivated intrusion set."}
        if request.prompt_version.startswith("ttp"):
            return {"filename": "T1566.004-scattered-spider-01.yaml", "body": TTP_BODY,
                    "warnings": []}
        self.analyst_calls += 1
        if self.analyst_calls == self._error_on:
            return RateLimited("usage limit reached")
        publisher = re.search(r"Publisher: (.+)", request.content).group(1)
        return {"primary_publisher": publisher, "claims": self.claims}


def web_transport(failing: set[str] | None = None) -> httpx.MockTransport:
    """Serve PAGES and the ATT&CK fixture. URLs in `failing` answer 503; the set may change between requests."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if failing is not None and url in failing:
            return httpx.Response(503)
        if url.endswith("enterprise-attack.json"):
            return httpx.Response(200, content=(FIXTURES / "attack_mini.json").read_bytes(),
                                  headers={"content-type": "application/json"})
        body = PAGES.get(url)
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, content=body.encode(), headers={"content-type": "text/plain"})

    return httpx.MockTransport(handler)


class World:
    """A temporary Argus home with the mini ATT&CK catalog, a scripted LLM and canned web pages."""

    def __init__(self, home: Path) -> None:
        self.llm = ScriptedLLM()
        self.config = ArgusConfig(feeds=[])
        self.paths = get_paths(home)
        self.paths.ensure()
        shutil.copy(FIXTURES / "attack_mini.json", self.paths.attack_file)
        with SQLiteStore(self.paths.db_file) as store:
            load_catalog_into_store(AttackCatalog.from_file(self.paths.attack_file), store)

    def services(self) -> Services:
        http = httpx.Client(transport=web_transport())
        return Services(
            paths=self.paths, config=self.config, store=SQLiteStore(self.paths.db_file),
            llm=self.llm, http=http,
            fetcher=Fetcher(http, max_bytes=100_000, sleep=lambda s: None, resolve_host=_public_resolver),
        )

    def investigate(self, target: str = "Scattered Spider"):
        services = self.services()
        try:
            return services.pipeline().investigate(target)
        finally:
            services.close()
