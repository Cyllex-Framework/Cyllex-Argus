"""Drive the real interface in Microsoft Edge against a fake, offline Argus world.

Opt-in: set ARGUS_E2E=1. Screenshots go to ARGUS_E2E_SHOTS (or the test's tmp dir).
"""

import json
import os
import re
import socket
import sqlite3
import threading
import time
from datetime import date, timedelta
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("ARGUS_E2E") != "1", reason="set ARGUS_E2E=1 to run the browser test")

sync_api = pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")

from cyllex_argus.web.app import create_app  # noqa: E402
from tests.support import CLAIM, PAGES, QUOTE, World  # noqa: E402

TOKEN = "e2e-token-0123456789abcdef"
TIMEOUT_MS = 60_000


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


INDICATOR_QUOTE = "The group used evil.example for command and control"


@pytest.fixture
def server(tmp_path, monkeypatch):
    world = World(tmp_path / "home")
    # One extra claim: an indicator (domain) that indicates Scattered Spider, quoted from the Mandiant page.
    url = "https://mandiant.example/spider"
    monkeypatch.setitem(PAGES, url, f"{PAGES[url]} {INDICATOR_QUOTE}.")
    world.llm.claims = [CLAIM, {
        "subject": "evil.example", "subject_type": "indicator", "predicate": "indicates",
        "object": "Scattered Spider", "object_type": "intrusion-set", "polarity": "asserts", "quote": INDICATOR_QUOTE,
    }]
    world.investigate("Scattered Spider")
    # The canned pages carry no publication date: date the indicator's fact a week ago so it resolves to `active`.
    recent = (date.today() - timedelta(days=7)).isoformat()
    with sqlite3.connect(world.paths.db_file) as conn:
        conn.execute(
            "UPDATE assessments SET last_seen = ? WHERE subject_entity_id IN (SELECT id FROM entities WHERE stix_type = 'indicator')",
            (recent,))
    world.recent = recent
    port = _free_port()
    app = create_app(world.services, token=TOKEN, port=port, claude_available=lambda: True)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    uv_server = uvicorn.Server(config)
    thread = threading.Thread(target=uv_server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not uv_server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", world
    uv_server.should_exit = True
    thread.join(timeout=10)
    app.state.jobs.shutdown()


@pytest.fixture
def shots(tmp_path) -> Path:
    directory = Path(os.environ.get("ARGUS_E2E_SHOTS") or tmp_path / "screenshots")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _record_problems(page, problems: list[str]) -> None:
    page.on("console", lambda message: problems.append(f"console: {message.text}") if message.type == "error" else None)
    page.on("pageerror", lambda error: problems.append(f"pageerror: {error}"))


def _shoot(page, path: Path) -> None:
    """Full-page screenshot with CSS transitions settled (headless otherwise catches the previous tab mid-fade)."""
    page.evaluate("document.getAnimations().forEach((animation) => animation.finish())")
    page.screenshot(path=str(path), full_page=True)


def test_the_interface_end_to_end(server, shots):
    server, world = server
    expect = sync_api.expect
    problems: list[str] = []
    stranger_problems: list[str] = []
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        try:
            context = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
            # Seed the session token in localStorage BEFORE any page in this context loads, which
            # is the post-login state we exercise. The real UX runs the login form at /login; the
            # end-to-end flow uses the same storage key and the test only cares about the gated
            # dashboard behaviour, not the form itself (that is covered by LoginPage unit tests).
            context.add_init_script(f"window.localStorage.setItem('argus.token', '{TOKEN}')")
            page = context.new_page()
            page.set_default_timeout(TIMEOUT_MS)
            _record_problems(page, problems)
            tabs = page.get_by_role("navigation")

            # A fresh install has no ATT&CK data yet: the dashboard says so and runs the update right there.
            world.paths.attack_file.unlink()

            # The token travels only in a header on each API call: nothing is set as a cookie, and
            # a request without the header is refused.
            page.goto(f"{server}/")
            expect(page).to_have_url(re.compile(r"/dashboard$"))
            assert "token" not in page.url
            assert page.evaluate("localStorage.getItem('argus.token')") == TOKEN
            assert context.cookies() == []
            assert context.request.get(f"{server}/api/overview").status == 401
            expect(page.get_by_text("Threats with facts")).to_be_visible()
            expect(page.get_by_role("link", name="Scattered Spider").first).to_be_visible()
            setup = page.get_by_role("region", name="Finish setup")
            expect(setup).to_contain_text("MITRE ATT&CK data is missing")
            _shoot(page, shots / "00-dashboard-setup.png")
            setup.get_by_role("button", name="Update ATT&CK").click()
            # The offline update can finish before its progress is seen; when it has, the settings refresh and the
            # notice goes away on its own.
            expect(setup).to_have_count(0)
            assert world.paths.attack_file.exists()
            _shoot(page, shots / "01-dashboard.png")

            # Threat search -> profile -> citations -> graph -> export.
            tabs.get_by_role("link", name="Threats").click()
            page.get_by_label("Search threats").fill("spider")
            page.get_by_role("link", name="Scattered Spider").click()
            expect(page.get_by_role("heading", name="Scattered Spider")).to_be_visible()
            page.get_by_role("button", name="Show table").click()
            page.get_by_role("table").get_by_text(re.compile("Spearphishing Voice")).first.click()
            expect(page.get_by_role("region", name="Citations").get_by_text(QUOTE, exact=False).first).to_be_visible()
            # The graph is a lazy chunk: wait for its canvas, then switch the depth and wait for the redraw.
            graph_canvas = page.locator('[data-testid="threat-graph"] canvas').first
            expect(graph_canvas).to_be_attached()
            page.get_by_role("button", name="Depth 2").click()
            expect(page.get_by_role("button", name="Depth 2")).to_have_attribute("aria-pressed", "true")
            expect(graph_canvas).to_be_attached()
            page.get_by_role("button", name="Depth 1").click()
            expect(page.get_by_role("button", name="Depth 1")).to_have_attribute("aria-pressed", "true")
            expect(graph_canvas).to_be_attached()
            _shoot(page, shots / "02-threat-profile.png")
            # Exports are fetched with the token header and saved from a blob under the server's file name.
            with page.expect_download() as download_info:
                page.get_by_role("button", name="Markdown", exact=True).click()
            assert download_info.value.suggested_filename == "Scattered_Spider.md"
            with page.expect_download() as download_info:
                page.get_by_role("button", name="Markdown + AI summary").click()
            summary_file = download_info.value.path()
            assert "financially motivated" in Path(summary_file).read_text(encoding="utf-8")
            with page.expect_download() as download_info:
                page.get_by_role("button", name="STIX 2.1").click()
            stix = download_info.value
            assert stix.suggested_filename == "Scattered_Spider.stix.json"
            assert '"type": "bundle"' in Path(stix.path()).read_text(encoding="utf-8")
            expect(page.get_by_role("alert")).to_have_count(0)

            # An app link opened in a new tab keeps the session: the token is in the origin's storage, not the URL.
            second_tab = context.new_page()
            second_tab.set_default_timeout(TIMEOUT_MS)
            _record_problems(second_tab, problems)
            second_tab.goto(f"{server}/threats")
            expect(second_tab.get_by_label("Search threats")).to_be_visible()
            expect(second_tab.get_by_text("argus serve")).to_have_count(0)
            second_tab.close()

            # Documents -> viewer with highlighted quotes.
            tabs.get_by_role("link", name="Documents").click()
            page.get_by_label("Filter by stage").select_option("validated")
            page.get_by_role("table").get_by_role("link").first.click()
            expect(page.locator('[data-testid="document-text"] mark').first).to_be_visible()
            page.get_by_role("region", name="Claims").get_by_role("button").first.click()
            expect(page.locator('mark[data-active="true"]').first).to_be_visible()
            _shoot(page, shots / "03-document-viewer.png")

            # Start an investigation and follow it live over SSE until it finishes. The ATT&CK data vanishes after
            # the page loaded: the server's refusal brings up the notice and its fix, not a dead-end error.
            tabs.get_by_role("link", name="Investigations").click()
            page.get_by_label("Threat to investigate").fill("Octo Tempest")
            start = page.get_by_role("button", name="Start investigation")
            expect(start).to_be_enabled()
            world.paths.attack_file.unlink()
            start.click()
            setup = page.get_by_role("region", name="Finish setup")
            expect(setup).to_be_visible()
            expect(start).to_be_disabled()
            _shoot(page, shots / "04a-investigation-needs-attack.png")
            setup.get_by_role("button", name="Update ATT&CK").click()
            expect(setup).to_have_count(0)
            expect(page.get_by_role("alert")).to_have_count(0)
            start.click()
            expect(page.get_by_text("Investigation progress")).to_be_visible()
            expect(page.get_by_role("link", name=re.compile(r"Open investigation #\d+"))).to_be_visible()
            _shoot(page, shots / "04-investigation-finished.png")
            page.get_by_role("link", name=re.compile(r"Open investigation #\d+")).click()
            expect(page).to_have_url(re.compile(r"/investigations/\d+/dashboard$"))
            expect(page.get_by_role("heading", name="ATT&CK matrix")).to_be_visible()

            # The investigation dashboard: header, ATT&CK matrix, side panel, fullscreen graph. The canned bundle
            # gets a tactic on Spearphishing Voice so the matrix has a cell to click.
            bundle = json.loads(world.paths.attack_file.read_text(encoding="utf-8"))
            for obj in bundle["objects"]:
                if obj.get("name") == "Spearphishing Voice":
                    obj["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
            world.paths.attack_file.write_text(json.dumps(bundle), encoding="utf-8")
            page.goto(f"{server}/investigations/1/dashboard")
            expect(page.get_by_role("heading", name="Scattered Spider", level=1)).to_be_visible()
            _shoot(page, shots / "08-dashboard-header.png")
            initial_access = page.get_by_role("listitem", name="Initial Access")
            cell = initial_access.get_by_role("button", name=re.compile(r"T1566\.004"))
            expect(cell).to_contain_text("Spearphishing Voice")
            _shoot(page, shots / "09-dashboard-matrix.png")

            # The pipeline trace: collapsed by default, expands into per-document decision rows.
            trace = page.get_by_role("heading", name="Pipeline trace").locator("xpath=ancestor::section[1]")
            trace.get_by_role("button", name=re.compile(r"\d+ events?")).click()
            expect(trace.get_by_role("listitem").filter(has_text="triage").first).to_be_visible()
            expect(trace.get_by_role("listitem").filter(has_text="analyst").first).to_be_visible()
            _shoot(page, shots / "09-pipeline-trace.png")

            # The scope switch: only what this investigation contributed, and the URL follows the toggle.
            page.get_by_role("button", name="This investigation").click()
            expect(page).to_have_url(re.compile(r"[?&]scope=investigation(&|$)"))
            expect(page.get_by_role("button", name="This investigation")).to_have_attribute("aria-pressed", "true")
            expect(initial_access.get_by_role("button", name=re.compile(r"T1566\.004"))).to_be_visible()
            _shoot(page, shots / "10-scope-this-investigation.png")
            page.get_by_role("button", name="Everything known").click()
            expect(page).not_to_have_url(re.compile(r"scope="))
            expect(cell).to_be_visible()
            cell.click()
            panel = page.get_by_role("dialog", name="Entity details")
            expect(panel).to_be_visible()
            expect(panel.get_by_role("heading", name="Spearphishing Voice")).to_be_visible()
            panel.get_by_role("table").get_by_role("row").nth(1).click()
            expect(panel.get_by_text(QUOTE, exact=False).first).to_be_visible()
            _shoot(page, shots / "10-dashboard-side-panel.png")
            page.keyboard.press("Escape")
            expect(panel).to_have_count(0)
            page.get_by_role("button", name="Expand graph").click()
            fullscreen = page.get_by_role("dialog", name="Relationship graph")
            expect(fullscreen).to_be_visible()
            expect(fullscreen.get_by_role("button", name="Close")).to_be_visible()
            expect(fullscreen.locator("canvas").first).to_be_attached()
            _shoot(page, shots / "11-dashboard-fullscreen-graph.png")
            # Filters: the indicator toggle exists (as a checkbox in the left drawer), switches off and on again.
            indicator_filter = fullscreen.get_by_label("Toggle Indicators")
            expect(indicator_filter).to_be_checked()
            indicator_filter.click()
            expect(indicator_filter).not_to_be_checked()
            indicator_filter.click()
            expect(indicator_filter).to_be_checked()
            # The side panel of the indicator: click its node at the position cytoscape rendered it.
            with sqlite3.connect(world.paths.db_file) as conn:
                indicator_id = conn.execute("SELECT id FROM entities WHERE stix_type = 'indicator'").fetchone()[0]
            canvas_host = fullscreen.get_by_test_id("threat-graph")
            position = canvas_host.evaluate(
                "(el, id) => { const p = el.__cy.$id(id).renderedPosition(); return { x: p.x, y: p.y } }", indicator_id)
            canvas_host.click(position={"x": position["x"], "y": position["y"]})
            indicator_panel = page.get_by_role("dialog", name="Entity details")
            expect(indicator_panel.get_by_role("heading", name="evil.example")).to_be_visible()
            expect(indicator_panel.locator("p", has_text="Value:")).to_contain_text("evil.example")
            expect(indicator_panel.locator("p", has_text="Kind:")).to_contain_text("domain")
            freshness_line = indicator_panel.locator("p", has_text="Freshness:")
            expect(freshness_line.get_by_text("active", exact=True)).to_be_visible()
            expect(freshness_line).to_contain_text(f"last seen {world.recent}")
            _shoot(page, shots / "11-indicator-detail.png")
            page.keyboard.press("Escape")
            expect(indicator_panel).to_have_count(0)
            page.keyboard.press("Escape")
            expect(fullscreen).to_have_count(0)
            expect(page.get_by_role("button", name="Expand graph")).to_be_visible()

            # Sources: rating a publisher saves it at once and recomputes the confidences in a job.
            tabs.get_by_role("link", name="Sources").click()
            page.get_by_label("Reliability of Mandiant").select_option("B")
            expect(page.get_by_role("status")).to_contain_text("Mandiant set to B")
            expect(page.get_by_role("status")).to_contain_text("confidences recomputed")
            _shoot(page, shots / "05-sources.png")

            # Settings: ATT&CK update runs as a job (served from the canned fixture).
            tabs.get_by_role("link", name="Settings").click()
            expect(page.get_by_text(re.compile(r"^\d+ techniques, \d+ groups"))).to_be_visible()
            page.get_by_role("button", name="Update ATT&CK").click()
            expect(page.get_by_text("ATT&CK update")).to_be_visible()
            expect(page.get_by_text("finished", exact=True).first).to_be_visible()
            _shoot(page, shots / "06-settings.png")

            # Logs: the global view lists the ATT&CK update job and the agents' recent events.
            tabs.get_by_role("link", name="Logs").click()
            expect(page.get_by_role("heading", name="Agent events")).to_be_visible()
            expect(page.get_by_role("cell", name="ATT&CK update").first).to_be_visible()
            expect(page.get_by_role("region", name="Collector").get_by_role("listitem").first).to_be_visible()
            _shoot(page, shots / "07-logs.png")

            # Unknown routes show the in-app not-found page.
            page.goto(f"{server}/no-such-page")
            expect(page.get_by_text("Page not found")).to_be_visible()

            # A browser that never had the tokened URL gets the session-expired notice, not broken screens.
            stranger = browser.new_context().new_page()
            stranger.set_default_timeout(TIMEOUT_MS)
            _record_problems(stranger, stranger_problems)
            stranger.goto(f"{server}/dashboard")
            expect(stranger.get_by_text("argus serve")).to_be_visible()
            _shoot(stranger, shots / "07-session-expired.png")
        finally:
            browser.close()

    # The signed-in page must be silent, but for the browser's log of the deliberate 409 (missing ATT&CK data).
    # The stranger's page may only fail with the deliberate 401s.
    assert [p for p in problems if "status of 409" not in p] == []
    assert len(problems) <= 1
    assert [p for p in stranger_problems if "401" not in p] == []
