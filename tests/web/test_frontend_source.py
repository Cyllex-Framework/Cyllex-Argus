import re
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "web" / "src"
# Built from parts so this file never matches its own scan.
FORBIDDEN = [
    "dangerously" + "SetInnerHTML",
    "inner" + "HTML",
    "outer" + "HTML",
    "insertAdjacent" + "HTML",
    "document." + "write",
    "ev" + "al(",
    "new " + "Function(",
]


def _sources() -> list[Path]:
    return [p for p in SOURCE.rglob("*") if p.suffix in {".ts", ".tsx"}]


def test_the_frontend_source_is_present():
    assert len(_sources()) > 20


def test_untrusted_text_is_never_injected_as_html():
    offenders = [f"{p.relative_to(SOURCE)}: {token}" for p in _sources()
                 for token in FORBIDDEN if token in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_every_new_tab_link_drops_the_opener_and_referrer():
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        assert text.count('target="_blank"') == text.count('rel="noopener noreferrer"'), path.name


def test_the_frontend_calls_only_its_own_api():
    offenders = [p.name for p in _sources() if "fetch('http" in p.read_text(encoding="utf-8")
                 or 'fetch("http' in p.read_text(encoding="utf-8") or "EventSource('http" in p.read_text(encoding="utf-8")]
    assert offenders == []


def _app_sources() -> list[Path]:
    return [p for p in _sources() if ".test." not in p.name and p.parent.name != "test"]


def test_the_frontend_never_relies_on_cookies():
    # The API authenticates with the X-Argus-Token header only; cookies would leak to every server on 127.0.0.1.
    # EventSource cannot send that header, so the job stream is read with fetch.
    forbidden = ["document." + "cookie", "credentials: 'include'", "credentials: 'same-origin'", "new Event" + "Source("]
    offenders = [f"{p.relative_to(SOURCE)}: {token}" for p in _app_sources()
                 for token in forbidden if token in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_no_link_points_at_the_api():
    # A plain link or download cannot send the token header: API files are fetched through the client and then saved.
    api_link = re.compile(r"""href=\{?\s*[`'"][^`'"]*/api/""")
    download_link = re.compile(r"<a\b[^>]*\sdownload[\s>=]", re.DOTALL)
    offenders = [p.name for p in _app_sources()
                 if api_link.search(p.read_text(encoding="utf-8")) or download_link.search(p.read_text(encoding="utf-8"))]
    assert offenders == []
