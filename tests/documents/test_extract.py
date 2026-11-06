import random
import time
from datetime import date

import pytest
from fpdf import FPDF

from cyllex_argus.documents.extract import (
    ExtractionError,
    canonicalize_url,
    content_hash,
    domain_of,
    extract,
)

HTML = b"""<!doctype html><html><head><title>Scattered Spider targets help desks</title>
<meta property="article:published_time" content="2024-05-17T10:00:00Z">
<script>var secret = "do not extract";</script></head>
<body><nav>Home | Products</nav><article><h1>Scattered Spider targets help desks</h1>
<p>Scattered Spider operators called the IT help desk and impersonated an employee to reset MFA.
This technique was observed across several intrusions in the hospitality sector during 2023.</p>
<p>After gaining access, the group deployed BlackCat ransomware against VMware ESXi hosts and
exfiltrated data with Rclone to cloud storage providers controlled by the operators.</p>
</article></body></html>"""


def _pdf(text: str, title: str) -> bytes:
    pdf = FPDF()
    pdf.set_title(title)
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    pdf.multi_cell(0, 10, text)
    return bytes(pdf.output())


def test_html_extraction():
    doc = extract(HTML, "text/html; charset=utf-8", "page.html")
    assert "Scattered Spider" in doc.title
    assert "impersonated an employee" in doc.text
    assert "do not extract" not in doc.text
    assert doc.published_at == date(2024, 5, 17)


def test_html_fallback_when_trafilatura_finds_nothing(monkeypatch):
    monkeypatch.setattr("cyllex_argus.documents.extract.trafilatura.extract", lambda *a, **k: None)
    doc = extract(HTML, "text/html", "page.html")
    assert "impersonated an employee" in doc.text
    assert "do not extract" not in doc.text


def test_empty_html_raises():
    with pytest.raises(ExtractionError):
        extract(b"<html><body></body></html>", "text/html", "empty.html")


def test_pdf_extraction():
    data = _pdf("Octo Tempest used SIM swapping against telecom employees.", "Octo Tempest Report")
    doc = extract(data, "application/pdf", "report.pdf")
    assert doc.title == "Octo Tempest Report"
    assert "SIM swapping" in doc.text


def test_pdf_detected_by_magic_bytes():
    data = _pdf("UNC3944 abused remote management tools.", "UNC3944")
    assert "remote management" in extract(data, None, "download").text


def test_plain_text_and_binary():
    doc = extract(b"Scattered Spider notes\n\nThey used Rclone.", "text/plain", "notes.txt")
    assert doc.title == "Scattered Spider notes"
    with pytest.raises(ExtractionError):
        extract(b"\x00\x01\x02garbage", "application/octet-stream", "blob.bin")


def test_content_hash_is_sha256():
    assert content_hash(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_canonicalize_url():
    assert canonicalize_url("http://www.Example.com/a/?utm_source=x&b=2#frag") == "https://example.com/a?b=2"
    assert canonicalize_url("https://example.com/a") == canonicalize_url("https://example.com/a/")
    assert canonicalize_url("https://example.com") == "https://example.com/"
    assert domain_of("https://www.Unit42.paloaltonetworks.com/x") == "unit42.paloaltonetworks.com"


def test_html_fallback_speed(monkeypatch):
    """Test that the HTML fallback is linear-time even with hostile input."""
    monkeypatch.setattr("cyllex_argus.documents.extract.trafilatura.extract", lambda *a, **k: None)
    hostile = b"<script>" * 40000 + b"<p>Real content about Scattered Spider operators.</p>"
    start = time.perf_counter()
    try:
        doc = extract(hostile, "text/html", "page.html")
        # Either we extract the content or raise an error, both are acceptable
        assert "Real content" in doc.text
    except ExtractionError:
        # With default CDATA handling, may not extract any content
        pass
    elapsed = time.perf_counter() - start
    assert elapsed < 2, f"Extraction took {elapsed:.2f}s, expected < 2s"


def test_unsupported_content_types():
    """Test that unsupported content types are rejected."""
    with pytest.raises(ExtractionError, match="unsupported content type"):
        extract(b"\x89PNG\r\n\x1a\n" + b"x" * 100, "image/png", "image.png")
    with pytest.raises(ExtractionError, match="unsupported content type"):
        extract(b"data", "audio/mpeg", "song.mp3")
    with pytest.raises(ExtractionError, match="unsupported content type"):
        extract(b"data", "video/mp4", "video.mp4")
    with pytest.raises(ExtractionError, match="unsupported content type"):
        extract(b"data", "font/woff", "font.woff")


def test_binary_rejection_with_random_bytes():
    """Test that random bytes are rejected in both text/plain and text/html."""
    random_bytes = random.Random(7).randbytes(3000)
    # Replace NUL bytes so they don't trigger the NUL check
    random_bytes = random_bytes.replace(b"\x00", b"x")

    with pytest.raises(ExtractionError, match="binary or undecodable"):
        extract(random_bytes, "text/plain", "data.txt")

    with pytest.raises(ExtractionError, match="binary or undecodable"):
        extract(random_bytes, "text/html", "data.html")


def test_script_content_not_leaked(monkeypatch):
    """Test that script content is not leaked from _fallback_html_text."""
    from cyllex_argus.documents.extract import _fallback_html_text

    # Test 1: script with HTML-like content
    markup = b'<script>var t="<div>LEAKED</div>";</script>'
    text = _fallback_html_text(markup.decode("utf-8"))
    assert "LEAKED" not in text

    # Test 2: script with write statement
    markup = b'<script>document.write("<b>SECRET</b>")</script>'
    text = _fallback_html_text(markup.decode("utf-8"))
    assert "SECRET" not in text

    # Test 3: noscript with img tag
    markup = b'<noscript><img src=x>TEXT</noscript>'
    text = _fallback_html_text(markup.decode("utf-8"))
    assert "TEXT" not in text

    # Test 4: noscript with p tag
    markup = b'<noscript><p>ENABLE JS</p></noscript>'
    text = _fallback_html_text(markup.decode("utf-8"))
    assert "ENABLE JS" not in text
