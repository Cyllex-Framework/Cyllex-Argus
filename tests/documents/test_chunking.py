import pytest

from cyllex_argus.documents.chunking import chunk_text
from cyllex_argus.documents.extract import extract


def test_short_text_is_one_chunk():
    chunks = chunk_text("Intro paragraph.\n\nSecond paragraph.", 1000)
    assert len(chunks) == 1
    assert chunks[0].index == 0
    assert chunks[0].text == "Intro paragraph.\n\nSecond paragraph."


def test_long_text_splits_at_paragraphs_and_keeps_headings():
    body = "\n\n".join(["Initial Access"] + [f"Paragraph {i}. " + "x" * 300 for i in range(10)])
    chunks = chunk_text(body, 1000)
    assert len(chunks) > 1
    assert all(len(c.text) <= 1000 for c in chunks)
    assert all(c.heading == "Initial Access" for c in chunks)
    assert [c.index for c in chunks] == list(range(len(chunks)))
    assert "Paragraph 9." in chunks[-1].text


def test_giant_paragraph_is_hard_split():
    chunks = chunk_text("word " * 1000, 1000)
    assert len(chunks) >= 5
    assert all(len(c.text) <= 1000 for c in chunks)


def test_rejects_tiny_chunk_size():
    with pytest.raises(ValueError):
        chunk_text("text", 10)


def test_chunk_overlap_prepends_tail_of_previous_chunk():
    """A quote spanning a chunk boundary must be reachable from the next chunk via overlap."""
    body = "\n\n".join([f"Paragraph {i}. " + "x" * 300 for i in range(20)])
    chunks = chunk_text(body, max_chars=2000, overlap_chars=300)
    assert len(chunks) >= 2
    tail = chunks[0].text[-120:]
    assert tail in chunks[1].text, (
        f"expected the last 120 chars of chunk 0 to appear in chunk 1\n"
        f"tail={tail!r}\nchunk1[:200]={chunks[1].text[:200]!r}"
    )


def test_chunk_overlap_respects_max_chars_cap():
    """overlap counts against max_chars; chunks never exceed the hard cap."""
    body = "\n\n".join([f"Paragraph {i}. " + "x" * 300 for i in range(20)])
    chunks = chunk_text(body, max_chars=2000, overlap_chars=300)
    assert all(len(c.text) <= 2000 for c in chunks)


def test_chunk_overlap_zero_is_identical_to_no_overlap():
    body = "\n\n".join([f"Paragraph {i}. " + "x" * 300 for i in range(5)])
    assert chunk_text(body, 2000) == chunk_text(body, 2000, overlap_chars=0)


def test_chunking_with_extracted_html():
    """Integration test: extract real HTML and verify chunking works on extracted text."""
    html = b"""<!doctype html><html><head><title>Threat Report</title></head><body>
    <h1>Advanced Persistent Threat Analysis</h1>
    <h2>Initial Access Vector</h2>
    <p>Attackers gained initial access through phishing emails targeting employees. This paragraph contains a significant amount of text to ensure it is long enough to test the chunking algorithm properly with realistic content about threat actors.</p>
    <p>The phishing emails contained malicious attachments that exploited vulnerabilities in commonly used office applications. Organizations should implement multi-factor authentication and security awareness training.</p>
    <p>Analysis shows this technique was observed across several intrusions in multiple sectors during the past year. The threat actors demonstrated advanced knowledge of network infrastructure.</p>
    <p>Further investigation revealed additional attack patterns and indicators of compromise that can help defenders identify similar intrusions in their environment.</p>
    <h2>Persistence Mechanisms</h2>
    <p>Once inside the network, threat actors deployed multiple persistence mechanisms to maintain access. They installed backdoors and created new user accounts with administrative privileges.</p>
    <p>The persistence techniques included scheduled tasks, service installations, and registry modifications. These methods allowed the attackers to maintain long-term access to compromised systems.</p>
    <p>Security teams should monitor for unusual account creation and system service installations. Behavioral analysis can detect anomalous network connections established by malware.</p>
    <p>The attackers used legitimate administrative tools to move laterally through the network. This approach helps them avoid detection by security solutions.</p>
    </body></html>"""

    doc = extract(html, "text/html", "report.html")
    chunks = chunk_text(doc.text, 1000)

    # Verify multiple chunks are created
    assert len(chunks) >= 2, f"Expected at least 2 chunks, got {len(chunks)}"

    # Verify no chunk exceeds max_chars
    assert all(len(c.text) <= 1000 for c in chunks), "Some chunks exceed 1000 chars"

    # Verify at least one chunk has a heading from the document
    headings = {c.heading for c in chunks if c.heading}
    assert "Initial Access Vector" in headings or "Persistence Mechanisms" in headings, \
        f"Expected at least one section heading, got: {headings}"

    # Verify each chunk's first line is a line from the original text
    original_lines = {line.strip() for line in doc.text.split("\n") if line.strip()}
    for chunk in chunks:
        if chunk.text:
            # Get the first line of the chunk
            first_line = chunk.text.split("\n")[0].strip()
            assert first_line in original_lines, \
                f"Chunk first line '{first_line[:50]}...' not found in original text"
