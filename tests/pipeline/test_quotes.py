import unicodedata

import pytest

from cyllex_argus.knowledge.models import QuoteStatus
from cyllex_argus.pipeline.quotes import (
    MAX_LOCATE_CHARS,
    QuoteLocator,
    locate_quote,
    normalize_text,
    verify_quote,
)

TEXT = (
    "Scattered Spider operators called the IT help desk and impersonated an employee to reset MFA.\n"
    "They later deployed “BlackCat” ransomware — encrypting VMware ESXi hosts."
)


def test_exact_match_ignores_case_and_whitespace():
    assert verify_quote("scattered spider operators   called the IT help desk", TEXT) is QuoteStatus.VERIFIED


def test_typographic_quotes_and_dashes_are_normalized():
    quote = 'deployed "BlackCat" ransomware - encrypting VMware ESXi hosts'
    assert verify_quote(quote, TEXT) is QuoteStatus.VERIFIED


def test_trailing_punctuation_is_ignored():
    assert verify_quote("impersonated an employee to reset MFA.", TEXT) is QuoteStatus.VERIFIED


def test_small_differences_verify_fuzzy():
    quote = "called the IT helpdesk and impersonated an employee to reset MFA"
    assert verify_quote(quote, TEXT) is QuoteStatus.VERIFIED_FUZZY


def test_threshold_is_configurable():
    quote = "called the IT helpdesk and impersonated an employee to reset MFA"
    assert verify_quote(quote, TEXT, fuzzy_threshold=100) is QuoteStatus.REJECTED


def test_fabricated_quote_is_rejected():
    quote = "The group exfiltrated data using Rclone to MEGA storage"
    assert verify_quote(quote, TEXT) is QuoteStatus.REJECTED


def test_short_quotes_are_rejected_even_if_present():
    assert verify_quote("Scattered Spider", TEXT) is QuoteStatus.REJECTED


def test_empty_text_rejects():
    assert verify_quote("called the IT help desk and impersonated", "") is QuoteStatus.REJECTED


def test_quote_longer_than_document_is_rejected():
    doc = "Attackers used phishing emails."
    quote = "Attackers used phishing emails. Then they exfiltrated 40 TB of data to MEGA and deployed BlackCat."
    assert verify_quote(quote, doc) is QuoteStatus.REJECTED


def test_curly_quotes_in_quote_normalize_to_straight_quotes():
    quote = 'deployed “BlackCat” ransomware against VMware hosts'  # curly quotes
    text = 'The group deployed "BlackCat" ransomware against VMware hosts last year.'  # straight quotes
    assert verify_quote(quote, text) is QuoteStatus.VERIFIED


LOCATE_TEXT = "Intro.\nScattered Spider operators called the IT\nhelp desk and impersonated an employee. End."


LDQ, RDQ, RSQ = chr(0x201C), chr(0x201D), chr(0x2019)  # curly double quotes and apostrophe
SOFT_HYPHEN = chr(0xAD)
LONE_SURROGATE = chr(0xD800)
EDGE_PUNCTUATION = " .,;:\"'"


def fullwidth(value: str) -> str:
    """ASCII letters to their fullwidth forms; NFKC folds them back."""
    return "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalpha() else c for c in value)


def assert_located(quote: str, text: str, *, fuzzy: bool = False) -> tuple[int, int]:
    """verify_quote accepts the quote, and locate_quote returns an in-bounds span that covers it."""
    assert verify_quote(quote, text) in (QuoteStatus.VERIFIED, QuoteStatus.VERIFIED_FUZZY)
    span = locate_quote(quote, text)
    assert span is not None
    start, end = span
    assert 0 <= start < end <= len(text)
    covered = normalize_text(text[start:end])
    needle = normalize_text(quote).strip(EDGE_PUNCTUATION)
    if fuzzy:
        words = needle.split()
        assert words[0] in covered and words[-1] in covered
    else:
        assert needle in covered
    return start, end


def test_locate_quote_exact_ignores_case_and_whitespace():
    start, end = assert_located("called the it help desk and IMPERSONATED an employee", LOCATE_TEXT)
    assert LOCATE_TEXT[start:end] == "called the IT\nhelp desk and impersonated an employee"


def test_locate_quote_fuzzy_covers_the_whole_quote_on_word_boundaries():
    start, end = assert_located("called the IT helpdesk and impersonated an employee", LOCATE_TEXT, fuzzy=True)
    covered = LOCATE_TEXT[start:end]
    assert covered.startswith("called") and covered.endswith("employee")


def test_locate_quote_fuzzy_respects_the_threshold():
    quote = "called the IT helpdesk and impersonated an employee"
    assert locate_quote(quote, LOCATE_TEXT, fuzzy_threshold=100) is None


def test_locate_quote_absent_or_too_long_returns_none():
    assert locate_quote("exfiltrated everything to a remote bucket", LOCATE_TEXT) is None
    assert locate_quote(LOCATE_TEXT + " and more words", LOCATE_TEXT) is None
    assert locate_quote("", LOCATE_TEXT) is None
    assert locate_quote("called the IT help desk", "") is None


def test_locate_quote_curly_quotes_in_the_quote_straight_in_the_text():
    text = 'The group deployed "BlackCat" ransomware against VMware hosts last year.'
    start, end = assert_located(f"deployed {LDQ}BlackCat{RDQ} ransomware against VMware", text)
    assert text[start:end] == 'deployed "BlackCat" ransomware against VMware'


def test_locate_quote_straight_quotes_in_the_quote_curly_in_the_text():
    text = f"The group deployed {LDQ}BlackCat{RDQ} ransomware against VMware hosts last year."
    start, end = assert_located('deployed "BlackCat" ransomware against VMware', text)
    assert text[start:end] == f"deployed {LDQ}BlackCat{RDQ} ransomware against VMware"


def test_locate_quote_curly_apostrophe_in_the_text():
    text = f"Analysts noted that the actor didn{RSQ}t reuse infrastructure between campaigns."
    start, end = assert_located("the actor didn't reuse infrastructure", text)
    assert text[start:end] == f"the actor didn{RSQ}t reuse infrastructure"


def test_locate_quote_fullwidth_text():
    text = "Intro. " + fullwidth("Scattered Spider operators called the IT help desk") + " End."
    start, end = assert_located("scattered spider operators called the it help desk", text)
    assert text[start:end] == fullwidth("Scattered Spider operators called the IT help desk")


@pytest.mark.parametrize("form_text, form_quote", [("NFD", "NFC"), ("NFC", "NFD")])
def test_locate_quote_matches_across_unicode_normal_forms(form_text, form_quote):
    base = "The operators phoned the help desk in Zürich to reset MFA for the café."
    text = unicodedata.normalize(form_text, base)
    quote = unicodedata.normalize(form_quote, "phoned the help desk in Zürich to reset MFA for the café")
    start, end = assert_located(quote, text)
    # The span keeps every combining mark of the last character together with its base.
    assert unicodedata.normalize("NFC", text[start:end]).endswith("café")
    assert unicodedata.normalize("NFC", text[start:end]).startswith("phoned")


def test_locate_quote_soft_hyphen_inside_a_word_of_the_text():
    text = f"Intro. Scattered Spider oper{SOFT_HYPHEN}ators called the IT help desk. End."
    start, end = assert_located("Scattered Spider operators called the IT help desk", text)
    assert SOFT_HYPHEN in text[start:end]
    assert text[start:end].startswith("Scattered") and text[start:end].endswith("desk")


def test_locate_quote_extra_whitespace_in_the_quote_locates_the_whole_text():
    text = "called the IT help desk"
    quote = "called   the   IT    help desk"
    assert len(quote) > len(text)
    assert assert_located(quote, text) == (0, len(text))


def test_locate_quote_maps_expanding_characters_back_to_the_original():
    # sharp s -> "ss", ligature -> "fi", capital dotted I -> "i" + combining dot.
    sharp = "Die Stra" + chr(0xDF) + "e operators called the help desk."
    start, end = assert_located("die strasse operators called", sharp)
    assert sharp[start:end] == "Die Stra" + chr(0xDF) + "e operators called"

    ligature = "The " + chr(0xFB01) + "rst operators called the IT help desk."
    start, end = assert_located("the first operators called the IT", ligature)
    assert ligature[start:end] == "The " + chr(0xFB01) + "rst operators called the IT"

    dotted = "operators from " + chr(0x130) + "stanbul called the help desk"
    start, end = assert_located(dotted, dotted)
    assert (start, end) == (0, len(dotted))


ODD_INPUTS = [
    ("", ""),
    ("   ", "   "),
    ("   ", LOCATE_TEXT),
    ("called the IT help desk", "   \n  "),
    (LONE_SURROGATE, LONE_SURROGATE),
    (f"called {LONE_SURROGATE} the IT", f"x called {LONE_SURROGATE} the IT y"),
    (chr(0x301) * 3, chr(0x301) * 3),
    (chr(0x301) + "e" + chr(0x301) + " help desk", "x" + chr(0x301) + "e" + chr(0x301) + " help desk"),
    (chr(0x130) * 4, chr(0x130) * 6),
    (chr(0xDF) * 5, "x" + chr(0xDF) * 5),
    (SOFT_HYPHEN * 3, SOFT_HYPHEN * 3),
    ('"\'.,;: ', '"\'.,;: '),
]


@pytest.mark.parametrize("quote, text", ODD_INPUTS)
def test_locate_quote_odd_inputs_never_raise(quote, text):
    span = locate_quote(quote, text)
    assert span is None or 0 <= span[0] < span[1] <= len(text)


def test_locate_quote_caps_the_quote_length():
    limit = "a" * MAX_LOCATE_CHARS
    assert locate_quote(limit, limit) == (0, MAX_LOCATE_CHARS)
    too_long = limit + "a"
    assert locate_quote(too_long, too_long + " tail") is None


def test_quote_locator_is_reusable_and_matches_locate_quote():
    quotes = [
        "called the it help desk and IMPERSONATED an employee",
        "called the IT helpdesk and impersonated an employee",
        "exfiltrated everything to a remote bucket",
        "Scattered Spider operators",
        "",
    ]
    locator = QuoteLocator(LOCATE_TEXT)
    first = [locator.locate(q) for q in quotes]
    assert first == [locate_quote(q, LOCATE_TEXT) for q in quotes]
    assert [locator.locate(q) for q in quotes] == first
    assert first[2] is None and first[0] is not None and first[1] is not None


def test_quote_locator_offset_map_agrees_with_normalize_text():
    samples = [
        LOCATE_TEXT,
        "  leading and trailing \n\t whitespace  ",
        f"curly {LDQ}quotes{RDQ} and{SOFT_HYPHEN}soft hyphen and {chr(0xA0)}nbsp",
        unicodedata.normalize("NFD", "Zürich café Créme"),
        "Stra" + chr(0xDF) + "e " + chr(0xFB01) + "rst " + chr(0x130) + "stanbul",
        fullwidth("Scattered Spider"),
        chr(0x301) + "x",
        "",
    ]
    for text in samples:
        locator = QuoteLocator(text)
        assert locator._normalized == normalize_text(text)
        assert len(locator._starts) == len(locator._ends) == len(locator._normalized)
        assert all(0 <= s < e <= len(text) for s, e in zip(locator._starts, locator._ends, strict=False))


@pytest.mark.parametrize("text, quote, word", [
    # NFD text: "resume" with combining acutes. The quote stops mid-word, so the span is snapped out to the word's end.
    ("Operators sent the phishing kit re\u0301sume\u0301 to candidates.",
     "operators sent the phishing kit resum", "re\u0301sume\u0301"),
    # A spacing vowel sign (category Mc, combining class 0) belongs to its consonant just the same.
    ("Operators sent the phishing kit \u0915\u093e\u0915\u093e to candidates.",
     "operators send the phishing kit \u0915\u093e\u0915", "\u0915\u093e\u0915\u093e"),
])
def test_locate_quote_never_splits_a_base_character_from_its_marks(text, quote, word):
    start, end = locate_quote(quote, text)
    assert text[start:end] == "Operators sent the phishing kit " + word
    assert end == len(text) or not unicodedata.category(text[end]).startswith("M")
