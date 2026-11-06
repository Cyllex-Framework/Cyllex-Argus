from datetime import date

from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.knowledge.models import AssessmentStatus, Evidence, Polarity, Reliability  # noqa: F401
from cyllex_argus.scoring.confidence import score

TODAY = date(2026, 9, 29)
CFG = ScoringConfig()


def ev(publisher_id, reliability="A", polarity=Polarity.ASSERTS, published=date(2026, 1, 1), observed=None,
       claim_id=1, document_reliability=None):
    return Evidence(
        claim_id=claim_id, publisher_id=publisher_id, reliability=reliability,
        document_reliability=document_reliability,
        polarity=polarity, published_at=published, observed_at=observed,
    )


def test_one_a_source_is_60_single_source():
    r = score([ev(1)], set(), CFG, TODAY)
    assert (r.confidence, r.status, r.admiralty) == (60, AssessmentStatus.SINGLE_SOURCE, "A3")


def test_two_and_three_a_sources():
    two = score([ev(1), ev(2)], set(), CFG, TODAY)
    assert (two.confidence, two.status, two.admiralty) == (84, AssessmentStatus.CORROBORATED, "A2")
    three = score([ev(1), ev(2), ev(3)], set(), CFG, TODAY)
    assert (three.confidence, three.admiralty) == (94, "A1")


def test_unknown_reliability_source_is_30():
    assert score([ev(1, reliability="F")], set(), CFG, TODAY).confidence == 30


def test_same_publisher_counts_once():
    r = score([ev(1, claim_id=1), ev(1, claim_id=2)], set(), CFG, TODAY)
    assert r.confidence == 60 and r.status is AssessmentStatus.SINGLE_SOURCE


def test_stale_dated_source_is_discounted():
    # A page from 2020 is beyond recency_years=3 → stale_factor=0.75 kicks in.
    # score = 100 * (1 - (1 - 0.6 * 1.0 * 0.75)) = 45
    assert score([ev(1, published=date(2020, 1, 1))], set(), CFG, TODAY).confidence == 45


def test_undated_source_is_discounted_harsher_than_ancient():
    """An undated page is a bigger analytic hole than a known-ancient one: we do not know
    when the claim was true. The score must reflect that gap (post-audit fix)."""
    stale = score([ev(1, published=date(2020, 1, 1))], set(), CFG, TODAY).confidence
    undated = score([ev(1, published=None)], set(), CFG, TODAY).confidence
    # undated_factor=0.5 → 100 * (1 - (1 - 0.6 * 1.0 * 0.5)) = 30
    assert undated == 30
    assert undated < stale, "undated must score STRICTLY below ancient-but-dated"


def test_undated_factor_is_configurable():
    """Operator tightening undated_factor further must lower undated confidence; relaxing it
    (equal to stale_factor) must restore the old 'undated == ancient-dated' behaviour so a
    conservative shop can opt back in."""
    harsh = ScoringConfig(undated_factor=0.25)
    relaxed = ScoringConfig(undated_factor=0.75)  # = stale_factor
    harsh_score = score([ev(1, published=None)], set(), harsh, TODAY).confidence
    relaxed_score = score([ev(1, published=None)], set(), relaxed, TODAY).confidence
    ancient_score = score([ev(1, published=date(2020, 1, 1))], set(), CFG, TODAY).confidence
    assert harsh_score < 30 < relaxed_score == ancient_score


def test_most_recent_document_of_a_publisher_is_used():
    r = score([ev(1, published=date(2019, 1, 1)), ev(1, published=date(2026, 1, 1))], set(), CFG, TODAY)
    assert r.confidence == 60


def test_refutation_from_another_publisher_contests():
    r = score([ev(1), ev(2, polarity=Polarity.REFUTES)], set(), CFG, TODAY)
    assert r.status is AssessmentStatus.CONTESTED
    assert r.admiralty == "A4"
    assert r.confidence == 60


def test_refutation_from_a_supporting_publisher_does_not_contest():
    r = score([ev(1), ev(2), ev(2, polarity=Polarity.REFUTES)], set(), CFG, TODAY)
    assert r.status is AssessmentStatus.CORROBORATED


def test_low_reliability_refuter_does_not_contest_corroborated_fact():
    """A single F-grade refuter must not flip five A-grade corroborators to CONTESTED."""
    supporters = [ev(i, reliability="A") for i in range(1, 6)]
    low_refuter = ev(99, reliability="F", polarity=Polarity.REFUTES)
    r = score([*supporters, low_refuter], set(), CFG, TODAY)
    assert r.status is AssessmentStatus.CORROBORATED


def test_credible_refuter_still_contests():
    """A refuter whose reliability clears the threshold must still mark the fact CONTESTED."""
    supporters = [ev(1, reliability="A"), ev(2, reliability="A")]
    b_refuter = ev(99, reliability="B", polarity=Polarity.REFUTES)
    r = score([*supporters, b_refuter], set(), CFG, TODAY)
    assert r.status is AssessmentStatus.CONTESTED


def test_contested_min_weight_is_configurable():
    """Lowering the threshold makes an F refuter count again (opt-in strictness)."""
    cfg = ScoringConfig(contested_min_weight=0.0)
    supporters = [ev(1, reliability="A"), ev(2, reliability="A")]
    low_refuter = ev(99, reliability="F", polarity=Polarity.REFUTES)
    r = score([*supporters, low_refuter], set(), cfg, TODAY)
    assert r.status is AssessmentStatus.CONTESTED


def test_competing_attribution_contests():
    r = score([ev(1), ev(2)], {3}, CFG, TODAY)
    assert r.status is AssessmentStatus.CONTESTED


def test_only_refutations():
    r = score([ev(1, polarity=Polarity.REFUTES)], set(), CFG, TODAY)
    assert (r.confidence, r.status, r.admiralty) == (0, AssessmentStatus.CONTESTED, "F4")


def test_best_letter_and_seen_range():
    r = score(
        [
            ev(1, reliability="D", published=date(2025, 3, 1), observed=date(2023, 6, 1)),
            ev(2, reliability="B", published=date(2026, 2, 1)),
        ],
        set(), CFG, TODAY,
    )
    assert r.admiralty == "B2"
    assert r.first_seen == date(2023, 6, 1)
    assert r.last_seen == date(2026, 2, 1)


def test_half_values_round_up():
    # Test deterministic round-half-up. Use ancient-but-dated sources (stale_factor path) so
    # the expected values are decoupled from undated_factor tuning — the point of this test is
    # the rounding behaviour, not which factor the branch returns.
    ancient = date(2020, 1, 1)
    assert score([ev(1, reliability="C", published=ancient)], set(), CFG, TODAY).confidence == 32  # 31.5
    assert score([ev(1, reliability="E", published=ancient)], set(), CFG, TODAY).confidence == 14  # 13.5
    assert score([ev(1, reliability="D", published=ancient)], set(), CFG, TODAY).confidence == 23  # 22.5
    assert score([ev(1, reliability="F", published=ancient)], set(), CFG, TODAY).confidence == 23  # 22.5
    assert score([ev(1, reliability="B", published=ancient)], set(), CFG, TODAY).confidence == 38  # 38.25


def test_weaker_document_publisher_caps_a_stronger_primary_publisher():
    r = score([ev(1, reliability="B", document_reliability="E")], set(), CFG, TODAY)
    assert (r.confidence, r.admiralty) == (18, "E3")  # 0.6 * 0.3, not B's weight


def test_weight_not_letter_order_decides_which_reliability_applies():
    # F has a higher default weight (0.5) than E (0.3): the E side must win in both directions.
    primary_f = score([ev(1, reliability="F", document_reliability="E")], set(), CFG, TODAY)
    assert (primary_f.confidence, primary_f.admiralty) == (18, "E3")
    document_f = score([ev(1, reliability="E", document_reliability="F")], set(), CFG, TODAY)
    assert (document_f.confidence, document_f.admiralty) == (18, "E3")


def test_missing_document_reliability_leaves_scoring_unchanged():
    r = score([ev(1, reliability="B", document_reliability=None)], set(), CFG, TODAY)
    assert (r.confidence, r.admiralty) == (51, "B3")  # 0.6 * 0.85 = 0.51


def test_document_reliability_applies_to_the_latest_document_of_a_publisher():
    r = score(
        [
            ev(1, reliability="A", document_reliability="A", published=date(2025, 1, 1), claim_id=1),
            ev(1, reliability="A", document_reliability="D", published=date(2026, 1, 1), claim_id=2),
        ],
        set(), CFG, TODAY,
    )
    assert r.admiralty == "D3"  # the latest document is the one used, and its weaker host applies
