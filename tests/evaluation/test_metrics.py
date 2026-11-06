from cyllex_argus.evaluation.metrics import Score, make_key, score_claims


def test_keys_are_normalized():
    assert make_key("Scattered Spider", "uses", "T1566.004") == make_key("scattered-spider", "uses", "t1566.004")


def test_precision_and_recall():
    expected = {make_key("A", "uses", "T1"), make_key("A", "uses", "T2"), make_key("A", "uses", "T3")}
    predicted = {make_key("A", "uses", "T1"), make_key("A", "uses", "T9")}
    score = score_claims(predicted, expected)
    assert (score.true_positives, score.predicted, score.expected) == (1, 2, 3)
    assert score.precision == 0.5
    assert round(score.recall, 3) == 0.333


def test_empty_sets():
    score = score_claims(set(), set())
    assert score.precision == 0.0 and score.recall == 0.0


def test_scores_add_up_micro_average():
    total = Score(1, 2, 3) + Score(3, 3, 5)
    assert (total.true_positives, total.predicted, total.expected) == (4, 5, 8)
    assert total.precision == 0.8 and total.recall == 0.5
