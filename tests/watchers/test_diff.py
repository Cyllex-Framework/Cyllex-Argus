"""The deterministic watcher diff engine."""

from cyllex_argus.knowledge.models import AssessmentStatus, ChangeKind, Citation, Polarity, QuoteStatus
from cyllex_argus.knowledge.profile import EntityRef, FactView
from cyllex_argus.watchers.diff import diff, snapshot_of

S, C, X = AssessmentStatus.SINGLE_SOURCE, AssessmentStatus.CORROBORATED, AssessmentStatus.CONTESTED


def _cit(pub="CISA", polarity=Polarity.ASSERTS):
    return Citation(claim_id=1, quote="q", quote_status=QuoteStatus.VERIFIED, polarity=polarity,
                    document_title="Advisory", publisher=pub)


def _fact(subj="APT29", pred="uses", obj="WellMess", status=C, admiralty="B2", citations=None):
    return FactView(
        subject=EntityRef(id=subj, stix_type="intrusion-set", name=subj), predicate=pred,
        object=EntityRef(id=obj, stix_type="malware", name=obj), status=status, confidence=70,
        admiralty=admiralty, citations=citations if citations is not None else [_cit()],
    )


def _key(f):
    return f"{f.subject.id}|{f.predicate}|{f.object.id}"


def test_snapshot_of_keys_by_triple():
    f = _fact()
    assert snapshot_of([f]) == {_key(f): C}


def test_new_fact_when_absent_in_previous():
    f = _fact()
    out = diff({}, [f], min_reliability="C", baseline=False)
    assert [c.kind for c in out] == [ChangeKind.NEW]
    assert out[0].to_status is C
    assert out[0].object == "WellMess"
    assert out[0].citation is not None


def test_verified_on_single_to_corroborated():
    f = _fact(status=C)
    out = diff({_key(f): S}, [f], min_reliability="C", baseline=False)
    assert [c.kind for c in out] == [ChangeKind.VERIFIED]
    assert out[0].from_status is S and out[0].to_status is C


def test_contested_on_move_to_contested():
    f = _fact(status=X)
    out = diff({_key(f): C}, [f], min_reliability="C", baseline=False)
    assert [c.kind for c in out] == [ChangeKind.CONTESTED]


def test_weakened_on_corroborated_to_single():
    f = _fact(status=S)
    out = diff({_key(f): C}, [f], min_reliability="C", baseline=False)
    assert [c.kind for c in out] == [ChangeKind.WEAKENED]


def test_unchanged_emits_nothing():
    f = _fact(status=C)
    assert diff({_key(f): C}, [f], min_reliability="C", baseline=False) == []


def test_below_floor_excluded():
    f = _fact(admiralty="D2")  # D is below the C floor
    assert diff({}, [f], min_reliability="C", baseline=False) == []


def test_corroborated_with_refuter_citation_no_change():
    # Scoring already decided this stays CORROBORATED despite a refuter; the diff sees only the
    # final status, so an unchanged status yields no event.
    f = _fact(status=C, citations=[_cit(), _cit(pub="Blog", polarity=Polarity.REFUTES)])
    assert diff({_key(f): C}, [f], min_reliability="C", baseline=False) == []


def test_baseline_caps_and_prefers_reliability():
    strong = [_fact(obj=f"A{i}", admiralty="A1") for i in range(2)]
    weak = [_fact(obj=f"C{i}", admiralty="C2") for i in range(30)]
    out = diff({}, strong + weak, min_reliability="C", baseline=True, baseline_cap=25)
    assert len(out) == 25
    assert all(c.kind is ChangeKind.NEW for c in out)
    objs = {c.object for c in out}
    assert "A0" in objs and "A1" in objs  # the A-grade facts survived the cap
