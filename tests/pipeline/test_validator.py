from datetime import date

import pytest

from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.knowledge.models import AssessmentStatus, ClaimDraft, Polarity, QuoteStatus
from cyllex_argus.pipeline.validator import Validator

SPIDER = "intrusion-set--00000000-0000-4000-8000-000000001015"
VOICE = "attack-pattern--00000000-0000-4000-8000-000015660004"
TEXT = (
    "Octo Tempest operators called the IT help desk and impersonated an employee to reset MFA. "
    "The group, also tracked as Muddled Libra by some vendors, later deployed BlackCat ransomware. "
    "The Operation Neon campaign was attributed to Scattered Spider by our analysts. "
    "Another vendor attributes it to Other Actor."
)


def _draft(**overrides):
    data = dict(
        subject="Octo Tempest", subject_type="intrusion-set", predicate="uses",
        object="Spearphishing Voice", object_type="attack-pattern",
        quote="called the IT help desk and impersonated an employee", technique_id="T1566.004",
    )
    data.update(overrides)
    return ClaimDraft(**data)


@pytest.fixture
def validator(attack_store, attack_catalog):
    return Validator(attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29))


@pytest.fixture
def add_doc(attack_store, new_doc):
    def factory(publisher="Mandiant", reliability="A"):
        doc, _ = attack_store.add_document(new_doc(publisher=publisher, reliability=reliability, text=TEXT))
        return doc
    return factory


def test_verified_technique_claim_creates_assessment(validator, attack_store, add_doc):
    summary = validator.process(add_doc(), [_draft()], "analyst-v1")
    assert (summary.accepted, summary.rejected) == (1, 0)
    assert summary.touched == {(SPIDER, "uses", VOICE)}
    [assessment] = attack_store.assessments_involving(SPIDER)
    assert assessment.object_entity_id == VOICE
    assert assessment.status is AssessmentStatus.SINGLE_SOURCE
    assert assessment.confidence == 60 and assessment.admiralty == "A3"




def test_fabricated_quote_is_stored_but_not_assessed(validator, attack_store, add_doc):
    doc = add_doc()
    summary = validator.process(doc, [_draft(quote="exfiltrated everything to a Russian server farm")], "v1")
    assert (summary.accepted, summary.rejected) == (0, 1)
    [claim] = attack_store.claims_for_document(doc.id)
    assert claim.quote_status is QuoteStatus.REJECTED
    assert attack_store.assessments_involving(SPIDER) == []


def test_unknown_or_missing_technique_is_rejected(validator, add_doc):
    doc = add_doc()
    summary = validator.process(doc, [_draft(technique_id="T0000"), _draft(technique_id=None)], "v1")
    assert (summary.accepted, summary.rejected) == (0, 2)


def test_claim_about_a_subject_the_document_never_mentions_is_rejected(validator, attack_store, add_doc):
    doc = add_doc()
    unrelated = _draft(subject="APT28", predicate="exploits", object="CVE-2099-0001",
                       object_type="vulnerability", technique_id=None, quote="later deployed BlackCat ransomware")
    summary = validator.process(doc, [unrelated], "v1")
    assert (summary.accepted, summary.rejected) == (0, 1)
    [claim] = attack_store.claims_for_document(doc.id)
    assert claim.quote_status is QuoteStatus.REJECTED
    assert attack_store.find_by_alias("APT28") is None  # a rejected claim creates no entity
    assert attack_store.find_by_alias("CVE-2099-0001") is None


def test_claim_about_an_object_the_document_never_mentions_is_rejected(validator, attack_store, add_doc):
    unrelated = _draft(predicate="exploits", object="CVE-2099-0001", object_type="vulnerability",
                       technique_id=None, quote="later deployed BlackCat ransomware")
    summary = validator.process(add_doc(), [unrelated], "v1")
    assert (summary.accepted, summary.rejected) == (0, 1)
    assert attack_store.assessments_involving(SPIDER) == []


def test_subject_named_by_a_known_alias_is_accepted(validator, attack_store, new_doc):
    text = "Octo Tempest operators called the IT help desk and impersonated an employee to reset MFA."
    doc, _ = attack_store.add_document(new_doc(text=text))
    summary = validator.process(doc, [_draft(subject="Scattered Spider")], "v1")
    assert (summary.accepted, summary.rejected) == (1, 0)
    [assessment] = attack_store.assessments_involving(SPIDER)
    assert assessment.object_entity_id == VOICE


def test_alias_claim_needs_the_new_name_verbatim_in_the_document(validator, attack_store, add_doc):
    doc = add_doc()
    # UNC3944 is a real alias of the same group, but this document never writes it.
    draft = _draft(subject="UNC3944", predicate="alias-of", object="Octo Tempest", object_type="intrusion-set",
                   technique_id=None, quote="also tracked as Muddled Libra by some vendors")
    summary = validator.process(doc, [draft], "v1")
    assert (summary.accepted, summary.rejected) == (0, 1)
    unmentioned_object = _draft(subject="Muddled Libra", predicate="alias-of", object="Wizard Spider",
                                object_type="intrusion-set", technique_id=None,
                                quote="also tracked as Muddled Libra by some vendors")
    summary = validator.process(doc, [unmentioned_object], "v1")
    assert (summary.accepted, summary.rejected) == (0, 1)
    assert attack_store.find_by_alias("Muddled Libra") is None
    assert attack_store.find_by_alias("Wizard Spider") is None


def test_alias_claims_teach_aliases_without_assessments(validator, attack_store, add_doc):
    draft = _draft(
        subject="Muddled Libra", predicate="alias-of", object="Octo Tempest",
        object_type="intrusion-set", technique_id=None, quote="also tracked as Muddled Libra by some vendors",
    )
    summary = validator.process(add_doc(), [draft], "v1")
    assert summary.accepted == 1 and summary.touched == set()
    assert attack_store.find_by_alias("Muddled Libra").id == SPIDER
    assert attack_store.assessments_involving(SPIDER) == []


def test_refuting_alias_claim_is_stored_but_teaches_no_alias(validator, attack_store, add_doc):
    doc = add_doc()
    draft = _draft(
        subject="Muddled Libra", predicate="alias-of", object="Octo Tempest", object_type="intrusion-set",
        technique_id=None, quote="also tracked as Muddled Libra by some vendors", polarity=Polarity.REFUTES,
    )
    summary = validator.process(doc, [draft], "v1")
    assert summary.accepted == 1
    [claim] = attack_store.claims_for_document(doc.id)
    assert claim.polarity is Polarity.REFUTES and claim.quote_status is QuoteStatus.VERIFIED
    assert attack_store.find_by_alias("Muddled Libra") is None


def test_malware_and_tool_types_are_compatible(validator, attack_store, add_doc):
    draft = _draft(object="BlackCat", object_type="tool", technique_id=None,
                   quote="later deployed BlackCat ransomware")
    validator.process(add_doc(), [draft], "v1")
    [assessment] = attack_store.assessments_involving(SPIDER)
    assert assessment.object_entity_id == "malware--00000000-0000-4000-8000-000000001068"


def test_two_publishers_corroborate(validator, attack_store, add_doc):
    validator.process(add_doc("Mandiant"), [_draft()], "v1")
    validator.process(add_doc("Microsoft"), [_draft()], "v1")
    [assessment] = attack_store.assessments_involving(SPIDER)
    assert assessment.status is AssessmentStatus.CORROBORATED
    assert assessment.confidence == 84


def test_competing_attributions_contest_each_other(validator, attack_store, add_doc):
    quote = "The Operation Neon campaign was attributed to Scattered Spider"
    attribution = dict(subject="Operation Neon", subject_type="campaign", predicate="attributed-to",
                       object_type="intrusion-set", technique_id=None, quote=quote)
    validator.process(add_doc("Vendor One"), [_draft(object="Scattered Spider", **attribution)], "v1")
    first = attack_store.assessments_involving(SPIDER)[0]
    assert first.status is AssessmentStatus.SINGLE_SOURCE
    validator.process(add_doc("Vendor Two"), [_draft(object="Other Actor", **attribution)], "v1")
    statuses = {a.object_entity_id: a.status for a in attack_store.assessments_involving(first.subject_entity_id)}
    assert set(statuses.values()) == {AssessmentStatus.CONTESTED}
    assert len(statuses) == 2


def test_refutation_from_another_publisher_contests(validator, attack_store, add_doc):
    validator.process(add_doc("Mandiant"), [_draft()], "v1")
    validator.process(add_doc("Microsoft"), [_draft(polarity=Polarity.REFUTES)], "v1")
    [assessment] = attack_store.assessments_involving(SPIDER)
    assert assessment.status is AssessmentStatus.CONTESTED


def test_reset_document_removes_its_evidence(validator, attack_store, add_doc):
    doc = add_doc()
    validator.process(doc, [_draft()], "v1")
    validator.reset_document(doc.id)
    assert attack_store.claims_for_document(doc.id) == []
    assert attack_store.assessments_involving(SPIDER) == []


def test_reset_document_recomputes_sibling_attributions(validator, attack_store, add_doc):
    quote = "The Operation Neon campaign was attributed to Scattered Spider"
    attribution = dict(subject="Operation Neon", subject_type="campaign", predicate="attributed-to",
                       object_type="intrusion-set", technique_id=None, quote=quote)
    validator.process(add_doc("Vendor One"), [_draft(object="Scattered Spider", **attribution)], "v1")
    second = add_doc("Vendor Two")
    validator.process(second, [_draft(object="Other Actor", **attribution)], "v1")
    campaign = attack_store.assessments_involving(SPIDER)[0].subject_entity_id
    assert {a.status for a in attack_store.assessments_involving(campaign)} == {AssessmentStatus.CONTESTED}

    validator.reset_document(second.id)

    [remaining] = attack_store.assessments_involving(campaign)
    assert remaining.object_entity_id == SPIDER
    assert remaining.status is AssessmentStatus.SINGLE_SOURCE


def test_untrusted_host_cannot_borrow_the_primary_publisher_reliability(validator, attack_store, new_doc):
    doc, _ = attack_store.add_document(new_doc(publisher="Random Blog", reliability="E", text=TEXT))
    mandiant = attack_store.get_or_create_publisher("Mandiant", default_reliability="A")
    attack_store.set_analysis(doc.id, mandiant.id, "v1")
    validator.process(doc, [_draft()], "v1")
    [assessment] = attack_store.assessments_involving(SPIDER)
    assert assessment.status is AssessmentStatus.SINGLE_SOURCE
    assert assessment.admiralty == "E3"
    assert assessment.confidence == 18
