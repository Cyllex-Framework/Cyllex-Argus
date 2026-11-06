from types import SimpleNamespace

from cyllex_argus.evaluation.keys import (
    check_expected,
    expected_claim_keys,
    is_ttp_key,
    score_ttp_claims,
    scored_claim_keys,
)
from cyllex_argus.evaluation.metrics import ClaimKey, make_key
from cyllex_argus.knowledge.names import normalize_name

_CANONICAL = {"octo tempest": "Scattered Spider", "0ktapus": "Scattered Spider"}
_TECHNIQUES = {"T1566.004": "T1566.004", "T1078": "T1078", "T1234": "T1078"}  # T1234: revoked, replaced


def resolve_name(name: str) -> str:
    return _CANONICAL.get(normalize_name(name), name)


def resolve_technique(technique_id: str) -> str | None:
    return _TECHNIQUES.get(technique_id.strip().upper())


def claim(**overrides):
    data = dict(
        subject_ref="Scattered Spider", predicate="uses", object_ref="BlackCat", object_type="malware",
        technique_id=None, polarity="asserts", quote_status="verified",
    )
    data.update(overrides)
    return SimpleNamespace(**data)


def keys_of(*claims, target="Scattered Spider"):
    return scored_claim_keys(claims, target, resolve_name, resolve_technique)


def test_verified_and_fuzzy_claims_are_kept():
    assert keys_of(claim(), claim(object_ref="Mimikatz", object_type="tool", quote_status="verified_fuzzy")) == {
        make_key("Scattered Spider", "uses", "BlackCat"),
        make_key("Scattered Spider", "uses", "Mimikatz"),
    }


def test_rejected_refuting_and_alias_claims_are_excluded():
    assert keys_of(
        claim(quote_status="rejected"),
        claim(object_ref="Mimikatz", polarity="refutes"),
        claim(predicate="alias-of", object_ref="Octo Tempest", object_type="intrusion-set"),
    ) == set()


def test_predicates_outside_the_labeling_contract_are_excluded():
    assert keys_of(
        claim(predicate="indicates", object_ref="BlackCat"),
        claim(predicate="variant-of", object_ref="ALPHV"),
    ) == set()


def test_all_scored_predicates_are_kept():
    keys = keys_of(
        claim(predicate="targets", object_ref="Retail", object_type="identity"),
        claim(predicate="exploits", object_ref="CVE-2015-2291", object_type="vulnerability"),
        claim(predicate="attributed-to", subject_ref="Operation Neon", object_ref="Scattered Spider",
              object_type="intrusion-set"),
    )
    assert {key.predicate for key in keys} == {"targets", "exploits", "attributed-to"}


def test_claims_about_other_entities_are_excluded():
    assert keys_of(claim(subject_ref="BlackCat", object_ref="Mimikatz", object_type="tool")) == set()


def test_the_target_as_object_is_kept():
    campaign = claim(
        subject_ref="Operation Neon", subject_type="campaign", predicate="attributed-to",
        object_ref="Scattered Spider", object_type="intrusion-set",
    )
    assert keys_of(campaign) == {make_key("Operation Neon", "attributed-to", "Scattered Spider")}


def test_target_is_matched_through_aliases():
    assert keys_of(claim(subject_ref="Octo Tempest"), target="0ktapus") == {
        make_key("Scattered Spider", "uses", "BlackCat")
    }


def test_technique_keys_use_the_resolved_attack_id_not_the_name():
    keys = keys_of(
        claim(object_ref="Spearphishing Voice", object_type="attack-pattern", technique_id="t1566.004"),
        claim(object_ref="Valid Accounts (old)", object_type="attack-pattern", technique_id="T1234"),
    )
    assert keys == {
        make_key("Scattered Spider", "uses", "T1566.004"),
        make_key("Scattered Spider", "uses", "T1078"),
    }


def test_unresolvable_technique_falls_back_to_the_raw_id():
    keys = keys_of(claim(object_ref="Made Up", object_type="attack-pattern", technique_id="T9999"))
    assert keys == {make_key("Scattered Spider", "uses", "T9999")}


def _entry(**overrides):
    data = {"subject": "Scattered Spider", "predicate": "uses", "object": "BlackCat", "object_type": "malware"}
    data.update(overrides)
    return data


def test_expected_labels_use_the_same_keys_as_predictions():
    entries = [
        _entry(),
        _entry(subject="Octo Tempest", object="Spearphishing Voice", object_type="attack-pattern",
               technique_id="T1566.004"),
    ]
    assert expected_claim_keys(entries, "Scattered Spider", resolve_name, resolve_technique) == {
        make_key("Scattered Spider", "uses", "BlackCat"),
        make_key("Scattered Spider", "uses", "T1566.004"),
    }


def test_mislabeled_entries_are_excluded_and_reported():
    entries = [
        _entry(),
        _entry(predicate="indicates", object="1.2.3.4", object_type="indicator"),
        _entry(subject="BlackCat", object="Mimikatz", object_type="tool"),
        _entry(object="Mimikatz", object_type="tool", polarity="refutes"),
    ]
    keys, warnings = check_expected(entries, "Scattered Spider", resolve_name, resolve_technique)
    assert keys == {make_key("Scattered Spider", "uses", "BlackCat")}
    assert len(warnings) == 3
    assert "indicates" in warnings[0] and "1.2.3.4" in warnings[0]
    assert "neither subject nor object" in warnings[1] and "BlackCat uses Mimikatz" in warnings[1]
    assert "refutes" in warnings[2]


def test_a_clean_label_set_has_no_warnings():
    assert check_expected([_entry()], "Scattered Spider", resolve_name, resolve_technique)[1] == []


def test_is_ttp_key():
    assert is_ttp_key(make_key("A", "uses", "T1566.004"))
    assert is_ttp_key(make_key("A", "uses", "t1078"))
    assert is_ttp_key(ClaimKey("a", "uses", "T1566.004"))
    assert not is_ttp_key(make_key("A", "targets", "T1078"))
    assert not is_ttp_key(make_key("A", "uses", "BlackCat"))
    assert not is_ttp_key(make_key("A", "uses", "T10"))
    assert not is_ttp_key(make_key("A", "uses", "T1566.0041"))


def test_ttp_score_only_counts_technique_use_claims():
    expected = {
        make_key("A", "uses", "T1"), make_key("A", "uses", "T1566.004"), make_key("A", "uses", "T1078"),
        make_key("A", "uses", "BlackCat"), make_key("A", "targets", "Retail"),
    }
    predicted = {
        make_key("A", "uses", "T1566.004"), make_key("A", "uses", "T9999"),
        make_key("A", "uses", "BlackCat"), make_key("A", "targets", "Retail"),
    }
    ttp = score_ttp_claims(predicted, expected)
    assert (ttp.true_positives, ttp.predicted, ttp.expected) == (1, 2, 2)
    assert ttp.recall == 0.5
