from datetime import date

from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.knowledge.models import AliasOrigin, ClaimDraft
from cyllex_argus.knowledge.profile import build_profile
from cyllex_argus.pipeline.validator import Validator
from tests.support import QUOTE, SPIDER


def test_profile_lists_facts_with_citations(attack_store, attack_catalog, new_doc):
    doc, _ = attack_store.add_document(new_doc(publisher="Mandiant", text=f"Scattered Spider {QUOTE}."))
    draft = ClaimDraft(
        subject="Scattered Spider", subject_type="intrusion-set", predicate="uses",
        object="Spearphishing Voice", object_type="attack-pattern", quote=QUOTE, technique_id="T1566.004",
    )
    Validator(attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29)).process(doc, [draft], "v1")
    profile = build_profile(attack_store, attack_store.get_entity(SPIDER))
    assert profile.entity.name == "Scattered Spider"
    assert "UNC3944" in profile.aliases
    [fact] = profile.facts
    assert fact.object.label == "Spearphishing Voice (T1566.004)"
    assert fact.source_count == 1
    assert profile.entity.attack is True
    assert fact.object.attack is True
    assert fact.citations[0].publisher == "Mandiant"
    assert attack_store.assessment_keys() == {(SPIDER, "uses", fact.object.id)}


def test_profile_marks_entities_that_do_not_come_from_attack(attack_store):
    custom = attack_store.create_entity("malware", "Custom Loader", AliasOrigin.DOCUMENT)
    profile = build_profile(attack_store, custom)
    assert profile.entity.attack is False
    assert profile.entity.name == "Custom Loader"
