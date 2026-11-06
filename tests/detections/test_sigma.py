"""Sigma rule generation from a threat profile."""

from __future__ import annotations

from datetime import date

from cyllex_argus.detections.sigma import (
    SigmaRule,
    _classify_ioc,
    _emit,
    _level,
    _scalar,
    generate,
    sigmahq_references,
)
from cyllex_argus.knowledge.models import AssessmentStatus
from cyllex_argus.knowledge.profile import EntityRef, FactView, Profile


def _ref(stix_type: str, name: str, external_id: str | None = None) -> EntityRef:
    return EntityRef(id=f"{stix_type}--{name}", stix_type=stix_type, name=name, external_id=external_id)


def _fact(subject: EntityRef, predicate: str, obj: EntityRef, confidence: int = 60, status: str = "single-source") -> FactView:
    return FactView(
        subject=subject, predicate=predicate, object=obj,
        status=AssessmentStatus(status), confidence=confidence, admiralty="B2",
        citations=[],
    )


# -- IOC classification -----------------------------------------------------------------


def test_ipv4_maps_to_firewall_logsource():
    ls, det = _classify_ioc("185.220.101.5")
    assert ls == {"category": "firewall", "product": "any"}
    assert det["selection"]["dst_ip"] == "185.220.101.5"


def test_refanged_ip_still_matches():
    """APT reports write 185[.]220[.]101[.]5 to defang. Sigma rules need the real IP."""
    ls, _ = _classify_ioc("185[.]220[.]101[.]5")
    assert ls["category"] == "firewall"


def test_url_maps_to_proxy_logsource():
    ls, det = _classify_ioc("http://evil.example/payload")
    assert ls == {"category": "proxy", "product": "any"}
    assert det["selection"]["cs-uri"] == "http://evil.example/payload"


def test_sha256_hash_maps_to_file_event():
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ls, det = _classify_ioc(sha)
    assert ls["category"] == "file_event"
    assert det["selection"]["Hashes|contains"] == f"SHA256={sha.lower()}"


def test_md5_hash_maps_to_file_event():
    md5 = "9e107d9d372bb6826bd81d3542a419d6"
    _, det = _classify_ioc(md5)
    assert det["selection"]["Hashes|contains"] == f"MD5={md5.lower()}"


def test_domain_maps_to_dns_query():
    ls, det = _classify_ioc("c2.evil-example.com")
    assert ls == {"category": "dns_query", "product": "windows"}
    assert det["selection"]["QueryName"] == "c2.evil-example.com"


def test_unknown_shape_returns_none():
    ls, det = _classify_ioc("not-an-ioc not-at-all")
    assert ls is None and det is None


# -- level mapping ---------------------------------------------------------------------


def test_contested_never_crosses_low():
    assert _level(95, "contested") == "low"


def test_corroborated_high_confidence_is_high():
    assert _level(80, "corroborated") == "high"


def test_moderate_band_is_medium():
    assert _level(60, "single-source") == "medium"


def test_below_50_is_low():
    assert _level(30, "single-source") == "low"


# -- generate() end-to-end -------------------------------------------------------------


def test_generate_emits_one_rule_per_ioc():
    actor = _ref("intrusion-set", "ZetaActor")
    profile = Profile(entity=actor, aliases=["Zeta"], facts=[
        _fact(actor, "uses", _ref("indicator", "185.220.101.5"), confidence=80, status="corroborated"),
        _fact(actor, "uses", _ref("indicator", "c2.evil.example"), confidence=60),
    ])
    rules = generate(profile)
    assert {r.logsource["category"] for r in rules} == {"firewall", "dns_query"}


def test_ioc_rule_tags_the_actor_group_not_every_technique():
    """An IOC rule must not inherit every technique the actor uses (a hash is not 'Proxy'). It
    carries the actor's ATT&CK group tag, which is what the indicator is actually attributed to."""
    actor = _ref("intrusion-set", "Volt Typhoon", external_id="G1017")
    ip = _ref("indicator", "209.200.83.43")
    technique = _ref("attack-pattern", "Proxy", external_id="T1090")
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(ip, "indicates", actor),
        _fact(actor, "uses", technique),
    ])
    rule = generate(profile)[0]
    assert rule.tags == ("attack.g1017",)             # the group, not the technique dump
    assert "attack.t1090" not in rule.tags


def test_ioc_rule_without_a_group_id_has_no_technique_dump():
    actor = _ref("intrusion-set", "NoGroupActor")      # no external_id
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(_ref("indicator", "1.2.3.4"), "indicates", actor),
        _fact(actor, "uses", _ref("attack-pattern", "Proxy", external_id="T1090")),
    ])
    assert generate(profile)[0].tags == ()


def test_ioc_description_is_type_aware():
    actor = _ref("intrusion-set", "ZetaActor")
    ip = generate(Profile(entity=actor, aliases=[], facts=[_fact(_ref("indicator", "1.2.3.4"), "indicates", actor)]))[0]
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    file = generate(Profile(entity=actor, aliases=[], facts=[_fact(_ref("indicator", sha), "indicates", actor)]))[0]
    assert "network connection" in ip.description.lower()      # an IP is traffic, named as such
    assert "file" in file.description.lower() and "traffic" not in file.description.lower()  # a hash is a file, not traffic


def test_ioc_rule_level_floors_at_medium():
    """A tracked IOC match is high-fidelity regardless of how strong the attribution is, so an IOC
    rule is never 'low' (which gets it ignored); a corroborated, high-confidence IOC is 'high'."""
    actor = _ref("intrusion-set", "APT29", external_id="G0016")
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(_ref("indicator", "1.2.3.4"), "indicates", actor, confidence=30, status="single-source"),
        _fact(_ref("indicator", "5.6.7.8"), "indicates", actor, confidence=85, status="corroborated"),
    ])
    by_value = {r.title.split()[1]: r.level for r in generate(profile)}
    assert by_value["1.2.3.4"] == "medium"   # floored up from 'low'
    assert by_value["5.6.7.8"] == "high"


def test_generate_handles_an_indicator_that_points_at_the_actor():
    """Real data links IOCs as `indicator --indicates--> actor` (the IOC is the SUBJECT), not only
    `actor --uses--> indicator`. Both directions must produce a rule."""
    actor = _ref("intrusion-set", "APT29")
    ip = _ref("indicator", "209.200.83.43")
    domain = _ref("indicator", "avsvmcloud[.]com")
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(ip, "indicates", actor, confidence=60),
        _fact(domain, "indicates", actor, confidence=40),
    ])
    rules = generate(profile)
    assert {r.logsource["category"] for r in rules} == {"firewall", "dns_query"}


def test_generate_skips_iocs_with_unknown_shape():
    actor = _ref("intrusion-set", "ZetaActor")
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(actor, "uses", _ref("indicator", "just some free text that is not an IOC")),
    ])
    assert generate(profile) == []


def test_generate_ignores_techniques_and_emits_only_ioc_rules():
    """Techniques are no longer turned into rules; they become SigmaHQ references instead.
    generate() emits one rule per IOC and nothing for a technique."""
    actor = _ref("intrusion-set", "ZetaActor")
    technique = _ref("attack-pattern", "LSASS Memory", external_id="T1003.001")
    ip = _ref("indicator", "185.220.101.5")
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(actor, "uses", technique, confidence=70, status="corroborated"),
        _fact(actor, "uses", ip, confidence=80, status="corroborated"),
    ])
    rules = generate(profile)
    assert [r.logsource["category"] for r in rules] == ["firewall"]  # the IOC only; no technique rule


def test_generate_without_iocs_is_empty():
    actor = _ref("intrusion-set", "ZetaActor")
    technique = _ref("attack-pattern", "LSASS Memory", external_id="T1003.001")
    profile = Profile(entity=actor, aliases=[], facts=[_fact(actor, "uses", technique)])
    assert generate(profile) == []


def test_generate_deduplicates_the_same_ioc_name():
    actor = _ref("intrusion-set", "ZetaActor")
    ip = _ref("indicator", "185.220.101.5")
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(actor, "uses", ip),
        _fact(actor, "uses", ip),
    ])
    assert len(generate(profile)) == 1


def test_rule_id_is_deterministic_for_the_same_ioc():
    """Running `argus generate-detections` twice must produce the same Sigma `id` so downstream
    systems can detect the file as 'already there' instead of as a new rule."""
    actor = _ref("intrusion-set", "ZetaActor")
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(actor, "uses", _ref("indicator", "185.220.101.5")),
    ])
    r1, r2 = generate(profile), generate(profile)
    assert r1[0].id == r2[0].id


# -- YAML emitter ----------------------------------------------------------------------


def test_scalar_quotes_strings_with_colons():
    assert _scalar("key: value") == "'key: value'"


def test_scalar_quotes_strings_starting_with_dash():
    assert _scalar("-leading dash") == "'-leading dash'"


def test_scalar_leaves_plain_strings_unquoted():
    assert _scalar("hello") == "hello"


def test_emit_renders_nested_dict_with_two_space_indent():
    out = _emit({"detection": {"selection": {"field": "value"}, "condition": "selection"}})
    assert "detection:" in out
    assert "  selection:" in out
    assert "    field: value" in out
    assert "  condition: selection" in out


def test_emit_renders_lists_with_dash_prefix():
    out = _emit({"tags": ["attack.t1003", "attack.t1055"]})
    assert "- attack.t1003" in out
    assert "- attack.t1055" in out


def test_rule_to_yaml_is_valid_shape():
    rule = SigmaRule(
        id="abc", title="t", description="d", author="a", date=date(2026, 1, 1),
        references=(), tags=("attack.t1003",),
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"Image|endswith": "\\mimikatz.exe"}, "condition": "selection"},
        falsepositives=("admin tools",), level="high",
    )
    yaml = rule.to_yaml()
    # Spot checks: the known-tricky lines are present and shaped right.
    assert "title: t" in yaml
    assert "- attack.t1003" in yaml
    assert "logsource:" in yaml
    assert "  category: process_creation" in yaml
    assert "detection:" in yaml
    assert "  condition: selection" in yaml
    assert "level: high" in yaml
    # The Mimikatz-like value starts with a backslash — must be quoted so YAML parses it.
    assert "'\\mimikatz.exe'" in yaml


# -- SigmaHQ references (techniques link to the community's vetted rules) ---------------

def test_sigmahq_references_link_each_observed_technique():
    actor = _ref("intrusion-set", "APT29")
    profile = Profile(entity=actor, aliases=[], facts=[
        _fact(actor, "uses", _ref("attack-pattern", "LSASS Memory", external_id="T1003.001")),
        _fact(actor, "uses", _ref("attack-pattern", "Additional Cloud Credentials", external_id="T1098.001")),
    ])
    refs = sigmahq_references(profile)
    assert [r.technique_id for r in refs] == ["T1003.001", "T1098.001"]  # sorted, deduped
    lsass = refs[0]
    assert lsass.technique_name == "LSASS Memory"
    assert lsass.count > 0 and lsass.rules                               # the bundled index has rules for it
    assert lsass.rules[0].url.startswith("https://github.com/SigmaHQ/sigma/blob/")
    assert "attack.t1003.001" in lsass.browse_url                        # the search fallback carries the tag


def test_sigmahq_references_dedupe_the_same_technique():
    actor = _ref("intrusion-set", "APT29")
    t = _ref("attack-pattern", "LSASS Memory", external_id="T1003.001")
    profile = Profile(entity=actor, aliases=[], facts=[_fact(actor, "uses", t), _fact(actor, "uses", t)])
    assert len(sigmahq_references(profile)) == 1


def test_sigmahq_references_empty_without_techniques():
    actor = _ref("intrusion-set", "APT29")
    profile = Profile(entity=actor, aliases=[], facts=[_fact(actor, "uses", _ref("indicator", "1.2.3.4"))])
    assert sigmahq_references(profile) == []
