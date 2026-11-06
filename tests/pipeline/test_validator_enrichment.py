"""Validator fires every enabled enricher that accepts a claim's indicator.

Covers both the IOC path (`indicates` claim, IOC is the subject) and the vulnerability path
(`exploits` claim, CVE is the object). An observable type the detector cannot classify is skipped
silently so the pipeline never fails because enrichment inferred nothing.
"""

from __future__ import annotations

from datetime import date

import pytest

from cyllex_argus.config.settings import EnricherConfig, EnrichmentConfig, ScoringConfig
from cyllex_argus.enrichment import (
    EnrichmentFinding,
    EnrichmentRequest,
    EnrichmentResult,
    EnrichmentRunner,
)
from cyllex_argus.knowledge.models import (
    AliasOrigin,
    ClaimDraft,
    Polarity,
)
from cyllex_argus.pipeline.validator import Validator


class RecordingEnricher:
    """Captures every call so the test can assert on what the Validator asked for."""

    def __init__(self, name: str, supported: tuple[str, ...]) -> None:
        self.name = name
        self.description = ""
        self.outbound = ""
        self.supported_types = supported
        self.calls: list[EnrichmentRequest] = []

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult:
        self.calls.append(request)
        return EnrichmentResult(
            request=request,
            findings=[EnrichmentFinding(source=self.name, key="k", value=request.indicator)],
            duration_ms=1,
        )


@pytest.fixture
def actor(attack_store):
    return attack_store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.ATTACK)


@pytest.fixture
def doc(attack_store, new_doc, text):
    doc, _ = attack_store.add_document(new_doc(text=text))
    return doc


@pytest.fixture
def text():
    # The validator demands the subject and object both appear in the document body.
    return (
        "The actor's C2 beacon called out to evil.example and 93.184.216.34. "
        "They exploited CVE-2024-12345 to drop their loader. Scattered Spider operators were persistent."
    )


def _make_validator(attack_store, attack_catalog, enricher, enabled_names):
    cfg = EnrichmentConfig(enrichers={name: EnricherConfig(enabled=True) for name in enabled_names})
    def factory(_investigation_id):
        return EnrichmentRunner(cfg, {enricher.name: enricher})
    return Validator(
        attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29),
        enrichment_factory=factory,
    )


def test_indicates_claim_with_domain_fires_a_domain_enricher(attack_store, attack_catalog, actor, doc, text):
    enricher = RecordingEnricher("stub-domain", supported=("domain-name",))
    validator = _make_validator(attack_store, attack_catalog, enricher, [enricher.name])
    draft = ClaimDraft(
        subject="evil.example", subject_type="indicator", predicate="indicates",
        object="Scattered Spider", object_type="intrusion-set", polarity=Polarity.ASSERTS,
        quote="The actor's C2 beacon called out to evil.example and 93.184.216.34.",
    )
    summary = validator.process(doc, [draft], "p-v1")
    assert summary.accepted == 1 and summary.rejected == 0
    assert [c.indicator for c in enricher.calls] == ["evil.example"]
    assert enricher.calls[0].indicator_type == "domain-name"


def test_indicates_claim_with_ipv4_fires_an_ipv4_enricher(attack_store, attack_catalog, actor, doc, text):
    enricher = RecordingEnricher("stub-ipv4", supported=("ipv4-addr",))
    validator = _make_validator(attack_store, attack_catalog, enricher, [enricher.name])
    draft = ClaimDraft(
        subject="93.184.216.34", subject_type="indicator", predicate="indicates",
        object="Scattered Spider", object_type="intrusion-set", polarity=Polarity.ASSERTS,
        quote="The actor's C2 beacon called out to evil.example and 93.184.216.34.",
    )
    validator.process(doc, [draft], "p-v1")
    assert len(enricher.calls) == 1
    assert enricher.calls[0].indicator_type == "ipv4-addr"


def test_exploits_claim_fires_a_vulnerability_enricher(attack_store, attack_catalog, actor, doc, text):
    enricher = RecordingEnricher("stub-nvd", supported=("vulnerability",))
    validator = _make_validator(attack_store, attack_catalog, enricher, [enricher.name])
    cve_entity = attack_store.create_entity("vulnerability", "CVE-2024-12345", AliasOrigin.DOCUMENT)
    draft = ClaimDraft(
        subject="Scattered Spider", subject_type="intrusion-set", predicate="exploits",
        object="CVE-2024-12345", object_type="vulnerability", polarity=Polarity.ASSERTS,
        quote="They exploited CVE-2024-12345 to drop their loader.",
    )
    validator.process(doc, [draft], "p-v1")
    assert [c.indicator for c in enricher.calls] == ["CVE-2024-12345"]
    assert enricher.calls[0].indicator_type == "vulnerability"
    assert cve_entity.id   # kept to silence an unused-local lint; the entity existing lets the resolver match


def test_disabled_enricher_is_not_called_even_when_wired(attack_store, attack_catalog, actor, doc):
    """An enricher wired into the factory but disabled in config must stay silent."""
    enricher = RecordingEnricher("stub-domain", supported=("domain-name",))
    cfg = EnrichmentConfig(enrichers={enricher.name: EnricherConfig(enabled=False)})
    def factory(_inv):
        return EnrichmentRunner(cfg, {enricher.name: enricher})
    validator = Validator(
        attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29),
        enrichment_factory=factory,
    )
    draft = ClaimDraft(
        subject="evil.example", subject_type="indicator", predicate="indicates",
        object="Scattered Spider", object_type="intrusion-set", polarity=Polarity.ASSERTS,
        quote="The actor's C2 beacon called out to evil.example and 93.184.216.34.",
    )
    validator.process(doc, [draft], "p-v1")
    assert enricher.calls == []


def test_unclassifiable_subject_skips_enrichment_without_erroring(attack_store, attack_catalog, actor, doc):
    enricher = RecordingEnricher("stub-domain", supported=("domain-name",))
    validator = _make_validator(attack_store, attack_catalog, enricher, [enricher.name])
    draft = ClaimDraft(
        subject="bare-word", subject_type="indicator", predicate="indicates",
        object="Scattered Spider", object_type="intrusion-set", polarity=Polarity.ASSERTS,
        quote="The actor's C2 beacon called out to evil.example and 93.184.216.34.",
    )
    # 'bare-word' is not a URL, IP, hash, CVE or multi-label hostname — detect returns None.
    summary = validator.process(doc, [draft], "p-v1")
    # The claim may still be accepted or rejected by the Validator's name-mention check; the
    # point of the test is that enrichment is not called, not what the claim's fate is.
    assert enricher.calls == []
    assert summary.accepted + summary.rejected == 1


def test_validator_without_a_factory_is_the_default_and_calls_nothing(attack_store, attack_catalog, actor, doc):
    """Existing deployments that construct Validator without the kwarg keep the old no-enrichment behaviour."""
    validator = Validator(attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29))
    draft = ClaimDraft(
        subject="evil.example", subject_type="indicator", predicate="indicates",
        object="Scattered Spider", object_type="intrusion-set", polarity=Polarity.ASSERTS,
        quote="The actor's C2 beacon called out to evil.example and 93.184.216.34.",
    )
    summary = validator.process(doc, [draft], "p-v1")
    assert summary.rejected + summary.accepted == 1   # no exception; nothing wired, nothing fires
