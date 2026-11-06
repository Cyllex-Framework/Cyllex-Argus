"""Behaviour of the STIX 2.1 ingest: dedupe, aliases, identity tagging, relationships, idempotency."""

from __future__ import annotations

import json

import httpx
import pytest

from cyllex_argus.config.settings import ArgusConfig, get_paths
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.importers import import_stix_bundle
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.llm.fake import FakeLLMProvider
from cyllex_argus.services import Services
from tests.support import _public_resolver

BUNDLE = {
    "type": "bundle",
    "id": "bundle--11111111-2222-3333-4444-555555555555",
    "created": "2024-06-01T00:00:00Z",
    "objects": [
        {
            "type": "intrusion-set", "id": "intrusion-set--aaaa",
            "name": "Scattered Spider",
            "aliases": ["UNC3944", "Octo Tempest"],
        },
        {
            "type": "malware", "id": "malware--bbbb",
            "name": "BlackCat",
        },
        {
            "type": "attack-pattern", "id": "attack-pattern--cccc",
            "name": "Phishing: Voice",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566.004"},
            ],
        },
        {
            "type": "identity", "id": "identity--dddd",
            "name": "Caesars Entertainment",
            "identity_class": "organization",
            "sectors": ["gaming"],
            "extensions": {
                "x-location-ext": {"country": "US"},
            },
        },
        {
            "type": "relationship", "id": "relationship--eeee",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--aaaa", "target_ref": "malware--bbbb",
        },
        {
            "type": "relationship", "id": "relationship--ffff",
            "relationship_type": "targets",
            "source_ref": "intrusion-set--aaaa", "target_ref": "identity--dddd",
        },
        {
            "type": "relationship", "id": "relationship--gggg",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--aaaa", "target_ref": "attack-pattern--cccc",
        },
        # An unsupported SDO type: should be skipped, not fail the whole import.
        {"type": "course-of-action", "id": "course-of-action--xxxx", "name": "Patch everything"},
        # An unsupported relationship type.
        {
            "type": "relationship", "id": "relationship--hhhh",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--xxxx", "target_ref": "attack-pattern--cccc",
        },
    ],
}


@pytest.fixture
def services(tmp_path):
    paths = get_paths(tmp_path / "home")
    paths.ensure()
    http = httpx.Client()
    svc = Services(
        paths=paths, config=ArgusConfig(feeds=[]),
        store=SQLiteStore(paths.db_file),
        llm=FakeLLMProvider(lambda r: {}),
        http=http,
        fetcher=Fetcher(http, max_bytes=100_000, sleep=lambda s: None, resolve_host=_public_resolver),
    )
    yield svc
    svc.close()


@pytest.fixture
def bundle_file(tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(BUNDLE), encoding="utf-8")
    return path


def test_import_adds_entities_aliases_and_claims(services, bundle_file):
    report = import_stix_bundle(services, bundle_file)
    assert report.bundle_id == "bundle--11111111-2222-3333-4444-555555555555"
    assert report.entities_added == 4   # intrusion-set, malware, attack-pattern, identity
    assert report.aliases_added == 2    # UNC3944, Octo Tempest
    assert report.claims_added == 3     # uses malware, targets identity, uses attack-pattern
    assert report.identities_tagged == 1
    # Aliases are reachable.
    actor = services.store.find_by_alias("UNC3944")
    assert actor is not None and actor.canonical_name == "Scattered Spider"
    assert services.store.find_by_alias("Octo Tempest").id == actor.id


def test_import_tags_identity_sector_and_country(services, bundle_file):
    import_stix_bundle(services, bundle_file)
    identity = services.store.find_by_alias("Caesars Entertainment")
    assert identity is not None
    assert identity.attributes.get("sector") == "gaming"
    assert identity.attributes.get("country") == "US"


def test_import_dedupes_attack_patterns_by_external_id(services, bundle_file):
    from cyllex_argus.knowledge.models import AliasOrigin
    # Seed an existing ATT&CK technique with the same external_id but a slightly different name.
    services.store.create_entity(
        "attack-pattern", "Spearphishing Voice", AliasOrigin.ATTACK,
        external_id="T1566.004", entity_id="attack-pattern--pre-existing",
    )
    report = import_stix_bundle(services, bundle_file)
    # The attack-pattern in the bundle must match the existing one, not create a sibling.
    assert report.entities_matched >= 1
    technique = services.store.find_by_external_id("T1566.004")
    assert technique.id == "attack-pattern--pre-existing"


def test_import_is_idempotent(services, bundle_file):
    first = import_stix_bundle(services, bundle_file)
    second = import_stix_bundle(services, bundle_file)
    # First run creates everything; second finds everything.
    assert second.entities_added == 0
    assert second.entities_matched >= first.entities_added


def test_import_reports_skipped_items_without_failing(services, bundle_file):
    report = import_stix_bundle(services, bundle_file)
    assert any("course-of-action" in s for s in report.skipped)
    assert any("mitigates" in s for s in report.skipped)


def test_import_rejects_non_bundle_input(services, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"type": "not-a-bundle"}', encoding="utf-8")
    with pytest.raises(ValueError, match="not a STIX bundle"):
        import_stix_bundle(services, bad)


def test_import_rejects_non_json_input(services, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("<html>nope</html>", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        import_stix_bundle(services, bad)
