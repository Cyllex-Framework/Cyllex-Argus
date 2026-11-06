from datetime import date
from pathlib import Path

import pytest

from cyllex_argus.attack.catalog import AttackCatalog, load_catalog_into_store
from cyllex_argus.knowledge.models import NewDocument
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from tests.support import World


@pytest.fixture
def store(tmp_path):
    s = SQLiteStore(tmp_path / "argus.db")
    yield s
    s.close()


@pytest.fixture
def new_doc(store):
    counter = {"n": 0}

    def factory(**overrides) -> NewDocument:
        counter["n"] += 1
        n = counter["n"]
        publisher = store.get_or_create_publisher(
            overrides.pop("publisher", "Mandiant"),
            default_reliability=overrides.pop("reliability", "F"),
        )
        data = {
            "url": f"https://example.com/report-{n}",
            "canonical_url": f"https://example.com/report-{n}",
            "title": f"Report {n}",
            "publisher_id": publisher.id,
            "published_at": date(2025, 1, 10),
            "content_hash": f"hash-{n}",
            "raw_path": f"raw/hash-{n}",
            "text": "Some text",
        }
        data.update(overrides)
        return NewDocument(**data)

    return factory


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def attack_catalog():
    return AttackCatalog.from_file(FIXTURES / "attack_mini.json")


@pytest.fixture
def attack_store(store, attack_catalog):
    load_catalog_into_store(attack_catalog, store)
    return store


@pytest.fixture
def world(tmp_path):
    return World(tmp_path / "home")


@pytest.fixture
def seeded_world(world):
    world.investigate()
    return world
