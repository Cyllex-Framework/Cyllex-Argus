"""The watchers config block (alert reliability floor)."""

import pytest
from pydantic import ValidationError

from cyllex_argus.config.settings import ArgusConfig


def test_default_min_reliability_is_c():
    assert ArgusConfig().watchers.min_reliability == "C"


def test_min_reliability_accepts_a_grade():
    assert ArgusConfig(watchers={"min_reliability": "A"}).watchers.min_reliability == "A"


def test_min_reliability_rejects_non_grade():
    with pytest.raises(ValidationError):
        ArgusConfig(watchers={"min_reliability": "Z"})
