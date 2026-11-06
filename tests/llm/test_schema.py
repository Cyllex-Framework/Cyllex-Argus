"""The JSON-schema helpers that back structured output.

`inline_strict_schema` produces the schema Anthropic strict tool use requires: every object
carries `additionalProperties: false` and lists all of its properties as `required`, with the
schema-noise keywords (`default`, `title`) stripped. Model fields that are optional in Python
are nullable, so requiring them is satisfied by the model emitting `null`.
"""

from __future__ import annotations

from cyllex_argus.llm.schema import inline_schema, inline_strict_schema
from cyllex_argus.pipeline.analyst import AnalystOutput


def test_inline_schema_expands_refs_without_strictness():
    """The non-strict helper is unchanged: it inlines $defs but does not tighten objects."""
    s = inline_schema(AnalystOutput)
    assert "$defs" not in s
    assert s["properties"]["claims"]["items"]["type"] == "object"
    # It must NOT force additionalProperties: false — that is strict-only behaviour.
    assert s.get("additionalProperties") is not False


def test_inline_strict_schema_requires_all_fields_and_forbids_extras():
    s = inline_strict_schema(AnalystOutput)
    assert s["type"] == "object"
    assert s["additionalProperties"] is False
    assert set(s["required"]) == {"primary_publisher", "claims"}

    # Nested claim object (its $ref was inlined into claims.items).
    item = s["properties"]["claims"]["items"]
    assert item["additionalProperties"] is False
    # Every field is required — including the model's optional (nullable) ones, which the model
    # satisfies by emitting null. This is the whole point: a weak model can no longer drop a
    # required field (the bug that lost documents to "claims: Field required").
    assert set(item["required"]) == {
        "subject", "subject_type", "predicate", "object", "object_type",
        "polarity", "quote", "observed_at", "technique_id",
    }
    # The optional fields stay nullable so "required" is satisfiable.
    observed = item["properties"]["observed_at"]
    assert observed.get("type") == "null" or {"type": "null"} in observed.get("anyOf", [])

    # Strict schemas carry no default/title noise anywhere.
    def no_noise(node) -> bool:
        if isinstance(node, dict):
            if "default" in node or "title" in node:
                return False
            return all(no_noise(v) for v in node.values())
        if isinstance(node, list):
            return all(no_noise(v) for v in node)
        return True

    assert no_noise(s)
