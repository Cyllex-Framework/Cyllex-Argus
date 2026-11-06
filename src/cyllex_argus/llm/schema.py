"""JSON schema helpers for structured output."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


def inline_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Return the model's JSON schema with every $ref expanded and $defs removed."""
    schema = model.model_json_schema()
    definitions = schema.pop("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                target = resolve(definitions[node["$ref"].rsplit("/", 1)[-1]])
                extras = {k: resolve(v) for k, v in node.items() if k != "$ref"}
                return {**target, **extras}
            return {k: resolve(v) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    return resolve(schema)


def inline_strict_schema(model: type[BaseModel]) -> dict[str, Any]:
    """`inline_schema` plus the constraints Anthropic strict tool use requires.

    Strict mode guarantees the model's `tool_use.input` validates against the schema exactly,
    which is what stops a weaker model (e.g. Haiku) from silently dropping a required field and
    failing the whole document. For that guarantee Anthropic requires every object to set
    `additionalProperties: false` and to list *all* of its properties in `required`; it also
    rejects the `default`/`title` keywords Pydantic emits for documentation. Fields that are
    optional in the model are nullable, so requiring them is satisfied by the model emitting
    `null` — no information is lost, only the escape hatch of omitting the key.
    """
    def tighten(node: Any) -> Any:
        if isinstance(node, dict):
            node = {k: tighten(v) for k, v in node.items() if k not in ("default", "title")}
            if node.get("type") == "object" and "properties" in node:
                node["additionalProperties"] = False
                node["required"] = list(node["properties"].keys())
            return node
        if isinstance(node, list):
            return [tighten(v) for v in node]
        return node

    return tighten(inline_schema(model))
