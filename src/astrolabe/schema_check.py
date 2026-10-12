"""Validate a document against the subset of JSON Schema used by the handoff schema."""

from __future__ import annotations

import json
from pathlib import Path


class SchemaError(ValueError):
    """The document does not match the schema."""


def load_schema(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SchemaError("Schema is not an object")
    return payload


def validate_schema(instance: object, schema: dict[str, object], *, path: str = "$") -> None:
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(instance, dict):
            raise SchemaError(f"{path} must be an object")
        required = schema.get("required")
        if isinstance(required, list):
            for key in required:
                if key not in instance:
                    raise SchemaError(f"{path} is missing {key}")
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            properties = {}
        if schema.get("additionalProperties") is False:
            unknown = [key for key in instance if key not in properties]
            if unknown:
                raise SchemaError(f"{path} has unsupported fields: {', '.join(unknown)}")
        for key, subschema in properties.items():
            if key in instance and isinstance(subschema, dict):
                validate_schema(instance[key], subschema, path=f"{path}.{key}")
        return
    if expected == "array":
        if not isinstance(instance, list):
            raise SchemaError(f"{path} must be an array")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(instance):
                validate_schema(item, items, path=f"{path}[{index}]")
        return
    if expected == "string":
        if not isinstance(instance, str):
            raise SchemaError(f"{path} must be a string")
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(instance) < minimum:
            raise SchemaError(f"{path} is shorter than {minimum}")
        allowed = schema.get("enum")
        if isinstance(allowed, list) and instance not in allowed:
            raise SchemaError(f"{path} must be one of {allowed}")
        return
    if "const" in schema and instance != schema["const"]:
        raise SchemaError(f"{path} must be {schema['const']!r}")
