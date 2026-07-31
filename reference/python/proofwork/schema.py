"""Hard validation gate against the documents in ``spec/``.

The schemas are the published contract for objective and claim shape. The
dataclasses in :mod:`proofwork.records` remain authoritative for *semantic*
rules (sealed refusal, ratchet shape, verifier-kind registration); this module
refuses structurally malformed JSON *before* those constructors run, so a body
the published schema rejects can never reach the log.

The validator interprets the schema documents rather than restating them in
Python. A hand-written field-by-field checker is easier to read but drifts: the
file in ``spec/`` is what third parties implement against, and a checker that
has quietly diverged from it is worse than no checker, because it makes two
implementations disagree about which objectives exist.

Only the JSON Schema keywords ``spec/*.json`` actually uses are implemented,
and an unrecognised keyword is an **error**, not a no-op. Silently ignoring a
keyword someone adds to the schema would turn a tightened contract into an
unenforced comment.

``jsonschema`` is not used, deliberately: this package has no dependencies, and
the Rust node cannot use it either. Two validators that disagree about which
objectives are well formed are two networks, so both sides implement the same
small subset and ``tests/test_schema.py`` pins them against each other.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "SchemaError",
    "claim_schema",
    "objective_schema",
    "spec_dir",
    "validate_claim",
    "validate_objective",
]


class SchemaError(ValueError):
    """A body does not match the published schema, or the schema is unusable."""


class UnusableSchema(SchemaError):
    """The schema document itself is broken.

    A separate type because it indicts the repository rather than the submitted
    body: a caller that maps ``SchemaError`` to "your record is malformed"
    would otherwise blame the user for our bug.
    """


_SPEC_ENV = "PROOFWORK_SPEC_DIR"


def spec_dir() -> Path:
    """Where ``objective.schema.json`` and ``claim.schema.json`` live.

    Walks up from this file to find the repository's ``spec/``. Rust embeds the
    documents with ``include_str!`` and so cannot be run without them; Python
    reads them at import time and raises if they are absent, which is the same
    posture. A node whose gate depends on a file it may not find is a node with
    no gate, so "not found" must not degrade to "allow everything".
    """
    override = os.environ.get(_SPEC_ENV)
    if override:
        return Path(override)
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "spec"
        if (candidate / "objective.schema.json").is_file():
            return candidate
    raise UnusableSchema(
        "cannot locate the spec/ directory holding the JSON Schemas; "
        f"set {_SPEC_ENV} to point at it"
    )


def _load(name: str) -> dict[str, Any]:
    path = spec_dir() / name
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise UnusableSchema(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise UnusableSchema(f"{path} is not JSON: {exc}") from exc


def objective_schema() -> dict[str, Any]:
    return _load("objective.schema.json")


def claim_schema() -> dict[str, Any]:
    return _load("claim.schema.json")


def validate_objective(body: Any) -> None:
    """Raise :class:`SchemaError` unless ``body`` matches the objective schema."""
    _check(objective_schema(), "#", body, "$")


def validate_claim(body: Any) -> None:
    """Raise :class:`SchemaError` unless ``body`` matches the claim schema."""
    _check(claim_schema(), "#", body, "$")


# Keywords that carry documentation or identity rather than constraints.
ANNOTATIONS = frozenset(
    {"$schema", "$id", "title", "description", "$comment", "default", "examples"}
)

SUPPORTED = frozenset(
    {
        "type",
        "const",
        "enum",
        "required",
        "properties",
        "additionalProperties",
        "items",
        "uniqueItems",
        "minLength",
        "minimum",
        "pattern",
        "format",
    }
)

_TYPES: dict[str, Any] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
}


def _type_of(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _matches_type(name: str, value: Any) -> bool:
    if name == "null":
        return value is None
    expected = _TYPES.get(name)
    if expected is None:
        raise UnusableSchema(f"unknown type name {name!r}")
    # ``bool`` is a subclass of ``int`` in Python and is emphatically not one
    # unit of money. Every integer check in this repository has to say so.
    if isinstance(value, bool) and name in ("integer", "number"):
        return False
    if name == "boolean":
        return isinstance(value, bool)
    return isinstance(value, expected)


def _render(value: Any) -> str:
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, dict):
        return "an object"
    if isinstance(value, list):
        return "an array"
    if value is None:
        return "null"
    return str(value)


def _check(schema: Any, spath: str, value: Any, path: str) -> None:
    if not isinstance(schema, dict):
        raise UnusableSchema(f"{spath}: schema node is not an object")

    for key in schema:
        if key not in ANNOTATIONS and key not in SUPPORTED:
            raise UnusableSchema(
                f"{spath}: keyword {key!r} is not implemented by this validator"
            )

    if "const" in schema and value != schema["const"]:
        raise SchemaError(
            f"schema violation at {path}: must equal {_render(schema['const'])}"
        )

    if "type" in schema:
        names = schema["type"]
        names = [names] if isinstance(names, str) else list(names)
        if not any(_matches_type(name, value) for name in names):
            raise SchemaError(
                f"schema violation at {path}: expected {' or '.join(names)} "
                f"but found {_type_of(value)}"
            )

    if "enum" in schema:
        options: Iterable[Any] = schema["enum"]
        if not any(option == value and type(option) is type(value) for option in options):
            rendered = ", ".join(_render(option) for option in options)
            raise SchemaError(
                f"schema violation at {path}: {_render(value)} is not one of [{rendered}]"
            )

    # Every remaining keyword is type-conditional: JSON Schema applies
    # ``minLength`` only to strings, ``required`` only to objects. A null
    # deadline therefore skips the date-time check with no special case.
    if isinstance(value, str):
        _check_string(schema, spath, value, path)
    elif isinstance(value, int) and not isinstance(value, bool):
        _check_number(schema, spath, value, path)
    elif isinstance(value, dict):
        _check_object(schema, spath, value, path)
    elif isinstance(value, list):
        _check_array(schema, spath, value, path)


_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)


def _check_string(schema: dict[str, Any], spath: str, text: str, path: str) -> None:
    minimum = schema.get("minLength")
    if minimum is not None and len(text) < minimum:
        raise SchemaError(
            f"schema violation at {path}: must be at least {minimum} character(s) long"
        )
    pattern = schema.get("pattern")
    if pattern is not None and re.fullmatch(pattern, text) is None:
        raise SchemaError(f"schema violation at {path}: does not match /{pattern}/")
    fmt = schema.get("format")
    if fmt is None:
        return
    if fmt != "date-time":
        raise UnusableSchema(
            f"{spath}: format {fmt!r} is not implemented by this validator"
        )
    if _RFC3339.match(text) is None:
        raise SchemaError(
            f"schema violation at {path}: is not an RFC-3339 date-time "
            "(YYYY-MM-DDTHH:MM:SS with a UTC offset)"
        )


def _check_number(schema: dict[str, Any], spath: str, value: int, path: str) -> None:
    minimum = schema.get("minimum")
    if minimum is not None and value < minimum:
        raise SchemaError(f"schema violation at {path}: must be >= {minimum}")


def _check_object(
    schema: dict[str, Any], spath: str, fields: dict[str, Any], path: str
) -> None:
    for name in schema.get("required", ()):
        if name not in fields:
            raise SchemaError(
                f"schema violation at {path}: missing required property {name!r}"
            )

    properties = schema.get("properties") or {}
    additional = schema.get("additionalProperties", True)
    if not isinstance(additional, bool):
        raise UnusableSchema(
            f'{spath}: "additionalProperties" must be a boolean here; '
            "subschemas are not implemented"
        )

    for name, child in fields.items():
        subschema = properties.get(name)
        if subschema is None:
            if additional:
                continue
            raise SchemaError(
                f"schema violation at {path}: unknown property {name!r} is not allowed"
            )
        _check(subschema, f"{spath}/properties/{name}", child, f"{path}.{name}")


def _check_array(
    schema: dict[str, Any], spath: str, items: list[Any], path: str
) -> None:
    subschema = schema.get("items")
    if subschema is not None:
        for index, item in enumerate(items):
            _check(subschema, f"{spath}/items", item, f"{path}[{index}]")
    if schema.get("uniqueItems"):
        seen: list[Any] = []
        for index, item in enumerate(items):
            if item in seen:
                raise SchemaError(
                    f"schema violation at {path}: duplicate entry "
                    f"{_render(item)} at index {index}"
                )
            seen.append(item)
