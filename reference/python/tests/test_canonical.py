import pytest

from proofwork.canonical import (
    CanonicalizationError,
    canonical_bytes,
    digest,
    merkle_root,
)


def test_key_order_does_not_change_identity():
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


def test_nested_key_order_does_not_change_identity():
    left = {"outer": {"z": [1, {"b": 1, "a": 2}], "a": None}}
    right = {"outer": {"a": None, "z": [1, {"a": 2, "b": 1}]}}
    assert digest(left) == digest(right)


def test_distinct_values_have_distinct_digests():
    assert digest({"n": 1}) != digest({"n": 2})
    assert digest({"n": 1}) != digest({"n": "1"})
    assert digest({"n": 1}) != digest({"n": True})


def test_floats_are_rejected():
    # Floats do not round-trip identically everywhere and do not reproduce
    # bitwise across heterogeneous hardware. Two honest nodes must never
    # disagree about an object's identity.
    with pytest.raises(CanonicalizationError, match="float"):
        canonical_bytes({"score": 1.5})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"nested": [{"x": 0.1}]})


def test_unsupported_types_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"when": object()})
    with pytest.raises(CanonicalizationError, match="keys must be strings"):
        canonical_bytes({1: "a"})


def test_unicode_is_stable():
    assert digest({"s": "café"}) == digest({"s": "café"})


def test_merkle_root_of_empty_is_none():
    assert merkle_root([]) is None


def test_merkle_root_promotes_odd_node_rather_than_duplicating():
    # Duplicating the final leaf lets two different leaf sets produce the same
    # root (Bitcoin CVE-2012-2459). Three leaves must not collide with four.
    a, b, c = digest({"i": 0}), digest({"i": 1}), digest({"i": 2})
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])


def test_merkle_root_is_order_sensitive():
    a, b = digest({"i": 0}), digest({"i": 1})
    assert merkle_root([a, b]) != merkle_root([b, a])
