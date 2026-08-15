"""Evaluator: how large is this cap set in F_3^n?

A cap set contains no three distinct collinear points -- in F_3, no three
distinct points summing to zero coordinatewise. Finding large ones is the
problem FunSearch used to produce a genuinely new mathematical result, and it is
the canonical shape for this network: an LLM proposes a construction, a cheap
deterministic scorer settles it, and nobody has to trust the proposer.

Note what the scorer does with an *invalid* set: scores it zero rather than
raising. An invalid submission is a bad artifact, not a broken verifier, and the
distinction decides whether the objective can be attacked by submitting garbage.

Returns an int. Never a float -- see verifiers/evaluator.py for why.
"""

DIMENSION = 4


def _valid_point(point) -> bool:
    return (
        isinstance(point, list)
        and len(point) == DIMENSION
        and all(isinstance(c, int) and not isinstance(c, bool) and 0 <= c <= 2 for c in point)
    )


def is_cap_set(points: list[tuple[int, ...]]) -> bool:
    seen = set(points)
    if len(seen) != len(points):
        return False
    ordered = sorted(seen)
    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            # In F_3, a+b+c = 0 has a unique solution for c given distinct a, b.
            third = tuple((-(a + b)) % 3 for a, b in zip(ordered[i], ordered[j]))
            if third != ordered[i] and third != ordered[j] and third in seen:
                return False
    return True


def score(artifact: dict) -> int:
    points = artifact.get("points")
    if not isinstance(points, list) or not points:
        return 0
    if not all(_valid_point(p) for p in points):
        return 0
    tuples = [tuple(p) for p in points]
    if len(set(tuples)) != len(tuples):
        return 0
    return len(tuples) if is_cap_set(tuples) else 0
