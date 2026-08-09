"""Evaluator: how short a 11-mark Golomb ruler?

A Golomb ruler has no two pairs of marks the same distance apart, so every
pairwise difference is unique. Optimal rulers are known only up to order 28 and
each new one has cost distributed-computing projects years, which makes this a
rare thing: a problem with a *verified* optimum to aim at, where finding it is
hard and checking it is a double loop.

Order 11 has a known optimum of length 72. Stated in the objective because a
target nobody can reach is a pool nobody can exhaust, and an agent that knows
where the floor is can tell "no more progress" from "not trying hard enough".

Scored by length, minimised. An invalid ruler scores the sentinel rather than
raising -- see `score` for why a minimise objective cannot use zero.

Returns an int. Never a float -- see verifiers/evaluator.py for why.
"""

MARKS = 11
# The artifact is attacker-supplied. The optimum is 72; a bound well past it
# still admits every honest near-miss and stops a submission from asking this
# node to loop over an enormous range.
MAX_LENGTH = 10_000

# What an invalid artifact scores.
#
# A *minimise* objective cannot reject with zero, because zero is the best
# score expressible -- a garbage artifact would take the frontier and the pool
# with it. The rejection value must therefore be worse than any real answer,
# which on this direction means larger than any length the checker will admit.
INVALID = MAX_LENGTH + 1


def _valid_marks(marks) -> bool:
    return (
        isinstance(marks, list)
        and len(marks) == MARKS
        and all(
            isinstance(mark, int) and not isinstance(mark, bool) and 0 <= mark <= MAX_LENGTH
            for mark in marks
        )
    )


def is_golomb(marks: list[int]) -> bool:
    """Every pairwise difference distinct."""
    seen = set()
    ordered = sorted(marks)
    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            gap = ordered[j] - ordered[i]
            if gap in seen:
                return False
            seen.add(gap)
    return True


def score(artifact: dict) -> int:
    marks = artifact.get("marks")
    if not _valid_marks(marks):
        return INVALID
    if len(set(marks)) != len(marks):
        return INVALID
    if not is_golomb(marks):
        return INVALID
    # Length is the span, so a ruler that does not start at zero is scored on
    # what it actually measures rather than on its largest mark. Translating a
    # ruler does not change it, and the score should not either.
    return max(marks) - min(marks)
