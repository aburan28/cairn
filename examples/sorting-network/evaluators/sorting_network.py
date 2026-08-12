"""Evaluator: how few comparators sort every 8-wire input?

A sorting network is a fixed sequence of compare-exchange pairs -- oblivious,
branch-free, the same operations whatever the data. Minimising the count for
small widths is a genuinely open combinatorial problem: the 8-wire optimum of
19 was proved by exhaustive search, and the shape of good networks is exactly
the kind of thing a search process finds and a human does not.

It is also the right shape for this network for a reason worth stating: the
zero-one principle. A network that sorts every 0/1 vector sorts every totally
ordered input, so checking all 2^8 = 256 binary vectors is a *complete* proof
rather than a sample. Verification is 256 passes over a short list -- cheap by
construction, which is the property `docs/consensus.md` says keeps the whole
consensus problem trivial.

Note what the scorer does with an invalid network: returns a sentinel rather
than raising. An invalid submission is a bad artifact, not a broken verifier,
and the distinction decides whether the objective can be attacked with garbage.

**The sentinel is not zero, and on a minimise objective that is the whole
ballgame.** Zero is the *best* score expressible here, so returning it for a
network that does not sort would hand the frontier -- and the pool behind it --
to the shortest possible garbage: an empty list. The rejection value has to be
worse than any honest answer, which on this direction means larger.

Returns an int. Never a float -- see verifiers/evaluator.py for why.
"""

WIRES = 8
# The artifact is attacker-supplied and it is billing this node's CPU. A
# correct network needs 19; anything past a few hundred is not a near-miss
# worth scoring, it is someone making the checker work for nothing.
MAX_COMPARATORS = 512

# What an invalid artifact scores. See the module docstring: on a minimise
# objective this must be worse than every real answer, never zero.
INVALID = MAX_COMPARATORS + 1


def _valid_comparator(pair) -> bool:
    return (
        isinstance(pair, list)
        and len(pair) == 2
        and all(
            isinstance(wire, int) and not isinstance(wire, bool) and 0 <= wire < WIRES
            for wire in pair
        )
        # A comparator on one wire is a no-op that would pad the count
        # downward-looking without doing any work; refuse rather than ignore,
        # so the recorded score is the size of a network that actually runs.
        and pair[0] != pair[1]
    )


def sorts_everything(comparators: list[tuple[int, int]]) -> bool:
    """The zero-one principle: all 2^WIRES binary vectors, exhaustively."""
    for bits in range(1 << WIRES):
        wires = [(bits >> i) & 1 for i in range(WIRES)]
        for lo, hi in comparators:
            if wires[lo] > wires[hi]:
                wires[lo], wires[hi] = wires[hi], wires[lo]
        if any(wires[i] > wires[i + 1] for i in range(WIRES - 1)):
            return False
    return True


def score(artifact: dict) -> int:
    comparators = artifact.get("comparators")
    if not isinstance(comparators, list) or not comparators:
        return INVALID
    if len(comparators) > MAX_COMPARATORS:
        return INVALID
    if not all(_valid_comparator(pair) for pair in comparators):
        return INVALID
    pairs = [(pair[0], pair[1]) for pair in comparators]
    return len(pairs) if sorts_everything(pairs) else INVALID
