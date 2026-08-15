"""Evaluator: how few comparators sort every 11-wire input?

The 8-wire objective in `examples/sorting-network/` is a worked demonstration:
its optimum of 19 was settled by exhaustive search and is quoted in textbooks.
Eleven wires is not settled. The best published network has 35 comparators and
the best published lower bound is 33 -- Van Voorhis, applied to the proved
S(10) = 29: S(11) >= S(10) + ceil(log2 11) = 29 + 4. The gap of two is open,
which is why this is a bounty and the 8-wire one is a tutorial.

Verification is complete rather than sampled, by the **zero-one principle**: a
comparator network that sorts every 0/1 vector sorts every totally ordered
input. So checking all 2^11 = 2048 binary vectors is a proof.

# Why the wires are bitmasks and not a list of ints

The 8-wire evaluator loops over 256 vectors and applies the network to each.
The same shape here is 2048 vectors times up to 256 comparators -- half a
million interpreter steps per candidate, on every node, for every submission.

So the transposition: wire `i` is a single 2048-bit integer whose bit `k` is
that wire's value on input vector `k`, and one comparator is two bigint
operations that advance all 2048 vectors at once. On 0/1 values min is AND and
max is OR, which is the whole trick. A 55-comparator network costs 110 bigint
ops instead of 140,800 interpreted ones.

That is not a micro-optimisation, it is the property `docs/consensus.md` rests
on: verification has to cost about one evaluation, because *every* node pays it
and a bounty whose checker is expensive is a denial-of-service surface pointed
at the people doing the work.

Returns an int. Never a float -- see `src/verifiers/mod.rs` for why.
"""

WIRES = 11

# The artifact is attacker-supplied and it is billing this node's CPU. The best
# known network needs 35 and a bubble network needs 55; a few hundred is not a
# near-miss worth scoring, it is someone making the checker work for nothing.
MAX_COMPARATORS = 256

# What an invalid artifact scores.
#
# A *minimise* objective cannot reject with zero, because zero is the best score
# expressible -- the empty comparator list sorts nothing and would take the
# frontier and the pool behind it. The rejection value has to be worse than
# every honest answer, which on this direction means larger.
INVALID = MAX_COMPARATORS + 1


def _valid_comparator(pair) -> bool:
    return (
        isinstance(pair, list)
        and len(pair) == 2
        and all(
            isinstance(wire, int) and not isinstance(wire, bool) and 0 <= wire < WIRES
            for wire in pair
        )
        # A comparator on one wire is a no-op that pads the count without doing
        # any work. Refuse rather than ignore, so the recorded score is the size
        # of a network that actually runs.
        and pair[0] != pair[1]
    )


def _input_columns() -> list[int]:
    """Wire `i` as a bitmask over all 2^WIRES inputs, bit `k` = bit `i` of `k`."""
    total = 1 << WIRES
    columns = []
    for i in range(WIRES):
        block = 1 << i
        column = 0
        # Bit i of the counter alternates in runs of 2^i, so the mask is a run
        # of ones every other block. Built by run rather than bit to keep this
        # linear in the number of runs instead of in 2^WIRES.
        for start in range(block, total, 2 * block):
            column |= ((1 << block) - 1) << start
        columns.append(column)
    return columns


def sorts_everything(comparators: list[tuple[int, int]]) -> bool:
    """The zero-one principle: all 2^WIRES binary vectors, exhaustively."""
    columns = _input_columns()
    for lo, hi in comparators:
        low, high = columns[lo], columns[hi]
        # Compare-exchange on 0/1: the smaller value is the AND, the larger the
        # OR. Both wires are read before either is written -- the two-name swap
        # is load bearing, and doing it in two statements silently computes
        # `high | (low & high)` on the second wire.
        columns[lo], columns[hi] = low & high, low | high
    # Sorted means wire i <= wire i+1 on every input, so every bit set in wire i
    # is set in wire i+1. `a & ~b` is exactly the counterexamples.
    return all(columns[i] & ~columns[i + 1] == 0 for i in range(WIRES - 1))


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
