"""Evaluator: how few edge relaxations compute shortest paths on any weighting?

This is the graph-search analogue of a sorting network. A *relaxation schedule*
is a fixed sequence of directed edges of the complete digraph on 6 vertices,
applied as `d[v] = min(d[v], d[u] + w(u, v))` from `d[source] = 0` and every
other distance infinite. Oblivious and branch-free, exactly like a comparator
network: the same operations run whatever the weights are, so the count is a
property of the schedule rather than of an input.

Textbook Bellman-Ford is one such schedule -- every edge, `|V| - 1` times, 150
relaxations here -- and it is obviously wasteful. How few suffice is not
obvious, and that is the bounty.

# Why this can be checked completely instead of sampled

There are infinitely many weight functions, so a checker cannot try them. It
does not have to, because of a criterion as sharp as the zero-one principle:

    A schedule is correct for every weighting (with no negative cycle) if and
    only if the edges of every simple path out of the source appear in the
    schedule, in path order, as a subsequence.

Both directions are short. (<=) is the path-relaxation property: if some
shortest path to `v` was relaxed in order then `d[v]` reached its true distance,
and shortest paths are simple whenever no negative cycle exists. (=>) is one
weight function per path: give the edges of a simple path `P` weight 0 and every
other edge weight 1. The only 0-weight route from the source to `P`'s endpoint
is `P` itself -- a simple path's vertices each carry exactly one of its edges
out -- so a correct schedule must have relaxed `P`'s edges in order.

So verification is: enumerate the 325 non-trivial simple paths out of the
source, and check the schedule covers all of them. Complete, and it costs one
pass over the schedule.

# What that criterion is *not*

It is not "reaches the right answer on the weights I tried". A schedule tuned
to a sampled set of weightings passes a sampling checker and is wrong, and
nobody would find out until it shipped. This is the difference between a
verifier and a test suite, and it is the reason the objective is fundable.

Returns an int. Never a float -- see `src/verifiers/mod.rs` for why.
"""

VERTICES = 6
SOURCE = 0

# The artifact is attacker-supplied and billing this node's CPU. Bellman-Ford
# needs 150; anything past a few hundred is not a near-miss worth scoring.
MAX_RELAXATIONS = 400

# What an invalid artifact scores. A *minimise* objective cannot reject with
# zero: the empty schedule computes nothing and would take the frontier and the
# pool with it. The rejection value must be worse than every honest answer.
INVALID = MAX_RELAXATIONS + 1


def simple_paths() -> set[tuple[int, ...]]:
    """Every simple path out of SOURCE, as a vertex tuple. Includes the empty one."""
    paths = {(SOURCE,)}
    stack = [(SOURCE,)]
    while stack:
        path = stack.pop()
        for nxt in range(VERTICES):
            if nxt in path:
                continue
            grown = path + (nxt,)
            paths.add(grown)
            stack.append(grown)
    return paths


# 1 + 5 + 20 + 60 + 120 + 120. Computed rather than written down, because a
# constant that disagrees with the enumeration would make every schedule look
# correct (too large) or none of them (too small), and neither failure is loud.
TOTAL_PATHS = len(simple_paths())


def _valid_edge(pair) -> bool:
    return (
        isinstance(pair, list)
        and len(pair) == 2
        and all(
            isinstance(v, int) and not isinstance(v, bool) and 0 <= v < VERTICES
            for v in pair
        )
        # No self-loops: relaxing (v, v) can never lower d[v] for a
        # non-negative-cycle weighting, so admitting it would only let a
        # submitter pad a schedule with operations that do nothing.
        and pair[0] != pair[1]
    )


def covers_every_path(schedule: list[tuple[int, int]]) -> bool:
    """Is every simple path out of SOURCE a subsequence of the schedule?"""
    # Paths are grown greedily, indexed by their last vertex: relaxing (u, v)
    # extends exactly those already-covered paths that end at u. Greedy is
    # correct here because covering a path as early as possible never blocks a
    # later extension -- a subsequence match has no reason to wait.
    covered = {v: set() for v in range(VERTICES)}
    covered[SOURCE].add((SOURCE,))
    for u, v in schedule:
        # Snapshot: a single relaxation of (u, v) extends each covered path by
        # at most one edge. Feeding this step's own output back in would let one
        # occurrence stand in for a repeated edge and accept a wrong schedule.
        grown = [path + (v,) for path in covered[u] if v not in path]
        covered[v].update(grown)
    return sum(len(paths) for paths in covered.values()) == TOTAL_PATHS


def score(artifact: dict) -> int:
    schedule = artifact.get("relaxations")
    if not isinstance(schedule, list) or not schedule:
        return INVALID
    if len(schedule) > MAX_RELAXATIONS:
        return INVALID
    if not all(_valid_edge(pair) for pair in schedule):
        return INVALID
    edges = [(pair[0], pair[1]) for pair in schedule]
    # Every relaxation in the list is counted, including ones into the source
    # and repeats of an edge already scheduled. They cost what they cost; a
    # score that quietly deduplicated would be scoring a schedule nobody ran.
    return len(edges) if covers_every_path(edges) else INVALID
