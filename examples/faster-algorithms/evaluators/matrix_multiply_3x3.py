"""Evaluator: how few multiplications multiply two 3x3 matrices?

The naive algorithm uses 27. Strassen showed 2x2 needs 7 rather than 8 and
started the field; for 3x3 the best published algorithm is Laderman's 23, from
1976, and the best published lower bound is 19 (Blaeser). Half a century of
attention, including several machine-search efforts, has not closed a gap of
four. This is the canonical "find a faster algorithm" problem and it is open.

# The artifact is the algorithm, and the check is exact

A bilinear algorithm of rank R is R products, each of one linear combination of
A's entries with one of B's entries, and then each entry of C as a linear
combination of those products. That is the whole algorithm: the coefficients
*are* the artifact, and R is the multiplication count.

Correctness is the Brent equations, checked over all 3^6 = 729 index tuples:

    sum_r  a_r[i,j] * b_r[j',k] * c_r[i'',k'']  ==  [i == i''][j == j'][k == k'']

Exhaustive over the tensor, exact in integers, and about 17,000 multiply-adds
for a rank-23 candidate. No sampling on random matrices, which would accept an
algorithm that happens to be right on the samples -- and by bilinearity there is
no need: agreeing on the 729 coefficients *is* agreeing on every input.

# Integers only, and that will bite a gradient-descent search

Coefficients are integers in [-2, 2]. Two reasons, and the first is not
negotiable: this network has no float type anywhere near identity or money, on
purpose, so "close enough" cannot be expressed and a tolerance cannot be
smuggled in. The second is that it costs nothing real -- Strassen's and
Laderman's coefficients are all in {-1, 0, 1}, so the best known result is
inside the box.

The practical consequence is worth knowing before you burn a submission: a
decomposition found by numerical optimisation scores the sentinel until it is
*rounded and re-checked*, and rounding a near-solution usually breaks it. The
discretisation is part of the problem, not an afterthought.

Returns an int. Never a float -- see `src/verifiers/mod.rs` for why.
"""

N = 3
ENTRIES = N * N

# The artifact is attacker-supplied and billing this node's CPU. Naive is 27;
# a rank far above that is not a near-miss worth scoring.
MAX_RANK = 40

# Coefficients an honest submission needs. Kept small so the Brent sums stay in
# a range where nothing surprising happens, and because every published 3x3
# algorithm fits inside {-1, 0, 1}.
MAX_COEFFICIENT = 2

# What an invalid artifact scores. A *minimise* objective cannot reject with
# zero: an empty product list would be the best score expressible and would take
# the frontier and the pool with it.
INVALID = MAX_RANK + 1


def _valid_vector(vector) -> bool:
    return (
        isinstance(vector, list)
        and len(vector) == ENTRIES
        and all(
            isinstance(c, int)
            and not isinstance(c, bool)
            and -MAX_COEFFICIENT <= c <= MAX_COEFFICIENT
            for c in vector
        )
    )


def _valid_product(product) -> bool:
    return (
        isinstance(product, dict)
        and all(key in product for key in ("a", "b", "c"))
        and all(_valid_vector(product[key]) for key in ("a", "b", "c"))
    )


def computes_the_product(products: list[tuple[list, list, list]]) -> bool:
    """The Brent equations, over every one of the 3^6 index tuples."""
    for x in range(ENTRIES):  # (i, j) into A, row-major
        for y in range(ENTRIES):  # (j', k) into B
            for z in range(ENTRIES):  # (i'', k'') into C
                # 1 exactly when A's column index meets B's row index and the
                # outer indices are the ones C is asking for. This is the
                # matrix-multiplication tensor written out.
                expected = int(x // N == z // N and x % N == y // N and y % N == z % N)
                total = 0
                for a, b, c in products:
                    # Skipping a zero coefficient is worth it: real
                    # decompositions are sparse, and this is the innermost of
                    # four nested loops.
                    if a[x] and b[y] and c[z]:
                        total += a[x] * b[y] * c[z]
                if total != expected:
                    return False
    return True


def score(artifact: dict) -> int:
    products = artifact.get("products")
    if not isinstance(products, list) or not products:
        return INVALID
    if len(products) > MAX_RANK:
        return INVALID
    if not all(_valid_product(product) for product in products):
        return INVALID
    triples = [(p["a"], p["b"], p["c"]) for p in products]
    # The score is the number of products declared, not the number that turn out
    # to matter. A submitter who pads with all-zero products only makes their own
    # score worse, which is the right direction for a knob they control.
    return len(triples) if computes_the_product(triples) else INVALID
