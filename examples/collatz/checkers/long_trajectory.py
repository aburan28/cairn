"""Certificate checker: does n have a Collatz trajectory of at least MIN_STEPS?

The shape every certificate checker has -- recompute from scratch, trust nothing
in the artifact except the bare witness. The submitter sends an integer; we
re-derive the property ourselves. How they found it is irrelevant and
unverifiable, which is exactly the point.
"""

BOUND = 10_000_000
MIN_STEPS = 500


def steps(n: int) -> int:
    count = 0
    while n != 1:
        n = n // 2 if n % 2 == 0 else 3 * n + 1
        count += 1
        if count > 100_000:  # guard against a non-int slipping through
            raise ValueError("trajectory did not terminate")
    return count


def check(artifact: dict) -> tuple[bool, str]:
    n = artifact.get("n")
    if isinstance(n, bool) or not isinstance(n, int):
        return False, "artifact.n must be an integer"
    if not 1 <= n < BOUND:
        return False, f"n must lie in [1, {BOUND})"
    observed = steps(n)
    if observed < MIN_STEPS:
        return False, f"n={n} has {observed} steps, need >= {MIN_STEPS}"
    return True, f"n={n} has {observed} steps"
