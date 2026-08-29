"""Evaluator: how far into SHA-1 a pair of message blocks collides.

A differential path is a plan; this is the artifact that proves one worked.
Submit two distinct 64-byte message blocks.  The evaluator runs SHA-1's
compression function on both from the standard IV and reports the largest
number of steps after which the two working states are still identical.

# Why the score cannot be inflated

The score is read off the two messages by running the real step function, so
nothing about the path, the disturbance vector, or the method is declared or
trusted -- only the pair.  A collision found by a differential path, by a
generic search, or by having been told it scores identically, which is the
property that makes an unreliable contributor safe to accept.

# The free baseline, and where work starts

The message words at steps 0..15 are the block itself, so two blocks that
differ only in the last word agree for fifteen steps at no cost at all.  That
is the floor anybody reaches by typing, and it is why this objective's
threshold sits above it: a score of 16 or more requires the difference to
survive the expansion, which is where the cryptanalysis begins.

The ceiling is not reachable by construction: 80 would be a one-block SHA-1
collision, which is open.  The published collisions (SHAttered, 2017) are
two-block chosen-prefix constructions and do not settle this.

# What is checked, exactly

* Both messages are 128 lowercase hex characters, in one spelling only.
* They differ.  Equal messages collide for 80 steps trivially and score zero.
* Score is the largest `r` at which the states agree, comparing the full
  five-word working state, which is what the next step consumes.

The largest, not the length of the agreeing prefix.  A differential path works
by letting the states *diverge* and steering them back together, so a prefix
measure would score the thing being looked for at zero and score a pair that
does nothing at fifteen.

The feed-forward is deliberately outside the comparison: it adds the same IV
to both states, so it can neither create nor destroy an agreement, and leaving
it out means the score is about the step function rather than about an
addition.

# What this does NOT decide

Anything about SHA-1 as a whole.  A pair colliding for `r` steps says the
reduced primitive has a collision, not that the full one does, and says
nothing about the second preimage or preimage questions.
"""

INVALID_SCORE = 0        # maximize: a bad artifact scores below every valid one

MASK = 0xFFFFFFFF
IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)
STEPS = 80


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK


def _f(t: int, b: int, c: int, d: int) -> int:
    if t < 20:
        return (b & c) | ((~b & MASK) & d)
    if t < 40:
        return b ^ c ^ d
    if t < 60:
        return (b & c) | (b & d) | (c & d)
    return b ^ c ^ d


def _expand(block: list) -> list:
    w = list(block)
    for t in range(16, STEPS):
        w.append(_rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))
    return w


def states(block: list) -> list:
    """Every working state from 0 to STEPS, so the comparison below is a walk
    rather than 80 restarts."""
    w = _expand(block)
    a, b, c, d, e = IV
    out = [(a, b, c, d, e)]
    for t in range(STEPS):
        t2 = (_rotl(a, 5) + _f(t, b, c, d) + e + K[t // 20] + w[t]) & MASK
        a, b, c, d, e = t2, a, _rotl(b, 30), c, d
        out.append((a, b, c, d, e))
    return out


def _parse_block(item) -> list:
    if not isinstance(item, str) or len(item) != 128:
        return None
    if any(ch not in "0123456789abcdef" for ch in item):
        return None
    return [int(item[i:i + 8], 16) for i in range(0, 128, 8)]


def score(artifact: dict) -> int:
    if not isinstance(artifact, dict):
        return INVALID_SCORE
    m1 = _parse_block(artifact.get("m1"))
    m2 = _parse_block(artifact.get("m2"))
    if m1 is None or m2 is None or m1 == m2:
        return INVALID_SCORE
    s1, s2 = states(m1), states(m2)
    best = 0
    for r in range(STEPS + 1):
        if s1[r] == s2[r]:
            best = r
    return best
