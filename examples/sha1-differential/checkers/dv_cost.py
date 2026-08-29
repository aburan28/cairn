"""Evaluator: the cost of a SHA-1 disturbance vector.

A differential attack on SHA-1 starts from a *disturbance vector*: a pattern
of single-bit disturbances, one per step, each of which is cancelled by
corrections in the five following steps -- a local collision.  Because the
message expansion is linear over GF(2), the disturbance vector is not free:
it must itself be a codeword of the expansion, and that is what makes finding
a good one hard.  Every disturbance that survives into the probabilistic part
of the attack costs conditions, so the search is for a codeword of low weight
there.

# What is checked, exactly

The artifact carries the sixteen 32-bit words of the disturbance vector at
steps 0..15.  Those determine the whole 80-step vector, because the checker
expands them with SHA-1's own recurrence

    DV[t] = ROTL1(DV[t-3] ^ DV[t-8] ^ DV[t-14] ^ DV[t-16])

so **the submitter cannot declare a codeword that is not one**.  This is the
distinction `examples/reversible-adder/` draws against `examples/ecdsa-fail/`:
the score is derived from the object, never read off a number the submitter
chose.

Two requirements, each load-bearing:

* **Not the zero vector.**  Zero is a codeword and would score zero.
* **No disturbance in steps 75..79.**  A disturbance at step `t` spawns
  corrections at `t+1 .. t+5`, so one starting after step 74 cannot be
  corrected inside the 80 steps and the local collision never closes.

Score: the number of disturbances in steps 20..74, minimised.  Steps 0..19 are
excluded because that is the span a non-linear path handles at no probabilistic
cost -- the standard model, and the reason this metric is a proxy for attack
cost rather than a restatement of it.

The metric cannot be gamed by dumping weight into the excluded early steps.
The expansion is invertible backwards,

    DV[t-16] = ROTR1(DV[t]) ^ DV[t-3] ^ DV[t-8] ^ DV[t-14]

so sixteen consecutive zero words force the entire vector to zero; steps
20..79 hold sixty consecutive words, and a score of zero would therefore mean
the zero codeword, which is already refused.  The floor is 1 and it is a real
floor.

# What this does NOT decide

That a low-weight vector yields a usable attack.  The true cost also depends
on *where* the disturbances sit -- bit position 1 propagates carries, the
round functions impose different conditions in each of the four rounds, and
consecutive disturbances interact.  Those judgements are not arithmetic and do
not belong in a verifier.  This decides one exactly computable quantity: the
weight of the codeword in the probabilistic window.
"""

# Above any threshold this objective would set, so an invalid artifact scores
# worse than every valid one rather than better.  See docs/verification.md:
# malformed input is a rejection, not an exception.
INVALID_SCORE = 10**18

MASK = 0xFFFFFFFF
FREE_STEPS = 20        # steps a non-linear path absorbs at no cost
TAIL_STEPS = 75        # a local collision starting here cannot close by 80


def _rotl1(x: int) -> int:
    return ((x << 1) | (x >> 31)) & MASK


def _expand(words: list) -> list:
    dv = list(words)
    for t in range(16, 80):
        dv.append(_rotl1(dv[t - 3] ^ dv[t - 8] ^ dv[t - 14] ^ dv[t - 16]))
    return dv


def _parse(artifact) -> list:
    if not isinstance(artifact, dict):
        return None
    w = artifact.get("dv")
    if not isinstance(w, list) or len(w) != 16:
        return None
    out = []
    for item in w:
        # One spelling only: eight lowercase hex characters.  Two spellings of
        # one vector would be two artifacts with two digests for one result.
        if not isinstance(item, str) or len(item) != 8:
            return None
        if any(c not in "0123456789abcdef" for c in item):
            return None
        out.append(int(item, 16))
    return out


def score(artifact: dict) -> int:
    words = _parse(artifact)
    if words is None:
        return INVALID_SCORE
    dv = _expand(words)
    if not any(dv):
        return INVALID_SCORE
    if any(dv[t] for t in range(TAIL_STEPS, 80)):
        return INVALID_SCORE
    return sum(bin(dv[t]).count("1") for t in range(FREE_STEPS, TAIL_STEPS))
