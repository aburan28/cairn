#!/usr/bin/env python3
"""Search the SHA-0 and SHA-1 expansion codes, and write the DV artifacts.

    search_dv.py            # search, score through the pinned evaluators, write
    search_dv.py --check    # re-prove the SHA-0 optimum and re-score what shipped
    search_dv.py --full     # add the expensive SHA-1 searches behind the bound

# The two halves of this file are not the same problem

**SHA-0 is decided here.** Its expansion, W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^
W[i-16], has no rotation, so XOR acts on the 32 bit positions separately: a
codeword is 32 independent codewords of one length-80 binary code with 16 free
bits, and the weight of the whole is the sum of the weights of the parts. The
lightest nonzero vector therefore uses exactly one bit position -- a second only
adds weight -- and one bit position has 2^16 codewords. So the optimum is a
loop over 65,536 cases, it is 17, and `--check` re-runs that loop in about a
second. The objective's target is that number, and its pool is exhausted
exactly there.

**SHA-1 is not.** Put the rotation back and the bit positions couple: the code
stops being 32 copies of an [80, 16] binary code and becomes one [2560, 512]
code, where finding a minimum-weight codeword is the hard problem it is
everywhere else. Everything below establishes an *upper* bound of 31 and no
lower bound at all. What was tried:

    every single-bit window, at every offset                       -> 31
    every pair of single-bit windows sharing an offset             -> 31
    sampled three- and four-bit windows                            -> 31
    a beam search over XOR combinations of the above               -> 31
    hill-climbing from random codewords                            -> ~800

The last line is the informative one. A random codeword of this code weighs
about half of 1760, and hill-climbing from one gets nowhere near 31: the light
codewords are not found by descending into them, they are the images of sparse
windows. That is why the objective's baseline is an upper bound somebody else's
search may well beat, and why its target is labelled a construction target.

# The scores in the objectives come from the evaluators, not from here

This file has its own fast expansion, because the search runs it millions of
times. It would be a poor reason to trust it. Every artifact written is scored
by loading the *pinned* evaluator and calling it, and the numbers quoted in the
objective records are those. A disagreement between the two implementations is
a failure of this script, and `--check` is where it surfaces.
"""

import importlib.util
import json
import pathlib
import random
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
ARTIFACTS = ROOT / "artifacts"

M32 = 0xFFFFFFFF
STEPS = 80
SCORE_FROM = 20
TAIL_FROM = 75
MAX_OFFSET = STEPS - 16


def evaluator(name):
    path = ROOT / "evaluators" / ("%s.py" % name)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def expand(window, offset, rotate):
    dv = [0] * STEPS
    dv[offset:offset + 16] = window
    for i in range(offset + 16, STEPS):
        x = dv[i - 3] ^ dv[i - 8] ^ dv[i - 14] ^ dv[i - 16]
        dv[i] = rotl(x, 1) if rotate else x
    for i in range(offset - 1, -1, -1):
        x = rotl(dv[i + 16], 31) if rotate else dv[i + 16]
        dv[i] = x ^ dv[i + 13] ^ dv[i + 8] ^ dv[i + 2]
    return dv


def artifact_of(dv, offset=0):
    return {
        "offset": offset,
        "window": ["%08x" % w for w in dv[offset:offset + 16]],
    }


def weight(dv):
    """None when the vector is unusable, so callers cannot score one by accident."""
    if not any(dv) or any(dv[i] for i in range(TAIL_FROM, STEPS)):
        return None
    return sum(bin(dv[i]).count("1") for i in range(SCORE_FROM, STEPS))


# ---------------------------------------------------------------------------
# SHA-0: exhaustive, and therefore a proof
# ---------------------------------------------------------------------------

def sha0_optimum():
    """Minimum weight over every nonzero SHA-0 codeword, by enumeration.

    One bit position, all 2^16 of its codewords. That covers every codeword of
    the full expansion because the positions are independent and their weights
    add: a vector touching two positions weighs at least what the lighter of
    the two does alone, so no combination can beat the best single one.
    """
    best = None
    for seed in range(1, 1 << 16):
        dv = expand([(seed >> i) & 1 for i in range(16)], 0, False)
        score = weight(dv)
        if score is not None and (best is None or score < best[0]):
            best = (score, dv)
    return best


def sha0_single_bit():
    """The obvious construction: one disturbed bit in one window."""
    best = None
    for offset in range(MAX_OFFSET + 1):
        for word in range(16):
            window = [0] * 16
            window[word] = 1
            dv = expand(window, offset, False)
            score = weight(dv)
            if score is not None and (best is None or score < best[0]):
                best = (score, dv, offset)
    return best


# ---------------------------------------------------------------------------
# SHA-1: an upper bound, and the searches that failed to lower it
# ---------------------------------------------------------------------------

def pack(dv):
    value = 0
    for i, word in enumerate(dv):
        value |= word << (32 * i)
    return value


SCORE_MASK = ((1 << (32 * (STEPS - SCORE_FROM))) - 1) << (32 * SCORE_FROM)
TAIL_MASK = ((1 << (32 * (STEPS - TAIL_FROM))) - 1) << (32 * TAIL_FROM)


def packed_weight(value):
    if value == 0 or value & TAIL_MASK:
        return None
    return bin(value & SCORE_MASK).count("1")


def sha1_atoms():
    """Every single-bit window, at every offset, packed into one integer each."""
    atoms = {}
    for offset in range(MAX_OFFSET + 1):
        row = []
        for word in range(16):
            for bit in range(32):
                window = [0] * 16
                window[word] = 1 << bit
                row.append(pack(expand(window, offset, True)))
        atoms[offset] = row
    return atoms


def unpack(value):
    return [(value >> (32 * i)) & M32 for i in range(STEPS)]


def sha1_bound(full):
    atoms = sha1_atoms()
    best = None

    def offer(value):
        nonlocal best
        score = packed_weight(value)
        if score is not None and (best is None or score < best[0]):
            best = (score, value)

    for row in atoms.values():
        for value in row:
            offer(value)
    print("  every single-bit window:            %d" % best[0])

    for row in atoms.values():
        # Rotating every word of a codeword by the same amount gives another
        # codeword of the same weight, because ROTL commutes with XOR and with
        # ROTL1. So one of the two bits can be pinned to position 0 and the
        # search is 32 times smaller with nothing lost.
        for i in range(0, 512, 32):
            left = row[i]
            for j in range(512):
                if j != i:
                    offer(left ^ row[j])
    print("  every pair sharing an offset:       %d" % best[0])

    if not full:
        print("  (--full adds the sampled and beam searches)")
        return best

    random.seed(20260829)
    for _ in range(400000):
        row = atoms[random.randrange(MAX_OFFSET + 1)]
        value = 0
        for index in random.sample(range(512), random.choice((3, 4))):
            value ^= row[index]
        offer(value)
    print("  sampled three- and four-bit windows: %d" % best[0])

    flat = list(dict.fromkeys(v for row in atoms.values() for v in row))
    beam = sorted(
        ((packed_weight(v), v) for v in flat if packed_weight(v) is not None),
        key=lambda pair: pair[0],
    )[:400]
    seen = {v for _, v in beam}
    for _ in range(4):
        nxt = []
        for score, value in beam:
            for atom in flat:
                combined = value ^ atom
                if combined in seen:
                    continue
                combined_score = packed_weight(combined)
                if combined_score is not None and combined_score <= score:
                    seen.add(combined)
                    nxt.append((combined_score, combined))
        if not nxt:
            break
        nxt.sort(key=lambda pair: pair[0])
        beam = nxt[:400]
        offer(beam[0][1])
    print("  beam search over XOR combinations:  %d" % best[0])
    print("  hill-climbing from random codewords: %d" % sha1_hill_climb())
    return best


def sha1_hill_climb(restarts=40):
    """Descend from random codewords, which is the search that does not work.

    Here so the claim is reproducible rather than asserted. A random codeword of
    this code weighs about half of 1760 bits, and greedily XOR-ing whichever
    basis vector reduces the weight bottoms out an order of magnitude above what
    a single sparse window reaches. Light codewords are not at the bottom of a
    hill; they are the images of sparse windows, and that is the whole reason
    the SHA-1 objective is a bounty and the SHA-0 one is a demonstration.
    """
    # A basis for the tail-free subcode, by elimination over the tail bits.
    pivots, subcode = {}, []
    for offset_atom in sha1_atoms()[0]:
        current = combination = offset_atom
        while True:
            tail = current & TAIL_MASK
            if not tail:
                subcode.append(combination)
                break
            bit = tail.bit_length() - 1
            if bit not in pivots:
                pivots[bit] = (current, combination)
                break
            previous, previous_combination = pivots[bit]
            current ^= previous
            combination ^= previous_combination

    random.seed(20260829)
    best = None
    for _ in range(restarts):
        current = 0
        for _ in range(random.randrange(1, 4)):
            current ^= random.choice(subcode)
        if current == 0:
            continue
        improving = True
        while improving:
            improving = False
            score = packed_weight(current) or 0
            order = subcode[:]
            random.shuffle(order)
            for vector in order:
                candidate = current ^ vector
                candidate_score = packed_weight(candidate)
                if candidate_score is not None and candidate_score < score:
                    current, score, improving = candidate, candidate_score, True
        score = packed_weight(current)
        if score is not None and (best is None or score < best):
            best = score
    return best


# ---------------------------------------------------------------------------

SHIPPED = (
    ("dv-sha0-optimal.json", "dv_sha0", 17),
    ("dv-sha0-baseline.json", "dv_sha0", 20),
    ("dv-sha1-baseline.json", "dv_sha1", 31),
)


def rescore(check_only):
    """Score every committed artifact through the pinned evaluator."""
    failures = []
    for name, which, expected in SHIPPED:
        path = ARTIFACTS / name
        if not path.exists():
            failures.append("%s is missing" % name)
            continue
        got = evaluator(which).score(json.loads(path.read_text()))
        mark = "ok" if got == expected else "MISMATCH"
        print("  %-24s %s scores %d (expected %d) %s" % (name, which, got, expected, mark))
        if got != expected:
            failures.append(
                "%s scores %d through %s, but the objective is written for %d"
                % (name, got, which, expected)
            )
    if failures and check_only:
        for line in failures:
            print("DRIFT: %s" % line, file=sys.stderr)
    return failures


def main():
    args = sys.argv[1:]
    check_only, full = "--check" in args, "--full" in args

    print("SHA-0, exhaustively (2^16 codewords of one bit position):")
    optimal_score, optimal = sha0_optimum()
    baseline_score, baseline, baseline_offset = sha0_single_bit()
    print("  proved optimum:                     %d" % optimal_score)
    print("  best single-bit window:             %d" % baseline_score)

    if not check_only:
        print("\nSHA-1, upper bounds only:")
        sha1_score, sha1_value = sha1_bound(full)
        ARTIFACTS.mkdir(exist_ok=True)
        for name, payload in (
            ("dv-sha0-optimal.json", artifact_of(optimal)),
            ("dv-sha0-baseline.json", artifact_of(baseline, baseline_offset)),
            ("dv-sha1-baseline.json", artifact_of(unpack(sha1_value))),
        ):
            (ARTIFACTS / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        print("\nwrote three artifacts; SHA-1 bound %d" % sha1_score)

    print("\nScored through the pinned evaluators:")
    failures = rescore(check_only)
    if optimal_score != 17 or baseline_score != 20:
        failures.append(
            "the SHA-0 search moved: optimum %d, single-bit %d; "
            "objective-dv-sha0.json is written for 17 and 20"
            % (optimal_score, baseline_score)
        )
        print("DRIFT: %s" % failures[-1], file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
