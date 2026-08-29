#!/usr/bin/env python3
"""Generate the pinned checkers and evaluators for the hash-differential family.

    build_pinned.py            # rewrite the pinned files and re-pin the objectives
    build_pinned.py --check    # verify the checked-in files match (CI)

# Why these files are generated rather than written

There are eight of them and they are nearly the same file. Six certificate
checkers differ only in a pinned instance block -- which hash, how many steps
of it, how many digest bits must agree, and which public prefix -- and the two
disturbance-vector evaluators differ only in whether the message expansion
rotates. Hand-maintaining eight copies of one argument is how five of them end
up correct and the sixth quietly does not check what its README says it does.

A pinned file cannot import a shared module: `docs/verification.md` rule 4 is
that a checker reading an unpinned file passes today and fails tomorrow at the
same hash, and `checker_sha256` covers this file only. So the duplication is
forced. What is not forced is that the copies drift, and `--check` is what
stops that: it re-renders every file and diffs, exactly as
`scripts/derive-first-blood.py --check` and
`examples/faster-algorithms/tools/build_baselines.py --check` do for their own
derived files.

# Regenerating moves objective ids, and that is correct

A checker's sha256 is inside its objective's id, so editing a template reissues
every objective it renders. That is the property that makes a mid-bounty rule
change unrepresentable rather than merely forbidden -- an edited instance forks
the objective instead of rescoring work already done against it. This script
rewrites the `checker_sha256` / `evaluator_sha256` field in each objective so
the pin and the file cannot disagree; the id moving is the visible consequence
and is meant to be noticed in review.

# Why the prefixes are derived and 64 bytes long

`PREFIX = sha512(seed)`, for a seed string printed in the file next to it.

*Derived*, because a funder who chooses a prefix can choose one whose chaining
value they have already attacked, and collect their own bounty. Every published
collision for these functions starts from the function's standard IV with a
prefix its author chose, so a derived prefix also makes the whole published
corpus unreplayable here: copying earns exactly zero because there is nothing
to copy. Grinding the seed buys nothing, for the same reason it buys nothing in
`scripts/derive-first-blood.py`: to gain you would have to recognise a chaining
value you can already collide, and recognising one means doing the work.

*64 bytes*, because that is exactly one message block for all four of these
functions. The chaining value the attack starts from is then one compression of
a public constant, with no partial block to fill first -- which is the input
every published attack tool actually takes.
"""

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT.parent.parent

SEED_PREFIX = "cairn hash-differential v1 "


# ---------------------------------------------------------------------------
# Shared source fragments. These are the bodies that get copied into every
# generated file; the argument for each one is written where it lands, not
# here, so the pinned file is readable on its own by someone auditing a bounty.
# ---------------------------------------------------------------------------

PREAMBLE = '''
_M32 = 0xFFFFFFFF


def _rotl(x, n):
    x &= _M32
    return ((x << n) | (x >> (32 - n))) & _M32
'''

PAD_LE = '''

def _pad(message):
    """Merkle-Damgard padding, little-endian length. RFC 1320 / RFC 1321."""
    bits = (8 * len(message)) & ((1 << 64) - 1)
    padded = message + b"\\x80"
    padded += b"\\x00" * ((56 - len(padded) % 64) % 64)
    return padded + bits.to_bytes(8, "little")
'''

PAD_BE = '''

def _pad(message):
    """Merkle-Damgard padding, big-endian length. FIPS 180."""
    bits = (8 * len(message)) & ((1 << 64) - 1)
    padded = message + b"\\x80"
    padded += b"\\x00" * ((56 - len(padded) % 64) % 64)
    return padded + bits.to_bytes(8, "big")
'''

MD4 = '''

_MD4_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
_MD4_ORDER = (
    tuple(range(16)),
    (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15),
    (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15),
)
_MD4_SHIFT = ((3, 7, 11, 19), (3, 5, 9, 13), (3, 9, 11, 15))
_MD4_ADD = (0, 0x5A827999, 0x6ED9EBA1)


def _compress(state, block):
    w = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(16)]
    a, b, c, d = state
    for i in range(STEPS):
        rnd = i // 16
        if rnd == 0:
            f = (b & c) | (~b & d)
        elif rnd == 1:
            f = (b & c) | (b & d) | (c & d)
        else:
            f = b ^ c ^ d
        t = (a + (f & _M32) + w[_MD4_ORDER[rnd][i % 16]] + _MD4_ADD[rnd]) & _M32
        a, d, c, b = d, c, b, _rotl(t, _MD4_SHIFT[rnd][i % 4])
    return tuple((x + y) & _M32 for x, y in zip(state, (a, b, c, d)))
'''

MD5 = '''

_MD5_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
# floor(2^32 * abs(sin(i + 1))), the RFC 1321 table. Written out rather than
# computed from `math.sin`: this file decides who is paid, and a table derived
# through the platform's libm is a table that can differ between two honest
# nodes. Integers in the source cannot.
_MD5_K = (
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
)
_MD5_S = (
    (7, 12, 17, 22), (5, 9, 14, 20), (4, 11, 16, 23), (6, 10, 15, 21),
)


def _compress(state, block):
    w = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(16)]
    a, b, c, d = state
    for i in range(STEPS):
        rnd = i // 16
        if rnd == 0:
            f, k = (b & c) | (~b & d), i
        elif rnd == 1:
            f, k = (d & b) | (~d & c), (5 * i + 1) % 16
        elif rnd == 2:
            f, k = b ^ c ^ d, (3 * i + 5) % 16
        else:
            f, k = c ^ (b | (~d & _M32)), (7 * i) % 16
        t = (a + (f & _M32) + _MD5_K[i] + w[k]) & _M32
        a, d, c, b = d, c, b, (b + _rotl(t, _MD5_S[rnd][i % 4])) & _M32
    return tuple((x + y) & _M32 for x, y in zip(state, (a, b, c, d)))
'''

SHA = '''

_SHA_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
_SHA_K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)


def _compress(state, block):
    w = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(16)]
    for i in range(16, STEPS):
        x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
        # The single bit of difference between SHA-0 and SHA-1, and the reason
        # one of these two objectives is a worked demonstration and the other
        # is an open bounty. See the disturbance-vector evaluators.
        w.append(_rotl(x, 1) if ROTATE_EXPANSION else x)
    a, b, c, d, e = state
    for i in range(STEPS):
        rnd = i // 20
        if rnd == 0:
            f = (b & c) | (~b & d)
        elif rnd == 2:
            f = (b & c) | (b & d) | (c & d)
        else:
            f = b ^ c ^ d
        t = (_rotl(a, 5) + (f & _M32) + e + _SHA_K[rnd] + w[i]) & _M32
        a, b, c, d, e = t, a, _rotl(b, 30), c, d
    return tuple((x + y) & _M32 for x, y in zip(state, (a, b, c, d, e)))
'''

CHECK = '''

def _trace(message):
    """Chaining value after every block. The path is recomputed from here."""
    data = _pad(message)
    state = _IV
    chain = [state]
    for offset in range(0, len(data), 64):
        state = _compress(state, data[offset:offset + 64])
        chain.append(state)
    return chain


def _digest(chain):
    return b"".join(x.to_bytes(4, _ENDIAN) for x in chain[-1])


def _decode(value, field):
    if not isinstance(value, str) or not value:
        return None, "artifact.%s must be a non-empty lowercase hex string" % field
    # Length before content. The artifact is attacker-supplied and it is billing
    # this node's CPU, so the megabyte of hex that would be rejected anyway is
    # rejected before it is scanned and decoded rather than after.
    if len(value) > 2 * MAX_MESSAGE_BYTES:
        return None, (
            "artifact.%s may be at most %d hex characters; got %d"
            % (field, 2 * MAX_MESSAGE_BYTES, len(value))
        )
    if len(value) % 2:
        return None, "artifact.%s must have an even number of hex characters" % field
    if any(c not in "0123456789abcdef" for c in value):
        return None, "artifact.%s must be lowercase hex" % field
    return bytes.fromhex(value), None


def _path(left, right, chain_left, chain_right):
    """Describe the differential path the pair actually follows.

    Derived by recomputation, never read off a field the submitter filled in.
    An artifact carrying a path it does not follow is not a different verdict
    here, it is the same verdict with a different sentence attached -- which is
    the point: the pair is the claim, and the path is what the pair does.
    """
    words = [
        i for i in range(0, min(len(left), len(right)), 4)
        if left[i:i + 4] != right[i:i + 4]
    ]
    steps = [
        i for i, (x, y) in enumerate(zip(chain_left, chain_right)) if x != y
    ]
    if not steps:
        return "no block ever differs (%d message words differ)" % len(words)
    # Whether the pair is a true collision or only agrees on the compared
    # prefix is visible right here, in the last chaining value, so say which
    # rather than letting a truncated instance read as a full one.
    closed = chain_left[-1] == chain_right[-1]
    return (
        "%d message words differ, first at word %d; the chaining difference is "
        "nonzero after blocks %d..%d of %d, and %s"
        % (
            len(words), words[0] // 4, steps[0], steps[-1], len(chain_left) - 1,
            "zero from there on -- a collision in the full state"
            if closed else
            "still nonzero at the end, so the pair agrees on the compared "
            "digest prefix and not on the whole state",
        )
    )


def check(artifact):
    if not isinstance(artifact, dict):
        return False, "artifact must be an object"
    left, error = _decode(artifact.get("m"), "m")
    if error is not None:
        return False, error
    right, error = _decode(artifact.get("m_prime"), "m_prime")
    if error is not None:
        return False, error
    if left == right:
        return False, "m and m_prime are the same message; a hash collides with itself"
    if len(left) != len(right):
        return False, (
            "m and m_prime must have the same length; got %d and %d bytes"
            % (len(left), len(right))
        )
    if len(left) > MAX_MESSAGE_BYTES:
        return False, (
            "messages may be at most %d bytes; got %d"
            % (MAX_MESSAGE_BYTES, len(left))
        )
    if not left.startswith(PREFIX) or not right.startswith(PREFIX):
        return False, (
            "both messages must begin with the pinned %d-byte prefix"
            % len(PREFIX)
        )
    chain_left, chain_right = _trace(left), _trace(right)
    digest_left = _digest(chain_left)[:DIGEST_BYTES]
    digest_right = _digest(chain_right)[:DIGEST_BYTES]
    if digest_left != digest_right:
        differing = sum(
            bin(x ^ y).count("1") for x, y in zip(digest_left, digest_right)
        )
        return False, (
            "digests differ in %d of %d bits: %s vs %s"
            % (differing, 8 * DIGEST_BYTES, digest_left.hex(), digest_right.hex())
        )
    return True, "%s on %s: %s" % (
        _CLAIM, digest_left.hex(), _path(left, right, chain_left, chain_right)
    )
'''

DV = '''
STEPS = 80
# Steps 0..19 are free to an attacker: the first sixteen message words are
# chosen directly, so conditions there are met by construction rather than by
# search. The weight that costs anything is what is left after that, which is
# why the score starts at step 20 and not at step 0.
SCORE_FROM = 20
# A disturbance at step i is cancelled by corrections at steps i+1..i+5. There
# is no step 80, so a disturbance at 75 or later has no room to be corrected
# and the vector cannot be completed into local collisions inside one
# compression. Refused rather than scored: a vector that cannot be used is not
# a good vector that happens to be cheap.
#
# Multi-block attacks relax exactly this, letting the uncorrected tail become a
# near-collision that the next block cancels. A vector refused here can still
# be useful there -- this objective buys single-block vectors, and says so.
TAIL_FROM = 75
MAX_OFFSET = STEPS - 16

# What an invalid artifact scores.
#
# A *minimise* objective cannot reject with zero, because zero is the best
# score expressible: the all-zero vector satisfies the recurrence, weighs
# nothing, and would take the frontier and the whole pool behind it while
# describing no attack at all. The rejection value has to be worse than every
# honest answer, which on this direction means larger than the heaviest
# possible vector.
INVALID = 32 * (STEPS - SCORE_FROM) + 1

_M32 = 0xFFFFFFFF


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def _expand(window, offset):
    """The 80-word codeword through the real message expansion, both ways.

    Sixteen consecutive words determine a codeword everywhere, because the
    recurrence is invertible: forwards it is the expansion itself, and
    backwards W[i] = R'(W[i+16]) ^ W[i+13] ^ W[i+8] ^ W[i+2]. Accepting a
    window at any offset is not a convenience -- published vectors are named by
    the position of the window that generates them, and forcing them to be
    re-anchored at step 0 by hand would make transcription errors the most
    likely failure of a submission.
    """
    dv = [0] * STEPS
    dv[offset:offset + 16] = window
    for i in range(offset + 16, STEPS):
        x = dv[i - 3] ^ dv[i - 8] ^ dv[i - 14] ^ dv[i - 16]
        dv[i] = _rotl(x, 1) if ROTATE_EXPANSION else x
    for i in range(offset - 1, -1, -1):
        x = _rotl(dv[i + 16], 31) if ROTATE_EXPANSION else dv[i + 16]
        dv[i] = x ^ dv[i + 13] ^ dv[i + 8] ^ dv[i + 2]
    return dv


def _window(artifact):
    """The 16 seed words, or None. Shape errors are scores, never exceptions."""
    if not isinstance(artifact, dict):
        return None
    offset = artifact.get("offset")
    if not isinstance(offset, int) or isinstance(offset, bool):
        return None
    if not 0 <= offset <= MAX_OFFSET:
        return None
    words = artifact.get("window")
    if not isinstance(words, list) or len(words) != 16:
        return None
    decoded = []
    for word in words:
        # Exactly one spelling, so one vector has one artifact and one digest.
        # "0x1", "1" and "00000001" are the same number and would otherwise be
        # three settling answers to one problem.
        if not isinstance(word, str) or len(word) != 8:
            return None
        if any(c not in "0123456789abcdef" for c in word):
            return None
        decoded.append(int(word, 16))
    return offset, decoded


def score(artifact):
    parsed = _window(artifact)
    if parsed is None:
        return INVALID
    offset, window = parsed
    dv = _expand(window, offset)
    if not any(dv):
        return INVALID
    if any(dv[i] for i in range(TAIL_FROM, STEPS)):
        return INVALID
    return sum(bin(dv[i]).count("1") for i in range(SCORE_FROM, STEPS))
'''


# ---------------------------------------------------------------------------
# The instances
# ---------------------------------------------------------------------------

FAMILY = {
    "md4": {"pad": PAD_LE, "body": MD4, "endian": "little", "iv": "_MD4_IV",
            "full_steps": 48, "digest_bytes": 16, "label": "MD4"},
    "md5": {"pad": PAD_LE, "body": MD5, "endian": "little", "iv": "_MD5_IV",
            "full_steps": 64, "digest_bytes": 16, "label": "MD5"},
    "sha0": {"pad": PAD_BE, "body": SHA, "endian": "big", "iv": "_SHA_IV",
             "full_steps": 80, "digest_bytes": 20, "label": "SHA-0", "rotate": False},
    "sha1": {"pad": PAD_BE, "body": SHA, "endian": "big", "iv": "_SHA_IV",
             "full_steps": 80, "digest_bytes": 20, "label": "SHA-1", "rotate": True},
}

INSTANCES = [
    {
        "name": "collide_md5_48",
        "objective": "objective-collide-md5-48.json",
        "family": "md5",
        "steps": 64,
        "digest_bits": 48,
        "seed": "md5-48",
        "cost": "about 2^24 MD5 computations, by any method at all",
        "intro": """This is the rung that exists to be climbed on the way in, and its answer
ships. Only the first 48 digest bits have to agree, so a generic birthday
search settles it in about 2^24 compressions -- a minute of one core, with no
cryptanalysis anywhere in it.

It is here for two reasons, both of them about the *checker* rather than about
MD5. It makes the whole loop -- post, commit, reveal, audit -- runnable end to
end from a committed artifact. And it demonstrates that this family of checkers
accepts something, which a checker shown only to reject cannot demonstrate
about itself: a checker that rejects everything is indistinguishable from a
correct one until a real pair passes it.

`artifacts/md5-48.json` is that pair, found by the rho search in
`tools/solve_truncated.py`, and it is published here -- so this objective is a
demonstration rather than a bounty, and settling it a second time earns
exactly zero.""",
    },
    {
        "name": "collide_md4",
        "objective": "objective-collide-md4.json",
        "family": "md4",
        "steps": 48,
        "digest_bits": 128,
        "seed": "md4",
        "cost": "a few hundred MD4 computations with the published differential path",
        "intro": """Full MD4, all 48 steps, all 128 digest bits, from a chaining value nobody
chose.

MD4 has been broken since Wang et al. (2005) and the attack has since been
sharpened to a couple of MD4 computations, so this is the cheapest real
differential-path work on the ladder -- an afternoon for someone implementing
the published path, and minutes for someone who already has. It is a bounty
rather than a demonstration only because *this* chaining value has not been
collided: the attack is public, the answer is not.

Nothing here helps you build the path, and the checker is indifferent to how
you built it.""",
    },
    {
        "name": "collide_md5",
        "objective": "objective-collide-md5.json",
        "family": "md5",
        "steps": 64,
        "digest_bits": 128,
        "seed": "md5",
        "cost": "roughly 2^16 to 2^24 MD5 computations with published tooling",
        "intro": """Full MD5, all 64 steps, all 128 digest bits, from a chaining value nobody
chose.

The identical-prefix attack works from an arbitrary chaining value and the
published implementations take a parameter for exactly that, so this rung is
minutes of compute for someone willing to run other people's code. That is a
statement about MD5 in 2026 and not a complaint about the bounty: the ladder
needs a rung where the cost is real, small, and known.""",
    },
    {
        "name": "collide_sha1_64",
        "objective": "objective-collide-sha1-64.json",
        "family": "sha1",
        "steps": 64,
        "digest_bits": 160,
        "seed": "sha1-64",
        "cost": "roughly 2^35 compressions with a published 64-step path",
        "intro": """SHA-1 cut to its first 64 steps: same padding, same expansion, same round
functions and constants, the last 16 steps simply not run, and the input
chaining value added to the state as usual. The reduced function is defined by
this file and nothing else, which is what makes "SHA-1 reduced to 64 steps"
a settleable phrase rather than a convention two nodes could read differently.

This is the bridge rung. Full SHA-0 and full SHA-1 are separated by nearly
thirty bits of work, and a ladder with nothing in that gap is a ladder with one
step missing exactly where the interesting differential-path engineering
happens: 64-step collisions were found in 2006 with paths built by hand and by
search, at a cost a single machine can still pay.""",
    },
    {
        "name": "collide_sha0",
        "objective": "objective-collide-sha0.json",
        "family": "sha0",
        "steps": 80,
        "digest_bits": 160,
        "seed": "sha0",
        "cost": "roughly 2^33 to 2^39 compressions, with a published vector",
        "intro": """Full SHA-0 -- the withdrawn 1993 function, identical to SHA-1 except that its
message expansion does not rotate -- all 80 steps, all 160 digest bits, from a
chaining value nobody chose.

The missing rotation is the whole of the difference and the whole of the
break: without it the expansion acts on the 32 bit positions independently, so
its low-weight codewords can be enumerated rather than searched for. That is
not an assertion here, it is the arithmetic that
`evaluators/dv_sha0.py` settles and `evaluators/dv_sha1.py` does not.

Cost is hours to days on one machine, which makes this the first rung on the
ladder that a laptop cannot finish while you watch.""",
    },
    {
        "name": "collide_sha1",
        "objective": "objective-collide-sha1.json",
        "family": "sha1",
        "steps": 80,
        "digest_bits": 160,
        "seed": "sha1",
        "cost": "2^61 to 2^63 compressions; this rung is not expected to settle",
        "intro": """Full SHA-1, all 80 steps, all 160 digest bits, from a chaining value nobody
chose. **This objective is not expected to settle**, and it is posted anyway,
for the same reason `examples/certicom-ecdlp/` posts ECCp-131: a research
network should carry one benchmark whose difficulty nobody local chose.

Published estimates for the identical-prefix attack run between 2^61 and
2^63 compressions. SHAttered (2017) paid it once, across a GPU cluster, over
months. Everything cheaper that is
published -- the two-block structure, the disturbance vectors, the speed-ups --
is public and does not move that exponent much.

The gap between this rung and the 64-step rung below it is where the field
actually is. A better disturbance vector, which `objective-dv-sha1.json`
pays for directly, is one of the few things that moves it.""",
    },
]

DV_INSTANCES = [
    {
        "name": "dv_sha0",
        "objective": "objective-dv-sha0.json",
        "family": "sha0",
        "intro": """SHA-0's expansion, W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], has no
rotation in it. XOR acts on each of the 32 bit positions separately, so a
codeword of this recurrence is 32 independent codewords of one length-80 binary
code with 16 free bits -- and the weight of the whole is the sum of the weights
of the parts.

**That makes this objective exhaustively solvable, and its optimum proved.**
The lightest vector overall is the lightest vector in one bit position, because
using a second position only adds weight; and one bit position has 2^16
codewords, which is a loop. `tools/search_dv.py` runs it. The answer is 17, the
pool is exactly exhausted there, and `artifacts/dv-sha0-optimal.json` reaches
it.

It is here as the control for `dv_sha1.py`, which is the same objective over
the same recurrence with the rotation put back, and which nobody can solve this
way. Two files, one line of difference, and the whole reason SHA-1 replaced
SHA-0 sits in the gap between what the two can prove.""",
    },
    {
        "name": "dv_sha1",
        "objective": "objective-dv-sha1.json",
        "family": "sha1",
        "intro": """SHA-1's expansion, W[i] = ROTL1(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]), is the
same recurrence as SHA-0's with one rotation added, and that rotation couples
the 32 bit positions. The code stops being 32 independent copies of a
[80, 16] binary code and becomes one [2560, 512] code, where finding a
minimum-weight codeword is the hard problem it is everywhere else.

So unlike `dv_sha0.py`, **nothing here proves an optimum**, and the target
below is a construction target rather than a bound. What the searches in
`tools/search_dv.py` establish is only an upper bound: 31, from a
single-bit window, unbeaten by every pair of single-bit windows, by sampled
three- and four-bit windows, and by a beam search over XOR combinations of
them. That is the baseline, so the vector this repository already holds
settles for nothing and the pool pays only for beating it.

One structural fact worth knowing before searching: rotating every word of a
codeword by the same amount gives another codeword of the same weight, because
ROTL commutes with both XOR and ROTL1. Bit position is therefore free, and only
the pattern matters.""",
    },
]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

CHECKER_HEADER = '''"""Certificate checker: a conforming pair for @@TITLE@@.

@@INTRO@@

# What is checked, exactly

Two hex messages of equal length, both beginning with the pinned prefix,
differing somewhere, whose @@CLAIM@@. Nothing else.

Equal length is a requirement rather than an accident. A same-length collision
composes: H(m || x) = H(m' || x) for every x, because Merkle-Damgard feeds the
same chaining value into the same remaining blocks. Colliding pairs of
different lengths do not compose, and the property that makes a collision worth
paying for is exactly the one that survives being appended to.

# What this does NOT decide

Anything about method. A pair from a hand-built differential path, from
published tooling, or from a birthday search verifies identically -- which is
the property that makes an unreliable contributor safe to accept, and the
reason this network buys artifacts rather than effort.

It also decides nothing about @@LABEL@@ in general: it decides one pair
against one pinned chaining value.

Cost is @@COST@@.

# Provenance

Generated by `tools/build_pinned.py`; `--check` re-renders it and diffs. The
sha256 of this file is inside the objective's id, so the instance below IS part
of the objective's identity: nobody can retarget a funded bounty at an easier
prefix, and an edit forks the objective rather than rescoring work already
done against it.

Self-contained on purpose. `docs/verification.md` rule 4: a checker that reads
an unpinned file passes today and fails tomorrow at the same hash.
"""

# -- the pinned instance ----------------------------------------------------
#
# PREFIX is sha512 of the seed string below: 64 bytes, which is exactly one
# message block for this function. Derived and not chosen -- a funder who picks
# a prefix can pick one whose chaining value they have already attacked.
# Deriving it also puts every published collision for @@LABEL@@ out of reach as
# a copy, since all of them start from the standard IV behind a prefix their
# own author chose.
PREFIX_SEED = "@@SEED@@"
PREFIX = bytes.fromhex(
    "@@PREFIX_A@@"
    "@@PREFIX_B@@"
)
# Compression steps actually run.
# @@STEPS_NOTE@@
STEPS = @@STEPS@@
# Leading digest bytes that must agree.
# @@DIGEST_NOTE@@
DIGEST_BYTES = @@DIGEST_BYTES@@
# The artifact is attacker-supplied and it is billing this node's CPU. A
# collision needs two blocks past the prefix, not sixty-four; the cap is
# generous and still bounds the check at a few thousand step functions.
MAX_MESSAGE_BYTES = 4096
'''

EVALUATOR_HEADER = '''"""Evaluator: how light can a @@LABEL@@ disturbance vector be?

@@INTRO@@

# What a disturbance vector is, and what this scores

A collision attack on a SHA-family compression function is built by picking a
difference in the expanded message words that can be cancelled, step by step,
by local collisions -- a disturbance at step i, and corrections at steps
i+1..i+5 that undo it. The difference has to be a codeword of the message
expansion, because expanded words are not free: they are determined by the
first sixteen. That codeword is the disturbance vector, and it is chosen before
any of the rest of the attack exists.

Its weight is what the attack costs. Every disturbed bit forces roughly two
conditions on the working state, and conditions in steps a message-modification
pass cannot reach have to be met by search. So:

    score = sum of the Hamming weights of DV[20..79], minimised

**This is a proxy and it is stated as one.** True attack cost also depends on
which bit positions are disturbed, on how local collisions overlap, and on how
far message modification actually reaches. What is being bought here is a
low-weight codeword of a specific linear code over a specific range, decided
exactly, and not a claim about anybody's attack.

# Why an empty answer cannot take the pool

The all-zero vector is a codeword, weighs nothing, and describes no attack, so
on a minimise objective it would take the frontier and the pool behind it.
Two things stop it. It is refused outright. And it could not have won anyway:
the score range is 60 words wide and the tail is required to be zero, so a
vector scoring 0 would have 60 consecutive zero words -- and any 16 consecutive
words determine a codeword everywhere, so 16 zeros already force the all-zero
vector. The minimum achievable score is bounded away from zero by the geometry
of the code, not by the guard, which is the version of that argument worth
having.

# Provenance

Generated by `tools/build_pinned.py`; `--check` re-renders it and diffs. The
sha256 of this file is inside the objective's id, so an edit forks the
objective rather than rescoring work already done against it.

Returns an int. Never a float -- see `src/verifiers/mod.rs` for why.
"""

# @@ROTATE_NOTE@@
ROTATE_EXPANSION = @@ROTATE@@
'''


def _substitute(template, values):
    text = template
    for key, value in values.items():
        text = text.replace("@@%s@@" % key, str(value))
    if "@@" in text:
        raise SystemExit("unsubstituted placeholder in template: %r" % text[
            text.index("@@"):text.index("@@") + 40
        ])
    return text


def render_checker(instance):
    family = FAMILY[instance["family"]]
    steps, full = instance["steps"], family["full_steps"]
    bits = instance["digest_bits"]
    full_bits = 8 * family["digest_bytes"]
    if bits % 8 or not 0 < bits <= full_bits:
        raise SystemExit("digest_bits must be a multiple of 8 in (0, %d]" % full_bits)
    if not 16 < steps <= full:
        raise SystemExit("steps must be in (16, %d]" % full)

    seed = SEED_PREFIX + instance["seed"]
    prefix = hashlib.sha512(seed.encode()).hexdigest()
    reduced = steps != full
    truncated = bits != full_bits
    claim = (
        "first %d digest bits agree" % bits if truncated
        else "digests are equal on all %d bits" % full_bits
    )
    header = _substitute(CHECKER_HEADER, {
        "TITLE": "%s%s%s" % (
            family["label"],
            " reduced to %d steps" % steps if reduced else "",
            ", truncated to %d bits" % bits if truncated else "",
        ),
        "INTRO": instance["intro"],
        "CLAIM": claim,
        "LABEL": family["label"],
        "COST": instance["cost"],
        "SEED": seed,
        "PREFIX_A": prefix[:64],
        "PREFIX_B": prefix[64:],
        "STEPS": steps,
        "DIGEST_BYTES": bits // 8,
        "STEPS_NOTE": (
            "Reduced from %d: the last %d steps are not run, so this is a\n"
            "# step-reduced variant, defined by this file and not by the\n"
            "# standard function."
            % (full, full - steps) if reduced else
            "All of them -- the unmodified function."
        ),
        "DIGEST_NOTE": (
            "Truncated from %d: only the leading %d bits have to agree,\n"
            "# which is what puts a generic birthday search in range and is why\n"
            "# this instance is a demonstration rather than a bounty."
            % (family["digest_bytes"], bits) if truncated else
            "All of them."
        ),
    })
    parts = [header]
    if "rotate" in family:
        parts.append(
            "# %s.\nROTATE_EXPANSION = %s\n" % (
                "SHA-1's expansion rotates; SHA-0's does not" if family["rotate"]
                else "SHA-0 is SHA-1 without this rotation, and that is the whole break",
                family["rotate"],
            )
        )
    parts.append('_CLAIM = "%s"\n_ENDIAN = "%s"\n' % (
        "collision on all %d digest bits" % full_bits if not truncated
        else "agreement on the leading %d digest bits" % bits,
        family["endian"],
    ))
    parts.append(PREAMBLE)
    parts.append(family["pad"])
    parts.append(family["body"])
    parts.append("\n\n_IV = %s\n" % family["iv"])
    parts.append(CHECK)
    return "".join(parts)


def render_evaluator(instance):
    family = FAMILY[instance["family"]]
    header = _substitute(EVALUATOR_HEADER, {
        "LABEL": family["label"],
        "INTRO": instance["intro"],
        "ROTATE": family["rotate"],
        "ROTATE_NOTE": (
            "The one line that separates this file from dv_sha0.py."
            if family["rotate"] else
            "The one line that separates this file from dv_sha1.py."
        ),
    })
    return header + DV


def repin(objective_path, field, digest, check_only):
    """Point the objective at the file that was just rendered."""
    record = json.loads(objective_path.read_text())
    current = record["verifier"].get(field)
    if current == digest:
        return None
    if check_only:
        return "%s pins a stale %s" % (objective_path.relative_to(REPO), field)
    record["verifier"][field] = digest
    objective_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return None


def main():
    check_only = "--check" in sys.argv[1:]
    drift = []
    rendered = [
        (ROOT / "checkers" / ("%s.py" % i["name"]), render_checker(i), i, "checker_sha256")
        for i in INSTANCES
    ] + [
        (ROOT / "evaluators" / ("%s.py" % i["name"]), render_evaluator(i), i,
         "evaluator_sha256")
        for i in DV_INSTANCES
    ]
    for path, body, instance, field in rendered:
        if check_only:
            if not path.exists():
                drift.append("%s is missing" % path.relative_to(REPO))
                continue
            if path.read_text() != body:
                drift.append("%s does not match its generator" % path.relative_to(REPO))
        else:
            path.write_text(body)
        digest = hashlib.sha256(body.encode()).hexdigest()
        stale = repin(ROOT / instance["objective"], field, digest, check_only)
        if stale:
            drift.append(stale)
        print("  %-44s sha256=%s" % (path.relative_to(ROOT), digest))
    if drift:
        for line in drift:
            print("DRIFT: %s" % line, file=sys.stderr)
        print(
            "\nRe-run examples/hash-differential/tools/build_pinned.py to fix.",
            file=sys.stderr,
        )
        return 1
    print("\n%d pinned files %s." % (
        len(rendered), "match their generator" if check_only else "written",
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
