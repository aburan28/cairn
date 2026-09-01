#!/usr/bin/env python3
"""Adversarial battery for the hash-differential checkers and evaluators.

    selftest.py

Eight pinned files decide who is paid on eight objectives, seven of which are
open. An open objective can only ever be observed *rejecting*, and a checker
observed only to reject is indistinguishable from one that rejects everything
-- so the interesting half of this file is the acceptances, and the rest is the
battery of things that must not be accepted.

What is asserted, and why each one is here:

1.  **Acceptance.** The committed 48-bit pair passes its own checker, and the
    three committed disturbance vectors score what their objectives were
    written for. Without this the whole directory is unfalsifiable.

2.  **The prefix binds.** A pair that collides behind a *different* prefix is
    refused. This is the property that makes every published collision for
    these functions worth nothing here, and it is the anti-self-dealing
    argument in `docs/threat-model.md` in executable form.

3.  **Truncation is not collision.** The 48-bit pair is refused by the full-MD5
    checker generated from the same template. Six near-identical files are
    exactly where a copied constant goes unnoticed, so the instance blocks are
    checked against each other rather than each against itself.

4.  **The reference functions are the real ones.** Every generated checker's
    digest is compared against `hashlib` where `hashlib` has the function, and
    against the published test vectors where it does not -- MD4 and SHA-0 are
    not in any modern OpenSSL, so a transcription error there would otherwise
    be invisible until it silently refused a correct break.

5.  **Malformed artifacts score, never raise.** `docs/verification.md` rule 3:
    an exception out of pinned code is a broken verifier, which is `Unavailable`
    -- and `Unavailable` is never `Reject`. A checker that throws on a stray
    type hands an attacker a way to make honest submissions unresolvable.

6.  **Nothing takes a minimise pool for free.** The all-zero vector, the vector
    with an uncorrectable tail, and every malformed shape must score strictly
    worse than the heaviest honest vector -- not zero, which on a minimise
    objective is the best score expressible and would take the frontier and the
    pool behind it.

7.  **The evaluator's own algebra.** Re-anchoring a vector at another offset,
    and rotating every one of its words, must not change its score: both are
    symmetries of the code, and a submitter who writes a published vector down
    at the offset it was published at must not be scored differently from one
    who re-anchored it by hand.
"""

import hashlib
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
FAILURES = []


def load(kind, name):
    path = ROOT / kind / ("%s.py" % name)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def artifact(name):
    return json.loads((ROOT / "artifacts" / name).read_text())


def objective(name):
    return json.loads((ROOT / name).read_text())


def report(ok, description, detail=""):
    print("  %s %s%s" % ("ok  " if ok else "FAIL", description,
                         "" if ok else "  <- %s" % detail))
    if not ok:
        FAILURES.append(description)


def accepts(checker, art, description):
    try:
        ok, detail = checker.check(art)
    except Exception as error:                      # noqa: BLE001 - that is the test
        report(False, description, "raised %r" % error)
        return
    report(ok, description, detail)


def refuses(checker, art, description):
    try:
        ok, detail = checker.check(art)
    except Exception as error:                      # noqa: BLE001 - that is the test
        report(False, description, "raised %r instead of returning False" % error)
        return
    report(not ok, description, "accepted: %s" % detail)


CHECKERS = {
    name: load("checkers", name) for name in (
        "collide_md4", "collide_md5", "collide_md5_48",
        "collide_sha0", "collide_sha1", "collide_sha1_64",
    )
}
EVALUATORS = {name: load("evaluators", name) for name in ("dv_sha0", "dv_sha1")}


# -- 1. acceptance ----------------------------------------------------------
print("\nacceptance -- the only evidence a checker accepts anything")
pair = artifact("md5-48.json")
accepts(CHECKERS["collide_md5_48"], pair, "the committed 48-bit pair passes its checker")

for name, which, expected in (
    ("dv-sha0-optimal.json", "dv_sha0", 17),
    ("dv-sha0-baseline.json", "dv_sha0", 20),
    ("dv-sha1-baseline.json", "dv_sha1", 31),
):
    got = EVALUATORS[which].score(artifact(name))
    report(got == expected, "%s scores %d" % (name, expected), "scored %d" % got)

for name, key in (
    ("objective-dv-sha0.json", "dv-sha0-optimal.json"),
    ("objective-dv-sha1.json", "dv-sha1-baseline.json"),
):
    record = objective(name)
    which = "dv_sha0" if "sha0" in name else "dv_sha1"
    score = EVALUATORS[which].score(artifact(key))
    ratchet = record["ratchet"]
    report(
        score <= record["verifier"]["threshold"],
        "%s: the committed vector clears the threshold" % name,
        "score %d, threshold %d" % (score, record["verifier"]["threshold"]),
    )
    report(
        ratchet["target"] <= score <= ratchet["baseline"],
        "%s: the committed vector lies inside the ratchet" % name,
        "score %d outside [%d, %d]" % (score, ratchet["target"], ratchet["baseline"]),
    )
report(
    EVALUATORS["dv_sha0"].score(artifact("dv-sha0-optimal.json"))
    == objective("objective-dv-sha0.json")["ratchet"]["target"],
    "the SHA-0 vector reaches the proved optimum and exhausts the pool",
)


# The `artifact_schema` in each record is a submitter's only non-prose source
# for the shape of an answer, so it has to be one. For the two ratchets the
# example is the objective's own baseline and must score exactly that -- an
# example that quietly did better would be publishing part of the answer inside
# the question.
for name, which in (("objective-dv-sha0.json", "dv_sha0"),
                    ("objective-dv-sha1.json", "dv_sha1")):
    record = objective(name)
    got = EVALUATORS[which].score(record["artifact_schema"]["example"])
    report(got == record["ratchet"]["baseline"],
           "%s: the schema example scores exactly the baseline" % name,
           "scored %d, baseline %d" % (got, record["ratchet"]["baseline"]))

# For the six collision objectives the example cannot collide -- that is the
# bounty -- but it must be well formed enough to be refused *for not colliding*
# rather than for its shape, or it is teaching the wrong shape.
for name, which in (
    ("objective-collide-md4.json", "collide_md4"),
    ("objective-collide-md5.json", "collide_md5"),
    ("objective-collide-md5-48.json", "collide_md5_48"),
    ("objective-collide-sha0.json", "collide_sha0"),
    ("objective-collide-sha1.json", "collide_sha1"),
    ("objective-collide-sha1-64.json", "collide_sha1_64"),
):
    ok, detail = CHECKERS[which].check(objective(name)["artifact_schema"]["example"])
    report(not ok and detail.startswith("digests differ"),
           "%s: the schema example is refused only for not colliding" % name,
           detail)

# -- 2. the prefix binds ----------------------------------------------------
print("\nthe pinned prefix -- why no published collision can be replayed here")
refuses(
    CHECKERS["collide_md5_48"],
    {"m": pair["m"][2:], "m_prime": pair["m_prime"][2:]},
    "a colliding pair with the prefix truncated is refused",
)
refuses(
    CHECKERS["collide_md5_48"],
    {
        "m": "00" + pair["m"][2:],
        "m_prime": "00" + pair["m_prime"][2:],
    },
    "a colliding pair behind a different prefix is refused",
)
foreign = CHECKERS["collide_md5"].PREFIX
report(
    foreign != CHECKERS["collide_md5_48"].PREFIX,
    "every instance derives a different prefix",
)
refuses(
    CHECKERS["collide_md5"],
    {"m": (foreign + b"\x00").hex(), "m_prime": (foreign + b"\x01").hex()},
    "two messages behind the right prefix that simply do not collide are refused",
)


# -- 3. the instances are not each other ------------------------------------
print("\ninstance separation -- six near-identical files that must not agree")
refuses(
    CHECKERS["collide_md5"],
    pair,
    "the 48-bit pair is refused by the full-MD5 checker",
)
report(
    CHECKERS["collide_md5_48"].DIGEST_BYTES == 6
    and CHECKERS["collide_md5"].DIGEST_BYTES == 16,
    "the truncated instance compares 6 bytes and the full one 16",
)
report(
    CHECKERS["collide_sha1_64"].STEPS == 64 and CHECKERS["collide_sha1"].STEPS == 80,
    "the reduced SHA-1 instance runs 64 steps and the full one 80",
)
report(
    len({c.PREFIX for c in CHECKERS.values()}) == len(CHECKERS),
    "all six prefixes are distinct",
)
report(
    all(len(c.PREFIX) == 64 for c in CHECKERS.values()),
    "every prefix is exactly one 64-byte message block",
)
for name, checker in CHECKERS.items():
    seed = checker.PREFIX_SEED
    report(
        hashlib.sha512(seed.encode()).digest() == checker.PREFIX,
        "%s: PREFIX re-derives from its published seed" % name,
    )


# -- 4. the functions are the published ones --------------------------------
print("\nreference agreement -- these are the real hash functions")
MESSAGES = [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"a" * 119, bytes(range(256))]


def digest(checker, message):
    return checker._digest(checker._trace(message))


for name, reference in (("collide_md5", hashlib.md5), ("collide_sha1", hashlib.sha1)):
    checker = CHECKERS[name]
    same = all(digest(checker, m) == reference(m).digest() for m in MESSAGES)
    report(same, "%s agrees with hashlib on %d messages" % (name, len(MESSAGES)))

# MD4 and SHA-0 are in no modern OpenSSL, so they are pinned against the
# published vectors instead -- RFC 1320 appendix A, and FIPS 180 (1993).
for name, message, expected in (
    ("collide_md4", b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    ("collide_md4", b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    ("collide_md4", b"message digest", "d9130a8164549fe818874806e1c7014b"),
    ("collide_md4", b"abcdefghijklmnopqrstuvwxyz",
     "d79e1c308aa5bbcdeea8ed63df412da9"),
    ("collide_sha0", b"abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
    ("collide_sha0", b"", "f96cea198ad1dd5617ac084a3d92c6107708c0ef"),
):
    got = digest(CHECKERS[name], message).hex()
    report(got == expected, "%s(%r) is the published vector" % (name, message[:20]),
           "got %s" % got)

# SHA-0 and SHA-1 differ in exactly one place, and it had better be that place.
report(
    digest(CHECKERS["collide_sha0"], b"abc") != digest(CHECKERS["collide_sha1"], b"abc")
    and CHECKERS["collide_sha0"].ROTATE_EXPANSION is False
    and CHECKERS["collide_sha1"].ROTATE_EXPANSION is True,
    "SHA-0 is SHA-1 with the expansion rotation removed, and only that",
)


# -- 5. malformed artifacts score rather than raise -------------------------
print("\nmalformed artifacts -- rule 3: an exception is a broken verifier")
good = pair["m"]
for description, art in (
    ("not an object", ["m", "m_prime"]),
    ("no keys at all", {}),
    ("m missing", {"m_prime": good}),
    ("m_prime missing", {"m": good}),
    ("m is not a string", {"m": 12345, "m_prime": good}),
    ("m is null", {"m": None, "m_prime": good}),
    ("m is empty", {"m": "", "m_prime": good}),
    ("odd hex length", {"m": good + "a", "m_prime": good}),
    ("uppercase hex", {"m": good.upper(), "m_prime": good}),
    ("non-hex characters", {"m": "zz" + good[2:], "m_prime": good}),
    ("hex far beyond the cap", {"m": "ab" * 100000, "m_prime": good}),
    ("identical messages", {"m": good, "m_prime": good}),
    ("different lengths", {"m": good, "m_prime": good + "00"}),
    ("a message shorter than the prefix", {"m": "00ff", "m_prime": "00fe"}),
    ("nested object where a string belongs", {"m": {"hex": good}, "m_prime": good}),
):
    refuses(CHECKERS["collide_md5_48"], art, "refused: %s" % description)

print("\nmalformed vectors -- and none of them may score better than an honest one")
zero_window = ["00000000"] * 16
for which, evaluator in EVALUATORS.items():
    worst = 32 * (80 - 20)
    report(evaluator.INVALID > worst,
           "%s: INVALID (%d) is worse than the heaviest vector (%d)"
           % (which, evaluator.INVALID, worst))
    for description, art in (
        ("the all-zero vector", {"offset": 0, "window": zero_window}),
        ("a disturbance at step 79", {"offset": 64, "window": zero_window[:15] + ["00000001"]}),
        ("a disturbance at step 75", {"offset": 64, "window":
                                      zero_window[:11] + ["00000001"] + zero_window[12:]}),
        ("not an object", [0, 1]),
        ("no keys", {}),
        ("offset missing", {"window": zero_window}),
        ("window missing", {"offset": 0}),
        ("offset negative", {"offset": -1, "window": zero_window}),
        ("offset past the last window", {"offset": 65, "window": zero_window}),
        ("offset is a bool", {"offset": True, "window": zero_window}),
        ("offset is a string", {"offset": "0", "window": zero_window}),
        ("fifteen words", {"offset": 0, "window": zero_window[:15]}),
        ("seventeen words", {"offset": 0, "window": zero_window + ["00000000"]}),
        ("window is not a list", {"offset": 0, "window": "0" * 128}),
        ("a word given as an int", {"offset": 0, "window": [0] * 16}),
        ("a word in uppercase", {"offset": 0, "window": ["0000000A"] + zero_window[1:]}),
        ("a word with an 0x prefix", {"offset": 0, "window": ["0x00001"] + zero_window[1:]}),
        ("a short word", {"offset": 0, "window": ["1"] + zero_window[1:]}),
        ("a long word", {"offset": 0, "window": ["000000001"] + zero_window[1:]}),
    ):
        try:
            got = evaluator.score(art)
        except Exception as error:                  # noqa: BLE001 - that is the test
            report(False, "%s: %s" % (which, description), "raised %r" % error)
            continue
        report(got == evaluator.INVALID, "%s: %s scores INVALID" % (which, description),
               "scored %d" % got)


# -- 6/7. the evaluator's own algebra ---------------------------------------
print("\nsymmetries of the code -- the same vector must score the same way")
for which, evaluator in EVALUATORS.items():
    base = artifact("dv-sha1-baseline.json" if which == "dv_sha1" else "dv-sha0-optimal.json")
    expanded = evaluator._expand([int(w, 16) for w in base["window"]], base["offset"])
    reference = evaluator.score(base)
    same = all(
        evaluator.score({
            "offset": offset,
            "window": ["%08x" % w for w in expanded[offset:offset + 16]],
        }) == reference
        for offset in range(0, evaluator.MAX_OFFSET + 1)
    )
    report(same, "%s: re-anchoring at all 65 offsets scores the same" % which)

# Rotating every word is a symmetry of both expansions: ROTL commutes with XOR,
# and with the ROTL1 that SHA-1 adds. A submitter who writes a vector down in a
# different bit position must not be scored differently.
for which, evaluator in EVALUATORS.items():
    base = artifact("dv-sha1-baseline.json" if which == "dv_sha1" else "dv-sha0-optimal.json")
    reference = evaluator.score(base)
    words = [int(w, 16) for w in base["window"]]
    same = all(
        evaluator.score({
            "offset": base["offset"],
            "window": ["%08x" % evaluator._rotl(w, r) for w in words],
        }) == reference
        for r in range(1, 32)
    )
    report(same, "%s: rotating every word by 1..31 scores the same" % which)

# And the expansion really is invertible: an expanded vector re-expanded from
# any window of itself must come back identical. This is what makes accepting a
# window at an arbitrary offset sound rather than merely convenient.
for which, evaluator in EVALUATORS.items():
    base = artifact("dv-sha1-baseline.json" if which == "dv_sha1" else "dv-sha0-optimal.json")
    full = evaluator._expand([int(w, 16) for w in base["window"]], base["offset"])
    same = all(
        evaluator._expand(full[offset:offset + 16], offset) == full
        for offset in range(0, evaluator.MAX_OFFSET + 1)
    )
    report(same, "%s: the expansion round-trips from every window" % which)


print()
if FAILURES:
    print("\033[31m%d FAILURES\033[0m" % len(FAILURES), file=sys.stderr)
    for line in FAILURES:
        print("  %s" % line, file=sys.stderr)
    sys.exit(1)
print("\033[32mhash-differential selftest OK\033[0m")
