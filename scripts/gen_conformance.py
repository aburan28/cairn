"""Generate cross-implementation conformance vectors from the Python reference.

The whole project rests on independent parties re-deriving the same answers. Two
implementations that hash the same object differently would break that silently,
so every implementation must agree on canonical bytes down to the byte. These
vectors are the executable contract.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reference", "python"
))

from proofwork.attribution import FlowParams, flow  # noqa: E402
from proofwork.canonical import canonical_bytes, digest, merkle_root  # noqa: E402
from proofwork.frontier import Ratchet  # noqa: E402
from proofwork.gossip import Candidate  # noqa: E402
from proofwork.partition import assign, beacon  # noqa: E402
from proofwork.records import Claim, Commitment, Objective, commitment_hash  # noqa: E402

TS = "2026-07-28T00:00:00+00:00"

# Strings chosen to pin every escaping decision an implementation could get
# wrong: quotes, backslashes, the five short-form control escapes, a generic
# control char, DEL (must NOT be escaped), non-ASCII (must stay raw UTF-8),
# and astral-plane characters (surrogate pairs in UTF-16 languages).
NASTY = {
    "quote": 'a"b',
    "backslash": "a\\b",
    "shorts": "\b\t\n\f\r",
    "control": "\x00\x01\x1f",
    "del": "\x7f",
    "latin": "café",
    "cjk": "日本語",
    "astral": "😀𝔸",
    "empty": "",
    "solidus": "a/b",
}

CANONICAL_CASES = [
    {},
    {"a": 1, "b": 2},
    {"b": 2, "a": 1},
    {"nested": {"z": [1, {"b": 1, "a": 2}], "a": None}},
    {"bools": [True, False], "null": None},
    # Canonical integers are specified to fit in a signed 128-bit range. Python
    # has bignums and Rust does not; rather than pull in arbitrary precision for
    # a field no record needs, the *format* declares the bound and both
    # implementations enforce it. Boundaries are pinned here so neither drifts.
    {"i64max": 2**63 - 1, "i64min": -(2**63), "neg": -(2**70)},
    {"i128max": 2**127 - 1, "i128min": -(2**127)},
    {"zero": 0, "negzero": -0},
    {"empty_list": [], "empty_obj": {}},
    {"deep": [[[[[1]]]]]},
    NASTY,
    {"unicode_keys_sort": {"b": 1, "a": 2, "é": 3, "A": 4, "Z": 5}},
]


def canonical_vectors():
    out = []
    for case in CANONICAL_CASES:
        raw = canonical_bytes(case)
        out.append(
            {
                "value": case,
                "canonical_utf8": raw.decode("utf-8"),
                "canonical_hex": raw.hex(),
                "digest": digest(case),
            }
        )
    return out


def merkle_vectors():
    out = []
    for n in range(0, 9):
        leaves = [digest({"i": i}) for i in range(n)]
        out.append({"leaves": leaves, "root": merkle_root(leaves)})
    # the promotion-vs-duplication case: three leaves must not equal four
    three = [digest({"i": i}) for i in range(3)]
    out.append({"leaves": three + [three[-1]], "root": merkle_root(three + [three[-1]])})
    return out


def record_vectors():
    objective = Objective(
        goal="GOAL-x",
        statement="find it",
        verifier={"kind": "certificate", "checker": "c.py", "checker_sha256": "ab" * 32,
                  "entrypoint": "check"},
        reward=1000,
        funder="treasury",
        created_at=TS,
    )
    with_deadline = Objective(
        goal="GOAL-x", statement="find it", verifier=objective.verifier, reward=1000,
        funder="treasury", created_at=TS, deadline="2026-12-31T00:00:00+00:00",
    )
    with_ratchet = Objective(
        goal="GOAL-x", statement="climb", verifier={"kind": "evaluator", "threshold": 0},
        reward=1100, funder="treasury", created_at=TS,
        ratchet={"baseline": 9, "target": 20, "reward": 1100, "direction": "maximize",
                 "min_improvement": 1},
    )
    # An explicit "public" must produce byte-identical output to omitting the
    # field, or the default would fork every objective written before the field
    # existed. Same record as `objective`, so its id must match exactly.
    explicit_public = Objective(
        goal="GOAL-x", statement="find it", verifier=objective.verifier, reward=1000,
        funder="treasury", created_at=TS, confidentiality="public",
    )
    assert explicit_public.id == objective.id, "explicit public must not fork the id"
    with_embargo = Objective(
        goal="GOAL-x", statement="find it", verifier=objective.verifier, reward=1000,
        funder="treasury", created_at=TS, confidentiality="embargoed",
    )
    # A statistical objective pins the test statistic, the rejection threshold
    # AND the seed inside the verifier block, so all three are part of the
    # objective's id. That is the whole point of the kind: moving the threshold
    # after the fact would be re-grading settled work, and here it forks the
    # objective instead. Appended last so no pre-existing vector shifts.
    statistical = Objective(
        goal="GOAL-x", statement="beat the null", reward=500, funder="treasury",
        created_at=TS,
        verifier={"kind": "statistical",
                  "statistic": {"path": "s.py", "sha256": "cd" * 32},
                  "entrypoint": "statistic",
                  "threshold": 50_000, "direction": "minimize", "seed": 7},
    )
    claim = Claim(objective.id, "alice", {"n": 42}, "nonce-1", TS, ())
    cited = Claim(objective.id, "bob", {"n": 43}, "nonce-2", TS, (claim.id,))
    commitment = Commitment(objective.id, "alice", claim.commitment_hash(), TS)
    return {
        "objectives": [
            {"record": o.to_dict(), "id": o.id}
            for o in (objective, with_deadline, with_ratchet, explicit_public,
                      with_embargo, statistical)
        ],
        "claims": [
            {"record": c.to_dict(), "id": c.id, "artifact_id": c.artifact_id,
             "commitment_hash": c.commitment_hash()}
            for c in (claim, cited)
        ],
        "commitments": [{"record": commitment.to_dict(), "id": commitment.id}],
        "commitment_hash_cases": [
            {"objective_id": objective.id, "submitter": s, "artifact": a, "nonce": n,
             "hash": commitment_hash(objective.id, s, a, n)}
            for s, a, n in (
                ("alice", {"n": 42}, "n1"),
                ("bob", {"n": 42}, "n1"),
                ("alice", {"n": 43}, "n1"),
                ("alice", {"n": 42}, "n2"),
                ("", {}, ""),
            )
        ],
    }


def ratchet_vectors():
    out = []
    specs = [
        {"baseline": 0, "target": 100, "reward": 1_000_000, "direction": "maximize"},
        {"baseline": 9, "target": 20, "reward": 1_100_000, "direction": "maximize"},
        {"baseline": 100, "target": 0, "reward": 1000, "direction": "minimize"},
        {"baseline": 0, "target": 7, "reward": 10, "direction": "maximize"},
        {"baseline": 0, "target": 3, "reward": 10**18, "direction": "maximize"},
    ]
    for spec in specs:
        r = Ratchet.from_dict(spec)
        span = r.span
        scores = sorted({0, 1, span // 3, span // 2, span - 1, span, span + 5})
        points = []
        for s in scores:
            score = r.baseline + s if r.direction == "maximize" else r.baseline - s
            points.append({"score": score, "progress": r.progress(score),
                           "cumulative": r.cumulative(score)})
        out.append({"ratchet": spec, "points": points})
    return out


def attribution_vectors():
    def claim(who, cites=()):
        return Claim("obj", who, {"who": who}, "n", TS, tuple(cites))

    a, b = claim("alice"), claim("bob")
    c = claim("carol", [a.id, b.id])
    d = claim("dave", [c.id, a.id])
    claims = {x.id: x for x in (a, b, c, d)}
    out = []
    for amount in (1, 2, 3, 7, 999, 1000, 10**6, 10**9 + 7):
        for num, den in ((0, 1), (1, 3), (1, 4), (1, 2), (2, 3), (1, 1)):
            for depth in (0, 1, 2, 8):
                payouts = flow(d.id, amount, claims, FlowParams(num, den, depth))
                out.append({
                    "amount": amount, "delta_num": num, "delta_den": den,
                    "max_depth": depth, "payouts": payouts,
                })
    return {
        "claims": [x.to_dict() for x in (a, b, c, d)],
        "claim_ids": {x.submitter: x.id for x in (a, b, c, d)},
        "root": d.id,
        "cases": out,
    }


def partition_vectors():
    out = []
    for epoch in (0, 1, 42, 10**6):
        for anchor in ("anchor", "sha256:" + "ab" * 32):
            b = beacon(epoch, anchor)
            out.append({
                "epoch": epoch, "anchor": anchor, "beacon": b,
                "assignments": [
                    {"node_id": f"node-{i}", "objective_id": "obj",
                     "partitions": p, "partition": assign(f"node-{i}", "obj", b, p)}
                    for i in range(6) for p in (1, 4, 16, 1000)
                ],
            })
    return out


def gossip_vectors():
    out = []
    for score in (0, 1, 999, 10**12):
        for tag in ("a", "bb", "😀"):
            cand = Candidate("obj", {"tag": tag}, score, "n0")
            out.append({
                "candidate": cand.to_dict(),
                "id": cand.id,
                "artifact_id": cand.artifact_id,
                "islands": {str(n): cand.island(n) for n in (1, 2, 4, 8, 64)},
            })
    return out


def main() -> int:
    vectors = {
        "_comment": (
            "Cross-implementation conformance vectors generated from the Python "
            "reference implementation. Any implementation that disagrees with these "
            "bytes cannot interoperate: two parties would compute different ids for "
            "the same object and silently fail to agree on what was settled."
        ),
        "canonical": canonical_vectors(),
        "merkle": merkle_vectors(),
        "records": record_vectors(),
        "ratchet": ratchet_vectors(),
        "attribution": attribution_vectors(),
        "partition": partition_vectors(),
        "gossip": gossip_vectors(),
    }
    target = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "conformance",
        "vectors.json",
    )
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(vectors, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    counts = {k: len(v) for k, v in vectors.items() if isinstance(v, list)}
    print(f"wrote {target}")
    print(f"  {counts}")
    print(f"  attribution cases: {len(vectors['attribution']['cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
