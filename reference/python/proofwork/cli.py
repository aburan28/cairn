"""Command line: post objectives, commit, reveal, audit, attribute.

    proofwork post      examples/cap_set/objective.json
    proofwork commit    <objective-id> --submitter alice --artifact a.json --nonce n1
    proofwork reveal    <objective-id> --submitter alice --artifact a.json --nonce n1
    proofwork settle
    proofwork audit
    proofwork attribute
    proofwork log
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from typing import Any

from .attribution import FlowParams, ledger_payouts
from .canonical import short
from .ledger import Ledger
from .node import Node, RuleViolation
from .records import Claim, Commitment, Objective, commitment_hash
from .schema import SchemaError, validate_claim, validate_objective

DEFAULT_LOG = os.environ.get("PROOFWORK_LOG", "proofwork.jsonl")


def _node(args: argparse.Namespace) -> Node:
    return Node(Ledger(args.log), root=args.root)


def _read_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def cmd_post(args: argparse.Namespace) -> int:
    node = _node(args)
    data = _read_json(args.objective)
    # The published schema runs *before* the constructor. ``from_dict`` is
    # permissive by necessity -- it has to read back records written by older
    # versions -- so it is the wrong place to enforce the contract third
    # parties implement against.
    try:
        validate_objective(data)
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    objective = Objective.from_dict(data)
    try:
        oid = node.post_objective(objective)
    except RuleViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"objective {oid}")
    print(f"  reward {objective.reward}  verifier {objective.verifier['kind']}")
    return 0


def cmd_commit(args: argparse.Namespace) -> int:
    node = _node(args)
    artifact = _read_json(args.artifact)
    nonce = args.nonce or secrets.token_hex(16)
    digest_ = commitment_hash(args.objective_id, args.submitter, artifact, nonce)
    try:
        node.commit(Commitment(args.objective_id, args.submitter, digest_, ts()))
    except RuleViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"committed {short(digest_)}")
    print(f"  nonce {nonce}   <- keep this; you need it to reveal")
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    node = _node(args)
    artifact = _read_json(args.artifact)
    claim = Claim(
        objective_id=args.objective_id,
        submitter=args.submitter,
        artifact=artifact,
        nonce=args.nonce,
        created_at=ts(),
        cites=tuple(args.cites or ()),
    )
    try:
        validate_claim(claim.to_dict())
    except SchemaError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    try:
        outcome = node.reveal(claim)
    except RuleViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    # The FULL claim id, not the display-shortened form: citing this claim is
    # the next thing anyone does with it, and a truncated id cannot be passed
    # to ``--cites``.
    print(f"claim {outcome.claim_id}")
    print(f"  verdict  {outcome.verdict.status.value}: {outcome.verdict.detail}")
    if outcome.is_pending:
        print(
            f"  pending  settles when epoch {outcome.pending_epoch} closes  "
            "(`proofwork settle`)"
        )
    else:
        print(f"  settled  {outcome.settled}  reward {outcome.reward}  ({outcome.note})")
    return 0 if outcome.verdict.status.settles else 3


def cmd_settle(args: argparse.Namespace) -> int:
    """Close every reveal epoch that is over and pay out its batch.

    Exists because settlement is deferred: a claim accepted in epoch N is paid
    when N closes, in beacon order rather than arrival order. Commit and reveal
    both drain due batches on the way in, so this is only needed when nothing
    else is happening -- a demo, a cron job, a quiet objective being wound down.
    """
    node = _node(args)
    try:
        settled = node.settle_at(ts())
    except RuleViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if not settled:
        print("no batch was due")
        return 0
    for outcome in settled:
        print(f"claim {outcome.claim_id}")
        print(f"  settled  {outcome.settled}  reward {outcome.reward}  ({outcome.note})")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    node = _node(args)
    problems = node.audit(rerun=not args.no_rerun)
    print(f"entries {len(node.ledger)}   head {short(node.ledger.head() or '-')}")
    print(f"merkle  {node.ledger.root() or '-'}")
    if problems:
        print(f"\n{len(problems)} problem(s):")
        for problem in problems:
            print(f"  ! {problem}")
        return 1
    print("\nlog verified: chain intact, every settled claim re-verified")
    return 0


def cmd_attribute(args: argparse.Namespace) -> int:
    node = _node(args)
    params = FlowParams(args.delta_num, args.delta_den, args.max_depth)
    payouts = ledger_payouts(node, params)
    if not payouts:
        print("no settlements yet")
        return 0
    total = sum(payouts.values())
    width = max(len(k) for k in payouts)
    print(f"delta {params.delta_num}/{params.delta_den}  max_depth {params.max_depth}\n")
    for who, units in sorted(payouts.items(), key=lambda kv: -kv[1]):
        print(f"  {who:<{width}}  {units:>10}  {100 * units / total:5.1f}%")
    print(f"  {'':<{width}}  {'-' * 10}")
    print(f"  {'total':<{width}}  {total:>10}")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    node = _node(args)
    for entry in node.ledger:
        summary = ""
        if entry.kind == "objective":
            summary = entry.payload["statement"][:60]
        elif entry.kind == "claim":
            summary = f"by {entry.payload['submitter']}"
        elif entry.kind == "verdict":
            summary = f"{entry.payload['verdict']['status']}: {entry.payload['verdict']['detail'][:40]}"
        elif entry.kind == "settlement":
            summary = f"{entry.payload['submitter']} <- {entry.payload['reward']}"
        elif entry.kind == "commitment":
            summary = f"by {entry.payload['submitter']}"
        elif entry.kind == "batch":
            summary = f"epoch {entry.payload['epoch']}: {len(entry.payload['claims'])} claim(s)"
        print(f"{entry.seq:>4}  {entry.kind:<11} {short(entry.hash)}  {summary}")
    return 0


def ts() -> str:
    from .node import now

    return now()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proofwork", description=__doc__)
    parser.add_argument("--log", default=DEFAULT_LOG, help="path to the JSONL log")
    parser.add_argument("--root", default=".", help="root for pinned verifier code")
    sub = parser.add_subparsers(dest="command", required=True)

    post = sub.add_parser("post", help="fund an objective")
    post.add_argument("objective", help="objective JSON file")
    post.set_defaults(func=cmd_post)

    commit = sub.add_parser("commit", help="commit to an artifact without revealing it")
    commit.add_argument("objective_id")
    commit.add_argument("--submitter", required=True)
    commit.add_argument("--artifact", required=True)
    commit.add_argument("--nonce")
    commit.set_defaults(func=cmd_commit)

    reveal = sub.add_parser("reveal", help="reveal a committed artifact and verify it")
    reveal.add_argument("objective_id")
    reveal.add_argument("--submitter", required=True)
    reveal.add_argument("--artifact", required=True)
    reveal.add_argument("--nonce", required=True)
    reveal.add_argument("--cites", nargs="*", default=[])
    reveal.set_defaults(func=cmd_reveal)

    settle = sub.add_parser("settle", help="pay out every reveal epoch that has closed")
    settle.set_defaults(func=cmd_settle)

    audit = sub.add_parser("audit", help="re-derive the entire log independently")
    audit.add_argument("--no-rerun", action="store_true", help="check hashes only")
    audit.set_defaults(func=cmd_audit)

    attribute = sub.add_parser("attribute", help="compute citation-flow payouts")
    attribute.add_argument("--delta-num", type=int, default=1)
    attribute.add_argument("--delta-den", type=int, default=4)
    attribute.add_argument("--max-depth", type=int, default=6)
    attribute.set_defaults(func=cmd_attribute)

    log = sub.add_parser("log", help="print the log")
    log.set_defaults(func=cmd_log)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
