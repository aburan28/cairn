# Operating a node

`scripts/setup.sh` does the whole path below. Read this when something needs
doing by hand, or when a step misbehaves.

## Posting an objective

An objective is a funded question plus a verifier pinned by hash. The id **is**
the hash of the whole record, verifier included, so there is no operation that
changes the rules of a live bounty — editing a checker produces a *different*
objective and claims against the original stop resolving. Mid-bounty rule
changes are not guarded against; they are unrepresentable.

```sh
proofwork --log LOG --root . post examples/reversible-adder/objective.json
```

The pin must be the file's real SHA-256:

```sh
sha256sum examples/reversible-adder/evaluators/adder_cost.py
```

**A wrong pin does not fail.** Because the id covers the verifier, a mistyped
hash mints a different objective — one whose every claim returns `InvalidSpec`
forever and whose reward is stranded. `post` warns when a pin does not resolve
on this node, but it cannot refuse: posting an objective whose checker a peer
will serve is exactly how content-addressed distribution works. Only you can
tell "a peer will serve this" from "I mistyped it", so read that warning.

### Writing a verifier worth funding

The one rule: **the check is the payment condition.** A verifier that reads a
number the submitter chose is not a check, and an objective built on one pays
for typing rather than for work.

Compare `examples/ecdsa-fail/` (accepts declared `{qubits, toffoli}`, checks
only that the product is arithmetic — a demo) with
`examples/reversible-adder/` (accepts a gate list, simulates it on every
input, derives the score from the circuit — a bounty). Same shape, and only
one of them is safe to fund.

Practical requirements:

- **Pure and deterministic.** `audit` re-runs settled verifiers; one that
  consults the clock, the network, or unpinned state will fail its own log
  later.
- **Integers only.** Never return a float. Scores are `i64`.
- **Invalid input scores invalid; it does not raise.** A bad artifact is a
  rejection. An exception is a broken verifier, and those are different facts.
- **Bound the work.** Cap gate counts, sizes, iterations. The artifact is
  attacker-supplied and it is billing your CPU.
- **Declare `artifact_schema`.** It is documentation, not a rule — the
  verifier stays the only authority — but it gives agents a shape from a
  structured field instead of from untrusted prose.

## Serving to strangers

```sh
proofwork-serve --log LOG --root . --listen 127.0.0.1:8787 --queue ./queue
proofwork drain --queue ./queue --log LOG --root .   # admit what arrived
```

`GET` is read-only and safe to expose. `POST /submit` **queues**; nothing
enters the log until `drain` re-checks every rule against the whole log. That
split is deliberate — admission stays in the rules engine, and the log keeps
exactly one writer.

Run `drain` on a timer, or after a notification. Until it runs, submitters see
their work queued and unsettled.

## Epochs

Commit and reveal must land in different epochs. The length defaults to **600
seconds** and is set by `PROOFWORK_EPOCH_SECONDS`.

Export it in **every** shell that touches the log — the CLI, the MCP server,
the daemon. Epochs are derived from record timestamps and never stored, so a
log written at one length audits as thoroughly broken at another: anchors do
not match and every batch looks settled out of order. `audit` names this when
every batch faults at once, but it is easier to not do it.

Use `PROOFWORK_EPOCH_SECONDS=1` for demos. Use the default for anything whose
log you intend to publish.

## Settling and auditing

```sh
proofwork --log LOG --root . settle     # drain closed epochs
proofwork --log LOG --root . audit      # chain, batches, verdicts
proofwork --log LOG --root . attribute  # citation-flow payouts
```

`audit` re-derives every settled result from the artifacts. It is the thing
the whole design exists to make possible, so run it before publishing anything
and after importing from a peer.

## Publishing what you settled

```sh
proofwork --log LOG --root . checkpoint --root-key KEY --out checkpoint.json
```

A checkpoint is `(merkle_root, height, signature)`. A reader pins it and
detects a rewrite:

```sh
proofwork --log LOG --root . verify --from checkpoint.json --root-key PUBKEY --audit
```

Publish the public key **somewhere the reader already trusts**. A key served
from beside the thing it authenticates authenticates nothing.

`launch/` in this repository is a worked example: a settled log, its
checkpoint, and the key, with `scripts/make-launch-log.sh` showing how it was
built.

## One writer per log

The ledger takes an advisory lock. Two writers over one file would fork it —
each computing `prev` from its own view of the tail — so the second is refused
rather than allowed to corrupt it.

In practice: do not point two MCP servers at one log, and do not run the CLI
against a log a server currently holds. If you want several agents working at
once, give each its own log and reconcile with the p2p daemon; different model
families are real search diversity and the population model preserves it
deliberately.
