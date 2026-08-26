# Serving a log to strangers

Everything else in this repository assumes you already have the log. The CLI
opens a file, `cairn-mcp` opens a file, and the p2p daemon reconciles with
peers who are already running nodes. None of that helps somebody who has only
heard the project exists — and *"anyone can independently re-derive every
settled result from the log alone"* is worth nothing to a person with no way to
obtain the log.

`cairn-serve` is that way.

```sh
cairn-serve --log cairn.jsonl --root . --listen 0.0.0.0:8080
```

Read-only. Add `--queue ./queue` to accept submissions, and `--checkpoint
checkpoint.json` to publish what you signed.

The log is appended without `fsync`: a power loss can lose the last records
written, which a peer still holds, and the next open reports a torn tail
rather than silently reading it. If yours is the one node contributors submit
to, so that a lost tail is a lost claim rather than a re-sync, set
`CAIRN_LEDGER_FSYNC=1` in the daemon's environment to pay one `fsync` per
record instead.

## The endpoints

| endpoint | what it is |
|---|---|
| `GET /log` | the log, byte for byte as it is on disk |
| `GET /checkpoint` | the signed `(root, height, signature)`, if you publish one |
| `GET /objectives` | every objective, with its frontier and whether it is still payable |
| `GET /objective/{id}` | one full record, verifier spec included |
| `GET /frontier/{id}` | best score, who holds it, what to cite, pool remaining |
| `GET /chain` | the epoch chain: `links` and `head` are the chain's, `height` and `ledger_head` are the ledger's — the units a checkpoint signs, and not interchangeable with the first two |
| `GET /chain.html` | the same, as a page with no build step |
| `GET /health` | liveness, for whatever is watching the process |
| `POST /submit` | queue a commitment or a claim (only with `--queue`) |

Everything except `/log` is a convenience. `/log` is the product.

Both objective views carry the same three lifecycle fields. `settled` means *no
longer payable* -- for a certificate, that a settlement exists; for a ratchet,
that the frontier is at the target or the span left under it is smaller than
`min_improvement`, so no claim can settle there again. It does **not** mean "a
settlement record exists": a ratchet writes one on every paying move, and by
that reading a progressive objective was settled from its first slice onward
with most of its pool untouched. `open` is its complement, published rather
than left for a reader to negate. `settlement` is `{claim_id, submitter,
reward}` for a settled certificate and `null` otherwise -- a ratchet's payouts
are many, and `frontier.paid_cumulative` carries them.

## What a contributor should actually do

Not trust this server. Fetch the log and check it:

```sh
curl -s http://the-operator:8080/log > cairn.jsonl
curl -s http://the-operator:8080/checkpoint > checkpoint.json
cairn verify --from checkpoint.json --root-key <the operator's key> --audit
```

That re-derives the chain, the Merkle root over the signed prefix, and every
settled result from the artifacts themselves. It is the same command the
operator runs, on the same bytes, and it does not care where the file came
from. A server that lied would fail it.

The one thing the transport *cannot* establish is that the root key is the
operator's. Get it from somewhere else — the project's repository, a signed
release, a person. A key served alongside the thing it authenticates
authenticates nothing.

## Why `POST /submit` queues instead of appending

A submission does not enter the log here. It lands in a spool directory, and
the operator's own node admits it — the daemon each round if it is running, or
the CLI if it is not:

```sh
cairn-p2p … --queue ./queue          # drains every round, holding the lock it has
cairn drain --queue ./queue          # or --dry-run to look first
```

**Both, not either, and that took a while to be true.** A `Ledger` is
single-writer by enforcement, so `cairn drain` wants the write lock
`cairn-p2p` holds: for as long as the daemon was the only thing that could
run alongside `cairn-serve`, a node that was *online* could not accept a
submission at all. For a network whose purpose is accepting submissions that is
not a small gap. The daemon is the operator's node and already holds the lock,
so it drains; the rules live in `serve::drain_into` and both callers use that
one copy, for the same reason given below about request handlers.

Two reasons, and the second is the load-bearing one.

**One writer.** A `Ledger` is single-writer by construction and, since the
lock landed, by enforcement. A server that appended would be a second writer
beside the operator's CLI and daemon, and two writers fork a hash-linked log.

**Admission is a rules question, not a transport question.** Whether a record
may enter the log is decided against the *whole log* — the epoch it was
committed in, whether its citations are accepted claims, whether its artifact
duplicates one already settled. Answering that inside a request handler would
put a second copy of the admission rules on the network boundary, which is the
worst possible place for two implementations to disagree.

So the queue holds *proposals*. `202 Accepted` means queued, not admitted, and
the response says so in those words. The record is checked exactly twice: once
for shape at the boundary (so a typo is reported immediately rather than after
a queue delay), and once for everything, by `node.rs`, at drain time.

The write boundary accepts only `Content-Type: application/json` (parameters
such as `charset=utf-8` are permitted). In particular it refuses browser-simple
`text/plain` POSTs. Combined with the absence of permissive CORS headers, that
prevents an unrelated web origin from queueing a record merely by causing a
visitor's browser to send a no-preflight request; deployments still enforce
their own origin policy at the TLS reverse proxy.

A refused record is dropped from the queue with its reason printed, rather than
retried: nearly every refusal is permanent — a stale epoch, a citation that is
not an accepted claim — and a queue that retries a permanent failure never
empties.

## What this is not

**Bounded.** The queue refuses submissions past `--max-queue` undrained
records (4096 by default) and answers 429. The spool de-duplicates by content
so a retry is free, but *distinct* records each cost a file, and unbounded that
fills the operator's disk -- which stops the node writing its own log. A cap
turns disk exhaustion into "come back later". It is not Sybil resistance and
cannot be: telling many honest submitters from one attacker needs an identity
that costs something, which is Stage 1's submission bonds.

**Partly authenticated.** A key-shaped `submitter` (64 lowercase hex) must
carry a valid ed25519 signature, so a submission under one cannot be forged.
A nickname submitter still cannot be authenticated at all; see the
identity gap in [launch-review.md](launch-review.md). Anyone can submit as
anyone, which matters because citation flow moves value. This is Stage 1 work
and it is not done.

**Not TLS.** Put a reverse proxy in front of it. The security argument here
does not rest on the transport: nothing served is secret, and nothing accepted
is trusted.

**Not rate-limited** beyond a concurrent-connection cap and a body-size cap.
An operator exposing this to the open internet should put it behind something
that does rate limiting, the same as any other small service.

**Not a way to avoid running a node.** It publishes one node's view. Two
operators serving two logs are two sources, and nothing here makes them agree —
that is what `p2p` and, eventually, settlement consensus are for.
