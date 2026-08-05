# Serving a log to strangers

Everything else in this repository assumes you already have the log. The CLI
opens a file, `proofwork-mcp` opens a file, and the p2p daemon reconciles with
peers who are already running nodes. None of that helps somebody who has only
heard the project exists — and *"anyone can independently re-derive every
settled result from the log alone"* is worth nothing to a person with no way to
obtain the log.

`proofwork-serve` is that way.

```sh
proofwork-serve --log proofwork.jsonl --root . --listen 0.0.0.0:8080
```

Read-only. Add `--queue ./queue` to accept submissions, and `--checkpoint
checkpoint.json` to publish what you signed.

## The endpoints

| endpoint | what it is |
|---|---|
| `GET /log` | the log, byte for byte as it is on disk |
| `GET /checkpoint` | the signed `(root, height, signature)`, if you publish one |
| `GET /objectives` | every objective, with its frontier |
| `GET /objective/{id}` | one full record, verifier spec included |
| `GET /frontier/{id}` | best score, who holds it, what to cite, pool remaining |
| `GET /health` | liveness, for whatever is watching the process |
| `POST /submit` | queue a commitment or a claim (only with `--queue`) |

Everything except `/log` is a convenience. `/log` is the product.

## What a contributor should actually do

Not trust this server. Fetch the log and check it:

```sh
curl -s http://the-operator:8080/log > proofwork.jsonl
curl -s http://the-operator:8080/checkpoint > checkpoint.json
proofwork verify --from checkpoint.json --root-key <the operator's key> --audit
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
the operator's own node admits it:

```sh
proofwork drain --queue ./queue          # or --dry-run to look first
```

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

A refused record is dropped from the queue with its reason printed, rather than
retried: nearly every refusal is permanent — a stale epoch, a citation that is
not an accepted claim — and a queue that retries a permanent failure never
empties.

## What this is not

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
