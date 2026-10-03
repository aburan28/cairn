# Serving a log to strangers

Everything else in this repository assumes you already have the log. The CLI
opens a file, `cairn mcp` opens a file, and the p2p daemon reconciles with
peers who are already running nodes. None of that helps somebody who has only
heard the project exists — and *"anyone can independently re-derive every
settled result from the log alone"* is worth nothing to a person with no way to
obtain the log.

`cairn serve` is that way (once a separate `cairn-serve` binary; now a
subcommand of the one `cairn` binary).

```sh
cairn --log cairn.jsonl --root . serve --listen 0.0.0.0:8080
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
| `GET /frontier/{id}` | best score, who holds it, what to cite, pool remaining; on a piecework objective, the unit price, units paid and pool remaining instead |
| `GET /progress/{id}` | one objective's search as a dashboard reads it: `derived` (per-worker paid units, steps from the witness counters, hourly buckets, unit coverage -- all recomputed from the log) beside `reported` (worker heartbeats held in memory, unverified). See [Progress](#progress-what-a-search-looks-like-while-it-runs) |
| `GET /work_assignment?objective_id=&node_id=` | the MCP `work_assignment` tool over HTTP: this node's slice of the unit space for the epoch, `partitions` and `epoch` optional |
| `GET /chain` | the epoch chain: `links` and `head` are the chain's, `height` and `ledger_head` are the ledger's — the units a checkpoint signs, and not interchangeable with the first two |
| `GET /chain.html` | the same, as a page with no build step |
| `GET /health` | liveness, for whatever is watching the process |
| `GET /` (and `/index`) | what this node is and every route it answers, including the ones it has disabled |
| `GET /peers` | the `peer` records in this log — **known** peers, not open connections |
| `GET /ui/` | the embedded reader, when the binary was built with the `ui` feature |
| `POST /submit` | queue an objective, a commitment or a claim (only with `--queue`); `?kind=` names which, else the record's own `type` |
| `POST /objective/prepare` | canonicalize a draft objective and return the exact bytes its funder must sign — see below |
| `POST /progress` | a worker's heartbeat: kept in this node's memory for `GET /progress/{id}`, never written to the log, accepted on a read-only node too |
| `POST /deposit/grant` | issue a short-lived upload grant against a node-local deposit; response never includes cloud keys |
| `PUT /deposit/upload/{grant_id}` | proxy redemption of a grant (file backend, or curl-to-S3 fallback) |

Everything except `/log` is a convenience. `/log` is the product.

`GET /` is the one to hit first against an unfamiliar node: it names the version
and every route, and marks `POST /submit` and `GET /ui/` as disabled when this
node was started read-only or built without the reader — so a 404 or a refusal
is explained before you hit it.

`GET /peers` answers from the log, so a peer listed there may be long gone: the
log is append-only and nothing retracts a record. Live session state lives in the
p2p service, which serves no HTTP at all.

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

## Progress: what a search looks like while it runs

A piecework objective pays for a search that takes a fleet months, and the
log shows it an epoch late: a claim lands after the work, a settlement after
the claim, and a trail two hours into its walk has written nothing. The
reader at `/ui/task?id=…` is the dashboard for that, and `GET /progress/{id}`
is what it reads. The answer has two halves that are kept apart because they
are different kinds of fact:

- **`derived`** is recomputed from this node's log on every request and is
  what the search has actually been paid for. Settlements are joined to the
  claims they paid and to the elements those claims carry: per submitter,
  claims paid, units paid (`reward / unit_price`, capped by the batch size,
  since a duplicate in a batch earns nothing), the steps those units cost,
  first and last payment; the totals, the last hour and day, hourly buckets,
  rejected claims and commitments not yet revealed. The step count is **in
  the record**: an ECC2K-130 element's eight witness counters sum to its
  trail length, and a version 1 element carries `steps`. Nothing is
  estimated from a density. With the job's seed layout (`?trail_bits=`, or
  the latest heartbeat that declared it) the paid seeds are binned by unit
  into a `coverage` strip of `?bins=` cells; without it the strip is absent
  rather than guessed. Anyone with the log recomputes all of it.
- **`reported`** is what workers posted to `POST /progress`: who is live
  (a heartbeat within 180 s), stale (within 30 min) or gone, the unit range
  each took this epoch, the unit it is on, steps and trails this session,
  units found and not yet submitted, the rate it claims and the rate this
  node measured from its own counter and clock. Held in memory, forgotten
  after a day, bounded in how much the node will hold, and **never a
  record**: not appended, not gossiped, not verified, not evidence of work.
  Anyone can post one under any name. A page shows it as reported, and
  nothing downstream reads it for money. The liveness thresholds are the
  ECC2K-130 campaign control plane's, so a worker running both clients is
  judged the same way by both.

A heartbeat is a JSON object: `objective_id` and `worker` (the same string
the worker submits claims under, so the two halves land on one row) and
`steps` are required; `epoch`, `units: {first, end}`, `unit`, `trails`,
`capped`, `units_pending`, `units_submitted`, `steps_per_second`,
`trail_bits`, `device`, `lanes` and `client` are optional. Fields the node
does not know are ignored and named back in the `202` so a misspelling is
noticed by the client that made it. An objective this log does not hold is
refused with `404`, which is what stops a stranger filling the roster with
names against ids nobody is working.

`GET /work_assignment` is the MCP tool over HTTP so a worker with no MCP
client -- a shell loop on a GPU box, `examples/certicom-ecdlp/tools/orbit_worker.py`
-- can take its slice from the node it reports to. It is the same pure
function of the same public inputs, anchored at the log head as of the
epoch's start, so anyone can recompute any node's slice and the answer does
not move within an epoch.

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

## `POST /objective/prepare`: the bytes a funder signs

A funder authorizes an objective by signing `Objective::funding_signing_payload`
in its canonical encoding, and canonical encoding is consensus-critical: it
lives in `src/` and `reference/rust/`, which must agree, and nowhere else.
A browser wallet therefore never *builds* the payload. The reader at `/ui/submit`
posts the draft here, gets `payload_hex` back, and hands those bytes to the
wallet unread. Any Ed25519 wallet works — a Solana key *is* a cairn funder id —
and the signature it returns is checked by the same `verify_funding_signature`
that checks one from `cairn identity`.

The answer is a convenience and never a source of truth. Admission recomputes
the payload from the record it is given, so a server that returned the wrong
bytes yields a signature that fails at the door (`/submit` checks it eagerly)
rather than one that passes. The route reads no log and writes nothing; it is
a `POST` only because it has a body, which also means a browser preflights it
and, like `/submit`, it is reachable from the node's own origin alone.

## Why `POST /submit` queues instead of appending

A submission does not enter the log here. It lands in a spool directory, and
the operator's own node admits it — the daemon each round if it is running, or
the CLI if it is not:

```sh
cairn p2p … --queue ./queue          # drains every round, holding the lock it has
cairn drain --queue ./queue          # or --dry-run to look first
```

**Both, not either, and that took a while to be true.** A `Ledger` is
single-writer by enforcement, so `cairn drain` wants the write lock
`cairn p2p` holds: for as long as the daemon was the only thing that could
run alongside `cairn serve`, a node that was *online* could not accept a
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
