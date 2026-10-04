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
| `GET /verifiers` | what this node can verify right now: every kind, the toolchain behind it (`lean`, `python3`) with where each resolved on this process's `PATH` and its version, the jail mechanism and whether `CAIRN_REQUIRE_SANDBOX` is set, and the kinds split into `servable` and `unservable` with a reason for each of the latter. A report about the node, never about an artifact: an unservable kind still answers `unavailable`, not `reject`. Cairn.app's Settings reads it |
| `GET /` (and `/index`) | what this node is and every route it answers, including the ones it has disabled |
| `GET /peers` | the `peer` records in this log — **known** peers, not open connections |
| `GET /sessions` | the peer sessions this process has run, from its own memory: `reached` within two minutes, `recent` within thirty, `lost` after — see [Sessions](#sessions-whom-this-process-has-reached). `available: false` on a plain `cairn serve`, which reconciles with nobody |
| `GET /network` | one answer for the reader's Network page: this node's declared roles (`CAIRN_ROLES`) and hardware, the sessions summary, every worker heartbeating to it on any objective summed by device and class, the registered hosts under `compute.hosts`, and the roles the log evidences identities playing — see [Roles](#roles-what-a-node-says-it-is-for) |
| `GET /leases` | objectives with an advisory lease held in this node's memory |
| `GET /leases/{id}` | one objective's task leases: who holds each task, who contended for it, what was released and how — see [Leases](#leases-saying-what-you-are-about-to-work) |
| `GET /knowledge` | every claim's standing as this node derives it from the log -- accepted, corroborated, contested, superseded, withdrawn, refuted, unverified -- newest first and capped, with a tally by standing; `?policy=demanding` applies the stricter built-in confidence policy. See [Knowledge](#knowledge-what-is-believed-and-who-stood-behind-it) |
| `GET /knowledge/{claim_id}` | one claim: its standing and confidence under the named policy, every relation asserted about it and whether it was heard, and who stood behind its verdict under bond with each attestation's status and whether a docket caught it |
| `GET /hosts` | machines that registered with `cairn agent`: each host's CPUs, memory, GPUs and the sandboxes it can run jobs under, as it described itself, with the live ones summed — see [Hosts](#hosts-what-machines-are-on-the-network) |
| `GET /ui/` | the embedded reader, when the binary was built with the `ui` feature |
| `POST /submit` | queue an objective, a commitment or a claim (only with `--queue`); `?kind=` names which, else the record's own `type` |
| `POST /objective/prepare` | canonicalize a draft objective and return the exact bytes its funder must sign — see below |
| `POST /progress` | a worker's heartbeat: kept in this node's memory for `GET /progress/{id}`, never written to the log, accepted on a read-only node too |
| `POST /lease` | take or renew an advisory lease on a task of an objective this log holds: held in memory like a heartbeat, never written, never a lock |
| `POST /lease/release` | end a lease you hold, as `completed`, `failed` or `abandoned` |
| `POST /hosts` | a host agent's registration: its hardware and sandboxes, kept in this node's memory for `GET /hosts` and `GET /network`, never written to the log, accepted on a read-only node too |
| `POST /deposit/grant` | issue a short-lived upload grant against a node-local deposit; response never includes cloud keys |
| `PUT /deposit/upload/{grant_id}` | proxy redemption of a grant (file backend, or curl-to-S3 fallback) |

Everything except `/log` is a convenience. `/log` is the product.

`GET /` is the one to hit first against an unfamiliar node: it names the version
and every route, and marks `POST /submit` and `GET /ui/` as disabled when this
node was started read-only or built without the reader — so a 404 or a refusal
is explained before you hit it.

`GET /peers` answers from the log, so a peer listed there may be long gone: the
log is append-only and nothing retracts a record. Whom this process has actually
reached is `GET /sessions`, from the daemon's own memory, and the two are
different facts: an announcement is an address somebody vouched for, a session
is a handshake that completed.

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

## Sessions: whom this process has reached

For as long as this server has existed the sentence above about `/peers` ended
*"live session state lives in the p2p service, which serves no HTTP"*, and
every reader rendered the address book under a disclaimer. The daemon now
hands its HTTP half a roster (`src/p2p/sessions.rs`) and `GET /sessions`
answers from it.

A cairn session is one exchange -- dial or accept, handshake, reconcile,
close -- not a held connection, so "connected" is a window: a peer is
`reached` when a session with it succeeded within two minutes, `recent`
within thirty, `lost` after that, and `unreached` if this node has only ever
failed to dial it. Each row carries the address of the last session, which
way it ran, how many sessions succeeded in each direction, the last error,
and this node's ledger length afterwards. Beside the rows: `address_book`
(endpoints this node could dial now, and signed hints it has learned),
`this_node` (its transport id, listen address and uptime, with `external` —
what its router said about forwarding the p2p port, a claim — and
`inbound_from_public_at`, the evidence: see [two-nodes.md](two-nodes.md)), and
`anonymous_inbound_failures` -- handshakes that failed before authenticating
anyone, counted and never attributed, because attributing them would let a
stranger write any id onto this roster with one garbage frame.

Like a heartbeat it is memory, not a record: forgotten on restart, never
gossiped, read by nothing that pays. A reached peer proved it holds the key
its id names and nothing else. A plain `cairn serve` runs no p2p service and
answers `available: false` rather than publishing an empty mesh.

## Leases: saying what you are about to work

`work_assignment` divides a search with no messages at all, and that stays
how work is assigned. What it cannot say is what is happening *now*: a slice
assigned to a worker that went home is a hole nobody sees until the epoch
turns, a straggler cannot tell which unworked unit is safe to pick up, and
two workers that chose the same unit find out when the second artifact
verifies fine and mints nothing. A lease lets a worker announce a task
before starting it and read back whether somebody else announced it first.

```sh
curl -s -H 'content-type: application/json' http://node:8080/lease -d '{
  "objective_id": "sha256:…", "task": "unit:4017", "holder": "gpu-7",
  "ttl_seconds": 600, "units": {"first": 4017, "end": 4018}, "epoch": 12}'
# -> 202 {"held": true, "held_by": "gpu-7", "expires_at": "…", "contended_with": []}
#    or   {"held": false, "held_by": "gpu-3", …}: somebody is on it; work something else
curl -s -H 'content-type: application/json' http://node:8080/lease/release -d '{
  "objective_id": "sha256:…", "task": "unit:4017", "holder": "gpu-7", "outcome": "completed"}'
```

The earliest live claim on a task holds it, by arrival at this node. Posting
again before `expires_at` renews; a holder that lapses and comes back is
behind whoever claimed meanwhile. A release ends the lease once, by its own
holder only: `completed` closes the task on this roster (a later claim is
answered `409`), `failed` and `abandoned` leave it open. TTLs run from one
second to a day, default one epoch. The roster is capped per objective, per
task and overall and answers `429` past a cap rather than evicting; an
objective this log does not hold is refused with `404`; everything released
or expired is forgotten after a day. Fields the node does not know are named
back in `ignored`, as a heartbeat's are.

**A lease is not a lock, a record or evidence.** The rules engine never reads
the roster, a claim on a leased unit pays exactly as it would otherwise, and
`held: false` is advice. Anyone can lease anything under any name; the worst a
false lease does is send a worker who trusts the roster to a different unit,
on the node the liar posted to. The lab (`docs/lab.md`) has the same idea for
agents sharing a space, as signed CRDT ops that merge across machines; this is
the worker-facing version for a fleet reporting to one node, and it uses the
lab's words -- `task`, `holder`, `ttl`, `held`, `contended`, the three
outcomes -- so a reader who knows one knows the other.
`docs/design/network-coordination.md` has the design, and the reader's
`/ui/coordination?id=…` draws the roster over the epoch's work assignment.

## Knowledge: what is believed, and who stood behind it

`cairn knowledge` derives a claim's **standing** from the log -- the pinned
verdict first, then the relations that verified claims asserted about it,
collapsed to independent parties -- and a **confidence** under a policy the
reader chooses ([knowledge.md](knowledge.md)). Until now that was a CLI on a
local log. `GET /knowledge/{claim_id}` is the same derivation over HTTP, so
an agent asking "is this still believed?" gets the same answer as an
operator with the file:

```sh
curl -s http://node:8080/knowledge/sha256:…
# -> {"claim_id": …, "objective_id": …, "submitter": …,
#     "state": {"standing": "corroborated", "verdict": "accept", "reproducible": "yes",
#               "corroborations": 2, "refutations": 0, "disputes": 0,
#               "superseded_by": [], "retracted_by": null,
#               "assertions": [{"by": "sha256:…", "relation": "replicates", "grounded": true, "class": 0}, …],
#               "confidence_per_mille": 840},
#     "attestations": {"accept": 2, "reject": 0, "slashed": 0, "bond_each": 50000,
#                      "attestations": [{"attestation_id": …, "attestor": "<hex key>", "status": "accept", "created_at": …, "slashed": false}, …]},
#     "policy": {"name": "default", "parameters": {…}}, "as_of_epoch": 12345, "note": …}
curl -s 'http://node:8080/knowledge?policy=demanding'
# -> {"claims": [...], "total": 412, "shown": 256, "by_standing": {"accepted": 380, "refuted": 20, …}, …}
```

Two things are published side by side and never added. `state` is what
`src/knowledge.rs` computes: anyone with the log recomputes it, and the
confidence is labelled with the policy that produced it because there is no
network-agreed number and a route that handed one out would become the
thing the knowledge layer refuses to be. `attestations` is who stood behind
the verdict under bond (`docs/bonded-verification.md`) and how it went for
them. Standing does not know attestations exist, by design: a verdict is the
verifier's and a relation is a verified claim's, and a bonded opinion is a
third kind of fact a reader may weigh and the derivation does not. Nothing
on either route is written to the log and nothing moves money.

## Hosts: what machines are on the network

A worker heartbeat says what one process is doing on one objective. A host
registration says what a machine *is*. `cairn agent run` posts one to
`POST /hosts` every minute -- the machine's name and declared roles, its
CPUs, memory, NUMA layout and every GPU, which sandboxes it can run a job
under (`kata`, `runsc`, `bwrap`, each with how it is driven and whether an
engine will pass it a GPU), and how many jobs it is running against its
capacity. `GET /hosts` lists every host with its standing (`live` within
180 s, `stale` within 30 min, `gone` after, forgotten after a day) and sums
the live ones; `GET /network` carries the same table under `compute.hosts`,
beside the heartbeating workers and never added to them: a host is where
workers run, a worker is a process on one, and a box with eight GPUs and no
worker yet is capacity, not work.

```sh
curl -s -H 'content-type: application/json' http://node:8080/hosts -d '{
  "host": "gpu-box-1", "roles": ["executor"],
  "hardware": {"cpus": 128, "memory_mb": 515821, "gpus": [{"vendor": "nvidia", "model": "NVIDIA A100-SXM4-80GB", "memory_mb": 81920}]},
  "sandboxes": {"kata": {"usable": true, "via": ["docker:kata"], "gpu": true}},
  "jobs": {"running": 1, "capacity": 2}}'
# -> 202 {"recorded": true, "host": "gpu-box-1", "status": "live", "ignored": []}
curl -s http://node:8080/hosts
# -> {"hosts": [...], "live": 1, "cpus": 128, "memory_mb": 515821, "gpus": 1,
#     "jobs": {"running": 1, "capacity": 2}, "sandboxes": [{"sandbox": "kata", "hosts": 1}], ...}
```

The `hardware`, `sandboxes` and `jobs` blocks travel through **opaque**: the
node caps the encoded registration at 16 KiB, lifts out the few integers it
sums, and hands the rest back as posted, so the agent and the page agree on
the shape and the node in between is a bounded mailbox. Unlike a heartbeat a
registration names no objective -- a machine is on the network before anyone
has posted work for it -- so what bounds a stranger is the roster's cap (4096
hosts, `429` past it rather than eviction) and the size cap on each entry.
`host` must be printable and short; unknown top-level fields are named back
in `ignored`.

**A registration is not a record, not evidence, and not trusted**, for every
reason a heartbeat is not: never appended, never gossiped, never verified,
read by nothing that moves money. [agent.md](agent.md) is the agent's side:
the probe, the sandboxes, the jobs and the systemd unit.

## Roles: what a node says it is for

`CAIRN_ROLES=coordinator,verifier` declares what the operator intends a node
for -- `coordinator` (posts and funds objectives, accepts submissions, hands
out assignments, keeps the lease roster), `executor` (runs the workers that
report here), `verifier` (runs pinned verifiers and stands behind verdicts
under bond), `relay` (holds and serves the log, reconciles, nothing else).
An unknown name refuses to start. `GET /network` publishes the declaration
under `node.roles`, beside `node.warnings` where the configuration
contradicts it (a coordinator with no `--queue`, a verifier that can serve no
kind, a relay in a process with no p2p service), and beside `roles` --
recomputed from the log: who funded objectives, whose claims were accepted,
who attested and how often they were slashed.

A declared role is a hint about intent, exactly as a worker's capability
advertisement is (`src/compute.rs`). It is never a permission: the only
authority on this network is the pinned verifier's verdict, and a node that
says `coordinator` gets no say over what settles. What a declaration buys is
legibility -- a reader sees what a node is for and can check it against what
the node can do and what the log shows it doing.

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
