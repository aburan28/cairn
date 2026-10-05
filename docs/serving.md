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
| `GET /goals` | the objectives grouped by the problem they attack and the angle taken on it, read off the `GOAL-<key>/<angle>` handle each carries; `?q=<words>` finds the goal a phrase names, in this log or in the catalog, so a new objective is posted as an angle on an existing goal rather than a second spelling of it — see [goals.md](goals.md) |
| `GET /goals/{key}` | one goal by key or alias, with every angle and objective under it; a catalog goal nobody funded answers with nothing funded rather than 404 |
| `GET /frontier/{id}` | best score, who holds it, what to cite, pool remaining; on a piecework objective, the unit price, units paid and pool remaining instead |
| `GET /progress/{id}` | one objective's search as a dashboard reads it: `derived` (per-worker paid units, steps from the witness counters, hourly buckets, unit coverage -- all recomputed from the log) beside `reported` (worker heartbeats held in memory, unverified). See [Progress](#progress-what-a-search-looks-like-while-it-runs) |
| `GET /work_assignment?objective_id=&node_id=` | the MCP `work_assignment` tool over HTTP: this node's slice of the unit space for the epoch, `partitions` and `epoch` optional |
| `GET /chain` | the epoch chain: `links` and `head` are the chain's, `height` and `ledger_head` are the ledger's — the units a checkpoint signs, and not interchangeable with the first two |
| `GET /chain.html` | the same, as a page with no build step |
| `GET /health` | liveness, for whatever is watching the process |
| `GET /verifiers` | what this node can verify right now: every kind, the toolchain behind it (`lean`, `python3`) with where each resolved on this process's `PATH`, its version, the root the operator granted its jail (`granted_root`), and for `python3` a `problem` when what was found cannot run in the jail (a version-manager shim), the jail mechanism and whether `CAIRN_REQUIRE_SANDBOX` is set, and the kinds split into `servable` and `unservable` with a reason for each of the latter. A report about the node, never about an artifact: an unservable kind still answers `unavailable`, not `reject`. Cairn.app's Settings reads it |
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
| `POST /submit` | queue an objective, a commitment or a claim (only with `--queue`); `?kind=` names which, else the record's own `type`. Every answer carries a `reason`, and a `202` a `wait` block — see [below](#why-a-submission-was-queued-or-refused-in-a-word) |
| `POST /objective/prepare` | canonicalize a draft objective and return the exact bytes its funder must sign — see below |
| `POST /progress` | a worker's heartbeat: kept in this node's memory for `GET /progress/{id}`, never written to the log, accepted on a read-only node too |
| `POST /lease` | take or renew an advisory lease on a task of an objective this log holds: held in memory like a heartbeat, never written, never a lock |
| `POST /lease/release` | end a lease you hold, as `completed`, `failed` or `abandoned` |
| `POST /hosts` | a host agent's registration: its hardware and sandboxes, kept in this node's memory for `GET /hosts` and `GET /network`, never written to the log, accepted on a read-only node too |
| `POST /fleet/join` | enroll a machine with an invite token, on a leader whose `CAIRN_FLEET` lists `enrolled`: signed by the invite key and by the new member key, answered with the member's name and expiry — see [Fleet](#fleet-signing-for-your-own-machines) |
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
this node's ledger length afterwards, and `about`: what the peer said it is
in the hello of that session -- its declared roles (`CAIRN_ROLES`), the
verifier kinds its machine can run, and its version. That is the peer's
word, with exactly the standing of this node's own `node.roles` on
`/network`: a hint about intent, never a permission and never checked. A
peer running a version older than the field is `null` there, not "no
roles", because it never said. The reader's Network page shows it in the
sessions table under *Says it is*. Beside the rows: `address_book`
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

## Why a submission was queued or refused, in a word

Every answer from `POST /submit` carries a `reason` beside its words, so a
client branches on a token and shows the sentence:
`{"error": "…", "reason": "queue_full"}`.

| reason | status | what it means | what to do |
|---|---|---|---|
| `queued` | 202 | in the spool, not yet admitted; see `wait` below | watch `GET /log` |
| `bad_body` | 400, 415 | not JSON, not UTF-8, empty, or not `application/json` | fix the request |
| `unknown_kind` | 400 | `?kind=` (or the record's `type`) is none of objective, commitment, claim | fix the request |
| `malformed` | 400 | the record does not decode as its kind | fix the record |
| `bad_funding_signature` | 400 | an objective's funding authorization does not verify | sign the bytes `POST /objective/prepare` returns |
| `schema` | 400 | a claim fails `spec/claim.schema.json` | fix the record |
| `not_a_member` | 403 | it names this node's identity, unsigned, and this node does not sign for the sender ([fleet.md](fleet.md)) | submit under your own name, or join the fleet |
| `relations_not_signed` | 403 | a fleet would sign a claim carrying `relations`; it never does | the leader signs those itself |
| `read_only` | 405 | this node queues nothing | submit to a node started with `--queue` |
| `host_not_allowed` | 421 | the write was addressed to a public DNS name this node does not list | address it by IP or LAN name, or list it in `CAIRN_HTTP_HOSTS` |
| `queue_full` | 429 | the operator has not drained lately | retry later; nothing was lost |
| `internal` | 500 | the spool could not be written | tell the operator |

A fleet member's signed request can also be refused before it reaches the
record, with the reasons in [Fleet](#fleet-signing-for-your-own-machines):
`malformed_authorization`, `member_unknown`, `member_revoked`,
`member_expired`, `clock_skew`, `bad_signature`, `enrollment_off`,
`not_a_member_route`. The heartbeat, lease and host routes refuse a reserved
name with `name_reserved` or `name_not_yours`.

**`wait`, on a `202`**, says what the record waits for, in fields:

```json
"wait": {"for": "admission", "drained_by": "this node", "drain_every_seconds": 5,
         "epoch": 2985, "epoch_seconds": 600, "epoch_ends_in_seconds": 312,
         "record_epoch": 2985, "at_risk": false,
         "reveal_from_epoch": 2986, "reveal_in_seconds": 312}
```

`drain_every_seconds` is null on a plain publisher, whose queue the operator
drains on no schedule this process knows. `record_epoch` and `at_risk` are on
commitments and claims. Admission checks the epoch a record claims against the
epoch it is drained in, so `at_risk` is true when the two differ, or when this
epoch ends before the next drain: the record will likely be refused for its
epoch, and the client should make a fresh one in the next. The `reveal_*`
fields are on commitments: the claim that opens one is admissible from the
next epoch on. `cairn work` reads all of this. It stops on a refusal no retry
can fix (`not_a_member`, `member_revoked`, `clock_skew`, …), keeps going past
one that a later round can (`malformed`, `queue_full`), and warns when a
record is at risk.

What the rules decide at drain time -- a stale epoch, an unaccepted citation --
is in the log's admission, not in this answer. MCP's `submit_claim` admits
directly and names those too, by rule ([agents.md](agents.md)).

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

## Fleet: signing for your own machines

A record is paid to the `submitter` it names, and a key-shaped submitter must
be signed by that key. A machine working for an operator should not hold the
operator's key. So a node started with `CAIRN_FLEET` and an identity
(`--mcp-identity FILE`, or `CAIRN_FLEET_IDENTITY=FILE`) **signs** every
unsigned commitment and claim that names its identity, before queuing it, for
the requests `CAIRN_FLEET` admits, and the `202` says so: `"signed_as": "<the
id>"`, and `"member": "<name>"` for an enrolled member.

- **`enrolled`**: a request signed by a member of the leader's registry
  (`<log dir>/fleet/`, kept by `cairn fleet`), from any address. The request
  carries `Authorization: CairnMember <member key> <time> <signature>`, the
  signature covering the method, the request-target exactly as sent, the
  SHA-256 of the body and the leader's own key, under the domain line
  `cairn-fleet-request/1`; the time must be within two minutes of the node's.
  A header that is present and fails is a `401` with its reason
  (`malformed_authorization`, `member_unknown`, `member_revoked`,
  `member_expired`, `clock_skew`, `bad_signature`), never an anonymous request.
  The header is read on `POST /submit`, `/progress`, `/hosts`, `/lease` and
  `/lease/release`; anywhere else it is refused with `400 not_a_member_route`.
  A verified member also passes the Host rule above, which stops web pages
  and not machines holding a key.
- **Networks** (`private`, `loopback`, CIDRs): any request from inside them,
  with no header. Kept for compatibility; the node says at start that it is
  trusting a network.

Anyone else gets `403` with `"reason": "not_a_member"`, rather than a record
queued to fail at drain time where the sender would never hear why. A
worker's own nickname, a worker's own key, anybody's already-signed record:
untouched. A member's name, and every `name/…` under it, is reserved on the
heartbeat, lease and host rosters: unsigned, it is refused with `403
name_reserved`; signed by another member, `403 name_not_yours`.

`POST /fleet/join` is how a machine becomes a member: a body signed twice,
by the invite key from the token and by the new member key, over the string
`cairn-fleet-join/1` builds (design §5). It answers `201` with the member's
name and expiry, the same membership again for a replay, and otherwise a
refusal with its reason (`invite_unknown`, `invite_expired`, `invite_spent`,
`name_taken`, `member_revoked`, …). It is the one route that changes
membership; nothing over the network can invite, admit or revoke.

`GET /network` publishes the arrangement under `node.fleet` (`sources`, with
`enrolled` first when it is on; `signs_as`, the id records name; `members`,
counts only) and the daemon's peer policy under `node.peers_policy` (`open`,
or an `allowlist` with how many it names, from `CAIRN_PEERS`). Both are
declarations about this process, like roles: nothing a reader can check
against the log. The whole arrangement -- inviting, joining, rented GPUs,
revocation, and what none of it does with money -- is [fleet.md](fleet.md),
and the design with its threat analysis is
[design/fleet-enrollment.md](design/fleet-enrollment.md).

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

**Not rate-limited** beyond these bounds: 64 connections at once, 16 of them
from any one non-loopback address; a request line or header of at most 8 KiB
and at most 100 headers; a 1 MiB body (64 MiB for a deposit upload, and only
once its grant has been checked); and 120 seconds for any connection,
request and response together, after which it is shut down whatever it is
doing. After answering, the server shuts its side and reads and drops what the
client is still sending, for at most 2 seconds and 1 MiB, before closing: a
refused request's unread bytes would otherwise make the close a reset, and a
reset can destroy the answer before the client reads it. An operator exposing this to the open internet should still put it
behind something that does rate limiting, the same as any other small
service.

**Writes are refused when addressed to a public DNS name.** A `POST` or `PUT`
whose `Host` is a name with a dot in it answers `421`, unless the name ends in
`.local`, `.lan`, `.internal`, `.localhost` or `.home.arpa` or is listed in
`CAIRN_HTTP_HOSTS` (comma-separated). IP literals, `localhost` and
single-label names always pass, and reads are never checked. This is the
DNS-rebinding defence: a page whose own name starts resolving to `127.0.0.1`
reaches a local node as a same-origin client, and its name is what it sends as
`Host`. A node behind a TLS proxy at `node.example.org` lists that name; a
`cairn work` worker that addresses its node by IP or LAN name needs nothing.

**Not a way to avoid running a node.** It publishes one node's view. Two
operators serving two logs are two sources, and nothing here makes them agree —
that is what `p2p` and, eventually, settlement consensus are for.
