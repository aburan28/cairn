# Seeing the network: sessions, compute, leases and roles

**Status: built**, in the node and in the reader, with nothing in consensus
by design. `src/p2p/sessions.rs` (the session roster, `GET /sessions`),
`src/lease.rs` (advisory task leases, `POST /lease`, `POST /lease/release`,
`GET /leases[/{id}]`), `src/network.rs` and `serve::network` (declared roles,
the hardware probe, the fleet summed by device and class, the roles the log
evidences: `GET /network`), the `fleet` view over the heartbeat roster in
`src/progress.rs`, and two pages in `ui/` -- `/network` and
`/coordination?id=…`. What is **not** built is listed at the end rather than
implied, and the one thing this note argues should *never* be built is in
§6.

Written against [coordination.md](../coordination.md), which this does not
revise -- every mechanism below is downstream of the position that document
takes, that coordination is a payment-structure problem and a dispatcher is a
self-inflicted wound -- and against [lab.md](../lab.md), whose `claim` and
`release` ops are the lease for agents, which this borrows the vocabulary of
for workers. Prompted by a review of the four readers
([review/gui-assessment.md](../review/gui-assessment.md)), which found that
every one of them rendered the same disclaimer in place of the same four
facts.

## 1. The gap

A node knew four things that no reader could see.

**Whom it had reached.** `docs/serving.md` said, from the day the HTTP half
existed: *live session state lives in the p2p service, which serves no HTTP*.
So `GET /peers` published the log's `peer` records -- announcements, append-only,
never retracted -- and the web page, both Mac apps and the phone each rendered
that list under a sentence explaining that it was not a list of connections.
Four readers, one disclaimer, and the operator who wanted to know whether their
node was talking to anyone read `node.log` in a terminal.

**What hardware was working for it.** Every heartbeat to `POST /progress`
carried `device`, `lanes`, `client` and a rate, and the task dashboard showed
them -- per objective. Nothing summed the fleet. "How much compute is on this
network right now, and what kind" had no answer shorter than opening every
task page and adding.

**Who was about to work what.** `work_assignment` divides a search with no
messages at all, and that is right ([§3](#3-leases-the-primitive-and-why-it-is-not-a-lock)
says why it stays that way). What it cannot say is what is happening *now*: a
slice assigned to a worker that went home is a hole nobody sees until the
epoch turns; a straggler that finished early cannot tell which unworked unit
is safe to pick up; two workers that both chose unit 4,017 find out when the
second artifact verifies fine and mints nothing. The lab had solved exactly
this for agents (`lab/state.rs`: `claim`, `release`, `held`, `contended`) and
a worker on a GPU box had no way to reach it.

**What it was for.** The research program this network grew out of runs on
three roles -- a coordinator that alone may change official state, executors
that alone run experiments, validators independent of both
(`orchestration/roles.yaml` in `crypto-autoresearcher`). A cairn node had no
way to say which of those its operator meant it to be, and a reader had no way
to tell a node that posts and funds objectives from one that only holds the
log, except by reading the log.

## 2. Three kinds of fact, three trust stories

The temptation is one route and one table. It would be wrong for the reason
[coordination.md](../coordination.md) gives for not pushing the population
through consensus: these are different kinds of fact with different costs of
being wrong, and a page that adds them produces a number nobody can check.

| fact | source | who can check it | cost of a lie |
|---|---|---|---|
| **declared** -- this node's roles, its own machine | `CAIRN_ROLES`, a probe at startup | nobody; the operator said so | a reader is misled about intent, and sees the contradiction when the node cannot do what it declares |
| **reported** -- sessions that completed, heartbeats and leases that arrived | the daemon's memory, workers' posts | nobody; held in one process, forgotten on restart | a reader is misled about *now*, on this node only, until the next honest post |
| **evidenced** -- who funded, whose claims were accepted, who attested | recomputed from the log on every request | anyone with the log | none: it is the log |

Every payload under `GET /network` keeps the three in separate fields
(`node`, `peers` + `compute`, `roles`) with a `note` saying which is which, and
the Network page colours them apart -- declared in blue, reported in amber,
evidenced in green -- the same convention the task dashboard already uses for
settled against reported. The rule the page follows is that **no number from
one kind is ever added to a number from another**: announcements in the log
and sessions in memory are two counts side by side, never a "peers" total.

### Sessions: a window, not a socket

A cairn session is one exchange -- dial or accept, handshake, reconcile
records (and the population when it is on), close. Nothing is held open. So
"connected" cannot mean a socket; it means *a session with this peer
succeeded recently*: `reached` within 120 s (two dozen ticks, about how often a
fanout-three random sample lands on each peer of a small mesh), `recent`
within 30 min, `lost` after, and `unreached` for a peer this node has only
ever failed to dial -- a different fact from a peer it has lost, and reported
as such.

One row per peer id, carrying the address of the last session (an inbound
peer's is its ephemeral source port and says nothing about where it listens;
the field is what was seen, not what to dial), which way the last session ran,
how many succeeded in each direction, the last error, and this node's ledger
length afterwards -- the one number a session changes that a reader can check
against `/chain`. Beside the rows: the address book's two sizes (endpoints
with a key this node could dial now; signed hints learned over the mesh),
this node's own transport id, listen address and uptime, and a count of
inbound handshakes that failed before authenticating anyone.

That last count is **never attributed**, and the reason is the only security
property the roster has. A peer appears on it after a handshake that
authenticated its McEliece key, so no stranger can put a name on another
node's roster by dialling with garbage. Attributing a failed inbound
handshake to the id it claimed would hand them exactly that.

The daemon writes the roster at the four places it already logged a session
(`daemon.rs`: inbound ok, inbound failed, outbound ok, outbound failed) and
notes the address book's sizes once a tick; the HTTP half holds an `Arc` to it
and reads. A plain `cairn serve` runs no p2p service and answers
`available: false` rather than publishing an empty mesh as if it were a lonely
one.

### Compute: the heartbeat roster read sideways

Nothing new is collected. `Board::fleet` reads the per-objective heartbeat
roster across objectives; `serve::network` sums it by device string, by device
class and by objective, over **live workers only** -- a stale worker's last
rate is a number about the past. `device_class` is a heuristic over the tokens
of whatever the worker called its hardware (`gpu`, `cpu`, `apple`, `fpga`,
`other`, `unreported`), computed once in the node so that every reader -- the
page, the phone, the Mac -- sums the same way rather than each inventing a
regex. A worker that calls its box `rig-3` is `other`, and that is the right
answer.

The node's own machine is probed once at startup (`available_parallelism`,
`/proc/meminfo` or `sysctl hw.memsize`, the `CAIRN_SANDBOX_*` caps the
operator set for verifiers) and reported under `node.hardware`, separately:
the node runs verifiers on it and nothing else, and macOS offers no way to cap
a GPU, so there is no GPU field. A worker's hardware is the worker's to
report.

## 3. Leases: the primitive, and why it is not a lock

A worker posts `{objective_id, task, holder, ttl_seconds, units?, epoch?,
note?}` to `POST /lease`. The node keeps it in memory, like a heartbeat, and
answers whether the worker **holds** the task -- the earliest live claim on a
task does, by arrival at this node -- or is **contended**, naming who holds it.
Posting again before expiry renews; a holder that lapses and comes back is
behind whoever claimed meanwhile. `POST /lease/release` ends a lease once, by
its own holder only, as `completed` (the task is done; a later claim is
answered `409`), `failed` or `abandoned` (somebody else may). `GET
/leases/{id}` is the whole roster for an objective, every lease with its
status, and `GET /leases` the objectives that have any.

The vocabulary is the lab's -- `task`, `holder`, `ttl`, `held`, `contended`,
the three outcomes -- so a reader who knows one knows the other. The semantics
are the lab's too, with one deliberate difference: the lab orders concurrent
claims by `(lamport, id)` because its replicas have no shared clock and every
replica must agree; this roster orders by arrival because it lives in one
process and says so. The two are for different fleets. The lab is for agents
sharing a space across machines, offline, with every conflict visible; this is
for a fleet of workers that already reports to one node and wants an answer in
one round trip with no identity to set up.

**It is not a lock, and nothing may make it one.** This is the load-bearing
sentence of the note. The rules engine does not read the roster.
`work_assignment` does not consult it. A claim on a unit somebody else leased
pays exactly as it would otherwise. `held: false` is advice to work something
else, not a refusal, and a worker that distrusts the roster ignores it at no
cost. The moment any of those changed -- a settlement that checked the lease,
an assignment that skipped a leased slice, a bond behind a lease -- this would
be the reservation system [coordination.md](../coordination.md) spends its
first page arguing against, with a lock table as a single point of censorship
and a free way for anyone to reserve a region they never intend to walk.

What the lease buys without that is exactly the three things in §1: a worker
that went home shows as a lease that expired with no release; a straggler
reads the roster and takes a task nobody holds; two workers on one unit learn
it from the second `202` rather than from the second settlement. The cost
falls where it should. A false lease -- anyone can post one, under any name,
for any task -- sends a worker who trusts the roster to a different unit, on
the node the liar posted to, for at most a day. The squatter gains nothing:
the partition function already handed that unit to somebody, and a squatted
unit is paid to whoever walks it. [threat-model.md](../threat-model.md) carries
the row.

The bounds are the heartbeat roster's: capped per objective, per task
(sixty-four names on one task is a flood or a very popular unit, and both are
visible at that size) and overall, refused with `429` past a cap rather than
evicting; an objective this log does not hold refused with `404`, so a
stranger cannot fill the roster against ids nobody is working; names printable
and short; a TTL from one second to a day, default one epoch; everything
released or expired forgotten after a day.

## 4. Roles: a hint, never a permission

`CAIRN_ROLES=coordinator,verifier` declares what an operator intends a node
for. Four names, each with a one-sentence duty and the place in the log a
reader would see it being played:

| role | duty | evidence in the log |
|---|---|---|
| `coordinator` | posts and funds objectives, divides them into piecework, accepts submissions, hands out assignments, keeps the lease roster workers coordinate through | objectives, under `funder` |
| `executor` | runs the workers that take assignments, heartbeat, lease tasks and submit claims here | claims accepted, under `submitter` |
| `verifier` | runs pinned verifiers and stands behind verdicts under bond, so a wrong verdict has somebody answerable | attestations, under `attestor` |
| `relay` | holds and serves the log, reconciles it with peers, nothing else | nothing; sessions on `GET /sessions` |

An unknown name refuses to start (`Serving::check_startup`), because a node
that quietly dropped `verifer` would look exactly like one never meant to
verify. The declaration is published under `node.roles`, beside
`node.warnings` where the configuration contradicts it -- a coordinator with
no `--queue` accepts no submissions; a verifier that can serve no kind on this
host; a relay in a process with no p2p service -- and beside `roles`,
recomputed from the log: every funder with how many objectives and how much it
funded, every submitter with accepted claims, every attestor with how many
attestations and how many were slashed.

The autoresearcher's roles are **authority boundaries**: a harness that
controls every tool call enforces that only the coordinator changes official
state. A network of strangers has no such harness, and the only authority on
it is the pinned verifier's verdict. So a role here must never become a second
one. A node declaring `coordinator` gets no say over what settles; a node
declaring `verifier` is believed exactly as far as the bond behind each
attestation (`docs/bonded-verification.md`); a node declaring `executor` is
believed as far as the claims the log accepted from the workers it runs. What
a declaration buys is **legibility**: a reader sees what the operator intends,
checks it against what the node can do, and checks that against what the log
shows. The three columns on the Network page are those three checks.

This is the same shape as `WorkerCapability` in `src/compute.rs` -- a worker
advertising what it can run, as a routing hint that is never evidence of work
-- applied to the node itself. Where the autoresearcher's role contract *does*
transfer is in the lab: a lab space's `admin` / `writer` / `reader` membership
is an authority boundary, enforced by signatures, and the role addresses its
messages go to (`coordinator`, `executor-1`) are what `CAIRN_LAB_ADDRESS`
names. A node's declared role and an agent's lab address are different
things, and nothing here conflates them.

## 5. What the reader shows

**`/network`.** Five tiles -- peers reached (with recent, lost and never
reached beside it), the address book (dialable now, hints, and the log's
announcements as a separate count), workers live, compute reported, lanes
reported -- then this node (declared roles with each one's warning on its own
row; machine; verifier caps; what it can verify and why not), what a role
means here, the session table, hardware by class with a share bar and by
device, the fleet with each worker's objective linked to its task dashboard,
and the three evidenced-role columns. Every reported figure is amber, every
evidenced one green, every declared one blue, and the provenance line says so.

**`/coordination?id=…`.** One divided search: the epoch (number, length,
time to the turn, anchor, the assignment formula), a strip of the unit space
in a reader-chosen number of partitions with each cell coloured by how many
live workers report a range overlapping it and ringed where a live lease
covers it, the lease table (held first, then contended, expired, released,
soonest expiry first), the workers reporting with their ranges, and the two
notes the node sends about what an assignment and a lease are. The partition
arithmetic is the node's exactly (`Assignment::share`, `Piecework::unit_range`),
in BigInt because a unit count of 2^48 times a bound of 2^32 does not fit a
double and a boundary off by one would draw a worker in its neighbour's slice.
Without `?id=` it lists the divided searches. Nothing on either page re-derives
a payment or an assignment; both read what the node answered.

## 6. What this deliberately does not build

**A lease that gossips.** Heartbeats are node-local and so are leases, which
makes both honest about what they are -- one process's memory of what it was
told -- and useless across nodes. Carrying leases as a p2p message family
(`pop.rs` is the shape) would let a fleet reporting to many nodes coordinate,
and the merge is an easy CRDT (union, with the arrival order replaced by the
lab's `(lamport, id)`). It is not built because the first fleet this is for
reports to one coordinator node, and because a gossiped lease is one step from
a *consulted* lease. If it is built, §3's sentence binds it too.

**A signed lease or heartbeat.** The same name-spoofing gap as heartbeats
(`threat-model.md`, *forged progress*): a lease under another worker's name is
indistinguishable from the real one. Signing with the submitter's key -- as
signed commitments already can be -- would close it. It is one record shape
away and it is not done.

**A lease the rules read.** Never. See §3. The arena (`docs/arena.md`) is the
place to show what it would cost if anyone is tempted: a scenario where an
attacker leases every slice and walks none should come back `INERT` today,
because nothing moves, and would come back `OPEN` the day a rule read the
roster.

**A GPU field on the node.** The node does not use one and macOS cannot cap
one. A worker's GPU is in its heartbeat, where it belongs.

**Roles with authority.** §4. The autoresearcher's coordinator may change
official state because a harness enforces it. Here, a pinned verifier's
verdict is the only thing that does, and that is the design.

**The native readers.** `GET /sessions` and `GET /network` are built for all
four readers and consumed by one. Cairn.app's Peers sheet, its status
popover's session count (parsed today from `node.log` lines), the
autoresearcher's Node pane and the iPhone's Peers screen each have a precise
change named in [review/gui-assessment.md](../review/gui-assessment.md); none
can be compiled or tested from the environment this note was written in, and
a Swift edit nobody ran is worse than a named one.

## 7. Checks

- `cargo test --lib -- sessions lease network progress::tests serve::tests`:
  the roster's reach windows, the bounded cap and the anonymous inbound count;
  the lease's hold/contend/renew/release/complete semantics and its caps; role
  parsing and the three contradiction warnings; the device classifier; and the
  four routes over HTTP, including that a lease flow leaves `/chain` untouched.
- `ui/lib/network.test.ts`, `ui/lib/leases.test.ts`: the fleet sums over a
  filtered subset, the partition arithmetic against the node's own fixture
  (four partitions of 4,096 abut at 1,024) and at 2^48 units, the overlap of
  reported ranges and leases onto partitions, the lease ordering.
- `scripts/node-smoke.sh`: every new route answers 200 from the one process
  holding the write lock, and both pages are served under their paths.
