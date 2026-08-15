# Verification

A currency is exactly as sound as the cheapest check that mints it. This
document is the ladder of checks `cairn` supports, what each one actually
proves, and how to author a verifier that cannot be gamed.

## The ladder

| tier | claim shape | who can check, and how | implemented |
|---|---|---|---|
| **V0** | NP certificate: a witness, counterexample, construction, collision | anyone, in milliseconds, by recomputation | `certificate` |
| **V1** | machine-checked proof | anyone, seconds to minutes; the kernel is the arbiter | `lean` |
| **V2** | bounded re-execution at a pinned commit, seed, environment | anyone with the compute; deterministic *only on reproducible fields* | `replay` |
| **V3** | statistical validation against a pre-registered test statistic | anyone, by rerunning the pinned statistic at the pinned seed | `statistical` |
| **V4** | judgement: is this novel, is this promising, is this important | nobody, mechanically. ever | never |

The `evaluator` verifier sits alongside V0: a pinned deterministic fitness
function costs exactly one evaluation to re-check — the same evaluation the
network was going to run anyway — so verification is *free*, not merely cheap.
This is the FunSearch/AlphaEvolve shape and it is the best value-per-check in
the whole table.

The V3 row deliberately says *rerunning at the pinned seed* rather than
*resampling*. See [V3, and what pre-registration buys](#v3-and-what-pre-registration-buys):
Stage 0 admits only statistics whose randomness is driven by a seed the
objective pins, so two honest nodes get the same integer rather than two draws
that agree probabilistically. A test that genuinely needs independent resampling
by several parties needs a committee, and that is Stage 2.

V4 is where most of the intellectual value of research lives, and it is
permanently unmintable. Any design that forgets this produces a token backed by
vibes with a cryptographic veneer.

## The rule that matters most

> A verifier that cannot run returns `UNAVAILABLE`. Never `ACCEPT`, never `REJECT`.

An unavailable toolchain, a missing file, a crashed evaluator, or a timeout is
an infrastructure fact. It is not a fact about the artifact. Collapsing it into
`REJECT` turns "my Lean install is broken" into "your proof is wrong" — and on a
network with money attached it is an attack: take verifiers offline and every
honest submission fails.

Only `ACCEPT` and `REJECT` settle. `UNAVAILABLE` and `INVALID_SPEC` record what
happened, move nothing, and leave the objective open for a node that can
actually run the check. `Status.settles` is the single place this is decided.

The symmetric rule: **absence of a witness within budget is not a refutation.**
A certificate proves a positive result is real; a search that found nothing is
a scoped negative observation about the region searched, and it mints nothing at
V0–V2. Rewarding "I looked and found nothing" pays for not looking.

## Authoring a verifier

This is the scarce skill in the whole system. Turning "understand X" into a
runnable checker is the actual bottleneck — "cure Alzheimer's" has no verifier;
"find a molecule maximizing this docking score under these constraints" does.

Four rules, each learned from a way verifiers get gamed:

**1. The statement comes from the objective, never the submitter.** The `lean`
verifier concatenates the objective's pinned `statement` with the submitter's
`proof`. If the submitter supplied both, they would prove an easier theorem and
collect.

**2. Enumerate the escape hatches and screen them before the checker runs.**
For Lean that means `sorry` and `admit` (explicit holes that compile and prove
nothing), `axiom` (a new trusted assumption smuggled in beside the proof),
`@[implemented_by]`, and `native_decide` (discharges goals via compiled
evaluation, trusting the compiler rather than the kernel — allowed only if the
objective opts in). Every verifier needs its own version of this list, and
writing it *is* the work of authoring an objective.

**3. Score invalid input, don't crash on it.** The cap-set evaluator scores a
non-cap-set as zero rather than raising. An invalid submission is a bad
artifact; an exception is a broken verifier. Confusing the two decides whether
the objective can be attacked with garbage.

**4. Be pure.** Pinning source by hash is necessary and not sufficient. A
checker that reads an unpinned file passes today and fails tomorrow at the same
hash — `tests/test_node.py::test_audit_flags_a_settled_claim_that_now_fails_verification`
pins that hazard. Depend on the artifact and nothing else.

### Integers only

Evaluator scores and thresholds must be `int`. IEEE-754 arithmetic does not
reproduce bitwise across heterogeneous hardware, so a float score can compare
differently on two honest nodes and they will disagree about whether a threshold
was met. Scale your score and say so in the objective statement. The same rule
is enforced one level down in canonical serialization, so a float cannot enter a
record at all.

### Time is not a checkable field

`replay` refuses any `reproducible_fields` entry that looks machine-dependent —
wall-clock, elapsed, memory, RSS, FLOPs, throughput, timestamps. Those measure
the host, not the computation, and two honest nodes disagree about them by
construction. A cost claim denominated in seconds is a claim about somebody's
hardware and cannot be settled by re-execution. Declaring one is a malformed
objective (`INVALID_SPEC`), not a failed run.

## V3, and what pre-registration buys

```json
{
  "kind": "statistical",
  "statistic": { "path": "statistics/paired_permutation.py", "sha256": "…" },
  "entrypoint": "statistic",
  "threshold": 50,
  "direction": "minimize",
  "seed": 0
}
```

The pinned file exposes `statistic(artifact, seed) -> int`, and `direction` plus
`threshold` decide accept or reject exactly as `evaluator` does.

Every one of those fields is inside the objective, and the objective's id is the
digest of its contents. That is the entire mechanism: **choosing a success
criterion after seeing the data means posting a different objective, with a
different id, that funded nothing.** A statistical claim whose criterion is
chosen after the samples is unfalsifiable, and on an open market it is the
oldest fraud in empirical work. Pre-registration costs nothing to enforce here
because content addressing was already doing the work.

Two rules beyond the evaluator's:

**The seed is pinned, and it belongs to the objective.** Permutation tests,
bootstraps and resampling are the normal shape of a test statistic, and they are
all randomised. A statistic whose randomness the *submitter* chooses is one the
submitter grinds until it clears. A statistic whose randomness is unpinned makes
two honest nodes disagree, which is worse — it turns a verdict into a coin flip.
So the seed is a spec field, passed to the entrypoint as a second argument, and
never merged into the artifact where a submitter could reach it. It defaults to
`0`, and defaults are omitted from the canonical encoding, so a deterministic
statistic does not have to carry the field or pay for it in its id.

**Integers only**, for the same reason as the evaluator, and it bites harder
here: p-values are the natural output and they are floats. Scale them — parts
per million is the usual choice — and say so in the objective statement. A float
returned by the statistic is `INVALID_SPEC`, not a rejection: the objective is
broken, not the artifact.

`examples/permutation/` is a worked one — a paired permutation test whose
statistic is a scaled p-value, `minimize`, threshold 50.

The Stage 0 boundary: only statistics cheap enough for every node to re-run.
A resampling test large enough to need a committee is
[consensus.md](consensus.md#where-original-protocol-work-is-needed)'s problem,
and it is Stage 2.

## Verifiers not implemented here

Because they need infrastructure this stage deliberately does not have, and
because each buys a weaker guarantee than those above:

- **Contributed inference.** [TOPLOC](https://www.primeintellect.ai/blog/intellect-2)
  — locality-sensitive hashing over activations — detects tampering and
  precision changes across non-deterministic GPUs at roughly free versus
  re-running. The right primitive when you must pay for effort rather than
  output.
- **TEE attestation.** Real, roughly free, and a *trust assumption about a
  hardware vendor* rather than a proof. Record it as one.
- **zkML.** Cryptographic, and in 2026 running 30 seconds to several minutes per
  inference. Fine for high-stakes settlement, too slow for the hot path.

## Sandboxing

Objective-authored code — pinned checkers, evaluators and statistics, `replay`
commands, and Lean run over submitted proof text — executes in a child process
inside an OS jail. `bwrap` on Linux, a `sandbox-exec` seatbelt profile on macOS.
`verifiers::SANDBOXING` is the authoritative statement, and a test pins that it
names every gap below; this section is the same list with room to explain it.

Enforced by the kernel:

- **No network of any kind**, including a unix socket to a daemon on the same
  host. An exfiltration path that only needs `localhost` is still an
  exfiltration path.
- **No writes outside a scratch directory** that is deleted when the check
  finishes.
- A wall-clock deadline, and best-effort `RLIMIT_CPU` / `RLIMIT_AS`.
- A **scrubbed environment** for pinned pure functions, so a checker cannot read
  the operator's credentials out of it.

A jail that cannot start is `UNAVAILABLE`, never `REJECT` — the rule at the top
of this document applies to the sandbox exactly as it applies to a missing
toolchain. When a jailed run fails, the verdict's evidence names the mechanism,
so an operator can tell a broken jail from a broken checker.

Four gaps are real and none of them are hypothetical:

1. **It is not a VM boundary.** A kernel or policy bug is still an escape.
   gVisor, Firecracker or WASM would bound that; none is implemented.
2. **macOS reads are not confined.** The seatbelt profile denies writes and
   network, not reads. Objective code can read any file the operator can — it
   simply cannot transmit or persist what it read.
3. **`replay` and `lean` inherit the operator's environment**, because their
   toolchains are configured through it. A pinned checker's environment is
   scrubbed; theirs is not.
4. **A host with neither mechanism runs the child unconfined.** Set
   `CAIRN_REQUIRE_SANDBOX=1` to make that `UNAVAILABLE` instead of a silent
   downgrade. Any node running third-party objectives should set it. The
   switch fails closed: any value other than an explicit `0`/`false`/`no`/`off`
   counts as on, so a typo cannot silently mean "unjailed".

One thing that is *not* a gap, because it is checked: directories a spec can
name — replay's `cwd`, lean's `project_root` — resolve against the objective
root and are refused when they escape it. A record cannot choose which host
paths are bound into its own jail.

One thing that is *not* a gap, because it is checked: directories a spec can
name — replay's `cwd`, lean's `project_root` — resolve against the objective
root and are refused when they escape it. A record cannot choose which host
paths are bound into its own jail.

**The reference implementation does not jail at all.** It spawns the
interpreter directly, by design — it exists to be an independent second opinion
on the *rules*, not a hardened node — and `reference/rust/src/verifiers.rs` says
so in those words. Do not point it at an objective you have not read.

It implements **every kind the primary settles**: `certificate`, `evaluator`,
`statistical`, `replay` and `lean`. That list was shorter for a long time, and
the way it stayed short is the point. A kind an implementation lacks answers
`Unavailable` for every claim — which is *correct*, since `Unavailable` is never
`Reject` — and the audit used to skip non-settling statuses without comment. So
an entire kind could have no cross-implementation coverage at all while every
run reported full coverage: two correct behaviours composing into a hole.

Three things now keep it closed.

**Both audits report any settled verdict they cannot re-derive.** Not only the
paid ones. Reporting only payments was the first version and it left the same
hole one rung down: a `reject` never pays, so a rejection no other node could
reproduce passed every audit in silence. That is the worse direction of the
two. A payment somebody will eventually contest; a rejected submitter has no
money to point at and no way to show the rejection was not reproducible.
Censorship that leaves no trace in any audit is precisely what re-derivation
exists to prevent. An `unavailable` the log never settled is still skipped —
nothing was claimed then and nothing is claimed now.

**One list of kinds, not two.** `verifiers::KINDS` is what the reference
consults when deciding whether it can post an objective. There used to be a
second list inside `node.rs`, and it still named `certificate` and `evaluator`
long after three more kinds were implemented — so the crate refused to post
objectives it could verify perfectly well, and interop could only ever drive
those kinds in one direction.

**A test walks the list** and fails on a kind that is advertised but not
dispatched, with the primary's kinds spelled out separately so that dropping
one from both places at once still fails.

And `scripts/interop.sh` drives a `lean` rejection through both implementations
in both directions. It needs no Lean toolchain — a proof containing `sorry` is
screened before the toolchain is ever looked for — so it runs on any host, and
it fails if the `lean` arm is removed from either dispatcher.

`lean` needs a Lean toolchain, which is not a build dependency of this crate: a
node without one answers `Unavailable`, which is the honest answer. The verdict
rules — a non-zero exit is a real `Reject` because the exit code *is* the
kernel's answer, a signal kill is not, and a clean exit that warns about `sorry`
is still a rejection — are tested against a stand-in binary, because what needs
checking is how an exit code maps to a verdict, and that does not need a kernel.

## What an audit actually re-derives

`cairn audit` prints one line — *chain intact, every settled claim
re-verified* — and the value of the whole project rests on that sentence being
literally true. What follows is what it did not check, found by asking what a
log could carry that the line would still be printed over, and then by running
the tools rather than reading them.

**A verdict this node cannot reproduce.** Covered above. Any settled verdict,
not only the paid ones.

**A verdict with a status nobody recognises.** A `"probably"` in the status
field used to surface only as a *disagreement* with a re-run, so on a node
without the relevant toolchain it was silent, and under `--no-rerun` it was
silent everywhere. It is a malformed record, which makes it exactly the kind of
defect the cheap structural pass exists for, so both implementations now report
it there.

**A batch that omitted a claim.** The reference re-sorted the claim list the
batch record itself supplied, which is a check that a batch dropping somebody
always passes. Which claims are in an epoch's batch is what decides who gets
paid that epoch, and it is the last thing an independent implementation should
take from the record it is auditing. Membership is now derived from the log in
both.

**A back-dated record invalidating an honest batch.** The inverse failure, and
an attack rather than an omission. Records arrive over sync stamped with their
own `created_at` and land at the tail, so a peer can append an accepted claim
dated into an epoch that already paid. The *anchor* derivation was already
bounded to the log as it stood when the batch was written; membership was not,
so the same append worked one field over — instead of "the anchor is wrong" the
audit said the operator "settled 1 claim(s) in an order the beacon does not
produce", forever, at a peer's choosing, about a batch that was correct when
written and could not have known about a record that did not yet exist.

The bound has to cover the *verdicts* as well as the claims, which is a second
version of the same attack and not an implementation detail: a claim already in
the log when the batch was drawn, whose accepting verdict arrives afterwards,
was correctly left out — counting its acceptance now faults the batch just as
surely. Both derivations in both implementations now take the bound, and each
half has a test that fails when its half of the bound is removed.

**The money.** The largest, and the last one looked for, because it is not
about records at all. The reference re-derived every id, every Merkle root,
every batch anchor — and never once added up what an objective had paid against
what it had funded. An operator could have overspent a pool by any amount and
the independent auditor would have said *log verified*. It now checks the pool
ceiling, double settlement of a non-ratcheted objective, a settlement whose
reward is not an integer, and an overflowing total (reported, never wrapped — a
wrapped sum resets an overspent pool to something small and hides exactly the
fault being looked for).

**And the rest of what one implementation checked and the other did not.** The
frontier of a ratcheted objective only moves forward, asked of `improves` rather
than by comparison, because `direction` decides which way forward is and
`min_improvement` is what stops a thousand claims each advancing by one unit —
the pool total can stay under the ceiling while the money went to the wrong
claims in the wrong order. A peer record supersedes only by advancing its
identity's sequence, which is what lets a mutable address hint live in an
append-only log; without it a replayed record puts a stale address back in
front, and it is perfectly signed, which is why signature checking alone does
not cover it. A claim with no matching commitment, meaning commit–reveal never
bound it to an epoch. A claim with no verdict, or naming an objective the log
does not contain. A batch with no epoch, no claim list, or a second batch for
an epoch that already settled — each of which the reference had been skipping
with a bare `continue`.

Porting the peer-sequence check is what found the next two, which is the
argument for a second implementation in miniature: writing the same rule twice
makes a disagreement visible, and each disagreement is a bug in one of them.

The primary tracked the *last* sequence seen rather than the highest. Given
seq 3, a replayed 1, then a 2, `Node::peers` still answers 3 — so neither
superseded and both are findings — but the audit reported the 1, adopted its
stale value as current, and passed the 2. An audit contradicting its own
implementation's resolution rule, on exactly the hand-assembled log an audit
exists for.

And the reference let a *forged* record's sequence participate. A record whose
signature does not verify is not a statement by anybody; counting it means
anyone can make the audit accuse an identity of replaying its own records by
appending an unsigned forgery — a finding manufactured out of nothing.

**A `peer` record its own decoder would refuse.** Found by running the command
rather than reading it. `cairn peer --transport <a libp2p-style id>`
appended happily, and every subsequent audit in both implementations reported
the record as undecodable: one command, no error, and a log that can no longer
be audited. Every other record kind reaches the rules engine already decoded, so
`from_value` has run and the fields are known good; `PeerRecord::new` is a plain
constructor that takes what it is handed, which left `peer` as the only kind
that could enter the log without meeting its own decoder. `post_peer` now
validates first.

**A tripwire nobody would read.** `cairn store status` listed every
unaccounted file it found. Pointed at a working directory that is seven hundred
lines, and the `KEY INSIDE THE STORE` finding — the one that means everything
beside it is readable — was somewhere in the middle of them. Keys are now said
first and never elided; the rest is capped with a count of what was left out.
The alarm was always the exit code and the total, not the list.

**`--help` exiting 2.** `cairn-serve` and `cairn-p2p` shared one usage
function between "you asked for help" and "you used me wrong", so asking a
question correctly returned a failure. `cmd --help >/dev/null || fail` is how a
packaging check or a container healthcheck asks whether a binary runs at all.
All four binaries now answer 0 for `--help` and 2 for misuse, and CI pins it.

**The reference could not audit a node that synced.** The case an independent
check exists for — no bundle, no authored objective, verifier code obtained by
hash — and the reference had no content-addressed fallback at all: it read the
pin from the bundle path and stopped. So on every peer that learned an objective
over the wire, the independent auditor reported *"was settled but can no longer
be re-verified"* for claims that re-verify perfectly. Found by running two
`cairn-p2p` daemons and auditing the one that synced, which nothing had ever
done — the daemon is the largest surface in the repository and `--help` was all
CI touched. `scripts/p2p-demo.sh` now runs both sides.

**A verdict that never settled, reported as contradicted.** The opposite
mistake, and the one an ordinary workflow reaches first. A node without a
pinned checker records `unavailable`, fetches the checker from a peer, and
audits — and every claim recorded before the fetch came back as *recorded
unavailable, re-verification says accept*. That is the node learning something,
not catching somebody: nothing settled, nobody was paid, the objective is still
open, and an `unavailable` was never a statement about the artifact. The
reference had this rule right and the primary did not. It failed
`scripts/blob-demo.sh` on its last line the first day there was a fetch path to
run.

The shape recurs often enough to be worth naming: **the summary line is a
claim, and every branch that quietly skips something is a way for it to be
false.** A skip is right only when nothing was ever asserted — an `unavailable`
the log also recorded as `unavailable`. Everywhere else, silence is the bug.
And the converse, which the last one earned: a *finding* about something that
was never asserted is noise, and noise in an audit is how a real finding gets
ignored.

And the corollary the last one earned: an independent implementation drifts
where nothing compares it. The two are checked against each other on ids, roots
and verdicts, so those stayed honest; the *arithmetic* and the output plumbing
had no cross-check, and both had quietly diverged. `cairn-reference` was
still using `println!`, which panics when the reader closes the pipe —
`… post | head -1`, which `scripts/interop.sh` itself does. The primary fixed
that before this crate existed and wrote a paragraph about it. It never crossed
over, and it surfaced as a flaky script rather than as a bug, because the race
is only lost under load.

## Checking one entry without the log

`audit` and `verify` both need a copy of the log. That is the right shape for
somebody re-deriving the whole network's history, and the wrong one for
somebody who wants to know whether a single settlement happened.

```sh
cairn prove 12 --height 25 --out proof.json
cairn check proof.json --from checkpoint.json --root-key operator.pub
```

`check` opens no log, no bundle, and no socket. Its whole input is the proof
and a root, and the root arrives inside a checkpoint somebody signed — which is
why `--root-key` matters and why its absence prints a warning rather than
passing quietly: a checkpoint checked against the key inside it is a checkpoint
checked against itself, and an operator rewriting history signs the rewrite
with a fresh key.

The cost is `log2(n)` hashes: five for the twenty-five-entry log in `launch/`,
fifteen for twenty thousand.

Three ways to fail, kept apart because they accuse different people:

| failure | what it means |
|---|---|
| the entry does not hash to the digest it carries | the holder's copy of that entry was edited |
| the path is for leaf *i* but the entry's seq is *j* | a proof about some other entry |
| the path does not reach the root | the entry is not in the log that root pins |

The third has an innocent cause that is far more common than the guilty one:
the log grew after the checkpoint was signed, so the proof is against a taller
tree. `check` catches that before it walks the path — comparing the proof's
leaf count against the checkpoint's height — and names the remedy
(`prove <seq> --height <the checkpoint's height>`) rather than reporting a
mismatch that reads as fraud.

This is consensus-critical in the same way roots are: a challenger who rejects a
proof an honest holder produced slashes a node that did its job, and one who
accepts a proof the holder could not have produced pays a node that stored
nothing. So it is not enough for each implementation to check its own proofs.
`scripts/differential.sh` runs both against the published log and requires that
each accept what the *other* emitted, byte for byte, in both directions, plus
that both refuse an entry edited under a path that still reaches the root. An
implementation wrong in a self-consistent way passes the first arrangement and
fails this one.
