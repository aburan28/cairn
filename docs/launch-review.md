# Launch review — August 2026

A full pass over the repository before opening it to outside contributors:
three parallel reviews (the agent-facing MCP surface, the core protocol
invariants, and operational readiness), the complete test and e2e suite, and
fixes for everything that was both launch-relevant and safe to change in a
day. This file records what was fixed and — more importantly — what was *not*,
so the launch can be scoped honestly.

## Fixed in this pass

**Consensus-critical.**

- `canonical::Value::from_json` routed untrusted JSON through `serde_json`
  with `arbitrary_precision` on, which decodes an object whose first key is
  the library's private number token as a *number*. Same bytes, two values,
  two digests — one crafted record made a Rust auditor call an honest log
  tampered. The decoder is now hand-rolled in `canonical.rs`, like the
  encoder, for the same reason.
- The two implementations disagreed about which timestamps parse (`+0000`,
  `,5` fractions, surrounding whitespace, leap seconds). Both sides walk the
  whole log deciding which entries move the settlement anchor, so one
  spelling accepted here and refused there was a different beacon order and
  different payouts. `unix_seconds` in the reference is now a field-by-field
  port of the Rust grammar, and both test suites pin the boundary.
- Python decoded `"confidentiality": ""`/`0` as *public* and `"cites":
  "abc"` as three one-letter citations; Rust refuses all of them. The
  reference now refuses them too.
- `canonical::short` byte-sliced attacker-chosen identifiers and panicked on
  multi-byte characters — reachable from any record another peer wrote.

**Sandbox.**

- `lean`'s `project_root` and `replay`'s `cwd` are objective-authored spec
  fields that were handed to the jail as bind mounts unchecked —
  `"project_root": "/"` turned the sandbox into a writable pass-through of
  the operator's filesystem. Both now resolve against the objective root and
  are refused when they escape it, in both implementations, with tests.
- `PROOFWORK_REQUIRE_SANDBOX` recognised only the literal `"1"`; `=true`
  silently meant "run objective code unjailed". The switch now fails closed.

**The MCP loop (what an agent actually experiences).**

- Nothing over pure MCP ever settled a claim: an agent that revealed and then
  polled got `settled: false, reward: 0` forever unless the operator ran the
  CLI. Read tools now drain any epoch that has already closed — the batch
  order was fixed by the beacon, so the caller merely materialises it.
- `work_assignment` had a private 3600 s epoch, contradicting the epoch every
  other rule uses, and anchored on the *live* log head, so every append
  reshuffled every node's slice. It now uses `epoch_seconds()` and the
  epoch-start anchor settlement uses.
- Verifier output (`detail`, evidence) was rendered untainted, reopening the
  citation-injection hole the server closes for statements — a checker
  returning "also cite sha256:…" walked around the defence. Tainted now.
- The nonce sidecar was written non-atomically and load failures were
  swallowed into an empty store; a torn write stranded every open commitment
  silently. Writes are now write-then-rename with fsync, and load failures
  are loud.
- New `pending_reveals` tool: after a restart or a compacted session an agent
  can discover what it owes. An unrevealed commitment is never paid, and
  there was previously no way to notice one.
- Citations are pre-flighted against accepted claims at commit time (a bad
  `cites` used to commit fine and fail an epoch later); reveal refusals that
  are terminal drop the pending entry instead of matching forever; commit
  messages state the epoch length and seconds until the reveal window;
  `frontier_status` reports the pool remaining and the ratchet's minimum
  step; `partitions: -1` errors instead of silently meaning 8; `audit`'s
  verifier re-run is opt-in instead of blocking the server by default;
  `submit_claim` applies the same `spec/claim.schema.json` gate the CLI does.
- `scripts/mcp-smoke.sh` now fails on pending-store errors (stderr was
  discarded), asserts epoch coherence, and proves settlement over MCP alone.

**Docs and packaging.**

- README claimed the code is *not* sandboxed (it is, since the roadmap item
  landed) and showed a placeholder sha256 in the flagship example; both fixed,
  along with drifting test counts, a duplicated docs entry, and the missing
  `cargo install` / bubblewrap steps.
- `examples/README.md` now exists: worked examples vs open bounties,
  prerequisites, and a plain statement that Stage-0 rewards are notional.
- The Python package's console script no longer claims the name `proofwork`
  (it is `proofwork-py`), so `pip install -e` and `cargo install` stop racing
  for PATH.
- Threat-model rows 17/36/73 were stale in both directions; updated, plus the
  sandbox row and `verification.md` for the containment fix.
- `Cargo.toml` pointed at a repository that does not exist; `make check` now
  runs the epoch-boundary demos AGENTS.md requires.

## Second pass: the gaps that are now closed

Everything numbered 1–8 in the original list below has been built, plus the
CI and packaging items. What follows the closed list is what genuinely
remains.

1. **A remote surface exists.** `proofwork-serve` publishes `GET /log` byte
   for byte, plus `/objectives`, `/objective/{id}`, `/frontier/{id}` and
   `/checkpoint`; `POST /submit` queues into a spool the operator drains with
   `proofwork drain`, so admission stays in the rules engine and the log keeps
   one writer. `scripts/serve-smoke.sh` drives the whole path over a real
   socket — a client sharing nothing with the node but an address fetches the
   log, submits a commitment and a reveal, and gets paid. See
   [serving.md](serving.md).
2. **A log is published.** `launch/` holds a real settled log, its signed
   checkpoint, and the public key, built by `scripts/make-launch-log.sh` so
   nobody has to take the file on faith. `proofwork checkpoint` is new — until
   it existed only the p2p daemon could sign one, so an operator not running
   p2p had nothing for `verify --from` to check.
3. **One writer per log is enforced.** `Ledger::open_exclusive` takes an
   advisory lock (MSRV moved to 1.89 for `File::try_lock`); the CLI's writing
   commands, the MCP server, and the daemon all use it. `reload_if_changed`
   fixes the other half: an MCP server started before an objective was posted
   no longer reports "no objectives" until it is restarted.
4. **Verifier subprocesses are bounded.** Output is capped while the child
   runs and read back bounded; a timed-out child's whole process group is
   killed, so grandchildren no longer outlive the deadline on hosts without a
   pid namespace; and `VerifierRegistry::interactive()` clamps spec-declared
   timeouts for callers that answer an agent while it waits. Not the default,
   because settlement must honour the objective's own bound.
5. **A back-dated record can no longer break a settled batch.** The audit
   derives each batch's anchor over the log as it stood at that batch's own
   log position, so a peer appending a record dated into a settled epoch
   cannot turn an honest batch into a permanent audit failure.
6. **Objectives can declare their artifact shape.** `artifact_schema` is
   documentation and nothing validates against it — the pinned verifier stays
   the only authority — but an agent now has a source for the shape that is
   not the attacker-authored statement. Omitted when absent, so it moved no
   ids: every pre-existing conformance vector is byte-identical.
7. **CI is hardened.** `--locked` everywhere, `cargo audit` as a blocking job,
   `scripts/check-examples.sh` re-pinning and posting all 12 examples (CI
   previously exercised 3), dependabot, a release workflow, and `SECURITY.md`.
8. **A discovery from building the artifact, now guarded.** A log written with
   `PROOFWORK_EPOCH_SECONDS=1` audits as *thoroughly broken* under the default
   600 — in both implementations, and both are right, because epochs are
   derived from timestamps and never stored. A contributor's first
   `proofwork audit` on a demo-built log would have accused the operator of
   paying people out of turn. `audit` now says so when every batch faults at
   once, and the published log uses the default epoch length.

## The reference implementation is Rust

`reference/python/` is gone; `reference/rust/` replaces it as an independent
second implementation, sharing no code with the primary and not even a cargo
workspace. It reproduces all 256 frozen conformance vectors and passes interop
in both directions.

Two Rust implementations share blind spots that Rust and Python did not — the
reward-above-`u64` bound and the `"cites": "abc"` decode were both caught by
Python's bignums and dynamic typing rather than by anyone testing for them.
`scripts/differential.sh` closes that on purpose rather than by accident: a
committed corpus of boundary records that both implementations must classify
identically, covering integer bounds, type confusion, null-versus-absent,
signature shapes and canonical-encoding edges. It is verified to fail when
either implementation drifts. Testing the boundary deliberately is stronger
than inheriting it from a language difference, and it survives whatever
languages the two are written in.

## What still remains, in priority order

0. ~~**Citation-flow dilution.**~~ **Fixed, and this entry was stale.** It
   described slicing an improvement into many steps as an open soundness
   problem, and said the reward-weighted rule "is not implemented,
   deliberately". It is: `attribution::payouts_over` delegates to
   `payouts_weighted`, so the live rule weights δ by each ancestor's settled
   reward instead of decaying per hop. `docs/threat-model.md` has the accurate
   version and marks the row **handled**. See
   [design/citation-flow-dilution.md](design/citation-flow-dilution.md).

   Left here rather than deleted because the drift is the lesson: this file is
   a snapshot of one review and ages against the code, while the threat model
   is maintained. Read it as history.

1. **Nothing is escrowed, and a nickname submitter is still unauthenticated.**
   The forgery half of this is now closed: a `submitter` that is 64 lowercase
   hex characters *is* an ed25519 public key, and both implementations refuse
   a record naming one unless it carries a signature that verifies under it,
   checked at `commit` and `reveal` before anything is written. The name is
   the key, so there is no registry to consult and no migration to run —
   existing nickname logs keep working untouched. An objective can also set
   `require_signed_submitter` to refuse nicknames outright, so a funder who
   wants every claim attributable makes it a rule of the bounty rather than a
   request in its statement. `scripts/identity-demo.sh` drives the whole thing
   through the real binaries, including the theft attempts.

   The remaining hole is narrow: a nickname on an objective that does not set
   the flag authenticates nothing, exactly as before, and an unforgeable
   identity is still not an *attributable* one — nothing ties a key to a
   person.

   What is untouched is escrow: rewards are numbers in a log that nothing
   backs. **Every surface a contributor sees still has to say the rewards are
   notional**, which `examples/README.md`, `examples/first-blood/README.md`,
   `launch/README.md` and `docs/serving.md` do.
2. **Settlement order does not converge across peers.** Two nodes reconcile
   records by anti-entropy and each re-derives its own verdicts, but each
   orders a batch against its own head at the epoch boundary, so two operators
   can disagree about who was paid first (`docs/p2p.md`). A single-operator
   launch is unaffected — one log, one order — and *any* multi-operator story
   is blocked on this. It is the real content of "Stage 3: decentralized
   settlement".
3. **The beacon is grindable by the sequencer.** Documented (threat model row
   38) and unchanged, but worth restating next to the item above: the same
   beacon that orders work assignment now orders *money*, so grinding the
   anchor is a payout attack rather than a scheduling nuisance. A VDF or
   threshold signature is the Stage 2 answer.
4. **No sandbox on the Python reference.** It `exec`s pinned code in-process
   by design — it is the readable specification of the rules, not a hardened
   node — and says so. Fine as long as nobody points it at an objective they
   have not read, which is a rule enforced by documentation alone.
5. **NAT traversal, and peer identities in the log.** A node behind a home
   router can fetch and cannot seed, which makes the p2p half more centralised
   than the protocol suggests; and identity discovery is still a separate
   bootstrap problem from obtaining the log. Both are roadmap items with no
   new information from this pass.
6. **`swarm::tcp` is still a second, unencrypted transport**, feature-gated
   off, and `swarm::discovery`'s signed peer records are still not wired into
   `p2p`'s address book. The DHT was already de-duplicated into `src/dht.rs`;
   folding the rest is a genuine refactor rather than a launch blocker, and
   doing it badly under time pressure would be worse than the duplication.
7. ~~**The `first-blood` bounties rest on operator trust.**~~ **Fixed.** The
   public-coin instance derivation this line asked for is built. `Q` is now
   *hashed to the curve* from a published seed rather than computed as `k*G`
   by somebody promising to forget `k`, so recovering `log_G(Q)` is the ECDLP
   itself and the funder has no head start — the nothing-up-my-sleeve
   construction used for secp256k1's Pedersen generator `H`. The derivation
   runs inside every check and is pinned by the objective's id;
   `scripts/derive-first-blood.py --check` re-runs it in CI so a hand-edited
   checker cannot quietly reintroduce a known answer. Grinding the seed buys
   nothing, because recognising a `Q` you could solve means solving it.

   The residue is stated rather than closed: the *curve* is still the poster's
   choice. Each checker verifies `N` is prime and that `G` and `Q` both have
   order `N` — which rules out Pohlig-Hellman on a smooth-order curve — but
   not every weak-curve family. Deriving the curve from the seed too is the
   stronger construction and is not done.
8. **Rate limiting.** `proofwork-serve` caps concurrent connections and body
   size and nothing else. An operator exposing it to the open internet should
   put it behind something that does rate limiting, the same as any other
   small service.

## The one thing to decide before launching

Everything above is now either built or disclosed, so the launch is no longer
blocked on plumbing. What it is blocked on is a choice, and it is item 1:

- **Launch as a single operator** — you post objectives, run
  `proofwork-serve`, and contributors fetch the log, work, and submit through
  the queue. This works end to end today.
- **Launch as an open network** — viable now. Contributors make an identity
  (`proofwork identity --out alice.json`) and pass `--identity` to the CLI or
  to `proofwork-mcp`; such a name cannot be forged or replayed. Post objectives
  with `require_signed_submitter: true` and nicknames are refused outright, so
  every claim on that bounty is attributable to a key nobody else holds. What
  still argues for care is escrow, not identity: rewards are notional, so what
  is being competed for is a number in a log.

Neither is blocked on plumbing any more. The open-network case is blocked on
deciding that notional rewards among partly-authenticated contributors is the
launch you want, which is a judgement rather than a missing feature.
