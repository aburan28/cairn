# Verification

A currency is exactly as sound as the cheapest check that mints it. This
document is the ladder of checks `proofwork` supports, what each one actually
proves, and how to author a verifier that cannot be gamed.

## The ladder

| tier | claim shape | who can check, and how | implemented |
|---|---|---|---|
| **V0** | NP certificate: a witness, counterexample, construction, collision | anyone, in milliseconds, by recomputation | `certificate` |
| **V1** | machine-checked proof | anyone, seconds to minutes; the kernel is the arbiter | `lean` |
| **V2** | bounded re-execution at a pinned commit, seed, environment | anyone with the compute; deterministic *only on reproducible fields* | `replay` |
| **V3** | statistical validation against a pre-registered test statistic | anyone, by resampling; agreement is probabilistic | not yet |
| **V4** | judgement: is this novel, is this promising, is this important | nobody, mechanically. ever | never |

The `evaluator` verifier sits alongside V0: a pinned deterministic fitness
function costs exactly one evaluation to re-check — the same evaluation the
network was going to run anyway — so verification is *free*, not merely cheap.
This is the FunSearch/AlphaEvolve shape and it is the best value-per-check in
the whole table.

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

## Verifiers not implemented here

Because they need infrastructure this stage deliberately does not have, and
because each buys a weaker guarantee than the four above:

- **Statistical (V3).** Needs the test statistic and rejection threshold
  registered *with the objective*, before any data exists. A statistical claim
  whose success criterion is chosen after seeing the samples is unfalsifiable,
  and on an open market straightforwardly exploitable.
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

Pinned verifier code executes in-process. That is adequate for a single operator
who authors or reviews every objective, and inadequate for permissionless
objective authorship: a malicious author would be running arbitrary code on
every contributor who touches the objective. Verifier execution must move into a
sandbox (container, gVisor/Firecracker, or WASM) with no network and a
wall-clock cap before objective authorship opens. Launch blocker, not a
nice-to-have.
