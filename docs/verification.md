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
   `PROOFWORK_REQUIRE_SANDBOX=1` to make that `UNAVAILABLE` instead of a silent
   downgrade. Any node running third-party objectives should set it. The
   switch fails closed: any value other than an explicit `0`/`false`/`no`/`off`
   counts as on, so a typo cannot silently mean "unjailed".

One thing that is *not* a gap, because it is checked: directories a spec can
name — replay's `cwd`, lean's `project_root` — resolve against the objective
root and are refused when they escape it. A record cannot choose which host
paths are bound into its own jail.

**The Python reference does not jail at all.** It `exec`s pinned code in-process
by design — it is the readable specification of the *rules*, not a hardened
node — and `proofwork.verifiers.base.SANDBOXING` says so in those words. Do not
point it at an objective you have not read.
