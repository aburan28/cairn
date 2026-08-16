# HEIR: buy the search, refuse the compute

[HEIR](https://github.com/google/heir) (Apache-2.0, Google, not an officially
supported product) is an MLIR-based compiler toolchain for homomorphic
encryption. It lowers a program through `secret`, `bgv`/`ckks`/`cggi`, `lwe` and
`mgmt` dialects to OpenFHE, Lattigo, tfhe-rs or Jaxite.

This document is the integration review: what an FHE compiler has to do with a
network that pays for verified results, which half of it fits, and which half
looks like the point and must be refused.

The short version, because the ordering is the argument:

| candidate | verdict | why |
|---|---|---|
| the **ILP instances** HEIR emits internally | **take** | expensive to find, cheap to check — the specification, exactly |
| HEIR pass pipelines as a repo-shaped benchmark | **take, later** | needs `workspace` + `prime`; every node pays a 30-minute build |
| FHE as *confidential compute* for objectives | **refuse** | confidentiality is not verification asymmetry |
| FHE-based private search over the corpus | **defer** | right problem, wrong tool, and nothing settles |

## The test that separates them

One question decides every row: **does a verifying node need HEIR?**

The founding constraint in [README.md](../../README.md) is not "hard problems
only", it is *the network can only work on tasks whose outputs are cheap to
check*. An objective that makes every verifier build LLVM from source has not
broken the rule, but it has spent most of the budget the rule was protecting.
An objective whose check is integer arithmetic over a pinned instance has spent
none of it.

The ILP row needs no HEIR at verification time at all. That is the whole reason
it goes first.

## The refusal

**There must be no FHE-evaluation verifier kind, and no objective whose inputs
the network cannot read.**

This is the row everyone arrives wanting, so it deserves the full argument
rather than a line in a table. The pitch is: contributors compute on ciphertext,
the operator learns nothing, the network settles the result. It fails, and not
for the reason usually given.

It does *not* fail on determinism. FHE evaluation is a deterministic function of
the ciphertext and the public evaluation key, so a second node can replay it and
compare output ciphertexts bitwise. `replay` would technically work.

It fails on **asymmetry**. Re-deriving an FHE result costs exactly what
producing it cost — times the 10³–10⁴ overhead FHE already carries over
plaintext. Every other kind this network has buys a check that is cheaper than
the search: a Lean kernel re-checks in milliseconds what took a prover hours, a
DRAT certificate is linear where the search was exponential, an evaluator scores
in seconds what took a GPU-week to find. FHE inverts that. It is the most
expensive available way to buy a result, and the thing it buys is confidentiality
from the operator, which is not what anyone is being paid for.

And it settles the wrong proposition. A verified FHE evaluation settles *"this
ciphertext is the correct homomorphic image of that circuit."* It settles
nothing about the plaintext. Only the key holder learns the answer, and if the
network records what they say the answer was, that is
[`examples/attested-fact/`](../../examples/attested-fact/)'s row again:

| what it would actually check | what that makes it |
|---|---|
| the key holder decrypted and reported X | an oracle with extra steps |

Two further facts, both of which matter if anyone revisits this:

**FHE is not maliciously secure.** A dishonest evaluator returns a wrong
ciphertext and nothing in the scheme detects it. Detection *is* the replay, at
full cost. Verifiable FHE — FHE composed with a succinct proof of correct
evaluation — is the honest construction and is research-grade, with proving
overheads that make the raw FHE cost look like the cheap part. If that changes,
it arrives as a `zk`-shaped kind and reuses none of this.

**Bitwise replay is more fragile than it looks.** Noise flooding and randomized
encryption break reproducibility unless the RNG is seeded and the seed lives in
the artifact, and CKKS is *approximate* — two honest nodes comparing CKKS
outputs bitwise is a hardware-dependent coin flip, and comparing them with a
tolerance reintroduces the float that
[AGENTS.md](../../AGENTS.md) forbids anywhere near money.

## The take: HEIR's ILPs are the artifact

HEIR solves integer linear programs inside two passes:

- [`OptimizeRelinearization`](https://github.com/google/heir/tree/main/lib/Transforms/OptimizeRelinearization)
  — "we use an integer linear program to determine the optimal relinearization
  strategy. It solves an ILP for each `func` op in the IR."
- [`ILPBootstrapPlacement`](https://github.com/google/heir/tree/main/lib/Transforms/ILPBootstrapPlacement)
  — bootstrap placement against a JSON latency cost model.

Both go through or-tools MathOpt with the GSCIP (SCIP) backend. This is the
seam, because an ILP solution is the canonical shape of everything this network
is built to buy: **a feasible assignment is checked by substitution, and finding
one is NP-hard.** The verifier does integer arithmetic over a pinned instance.
No MLIR, no or-tools, no FHE, no LLVM.

### What is *not* the prize

The obvious pitch is "HEIR stops at a 1% optimality gap, so pay people to close
it." Read what the pass actually says first:

> The ILP is solved to a fixed 1% relative optimality gap with no time limit […]
> Proving full optimality often dominates solve time on large instances while
> improving the objective by less than measurement noise in the profiled cost
> models.

That is HEIR documenting that the last 1% is *below its own measurement noise*.
An objective that pays to close it pays real money for a number that does not
move a wall clock. Say so before building it, not after.

### What is the prize

The same sentence names it: solve time **dominates on large instances**, and the
configuration has **no time limit**. The failure mode of these passes is not a
slightly suboptimal schedule; it is a compile that does not finish. The circuits
FHE most needs — deep networks, large matvecs — are exactly the instances where
a branch-and-cut solver stalls.

So the objective is:

> Here is a bootstrap-placement instance from a circuit that HEIR does not
> currently compile in tolerable time. Produce a feasible schedule. Score is its
> cost under the pinned model, minimized.

That is worth paying for, it is checked in milliseconds, and a good answer
unblocks a compile that does not happen today. It is also a domain where
solver-tuning, heuristics and LLM-guided search plausibly beat SCIP's default
configuration on structured instances, which is the sort of thing this network
exists to find out.

### The spec

`evaluator`, which exists and needs no new kind:

```json
{
  "kind": "evaluator",
  "evaluator": "examples/heir-bootstrap/check.py",
  "evaluator_sha256": "…",
  "entrypoint": "score",
  "direction": "minimize",
  "threshold": 0
}
```

The instance is a blob pinned by the objective; the artifact is the assignment:

```json
{
  "instance_sha256": "…",
  "assignment": { "b_7": 1, "b_23": 0, "level_11": 4 },
  "results": { "score": 41822000 },
  "note": "greedy seed on the depth-4 frontier, then local search on bootstrap pairs",
  "model": "claude-opus-5"
}
```

Three rules the evaluator must get right, each one a lesson this repository has
already paid for:

**Infeasible is `Reject`, not a bad score.** An assignment that violates a
constraint is a fact about the artifact and must refuse, not score poorly and
sit on a leaderboard looking like a weak submission. `score_verdict` routes a
score through `threshold`/`direction`; infeasibility has to short-circuit before
it, the way [`verify_replay`](../../src/verifiers/mod.rs) separates a mismatch
from a timeout.

**Every number is an integer, including the cost model.** This is the sharpest
practical constraint and it is not optional. HEIR's cost model is latency in
*microseconds*, and it least-squares fits `cost(level) = slope * level +
intercept` — floats produced by a floating-point fit. `canonical::Value` has no
float variant, deliberately, and AGENTS.md is blunt: no floats anywhere near
money or identity. So the pinned instance must carry **pre-fitted integer
coefficients** (nanoseconds, `i64`), computed once by the objective author and
frozen into the blob. Re-running a least-squares fit at verification time is two
nodes disagreeing about a payout in the low bits.

**The instance is pinned as bytes, not regenerated.** A node must never run
`heir-opt` to reconstruct what it is checking. The instance blob is authoritative
and `Registry::pinned` already gives `InvalidSpec` on a hash mismatch and
`Unavailable` when the bytes cannot be fetched — the two verdicts wanted.

### The one upstream dependency

HEIR has no documented flag today that dumps the MathOpt model it builds. Some
scaffolding is there — `OptimizeRelinearization` has
`use-loc-based-variable-names` "to help debug ILP model bugs" — but a stable,
canonical export does not exist as a published interface.

So this design needs either a small upstream contribution (`--dump-ilp-model`,
MathOpt already serializes to MPS and to its own proto) or an out-of-tree tool
pinned to a HEIR commit. This is the honest cost of the row, and it is one
patch against a project with monthly community meetings and a
`good first issue` queue rather than a fork.

Note what it is *not*: it is a cost paid **once, by the objective author**, to
mint an instance. It is not paid by every verifying node on every submission.
That asymmetry is the entire design.

## The second take: HEIR as a `workspace` benchmark

The other shape is the one [workspace-benchmarks.md](./workspace-benchmarks.md)
just designed for Yukon: pin a base tree, let a solver replace declared paths,
score with a pinned command. Applied here — *"beat the baseline compilation of
this circuit"*, where the editable paths are a pass pipeline or a rewritten
`.mlir` module.

It is real, and it is strictly downstream of two things that do not exist yet:

- `workspace` itself, which is designed and unbuilt.
- `bench prime`, because [`src/verifiers/sandbox.rs`](../../src/verifiers/sandbox.rs)
  passes `--unshare-net` unconditionally and must keep doing so. A HEIR
  toolchain cannot be fetched inside the jail. It is a Bazel build that compiles
  LLVM from source — thirty minutes clean, by HEIR's own README — plus a
  backend, plus or-tools, plus a Python 3.13 constraint that or-tools 9.12
  imposes. `prime` is designed for exactly this and this is the heaviest thing
  anyone would point it at.

Two problems are specific to compilers and worth naming before someone builds
this and discovers them:

**Equivalence is the hard part, and testing is not proof.** A submission that
compiles the circuit faster is worthless if it compiles it *wrong*, and running
the pinned test vectors only shows it is right on those vectors. For arithmetic
circuits over a finite field there is a real answer — Schwartz–Zippel: evaluate
both circuits at a random point and they agree with probability bounded by
`deg/|F|`. That gives a soundness bound rather than a vibe. It needs randomness
the submitter cannot grind, which is `beacon(epoch, anchor)` — the same
unbiasable-beacon requirement
[confidential-corpus.md](./confidential-corpus.md) already records for other
reasons, and the same rule `statistical` already enforces by pinning its seed.
One mechanism, a third caller.

**Compiler determinism is an assumption, so test it first.** MLIR passes are
generally deterministic, but "generally" is not the standard here — two nodes
must produce the same verdict. Pointer-keyed iteration order, parallel pass
management, and a branch-and-cut solver that can be sensitive to timing are all
live risks, and SCIP's answer at a 1% gap need not be stable across builds. The
first experiment is not a verifier; it is running the pinned pipeline twice on
two hosts and diffing the output. If it does not reproduce, this row dies and
the ILP row is unaffected — which is a good reason to build them in that order.

## The defer: private search over the corpus

[confidential-corpus.md](./confidential-corpus.md) names search as "the largest
gap, and the one that decides whether this is a knowledge base or a filesystem":
searchable symmetric encryption leaks access patterns and the leakage-abuse
literature exploits that; PIR avoids it and is expensive.

FHE is a genuine answer to that gap. HEIR is not the reason it would be — a PIR
implementation is a library, not a compiler output, and HEIR earns its place
only if the query circuits are custom enough to need compiling. More decisively:
this is a **serving** feature. Nothing settles, no verdict is reached, no money
moves. It belongs to the corpus roadmap and it does not touch
`src/verifiers/`.

Recording it here so the next person who notices FHE and the corpus in the same
week finds the reasoning instead of redoing it.

## Work

Only the ILP row is proposed for building. It is deliberately small, because
almost all of it already exists.

- **Upstream or out-of-tree**: a canonical dump of the MathOpt model from
  `ILPBootstrapPlacement` / `OptimizeRelinearization`, pinned to a HEIR commit.
  Prerequisite for everything below; nothing here works around its absence.
- `examples/heir-bootstrap/` — a new objective directory: the pinned instance
  blob with integerized cost coefficients, `check.py`, a `README.md` carrying the
  provenance of the instance (which circuit, which HEIR commit, which cost
  model), and a `demo.sh` that exercises an infeasible submission as well as a
  good one.
- `conformance/adversarial.jsonl` — the boundary cases, so `differential.sh`
  proves both implementations classify them alike: an assignment violating a
  constraint, an assignment naming a variable the instance does not have, a
  missing variable, a float in `results.score`, a `results.score` that disagrees
  with the recomputed objective, an instance blob that does not match its hash.
- `docs/verification.md` — no new row. `evaluator` is already there, and this
  adds an objective, not a kind. If a row appears, something went wrong.

`conformance/vectors.json` stays frozen. No record shape changes, no verifier
kind is added, no digest moves — which is the strongest argument that this is
the right seam.

The `workspace` row is blocked on `workspace` and `prime`, and its own first
task is the two-host determinism experiment above, not code.

## Residual gaps, stated rather than closed

**The cost model is a proxy, and this network will optimize it exactly.** Score
is modeled latency, not measured latency, and a ratchet paying for modeled cost
will find whatever the model gets wrong. This is the same class of problem as
any benchmark objective — with the sharpening that HEIR has already told us the
last 1% of this model is noise. An instance is only worth funding where the gap
being closed is large enough to survive the model's own error bars, and the
objective statement should say which circuit and which profile produced the
coefficients so a reader can judge that.

**A HEIR-derived instance ages.** It is pinned to a commit of a pre-1.0 project
that explicitly disclaims support and whose pass names and IR change. The
pinned bytes stay verifiable forever, which is the property that matters — but
an instance can become an accurate answer to a question the compiler no longer
asks. That is a funder's problem, not a verifier's, and it is the normal state
of every benchmark.

**No threat-model row is owed.** Worth stating explicitly, since the last two
design documents both owed several: this adds no new execution surface, no new
record kind, and no new trust assumption. The evaluator is a pinned pure
function over an artifact, jailed like every other, and the instance is bytes
addressed by their own hash.
