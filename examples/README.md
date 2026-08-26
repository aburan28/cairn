# Worked objectives and open bounties

Writing a new one starts with `cairn scaffold <name> --kind <kind>`, which
writes an `objective.json` with the fields that kind's verifier actually reads,
a stub already pinned by its own hash, and a placeholder artifact — in the
shape everything below uses. It posts nothing: funding a statement is a
decision a person makes after reading it. The generated stub rejects
everything, which is the safe direction for logic nobody has finished writing.

Every objective here has its verifier pinned by hash, so re-computing the pin
(`sha256sum` on the named file) must match the record — CI checks that. What
differs is whether a worked artifact ships beside it, and what your machine
needs before the verifier can run.

**Rewards are notional.** Stage 0 has no token, no escrow, and no transfer
primitive; the numbers below are the unit of account the settlement rules
operate on, not money anyone is holding. See *What this is not* in the
top-level README.

| example | verifier | reward | status | needs | worked artifact |
|---|---|---|---|---|---|
| [`reversible-adder`](reversible-adder/) | evaluator (minimize) + ratchet | 1000000 | **worked, and open** | python3 | `artifact-cuccaro.json`, `artifact-truncated.json` |
| [`secp256k1-modadd`](secp256k1-modadd/) | evaluator (minimize) + ratchet | 1000000 | **worked, and open** | python3 | `artifacts/vbe-seed.json`, `artifacts/reused-ancillas.json` |
| [`collatz`](collatz/) | certificate | 100000 | worked | python3 | `artifact.json` |
| [`capset`](capset/) | evaluator | 250000 | worked | python3 | `artifact.json` |
| [`capset_progressive`](capset_progressive/) | evaluator + ratchet | 1100000 | worked | python3 | `artifact-12/16/20.json` |
| [`ecdsa-fail`](ecdsa-fail/) | evaluator (minimize) + ratchet | 1000000 | worked | python3; optional external `ecdsafail` CLI | `artifacts/` |
| [`permutation`](permutation/) | statistical | 50000 | worked | python3 | `artifact.json` |
| [`ecdlp`](ecdlp/) | certificate | 250000 | **open bounty** | python3 | none — that is the point |
| [`elliptic-rank`](elliptic-rank/) | certificate + exact evaluator | 20000000 – 64000000 | **4 open rank-record bounties** | python3 | rank-30 record (baseline only) |
| [`lean`](lean/) | lean | 50000 | **open bounty** | a Lean 4 toolchain on PATH | none |
| [`first-blood`](first-blood/) | certificate | 100000 – 409600000 | **open bounty** ×5 | python3 | none |
| [`faster-algorithms`](faster-algorithms/) | evaluator (minimize) + ratchet | 1200000 – 2000000 | **open bounty** ×4 | python3 | `artifacts/`, baselines only |

- **worked** — a passing artifact is committed, so the whole loop
  (`post → commit → reveal → audit`) can be exercised end to end. Start here.
  `cairn try <objective.json> --submitter you --artifact <artifact.json>`
  runs that loop in one command, waiting out the epoch between the commit and
  the reveal rather than making you sleep past it by hand. A real round takes a
  real epoch — 600s — so set `CAIRN_EPOCH_SECONDS` for a local trial, and
  only against a log used for nothing else.
- **[`faster-algorithms`](faster-algorithms/) is four bounties for doing the
  same work with fewer operations** — sorting, graph search, matrix
  multiplication, MixColumns — and its README is where the rule that makes any
  of them settleable is written down: *"faster" is a count of operations under a
  stated cost model, derived by simulating the artifact, and never a
  measurement of time.* Wall-clock seconds are a property of the machine, so two
  honest nodes disagree about them by construction; `TIME_LIKE` in
  `src/verifiers/mod.rs` already refuses that class of claim. Read it before
  writing an objective about performance.
- **`reversible-adder` is the one to read if you are judging the design.** Its
  score is *derived by simulating the artifact* rather than read off a field the
  submitter filled in, which is what makes an objective safe to fund. Compare it
  against `ecdsa-fail`, which has the same shape and accepts declared numbers —
  one is a bounty, the other is a demo, and the difference is the whole thesis.
- **[`secp256k1-modadd`](secp256k1-modadd/) is that same treatment carried one
  step toward a real target.** Modular addition is the primitive that dominates
  elliptic-curve point-add cost, and `P = 29 = 2⁵ − 2¹ − 1` is a pseudo-Mersenne
  prime of the same shape as secp256k1's `p = 2²⁵⁶ − 2³² − 977`, so the
  structure a construction exploits is the structure that matters there. It is
  harder than the adder next door because the reduction is conditional and its
  condition has to be uncomputed — the same obligation ecdsa.fail's
  forward∘reverse check imposes. All 841 valid input pairs are simulated, so the
  check is total.
- **open bounty** — no known solution ships. Submitting requires actually
  solving the problem; scoring a candidate is still free.
- Without a Lean toolchain the `lean` objective verifies as `unavailable` on
  your node — which is correct behaviour, not a bug: it says your node cannot
  check, nothing about anyone's proof.
- The `first-blood` instances state that the discrete log was discarded at
  generation time; that claim is the operator's, and nothing in this
  repository lets you verify it. Judge the bounty accordingly.

The quickest way to see one run:

```sh
./scripts/demo.sh              # posts collatz + capset, full commit-reveal-audit
./scripts/ratchet-demo.sh      # capset_progressive: the progressive bounty
examples/ecdsa-fail/demo.sh    # the minimize-direction ratchet
```

## Objectives that accept only signed identities

Set `"require_signed_submitter": true` and the network refuses any submitter
that is not an ed25519 public key with a matching signature — so every claim on
that bounty is attributable to a key nobody else holds. The cost is real and is
the funder's to weigh: it turns away contributors who have not made an
identity, which is why it is per-objective and off by default. Contributors
make one with `cairn identity --out alice.json` and submit with
`--identity alice.json`.
