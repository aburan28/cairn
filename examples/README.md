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

Every directory under `examples/` is listed; the table was regenerated from
the tree on 2026-08-25 (19 directories, 32 objective files), and the *status*
column for every committed artifact is what `cairn try` reported on that date.

| example | verifier | reward | status | needs | worked artifact |
|---|---|---|---|---|---|
| [`reversible-adder`](reversible-adder/) | evaluator (minimize) + ratchet | 1000000 | **worked, and open** | python3 | `artifact-cuccaro.json`, `artifact-truncated.json`, `artifact-5ccx.json` (score 45) |
| [`collatz`](collatz/) | certificate | 100000 | worked | python3 | `artifact.json` |
| [`collatz_bisectable`](collatz_bisectable/) | certificate, with a pinned stepper so a dispute bisects the trajectory | 100000 | worked | python3 | `artifact.json` |
| [`capset`](capset/) | evaluator | 250000 | worked | python3 | `artifact.json` |
| [`capset_progressive`](capset_progressive/) | evaluator + ratchet | 1100000 | worked | python3 | `artifact-12/16/20.json` |
| [`ecdsa-fail`](ecdsa-fail/) | evaluator (minimize) + ratchet | 1000000; `objective-live.json` 5000000 | worked | python3; optional external `ecdsafail` CLI | `artifacts/` |
| [`permutation`](permutation/) | statistical | 50000 | worked | python3 | `artifact.json` |
| [`ecdlp`](ecdlp/) | certificate | 5000 | worked — a 45-bit demonstration whose answer ships | python3 | `artifact.json` |
| [`golomb-ruler`](golomb-ruler/) | evaluator (minimize) + ratchet | 900000 | worked; `artifact-72.json` reaches the proved optimum and exhausts the pool | python3 | `artifact-72.json`, `artifacts/greedy-96.json` (baseline) |
| [`sorting-network`](sorting-network/) | evaluator (minimize) + ratchet | 800000 | worked; `artifact-batcher19.json` reaches the proved optimum and exhausts the pool | python3 | `artifact-batcher19.json`, `artifacts/bubble-56.json` (baseline) |
| [`ramsey`](ramsey/) | certificate | 250000 | worked — a witness to a known bound, `R(4,4) = 18` | python3 | `artifacts/paley-17.json` |
| [`attested-fact`](attested-fact/) | certificate | 100000 | worked — verifies **provenance, not truth**; read its README | python3 | `artifacts/sourced.json`; `misquoted`, `one-source` and `tampered-source` are there to be refused |
| [`programbench-vetted`](programbench-vetted/) | evaluator (maximize) + ratchet | 1000000 | worked — a held-out benchmark task graded on a log | python3 | `artifacts/resolved.json`; `partial`, `almost`, `cheating`, `hanging` score lower or are refused, by design |
| [`lean`](lean/) | lean | 50000 | worked, if you have Lean — `unavailable` on a node without it | a Lean 4 toolchain on PATH | `artifact.json`; `hole.json` is the `sorry` the verifier refuses |
| [`elliptic-rank`](elliptic-rank/) | certificate + exact evaluator | 20000000 – 64000000 | **4 open rank-record bounties** | python3 | `artifacts/rank-30-record.json` — a baseline, rejected by the rank-31 objective |
| [`certicom-ecdlp`](certicom-ecdlp/) | certificate | 120000 / 400000 / 2000000 | **open bounty** ×3 — two solvable NUMS rungs (50 and 60 bits) and Certicom's ECCp-131, posted as a frontier and not expected to settle | python3 | none |
| [`first-blood`](first-blood/) | certificate | 100000 – 409600000 | **open bounty** ×5 | python3 | none |
| [`aadp-witness-encryption`](aadp-witness-encryption/) | certificate | 300000 | **open bounty** — an external cryptanalysis challenge, pinned as posted | python3 | none |
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
- **`reversible-adder` is the one to read if you are judging the design.** It
  is the only example whose score is *derived by simulating the artifact*
  rather than read off a field the submitter filled in, which is what makes an
  objective safe to fund. Compare it against `ecdsa-fail`, which has the same
  shape and accepts declared numbers — one is a bounty, the other is a demo,
  and the difference is the whole thesis.
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
