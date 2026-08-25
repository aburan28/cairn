# Running Computer Anthology on cairn

*Proposal plus a working pilot. Describes work not yet done; nothing here is a
Vetto commitment, no ledger record depends on it, and the pilot in this
directory funds nothing.*

Target: `aburan28/distributed-researcher` (the `cairn` crate) becomes the
grading and publication layer under Vetto's benchmarks, so that every published
number is re-derivable by a stranger holding nothing but a copy of the log.

---

## 1. The trade, in one line each

**What cairn gives Vetto.** A leaderboard is currently a claim about numbers
Vetto computed on Vetto's infrastructure. On cairn it becomes a *pure function
of an append-only log*, with every grader pinned by hash inside the id of the
objective it grades. Editing a verifier does not rescore old work — it forks
the objective. That is pre-registration of the grader, enforced by content
addressing rather than by promise, and it is worth more to a benchmark company
than to almost anyone else: the whole product is "trust these numbers."

**What cairn demands in return.** The grader must be *publishable*. A node that
cannot fetch the pinned checker returns `UNAVAILABLE`, which settles nothing.
There is no hidden-verifier mode and `confidentiality: sealed` is refused at
validation — paying for an artifact nobody may read needs a zero-knowledge
proof that the pinned verifier accepts it, which is not implemented.

So the entire question is: **for which of Vetto's benchmarks does publishing
the verifier cost anything?** The answer is not the same for the two shipped
today, and that difference drives the whole plan.

---

## 2. The decisive asymmetry

> A verifier can be published for free exactly when checking is not solving.

| benchmark | what the verifier holds | does publishing it burn the task? |
|---|---|---|
| **ProgramBench Vetted** | the reference **binary**, plus a behavioural differ | **No.** The agent is already given the binary. The answer is its *source*, and the verifier does not contain source. |
| **Terminal Tasks v1.0** | held-out configurations and expected values — `go-netscan`'s 25 hidden grids, `financial-reconciliation`'s expected CSV | **Yes.** The verifier *is* the answer key. Vetto says as much: publishing a held-out task burns it, which is why the three samples were retired first. |

This is the same line cairn's own `docs/verification.md` draws when it says the
network can only work on tasks whose outputs are cheap to check. ProgramBench
sits on the good side of it by construction, and for a reason that is worth
naming because it is not luck: reconstruction from a runnable artifact is an
*NP-shaped* task. The oracle is cheap, public, and useless as a hint.

**Consequence.** ProgramBench Vetted can run open on cairn today, held-out
tasks and all — because "held out" there means *which 50 binaries*, not *what
the grader knows*. Terminal Tasks cannot, and no amount of protocol work fixes
that; only retirement does.

---

## 3. The mapping

| Vetto | cairn | note |
|---|---|---|
| a benchmark (ProgramBench Vetted) | `Objective.goal`, one string across the set | free-form; put `programbench-vetted-v1` in verbatim |
| one held-out task | one `Objective` | 50 objectives under one goal |
| deterministic behavioural grading | `verifier.kind: evaluator` | pinned `score(artifact) -> int`, run under seatbelt/bubblewrap, deny-by-default, no network |
| fractional test score | basis points, `0..10000` | **integers only.** IEEE-754 does not reproduce bitwise across hosts, so a float score can compare differently on two honest nodes |
| `resolved` (100%) | `score == 10000` | a reading of the recorded score, not the accept bit |
| `almost` (≥ 95%) | `score >= 9500` | likewise |
| `mean reward` | mean of recorded scores | recorded on **rejects too**, so partial credit survives in the log |
| partial credit for RL | `ratchet` | progressive bounty; pays for distance moved, so publishing an improvement beats hoarding it |
| pass@1 over 5 trials | 5 claims, one per trial | cairn verifies artifacts, never rollouts |
| bootstrap 95% CI | `verifier.kind: statistical` | pinned statistic **and pinned seed**, scaled to parts-per-million; a seed the submitter picks is a seed the submitter grinds |
| Terminal Tasks binary reward | `evaluator`, threshold `10000` | but see §4 — the verifier cannot be published while the task is live |
| container + pytest verifier | **nothing today** | `evaluator` runs one pinned `.py`. See §5, blocker 1 |
| peak-RSS caps, latency SLAs | **refused, on purpose** | `TIME_LIKE` denies time, seconds, latency, throughput, memory, flops. See §5, blocker 2 |
| provider safety filter | `UNAVAILABLE`, never `REJECT` | see §5, blocker 3 |
| model + harness label | **nothing.** See §4 | |

---

## 4. What the log cannot say

cairn pays for artifacts and never for effort, provenance, or who ran what.
`docs/verification.md` lists contributed inference (TOPLOC and friends) under
*verifiers not implemented here*. The consequence for a leaderboard is sharp
enough that it should be decided before any engineering starts:

> **The grading is distributable. The attribution is not.**

A settled claim proves *this artifact scores 9900 against this pinned grader*.
It cannot prove the artifact came from Claude Opus 5 at high effort under
Terminus-2, or from a model at all. On an open network where anyone may
submit, the model label is worth exactly the signature behind it — and the
board is the part of the product that is entirely made of model labels.

Three options, and only the third is honest at Stage 0:

1. **Crowdsource the board.** Dead on arrival. Nothing distinguishes a Devstral
   run from a human with a debugger, and money makes someone try.
2. **Attest provenance in-protocol.** Needs trusted execution or activation
   fingerprinting at the provider. Not available, and it would move the trust to
   the provider rather than removing it.
3. **Split the two claims, and say which is which.** Verified: the score.
   Attested: the configuration that produced it. Vetto signs every claim
   (`require_signed_submitter: true`, where the submitter *is* an ed25519 public
   key), so a wrong label is a signed statement that can be caught and punished
   rather than a number nobody can check. Falsifiability, not proof.

The pilot's `tools/board.py` prints that distinction under every board it
derives, because a board that quietly implies more than it verified is the
failure mode this whole exercise exists to remove.

---

## 5. Blockers, in the order they bite

**1. Container-graded tasks have no verifier kind.** `evaluator` runs a single
pinned Python file against a JSON artifact. A Terminal Tasks verifier rebuilds
a repository, runs the agent's own suite, and invokes a binary on held-out
configurations, in a container the agent never sees. The closest existing shape
is `replay` — pinned image digest, pinned command, `reproducible_fields` — and
it would need: an OCI digest pin alongside the source pin, a hermetic
(network-off) verify path, and blob distribution for images that are gigabytes
rather than kilobytes. `shard` erasure-codes large blobs already, so the
transport is not the hard part; the verifier kind is. **This is the single
largest piece of new protocol work, and nothing on the ProgramBench path needs
it.**

**2. Roughly 21 Terminal Tasks tasks are unsettleable as written.** The set
deliberately includes production-style constraints — bounded memory,
out-of-core processing, latency SLAs — and grades a correct-but-resource-blind
solution as a failure. Peak RSS and latency are properties of the host, so two
honest nodes disagree about them by construction, and cairn refuses to let one
back a settlement. This is not an incompatibility to route around: Vetto's own
defect taxonomy already lists *absolute timing gates that tie the reward to host
hardware* as a defect. The fix is the one `examples/faster-algorithms` makes —
**count, never time**: re-denominate into allocations, bytes moved, or
instructions retired under a pinned model. A hash-under-a-peak-RSS-cap check
becomes a hash-under-an-allocation-cap check, or it stays off the log.

**3. A provider refusal is an infrastructure fact.** 1.4% of Terminal Tasks
trials hit a safety filter. Vetto counts a terminal filter as a failure, which
is a defensible *measurement* choice, and cairn must not learn it: collapsing
"the provider refused" into `REJECT` makes taking a provider offline an attack
on every honest submission. Filters map to `UNAVAILABLE`, which settles
nothing, and the count-it-as-failure rule is applied by the board **above** the
ledger, where it is visible and reversible.

**4. Public objectives leak solutions.** Once a ProgramBench objective settles,
its artifact is public and anyone can resubmit it. cairn already handles both
halves — commit–reveal stops a watcher front-running a reveal, and a duplicate
artifact verifies and mints zero — but the board must not count a copy as a
second independent solve. Dedupe by artifact digest before aggregating.

**5. Self-dealing is the default failure, not an edge case.** Vetto would fund
objectives built from tasks Vetto authored and has already solved. cairn's
`examples/certicom-ecdlp` found exactly this in its own `examples/ecdlp/`, and
the fix is adopted wholesale: instances derived from a public seed by a pinned
rule the checker re-derives, and any instance whose answer is published retired
to a test vector rather than left standing as an objective.

**6. Trajectories are not artifacts.** The explorer's per-step reasoning is the
product's most distinctive asset and it is unverifiable prose. It goes in the
log as `relations`-style commentary that carries no money, or it stays off the
log. It must not become something a settlement depends on.

---

## 6. Five invariants that must survive the bridge

Each is already true on one side. Each has a specific way of being lost in the
crossing, so each gets a check in whatever validator ships with the bridge.

**(a) A verified score is evidence, never a rank.** Ordering, effort tiers, and
harness pairing are editorial. *Check:* no published rank may cite a claim id
as its sole basis without also naming the attestation behind the label.

**(b) `UNAVAILABLE` is never negative evidence.** Same sentence in both
projects, and the bridge is where a `status != accept` branch written in a
hurry collapses them. *Check:* no `unavailable` verdict may enter any
denominator.

**(c) Scores are integers, everywhere.** A float cannot enter a record at all,
so the failure mode is not a wrong number — it is a rejected record at the
worst moment. *Check:* every grader returns `int`, and every published
percentage is a rendering of basis points.

**(d) The grader is inside the id.** A verifier fix mid-season forks the
objective and the old results stand against the old id. That is correct and it
is also operationally surprising. *Check:* a board may aggregate only claims
against a single objective id per task, and a re-verified season is a new goal.

**(e) The calibration set is not the graded set.** Vetto's own finding — the
GPT-calibrated subset is 14.8 points harder for everyone — is a composition
fact that survives publication. *Check:* subset composition is pinned in the
goal's statement, so a board cannot be recomposed after the fact.

---

## 7. Staging

**Stage 0 — one task, public, end to end.** Already done; it is the pilot in
this directory. Proves the plumbing: a pinned evaluator, integer basis points,
partial credit through a ratchet, three screened escape hatches, a settled log
that audits, and a board derived from the log by a stranger's script.

**Stage 1 — ProgramBench Vetted, open.** 50 objectives under one goal, one per
held-out program, evaluators published as blobs. Vetto signs every claim, so
the board's labels are attested by a named key. Buys: the whole leaderboard
becomes re-derivable, and the second implementation in `reference/` re-derives
it independently. Costs: 50 evaluators to author with escape hatches
enumerated, which is the real work and cannot be automated.

**Stage 2 — Terminal Tasks, retired tasks only.** Every task retired from the
live set becomes a permanent public objective instead of a blog post. The log
then dates the burn: the objective id is the moment those tests became public,
which is a contamination record nobody has to be trusted to keep. Needs blocker
1 solved.

**Stage 3 — live sets, commitment only.** Post the objective at freeze time
with the verifier pinned by hash but the blob withheld. Strangers get
`UNAVAILABLE` and the objective stays open; only Vetto's node can settle it.
That window is one-operator trust and must be labelled as such — what it buys
is that at release, anyone can check the revealed verifier hashes to the pin,
so a grader cannot be edited after the results are in. Pre-registration now,
re-derivation later.

---

## 8. What I could not settle

- Whether a container-graded verifier is cheap enough for Stage 0's rule that
  every node can re-run every check. A 1 CPU / 2 GB container plus pytest is
  minutes, comparable to Lean, so probably yes — but the image distribution
  cost is real and unmeasured here.
- Whether 5 trials per configuration is enough for a *bonded* dispute to be
  worth opening. The arena's numbers are about attacks on settlement, not about
  statistical claims over rollouts.
- Whether embedding an emulator of the reference binary should score as a
  resolve. Behavioural grading cannot tell the difference from outputs alone;
  the pilot screens it by reading the source, and that is a judgement call
  ProgramBench has to make explicitly rather than inherit from a screening
  heuristic.

---

## 9. The pilot

From the repository root:

```sh
./examples/programbench-vetted/scripts/pilot.sh
```

One ProgramBench-shaped task, end to end, against the real `cairn` binary:

- `evaluators/programbench_pilot.py` — the grader. Carries the reference as a
  flat opcode list for the stack machine it also implements: the "runnable
  binary". Scores basis points over 200 cases derived from a pinned seed.
  Screens the three escape hatches, and scores rather than raising on all of
  them.
- `objectives/objective-pb-pilot-0001.json` — the objective, with the evaluator's SHA-256
  inside its id, plus a ratchet from baseline 100 to target 10000.
- `artifacts/` — a correct reconstruction, a near miss, a wrong-but-honest
  attempt, a submission that ships the emulator, and one that never returns.
- `tools/board.py` — derives the board from the exported log and nothing else.
- `tools/assemble.py --check` — re-derives the pinned machine code from its
  listing.

Last run:

```
  opus-5       accept: score 10000    devstral-2   reject: score 0 (never returns)
  sol-5.6      accept: score  9900    glimmer-30b  reject: score 0 (ships the emulator)
  sonnet-5     accept: score  4700

  #  submitter         mean   almost  resolved   n
  1  opus-5          100.0%   100.0%    100.0%   1
  2  sol-5.6          99.0%   100.0%      0.0%   1
  3  sonnet-5         47.0%     0.0%      0.0%   1
  4  glimmer-30b       0.0%     0.0%      0.0%   1
  5  devstral-2        0.0%     0.0%      0.0%   1

  log verified: chain intact, every settled claim re-verified
```

The submitter names are stand-ins for model+harness configurations and they
are exactly as trustworthy as §4 says: identities, not provenance.
