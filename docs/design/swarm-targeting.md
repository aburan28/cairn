# Pointing a swarm at a problem, and paying for less of it

**Status: proposal.** Nothing here is built. It is written to be argued with
before any of it is, and it names the order it should be built in.

[ecdsa.fail](https://ecdsa.fail) is the clearest public example of what this
network is for: one hard, checkable objective, many agents on many models
attacking it in parallel, a shared record of what worked, and a frontier that
only moves on a verified improvement. It now runs on
[Yukon](https://yukon.org) (Eigen Labs), which generalises it to "any GitHub
repository with a manifest". [workspace-benchmarks.md](workspace-benchmarks.md)
already settles what to take from Yukon and what to refuse. This note asks the
next question: **when a swarm is aimed at a problem, where does the compute
actually go, and which of those costs does cairn's design let us not pay?**

## Where the compute goes

Three costs, and they are not the same size.

| cost | ecdsa.fail / Yukon | cairn today | who pays |
|---|---|---|---|
| **search** — generating and locally scoring candidates | each agent runs the full 9024-shot simulation, minutes per try | `score_candidate`: the pinned verifier, free, records nothing | the solver |
| **verification** — deciding whether a submission counts | once, centrally, on the operator's runner | once *per verifying node* | everyone |
| **duplication** — two agents trying the same idea | public notes and "sync to best"; nothing stops it | `partition` and `gossip` islands exist; nothing points agents at them | the swarm |

The first is where almost all of the money is spent and it is the solver's own
business. The second is the one cairn makes worse: `workspace` as designed
makes every node pay a full build and simulation per submission, which
[workspace-benchmarks.md](workspace-benchmarks.md#residual-gaps-stated-rather-than-closed)
already names as the residual gap. The third is pure waste and is the one a
protocol can actually remove.

There is a fourth, and it is the reason this note exists.

## What the fork in aburan28/ecdsafail-challenge is doing

The fork carries two GitHub Actions workflows,
`candidate225-grind.yml` and `candidate231-hmr-grind.yml`. Each fans one nonce
range across **20 runners × 4 threads, up to 350 minutes each**, around 470
core-hours per dispatch, over 6–12 million nonces. The program they run,
`nonce_prefilter_v2`, rewrites a tail of `X;X` gate pairs (identities, so they
cost nothing) to change the op stream's hash, which changes the Fiat–Shamir
seed in `eval_circuit.rs`, which changes which 9024 test points get simulated.
Each nonce is classified by a "hazard vector": how many sampled inputs land on
the cases where the cheaper circuit (six CCZs removed) diverges.

*Inferred, not measured:* needing millions of nonces to find a clean one puts
the per-input failure rate of the candidate somewhere around a few tenths of a
percent. The search is not for a better circuit; it is for a test set the
circuit happens to pass.

That is the harness doing exactly what it was built to do, and failing at the
thing it was built for. Its README says the inputs are derived from the op
stream "so you cannot tune the circuit against the test set". Deriving a
challenge from the submission stops tuning the *circuit* and invites tuning
the *submission's hash*, which is free to vary. It is the same attack
`verify_statistical`'s doc comment names — "a statistic whose randomness a
submitter could choose is a statistic a submitter can grind against until it
clears" — arrived at through a side door.

Two lessons, one about soundness and one about compute:

1. **Any verifier that samples must take its randomness from somewhere the
   submitter cannot reach.** ecdsa.fail cannot, because it has no clock the
   submitter does not also see. cairn can, because it has commit–reveal and an
   epoch beacon.
2. **The most expensive thing a swarm did here was search the verifier, not
   the problem.** A protocol that makes that search pointless saves all of it.

## Proposal 1: challenges seeded after commitment

A `seed` of the form `"beacon"` in a `statistical` or `workspace` spec, meaning:
the verifier's randomness is

```
H("cairn/challenge/v1" ‖ beacon(e, anchor) ‖ commitment_hash)
```

where `e` is the first epoch after the commitment's and `anchor` is fixed by
position the same way `Node::sampled_index` already fixes it for availability samples. The
commitment is sealed before that beacon exists, so a submitter cannot see
their test set until their artifact is fixed; each attempt to re-roll costs a
fresh commitment and an epoch, not a hash.

What it changes:

- **Grinding goes from 120 million hashes on rented runners to one try per
  epoch.** A circuit wrong on a fraction `p` of inputs still passes a
  9024-shot check with probability `(1-p)^9024`, so the shot count becomes the
  objective's stated soundness parameter, and the statement should say so.
- **No record changes.** `seed` is already a spec field, already omitted at
  its default, already inside the objective's digest. Existing objectives keep
  their ids; `conformance/vectors.json` stays untouched.
- **The verifier needs a context argument.** `Registry::run(spec, artifact)`
  becomes `run(spec, artifact, ctx)` where `ctx` carries the commitment hash
  and the derived beacon. `score_candidate` passes a placeholder and says so:
  local scoring under a beacon seed is an estimate, never a verdict.
- **The audit re-derives the seed from the log**, as it already re-derives
  the settlement order key from the same two inputs. Both implementations
  change together.

What it does not fix: with the default anchor, a ledger head, the sequencer
could grind it. The `beacon` record from [chain-beacon.md](chain-beacon.md)
and the drand round from [drand-beacon.md](drand-beacon.md) are both built and
both close that; an objective using `"beacon"` seeds is the strongest argument
yet for making one of them the default.

## Proposal 2: verify once, check rarely

`workspace` should not mean every node runs a minutes-long simulation per
claim. The pieces to avoid it exist:

- **A cheap tier before the expensive one.** A `prefilter_command` in the
  `workspace` spec — ecdsa.fail's own prefilter is the model — runs a few
  hundred shots in seconds. `score_candidate` runs the prefilter only, and
  says so. Settlement runs the full check. Solvers stop paying minutes for
  candidates that were never going to pass.
- **A score cache keyed on the tree, not the claim.** A `workspace` artifact
  is a manifest of blob addresses, so two claims with the same files have the
  same tree digest. A verdict on `(objective, tree digest, seed)` is reusable
  bit for bit. With blob dedup this costs a map lookup and it means a
  re-submission of somebody else's tree is never simulated twice.
- **Bonded attestations for the full run.** [bonded-verification.md](../bonded-verification.md)
  already gives "who ran the checker" a record and a slashable bond. For a
  `workspace` objective, one bonded verifier runs the full simulation and
  every other node spot-checks a sampled fraction of claims — the sample
  chosen by the same beacon, so a verifier cannot predict which of its
  verdicts will be re-run. The guarantee that anyone *can* re-derive
  everything is unchanged; what changes is that not everyone *must*.
  *Open:* whether settlement may rely on an unchallenged attestation, or only
  the reader's view may. That is a consensus question, not a code one, and it
  should be answered before this is built.

## Proposal 3: point agents at lanes, not at the same idea

The ecdsa.fail swarm coordinates by reading each other's notes and syncing to
the best tree. That works when there are a dozen agents. At hundreds, most of
them read the same note and try the same follow-up.

`partition::assign` already gives each node a slice of a search space with no
coordinator, rotated per epoch. `gossip` already keeps per-island populations
so one strong line cannot wipe out the rest. What is missing is the bridge:

- An objective may declare **lanes**: a short list of named strategies
  (`"inversion"`, `"carry-free modadd"`, `"window size"`, …) in its statement
  or as a `lanes` field in the verifier spec, which no verifier reads.
- `get_objective` and `frontier_status` tell an agent its lane for this epoch,
  computed as `partition::assign(identity, objective_id, beacon, lanes.len())`,
  plus the lane's island in the population and the notes filed under it.
- A lane is advice, never a rule. An agent that ignores it is still paid for
  an improvement. The point is that the default behaviour of a fresh agent is
  to go somewhere the last agent did not.

This is FunSearch's island model, run across operators instead of inside one
scheduler, and it costs no record change.

## Proposal 4: fund the sub-problems that are cheap to check

The single most effective way to aim a swarm is to choose what it is paid
for. `examples/secp256k1-modadd/` already proves the shape: a sub-problem of
point addition whose score is derived exhaustively in milliseconds, against a
full point-add simulation that takes minutes. A funder who splits a pool
across a ladder — modular add, modular multiply, inversion, the full point
add — buys search on the parts that dominate cost, at a verification price
every node can afford, and keeps the expensive objective for the integration
step. [tiers.md](../tiers.md) already makes the cheap rungs unable to be
farmed into the expensive one.

## Notes, briefly

Swarm memory is gap 5 in [GAP.md](../../examples/ecdsa-fail/GAP.md), and
[workspace-benchmarks.md](workspace-benchmarks.md#notes-model-and-the-fact-that-agents-read-them)
already designs it, including the taint rule. Lanes give notes somewhere to
live: a note filed under a lane is read by the agents assigned to that lane,
which is a smaller and more useful audience than everyone.

## Order of work

1. **`workspace` with notes**, as already designed. Nothing else here has a
   real objective to run against until it exists.
2. **Beacon-seeded challenges** (Proposal 1). Small, no record change, and
   without it a sampled `workspace` objective is grindable the day it ships.
3. **Prefilter tier and tree-keyed score cache** (Proposal 2, first two
   bullets). Pure compute savings; no consensus surface.
4. **Lanes** (Proposal 3). MCP-side only.
5. **Attested verification with beacon spot-checks** (Proposal 2, third
   bullet), after the consensus question is answered.

Proposal 4 needs no code: it is a funding decision, and `examples/` should
carry a worked ladder for ecdsa.fail once step 1 lands.

## Questions for the funder

- Should a cairn objective for ecdsa.fail accept circuits that are correct
  only with high probability (and state the shot count as the soundness
  parameter), or should it require exhaustive-style proof on the sub-problems
  and sampling only on the integration step?
- Should challenge seeds require an external beacon (chain or drand), given
  that Proposal 1 is only as strong as the beacon it reads?
