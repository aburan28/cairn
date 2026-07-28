# Consensus

What the validators are actually for — which is much narrower than it looks, and
narrower in a way that should change what you build.

## Validators do not vote on truth

The instinct is that validators check results and agree on which are correct.
That is not what happens here, and building as if it were produces a system that
is both slower and weaker than necessary.

For a pure, pinned verifier, **correctness is not a consensus question**. Anyone
can re-run the checker and get the same answer; a validator that says otherwise
is simply wrong, detectably, by anyone who bothers to look. There is nothing to
agree on. A cap set either has three collinear points or it does not, and a
million validators voting cannot change it.

What genuinely requires agreement is narrower:

1. **Order.** Who advanced the frontier first. Payment depends on it, and two
   honest nodes with different message-arrival orders will disagree.
2. **Inclusion and availability.** Was this submission published at all, or
   withheld? Unlike correctness, absence is not locally checkable — you cannot
   distinguish "nobody submitted" from "the sequencer dropped it."
3. **Non-deterministic verdicts.** Which this design eliminates by requiring
   verifiers to be pure, refusing float scores, and refusing machine-dependent
   replay fields. Removing this category is a consensus-design decision as much
   as a correctness one.

So: **consensus over ordering and data availability, not over state validity.**
A chain that gets the order wrong misallocates a payment. A chain that gets
*truth* wrong is not really possible here, because every reader re-derives it.
That is a far weaker requirement than a general smart-contract platform carries,
and it should be spent on something.

## Spend it on censorship resistance

The dangerous attack is not a forged result — it is a suppressed one. Withhold a
competitor's reveal until after your own, or past a deadline, and you take a
bounty you did not earn. **Liveness is money here.** Safety violations are
detectable and correctable after the fact; a censored submission is
indistinguishable from a submission that never happened, and the loss is
permanent.

That inverts the usual priority ordering. Throughput barely matters (see the
latency budget in [coordination.md](coordination.md) — frontier advances are
minutes apart). Sub-second finality barely matters. **Forced inclusion matters
enormously**, and it is the property most chains treat as an afterthought.

Design consequences:

- Every submission path needs an escape hatch that does not route through the
  sequencer.
- Deadlines must be measured in a way that a censoring sequencer cannot
  manipulate — block height on a chain it does not control, not its own clock.
- A reveal that misses its deadline because of censorship must be recoverable,
  which means the *commitment* has to be independently timestamped. This is the
  strongest argument for anchoring commitments externally.

## Do not write a consensus protocol

Two reasons, and the second is the one that kills projects.

**The requirement is over-served by what exists.** Ordering plus data
availability plus forced inclusion is what every BFT chain and every rollup
already provides. There is no property in the list above that motivates a new
protocol, and a novel consensus protocol is a multi-year effort with a long tail
of subtle liveness bugs — spent to buy nothing this application needs.

**Bootstrap circularity.** A proof-of-stake chain's security is proportional to
the value of its stake. The stake's value derives from settled research. Settled
research needs the chain. There is no ordering of those three that starts. The
usual outcome is a chain secured by almost nothing during precisely the window
when attacking it is cheapest and most profitable — and the failure is not
gradual, because an attacker who can reorder can take every bounty in flight.

You cannot design your way out of this. You can only avoid needing to solve it.

### The recommendation: rollup, not L1

Post commitments and settlement roots to an established chain. Run the sequencer
yourself. Add fraud proofs over the state transition, and forced inclusion via
the base layer.

- Security is inherited rather than bootstrapped, so the circularity never
  arises.
- Forced inclusion via the base layer delivers the primary security property
  directly, rather than as a secondary consideration.
- The state transition is *already* the deterministic function in
  `proofwork/node.py`, and `audit()` is already the re-derivation a fraud proof
  needs. That is not a coincidence — it is why Stage 0 was built as a pure
  function over an append-only log.
- No validator recruitment, no token needed for security, no new protocol.

At Stage 0 the "sequencer" is one operator and a JSONL file. The upgrade path to
a rollup does not require rewriting any of the logic above it, only replacing
where the log is anchored.

## Where original protocol work *is* needed

None of these are consensus protocols. All of them are application protocols
that sit on top of settlement, which is the right place for the hard parts.

**Verification committees for expensive checks.** V0 and evaluator objectives
are checkable by everyone, so no committee is needed. V2 replay and V3
statistical validation are not: someone has to spend real compute, and the rest
of the network has to accept their word or spend it too. Sample a committee per
claim by VRF, bond them, and resolve disputes by bisecting the execution trace
down to a single step the base layer can adjudicate cheaply — the run manifest
already pins command, seed, and environment, which is exactly what makes a trace
bisectable.

**Epoch-batched commit–reveal.** Commits in epoch N, reveals in epoch N+1, order
within the epoch fixed by the beacon rather than arrival time. Kills in-flight
front-running and removes the sequencer's ability to reorder for profit.

**A real randomness beacon.** `partition.py` currently derives its beacon from
ledger heads and admits in its own docstring that a sequencer free to choose
that value could grind it. A VDF or threshold signature is required before the
sequencer is untrusted.

## The verifier's dilemma, and why it is mild here

When verification is expensive, rational validators stop verifying and
rubber-stamp — and a rubber-stamp validator set is worse than none, because it
looks like one. The standard defences are canary claims (known-invalid
submissions, slashing anyone who approves them), bonded challenge windows, and
fraud proofs.

But notice the structural point: **for the work shapes this network is designed
around, verification costs about one evaluation.** Every validator simply checks,
because checking is cheaper than the bookkeeping required to skip it safely.
Cheap verification is not only an economic property — it is what keeps the
consensus problem trivial.

That is the strongest argument for the constraint the whole system is built on.
Keeping work in the cheap-verification shapes is not merely a matter of cost. It
is what lets you avoid designing an incentive-compatible verification game at
all, and every objective that drifts out of those shapes drags one back in.

## If you must run your own validator set

- Proof of stake. Not proof of research work — that fails for the reasons in
  [economics.md](economics.md): research work is not difficulty-tunable, not
  precomputation-resistant, and not progress-free.
- Be honest about what stake distinctness buys. Distinct stake is not distinct
  operators, and distinct operators are not independent judgement. An operator
  running one backend behind three keys collects three rewards for one
  correlated opinion, and no amount of on-chain data reveals it.
- TEE attestation can bind execution to an identity. That is a trust assumption
  about a hardware vendor, not a proof, and it belongs in the record as one.
- Concentration caps and slashing are mitigations, never prevention.

## Summary

| question | answer |
|---|---|
| Do validators decide correctness? | No. It is locally checkable by anyone. |
| What needs agreement? | Order, and data availability. |
| Most important property? | Censorship resistance. Liveness is money. |
| Fastest finality needed? | Seconds. Frontier advances are minutes apart. |
| Build a new consensus protocol? | No. |
| Run an L1? | No — rollup on an established chain. |
| Where is the real protocol work? | Verification committees, epoch-batched reveal, randomness beacon. |
| What keeps this tractable? | Verification costing one evaluation. |
