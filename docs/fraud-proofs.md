# Interactive fraud proofs

*How a disputed computation gets settled by executing one step instead of all of
them.*

Implemented in [`src/challenge.rs`](../src/challenge.rs) and
[`src/challenge/stepper.rs`](../src/challenge/stepper.rs). Every number below is
produced by a test in `src/challenge/tests.rs`; none of them is an estimate.

## The problem

A `replay` objective pins a command, and the only way to check a claim about it
is to run the command. That is honest, and it does not scale. If every node
re-runs every computation, the network's verification bill is the work
multiplied by the node count, and `design::decomposition_floor` says exactly
when that stops paying: at full redundancy across 100 nodes, an objective must
settle for more than **800,000** to cover the verification it asks for.

Sampling helps — 24,000 at 3-fold redundancy — but sampling is what
[node-incentives.md](node-incentives.md) then has to spend a whole mechanism
defending, because a node that is only sometimes checked is a node that is
sometimes not.

Interactive fraud proofs attack a different term. Instead of reducing how *often*
somebody checks, they reduce how *much* a check costs when there is an actual
disagreement.

## The shape

```text
  defender    s0  s1  s2  s3  s4  s5  s6  s7  s8      root_d
  challenger  s0  s1  s2  s3  X4  X5  X6  X7  X8      root_c
                           ^^^^ first divergence

  round 1   both open state 4   differ  ->  [0, 4]
  round 2   both open state 2   agree   ->  [2, 4]
  round 3   both open state 3   agree   ->  [3, 4]
            one step wide: agreed on s3, disagreed on s4

  adjudicate: run ONE step from s3. Whichever s4 it produces, wins.
```

Both parties commit to a Merkle root over their whole trace *before* the search
starts. Every move opens one state against the mover's own root, so a party
losing the search cannot answer with whatever state wins the current round —
which is the attack that would otherwise make the whole thing worthless.

## What it costs

| | full re-verification | bisection |
|---|---|---|
| steps executed to settle a dispute | `n` | **1** |
| parties who must execute | everyone | one adjudicator |
| records exchanged | 0 | `2·⌈log₂ n⌉` |

Measured on a 256-state trace with the shipped Collatz stepper:

```
8 rounds of search in 7.7ms, one step of adjudication in 31ms,
full replay in 8.10s
```

258×, and the ratio grows linearly with trace length because adjudication is
flat. A million-state trace is 20 rounds; the module's 2²⁴-state cap is 24
rounds, or 48 records — which is what makes a dispute something an append-only
log can actually carry.

## What it does *not* buy

It does not remove execution. Somebody still runs pinned code, and that node is
trusted exactly as much as a node running a `certificate` verifier today — no
more, no less. What changes is the quantity and the number of parties. Claiming
a trust improvement here would be false.

It also does not work on every objective. See below.

## The stepper, and why bisectability is a property of the objective

A command has an input and an output and nothing in between that two parties can
point at. To bisect, the computation must be broken into steps *both parties can
name*, and only the objective's author can say what a step is. So a `stepper`
block in the verifier spec is what declares an objective bisectable:

```json
"stepper": {
  "code": "examples/collatz_bisectable/steppers/trajectory.py",
  "code_sha256": "b374839a…",
  "entrypoint": "step"
}
```

Pinned by hash, run in the same jail as every other piece of objective-authored
code, through the same spawn path — hash checked before the subprocess exists,
scrubbed environment, memory cap, wall-clock bound. A second, laxer route to
executing a stranger's code would be the weakest one an attacker has to find.

Collatz is the honest example rather than a flattering one: `n ↦ n/2 or 3n+1` is
already a step function, so nothing had to be invented to make it bisectable. An
objective whose computation has no natural step is not made bisectable by
writing a stepper for it. It stays on full re-verification.

### Three obligations a stepper carries

Each one is a real failure mode, and each is tested against the shipped example.

1. **Deterministic.** No clock, no randomness, no environment. A state two
   honest machines disagree about cannot adjudicate anything, so a stepper with
   a nondeterministic step makes its objective *look* bisectable while being
   unbisectable — worse than not having one.
2. **Total.** Every input state maps to some output state, malformed ones
   included. A stepper that raises hands the adjudicator an `unavailable`, and a
   dispute that cannot be adjudicated is precisely what a liar wants. So a bad
   state steps to a `halted` state carrying the reason, and the party who
   committed to it loses on comparison like anyone else.
3. **Canonically representable.** Integers, never floats. `n // 2` and not
   `n / 2`. The digest of a state nobody can agree on is the digest of nothing.

## Two preconditions, both found by a failing test

The first version of the game assumed its own invariant — agreed at the bottom
of the interval, disagreed at the top — rather than establishing it. Two
disputes could not be settled as a result, and neither was visible by reading
the code:

- **A lie in the very first step.** The interval's lower bound never moves off
  zero, and adjudication needs the *state* at the lower bound to step from.
  Nobody ever opened state 0, so there was nothing to run.
- **Two traces that diverge and rejoin.** Their final states are equal, so the
  upper bound is not a disagreement at all, and the search terminates on an
  interval whose endpoints both agree. That dispute has no answer — and refusing
  it is correct rather than a limitation, because a challenger who reaches the
  same result by another route has contradicted nothing the claim asserts.

So a dispute now opens with four moves — both parties' first state, which must
match, and both parties' last, which must differ — and the invariant is
witnessed instead of assumed. `a_dispute_is_only_well_founded_when_its_endpoints_are`
pins both.

## Adjudication when both sides are wrong

If the step reproduces neither party's state, **the challenger wins**. The
alternative — awarding it to the defender because the challenger is also wrong —
would make a false claim safe as long as nobody could produce a perfectly
correct refutation, and producing a correct refutation is a much harder thing
than producing a correct *objection*. A challenge asserts one thing: that the
defence does not reproduce. If it does not, the challenge was right.

## Silence

A liar's dominant strategy against any interactive protocol is to play until the
search reaches the step where they lied, and then stop. So the side that owes a
move and does not make it loses, and `Next::Open` names who owes it, which makes
the debt attributable rather than a matter of opinion.

Whether *enough time has passed* is an epoch question, and epochs come from
records — so the window belongs to `node`, not here. `challenge.rs` encodes only
what silence means.

## Status

Built: the game, the trace commitment, the stepper, the adjudication, and a
worked example (`examples/collatz_bisectable/`).

Also built: **the bond**. `records::Challenge` stakes units behind an objection
and `records::BisectionMove` carries one answer; `Node::post_challenge` and
`Node::post_bisection` admit them; `Node::dispute` folds the game back out of
the log; `Node::settle_challenge` decides it and moves the money. The
challenger's bond is committed the moment the objection is, so one balance
cannot fund two simultaneous objections, and `reference/rust` accounts for both
sides of a slash — otherwise it would report the winner as overdrawn and certify
the loser as solvent. `scripts/dispute-demo.sh` runs the whole thing through the
CLI and hands the finished log to the reference.

What the parties risk is asymmetric, and the asymmetry is stated rather than
hidden. A challenger stakes a bond. A defender stakes the payout for the claim
under dispute, **capped at what they still hold** — so a defender who spends the
reward before the window shuts keeps the difference. Closing that means holding
a bisectable claim's payout until its window closes, which is a change to the
settlement path in both implementations and is the same missing piece as bonded
availability custody.

Two other limits worth naming. `CHALLENGE_WINDOW_EPOCHS` is a constant and not
an environment variable, for the reason `EPOCH_SECONDS` is: a rule that depends
on a process's environment is not a consensus rule, and two auditors reading one
log would disagree about who forfeited. And the reference implementation checks
everything the transcript decides on its own — who may object, to what, by when,
with what staked, and that every move opens the root its author committed to —
but it has no stepper, so whether the disputed *step* reproduces is checked by
the primary's `audit --rerun` alone.
