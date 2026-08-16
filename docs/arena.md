# The adversarial arena

*Strategies played for money against the real rules engine.*

```sh
cargo run --release --bin arena          # every scenario, seed 1
cargo run --release --bin arena -- --seed 7
```

Implemented in [`src/arena.rs`](../src/arena.rs) and
[`src/arena/scenarios.rs`](../src/arena/scenarios.rs); the verdicts are pinned
in `tests/arena.rs`.

## What this is, against two things it is not

| | what it varies | what it holds fixed | what it proves |
|---|---|---|---|
| `src/incentive/` | strategies, exactly | **the rules are a model** | honest play is an equilibrium *of that model* |
| `tests/simulation.rs` | network timing, seeded | strategies are honest | nodes converge on what settled |
| **`src/arena/`** | strategies, against the real `Node` | timing is simple | whether an attack **pays**, in settled units |

[proving-it.md](proving-it.md) names the gap between the first row and the third
as the largest hole in the whole argument: *"`src/incentive/` is not a code
path"*, so a passing report reads **if** the network implemented this mechanism,
honest play would be an equilibrium of **a model of it**. Both conditionals are
load-bearing. The arena removes the second one for the attacks it covers.

Every action goes through `post_objective`, `commit`, `reveal`,
`post_challenge`, `post_undertaking`, `post_availability` and `settle_due`, and
the payoff is read out of the balances a real node settled.

## The discipline that makes it evidence

**The arena never grants a strategy anything the rules would refuse.** An attack
the admission rules reject is *reported as rejected* — "the mechanism refused
it" is the strongest possible result, and forcing it through to make the
simulation interesting would invert the finding.

**Every attack is run twice**, with the defence and without. A lone number has
no scale attached; the pair is a measurement of the defence.

**One modelled quantity.** What it costs an operator to run a checker is an
off-log fact about their machine, so `Costs` carries it and nothing else is
modelled. Where a result depends on it, the result says so.

## The verdicts, and why there are six

A boolean would have been dishonest. Four of these say the mechanism held, by
different routes; two say something is missing — including from the *scenario*.

| verdict | meaning |
|---|---|
| `CLOSED` | the defence turned a profitable attack into a losing one |
| `NEUTRAL` | the attacker earns no more than an honest player with the same resources — the incentive is *removed*, not priced |
| `REFUSED` | every attacking action was declined at admission; the attack has no representable form |
| `PROTECTED` | the attack costs the attacker and leaves its victim better off |
| `OPEN` | the attack pays even with the defence in place |
| `INERT` | the attack lost money undefended too, so the run measures nothing |

`INERT` is the one that keeps the file honest. Three of the first five scenarios
written here returned it, which correctly said *the scenario failed to set
itself up* rather than *the defence works*.

## What it currently reports

At seed 1, with default costs:

| attack | verdict |
|---|---|
| sybil identity splitting | **NEUTRAL** — 5,952 across eight keys where one key earns 5,994; a head-counted pool would have paid 10,608 |
| availability free-riding | **NEUTRAL** — a node that stored nothing earns 0; one that stored earns 11,994 |
| standing bought on the cheapest tier | **CLOSED** — 5,000 untyped, 0 spendable where expensive work is priced |
| griefing bonded disputes | **PROTECTED** — the griefer forfeits 6,000 and the submitter it stalled ends 9,000 up instead of 3,000 |
| griefing a plain objective | **REFUSED** — an objective with no stepper cannot be disputed at all |
| rubber-stamping | **CLOSED** — 8,000 undefended against −92,000 defended |

No attack in this set is profitable against its defence.

### The one that used to be open

This file previously reported rubber-stamping as **OPEN**, and
`tests/arena.rs` asserted it *stayed* open — with a note saying the test should
start failing when a verification bond landed. It did.

The docket had always known *which* verdicts were wrong; what it could not do
was name a party, because a Stage-0 log has one writer and no record said who
ran the checker. [`records::Attestation`](../src/records.rs) is that record, and
the docket is now compared against attestations rather than against the node's
own verdicts, so a finding arrives already attached to a key with a bond behind
it. Full account in [bonded-verification.md](bonded-verification.md).

The swing between the two arms is 100,000 — two bonds, to the unit, for the two
known-bad canaries the stamper accepted — and `rubber_stamping_costs_more_than_it_saves`
checks that it is a whole number of bonds and that every one of them was *named
by a canary before it was charged*. A slash the docket did not point at would
mean the expensive half ran on its own, which is the cost the cheap half exists
to avoid.

Pinning a known-open hole was worth as much as pinning a closed one, and this is
why: an open hole can silently be believed fixed, and a test that asserts it is
still open is the only thing that makes closing it an event.

## What it found

A real defect in the challenge mechanism, on its first run against a griefer
that opened bonded objections and then did nothing at all.

At the very start of a dispute **both** sides owe their opening endpoints, so
`Node::overdue` named nobody, no forfeit was ever due, and a challenge nobody
played stayed open forever — bond locked, no outcome, and a defender who wanted
the matter closed could not close it. The burden of prosecution is the
challenger's: they opened the objection, so if they have made no move at all by
the time the window has run, they forfeit whatever the defender has or has not
done. `a_dispute_neither_side_plays_resolves_against_the_challenger` in
`tests/fraud_proofs.rs` is the regression.

**A trap with only one jaw.** The arena's pinned checker was
`artifact.get("ok") is True`, and every edit `canary::Generator` makes is shape-
and length-preserving over *numbers and strings* — it has no move that flips a
boolean. So no canary it could mint would ever make that checker **reject**, and
the rubber-stamping scenario had been running against a docket of two known-good
canaries and zero known-bad ones: the half that catches blind *rejection*,
pointed at an attacker that blindly accepts. `Docket::mix` existed and said so;
nothing was asking it. The scenario now asserts both halves before it measures
anything, and the checker depends on a number the generator can actually move.

Four bugs in the arena's own scenarios turned up the same way, and are worth
naming because each made a defence look better or worse than it is:

- **A locked bond read as a loss.** Scoring on `balances`, which subtracts what
  is committed, made every honest participant appear to lose its stake the
  moment it staked it — and made a free-rider who staked nothing look prudent.
- **The canary round submitted stand-in artifacts.** A docket is keyed on the
  artifact digest, so it matched nothing and the defence appeared to do nothing
  when it had never been pointed at anything.
- **The sybil comparison gave every key the same stake**, so an eight-way split
  started with eight times the money and the run measured the extra money rather
  than the extra keys.
- **Four canaries shared one objective**, which settles once — so the first
  landed, the other three were refused at commit, and the docket ended up
  pointed at half a batch it believed was whole.

## Scope, stated rather than implied

One node, many identities. That is Stage 0's trust model and where every money
rule in this crate lives. Attacks needing *two disagreeing nodes* — equivocation,
a partitioned settlement order — are not here and are not claimed;
`tests/simulation.rs` is the harness for those.
