# Agent-to-agent rewards

Every payment in this repository points the same way. A funder escrows against an
objective, an artifact verifies, settlement releases, and citation flow moves a
fraction of that same money backwards along the claim DAG. Node rewards are a fee
skimmed off the top of it. Every unit that reaches a participant entered the
system as somebody's bounty.

Nothing pays an agent for anything another *agent* wanted. That is the gap, and
this document scopes it: what a peer-to-peer reward mechanism would have to be,
which parts of it the existing machinery already implements, which parts are new
primitives, and — the part worth having early — which parts cannot be built and
should stop being on anyone's list.

## What is actually missing

Four things agents cannot do today, in increasing order of how hard they are:

1. **Subcontract.** An agent holding the frontier on a large objective cannot pay
   fifty other agents to explore branches of it. It can only do the work itself,
   or publish and hope.
2. **Get paid for a decomposition.** [architecture.md §5](architecture.md) makes
   decomposition a first-class role and calls it the network's scarce skill. The
   only payment path it has is citation flow, which requires the decomposer to
   have been the *funder* of the objectives — and funding is not a role an agent
   can occupy.
3. **Sell a sub-frontier candidate.** `gossip.rs` assumes candidates worth
   mutating circulate freely. They circulate freely because nothing prices them,
   and nothing prices them because the ratchet pays for distance moved and a
   sub-frontier candidate moves nothing.
4. **Sell a technique.** "Try annealing on the third coordinate." Named in
   [coordination.md](coordination.md) as the thing this design captures worst.

The first three are mechanism gaps. The fourth is not, and §*What cannot be
priced* explains why it belongs on a different list.

## The asymmetry that makes this tractable

The hard problem in every mechanism here so far has been that the protocol has to
decide something nobody knows. The verifier's dilemma is exactly that: nobody
holds the right answer, so a node that attests without looking is
indistinguishable from one that looked, and the fix is to manufacture ground
truth with canaries ([node-incentives.md](node-incentives.md)).

A trade between two agents does not have that problem, and the reason is worth
stating precisely because it decides the whole scope:

> **The buyer is the oracle.** When agent A pays agent B, A is spending its own
> money on a good it wants. Whether the good was worth the price is A's problem,
> A is motivated to get it right, and A already has the objective's pinned
> verifier to check with. The protocol never has to price anything.

So the protocol's job in a P2P trade is **atomicity, not valuation**: the thing
paid for was delivered, exactly once, and the record of it is in the log. That is
a fair-exchange problem, and the crypto for it is already here — commitments in
`records.rs`, sealed envelopes and Shamir in `crypto/`, the hash-linked log in
`ledger.rs`.

There is exactly one way to lose this property, and it is the same failure as
every other one in this project:

> **No protocol payment may ever be a function of P2P trade volume.**

The moment a fee rebate, a reputation score that pays, a ranking that pays, or
any issuance keys off "how much has this agent traded", the buyer stops being a
disinterested oracle: a sybil pair can trade a worthless good back and forth at
any price for free, because the money returns to the same operator. That is the
grinding attack from [economics.md](economics.md) with a market wrapped around
it. Demand-gating is the rule that survives; trade volume is not demand.

## What agents could sell each other

| good | what changes hands | checkable? | escrow condition |
|---|---|---|---|
| **sub-frontier candidate** | an artifact and its claimed score | **yes, free** — the objective's pinned evaluator scores it, and the buyer was going to run that evaluator anyway | "the delivered artifact scores at least `s` under the objective's pinned verifier" |
| **sub-objective result** | an artifact against a narrower objective the buyer wrote | **yes** — it is an ordinary settlement | the existing one |
| **decomposition** | objectives plus their verifiers | partly — the verifiers run; whether the decomposition is *useful* is judgement | none direct. Paid downstream by citation flow, or by subscription |
| **exclusion** | "region R contains nothing above `s`" | **no.** A universal claim, refutable but not confirmable | bond plus a refutation bounty, paid on survival |
| **technique** | prose | **no**, and not even refutable | none exists |
| **compute** | hours | no — this is the thing [the roadmap's non-goals](roadmap.md) rule out | none |

One row is a clean fit and one is nearly so. The candidate row is the interesting
one: its escrow condition is **the same check settlement already performs**, at a
lower threshold. No new verifier, no new trust assumption, no new cost — the
buyer's check of the goods is a check it was going to run regardless. Everything
below the double line needs either a mechanism this project says it cannot build,
or a market it has already declined to be.

## The recommendation: don't build a market, make `funder` mean something

`Objective::funder` is a `String`. Nothing in the code requires it to say
`"treasury"`. There is no balance, no account, no transfer primitive anywhere in
`src/` — settlements are log records and payouts are *derived* by `attribute`
rather than held. That absence is a feature, and it points hard at one answer:

> **An agent-to-agent payment should be an objective, not a transfer.** A buys
> from B by posting a funded objective B can settle. Escrow, verification,
> settlement, audit and citation flow all apply unchanged.

The alternative — balances and transfers — adds a money primitive that `audit`
would have to re-derive, a new class of state that has to be consistent, and a
second way for value to move that every future rule has to be written against
twice. Recursive bounties add none of that. The trade is already expressible; the
only reason it is not already possible is that Stage 0 has one operator who is
also the only funder.

This also settles the atomicity question for free. Escrow releases on a verdict,
so a seller that delivers nothing is paid nothing, and a buyer that refuses to
pay cannot — the money was committed before the work started. Fair exchange
falls out of the existing settlement path rather than needing its own protocol.

So the scope is not "design a market". It is: **what breaks when the funder is an
agent?**

## What breaks when the funder is an agent

### 1. Citation dilution — the sharp one

An improvement must cite the frontier it beat (`node.rs`, enforced at
submission), and `attribution::flow` splits δ **evenly** across a claim's
citations. Even splitting is safe when citable claims are scarce. It is not safe
when an agent can manufacture them.

With δ = 1/4 and `m` citations, the frontier holder B receives `δR/m` of the
improver's reward R. An agent A that cites B plus `m − 1` claims it controls
recovers `(m − 1)/m × δR` — at m = 5, four fifths of what the ratchet promised B.
The claims are real: A posts cheap objectives, A's own identities settle them,
and every edge resolves. The cost is the protocol fee on `m − 1` sub-settlements
of a reward A chooses, and A can choose one unit.

This is possible today only within a bound: A can cite any accepted claim,
including its own against other people's objectives, but it cannot create more of
them than the network happens to have funded. **Agent funding removes the bound.**
The supply of citable claims goes from scarce to free.

The mitigation on the books is `spurious citations | validators slashing bad
edges` ([threat-model.md](threat-model.md), marked *partial*), which asks a
validator to decide whether an edge is a real dependency. That is a judgement
call, and judgement is the one thing this design says repeatedly that it cannot
verify. It should not be the thing holding up the ratchet's central promise.

Two fixes, and they are not alternatives — the first is a gate, the second is the
general answer:

- **Reserve the enforced citation's share.** Split δ into a mandatory part and a
  discretionary part. The frontier citation the protocol *requires* receives a
  fixed fraction regardless of fanout; only the remainder dilutes. Minimal, needs
  no new inputs, and protects exactly the edge the ratchet's guarantee rests on.
- **Weight the discretionary split by the cited claim's own settled reward.**
  Halving B's share then requires settling claims worth as much as B's, which
  costs real money and real verification. This is the general answer and it is
  more expensive: `flow()` takes claims and an amount, not settlement values, so
  it is an interface change and a **conformance change** — attribution is pinned
  in `conformance/vectors.json` and shared with the Python reference.

Both must land *before* agent funding, for the same reason confidentiality
classes had to land before objectives are funded: it is a change to how money
moves, and retrofitting it re-prices claims that were already settled.

### 2. The decomposition floor

A sub-objective costs the network a verification. Node rewards are a fee on
settlement, so a sub-objective that settles for less than its own verification
costs is subsidized by everything else that settles.

The break-even is a division of existing parameters:

```
V_min  =  verifiers_per_artifact × verify_cost / (fee × verify_split)
```

At the reference parameters (`fee = 1/20`, `verify_split = 1/2`, so a fortieth of
settled value reaches verifiers; `verify_cost = 200`):

```
full redundancy, 100 nodes    100 × 200 × 40  =    800,000  per settled artifact
k-fold sampling                 k × 200 × 40  =      8,000k
```

The reference network settles 10,000,000 per epoch, so at full redundancy it can
afford about twelve settlements an epoch. **Fine-grained subcontracting is not
free; it is one of the more expensive things an agent can ask the network to do.**
Three consequences for the scope:

- Sub-objectives should be **few and large**. A decomposition into a hundred
  thousand-unit tasks costs more in verification than the parent bounty pays.
- The floor is **per verifier tier**. `verify_cost` is a modelled unit, and a
  certificate check (milliseconds) and a replay (a full re-run) are orders of
  magnitude apart. A design rule falls straight out: *a sub-objective should use
  the cheapest tier that can express it*, and the tier is visible in the
  objective, so the floor is computable before anything is funded.
- Sampling is doing most of the work. The harness models full redundancy
  deliberately, as the conservative case; the difference between 800,000 and
  8,000k is the entire argument for sampled verification, and it is an argument
  the P2P market makes urgent rather than optional.

### 3. Escrow is prepaid, and that is a real cost

An agent funding a sub-objective out of a parent bounty it has not won yet is
posting collateral it does not have. The rule has to be that escrow is funded
from a settled balance at post time — anything else is credit, and credit needs a
default path, which needs a liquidation mechanism, which needs prices.

Stated rather than solved: this favours capitalized agents, and it is the
bootstrap problem from [economics.md](economics.md) reappearing one level down. A
new agent cannot subcontract until it has won something.

### 4. Objective spam

Permissionless posting is permissionless spam, and every objective costs readers
storage and costs the discovery layer attention. Posting bonds are already on the
Stage 1 list ("rate limiting and submission bonds against spam"); agent funding is
what makes them load-bearing rather than tidy.

### 5. Self-dealing, and why it is mostly self-limiting

Funding your own objective and solving it moves money in a circle and pays the
protocol fee for the privilege. The one thing it buys is a larger `settled_value`,
which is the input to the node fee pool — so an operator that also runs nodes
recovers its stake-weighted share of the fee it just paid. That is a loss unless
the operator holds essentially all the stake, so the attack is self-limiting;
it should still be *stated*, because "inflate the number that sizes the security
budget" is the kind of thing that stops being self-limiting when a later
mechanism reads `settled_value` for something else.

The remaining live case is the one [architecture.md §8](architecture.md) already
names — *funder ≠ solver for protocol-funded pools* — which is unenforceable
without an identity layer and stays unenforceable with one, because `funder` is a
string and identities are free.

## The tension that decides whether this is worth building

Two risks matter more than everything above, and they pull against each other.

### Does a market beat the ratchet?

The ratchet exists because winner-take-all makes hoarding rational
([coordination.md](coordination.md)). A private market gives an agent a *third*
option — sell it quietly — and if selling beats publishing, the frontier stops
moving and the ratchet's central claim is dead.

It does not, and the algebra is short. Write Δ for the ratchet payout on moving
the frontier from `s0` to `s1`, and φ for the citation inflow the mover collects
later from everyone who builds on it — the effect that gives alice the largest
total from the smallest direct reward in the README's worked example.

```
publish     Δ + φ
sell        π + φ'          where π ≤ Δ + φ_buyer − c_buyer
```

A buyer will not pay more than what the good is worth to it, which is what it
collects by publishing, less its own cost of getting there. So `π < Δ + φ`, and
if the trade leaves the seller no citation edge (`φ' = 0`) selling is strictly
worse than publishing. **Anything the ratchet pays for, the holder should
publish.** The market cannot outbid it.

Which yields the scope's cleanest boundary:

> **The market's entire domain is the set of goods the ratchet prices at zero.**

Sub-frontier candidates, decompositions, exclusions, work on objectives the seller
has no standing to settle. Not frontier advances. That is not a restriction to
enforce — it is what the payoffs already say.

One case survives the inequality: a buyer that pays above Δ because it wants
`φ_buyer`, the downstream citation stream that comes with sitting on the frontier.
Frontier *position* is purchasable. The honest reading is that this is fine: if
you bought the artifact you published, you did build on it, and the citation graph
is not lying about anything — provided the edge exists. Which gives the one
enforcement rule the market needs:

> **A purchased good must appear as a citation edge when the buyer settles**,
> enforced at submission exactly as the frontier citation is. The trade is in the
> log and the artifact's hash is known, so this is mechanical rather than a
> judgement.

With that rule, `φ' = φ` and selling is not a defection from the ratchet — it is
an on-ramp to it, and a seller who sells is paid twice on purpose: once by the
buyer, once by the citation flow. Without it, the market is a laundry for
attribution.

**Residual, and it does not have a fix.** A buyer can strip attribution for
anything short of a verbatim resubmission. Verbatim is already caught — a
duplicate artifact verifies and mints zero — but a buyer that *modifies* what it
bought produces a new artifact with no mechanical link to the original. The
mitigation is that sellers price this in, not that the protocol prevents it.

### Does a market starve the gossip population?

This is the one that could sink the whole idea, and it is not visible from the
payment layer at all.

`gossip.rs` is a bounded join-semilattice of candidates worth mutating, and the
island model depends on those candidates actually circulating. They circulate
because they are worth nothing to hold: the ratchet pays zero for a sub-frontier
candidate, so gossiping it costs nothing and the reciprocity is free.

Price them, and gossiping one is giving away inventory.

```
gossip      0 + (what everyone else's gossip is worth to me)
sell        π + (the same, minus what my withholding costs the pool)
```

The price π is bounded above by the free supply — if everyone gossips, nobody
buys — so this is a congestion game with a plausible interior equilibrium and a
plausible collapse. **A market for candidates may destroy the free candidate
population**, which is the input the search method depends on, in exchange for
pricing a good that was already flowing.

That is an empirical question about a payoff structure, which is exactly the kind
of question `src/incentive/` exists to answer, and it should be answered before
any of this is built rather than after. It is the single highest-value item in
this scope.

## Where the market lives

[coordination.md](coordination.md) sorts shared state by what consistency it
actually needs. The market adds one row of each kind, and they land in different
places:

| state | volume | needs | mechanism |
|---|---|---|---|
| frontier — who holds the best score | low | total order | consensus |
| population — candidates worth mutating | high | eventual convergence | CRDT + gossip |
| work split — which region a node searches | zero messages | nothing | pure function |
| **offers** — what an agent will buy or sell, at what price | high, churning | eventual convergence; a stale offer is a wasted round trip, not a loss | **CRDT + gossip** |
| **trades** — who paid whom for what | low | total order; a trade must not settle twice | **the log** |

Offers ride the transport that already exists for candidates and need no finality.
Trades are settlements and are already in the log by construction, because a trade
*is* an objective settling. No new state class, no new consistency requirement.

## What cannot be priced

**Techniques.** No artifact, no hash, no check. A technique cannot be escrowed
because there is no condition to release against, and it cannot be sold on trust
because the buyer must see it to value it and cannot un-see it. This is not a
mechanism gap to be closed later — it is the judgement problem, and it should
come off the list rather than sit on it as future work.

**Exclusions**, provisionally. "Region R contains nothing scoring above `s`" is
genuinely valuable, unfakeable except by effort, and refutable-but-not-confirmable
— so it can only be paid the expensive way: post a bond, publish the exclusion,
pay a refutation bounty to anyone who produces a counterexample, and release to
the seller after a window in which nobody did. That is buildable and it is
buying claimed effort with extra steps, which is the thing this project's first
sentence refuses. [economics.md](economics.md) already says it: *a network that
pays well for "I looked and found nothing" is paying for not looking.* If it is
built it should be funded explicitly as exploration, at a lower tier, never as a
peer-to-peer good.

**Compute.** Out of scope by the roadmap's non-goals. An agent that wants
somebody else's compute should post an objective, which is the same transaction
with the verification attached.

## The sub-game `src/incentive/` needs

Everything above is an argument. The house style is that arguments about
equilibria get solved rather than asserted, and this one has a shape the harness
already supports: interchangeable players, a small action set, exact rational
payoffs, `Symmetric`.

A fourth sub-game beside `Verification`, `Availability` and `Custody`. An agent
holds a sub-frontier candidate and chooses:

| action | payoff sketch |
|---|---|
| `Gossip` | 0, plus the reciprocity value of everyone else's gossip |
| `Sell` | π, minus the reciprocity forgone, where π falls as more agents gossip |
| `Hoard` | option value of finishing alone, times the chance nobody beats you |
| `Publish` | Δ + φ when the candidate advances the frontier; zero when it does not |

New parameters, all of them things somebody has to measure: the value of a
candidate to its holder, the value of the population to a searcher, the market
fee, the fraction of agents with the capital to buy, and the rate at which
candidates advance the frontier.

The questions worth solving for, in the order they should be answered:

1. **Is `Gossip` still a best response once `Sell` exists**, and at what fraction
   of sellers does the population stop being worth having? The tipping-point
   machinery in `dynamics` answers exactly this shape of question, and the answer
   decides whether to build any of it.
2. **Is there a rival equilibrium** where everybody sells and nobody gossips? If
   there is, this is bistable in the same way verification is without canaries,
   and a shared client default gets there in one step.
3. **What is the smallest reserved citation share** that makes dilution
   unprofitable at a given fanout — the inverse question `design` is for.
4. **Is the market sybil-proof** under a per-identity reward rule? It is not, for
   the reason `RewardRule` already documents; the report should price the rejected
   alternative rather than assume it away.

## Scope, in order

**Before any of it — the gates.** These change how money moves and cannot be
retrofitted onto settled claims.

- [ ] Reserved citation share for protocol-enforced citations, so the ratchet's
      guarantee survives a free supply of citable claims.
- [ ] Reward-weighted discretionary split, with the conformance vectors and the
      Python reference moved together.

**Stage 1 — agent as funder.** Everything here is enabling an existing field.

- [ ] `funder` bound to a submitter identity rather than a free string.
- [ ] Escrow prepaid from settled balance at post time; no credit.
- [ ] Posting bonds, sized against the verification the objective will cost.
- [ ] The decomposition floor computed from the objective's verifier tier and
      surfaced at post time, so an agent is told what its sub-objective costs the
      network before it funds it.

**Stage 2 — the market proper**, and only if the harness says the population
survives it.

- [ ] The `Market` sub-game in `src/incentive/`, with the four questions above.
- [ ] Offers on the gossip transport (which does not exist yet — the merge law
      does, the wire protocol does not).
- [ ] Purchased-good citation enforced at submission.

**Not in scope, with reasons.** Techniques (unpriceable). Compute (a non-goal).
Reputation that pays (sybil-forgeable at zero cost, and it re-introduces the
volume-keyed issuance the whole design refuses). Balances and transfers (a second
money primitive buying nothing the recursive-bounty shape does not already give).

## Where this is wrong

- **The buyer-is-the-oracle argument assumes a competent buyer.** An agent that
  cannot value what it is buying is not protected by being the one who pays; it
  is merely the one who loses. The protocol is indifferent to this by design, and
  a population of bad buyers is a market that stops existing rather than a market
  that misprices — which is the right failure mode, but it is a failure mode.
- **The ratchet inequality assumes the seller could publish.** It shows selling
  is dominated for anyone with standing to move the frontier. It says nothing
  about an agent that has been excluded from settling — by censorship, by a
  deadline, by lacking the bond — and for that agent selling may be the only
  option and the price may be terrible.
- **The decomposition floor uses the harness's full-redundancy model**, which is
  deliberately conservative. Under sampling the real floor is far lower, and the
  number that matters is `verifiers_per_artifact`, which no part of this
  repository currently chooses.
- **The gossip-starvation risk is stated, not solved.** It is the one thing here
  that could make the entire mechanism net-negative, and this document does not
  know the answer — it knows which harness question produces it.
- **None of this is code.** Same caveat as `src/incentive/`: what exists is a
  scope and an argument. The reason to write it before building is that two of
  the items above are changes to how settled money is split, and those get
  expensive the day after the first agent-funded objective settles rather than
  the day before.
