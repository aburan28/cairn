# Roles and rewards

*Who does what on the network, what each one is paid for, and why the ones
that are not paid are not paid yet.*

Status: **partly built.** The roles a person can pick, and the tools to pick
them, ship with this note: `cairn work`, sharing a node on the LAN, the Roles
section in Cairn.app's Settings, and the reader's `/contribute` page. The
payment rules for two of the five roles do not exist yet, and §4 and §5 say
exactly what would have to be true before they can, which is more than "it
is on the roadmap".

## The rule every role is held to

A role is paid for something **the log can show was done**, out of money
somebody **funded**, in proportion to something that **cannot be split for
free**. Each clause has already been paid for once in this repository:

- *The log can show it.* A payment for work nobody can check is a payment to
  whoever claims it most. Every unit in `cairn balances` traces to
  `Node::gross_paid_within` (`src/node.rs`), and every credit there reads a
  record whose truth a second implementation re-derives.
- *Somebody funded it.* Issuance not gated on funded demand is the grinding
  attack in another hat ([economics.md](../economics.md)), so no role is paid
  by minting. Every pool is charged against a declared supply.
- *Cannot be split for free.* A pool divided per identity pays forty keys
  forty times. Divided by stake or by verified output, splitting is exactly
  neutral — measured, not argued, in
  `splitting_a_stake_across_many_identities_earns_what_one_identity_earns`
  and the arena's sybil scenario (**NEUTRAL**).

And one consequence from [node-incentives.md](../node-incentives.md) that
shapes everything below: **the size of a pool decides how many people take a
role; it does nothing to decide whether they do it honestly.** Honesty comes
from what a cheat stands to lose and how likely the protocol is to notice.

## The five roles

| role | what it does | what the log shows | paid today | how |
|---|---|---|---|---|
| **Experimenter** | finds answers to objectives | claims and the pinned verifier's verdict | **yes** | the bounty, or on a ratchet a share of the pool in proportion to the distance moved |
| **Compute** | runs machines on an objective with a supplied solver | the claims those machines submit | **yes** | the same as an experimenter: for accepted output, never for time |
| **Validator** | re-runs checkers and signs what they said | bonded attestations, and slashes | **no** — bonded | 50,000 staked per attestation, returned after six epochs; lost to whoever proves it wrong |
| **Relay / seed** | accepts peers, serves the log | nothing for a relay; undertakings and sampled answers for storage | **no** for relays; storage only on its own log | storage: an availability pool split by bond |
| **Funder** | posts objectives | the objective, charged against a supply | pays | the bounty is escrowed when posted |

`/contribute` renders this table from `ui/lib/contribute.ts`, whose test
pins the pay column against this file. Change them together.

## 1. Experimenter

Built, and the most attacked role in the repository. What stops each way of
getting paid without doing the work:

| attack | defence | where it is pinned |
|---|---|---|
| copy a published answer | a duplicate verifies and mints nothing | `docs/formal-model.md`, "a copy earns zero" |
| copy one in flight | commit–reveal binding the submitter into the hash | threat model, *front-running* |
| slice one improvement into many | ratchet payouts telescope: eight slices earn what one claim earns | arena, *epsilon-farming*: **NEUTRAL** |
| starve the work you built on | citation weights by settled reward, slicing-invariant | `tests/citation_flow.rs` |
| grade your own work | the verdict is the pinned verifier's | everywhere |

Nothing to add here. It is listed because every other role is measured
against it: an experimenter is paid for a result anyone can re-check, and
that is the property the other roles are trying to reach.

## 2. Compute — paid for output, never for time

The obvious design for "offer your spare compute" is to pay a machine for the
hours it spends. It is the wrong one, for the same reason a relay is unpaid:
**nothing in the log can show an hour was spent.** A heartbeat
(`POST /progress`) is what a worker *says*, held in memory and checked by
nobody; a host registration (`POST /hosts`) is the same, and
[agent.md](../agent.md) says so. Pay either and the cheapest way to earn is a
script that posts heartbeats.

So compute is paid the way experimenters are: by what the machines find.
`cairn work` is the tool for it — the assignment, the heartbeat, commit and
reveal, the citation rule — around a solver the operator supplies:

```sh
cairn work --node http://192.168.1.20:8080 --objective sha256:… \
           --worker garage-gpu -- ./my-solver
```

On a divided search (piecework) this *is* a per-unit wage: every novel unit
an accepted claim covers is paid `unit_price`, duplicates are paid nothing,
and the assignment hands each worker name a different slice so overlap is
waste rather than double pay. On a bounty it is a lottery ticket, which is
the honest description of a bounty.

What the heartbeat still buys is visibility. It is what puts a machine on a
challenge's *Who is working on this* roster as **working now**, labelled as
self-reported, and moves no money — so spoofing it is cosmetic.

`scripts/work-demo.sh` checks the whole path against a real node: a worker
that shares nothing with the node but its address takes work, shows up live,
commits, reveals after the epoch turns, and is paid by the verifier.

### On a LAN, and offline

A worker needs one thing from the node: an HTTP address it can dial. Cairn.app
used to bind that to loopback unconditionally, so no second machine could
join. Settings ▸ Network ▸ *Share this node on my network* (or Roles ▸
*Worker host*) binds it to every interface, `GET /network` now publishes
`node.reach` — what it bound and the LAN URLs that reach it — and
`/contribute` turns that into the exact command for each machine.

Sharing exposes nothing that a public seed does not already serve: the log,
the reader, and the routes workers call. Anyone on the network can post
answers and heartbeats; nobody can change what has settled, because
admission runs the same rules whoever posts.

Offline is a setting rather than a mode: `CAIRN_SEEDS=off` (Settings ▸
Network ▸ *Offline*) stops the node dialling the built-in internet seeds.
Nodes on one network still find each other by the LAN beacon, workers only
ever need the node's address, and epochs come from the clock, so a building
with no route out runs, settles and pays exactly as a connected one does.

## 3. Funder

Pays. The whole reward is escrowed against the funder's spendable balance at
post time and never returned ([node-incentives.md](../node-incentives.md),
*charged in full and permanently*). Listed for completeness and because it is
where every other role's money comes from.

## 4. Validator — why checking is bonded and not yet paid

Built: the record (`records::Attestation`), the bond (`VERIFICATION_BOND`,
50,000, returned after `ATTESTATION_WINDOW_EPOCHS` = 6), the slash to whoever
catches a wrong one, and the loop that does the work
(`cairn run --attest-identity`, Settings ▸ Roles ▸ *Validator*). See
[bonded-verification.md](../bonded-verification.md). A correct attestation
earns nothing.

The design in [node-incentives.md](../node-incentives.md) funds verifiers from
a fee on settlement. Building it as written would pay for the wrong thing.

### The strategy the model left out: echo the admitter

The verifier's-dilemma model has four actions — verify, accept blind, reject
blind, abstain — and canaries police the two blind ones, because the protocol
knows a canary's verdict and the blind attestor does not. That is the result
the whole canary pipeline rests on.

But in this protocol the attestor *does* know the verdict. The admitting node
appends a claim and its verdict as consecutive entries (`src/node.rs`,
`append(CLAIM, …)` then `append(VERDICT, …)`), and attestations are posted
afterwards. So there is a fifth action: **attest whatever the log already
says.** It costs nothing to run. It passes every canary — a canary is admitted
like any claim, so the log carries its correct verdict too. It is wrong only
when the admitting node was wrong, and then it is caught only if somebody
*else* verified: the same `[v > 0]` indicator that made universal
rubber-stamping an equilibrium at any penalty, with no canary term to break
it.

Pay attestations from a fee and echo collects the same share as honest
verification without the cost of a check. The pool cancels between them, as
it always does, and what is left is `−cost` against echo. **A paid
verification pool, as designed, buys echo.** Every validator agrees with the
admitting node, the network's independent verification goes to zero, and the
dashboard shows more attestations than ever.

`src/incentive` now has the strategy (`Attest::Echo`), and `cairn incentives`
reports it. At the reference parameters, with every verdict readable:

- one echoer among honest verifiers earns **+200 per claim** more than
  verifying — exactly `verify_cost`. The pool, the canary rate and, at an
  honest admitter, the slash all cancel;
- universal echo is a **strict** Nash equilibrium at every canary rate from 0
  to 999/1000 and every bond up to the modelling bound at a 100% slash;
- a careless admitter does not rescue it: even one that accepts *every*
  fraud pays a lone verifier among echoers 50 against a check that costs 200.

The algebra and the tests that pin each line are in
[node-incentives.md](../node-incentives.md), *A third way to attest without
looking*.

### What would make paying validators safe

**Blind sampling.** For a sample of claims drawn from the epoch beacon — so no
admitter chooses it and no attestor predicts it — the admitting node writes a
*commitment* to the verdict instead of the verdict, and opens it after the
attestation window closes. On a sealed claim there is nothing to echo: an
attestor either runs the checker or guesses, and guessing is exactly the
blind accept/reject that canaries already police. Pay only attestations made
on sealed claims before they opened. Echo then earns nothing, and the
canary analysis holds again on the paid sample.

"Only" is the load-bearing word, and the harness found it rather than this
note. Sealing a share of claims and paying attestations on all of them stops
an operator that never checks once the share passes 16/175 (about 9.1% at the
reference parameters; the honest-stability constraint needs 8.7%). It does
not stop the operator that matters: one that reads which claims are sealed,
verifies those, and copies the rest. That strategy gains +100 per claim at a
half-sealed sample and stays ahead at **every share below 1**. The minimum
share is a fact about a lazy node; the payment rule is what closes the
selective one. Pay sealed attestations only, and the sample size becomes a
choice about cost and settlement delay, not about echo.

What that costs, stated before anyone builds it:

1. **A record change, in both implementations.** A sealed verdict and its
   opening are new record kinds; settlement must read the opened verdict, and
   a verdict that is never opened must resolve to `unavailable`, never
   `reject` (AGENTS.md). New conformance vectors alongside, never replacing.
2. **Settlement waits.** A sealed claim cannot settle until it opens, so the
   sample's payouts land one window later. With payment restricted to the
   sealed sample, its size trades verification coverage against that delay;
   `design::minimum_blind_sample` still says where a network that paid every
   attestation would stop deterring a node that never checks, which is the
   floor below which the sample cannot be the network's only check.
3. **Attestations must travel.** Today `p2p::sync` replays objectives,
   commitments, committee shares and claims (`src/p2p/service.rs`,
   `replay_records`) and nothing else, so a validator's attestations live only
   in its own log. A validator paid for checking other people's work has to be
   able to post that work where they will read it.
4. **The fee itself**: a basis-point rate declared in the genesis prefix,
   beside the issuance records, so a log that declares no fee keeps today's
   arithmetic to the unit and every existing id and balance is unchanged.
   Split between verification and availability; zero at launch, which is the
   bootstrap gap [node-incentives.md](../node-incentives.md) already names —
   a treasury-funded pool covers it, exactly as availability pools are funded
   now.

Until those land, the honest offer is the current one: validating is for
people who want results checked, it costs a bond, and the page says so.

## 5. Relay and seed

**Relays are unpaid, and should stay unpaid until something in the log can
show a relay did its job.** Accepting a connection and forwarding a log leave
no record; any payment for them is a payment for a claim, and the cheapest
claimant is a script.

**Storage is the paid part of seeding, on one log.** A seed's value is that it
keeps a copy and serves it, and that *can* be shown: an undertaking stakes a
bond against the log as it stood, each epoch a beacon-drawn entry must be
produced with its Merkle path, and settlement splits a funded availability
pool by bond and names the silent ([node-incentives.md](../node-incentives.md),
*Three services*). The arena's availability free-riding scenario is
**NEUTRAL**: a node that stored nothing earns 0.

What stops it paying a seed *across* the network is the same gap as §4's third
point, plus one more: undertakings and answers do not sync, and availability
eligibility is fixed by **log position** ("the first log entry in or after the
epoch"), which differs between two nodes that received the same records in a
different order. Syncing the records without changing that rule would make
two honest nodes pay different seeds for the same epoch — a settlement fork.
The fix is to anchor eligibility to something both nodes agree on — the
epoch's batch anchor, which settlement already re-derives — before the
records travel.

Until then, `cairn availability` pays storage on the log it is written into,
which is the right shape for one operator's cluster and the wrong one for
strangers.

## What to build, in order

1. **Done here:** compute paid by output (`cairn work`), LAN sharing and
   offline in Cairn.app, `node.reach`, the Roles section, `/contribute`, and
   this accounting.
2. **Order-independent availability eligibility**, then sync of undertakings
   and answers. No new money: it makes the storage pay that exists work
   between nodes. Needs both implementations and `scripts/differential.sh`.
3. **Attestation sync.** Makes validators' work visible where it matters;
   still bonded-only.
4. **Blind sampling**, paying sealed-claim attestations only.
5. **The settlement fee**, split between the sealed-sample verification pool
   and availability, declared in the genesis prefix. Only after 4: a fee that
   lands before the sample is sealed funds echo.

Each of 2–5 changes what settles, so each needs `cairn arena` run before and
after, a threat-model row moved, and the reference implementation changed in
the same pull request.
