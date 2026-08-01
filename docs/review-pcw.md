# Review: Proof of Adaptive Challenge Solving

A design review of PCW — model commitment, freshly generated challenges, adaptive
challenge trees, and a work score gating block eligibility — considered as a
**core consensus mechanism** for this network.

## The verdict in one sentence

[economics.md](economics.md) states four properties Nakamoto consensus needs from
its work — *(i) tunable to arbitrary difficulty on demand, (ii) bound to the
previous block, (iii) progress-free, (iv) trivially verifiable* — and observes
that useful research satisfies (iv) and fails the rest.

> **PCW fixes (ii). It does not fix (i) or (iii), and its own machinery puts
> (iv) at risk.**

That is not a dismissal. Fixing (ii) is real work and the construction is
correct. But (i) and (iii) are the two that decide whether a chain has stable
block times and a fair-share property, and neither is addressed. Meanwhile the
challenge tree and the score function both push against (iv), which was the one
property research already had.

The strongest idea in the proposal — *useful work establishes eligibility, a hash
lottery resolves leader selection* — is also the one that dissolves the case for
calling it a consensus mechanism at all. See §7.

## 1. What is right, specifically

Credit where it is due, because several of these are not obvious.

**Fresh randomness for instance generation** genuinely kills precomputation.
`C_t = G(r_t, D, θ)` with `r_t` from the previous block is the correct shape, and
it is exactly the property [economics.md](economics.md) says research lacks. The
proposal earns that one.

**Per-miner salting**, `C_{t,i} = G(r_t, H(pk_i), θ)`, kills answer copying more
cleanly than commit–reveal does, because there is no shared answer to copy. This
is better than what this repo currently has for submissions, and it is worth
stealing regardless of what happens to the rest.

**Refusing to treat natural-language chains of thought as proof.** Correct, and
correct for the right reason. The insistence on externally checkable artifacts —
code, formal proofs, solver certificates, deterministic tool outputs — is the
same discipline [verification.md](verification.md) enforces with its V-tiers, and
a proposal that got this wrong would not be worth reviewing.

**Separating eligibility from leader election.** The single best structural idea
here. It means the hard, judgement-laden parts never sit in the critical path of
block production. §7 argues it proves more than intended.

**Naming what the mechanism does not prove.** "It should probably not claim to
prove subjective understanding, consciousness, exclusive authorship..." — this is
the right epistemics and most proposals in this space do not manage it.

## 2. Verification cost is the binding constraint, and it is off by orders of magnitude

Bitcoin's ratio of verify-cost to work-cost is around `10⁻²⁰`. That number is not
incidental; it is what lets every node validate every block forever. Write `S`
for the cost of solving a challenge, `V` for the cost of verifying one, and `N`
for the number of validating nodes. Total network expenditure per block is
`S + N·V`, so the fraction spent on the useful part is

```
useful fraction = S / (S + N·V)
```

and for that to stay near 1 you need `V/S ≪ 1/N`. At a thousand validators,
verification must cost under a tenth of a percent of solving.

Now take the *most favourable* case in the proposal's own list. Lean proof
search on a hard theorem: minutes to hours. Kernel checking of the resulting
proof: seconds. So `V/S ≈ 10⁻³` to `10⁻⁴` — genuinely excellent, several orders
better than anything else on the list, and **still one to two orders of magnitude
too expensive at a thousand validators.** Verification would consume between 10%
and 100% of what the network spends on work.

Every other class is worse. "Hidden test execution" runs the submitted program
once per validator. "Cross-verifier agreement" multiplies by the number of
verifiers *by construction*. "Occasional expensive audits" is an admission that
`V` has a heavy tail.

The same arithmetic already binds this repo elsewhere. Node rewards are a fee on
settlement, so a settled artifact must pay for its own re-verification: at the
reference parameters in [node-incentives.md](node-incentives.md) — a 5% fee, half
of it to verification, 100 nodes at a verification cost of 200 — the break-even is
`100 × 200 / (1/40) = 800,000` units of settled value per artifact under full
redundancy. The conclusion transfers: **redundant verification is affordable for a
market that settles a few valuable things and unaffordable for a chain that
validates every block.**

The fix is sampling — but sampled verification is exactly what makes consensus
probabilistic about *validity*, not just about ordering, and that is a different
and much weaker security model than the proposal implies.

## 3. The score function cannot be in consensus

```
S = w_c·C + w_r·R + w_g·G + w_u·U − w_k·K
```

`C` (correctness) and `K` (verification cost) are computable. `R` (robustness
under perturbation) is computable if the perturbations are deterministically
checkable. `G` (generalization) and `U` (**external utility**) are not.

This is not a calibration problem. Any term two honest validators can evaluate
differently means they compute different `S`, therefore different `f(S)`,
therefore different eligibility thresholds, therefore **different views of who
won the block**. That is a chain fork caused by an opinion.

[consensus.md](consensus.md) makes the same point from the other direction:
non-deterministic verdicts are eliminated *as a consensus-design decision*, by
requiring pure verifiers, refusing float scores, and refusing machine-dependent
replay fields. `U` is the V4 judgement tier that [verification.md](verification.md)
says no mechanism settles. Putting it in a block-scoring function does not make
it settleable; it makes the chain's safety depend on it.

**Any score used for consensus must be integer-valued and computable by every
node from the block alone.** That deletes `G` and `U`, which are the two terms
carrying most of the proposal's claim to usefulness.

## 4. Progress-freeness, and why its absence is not a detail

Hash mining is memoryless: the chance of finding a block in the next second does
not depend on how long you have been trying. This single property gives Bitcoin
three things people rarely notice:

- **Fair share.** 10% of hashrate wins ~10% of blocks. Continuous, not stepwise.
- **Bounded variance** and therefore predictable block times.
- **No advantage to having started early**, so a block found by anyone resets
  everyone equally.

Research is the *maximally* progress-ful activity. A solver nine minutes into a
ten-minute problem is nearly certain to beat one that just started. Consequences:

- **The mapping from capability to blocks is a step function, not a line.** The
  fastest solver wins nearly every block, not proportionally more. A solver 10%
  slower wins almost nothing. Winner-take-all is not an emergent risk here; it is
  the default.
- **Withholding pays.** A solver who finishes early can sit on the answer, which
  is selfish mining with a much lower threshold, because the "head start" is
  measured in solve-time rather than hashes.
- **Block time inherits the solve-time distribution**, which for the proposal's
  own examples is heavy-tailed. SAT instances near the phase transition vary by
  orders of magnitude at *fixed* parameters.

The lottery is presented as the fix. It is not, and §7 explains why: the lottery
resolves *who among the eligible*, and eligibility is where the step function
lives.

## 5. Difficulty cannot be tuned, and the network's own success decalibrates it

`θ` appears in `G(r_t, D, θ)` as a difficulty parameter, and the proposal does
not say what it is. It cannot, for most of the listed families:

- **Theorem proving** has no difficulty dial at all. Statement length is
  uncorrelated with proof difficulty; that is nearly the definition of an
  interesting theorem.
- **SAT** has a dial (clause/variable ratio) whose relationship to difficulty is
  non-monotone and has a phase transition. You cannot order 2.3× last week.
- **Program synthesis against hidden tests** has difficulty determined by the
  tests, which must stay hidden, so difficulty cannot be publicly audited.

And then the deeper problem, which is specific to a *research* network:

> **The capability improvement the network exists to produce is the thing that
> breaks its difficulty calibration.**

A challenge family that took an hour last year takes a second once someone
publishes a better method — and publishing better methods is the entire point.
Bitcoin's hashrate also grows, but hash difficulty is exactly and continuously
tunable, so retargeting absorbs it. Here, a capability jump in one family is a
discontinuity in block time that `θ` may have no way to answer.

## 6. The liveness fallback is the attack surface, and probably the equilibrium

Bitcoin never stalls: difficulty is continuous, so *someone* finds a hash. PCW
can stall — an instance may be too hard, or the families may be
temporarily out-solved. So the chain needs a fallback for "nobody solved `C_t`
within the window".

Whatever that fallback is — a hash-only block, a difficulty crash, an empty block
— it is now the cheapest path for an attacker, who only has to make solving *look*
unattractive rather than actually outcompete anyone. Worse, it is the cheapest
path for **everyone**: if the fallback ever costs less than solving, the rational
strategy for all miners is to wait for it.

This is the same shape as the rubber-stamping result in
[node-incentives.md](node-incentives.md): when the cheap path and the expensive
path lead to the same reward, the population goes to the cheap one, and no
penalty on the expensive path fixes it. **A useful-work chain needs its fallback
to be strictly worse than the work, and a fallback strictly worse than the work
is one that cannot save liveness when the work genuinely fails.**

I do not think this is unsolvable, but it is unaddressed and it is load-bearing.

## 7. The best idea in the proposal argues against the proposal

> "useful challenges establish costly eligibility; a simple random process
> resolves leader selection."

This is right, and it should be taken further than intended. If leader selection
is `H(r_t ‖ π) < T/f(S)` — a hash lottery among the eligible — then **the chain's
resistance to reorganisation comes from the hash lottery, not from the research.**
An attacker needs eligibility once and hashpower continuously. The marginal cost
of attacking is hashrate.

So the research is not the proof of work. It is a **Sybil gate on who may mine**,
which is a genuinely useful thing to be and a different thing from what the name
claims.

That reframing has a sharp consequence. A one-time gate is weak — solve one
problem, mine forever. To be a security property, eligibility must expire
per-round. But per-round eligibility means every miner must solve a fresh
research problem every block, which reintroduces §4 (the fastest solver is
eligible most often), §5 (block time is solve time), and §6 (what if nobody
qualifies) in full.

**Eligibility is either weak or it is the whole problem again.** The lottery does
not escape this; it only decides who wins among whoever got past the step
function.

## 8. Smaller problems worth fixing regardless

**`Com(M)` is decorative as specified.** `m = H(weights ‖ prompt ‖ tools ‖ runtime)`
is only meaningful if someone can later check that the committed thing is what
ran. If the weights stay private, the commitment proves the miner had *some*
fixed string, and "prevents switching models mid-session" is unenforceable —
detecting a switch requires running the model, which requires the weights.
Making it real needs a TEE (trusting a hardware vendor, which
[architecture.md](architecture.md) prices as a trust assumption rather than a
proof) or zkML (30 s to minutes per inference, per the same table). Either is a
large architectural commitment that the proposal does not currently make.

The honest version: drop `Com(M)` and stop claiming anything about *which* agent
solved the problem. §"what it actually proves" in the proposal is already
compatible with this — it says it should not claim "that no external model was
used" — so the commitment is doing no work the proposal relies on.

**Check 3 — "the answer was submitted before solutions became public" — is not
chain-observable.** "Public" is not a predicate a validator can evaluate. What
the chain can see is inclusion order. Restate as *"the commitment was included
before the reveal window opened"*, which is checkable and is what commit–reveal
actually gives. Small, but the difference between a checkable rule and an
unfalsifiable one is the whole game here.

**The verifier's dilemma is unaddressed.** "Cross-verifier agreement" and
"occasional expensive audits" are exactly the conditional-punishment design that
`node-incentives.md` proves cannot work: if nobody checks, nobody is caught, so
no penalty fires, and *everybody rubber-stamps* is a Nash equilibrium at any
penalty. That result sweeps stakes to the modelling bound at a 100% slash rate
and finds the trap standing every time. The fix is unconditional punishment,
which needs canaries — and see §10, because PCW is unusually well placed to
supply them.

## 9. What the shipped systems did instead

Worth noting the pattern, because it is unanimous.

| system | "useful" resource | why it works |
|---|---|---|
| Primecoin | Cunningham chains | prime chains have a natural, continuous difficulty parameter |
| Filecoin | storage | tunable, cheaply verifiable, progress-free |
| Chia | disk space | same |
| Ball–Rosen–Sabin–Vasudevan | orthogonal vectors / 3SUM | *provable* hardness with tunable difficulty |

Every system that shipped chose a resource that happens to satisfy the four
properties, and then argued it was useful. None chose something people wanted and
then tried to make it satisfy the properties. Filecoin in particular could have
picked useful computation and picked storage instead — and storage is the one
where the protocol holds the right answer, which is precisely the asymmetry
`node-incentives.md` identifies as making availability easy and verification
hard.

The BRSV line is the closest anyone has come to the real thing, and the price
they paid is that orthogonal vectors is useful to complexity theorists and nobody
else. **You appear to get usefulness or the four properties, and the ones who
shipped took the properties.**

## 10. The reframe: right machine, wrong socket

Nearly every component here is valuable. The consensus framing is what causes the
problems, and removing it costs almost nothing, because this repo already has a
mechanism that wants exactly these parts.

**Adaptive challenge trees are a canary generator.** This is the strongest
constructive observation in the review. `node-incentives.md` names canaries — 
artifacts whose verdict the protocol already knows, mixed indistinguishably into
a verifier's sample — as the thing that converts conditional punishment into
unconditional punishment and makes honest verification an equilibrium. It also
says the generator is unbuilt, and that indistinguishability is "the whole
assumption": at `canary_leak = 1` the harness reports that no canary rate works.

PCW's `G(r_t, D, θ)` is that generator. Procedurally generated instances *with
planted solutions* are standard practice in SAT and constraint benchmarking, they
come from the same pipeline as real instances by construction, and their verdict
is known in advance because the solution was planted rather than found. That is
the indistinguishability property the mechanism needs, obtained from machinery
the proposal already specifies.

**Per-miner salting belongs in submissions**, not just in mining. It is a
strictly better anti-copying defence than commit–reveal for any objective where
the instance can be parameterised.

**Adaptive follow-ups belong in dispute resolution**, where interaction is
affordable because it is rare. A bonded challenge window over a claim someone has
disputed is exactly the place to ask "solve a perturbed instance" — and it is
already on the Stage 2 roadmap as interactive fraud proofs.

**The eligibility/lottery split belongs in verifier sampling.** Which nodes are
eligible to verify a given artifact this epoch is a real question, currently
answered by `partition.rs` with a beacon-derived pure function. Gating it on
demonstrated capability is a plausible improvement and costs no consensus
complexity at all.

## 11. One structural objection to the whole direction

[consensus.md](consensus.md) argues against running an L1 partly on a bootstrap
circularity: stake value ← settled research ← chain. PCW makes that loop tighter
rather than looser, because chain security now depends on research difficulty,
which depends on model capability, which depends on who is mining, which depends
on chain rewards.

And the deeper point that survives every implementation detail: **consensus over
useful work makes the chain's security a function of how hard research currently
is.** That is a quantity nobody controls, that changes discontinuously, and that
the network is explicitly trying to reduce. A security budget denominated in
"how hard is this problem today" is denominated in the one thing everyone is
working to make smaller.

## 12. What I would build from this, in order

1. **Planted-solution challenge generators** as the canary pipeline for
   `src/incentive/`. Highest value, no consensus involvement, and it closes the
   assumption the node-operator mechanism currently rests on.
2. **Per-miner instance salting** for parameterisable objectives.
3. **Adaptive follow-ups in the dispute path**, not the settlement path.
4. **Capability-gated verifier sampling**, replacing or augmenting the beacon
   partition.

And explicitly not: block production, leader election, or a work score with `G`
and `U` in it.

## Where this review might be wrong

- **I have assumed every validator verifies every block.** A design with
  succinct proofs of verification — a SNARK over the checker's execution — would
  change §2 completely, since `N·V` collapses to `N` times a constant. That is a
  real research direction and the proposal does not invoke it; if it did, several
  objections here would need re-running.
- **§4 assumes solve times are heavy-tailed and deterministic.** A challenge
  family with tightly concentrated solve times would recover much of the
  fair-share property. I do not know of one that is also useful, but I have not
  proved there is none.
- **§7's claim that eligibility is "weak or the whole problem again" is a
  dichotomy, and dichotomies are where arguments hide a middle.** Eligibility
  decaying over many blocks rather than expiring per-block might sit between, at
  the cost of a slower-moving but still real capability advantage.
- **I am reviewing this against a design that has chosen not to be a chain.**
  Some of what reads as an objection is really a statement that PCW solves a
  problem this repo decided not to have. A project that genuinely needs its own
  L1 would weigh §2 and §5 differently, though I do not think it can weigh §3
  differently — the score function problem is fatal anywhere.
