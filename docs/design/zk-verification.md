# Proofs about verification: what they would buy, and what they would cost

**Status: analysis only. Nothing here is built, and the recommendation is to
build none of it yet — but §6 records a forward-compatibility fact that is
cheaper to decide now than later, and that contradicts what this note's author
first believed.**

Two different things get called "using ZK here", they are bought for completely
different reasons, and arguing for them together is how a proposal gets
accepted on one case's merits and built for the other's:

| | what it buys | who wants it | governed by |
|---|---|---|---|
| **succinctness** | verification cost `N × V` collapses to `N × constant` | every verifying node | the size of `N` |
| **zero-knowledge** | a verdict about an artifact nobody may see | one class of objective | nothing else can do it |

Only the second is *zero-knowledge* in the sense that matters. The first wants a
small proof and would take a transparent one with no secrecy at all.

## 1. Succinctness: the break-even is a number, and it is large

The guarantee this project sells is that anyone can re-derive every settled
result. Today that means every verifying node re-runs every pinned checker —
`audit --rerun` is exactly that — so the network spends `N × M × V` for `N`
nodes, `M` claims and a per-claim verifier cost `V`.

With a proof carried alongside the claim, the submitter pays a proving cost `P`
once and each node pays a verification cost `v` of milliseconds. The network
spends `P + N × v`. So proofs are worth it when

```
N × V  >  P + N × v        and since V >> v,        N  >  P / V
```

**`P / V` is the proving overhead factor, so the break-even node count is the
overhead itself.** For a zkVM executing an unmodified interpreter that factor is
somewhere in the thousands to hundreds of thousands — it moves fast enough that
any number written here will be wrong within a year, and the shape of the
conclusion does not depend on which end of that range is right.

So the honest reading: **this pays off at somewhere between a thousand and a
hundred thousand independently verifying nodes.** Stage 0 has one. The payoff
grows exactly with `N`, which is the quantity this project does not yet have and
is the whole point of Stages 1–3 — so it is correctly a late item, not because
it is hard but because the numerator is currently one.

Two corollaries worth keeping:

- **Nothing about this is urgent, and nothing about it is wrong.** It is the
  single largest structural win available to the design, and
  [`review-pcw.md`](../review-pcw.md) is right that several of its own
  objections would need re-running against it.
- **Do not build it to save the operator time.** At `N = 1` it strictly loses.

## 2. What it would cost the guarantee, which is not a cost in compute

Today, to check a settled result you need the log, this crate, and an
interpreter. The root of trust is *your own re-execution*. With a proof it
becomes a circuit, a proving system, and possibly a setup ceremony.

"Anyone can independently **re-derive** every settled result" quietly becomes
"anyone can **re-verify**" — and those are different sentences. A bug in the
zkVM is a bug in every settled result at once, and it is a bug nobody can find
by re-running anything, because re-running is the thing that was removed.

That gives the rule any proof-carrying tier has to obey:

> **Succinct verification must be additive.** The artifact stays public, the
> checker stays pinned and runnable, and the proof only saves work for whoever
> chooses to accept it. A node that ignores every proof and re-runs everything
> must still reach the same settlement.

Under that rule a proof is an *optimisation for people who already trust the
setup*, and the fallback is never removed. `Unavailable` is never `Reject`
carries over unchanged: a node with no verifier for that proof system says
nothing about the artifact, and falls back to running the checker.

The one place the rule cannot be obeyed is §3, which is why §3 is a different
asset rather than a faster path to the same one.

## 3. Zero-knowledge: `sealed`, and why its economics are unrelated

[`censorship.md`](../censorship.md) §6 already declares three confidentiality
classes, and already says the thing this note would otherwise have to argue:

| class | artifact | verification |
|---|---|---|
| `public` | revealed at epoch end | anyone re-runs the verifier |
| `embargoed` | revealed after N epochs | anyone re-runs it, later |
| `sealed` | never revealed | **zero-knowledge only** |

`Objective::confidentiality` implements it, and `sealed` is **refused at
validation** rather than downgraded — a funder who asked for "never revealed"
must not silently get "revealed in six hours".

Note what is *not* true of this case: `N` does not appear anywhere. A proof here
is not saving anyone work, it is the only mechanism by which a result that must
never be published can be paid for at all. It would be worth building at `N = 1`
if there were demand, and the succinctness case would not.

Two limits, one already documented and one not:

**Feasibility is narrow, and `censorship.md` says so** — practical for
arithmetic certificate checkers, out of reach for a Lean kernel or an arbitrary
evaluator. Of the five kinds in `VerifierRegistry::kinds()` —
`certificate`, `evaluator`, `lean`, `replay`, `statistical` — only the first is
a plausible first target.

**A sealed claim is a permanent leaf in the citation graph**, and this is not
written down anywhere. Citation flow pays for being built upon; nobody can build
on an artifact they cannot see. So a sealed claim earns its direct reward and
**never earns citation income**, however foundational it turns out to be. That
is not a defect to fix — it is the honest price of secrecy, it makes `sealed`
economically self-limiting, and a funder should see it before choosing the
class.

## 4. The prerequisite that has already been paid for

Encouraging, and not obvious: **the verifier-authoring rules are already most of
the way to "provable"**, for reasons that had nothing to do with proofs.

- No floats. `canonical::Value` has no float variant, deliberately, and
  evaluator scores and thresholds are integers.
- [`verification.md`](../verification.md) has *Time is not a checkable field*
  and *Integers only* as authoring rules.
- V2 `replay` already pins command, seed, and environment — which is what makes
  a trace bisectable, and is the same discipline a circuit needs.

A zkVM needs exactly this: no clock, no network, no floating point, no ambient
state. The gap that remains is not the *rules*, it is the *interpreter* — the
checkers are Python, and an unmodified CPython inside a zkVM is where the
overhead in §1 comes from.

One row of the threat model gets *better* rather than worse. **impure
verifier** — a checker reading unpinned external state that passes today and
fails tomorrow — is currently caught after the fact by `audit`. In a zkVM there
is no external state to read, so an impure checker cannot be proven at all: a
detected-later problem becomes an unrepresentable one.

## 5. Stage 3, where the prerequisite is also already built

[`consensus.md`](../consensus.md) already chooses a rollup on an established
chain over an L1. Validity proofs versus fraud proofs is precisely the open
question there, and the expensive prerequisite is done: `node.rs` is a pure
state transition and `audit()` is the re-derivation a proof would attest to.

Light clients are the smaller version. Signed checkpoints plus
`verify --from <checkpoint> --root-key` already give a reader head, root and
height without the log — at the cost of trusting a pinned operator key. A
recursive proof over the state transition removes that trust assumption. Worth
noting, not worth building: the trust assumption is currently the *smallest* one
in the system.

## 6. The thing that is not free, and was assumed to be

**A new verifier tier is a coordinated upgrade, not an additive change.** This
note's author asserted the opposite before reading the admission path, on the
strength of `an_unknown_kind_is_unavailable_because_another_node_may_know_it`.
That test is real and says what it says — but it is about the **verdict** layer,
`VerifierRegistry::run`, and not about **admission**:

```rust
// Node::post_objective
Some(kind) if VerifierRegistry::supports(kind) => kind,
_ => return Err(RuleViolation::UnknownVerifierKind { … })
```

An objective naming a kind this build does not know is **refused**, on the
stated ground that an objective whose payout has no machine behind it is an
opinion. And over the wire it is worse than refused — `apply_records` in
`p2p/service.rs` calls `post_objective` and discards the error, so an old node
**silently drops** it.

The consequence for a proof-carrying tier: upgraded nodes admit those
objectives and their claims and settlements; old nodes have none of it, and say
nothing about why. Not a fork in the dangerous sense — nobody settles the same
claim two ways — but a partition by *omission*, which is quieter and therefore
harder to notice than the contradiction AGENTS.md warns about.

**This is a decision, and it is cheaper to make before there are two tiers than
after.** Three options, none of them free:

1. **Accept it.** A new tier ships as a version bump everyone must take. Honest,
   and normal for a protocol at this stage.
2. **Admit unknown kinds and hold them unverifiable.** Objectives sync, claims
   against them never settle anywhere until a node knows the kind. This is the
   `Unavailable` philosophy applied one layer earlier, and it is what would make
   tiers genuinely additive — at the price of a log full of objectives nobody
   can act on, and a change to *what is admissible*, which is
   consensus-critical: both implementations, the adversarial corpus, and the
   differential run.
3. **Do nothing and rediscover this later**, which is what will happen if it is
   not written down, hence this section.

No recommendation between (1) and (2) here — it wants its own decision with the
sync semantics in front of it. Recording that the choice exists is the point.

## 7. Where proofs do not help

- **Possession and availability.** Physical, not cryptographic. See
  [`shard-assignment.md`](shard-assignment.md) §5: a proof cannot distinguish a
  disk from a fast friend, and the property people hope a SNARK provides —
  a distinct physical copy — comes from sequential encoding, not from secrecy or
  succinctness.
- **Sybil resistance.** Proofs do not create scarcity.
- **Citation privacy.** Hiding the graph destroys the thing attribution is
  computed from. `censorship.md` already states the graph is public by
  construction.
- **Consensus, in the ordering sense.** Nothing here is a total-order primitive.

## 8. Recommendation

1. **Build none of it now.** §1's break-even is the argument, and it is
   arithmetic rather than taste.
2. **Decide §6 consciously**, in its own change, before a second verifier tier
   exists — a proof-carrying tier is the obvious one, but a WASM or a
   native-binary tier hits the same wall.
3. **Do not "prepare" for proofs by adding fields now.** A record's id covers
   its content, so a speculative field moves every objective's digest for a
   feature that may never arrive. The right preparation is the discipline in §4,
   which is already in force for other reasons.
4. **If demand for `sealed` appears, treat it as its own project**, priced
   against a `certificate` checker and nothing more ambitious — and put the
   citation-leaf consequence in front of the funder before they choose the
   class.
