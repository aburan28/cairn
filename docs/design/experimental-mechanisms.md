# Experimental mechanisms for reasoning and delivery

Status: a local reasoning-contract prototype and two proposed network
experiments. None changes Cairn records, balances, verifiers or routing. The
task-plan format can name future policies by digest, but does not implement
them. All credit amounts below are experiment inputs, not prices or payouts.

The useful design space is wider than counting tokens or trusting a relay's
receipt. The constructions below combine established techniques for a possible
Cairn deployment; they are not claimed as new cryptographic primitives or as
world-first research. Their assumptions are part of the contract.

## 1. Buy an improvement in knowledge

For research questions with independently checkable outcomes, buy a forecast
update rather than a claimed amount of thinking. Examples include whether a
frozen candidate meets a pinned bound on a held-out corpus, or whether a fixed
mathematical statement has a decisive witness under a specified checker. An
unresolved question stays unresolved: a failed proof search does not establish
that the statement is false.

The executable prototype in `research/reasoning-contract/` seals each forecast,
reserves collateral, keeps both gains and losses, and settles updates as one
chain. Signed quadratic score differences telescope: intermediate reports by a
funded coalition cancel exactly, regardless of their owners. A genuinely
informative signal can have positive expected value. The exact report exposes
what breaks if losses are forgiven, a worker controls its own baseline, the
outcome can be chosen, or extra paid rights appear with fresh identities.

This connects to proper scoring and information acquisition
([Gneiting and Raftery](https://doi.org/10.1198/016214506000001437),
[Papireddygari and Waggoner](https://arxiv.org/abs/2204.01773)). Strict
propriety for an individual does not establish coalition resistance:
[Chun and Shachter](https://proceedings.mlr.press/r9/chun11a.html) analyze
coalition arbitrage in proper scoring mechanisms.

The integration hypothesis is that a sponsor can fund model calls through a
capped gateway and offer an outcome-scored report contract for the resulting
information. Model configuration remains a gateway policy; an outcome score
does not authenticate the model. The provider bill, private effort cost, task
value and score scale must all be calibrated. This is not a generic way to pay
for every open-ended thought: it needs an eventual independent outcome.

**Pilot gate:** use a frozen held-out benchmark family, commit candidates and
baseline independently, anchor report closure before answer release, and compare
budget levels on randomized assignments. Publish all bought report rights,
abstentions and unresolved items, not only winners. Require an independently
verified outcome certificate before any score can become a settlement proposal.
Reserve losses before the report and test answer leakage and slot withholding.
Keep the contract in sponsor-controlled experimental credits until both ledger
implementations and an imported-log audit can enforce its complete semantics.

## 2. Many small challengers can test one fast link

The earlier dynamic-market design rules out a log magically recovering physical
timing. That leaves room for a conditional measurement protocol. The
[Proof of Backhaul paper](https://arxiv.org/abs/2210.11546) combines synchronized
challenge traffic, signed probe packets, Merkle receipts and robust timing.
Its analysis assumes a selected challenger population with fewer than one
third corrupted, a synchronous network with synchronized clocks, and a trusted
verifier/broadcast role. Those assumptions enable a conservative estimate;
they do not follow from a relay's signature.

For Cairn, the proposed experiment is a **sponsor-selected challenge mesh**:

1. Fix the prover, service interval, probe budget and admitted operator pool
   before an unpredictable public draw. Admission must constrain common
   control and shared bottlenecks; a count of public keys does not do this.
2. Draw several challengers and cap each one's attributable probe traffic.
   Align fresh, non-precomputable probe streams so one weak challenger need
   not saturate the prover's link by itself. Record real packet receipts and
   the complete measurement transcript, including missing reports.
3. Derive a conservative bound only under the measured clock-error, path,
   loss and corruption assumptions. Compare it with independently instrumented
   ground truth while injecting rushing, withholding and false timing.
4. Repeat under real background traffic and during customer workload. A short
   successful probe does not reserve future capacity or certify another path.

The prototype computes only the **sampling assumption's sensitivity**, not this
packet protocol: selecting 10 challengers from 1,000 operators with 100 corrupt
ones exceeds an allowance of 2 corrupt challengers about 6.924% of the time.
With 31 challengers and an allowance of 10, the chance is about 0.00900% per
draw. If Sybils make 60% of that pool adversarial, the first bound fails about
98.806% of draws. These are exact hypergeometric calculations; they are not
measured attack probabilities or a system-wide security bound. Repeated draws,
adaptive corruption and correlated operators require additional analysis.

**Pilot gate:** implement and independently replay packet/receipt validation,
measure against shaped links, and preserve adversarial traces. Establish the
admission and clock assumptions empirically before advertising any guarantee.
Physical QoS billing retains an explicit witness trust policy; it does not
silently inherit Cairn's log-only result guarantee.

## 3. Buy recoverable data before a deadline

Make the queue a supplier of an object that the receiver can reconstruct. Split
a content-addressed object into `k` data shards and `n-k` redundant shards, route
them over independently selected providers, and complete when any valid `k`
arrive. The sponsor purchases a fixed redundancy budget and pays only under
that quoted contract, so a worker cannot mint extra shards to grow its reward.
This trades extra traffic for tolerance of slow providers. Coding and queue
latency are established research topics
([Joshi, Liu and Soljanin](https://arxiv.org/abs/1305.3945)).

A candidate extension is to hide audit status inside encrypted item envelopes.
Customer and audit items share sizes, ingress and scheduling; the audit flag
is disclosed only after delivery commitments. A relay then has less ability
to provide fast service exclusively to recognizable probes. This is an
indistinguishability hypothesis, not a consequence of encrypting the payload:
timing, sender identity, size, destination and retry patterns can reveal probes.

**Pilot gate:** compare completion-time distributions and total bytes for one
route, replicated routes, and coded routes under the same offered load. Inject
one shared ISP failure and one coordinated provider to expose correlated
redundancy. Measure whether a classifier can distinguish audit items from real
items using relay-visible metadata. Keep timeout, cancellation, partial shard
payment and acknowledgement replay rules explicit. A valid shard proves data
correctness; observed timely delivery still needs the stated measurement trust.

## Decision

The information contract is implemented as a reproducible local experiment
because its arithmetic and profitable deviations can be tested exactly. The
challenge mesh and coded queue need live, independently instrumented network
experiments before their performance claims can be assessed. None of these
constructions proves that a private model had a particular internal thought,
or that a physical event can be replayed from signatures alone.
