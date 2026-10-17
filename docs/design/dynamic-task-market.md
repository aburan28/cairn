# Dynamic task plans, reasoning, and transport

Status: design and a non-consensus task-plan schema. No distributed execution
queue, bandwidth payment, challenge market, or production inference gateway is
implemented by this document. The existing submission spool accepts proposed
**ledger records**, not executable jobs. Its receipt is not a delivery proof.

## The boundary that makes the market coherent

A goal is the problem handle (`docs/goals.md`). An objective is a funded,
content-addressed question with a pinned checker. A task plan is a revisioned
proposal for decomposing work on that goal. Its `priority`, estimates and
dependency graph guide an agent or scheduler; they do not change a ledger
record, reserve money, or certify output. `src/agent/job.rs` describes one
sandbox execution, `spec/search-job.schema.json` pins a particular divided
cryptographic walk, and `src/compute.rs` routes against advertised capabilities.
None is a general task graph. `spec/task-plan.schema.json` fills that gap.

```
goal -> plan snapshot -> task DAG -> off-log execution and delivery
  |                          |                 |
  +-> funded objective ------+-> pinned check -> claim -> settlement
```

The log remains the sole authority for settled work. A plan may refer to an
objective ID, but a plan author cannot define a new checker or payout by
writing `acceptance`. `local_only` means no Cairn result payment. A task whose
`acceptance` names a `pinned_objective` still has to use the ordinary commitment,
reveal, verification, and settlement path. Neither a queue acknowledgment nor
a gateway receipt substitutes for that path.

## Task-plan contract

`spec/task-plan.schema.json` is JSON Schema draft 2020-12. The JSON example at
`examples/task-plan.json` shows inference, independent checking, and delivery.
Its repeated-digit policy digests, sink key and model name are placeholders;
every acceptance is `local_only` and it cannot dispatch a real call or pay a
claim. Replace them with authenticated inputs before any pilot.
An agent may author YAML as a UI format, but the importer must reject duplicate
keys, aliases, custom tags, floats, implicit timestamps, and out-of-range
integers; convert to the schema's JSON value types; validate; then digest the
canonical JSON value. Never sign raw YAML text or let two YAML parsers define
the identity of a funded object. A plan digest is a local planning identity,
not a Cairn record ID.

The importer must enforce constraints JSON Schema cannot express across array
elements:

1. Every task ID is unique. Every `depends_on` and `from_task` target exists,
   refers to a different task, and the graph is acyclic. A `from_task` target
   must also be a dependency, so a runner cannot consume an unfinished output.
2. A task executes only against a pinned plan digest and input digests.
   Reprioritization, changed limits, changed routing, or a changed dependency
   makes a **new** plan whose `supersedes` points to the old digest. A lease
   carries the plan digest, task ID, attempt ID, and a fencing generation;
   only the current generation may publish an off-log completion.
3. An `observed_log_head` is an observation, not a license to treat the
   frontier as frozen. Before executing or paying, re-read objective state;
   a completed task can be stale when another contributor settles first.
4. An `acceptance.objective_id` must resolve to an existing funded objective
   whose checker is independently reproducible. The operator must verify its
   actual rules, assignee, deadline and open reward. A planning budget is not
   escrow; provider dispatch needs a separately signed sponsor policy held by
   the gateway. The sum of reservations for concurrent calls must fit that
   policy's ceiling before any call goes out.
5. Secret-bearing input bytes and model exchanges stay in sponsor-controlled
   storage. A digest in a public plan is not a promise that the content is
   public, and private content cannot be the only evidence for a public
   settlement.

This is deliberately an orchestration interface first. Shipping it as a new
consensus record would make evolving scheduler fields move objective IDs and
force two implementations to agree on decisions that do not determine payout.

## Reasoning incentives

The desired choice is **use enough reasoning to produce a useful verified
result**. A token is an input expense, not a result. A paid token stream gives
a worker positive marginal revenue for padding prompts, output, retries, and
requested thinking. A sponsor-paid gateway removes that direct token revenue,
but also makes the worker's private marginal call cost zero, so a hard budget
and rate limits remain necessary.

For a task with value `V` on a correct, novel result, let `p(e)` be the chance
that effort `e` succeeds, `C(e)` the provider and worker cost, and `L(e)` the
delivery delay cost. The sponsor wants to maximize
`p(e) * V - C(e) - L(e)` under its risk and budget constraints. The worker
cannot be made to choose that optimum by paying `C(e)` plus a fixed margin:
the worker then prefers more billed effort. Instead:

- Fund a pinned deliverable and pay for **settled novelty or specified checked
  coverage**. A coverage claim must identify a precommitted input region and
  carry evidence the pinned checker can reproduce or verify; a transcript
  saying "I tried" is not coverage. Keep provider expense in a separately
  capped sponsor account.
- Let the sponsor or a trusted gateway choose the exact model/configuration
  and enforce the budget before dispatch. Bind each completed provider response
  to one assignment and request ID in a signed receipt. Reconcile totals with
  the provider account. A receipt proves the gateway's attestation, not hidden
  model weights or quality.
- Record requested effort/budget, provider-reported input, cache-read,
  cache-write, output and thinking-token counts where available, request start
  and end, queue wait, time to first byte, and final outcome. Thinking tokens
  are a subset of billed output tokens, never added to that total. Actual
  provider usage and time are measurements; `effort_hint` is merely a request.
  Anthropic currently documents `usage.output_tokens_details.thinking_tokens`
  as the billed-output subset for its thinking mode
  ([provider documentation](https://platform.claude.com/docs/en/build-with-claude/thinking-steering-and-cost)).
- Estimate **marginal value of reasoning** with randomized budget/effort
  assignments within comparable task families, a preregistered checker and
  held-out inputs. Compare verified yield, spend per accepted result, and
  latency at each budget. Do not infer skill from long traces, raw wall time,
  or a claimed model name. A cheaper model that passes the same independent
  checker is economically useful; an unauthorized model is a gateway-policy
  violation, not evidence that its correct answer is wrong.

For contributor routing, keep the existing audited, settlement-gated score
separate by task family and verifier tier. Count accepted assignments only
after the contributor's signed commitment; count a miss after the deadline;
keep checker unavailability separate from failure. Add periodic, privately
sampled held-out assignments from independent sponsors only after challenge
selection, issuer independence, and appeal rules exist. The challenge seed
must be hidden until the worker commits to take the assignment; otherwise a
worker can accept only easy tests. A challenge payout must cover legitimate
cost, or honest workers will rationally refuse it. With challenge probability
`q`, detection probability `d`, cheating gain `G`, and a validly enforceable
loss `S`, deterrence requires `q*d*S > G`; these quantities must be measured,
not assumed. Slashing a merely wrong research answer would punish honest
uncertainty, so any bond should target falsified receipts or deliberate
protocol violations with independently checkable evidence.

## A commodity transfer and aggregation service

Offer a service in units of **unique bytes delivered to an authorized sink
before a deadline**, plus a separately quoted latency target. Do not sell
advertised Mbps or the number of queue entries. The data plane can use
existing transport and content-addressed chunks; a relay or aggregator may
batch small items into a Merkle-rooted bundle, with a manifest of original
item IDs, byte lengths and hashes. The sink signs an acknowledgment of the
specific bundle root and the original item IDs. Deduplication is by item ID
and content hash, across retries and relays, so splitting one item cannot
increase billable bytes. A relay pays for egress it actually sends and may
charge for storage while waiting, but only where the sponsor explicitly buys
that service.

The queue is off-log and at-least-once: `offered -> durably_queued -> leased ->
delivered -> acknowledged`, with expiry returning a lease to `queued` and a
failed item to an explicit dead-letter state. The sender uses one idempotency
key per logical item; a lease has a fencing generation; an old worker's late
ack cannot finish a newer attempt. A sink acknowledgment is evidence of
receipt by that sink key, not proof that the sink is independent. Aggregate
small acknowledgments into a periodic **sponsor invoice**, not a Cairn
settlement. A historical log can recheck signatures and hashes, but cannot
replay the physical event or the time at which bytes crossed a link. Paying
consensus balances for that event would weaken Cairn's log-only re-derivation
guarantee unless the network explicitly adopted a trusted witness as a new
assumption. A public challenge-response for content bytes might support a
separate, replayable availability objective; it still would not prove a
millisecond latency or a link's spare capacity. Queue depth and latency
advertisements remain hints, as `src/compute.rs` already says.

Measure the **whole path**, not one convenient hop:

- The requester measures offer-to-sink-ack time on its own monotonic clock,
  including queue wait, batching wait, transport, sink processing and retry.
  Report p50/p95 and deadline miss rate by size bucket and region. A relay's
  own timestamps cannot prove this latency. Without trusted synchronized
  clocks, two parties' timestamps do not establish one-way delay; RFC 7679
  explicitly accounts for synchronization error
  ([RFC 7679](https://www.rfc-editor.org/rfc/rfc7679.html)).
- The sink checks pseudorandom challenge payloads or random chunks against a
  seed disclosed after relay selection. It signs bytes actually received and
  the challenge nonce. Compute **end-to-end service goodput** as verified unique
  payload bits divided by the requester's measured service interval; this
  includes queue and acknowledgment time and is not a physical link-capacity
  estimate. Exclude retransmitted and duplicate bytes. Probes should include
  sizes large enough to exercise sustained throughput, not just tiny RTT pings.
  M-Lab's ndt7 is a useful
  reference for an active throughput measurement rather than a proof of
  delivery to this network's sink
  ([ndt7 protocol](https://www.measurementlab.net/tests/ndt/ndt7/)).
- Use independent, geographically diverse requesters and sinks, random probe
  times and payloads, and a customer-visible record of misses. QUIC's RTT
  samples derive from locally observed send and acknowledgment times; an
  application should retain the same principle when reporting path latency
  ([RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html)).

These are **challenge-backed service measurements**, not a cryptographic proof
of physical bandwidth. A relay can rent capacity for probes, co-locate with a
friendly sink, collude with witnesses, or prioritize only challenge traffic.
Real customer traffic and randomized probes must share the same queue and
rate-limiting policy; independent sink choice and continuing observations
reduce, but cannot eliminate, those attacks. One physical link behind many
identities also defeats per-identity capacity claims. Buy per-delivery service
from a bonded operator or independently selected path set; do not pay every
Sybil for a self-reported capacity advertisement.

## Dynamic routing and failure incentives

Use the plan's priority only **within the sponsor's own paid budget**. Across
sponsors, admit work under precommitted deposits and apply weighted fair
queuing with per-sponsor admission limits and aging. Otherwise a spammer can
set every task to priority 100, or flood free requests until an honest user's
deadline fails. Give latency-sensitive items a bounded fast lane funded by
their own premium; cap its share so bulk delivery does not starve. Batch while
`estimated_batch_wait + estimated_service_time <= deadline_remaining`, and
send immediately once the bound would be crossed. Recompute from measured
service times rather than a relay's advertised numbers.

The main profitable deviations to test are:

| deviation | required countermeasure | current status |
|---|---|---|
| inflate tokens, retry, or run a premium model only in the receipt | gateway-owned credential, pre-dispatch atomic reservation, idempotent request IDs, provider reconciliation | gateway absent; offline receipts only |
| use a cheap model while claiming a required premium one | gateway dispatches exact model and records response metadata; output checker still decides merit | gateway absent; weights inside provider remain opaque |
| cherry-pick easy reputation challenges or collude with funder | hidden random selection after acceptance, independent issuer set, family-specific scores, minimum sample size | challenge protocol absent |
| self-acknowledge fake transfer, replay bytes, or split one item | authorized sink signature, nonce, content hash, unique item IDs and one-use accounting | transport payment absent |
| rent bandwidth only for probes or use many Sybils on one link | random real-path probes, independent sinks, pay unique delivery rather than claimed capacity | physical capacity cannot be proved by a log |
| underbid, accept a lease, and stall rivals | bounded lease, fencing, deadline misses in routing history, independently measured service | distributed queue absent |
| rush high priority tasks into the queue for free | sponsor budget authorization, per-sponsor admission, fair queue and bounded fast lane | task plan priority is advisory only |
| route work through a colluding checker or omit a failed attempt | objective-pinned independent verifier and append-only settlement log; include all gateway attempts in sponsor reconciliation | partial; provider call path absent |

## Build order and falsifiable gates

1. **Plan importer and scheduler.** Validate schema and graph, reject duplicate
   keys and unknown fields, produce a canonical digest, and pin plan revision,
   task inputs and attempt IDs. Test cycles, dangling dependencies, a stale
   lease, changed plan bytes, budget overflow, and priority spam. Keep it off
   the consensus path.
2. **Sponsor gateway.** Own provider credentials; atomically reserve worst-case
   cost before calls; persist request IDs, actual usage and failures; sign
   receipts only for calls made; reconcile with provider reports. The release
   gate is an adversarial concurrent/retry/crash test in which the real bill
   cannot exceed the sponsor ceiling. Record detailed timing and usage but
   keep private prompts and responses under sponsor control.
3. **Held-out challenge pilot.** Fund a stratified pool with pinned checkers;
   preregister sampling, appeals and score calibration. Compare a cheap model,
   the required model at multiple effort limits, and human/compute baselines
   on unseen work. Report confidence intervals for verified yield and cost per
   result, not a universal reasoning-level number.
4. **Transfer pilot.** Deliver content-addressed items through at least two
   independent routes and sinks. Measure per-size p95 end-to-end latency,
   goodput, loss, duplicate delivery, deadline misses, probe/customer gap and
   cost per unique acknowledged byte under load and faults. Reconcile every
   billed item to a sink acknowledgment under an explicit sponsor contract.
   Keep this invoice outside Cairn balances. Before proposing any ledger
   payment, state which *publicly replayable fact* it pays for, make both
   implementations audit its exact one-use rule, and run splitting, self-ack,
   Sybil and stalling strategies in `cairn arena`. A measured QoS event alone
   does not meet the log-only proof standard.

The sponsor should start with a small, fixed budget and explicit stop limits.
Success is verified work per total expense and a measured delivery service
level under load; token volume and link speed in isolation are diagnostics.
