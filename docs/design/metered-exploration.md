# Metered exploration assignments

Status: foundation in this branch; no production gateway or automatic usage
reimbursement. This design covers metering, a sponsor budget, and a reader-side
contributor score. Random contributor challenges are a later protocol.

## Economic contract

A sponsor creates a funded, pinned-verifier objective and optionally assigns it
to one signed contributor. The objective's reward pays for an accepted work
artifact under the existing settlement rules. Separately, the sponsor may
operate or authorize a gateway to buy bounded model calls. The gateway's
receipts account for that provider expense; token volume does not increase the
worker's settlement. This avoids paying a worker to issue unnecessary prompts,
request extra output, or select a costly model.

The sponsor fixes the model, configuration digest, request window, request and
token caps, integer rates, and total cost ceiling before work begins. The
gateway must enforce those limits before forwarding a request, because a post
hoc cap on accounting does not stop the real provider bill. The sponsor
precommits a useful deliverable and a pinned checker. A failed search can earn
an objective reward only if its specified coverage evidence passes that checker.
No transcript length or elapsed wall time is a sufficient deliverable.

The standard claim path remains commit, reveal in a later epoch, pinned verdict,
then settlement. An assigned objective accepts only its designated key at both
commit and reveal; the imported-log audits in both implementations enforce the
same restriction. The assignee's signed commitment also serves as observable
acceptance for the reader-side delivery score. A funder cannot damage someone
else's score simply by naming their public key on unwanted objectives.

## Receipt and trust boundary

GatewayReceipt signs a versioned canonical payload with the sponsor-approved
gateway key. It binds assignment and request IDs, contributor, exact provider
and model strings, configuration digest, request and response digests, UTC
start/end seconds, and the provider usage categories. A reported thinking-token
count is optional and is a subset of output tokens; it is never added to the
bill again. The receipt has no power to change a verifier verdict or a balance.

A valid receipt proves what that gateway key attested, not which model weights
ran inside a private provider. A contributor can forge its own usage JSON, so
receipts are credible only if the gateway holds the provider credential, sends
the request itself, parses returned usage, and protects its signing key. The
provider's organization usage report should reconcile aggregate charges; it
usually cannot prove which private assignment caused an invoice line. Archive
exact exchanges under sponsor control, with hashes in receipts and a declared
retention/access policy. Every independently settled research result must still
be re-derivable from the public log and pinned checker; private gateway traces
cannot replace that proof.

AssignmentPolicy computes attributed cost with checked u128 intermediates and
integer Cairn units per million tokens. It refuses a different gateway,
contributor, provider, model, configuration, time window, duplicate request ID,
or request beyond input/output caps. It sums numerator units across an
assignment before dividing once, so splitting a request cannot capture extra
rounding units. The ceiling applies after that calculation. Callers must supply
already accounted request IDs from authenticated history if aggregating
multiple completions. This module moves no money.

## Contributor score

The score is a reader calculation over an audited log and a reader-selected set
of trusted funders. It separates task family and verifier tier, uses a declared
recency window, and displays verified, rejected, missed, and unavailable counts.
It also displays attributed spend and settled reward separately. A signed
commitment is required before an assignment enters the denominator. A miss is
counted only after the deadline epoch closes; an unavailable checker is not a
wrong answer. The smoothed delivery fraction and minimum sample threshold are
client routing preferences, never consensus or an automatic right to a bounty.

The score describes selected assignments. Without held-out challenges, it does
not estimate unseen-task ability or establish that Claude rather than another
model performed the work. Self-funded objectives are excluded by the reader's
trusted-funder set; colluding trusted funders remain a governance risk.

## Release sequence

1. **Ledger and offline accounting (this branch).** Keep existing objective
   settlement as the only money path. Add optional assignee to both
   implementations, schema and audit; preserve old objective bytes when absent.
   Add canonical receipt and policy parsing, checked cost calculation, and the
   reader-side score. Cross-check assigned-objective bytes and admission on
   both implementations. No public objective may imply that merely presenting
   a receipt gets a reward.
2. **Operational gateway.** Add a gateway that owns provider credentials and
   signs only completed calls it made. Enforce each policy limit before API
   dispatch, persist idempotency IDs, archive encrypted exchanges, and reconcile
   provider usage reports. Test retries, timeouts, streaming truncation, cache
   categories, model aliases, and key rotation. A provider or gateway failure
   must remain unavailable, not a rejection of work.
3. **Sponsored pilot.** Have a sponsor pay the provider bill directly and fund
   a small set of assigned objectives with independently pinned work checkers.
   Publish per-assignment cost, accepted-work yield, and spend per accepted
   result. Run honest and adversarial strategies in cairn arena before selecting
   caps or any bond. The first pilot should use deterministic evidence that
   peers can reproduce, not a sponsor's subjective sign-off.
4. **Consensus extension only if needed.** If contributors must buy their own
   calls and claim reimbursement, design a separate escrowed cost pool with
   exact one-use receipt accounting, sponsor authorization, provider/gateway
   trust, and independent replay in reference/rust. Reimbursement should be
   capped at verified expense and paired with a deliverable gate; token count
   must never be a source of profit. This is a different contract from the
   sponsor-paid pilot and requires its own adversarial test suite.

## Release gates and known gaps

- Both implementations preserve all frozen conformance vectors and agree on
  new assigned-objective bytes, admission, and imported-log audit.
- The sponsor's actual gateway bill stays below the committed cost cap even
  after concurrent requests, retries, and crashes. Offline receipt validation
  by itself cannot enforce that property.
- Duplicate receipts across claims and objectives cannot inflate reported
  cost. A persisted gateway request ID and an audit-derived used-ID set are
  needed before cost accounting influences allocation.
- A verifier accepting an artifact proves the work criterion only. Gateway
  signatures cannot prove hidden reasoning quality or prevent a trusted gateway
  and contributor from colluding. Model quality is controlled by the task
  checker and observed delivery, with random challenges deferred.
