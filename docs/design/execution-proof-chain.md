# Prescribed execution in the proof chain

**Required integration design, 2026-10-16. Not implemented.** The owner
requires prescribed-computation proofs to be integral to the proof chain
shared with crypto-autoresearcher. This is the implementation contract and
release gate for that work. It does not register a verifier, change historical
objectives, authorize a payout, or turn existing receipts into execution proofs.

The current registry in [`src/verifiers/mod.rs`](../../src/verifiers/mod.rs)
has no execution-proof backend. The endpoint certificate in
[`ecc2k23_orbit_batch.py`](../../examples/certicom-ecdlp/checkers/ecc2k23_orbit_batch.py)
explicitly does not check the prescribed branch rule. That gap remains open
until the gates below pass. Ordinary certificates remain appropriate for
objectives that ask only for a witness, rather than how it was found.

## The required chain

```text
approved protocol and complete trial plan
                  |
                  v
reviewed executable + committed inputs + prescribed randomness
                  |
                  v
verified execution proof + complete workload coverage
                  |
                  v
committed raw results -> independently checked metrics and controls
                  |
                  +--> research evidence -> independent review -> DEC
                  |
                  +--> objective verifier -> claim -> settlement -> offline audit
```

The execution proof is a required dependency for an objective that promises
prescribed execution. It is not optional metadata beside a certificate or an
operator's assertion that a process ran. Research review and settlement are
separate consumers: neither substitutes for the other, and a payout never
changes a hypothesis's status.

The chain proves a relation between program, inputs and outputs under the
named proof system's assumptions. It does not prove personal authorship,
fresh physical effort, elapsed time, instrument truth, novelty, causal
interpretation, a heuristic, or an asymptotic extrapolation.

## One immutable statement across the boundaries

The objective must commit to an execution policy before accepting claims.
Its statement binds the following. Field names and wire encoding are not yet
implemented; freezing them requires the protocol work in milestone 1.

| Binding | Required content and check |
| --- | --- |
| Protocol | Protocol digest, approved trial-plan digest, experiment and trial identity; the objective supplies the expected values |
| Program | Guest executable/image ID, source/dependency closure, reproducible build recipe and compiler identity; source revision alone is insufficient |
| Inputs | Complete input commitment and parameters, including curve/field identity, preprocessing, baseline/candidate identity and cost model where applicable |
| Randomness | Fixed seed derivation, beacon identity and exact future round if used; no contributor-selected replacement draw |
| Coverage | Required indices/ranges, controls, fixed stopping rules and completion conditions; no missing trials or duplicate chunks |
| Results | Commitment to the actual raw output bytes plus canonical integer/boolean fields; metrics consumed downstream must derive from these results |
| Proof profile | Backend, release, verification parameters, receipt mode, security assumptions and bounded decoding/verification resources |
| Work identity | Semantic unit identity independent of proof randomness, signatures, receipt serialization and contributor relabeling |

Avoid commitment cycles. A specification does not contain its own digest, a
result commitment does not include its proof, and a guest image does not embed
the ID of an objective that itself commits to that image. Domain-separate the
different commitments and supply fixed cross-language conformance vectors.

A guest must compute or constrain the claimed arithmetic. An untrusted host
hint, CUDA result, file read, checker verdict or summary is not established
merely by being copied into a proved journal. A postprocessing-only proof has
postprocessing-only scope and cannot satisfy a full-execution requirement.

For chunked jobs, each proved transition binds task identity, position, input
state and output state. Aggregation verifies every child proof and establishes
ordered, gap-free coverage of the required workload, including capped trails,
misses and failed controls. Checking an endpoint or a sum of self-reported
counts is insufficient.

## Backend decision

Implement the bounded arithmetic pilot with **RISC Zero STARK receipts**;
evaluate **SP1** on the same workloads if the proving cost misses the declared
pilot targets. Do not require a hosted prover or an on-chain SNARK wrapper for
verification. A proving service can supply a receipt, never its authority.

The research baseline is RISC Zero `v3.0.6`. Pin the entire guest and verifier
dependency closure and review advisories again at implementation time. Its
published security model targets approximately 96 bits; record the actual
parameters rather than claiming 128-bit security. A STARK-to-Groth16 wrapper
would add setup and elliptic-curve assumptions. No end-to-end post-quantum or
confidentiality claim follows from choosing a STARK receipt.

References: [receipts](https://dev.risczero.com/proof-system/),
[security model](https://dev.risczero.com/api/security-model),
[guest input vulnerability and rebuild requirement](https://github.com/risc0/risc0/security/advisories/GHSA-jqq4-c7wq-36h7).
For an SP1 comparison, the native Rust verifier must include the fix in
`v6.8.1` or a reviewed successor for
[GHSA-p7v2-jjv3-8p8f](https://github.com/succinctlabs/sp1/security/advisories/GHSA-p7v2-jjv3-8p8f).
The current release at research time is `v6.9.0`; a version string alone is
not an audit of the dependency closure.

The verifier must reject fake/development receipts even if its environment
enables development mode. It must verify successful execution, the expected
image and public output, and all assumptions/deferred proofs. Integrity-only
receipt verification does not establish the expected program or success.
Malformed proof data is untrusted input: decoding limits, verifier isolation,
memory bounds and a watchdog belong to the design, not a later hardening pass.

## Enforcement in Cairn

Implement a backend-neutral verifier dispatch entry, provisionally
`execution`, in the primary and reference implementations. The name is a
proposal, not a kind a current node accepts. The objective's existing
`verifier` value contains the immutable execution policy; no default field
may change historical record IDs. Schema, readiness reporting, typed balances,
admission, imported-log audit and verifier dispatch must all understand the
same new kind before release.

| Condition | Required verdict |
| --- | --- |
| Complete valid proof matching every objective binding | `accept` |
| Missing required proof in an otherwise available claim, invalid proof, wrong program/input/output, incomplete proved coverage | `reject` |
| Backend absent, required stored blob unavailable, local verifier timeout/crash | `unavailable`; no settlement and no negative scientific evidence |
| Malformed execution policy or contradictory objective | `invalid_spec`; no settlement |

Unsupported proofs must never fall back to a witness checker, replay, hardware
attestation or an operator's signature. A different trust policy requires a
different explicitly funded contract. A legacy objective is not silently
upgraded by a new binary.

Keep pilot proofs inline and within a declared claim-size cap so a log-only
auditor can verify them. The code blob store currently limits blobs to 1 MiB
and its discovery focuses on verifier code. If larger proof packages are
needed, specify chunk commitments, dependency discovery, bounded transfer,
retention and missing-data outcomes before using external references. A URL
or digest without obtainable bytes cannot complete the audit chain.

Proof encodings can vary for one computation. Piecework novelty must name the
semantic unit, not the proof or whole artifact digest. Current cross-objective
piecework scope compares the verifier and piecework blocks. A backend upgrade
can therefore create a new scope; explicitly settle the policy for prior paid
units and top-ups instead of promising cross-version deduplication that does
not exist. Do not change existing orbit novelty away from canonical orbit IDs.

Beacon-based challenges fix the implementation/plan before the selected draw.
Reuse [drand](drand-beacon.md) verification where appropriate, but make a
missing required draw pending rather than silently using a different seed.
An adversarial operator can backdate its own log: proving pre-registration
before a draw needs a previously witnessed checkpoint or external anchor.
Neither `created_at` nor a signature by that same operator supplies one.

## Milestones and evidence required to close them

All milestones are open. A document, schema, mocked receipt or successful
hash check does not close an execution-proof milestone.

| Milestone | Deliverable | Acceptance evidence |
| --- | --- | --- |
| 1. Statement | Versioned policy/journal encoding and source-to-image build contract | Independent encoding vectors; task/input/program/output substitution and commitment-cycle cases |
| 2. Real pilot | Guest for the existing small `ecc2k-23` prescribed walk and a complete seeded count batch | Real non-development receipts; independent arithmetic agreement; the endpoint-valid alternative walk fails |
| 3. Node integration | Primary/reference verification, schema, readiness and bounded proof transport | Both audit the same settled pilot log; existing frozen conformance bytes unchanged; malformed/imported claims agree |
| 4. Research bridge | Approved plan -> proof -> raw results -> metrics -> evidence -> review/DEC | crypto-autoresearcher cannot promote a covered run after removing/replacing its proof, output or a required trial |
| 5. Economics and adversaries | Cost report plus replay, duplicate-unit, withholding, abort and verifier-failure cases | Native/prover/verifier/storage costs reported separately; both settlement and audit enforce the same rules |
| 6. Enforcement | Newly funded objectives require the policy after a shadow-verification pilot | Fresh offline audit and independent review of the exact release; historical objectives retain their semantics |

Proposed workload ladder: grow deterministic step/sample counts geometrically,
starting with the existing toy orbit implementation and a bounded count batch.
Freeze the pilot's correctness and resource targets before measurement. Report
proof cost, verification cost, proof bytes and peak memory; do not infer
production-scale feasibility from a toy success. Count a complete zero-hit
shard as execution evidence only in its exact finite scope; making it payable
is a separately explicit objective, not a proof of general hardness.

Preserve the independent reference boundary: each implementation derives the
expected statement and rules itself. If both initially use one upstream proof
verification library, disclose that shared dependency. Agreement is not two
independent cryptographic implementations.

## Related contracts

- [Verification](../verification.md) describes current supported checks.
- [Proof-chain status](../proving-it.md) tracks what the system can claim.
- [Threat model](../threat-model.md) keeps this gap explicitly open.
- [crypto-autoresearcher proof chain](https://github.com/aburan28/crypto-autoresearcher/blob/main/docs/execution-proof-chain.md)
  maps this contract to frozen plans, immutable runs, evidence and promotion.
