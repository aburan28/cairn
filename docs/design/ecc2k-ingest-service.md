# Ingester operation as period piecework

The ECC2K-130 ingester is a continuing service. Its operator should earn for
verified operation over time, without claiming that it has an expected finish
date. The existing `piecework` rule expresses this directly: the novelty key
is `replica_id:period`, and the pool pays one `unit_price` for each accepted
new replica and UTC period. Two replicas can be paid for the same period;
the same replica-period is paid once. Pool exhaustion means only that the
current funding tranche ended.

The pinned certificate checker reads the receipt in
`examples/ecc2k-ingest-service/`. It checks a named auditor's Ed25519 approval
and deterministic conditions over the public receipt. It never uses the local
clock or contacts S3 or RDS. Receipt acceptance can therefore be replayed from
the log alone. The buyer can audit the private systems and decide whether to
approve a period; Cairn settles exactly that approval. This is a buyer
attestation contract with public input and output receipts, rather than a
claim that a hash by itself proves a private database write.

The top-level `unit` combines the replica id and period from the signed body;
the checker requires them to match. It also pins the input S3 bucket, service
id, auditor key, and period length; a receipt from a different source cannot
be substituted. The ingester records source SHA-256, size, S3 version id where
available, and replica id in the same transaction as each progress row. It
also writes a timestamped database row after every completed S3 pass. The
auditor exports those poll rows and refuses an empty period. Empty
`input_objects` is valid: polling and maintaining an available replica
still cost operator time when the walkers have uploaded nothing. The buyer
should use health telemetry and fresh before/after status snapshots to decide
whether that idle period earned payment. The orbit producer objective remains
separate so each point is not paid twice for the same activity.

## Threats and limits

| Surface | Current rule | Remaining dependence |
| --- | --- | --- |
| Forged receipt | The pinned auditor public key verifies the signed body. | Auditor private key security. |
| Altered public output | Both status JSON byte strings are included and rehashed. | Auditor must have captured the public feed at the stated time. |
| Invented private input or RDS progress | The collector hashes S3 bytes and compares their digest, size, and version with ingestion-time values in committed progress rows. | Other nodes need source access or publication of raw point records to repeat this check. Retain object versions or enforce immutable keys so a later audit can reread the same bytes. |
| Duplicate replica-period | `piecework.key = "unit"` pays `replica_id:period` once for matching checker and piecework terms. | A different checker is a different contract; the funder must not double fund overlapping contracts. |
| Receipt copied before commitment | The auditor gives the receipt to the operator privately. | The certificate verifier cannot bind its named operator to the outer Cairn submitter; a leaked receipt can be raced. |
| Silent service outage | Boundary snapshots and exported completed-poll rows are required. | A process with database write access could forge poll rows; the auditor must check independent health logs, replica inventory, and gaps between polls. |

To remove the auditor dependence, the source bytes and enough output data to
reconstruct the database transition would have to be published or made
available to all verifiers. Publishing only hashes and counters does not do
that. A later version may use a separately specified cryptographic proof of
the transition, but the current receipt does not claim one.
