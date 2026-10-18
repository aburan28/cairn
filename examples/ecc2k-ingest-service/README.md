# Paying for the ECC2K-130 distinguished-point ingester

The existing `dp_ingest.py` process consumes private `dp/` objects from S3,
commits distinguished points and an object-level progress row in one RDS
transaction, and publishes public `status.json`. The scheduled GitHub action
copies that status to Pages. This Cairn objective pays the **operator for one
audited period of that service**, including a period with no new point files.
It does not pay for producing points; the orbit objective does that separately.

An objective has a configurable `unit_price` and a finite pool of
`unit_price * funded_replica_periods`. It has no completion condition. A later
tranche can use the exact same checker and piecework block; Cairn carries the
paid `replica_id:period` keys across those objectives. The buyer sets the
price, period length, funded number of replica-periods, and auditor key before
posting. No amount is hard coded as a fair rate. The auditor approves each
replica's capacity and health, including an idle replica that stayed available.
Choose the period length before funding to keep a complete receipt below
900 kB. At a busy fleet's object rate, 600-second periods may be more suitable
than the 3600-second example below. `prepare` refuses an oversized receipt so
it cannot silently omit committed objects to fit Cairn's HTTP claim limit.

## Run the service continuously

On each host with approved S3 and RDS access, `cairn_ingest_operator.py` supervises one
replica of the existing ingester. It keeps one local process under a host lock, restarts a
failed process after a delay, and archives exact public status bytes and a
timestamped operating journal. It neither funds an objective nor signs its
own period receipts. The auditor still checks operation and source evidence.
The existing AWS ingest host already has a `rho-ingest.service` systemd unit.
Stop **all** old `dp_ingest.py` processes before a replica rollout: old builds
do not take cross-host object locks. Replace that unit through a reviewed
deployment, then add more replicas. Keep exactly one designated status
publisher; other replicas use `--worker-only`. Each replica needs a distinct,
stable id and evidence directory. The ingester writes its id, exact source
SHA-256, S3 version (where available), and byte count into the committed
progress row. See `ecc2k130/aws/README.md` in the crypto repository for the
database coordination rule. Each completed S3 pass also writes a timestamped
`dp_ingest_polls` row, including a pass that found no new objects.

The crypto repository's `ingest_host.sh` can deploy this supervisor with
`INGEST_CAIRN_SERVICE=1`, `INGEST_OPERATOR_PATH` pointing at this file, and
`INGEST_PERIOD_SECONDS` matching the funded objective. Its paid-service
preflight requires source-bucket versioning and refuses an active older
ingester. On each EC2 replica, systemd starts `cairn_ingest_operator.py`, which in turn
starts the ingester with the same hostname replica id. A two-minute shipper
copies completed period journals and exact public status snapshots into the
private source bucket's `logs/rho-ingest-<instance>/evidence/` prefix, and
ships again when the service stops. This is retained source evidence for the
auditor; no unfinished `current-period.json` is uploaded. The launcher does
not post an objective or sign a receipt.

```sh
python3 examples/ecc2k-ingest-service/cairn_ingest_operator.py \
  --replica-id ingest-a --evidence-dir /srv/cairn/evidence/ingest-a \
  --status-url "$PUBLIC_STATUS_URL" \
  --period-seconds 3600 -- \
  /opt/rho-ingest/venv/bin/python3 /opt/rho-ingest/dp_ingest.py \
    --replica-id ingest-a --bucket "$DP_BUCKET" --status-bucket "$STATUS_BUCKET"
```

Run this foreground command under the host's service manager. The command
after `--` must be the ingester itself, not a cloud allocation command.
`period-N.json` records the replica id, starts, exits, snapshot observations, and whether the
ingester was alive at the boundary. It is operator evidence, not a payout
certificate. A restart, status failure, missing input inventory, or uncovered
portion of a period needs an auditor decision before signing. `--max-periods`
exists for a local rehearsal; production leaves it at zero and runs until
stopped. Keep the evidence directory private until the auditor selects fields
for release.

Distributed agents reach the common Cairn MCP endpoint described in
`docs/agents.md`. The private ingester does not accept network tool calls;
agents can observe the public status and signed receipts, and a credentialed
operator can score and submit a period receipt through the endpoint.
`cairn-ingest-hub.service` keeps that endpoint's one ledger writer alive on a
durable Linux host. `hub-check.sh` verifies the authenticated HTTPS MCP path
from each enrolled agent location before the agent submits a claim. It is a
read-only probe; a successful probe does not certify an ingester period.
The gateway currently uses one Cairn signing identity for all its sessions,
so every account at that address must be trusted to act for the operator.
Run the local two-session payment and independent replay with
`python3 scripts/mcp-http-ingest-smoke.py` after building the Cairn and
reference binaries.

The signed Cairn artifact publishes S3 input object digests and matching
ingestion-time RDS progress digests, bytes, version ids, and commit timestamps
as input and output receipts, with exact status bytes on both sides of the period.
An independent verifier can check the signature, status hashes, timing, and
payment from the log alone. Checking that private data matches a digest still
requires retained object versions or an independent auditor with source
access. Publicly readable immutable copies of the exact S3 object versions
and a point-level output export would be needed for fully independent
input/output replay. A hash-only manifest does not establish that proof.

## What a settled period establishes

The claim includes a receipt with:

- the service id, pinned private S3 bucket name, UTC period number, stable replica id, operator name, random nonce, and auditor
  exported completed-poll rows;
- for every S3 object whose RDS progress row was committed in the period:
  object key, byte length, S3 version id if available, SHA-256 of its bytes,
  record count, duplicate count, and ingestion timestamp from that committed row;
- exact public status JSON bytes captured before and after the period, plus
  their SHA-256 digests; and
- an Ed25519 signature over the canonical receipt body from the auditor key
  pinned in the checker.

Every Cairn node replays the signature, status-byte hashes, period timing,
counter shapes, and the once-per-period payment from the log alone. A node
cannot independently inspect the private S3 corpus or RDS table from this
receipt. The auditor must do that before signing, and the objective statement
names this trust boundary. The S3 digests commit to the exact bytes the auditor
read and support a later public disclosure or second audit. The status bytes
themselves are public in the claim even after the mutable feed is overwritten.

The auditor should sign only after independently checking:

1. the exported completed-poll rows match RDS and represent the ingester's
   operation throughout the period; check process logs or a separately retained
   health trace for gaps and unexpected replica ids;
2. the RDS progress rows are committed and match the S3 objects it rehashed;
3. the input inventory is complete for the period, including unreadable or
   outstanding objects, and the published status reflects the RDS state; and
4. the before/after status bytes were captured from the public feed at the
   relevant boundaries.

`collect` performs the read-only S3/RDS hash, progress-row, and poll-row export.
It does not certify continuous operation, inventory completeness, or the public
feed's provenance by itself. In particular, a signed
receipt means **auditor approval of operation**, not a publicly proven claim
that every private database row is correct. A progress row is transactionally
committed with point insertion by the current ingester, but `collect` does not
recompute every point row in RDS; the auditor must decide how much additional
database sampling or replay the contract requires.
The replica code stores an object digest, byte count, and S3 version id at
ingestion time in the same transaction as the points. `collect` rereads that
version and refuses a mismatch. Older progress rows have no such metadata and
cannot be used for this receipt. If bucket versioning is off, an overwritten
object may make collection impossible; require immutable object keys or S3
version retention for durable audits.

## Run a local Cairn payment

From the Cairn repository root:

```sh
python3 -m unittest discover -s examples/ecc2k-ingest-service -p 'test_*.py'
./scripts/ecc2k-ingest-service-demo.sh
```

The demo creates an ephemeral auditor key, two status snapshots, an input
manifest and a matching progress export; it builds the pinned objective,
signs one replica-period, settles its 800000-unit example payment, pays an
earlier idle period and a second replica in the same period at the same rate,
checks the settled log with `cairn-reference`, and confirms the same
replica-period cannot be paid twice. The
fixture exercises the payment contract and receipt verification. It does not
claim a live S3/RDS audit.

## Prepare an actual period

The production auditor keeps its Ed25519 private key outside the repository.
`service.py` uses `cryptography` for signing; the pinned checker has no external
Python dependencies. `collect` additionally needs `boto3` and `psycopg` in the
auditor's Python environment. For a 3600-second period, the period number is the UTC
Unix timestamp divided by 3600, rounded down. Capture exact `status.json`
bytes at both boundaries before the public status object is overwritten:

```sh
python3 examples/ecc2k-ingest-service/service.py capture \
  --url "$PUBLIC_STATUS_URL" --out before-status.json
# At the next boundary:
python3 examples/ecc2k-ingest-service/service.py capture \
  --url "$PUBLIC_STATUS_URL" --out after-status.json
```

This is prospective accounting: once a boundary snapshot has been overwritten
without an archive, this receipt format cannot reconstruct it.
The checker requires the before snapshot to have been generated no later than
the period start and the after snapshot no earlier than its end. Wait for the
first feed publication after the end boundary before capturing `after-status`.

On this macOS Python installation, the default CA path was empty; setting
`SSL_CERT_FILE` to the installed `certifi` CA bundle let the live HTTPS capture
pass while retaining certificate verification.

After the period, the auditor exports and hashes committed inputs. `collect`
uses the standard AWS credential chain and a read-only PostgreSQL connection;
`DATABASE_URL` and `DP_BUCKET` stay in the auditor environment. Its time range
is half open and uses `dp_ingest_progress.ingested_at`:

```sh
python3 examples/ecc2k-ingest-service/service.py collect \
  --bucket "$DP_BUCKET" --replica-id "$REPLICA_ID" \
  --start 2026-10-10T12:00:00Z --end 2026-10-10T13:00:00Z \
  --objects-out objects.json --progress-out progress.json \
  --polls-out polls.json
```

Then the auditor checks the other conditions above and prepares the signed
receipt. `NONCE` is 32 random bytes encoded as lowercase hex. The auditor
delivers the signed receipt privately to the named operator, who commits it to
Cairn before revealing it. Cairn's current piecework checker sees the artifact
but not the outer submitter, so a party who obtains an unpublished receipt
could race the operator to claim the first payment. Keep it private until the
operator has committed. This is a limitation of this objective design.

```sh
python3 examples/ecc2k-ingest-service/service.py prepare \
  --input-bucket "$DP_BUCKET" --period "$PERIOD" --replica-id "$REPLICA_ID" \
  --operator "$OPERATOR" --nonce "$NONCE" \
  --polls-file polls.json --objects objects.json --progress progress.json \
  --before before-status.json --after after-status.json --out body.json
python3 examples/ecc2k-ingest-service/service.py sign \
  --body body.json --auditor-key "$AUDITOR_PRIVATE_KEY" --out receipt.json
```

The funder builds the objective once with the auditor's **public** key:

```sh
AUDITOR_PUBLIC_KEY=$(python3 examples/ecc2k-ingest-service/service.py \
  public-key "$AUDITOR_PRIVATE_KEY")
python3 examples/ecc2k-ingest-service/service.py objective \
  --auditor-public-key "$AUDITOR_PUBLIC_KEY" \
  --input-bucket "$DP_BUCKET" \
  --unit-price "$PRICE" --funded-replica-periods "$FUNDED_REPLICA_PERIODS" \
  --funder "$FUNDER" --created-at "$CREATED_AT" --out-dir "$OBJECTIVE_DIR"
```

Post `objective.json` with the generated `checker.py` under the same Cairn
root, score the receipt with the pinned checker, then commit, reveal in a later
epoch, and settle after the reveal epoch closes. A top-up must retain the same
checker bytes and `piecework` block to retain once-only period accounting.
Changing the key or period length creates a different service contract.
