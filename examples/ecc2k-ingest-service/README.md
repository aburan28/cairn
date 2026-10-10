# Paying for the ECC2K-130 distinguished-point ingester

The existing `dp_ingest.py` process consumes private `dp/` objects from S3,
commits distinguished points and an object-level progress row in one RDS
transaction, and publishes public `status.json`. The scheduled GitHub action
copies that status to Pages. This Cairn objective pays the **operator for one
audited period of that service**, including a period with no new point files.
It does not pay for producing points; the orbit objective does that separately.

An objective has a configurable `unit_price` and a finite pool of
`unit_price * funded_periods`. It has no completion condition. A later tranche
can use the exact same checker and piecework block; Cairn carries the paid
period keys across those objectives. The buyer sets the price, period length,
funded number of periods, and auditor key before posting. No amount is hard
coded as a fair rate.

## What a settled period establishes

The claim includes a receipt with:

- the service id, pinned private S3 bucket name, UTC period number, operator name, random nonce, and auditor
  observed poll count;
- for every S3 object whose RDS progress row was committed in the period:
  object key, byte length, SHA-256 of its bytes, record count, and duplicate
  count from that committed row;
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

1. the ingester was polling throughout the period and the observed poll count
   is accurate; check its process logs or a separately retained health trace;
2. the RDS progress rows are committed and match the S3 objects it rehashed;
3. the input inventory is complete for the period, including unreadable or
   outstanding objects, and the published status reflects the RDS state; and
4. the before/after status bytes were captured from the public feed at the
   relevant boundaries.

`collect` performs the read-only S3/RDS hash and progress-row check for step
2. It does not certify steps 1, 3, or 4 by itself. In particular, a signed
receipt means **auditor approval of operation**, not a publicly proven claim
that every private database row is correct. A progress row is transactionally
committed with point insertion by the current ingester, but `collect` does not
recompute every point row in RDS; the auditor must decide how much additional
database sampling or replay the contract requires.
The current progress table does not store an object digest or S3 version id at
ingestion time. `collect` hashes the object version it can read at audit time;
an overwritten object could therefore have different bytes from those the
ingester processed. The auditor should require immutable object keys or S3
version retention before treating that hash as an ingestion-time input receipt.

## Run a local Cairn payment

From the Cairn repository root:

```sh
python3 -m unittest discover -s examples/ecc2k-ingest-service -p 'test_*.py'
./scripts/ecc2k-ingest-service-demo.sh
```

The demo creates an ephemeral auditor key, two status snapshots, an input
manifest and a matching progress export; it builds the pinned objective,
signs one period, settles its 800000-unit example payment, pays an earlier
idle period at the same rate, checks the settled log with `cairn-reference`,
and confirms the same period cannot be paid twice. The
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
  --bucket "$DP_BUCKET" \
  --start 2026-10-10T12:00:00Z --end 2026-10-10T13:00:00Z \
  --objects-out objects.json --progress-out progress.json
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
  --input-bucket "$DP_BUCKET" --period "$PERIOD" \
  --operator "$OPERATOR" --nonce "$NONCE" \
  --polls "$AUDITED_POLLS" --objects objects.json --progress progress.json \
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
  --unit-price "$PRICE" --periods "$FUNDED_PERIODS" \
  --funder "$FUNDER" --created-at "$CREATED_AT" --out-dir "$OBJECTIVE_DIR"
```

Post `objective.json` with the generated `checker.py` under the same Cairn
root, score the receipt with the pinned checker, then commit, reveal in a later
epoch, and settle after the reveal epoch closes. A top-up must retain the same
checker bytes and `piecework` block to retain once-only period accounting.
Changing the key or period length creates a different service contract.
