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

The current Mac ingester publishes public status and uses
`scripts/ship-ecc2k-evidence.zsh` through a ten-minute LaunchAgent to copy
completed evidence to the versioned private source bucket. A second ingester
replica runs on EC2 in worker-only mode and ships its completed evidence every
two minutes. Both use the RDS object lease and distinct replica ids. The Mac
shipper excludes its live period and lock; the EC2 shipper likewise sends only
completed periods. The Mac remains the single public status publisher.

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
The current hub runs as `com.adamburan.cairn-ingest-hub` on the Mac; move its
single ledger and private keys to an always-on tailnet host before treating it
as highly available. `hub-check.sh` verifies the authenticated HTTPS MCP path
from each enrolled agent location before the agent submits a claim. It is a
read-only probe; a successful probe does not certify an ingester period.
Enroll each remote agent with its own bearer and signing identity. Set
`CAIRN_MCP_HTTP_AGENTS_FILE` to a private mode-0600 JSON file on the hub:

```json
{
  "schema": "cairn-mcp-agent-profiles-v1",
  "agents": [
    {"name": "americas", "token": "<64 lowercase hex characters>", "identity": "/srv/cairn/americas.identity.json"},
    {"name": "europe", "token": "<different 64 lowercase hex characters>", "identity": "/srv/cairn/europe.identity.json"}
  ]
}
```

Create each identity with `cairn identity --out` and keep its file private.
The existing `CAIRN_MCP_HTTP_TOKEN` remains the operator profile. Each bearer
selects one signing identity and a separate MCP session table, while all
profiles share the daemon ledger and one spend ceiling. A leaked bearer lets
its holder act as that agent, including invoking the hub's other MCP tools;
revoke it by replacing the token in the private file and restarting the hub.
Keep each `name` stable across restarts: its private pending sidecar holds the
nonce needed to reveal commitments that agent already made.
The hub holds all signing keys, so its host is trusted for every profile;
profiles share the ledger and spending ceiling. Require Tailscale enrollment
and ACL access as well as the profile's Bearer token. A temporary direct
Tailscale Serve route can enforce the random `CAIRN_MCP_HTTP_TOKEN` for the
operator profile and exact `CAIRN_MCP_HTTP_PUBLIC_HOST`; set both privately,
keep the ACL restricted, require HTTPS, and retain the default zero MCP spend.
Public internet access is unsupported.

### EC2 agent route while the hub runs on the Mac

The EC2 worker host has no Tailscale client. A Mac LaunchAgent keeps an SSH
reverse forward from an EC2 **loopback-only** port to the hub's Tailscale Serve
HTTPS address. The dedicated Ed25519 SSH key stays on the Mac. Its EC2
`authorized_keys` entry uses `command="/bin/false",restrict,port-forwarding`,
pins the one permitted listen address and port with `permitlisten`, and denies
useful local forwarding with `permitopen`. The Mac SSH client pins the EC2 host
key, uses `ExitOnForwardFailure` and keepalives, and launchd restarts it after
a disconnect. Do not put the tunnel key or an agent bearer in this repository.

On that EC2 host, one `/etc/hosts` entry maps the hub's tailnet DNS name to
`127.0.0.1`. A normal HTTPS MCP client then connects through the reverse
forward using the real DNS name for TLS certificate verification, SNI, and the
HTTP Host header. The agent's separate bearer is in a mode-0600 file under
the agent account. Its `cairn-ingest-mcp` wrapper reads that file and runs
`scripts/cairn-remote-stdio.py` against the HTTPS `/mcp` URL. A live probe
initialized a session, listed all 15 tools, restarted the tunnel LaunchAgent,
and repeated the authenticated probe successfully. A stolen bearer still
grants that profile's full MCP tool access; the restricted SSH key is only a
transport credential.

This route depends on the Mac staying awake and the EC2 instance retaining
its current public SSH address. The host-key pin fails closed if EC2 is
replaced. Move the hub and agents onto an always-on private network for
resilience; remove the EC2 `/etc/hosts` override when direct tailnet routing
replaces the tunnel. The Mac hub currently remains the one Cairn ledger writer.

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
  exported completed-poll rows, or a complete supervisor journal if the S3 pass spans the period;
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

1. the exported completed-poll rows match RDS. If none completed during a long
   S3 pass, check the complete supervisor journal against host logs and private
   S3/RDS activity. A journal by itself cannot prove that useful work occurred;
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

For a pass that crosses the entire period without completing, use
`--allow-empty-polls` on `collect` after confirming the private inventory and
host activity. Pass the archived `period-N.json` to `prepare` with
`--journal-file period-N.json`. The pinned checker then requires boundary
coverage, regular exact-status observations, a live child at the end, and no
recorded restart or status error. The auditor still must corroborate the
operator-controlled journal before signing. A partial or missing journal is
not an eligible operating period.

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

## Submit audited periods over MCP

An auditor host with read-only access to the private source bucket and RDS can
assemble candidates as periods close. It fetches the completed supervisor
journal and every distinct status snapshot named by that journal from the
shipped S3 evidence prefix, checks their hashes, the status boundary times, and
a continuous healthy trace,
then runs `collect` and `prepare` against the committed source versions. It
stores the exact evidence files, unsigned body, and an evidence-version manifest
in a private directory. When the period's last observation predates its end,
the assembler waits for the next completed journal's first status generated
after that boundary. S3 must return version ids for the journal and status
objects; an unversioned evidence copy is refused. `--watch-from` catches up
after downtime and waits for later completed periods without assuming an end
date:

```sh
python3 examples/ecc2k-ingest-service/period_candidate_runner.py \
  --ingest-source /opt/rho-ingest/dp_ingest.py \
  --db-secret "$AUDITOR_READ_ONLY_DB_SECRET" \
  --db-instance "$DP_DB_INSTANCE" --aws-region "$AWS_REGION" \
  --bucket "$PRIVATE_DP_BUCKET" \
  --evidence-prefix "logs/rho-ingest-$REPLICA_HOST/evidence/" \
  --replica-id "$REPLICA_HOST" --operator "$OPERATOR_PUBLIC_ID" \
  --period-seconds "$PERIOD_SECONDS" --watch-from "$FIRST_CLOSED_PERIOD" \
  --out-dir "$PRIVATE_AUDITOR_CANDIDATES"
```

The runner uses the auditor host's AWS credential chain to resolve the RDS
endpoint and the explicitly selected Secrets Manager credential. Configure
that secret for a dedicated, non-privileged database role with `SELECT` access
to `dp_ingest_progress` and `dp_ingest_polls` and no write grants on either
table. The runner refuses a pre-existing `DATABASE_URL`, privileged database
roles, DML grants on those tables, or a connection that does not report
`transaction_read_only=on`. The session setting is defense in depth; database
grants are the authority boundary. The AWS role needs only the required RDS
endpoint lookup, access to that selected database secret, and the evidence and
source S3 reads. Do not give it the ingester's write credential for this task.

This process holds no auditor signing key and never calls Cairn. A missing
shipped period is retried in watch mode; an unhealthy or inconsistent journal
stops the assembler for investigation. It writes only the private local
candidate directory. The independent auditor must still review source
inventory, RDS output, and public status provenance before running
`service.py sign` on `body.json`. For a period with completed polls, the
supervisor journal remains review evidence in `candidate.json` and is not
inside the signed Cairn artifact. Until the contract binds that journal, the
auditor's approval is the public claim about continuous operation.

The runner passes the selected database URL to the candidate collector in
process memory and does not export it as `DATABASE_URL`; the AWS credential
chain and its credential-provider subprocesses therefore do not inherit that
database URL. `PGOPTIONS` supplies a session-level read-only safeguard for
every PostgreSQL connection made by the candidate process. Keep the database
role itself SELECT-only, since session options are not a privilege boundary.

After the funder posts the objective, the independent auditor can place each
signed `*.receipt.json` file in a private inbox for that replica's agent. The
agent does not hold the auditor key or sign receipts. It scores every new
artifact with the pinned verifier, commits it through its own Cairn bearer,
returns after the epoch changes to reveal the exact saved artifact, and polls
the accepted claim until the log shows a settled reward. Run one agent per
replica under the host service manager; `--watch` keeps it running without an
assumed campaign finish date:

```sh
python3 examples/ecc2k-ingest-service/receipt_agent.py \
  --endpoint "$CAIRN_MCP_URL" --token-file "$PRIVATE_AGENT_TOKEN_FILE" \
  --objective-id "$FUNDED_OBJECTIVE_ID" \
  --inbox "$PRIVATE_SIGNED_RECEIPTS" --state-dir "$PRIVATE_AGENT_JOURNAL" \
  --expected-unit-price "$PRICE" --watch --interval 30
```

The bearer file and journal directory must be readable only by the agent
account. The agent copies each signed artifact into its journal before its
first submission. It retains that copy for reveal even if the inbox file is
removed, refuses two different receipts for one replica-period, and records
the claim id and actual settled reward. An unavailable score is retried; a
rejection is recorded without submission. A lost response to a commit or
reveal leaves `commit_inflight` or `reveal_inflight` in the journal and stops
automatic retries for that receipt. Inspect the Cairn pending commitments
and log before resolving that uncertainty. Cairn's `cairn/payment` metadata
distinguishes a pending batch from a final zero reward. The agent records that
result as `unpaid`, a positive reward at the configured price as `paid`, and a
different positive reward as `payment_mismatch`. With an older Cairn node
that has no payment metadata, a claim without a settlement entry remains
`revealed` because the node cannot distinguish pending from final zero.
Omit `--watch` for one bounded pass. Deliver each
receipt to the inbox by atomic rename after the auditor finishes writing it.

The local HTTP integration probe exercised this agent against a real Cairn
node through score, commit, later reveal, 17-unit settlement, and independent
reference replay. The live objective cannot be posted until the buyer selects
its exact price, funded period count, funder, and auditor public key.
