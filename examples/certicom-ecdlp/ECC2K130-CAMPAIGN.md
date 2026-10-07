# ECC2K-130: paid orbits on cairn, campaign DPs on the status site

Two paths that share a walk and must not be confused.

## Paid path (this repository)

`objective-ecc2k130-orbit-batch.json` pays for a **witnessed orbit** of the
Bailey et al. walk. Submit `{dps: [{x, seed, j}, …]}`; the checker rebuilds
`μ` from the eight counters and requires `[μ·α₀]P + [μ]Q` to land on `x`.
Design: [`docs/design/orbit-piecework.md`](../../docs/design/orbit-piecework.md).
Demo: `./scripts/orbit-demo.sh` on the 21-bit twin.

## Watching the paid path: `/ui/task?id=…`

A node's reader has a dashboard per divided search, fed by
`GET /progress/{id}` (`docs/serving.md`). It shows two kinds of number and
says which is which:

- **Settled**, recomputed from the log: orbits paid per worker, the group
  operations those orbits cost (the eight witness counters sum to the trail
  length, so the step count is in the record), the hour-by-hour history, and
  which part of the `2^48` seed space the paid orbits came from. Against the
  job's expected cost -- `sqrt(pi n / (2 * 262))`, about `2^60.81` -- that is
  the share of the search done and the birthday odds a collision has already
  happened.
- **Reported**, posted by workers to `POST /progress` about once a minute:
  who is live, the unit range each took this epoch, steps and trails this
  session, orbits waiting for the next batch, and the rate. Held in the
  node's memory, unverified, never a record; the ETA on the page is computed
  from it and labelled so.

`tools/orbit_worker.py` is the reference worker loop -- take a slice from
`GET /work_assignment`, walk it with `orbit_dp.py`, heartbeat, commit and
reveal batches over `POST /submit` -- and `scripts/progress-demo.sh` runs
three of them against one node on the 21-bit twin. **The GPU client earns on
cairn by doing the same four things**: emit the eight counters
(`CAIRN-WITNESS.md` in `aburan28/crypto`), submit `{dps: [{x, seed, j}]}`
batches as commit/reveal claims (the `rho-collab` transport there already
does), and post the heartbeat body `orbit_worker.py` posts, with `worker` set
to the same pseudonym it submits under so the dashboard puts both halves on
one row.

## Campaign path (aburan28/crypto + this script)

The live Certicom search collects `(seed, canon)` records into S3. The
distinguished-point **ingester** (`ecc2k130/aws/dp_ingest.py`) folds those
objects into Postgres; the status pipeline publishes **aggregates only** to
[https://aburan28.github.io/crypto/status/](https://aburan28.github.io/crypto/status/).
Point keys, coefficients and seeds never reach the page.

`scripts/ecc2k-dp.sh` is cairn's operator seam onto that path. Credentials
live in `cairn secret`, not in the shell:

```sh
cairn secret set AWS_ACCESS_KEY_ID --file ~/aws.key.id
cairn secret set AWS_SECRET_ACCESS_KEY --file ~/aws.key.secret
cairn secret set ECC_BUCKET --value ecc2k130-<account>
# optional when not using Secrets Manager:
cairn secret set DATABASE_URL --file ~/rho-dp.url

export CAIRN_CRYPTO_ROOT=/path/to/aburan28/crypto
./scripts/ecc2k-dp.sh secrets-check   # which credentials are stored
./scripts/ecc2k-dp.sh status          # live Pages snapshot (JSON)
./scripts/ecc2k-dp.sh upload --dp-file dps.bin --slot 0
./scripts/ecc2k-dp.sh ingest once     # or: pending | verify
./scripts/ecc2k-dp.sh status-url
```

Uploads go through `cairn deposit`, not boto3: the node mints a content-keyed
object name (`dp/slot-N/<stream>-0-<sha>.bin`, the shape `dp_ingest` files
new worker output under), signs the PUT itself over `curl`, and writes the
`.bin.json` commit marker beside the body. The deposit is created on first
upload and reused after; a v2 corpus is stripped to its 32-byte records for
the PUT while the local file keeps its witnesses. No Python AWS stack, no
keys in the environment — and a remote worker with no credentials at all can
upload the same way through `request_upload_grant` (or `POST /deposit/grant`),
which answers a presigned body URL plus a signed marker URL.

`cairn secret path` prints the secrets directory. `cairn secret run` is what
the script uses internally: named secrets are exported into the child's
environment (optionally remapped with `NAME=ENVVAR`) and never printed.

MCP agents that need to configure the same credentials call `set_secret`
(value written, never returned) and `list_secrets` (names only). There is no
`get_secret` tool — agents log what they see.

## What this does not do

- It does not put the campaign corpus into the cairn log. A full ECC2K-130
  table is terabytes; piecework pays a tranche. See orbit-piecework §6.
- It does not replace the GPU client. Walk, bitslice and corpus format live
  in `aburan28/crypto` (`ecc2k130/`). To *earn* on cairn that client must
  emit the eight counters (CAIRN-WITNESS.md there).
- Uploading a DP file here updates the **campaign** store. Settling a cairn
  claim still goes through `submit_claim` / `cairn reveal` as usual.
