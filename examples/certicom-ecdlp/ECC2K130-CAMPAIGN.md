# ECC2K-130: paid orbits on cairn, campaign DPs on the status site

Two paths that share a walk and must not be confused.

## Paid path (this repository)

`objective-ecc2k130-orbit-batch.json` pays for a **witnessed orbit** of the
Bailey et al. walk. Submit `{dps: [{x, seed, j}, …]}`; the checker rebuilds
`μ` from the eight counters and requires `[μ·α₀]P + [μ]Q` to land on `x`.
Design: [`docs/design/orbit-piecework.md`](../../docs/design/orbit-piecework.md).
Demo: `./scripts/orbit-demo.sh` on the 21-bit twin.

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
# optional when not using Secrets Manager:
cairn secret set DATABASE_URL --file ~/rho-dp.url

export CAIRN_CRYPTO_ROOT=/path/to/aburan28/crypto
./scripts/ecc2k-dp.sh upload --dp-file dps.bin --slot 0
./scripts/ecc2k-dp.sh ingest once     # or: pending | verify
./scripts/ecc2k-dp.sh status-url
```

`cairn secret run NAME… -- cmd` is what the script uses internally: named
secrets are exported into the child's environment and never printed.

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
