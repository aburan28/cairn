# Deposit grants: mediated uploads to stranger-owned storage

**Status: Stage A built.** `src/deposit.rs`, `cairn deposit`,
`POST /deposit/grant` + `PUT /deposit/upload/{id}` on `cairn serve`, MCP
`request_upload_grant`, a `file` backend for demos and tests, and an `s3`
backend that mints uploads through credentials held in `cairn secret` —
never handed to a contributor. Stage B (pinning a deposit on an Objective)
is designed below and not yet consensus-critical.

This is the construct that lets a challenge say "put the large thing *there*"
without giving every contributor the bucket keys, and without baking AWS or
GCS into the protocol.

## 1. The problem

Some challenges produce artifacts that do not fit in a claim:

| challenge | what is large | where it wants to live |
|---|---|---|
| ECC2K-130 campaign | distinguished-point corpora, GB/day | S3 (`dp/slot-N/…`) feeding the status page |
| workspace benchmarks | trees of source, not a zip ([workspace-benchmarks.md](workspace-benchmarks.md)) | content-addressed blob store, already in-tree |
| a funder's private evaluation set | held-out data a checker must reach | the funder's bucket, not every peer's disk |

For the second row, `blobs.rs` already is the answer: the claim carries
digests, the bytes move peer-to-peer. For the first and third, the bytes
have to land in storage **somebody else operates**, and that operator does
not want to mint an IAM user per contributor.

Handing out long-lived cloud credentials is the obvious move and the wrong
one: a leaked key is a blank cheque against the funder's bill, and an agent
transcript that once saw `AWS_SECRET_ACCESS_KEY` has published it. The
network already refuses to put commit–reveal nonces in transcripts for the
same reason ([threat-model.md](../threat-model.md) "Secrets in transcripts").

## 2. The construct, in one sentence

A **deposit** is a named place to put bytes. A **grant** is a short-lived,
single-use right to put one object under that deposit's prefix. The node that
holds the credentials issues the grant; the contributor never sees the key.

```
contributor                    cairn node                     object store
    |                              |                               |
    |-- request_upload_grant ----->|                               |
    |   (identity, deposit, size)  |-- read credentials ---------->|
    |                              |   from cairn secret           |
    |<- grant {id, put_url, …} ----|                               |
    |                              |                               |
    |-- PUT bytes ---------------> |  (proxy)  OR  (presigned) --->|
    |                              |                               |
    |-- claim artifact with -------> log                           |
       {deposit, key, digest}
```

Two upload modes, same grant:

| mode | when | who sees the bytes in transit |
|---|---|---|
| **proxy** | `file` backend, or any backend without native presign | contributor → cairn → store |
| **presigned** | S3 (and later GCS/Azure) when the backend can mint a URL | contributor → store; cairn only saw the request for the grant |

Presigned is preferred for large bodies: `POST /submit` already caps bodies at
1 MiB, and a campaign DP object is not a claim. The grant response tells the
contributor which mode to use.

## 3. What is public, what is secret

| | lives where | example |
|---|---|---|
| deposit **name** | node config, eventually an Objective field | `ecc2k130-campaign` |
| **provider** + **location** (bucket, prefix, region) | same — public | `s3`, `ecc2k130-$ACCOUNT`, `dp/`, `us-west-2` |
| **credential secret names** | node config only — names, not values | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| credential **values** | `cairn secret` / `~/.cairn/secrets/` | never in the log, never in MCP output |
| grant **token** | server-side map, random 256-bit | like an MCP nonce: generated and consumed, not returned twice |

A deposit config that named the secret *value* would be a credential in a
file people sync. Naming the secret *by the name `cairn secret` already
uses* keeps one store of secrets and lets `cairn secret run` and the deposit
machinery share it.

## 4. Binding a grant

A grant that is "anyone with the URL may PUT anything for an hour" is a
credential with a short TTL. The bindings that make it a *right* rather than
a key:

1. **Prefix.** The object key is minted by the node, in one of two shapes:
   the default `{prefix}/{deposit}/{submitter_short}/{grant_id}`, or, on a
   deposit configured with `--key-shape ecc2k-dp`,
   `{prefix}slot-N/<stream>-0-<sha>.bin` — the content-keyed shape the
   ECC2K-130 ingester files new worker output under, with a minted stream id
   and the body's own sha-256. Either way a contributor cannot write outside
   the deposit's prefix, overwrite another submitter's objects, or pick a key
   the ingester will not recognise. Campaign grants require the slot and the
   digest the key names; redemption writes the `.bin.json` commit marker
   beside the body (presigned grants return a signed marker URL instead).
2. **Size.** `max_bytes` is fixed at grant time; a PUT past it is refused
   by the node (proxy). An S3 grant is presigned only when the request names
   the exact `size` and `digest`: the URL then signs `Content-Length` and
   `x-amz-checksum-sha256`, the response lists both under `headers`, and the
   store refuses any other length or bytes however often the URL is used.
   Without both, an S3 grant is proxy mode, and the node signs the exact
   length and checksum of what it forwards. One remote address may hold at
   most 64 unexpired grants, of the 1024 a node keeps.
3. **Expiry.** Default 15 minutes. A stale grant is deleted, not renewed in
   place — renew by requesting again.
4. **Single use.** The grant is consumed on the first successful PUT. A
   retry needs a new grant. That is what stops a leaked grant URL becoming a
   standing write token.
5. **Optional digest.** When the contributor already knows the SHA-256, the
   grant records it and the PUT must match. When they do not (a streaming
   walk), the receipt carries the digest the node computed.

The grant id is what the contributor puts in their claim artifact as proof
of deposit. Re-deriving "this object exists at this key with this digest" is
a `HEAD` any auditor with read access can do; the grant itself is not in the
log and does not need to be.

## 5. Cloud-agnostic on purpose

The protocol speaks **deposits and grants**. Providers are adapters:

```text
ObjectStore
  put_via_grant(grant, body) -> Receipt
  presign_put(grant) -> Option<Presigned>     # None => use proxy
  head(key) -> Meta
```

| provider | Stage A | notes |
|---|---|---|
| `file` | **built** | root directory on the node; demos, tests, air-gapped |
| `s3` | **built** | credentials from `cairn secret`; SigV4 presigned PUT (no TLS crate); CLI redeem shells out to `curl` |
| `gcs` | designed | same shape; secret names `GCS_SERVICE_ACCOUNT_JSON` or ADC |
| `azure` | designed | same shape; secret names for account + key |
| `http` | designed | generic signed PUT against any HTTPS endpoint the funder names |

Adding a provider is an adapter and a row in the deposit config. It is not a
new record kind and not a consensus change. An objective that *pins* a
provider (Stage B) pins the public location; the adapter that speaks that
provider is the node operator's problem, exactly as a verifier kind is.

**Why not put the AWS SDK in the crate.** One SDK per cloud is a dependency
graph this repository has declined for TLS and AES already
(`tests/cipher_policy.rs`). Stage A's S3 path mints a SigV4 query-string URL
in pure HMAC-SHA256 and lets the contributor (or system `curl`, when the CLI
redeems locally) make the HTTPS hop — so no TLS crate enters this binary. A
node that prefers the AWS CLI can still `cairn secret run … -- aws s3 cp`
beside this; the grant machinery is what stops that CLI being the
*contributor's* problem.

## 6. Stage A vs Stage B

**Stage A (this change) — node-local deposits.**

```
<data-dir>/deposits/<name>.json     public location + secret *names*
~/.cairn/secrets/<NAME>             the values, via `cairn secret`
```

An operator configures a deposit once. Contributors (and MCP agents) ask that
node for grants against it. Nothing about the deposit enters the log, so two
nodes can point the same objective at different buckets — which is fine for a
campaign the funder operates, and wrong for a bounty that needs every peer to
agree where the corpus is. That wrongness is Stage B.

**Stage B — optional `deposit` on `Objective`.**

A public block, omitted when absent (so existing digests do not move):

```json
"deposit": {
  "name": "ecc2k130-campaign",
  "provider": "s3",
  "bucket": "ecc2k130-123456789012",
  "prefix": "dp/",
  "region": "us-west-2"
}
```

Credentials stay out of the record. A node that cannot serve grants for a
pinned deposit answers `unavailable` for `request_upload_grant`, the same way
it answers for a verifier it cannot run. Both implementations would have to
learn the field together; until then Stage A is enough to run the campaign
from an operator's node without orphaning any live bounty.

## 7. Surfaces

| surface | what it does |
|---|---|
| `cairn deposit add --name N --provider file\|s3 … [--key-shape default\|ecc2k-dp]` | write the public config; secret *names* only |
| `cairn deposit list` / `cairn deposit show N` | public parts; never values |
| `cairn deposit grant --deposit N --submitter S [--bytes N] [--size N] [--digest H] [--slot N]` | issue a grant (CLI operator / tests); `--slot` is required by `ecc2k-dp` deposits |
| `cairn deposit put --grant G --file F` | redeem a grant through the local node |
| `POST /deposit/grant` | contributor or agent asks for a grant |
| `PUT /deposit/upload/{id}` | proxy redemption |
| MCP `request_upload_grant` | same as POST; response has the put URL and never a cloud key |

`scripts/ecc2k-dp.sh upload` is the *operator* path onto a campaign deposit:
grant plus put through the local node, with the commit marker written by the
redemption. Contributors without credentials use grants instead — presigned
for the body and the marker both.

## 8. Threats this closes, and what it does not

| attack | answer | status |
|---|---|---|
| contributor receives long-lived cloud keys | they receive a grant; keys stay in `cairn secret` | handled (Stage A) |
| grant URL replayed as a standing write token | single-use; consumed on first successful PUT | handled |
| contributor writes outside the allowed prefix | key is minted by the node, not chosen by the uploader | handled |
| oversized PUT fills the funder's bucket | `max_bytes` on the grant; deposit-level default | handled |
| agent transcript leaks credentials | MCP never returns secret values; grant response has no keys | handled |
| node operator's disk is copied | secrets are outside the data dir, same as the at-rest key | handled |
| hostile node issues grants against a funder's bucket | the hostile node needs the credentials; without them it answers unavailable | handled |
| Stage A: two nodes disagree about where uploads go | not consensus yet; Stage B pins the public location | partial |
| a grant for a digest the contributor later changes | optional digest binding; without it the receipt's digest is what the claim must cite | partial |
| funder wants *read* access shared too | out of scope; this construct is for upload. Read policies stay with the cloud IAM | not handled |

## 9. Trying it

```sh
# operator
cairn secret set AWS_ACCESS_KEY_ID --file …
cairn secret set AWS_SECRET_ACCESS_KEY --file …
cairn deposit add --name ecc2k-demo --provider file --root /tmp/cairn-deposit
# or: --provider s3 --bucket ecc2k130-$ACCOUNT --prefix dp/ --region us-west-2

# contributor (or the operator testing)
GRANT=$(cairn deposit grant --deposit ecc2k-demo --submitter alice --bytes 1024)
cairn deposit put --grant "$GRANT" --file ./dps.bin
```

With `cairn serve` running and a deposit configured, `POST /deposit/grant`
and MCP `request_upload_grant` are the same loop for an agent.
