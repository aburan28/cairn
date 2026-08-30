# drand: a beacon a log-only auditor can check

[chain-beacon.md](chain-beacon.md) built the beacon record and left one
sentence as its honest limit:

> A wrong `value` is therefore caught by anyone holding the chain, and never by
> someone holding only the log. That is a real limit, stated rather than
> hidden: the log-only auditor is trusting that *somebody* checked, which is
> the same shape as the availability argument and no stronger.

That sentence is the whole reason this note exists. It is forced by Ethereum,
not by beacons: `block.prevrandao` at block *N* is a fact about a chain, and
the only way to learn it is to hold the chain. A **drand** round is a
threshold BLS signature over the round number, so checking one is a pairing
against a public key that fits in this file. No RPC, no chain state, no sync —
which means the tier of auditor who could not check the value before is the
same tier who can check it after.

This is a smaller claim than "drand is better randomness". It is a claim about
*who can audit*, which is the axis this project spends its budget on.

**Status: built, in both implementations.** The derived round, the record
shape, the pairing check and the audit are all there, and the two
implementations run the pairing on *different* BLS libraries on purpose. What
remains open is not a piece of code: it is chain-beacon.md's recommendation 3,
whether the network should adopt an external beacon at all.

## Which chain, and what gets pinned

**quicknet**, and the constants are here rather than in a config file because a
beacon whose parameters an operator can edit is a beacon the operator chose:

| | |
|---|---|
| chain hash | `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` |
| scheme | `bls-unchained-g1-rfc9380` |
| period | 3 s |
| genesis | 1692803367 |
| public key | 96 bytes on G2, signatures 48 bytes on G1 |

The obvious alternative is drand's `default` chain — older, more relays, the
one most people mean. It is the wrong one here, for a reason that is exactly
the reason we came: `default` is **chained**, so round *N* signs
`H(sig(N−1) ‖ N)`. Verifying it means holding its predecessor, and verifying
*that* means holding the one before, so a chained beacon is checkable only
relative to some point you already trust. That is the Ethereum problem again
with a different chain in it. quicknet is **unchained** — round *N* signs
`H(N)` and nothing else — so one round is self-contained, which is what makes
it checkable from the log alone and, not by coincidence, what makes timelock
encryption possible at all ([tlock](#tlock-is-a-different-decision-and-a-later-one)).

The 3-second period is a smaller convenience with the same shape: an epoch
boundary is never more than three seconds from a round, so "the round at the
boundary" needs no tolerance parameter, and a tolerance parameter is a thing
somebody eventually widens.

## The round is derived, never asserted

chain-beacon.md had to write a *rule* — read the first block whose timestamp
is at or after the epoch boundary — and then note that only a chain holder can
tell whether the rule was followed. Under drand the same rule is arithmetic
every reader already has:

```
round(E) = ceil((E · epoch_seconds − genesis) / period) + 1
```

the first round at or **after** the boundary of epoch `E`, clamped to round 1
for a boundary at or before genesis (not hypothetical: `CAIRN_EPOCH_SECONDS=1`
demos start at epoch 0).

`ceil` and not `floor`, and that is the security property rather than an
off-by-one. A round at or *before* the boundary was published before the epoch
opened, so a committer in the previous epoch held it while their commitment
hash was still theirs to grind — the thing `BeaconOutOfEpoch` exists to stop.
It is invisible at the network's own parameters, because 600 and 1692803367 are
both divisible by 3 and every boundary lands exactly on a round; it stops being
invisible under `CAIRN_EPOCH_SECONDS`, which every demo script here sets to
seconds. So `block` stops being provenance an operator asserts
and becomes a value every auditor re-derives, and a mismatch is an audit fault
in both implementations. The operator's choice of *which draw to use* — the
thing the Ethereum rule existed to remove and could not prove it had removed —
is gone rather than constrained.

What each auditor can check, which is the table chain-beacon.md wrote and the
line this note moves:

| | `ethereum` beacon | `drand` beacon |
|---|---|---|
| the order follows from the recorded value | log alone | log alone |
| it was drawn in the epoch it orders | log alone | log alone |
| there is exactly one | log alone | log alone |
| **`block` is the draw this epoch names** | an Ethereum node | **log alone** — arithmetic |
| **`value` really is that draw** | an Ethereum node | **log alone** — one pairing against a key in `src/drand.rs` |

The bottom two rows are the ones that moved, and they moved out of the "someone
else checked" column entirely. `cairn audit` on a log with no network access
now re-derives every claim a `drand` beacon makes about itself.

One operator-facing consequence, since it will otherwise be found the hard way:
the round moves with `CAIRN_EPOCH_SECONDS`, because the epoch does. A log
written under a one-second demo epoch reports round mismatches when audited at
the default length — the same way every other epoch-derived check behaves, and
what `Node::epoch_length_report` already exists to explain. Deriving the round
from the constant while the epoch came from the override would be worse: it
would pin a round to a boundary that does not exist.

## `value` carries the signature, not the randomness

drand publishes both a `signature` and `randomness = SHA256(signature)`.
Recording the randomness is the obvious choice and it is wrong: it is a hash of
the only thing that proves it, so a record carrying it is unverifiable by
construction, which is the property we are here to fix.

So `value` is the signature, in hex. That costs nothing, because `value` is
opaque to the rules engine — fed to `partition::beacon` as a string exactly as
the epoch-chain head was — so no field is added, no digest moves, and all 448
conformance vectors reproduce untouched. The record stops being a claim about
a value and becomes the value's own evidence.

One thing worth stating so nobody rediscovers it as a bug: a compressed G1
point's leading byte carries format flags, so the hex is not uniform in its
first few characters. It is HMAC key material and then a SHA-256 preimage, and
48 bytes with ~381 bits of entropy in them is not improved by being
prettier. The bias is real, visible, and irrelevant here — but it *would*
matter to anyone who took `value` for a uniform random string, so: it is not
one.

## The timing rule stays, and the tempting relaxation is wrong

Because the round is a function of the epoch, a beacon fetched late is the
same beacon. Nothing an operator learns between the boundary and the fetch
changes which round they are allowed to record, so the grinding argument that
motivates `BeaconOutOfEpoch` appears not to need the rule any more, and
dropping it would buy real liveness: a node whose relays were unreachable at
the boundary could fill the epoch in afterwards instead of losing it to the
fallback.

Do not, while the fallback exists. An operator who may append the beacon after
reading the reveals cannot choose its *value*, but can still choose **whether
to append it at all** — and the fallback means not appending is not an error,
it is the old, grindable, epoch-chain ordering. That is a free 1-of-2 choice
over who gets paid first, taken with full knowledge of both outcomes, which is
strictly worse than the residual gap chain-beacon.md already documents.

The relaxation becomes safe only if a beacon is *mandatory* for an epoch to
settle, and chain-beacon.md explains why it is not: refusing to settle a closed
epoch that has none would strand its claims. So the rule stays as it is. This
section exists because the relaxation is the first thing anyone will propose
after reading the section above it.

## What is not built: the fetch, and why it is not in the binary

`tests/cipher_policy.rs` fails the build if a TLS crate enters the dependency
tree, and its module docs name this exact scenario:

> nobody adds AES on purpose, they add a crate that wants `aes-gcm` for one
> field, or a HTTP client that pulls in `rustls`

An HTTP client is how you fetch a drand round, so the fetch stays outside the
binary — which is where chain-beacon.md already put it, for the different and
better reason that fetching is not a rules-engine job. `scripts/drand-beacon.sh`
does it with `curl` and pipes the result into `cairn beacon --drand-signature`.

The script queries several independent relays and stops if they disagree, and
it is worth being precise about what that is and is not. It is **not** the
security check: `cairn beacon` verifies the pairing before it writes anything,
so a lying relay is refused by the rules engine and the script cannot launder a
forged value into a log. The relays are queried for *availability* — any one of
them can be down or behind — and disagreement stops the run because it means
something is wrong with a public good and a person should hear about it, not
because recording the wrong answer would be dangerous. It would be refused.

## The dependency, and the doctrine it bends

Checking a quicknet signature needs BLS12-381 with RFC 9380 hash-to-curve:
`e(sig, -g2) · e(H(round), pk) == 1`. It was taken. Three things had to be true
first, and the third is the real one.

**Pure Rust.** `blst` is faster and compiles C, which would put a `cc` in the
graph and end the static musl build `release.yml` ships. So `bls12_381` in the
primary — `default-features = false` to drop `bitvec`, which nothing here
needs.

**One SHA-256, not two.** The crate's own `ExpandMsgXmd` is generic over
`digest` 0.9, and reaching it would mean a second SHA-256 implementation in a
crate that hashes for record identity. So `expand_message_xmd` is written out
in `src/drand.rs` over the `sha2` already present — forty lines of RFC 9380
§5.3.1, pinned to the RFC's own vectors, including the oversize-DST branch this
crate never takes. Same bargain as the in-crate Shamir implementation: a path
that decides who gets paid should be auditable where it is used. The `digest`
0.9 that the feature gate drags in is compiled and called by nothing, and that
cost is written in `Cargo.toml` rather than left to be found in `cargo tree`.

**And then the doctrine problem.** `src/crypto/mod.rs` removed `x25519-dalek`
rather than leave it unused, because "a dependency still in the tree is one the
next person can reach for", and every KEM in this crate is post-quantum on the
argument that an adversary who records now and factors later needs only
*later*. BLS12-381 is a pairing curve. It is not post-quantum.

What makes it admissible — and this needs stating, because waving it through on
"it's only a signature" is how the next one gets waved through too — is that
this signature **covers a value that is already public**. There is no secret
with a tail. An adversary who can forge a 2026 round in 2035 cannot change what
a 2026 epoch settled: that epoch closed years earlier and its batch is in the
hash chain. The post-quantum argument is about confidentiality that has to
survive, and nothing here has to survive.

That argument does **not** extend to tlock over the same curve, and the two
must not arrive together in one change.

### Two libraries, on purpose

`reference/rust` verifies with `bls12_381_plus`, not `bls12_381`.

Everywhere else the two implementations agree because they were written
separately over the same integers and strings, and two correct programs cannot
disagree about a SHA-256. A pairing is the exception. Subgroup membership and
non-canonical point encodings are where BLS libraries have historically
differed, so a signature crafted at that boundary could verify under one and
not the other. That is the one disagreement in this protocol worth a second
dependency to find, and `scripts/differential.sh` is where it would surface.

Both take the checked constructor — `from_compressed`, never
`from_compressed_unchecked` — because skipping the prime-order-subgroup test is
the standard way a BLS verifier is made to accept something it should not.

### Refused when written, reported when read, never consulted when settling

The timing and duplicate rules reach settlement: `epoch_beacon_within` skips a
beacon drawn outside its epoch, so such a record orders nothing. **The pairing
check deliberately does not join them**, for two reasons pointing the same way.

It would buy almost nothing. A beacon that orders nothing falls back to the
epoch-chain head, which is the value a sequencer can grind anyway — so
filtering converts *grinding via a forged beacon* into *grinding via the
fallback*, and the attacker is no worse off.

And it would cost the one thing this project cannot spend. Two implementations
that disagreed about whether a signature verifies would disagree about the
anchor, settle in different orders, and both audit clean: precisely the silent
fork [settlement-convergence.md](settlement-convergence.md) exists to prevent.
Off the settlement path, the same disagreement is a failing `differential.sh`
instead — loud, and in the place built to hear it.

## The VDF is the other answer, and it is also built

`src/vdf.rs` landed separately: a Wesolowski delay function over the RSA-2048
challenge modulus, recorded as a beacon with `source: vdf` and checked against
a seed derived from the log's own Merkle root. It closes the same attack from
the other side, and the two are worth holding next to each other because the
trade is genuinely different rather than a matter of taste.

| | `vdf` | `drand` |
|---|---|---|
| why a sequencer cannot grind | each candidate costs `T` sequential squarings | the draw happens somewhere they are not |
| outside dependency | none | drand's relays, for liveness only |
| who else could cheat | whoever knows the factors of RSA-2048 — believed nobody | a colluding threshold of the drand network, who learn rounds early |
| cost to produce | the full delay, every epoch | one HTTP request |
| checkable from the log alone | yes | yes |

`source` is what discriminates, in `record_beacon_with` and in the audit, so
the two coexist and an epoch still gets exactly one beacon — `cairn beacon`
refuses `--delay` and `--drand-signature` together rather than ranking them,
because silently preferring one proof over the other would be the command
choosing an epoch's settlement anchor on the operator's behalf.

If the network ever decides it wants no outside dependency at all — which is
[anchored-time.md](anchored-time.md) recommendation 3, still open — the VDF is
the answer and this note is the one that gets dropped. Nothing here argues
otherwise. What drand buys in the meantime is a beacon that costs an HTTP
request rather than most of an epoch's compute, on a network where a node is
meant to be spending its cycles on the objectives.

## tlock is a different decision, and a later one

Timelock encryption falls out of an unchained beacon: encrypt to round *R* with
the round number as an identity, and the decryption key is that round's
signature, which the network publishes on schedule and nobody can produce
early. That is aimed squarely at the blocker in
[embargo-release.md](embargo-release.md):

> The collusion window grows linearly with the embargo length, which is the one
> parameter an embargo exists to make large.

It grows because shares are KEM-sealed to a committee drawn at *commit* time
and rotating them needs `K`, which the premise says is gone. tlock has no
per-ciphertext committee to freeze, and drand reshares its own group behind a
fixed public key, so the exposure does not scale with the embargo. The doc's
central objection dissolves.

The trade is the one named above, and it lands differently in each of the three
confidentiality classes:

| class | tlock | why |
|---|---|---|
| `embargoed` | fits | the plaintext is public at the deadline anyway, so harvest-now-decrypt-later buys an adversary a date that was already coming |
| `sealed` (never public) | does not apply | a confidentiality guarantee with no expiry is exactly the case the PQ doctrine was written for |
| hybrid — tlock **and** a committee | possible, and self-defeating | needing both restores post-quantum safety and restores the frozen committee with it, which is the thing tlock was brought in to remove |

`src/sealed.rs` has a separate and weaker reason to want it: its committee is
drawn from the log's own peer records, so at Stage 0 it is "exactly as
trustworthy as the operator's control of that set". An external, diverse
threshold group is better than that today. That is an argument for tlock as a
*second* leg, not a replacement, and it needs its own note.

## What this does not fix

- **Partial view at drain time.** Untouched. Same tradeoff, same two honest
  options.
- **Total censorship.** A sequencer that includes nothing is unaffected by how
  the batch it never wrote would have been ordered.
- **The fallback opt-out.** Still the honest limit. Grinding is *closed* for an
  epoch with a beacon, *visible* for one without, *refusable* by a reader with
  `CAIRN_REQUIRE_BEACON=1` — three states, exactly as before.
- **Liveness.** Unreachable relays cost the epoch its beacon, not its
  settlement. `Unavailable is never Reject` applies to a randomness source too.

And one new row for [threat-model.md](../threat-model.md), because this
imports a trust assumption rather than removing one:

**A colluding threshold of the drand network learns future rounds early.** They
cannot *choose* a round — the signature is deterministic, so there is nothing to
grind — but knowing it in advance is enough for a committer to grind a
commitment hash against a value nobody else has yet, which is precisely the
attack the drawn-in-epoch rule exists to stop. Different shape from RANDAO's
proposer bias and honestly compared: RANDAO's is one bit per consecutive slot,
cheap to attempt and bounded; drand's needs a threshold of a diverse operator
set, and is worse than bounded if it ever happens. Higher bar, larger blast
radius. Mark it **partial**, mitigated by the same fallback and by nothing else.

## Status

Built, both implementations:

- `src/drand.rs` and `reference/rust/src/drand.rs` — pinned quicknet
  parameters, `round_for_epoch`, `expand_message_xmd`, and `verify`. No network
  in either. Two deliberate divergences between them: the round derivation
  (primary rounds up; reference rounds down and steps forward — invisible at
  600-second epochs, reachable in every demo), and the pairing library itself.
- `cairn beacon --orders E --drand-signature HEX` — derives `source`, `block`
  and `value`, and **refuses** `--source`/`--block`/`--value` alongside it
  rather than overriding them. `record_beacon` refuses a `drand` beacon whose
  round is not the one its epoch names, and one whose signature does not verify
  — so both are rules, not conveniences.
- `cairn drand-round [--orders E]` — the same mapping as a query. It exists so
  the fetch script does not re-derive a consensus-visible mapping in bash.
- the audit checks, in both: a `drand` beacon whose `block` is not the round its
  epoch names, and one whose `value` is not that round's signature. The pairing
  runs against the round the record *claims*, so "a real round, but not this
  epoch's" stays a separate accusation from "not a round at all".
- `scripts/drand-beacon.sh` — the fetch, outside the binary, across four
  independently operated relays, on the v1 path because Cloudflare's relay
  serves no v2 and a relay that never answers never disagrees.
- `cairn drand-verify --round N --signature HEX`, and the same on the
  reference — check a signature against the pinned key and nothing else. For an
  operator handed a beacon value, and for the section below.
- a `drand signatures` section in `scripts/differential.sh`: thirteen fixtures
  put in front of both implementations, mostly boundary cases — the point at
  infinity, infinity with the sign bit set, an x coordinate larger than the
  field, `x = p` exactly, a real signature over the neighbouring round. Both
  BLS libraries must return the same verdict on every one. No network: a
  verification test that had to reach a relay would fail when somebody else's
  server did.

Verified: the full suite plus 448 conformance vectors unmoved, `interop.sh`,
`differential.sh`, `fuzz-differential.sh`, and the three CLI demos. RFC 9380's
own expander vectors, in both implementations, against two separately written
expanders. Real quicknet rounds verify and verify for no other round, under
both pairing libraries. A live round was fetched from all four relays and
recorded end to end; both implementations audit the resulting log clean and
derive the same Merkle root, and both report it when the round or the value is
edited by hand.

Not built:

- [ ] the daemon (`cairn p2p` / `cairn run`) drawing one per epoch on a timer — inherited from
      chain-beacon.md and unchanged by any of this. Until it exists, a beacon
      is something an operator runs a script for, and an epoch whose script did
      not run keeps the fallback.
- [ ] tlock, embargo, and the note that has to argue for them separately.

Not a code question, and still open:

- [ ] whether the network should depend on an external beacon at all —
      [anchored-time.md](anchored-time.md) recommendation 3. Everything above
      makes the mechanism strictly better than the status quo under either
      answer; none of it makes the choice.
