# Cairn

**Verified results as the unit of account.**

*6 October 2026. This paper describes the system in this repository. Where an
earlier note and the code disagree, the code is the authority, and the
disagreement is named here. It is not a claim that every design note has
shipped.*

## Abstract

Cairn is a research network that pays for artifacts a pinned checker accepts,
and pays nothing for time, hardware, or a contributor's say-so. The log is an
append-only sequence of content-addressed records. Anyone with a copy can
re-derive which claims settled, in which order, and for how much. Two
implementations that share no crate do that re-derivation independently, and a
frozen corpus of vectors keeps either one from quietly becoming the definition
of the format.

The network can only buy work whose outputs are cheap to check. That is the
specification, not a gap to be routed around. Ordering of payments inside an
epoch is a public hash of a beacon and the commitment that froze the artifact
before the beacon existed. Citations are the only edge that attribution reads.
Relations revise a reader's view of the literature and move no money. A
verifier that could not run says nothing about the artifact.

What follows is the mechanism, the cryptography that carries it, and the list
of things this paper will not pretend are finished.

## 1. The decision

A compute market tries to buy hours and then spends its design budget proving
the hours were real. Cairn buys artifacts. A Lean kernel accepts or rejects a
proof. An evaluator scores a program. A certificate recomputes in
milliseconds. The contributor's hardware, honesty, and model are not inputs to
the payment. The same artifact pays the same amount whether it was derived by
hand or emitted by a model.

The corollary is sharp. Distributed pretraining, a physical experiment, and a
question whose success criterion is someone's taste do not fit, because the
output is not cheap to check. Those can be funded explicitly, and labelled as
such. They are not the core.

Stage 0 is one operator and a log. It does not introduce a token, a validator
set, or a new consensus protocol. What it does provide is the property the
rest of the design is for: *anyone can independently re-derive every settled
result from the log alone.*

## 2. Records

Three records do most of the work.

An **objective** names a statement, a pinned verifier, a funder, and a reward.
Its id is the hash of its canonical bytes. Editing the checker produces a
different objective. There is no operation that changes the rules of a bounty
that already exists.

A **commitment** binds an objective, a submitter, an artifact, and a nonce,
without revealing the artifact. A **claim** opens that commitment in a later
epoch and carries the artifact, the citations, and the signature.

Every id is the digest of a canonical encoding. Absent and null are different
bytes, so an optional field is omitted when it holds its default. Adding a
field that is always emitted would move every existing id and orphan every
claim posted against a live bounty. That rule is why the post-quantum
signature fields below are absent on an old claim and present only when a
submitter actually produced them.

Canonical values have no float. Money and identity are integers. A score a
verifier returns is an integer. Two nodes that could round a float differently
would settle different amounts and both believe they were right.

The encoding is pinned by `conformance/vectors.json`, produced by a Python
implementation that no longer exists. Nothing in this repository regenerates
that file. A diff in an existing vector means an id moved. New cases are added
beside it.

`reference/rust` re-derives the same rules and does not depend on the primary
crate. Agreement on valid logs is `scripts/interop.sh`. Agreement on the
boundary — the records one implementation would admit and the other would
refuse — is `scripts/differential.sh` against `conformance/adversarial.jsonl`,
plus a fuzzer. Two nodes that disagree about admissibility disagree about what
was settled, and neither ever errors. That is the failure this split is there
to catch.

## 3. Commit, reveal, settle

A reveal must land in a strictly later epoch than its commitment. The epoch is
derived from the record's own timestamp and a length (`EPOCH_SECONDS`, ten
minutes unless `CAIRN_EPOCH_SECONDS` overrides it for a demo). It is not read
from a clock at audit time, and it is not stored. Stamping a replayed record
with the local clock puts the commitment and the claim in the same epoch, the
reveal is refused, and sync reports success while the log stops growing.

Inside an epoch, accepted claims settle in order of

```
settlement_rank = SHA-256( beacon(epoch, anchor) || commitment_hash )
```

`beacon` is the bare hex of `SHA-256("{epoch}:{anchor}")`, with no `sha256:`
prefix, because that spelling is itself an input to assignment. The anchor is
the epoch-chain head, or a `beacon` record drawn in the epoch it orders. The
rank is keyed on the **commitment hash**, not the claim id. The claim id covers
`created_at` and `cites`. The commitment does not. A submitter who could
re-stamp either of those after the anchor was public could re-roll their place
in line. The commitment hash was frozen an epoch earlier, when the anchor did
not yet exist.

`settled: false` on an accepted claim means the reveal epoch has not closed.
It does not mean the artifact was rejected. Nobody, including the operator,
chooses who in a batch is paid first.

Causal clocks and the citation DAG detect that two frontiers were advanced
concurrently. They do not order payouts. A Lamport timestamp a submitter can
choose is a lottery ticket. Settlement stays the beacon rank above.

## 4. What pays

`cites` is the edge attribution walks. The default split keeps three quarters
of a settled reward with the claim and sends one quarter upstream, divided
across the claims it cites, to a depth of six. The fraction is a rational.
The odd unit in an uneven split goes to citations in sorted claim-id order.
The sum of the shares is the amount distributed. `cairn attribute` prints
that split.

It is a report. Settlement credits the claim's submitter the gross reward.
No balance changes because of a citation. The report is the mechanical answer
to "who was named as a dependency." It is not yet income. Treating the report
as a balance would be a consensus change in both implementations, and it has
not been made.

`relations` are the other edge. They say what one accepted claim found about
another: supports, refutes, supersedes, retracts, and the rest of a small
declared set. `knowledge` reads them and derives a standing a reader can
filter. Attribution, settlement, and the frontier do not read them. If
"I refute you" paid, refutation would be a bill. If "I supersede you" moved
the frontier, it would take a bounty for the price of one append. A test
builds two logs that differ by a single `refutes` edge and requires the same
settled amounts and the same citation report.

Relations sit inside the claim's signing payload. An unsigned relation
appended to someone else's claim breaks their signature. That is what stops a
stranger retracting their work.

Once an objective has a frontier, every later submission must cite the claim
that holds it. The rule is not reserved for improvements. A duplicate artifact
verifies and mints nothing. Novelty is necessary and not sufficient: a claim
mints only against an objective whose reward was escrowed for that statement.
Minting on any novel certificate would let a grinder invent cheap problems,
solve them, and inflate the supply without bound.

An epoch comes from the record. A reward is an integer. A citation that is
not an accepted claim in the log is refused. Those are admission rules, and
they are also audit rules. A check that runs only when a record is appended
locally is a check a log imported from a peer does not have. This repository
has shipped that bug more than once. Bonds, in particular, are checked with
`spendable_within` at the entry's sequence, not against the balance at the
end of the log. An identity that was broke at entry `n` and paid at entry
`n + k` balances in total, and the bond it staked in between was money it did
not have.

## 5. Verification

The verifier is part of the objective's identity. It is pinned by hash and
runnable before anyone starts work. An objective with no checker is not
admitted: its payout would be someone's opinion.

Five kinds ship: `certificate`, `evaluator`, `statistical`, `replay`, and
`lean`. The checker runs in a jail. Bubblewrap is the default on Linux.
gVisor is opt-in with `CAIRN_SANDBOX_MECHANISM=gvisor` when `runsc` works.
macOS uses a deny-by-default seatbelt profile. No network. Writes stay in
scratch. A host without a jail, asked to require one, fails closed.

The verdicts are `accept`, `reject`, and `unavailable`. Unavailable means the
node could not run the checker. It is not a rejection. Collapsing the two
would let an attacker fail every honest submission by taking verifiers
offline. A contributor who sees unavailable retries. They do not "fix" the
artifact in response to it.

The contributor does not grade their own work. `score_candidate` runs the
pinned verifier and records nothing. The verdict that settles is the one the
node's checker returns.

Objective statements are untrusted text. A statement that tells an agent to
cite a particular claim, or to reveal a secret, is an attempt to route a
payment or extract something. The server accepts a citation only together with
a session-local capability that a frontier query or a successful submission
returned. A bare id copied out of the statement is refused.

## 6. Cryptography

Identity, for a signed claim, is still an ed25519 key. The submitter string
*is* that key when it is 64 lowercase hex characters. Replacing that spelling
would move every signed id. The migration is not done.

A claim may also carry ML-DSA-65 (`pq_key`, `pq_signature`) and, beside that,
SQIsign level 1 (`sqisign_key`, `sqisign_signature`; a 65-byte key and a
148-byte signature). Each pair is omitted when absent, and the ed25519
signature covers the public key when it is present. One field without the
other is invalid. SQIsign is refused unless the submitter is already an
ed25519 key, so it cannot be the only signature. Admission does not yet
require either extra signature. A policy epoch that refused ed25519-only
claims would fork every log that predates it, and that epoch is not in the
protocol.

SQIsign here is research-grade. The crate is not audited. Signing uses a
floating-point approximation inside LLL, which is why a seed does not pin
signature bytes and why SQIsign is not the identity. Verification, which is
what admission checks, is the integer isogeny. The reference implementation
links that project's verifier because no second implementation exists. That is
a weaker split than the BLS pair used for drand, and the paper says so.

The key-encapsulation policy (version 1) requires Classic McEliece and at
least two families. ML-KEM-768 and HQC are accepted. An unknown policy version
reads as "I do not know these rules," never as a default. Transport hellos are
still McEliece-only; the bundle can already express the other legs, and the
framing cannot.

At rest and on the wire, the AEAD is ChaCha20-Poly1305. A second construction
exists beside it: ChaCha20, Threefish-256 in counter mode, and Serpent-256 in
counter mode, XORed, with one HMAC-SHA-512 tag and a version byte. Either
stream alone is not the construction; the point of the cascade is that a break
of one cipher does not open the plaintext. It is not wired into the sealed
store. Old stores stay on ChaCha20-Poly1305, which is the property a
known-answer test has to protect: a round trip in one process passes for any
construction that is merely self-consistent. Serpent is pinned to the NESSIE
vector, Threefish to the Skein all-zero vector, and the combination's framing
to `conformance/cascade-v1-cairn.hex`.

AES does not appear. `tests/cipher_policy.rs` fails the build if an AES crate
or a TLS crate arrives transitively. The owner has allowed TLS and QUIC for
NAT traversal. That exception is for a stack that can be ChaCha20-only. The
hole-punch in the tree is a long UDP datagram shaped like a QUIC Initial,
carrying a path challenge and an observed address. It is not a QUIC
connection, and it is not a peer identity. Linking `quinn` would compile AES,
so it was not linked.

## 7. Reaching another node

A fresh node needs a way to find someone. Three mechanisms exist, and they are
not interchangeable.

Compiled seeds are dial hints. The daemon asks each one for its key and keeps
the endpoint only if the key hashes to the listed id. One seed is one
machine. A peer cache remembers who answered, so a node that has connected
once can start again with that seed down. The cache is plaintext on purpose:
the addresses are what this node already dials.

On a LAN, a multicast beacon announces the node. Off the LAN, `CAIRN_MAINLINE`
opens a UDP socket and speaks a small piece of the BitTorrent DHT:
`find_node`, `get_peers`, `announce_peer`, under an infohash of
`SHA-256("cairn/mainline/v1" || epoch)`. The hash is a meeting place. It is
not a record id, and SHA-1 is not used for one. The key rotates with the epoch
so one crawler key cannot enumerate the network forever. `CAIRN_DHT_STATIC=1`
holds the key still, which is the enumeration rotation exists to prevent, and
it is off unless set.

Two nodes that were not given each other's address learn it from a rendezvous
that stores the announce. The test uses an in-process rendezvous, so
continuous integration does not dial the public DHT. The walk asks the
bootstrap's neighbourhood and stops. It is not a full iterative lookup, and a
green test is not evidence that two nodes met on `router.bittorrent.com` with
every cairn seed down. What comes back is a dial hint. The handshake still
decides who answered. A hint that cannot complete it is never a peer.

A cairn rendezvous caps announces per key and does not evict. Eviction is how
a flood displaces an honest hint. The public DHT's own eviction policy is not
ours. A token the rendezvous did not issue does not publish an address.

## 8. Divided search

Some objectives have no frontier to move. The unit is a verified piece of a
search: a distinguished point, or, on a Koblitz curve, an orbit under negation
and Frobenius. `work_assignment` gives each node a slice of the seed space for
the epoch, as a function of public inputs. Overlap wastes compute. It does
not corrupt the result. The second claim of an orbit that was already paid
mints nothing.

An orbit is named by the least rotation of its normal-basis coordinate, so
the 262 relabellings of one class are one payment. The artifact carries eight
per-branch step counters. Those collapse the trail to one scalar, and the
checker rebuilds the endpoint with one double scalar multiplication. Without
the witness, a low-weight bit string is free to invent. With it, inventing an
orbit that passes costs a real trail.

The witness does not prove the walker used the shared branch rule. A private
rule verifies and never collides. That check is a sampled re-walk, and a
bonded attestation is what makes a lie expensive for the attestor. The
submitter, at Stage 0, posts no bond and keeps one payment if caught. That gap
is open.

The full ECC2K-130 corpus does not fit in a log. The posted objective funds a
tranche. Witnesses for the local index live under the shard store, in a
directory named by the first byte of `SHA-256(orbit)`. Two witnesses are both
kept. `OrbitIndex::collisions` reports a name once two distinct bodies are
stored. Storing the same bytes twice is a replay, not a collision. The index
does not pay, it is not on the swarm, and it is not in the log. The GPU
client that would run the search lives in another repository. Its packed
backend has not been timed with the counters in this tree, and this paper
does not invent a steps-per-second figure for it.

## 9. Sponsorship, and rails

A proposal names a target and a deadline. Pledges name units against it.
Activation is derived, the way a verdict is derived: at or before the
deadline, if the sum meets the target, each sponsor pays a pro-rata share of
the target and keeps the rest; otherwise every pledge returns in full. The
remainder under the target is handed out one unit at a time in sponsor-name
order, ties broken by input order, so two implementations cannot pay a unit
to different sponsors. Both crates implement that rule.

The function does not debit a balance. Wiring a debit that does not consult
`spendable_within` at the entry's sequence is the bug named in §4. Until that
debit exists in both ledgers, a proposal is an assurance-contract calculation,
not a movement of units.

Deposits are refused unless genesis names a rail. The default build names
none. There is no built-in currency. A log may declare an issuance, and once
it does, conservation is checked. A log that declares none does not pretend
to be scarce.

## 10. What this paper will not claim

| question | status in this tree |
|---|---|
| Can a reader re-derive a settlement from the log, on two implementations? | Yes. That is the guarantee. |
| Does a citation credit a balance? | No. `cairn attribute` reports the split. Settlement pays the submitter the gross reward. |
| Does a relation pay, or move the frontier? | No. |
| Is an ed25519-only claim refused? | No. ML-DSA and SQIsign are optional extra signatures. |
| Is SQIsign a sole signature, or audited? | No. Third leg only. Signing is not deterministic across a seed. |
| Is the sealed store on the cascade? | No. ChaCha20-Poly1305 remains the AEAD. |
| Is the hole-punch a QUIC session? | No. It is a UDP datagram. The address it learns is not an identity. |
| Do two fresh nodes find each other on the public DHT with every seed down? | Not shown. They find each other through a rendezvous the test runs locally. `CAIRN_MAINLINE` uses the same client against a public bootstrap and does not complete a full walk. |
| Does the orbit index pay a collision, or ship the corpus? | No. It reports distinct bodies under one name, on disk, off the log. |
| Does sponsorship move units? | No. The pro-rata rule is implemented and does not touch a balance. |
| Is there a token, or a deposit rail, in the default build? | No. |
| Is unavailable a rejection? | No. |

Attacks and the status of each mitigation are kept in
[threat-model.md](threat-model.md), marked handled, partial, not handled, or
unsolvable. This paper does not soften those rows. Overstating what is
defended is the failure this repository cannot afford.

## 11. Checking the paper against the tree

The sentences above are claims about code. These are the checks that correspond
to them.

- `cargo test --all-targets` and the same for `reference/rust`.
- `cairn-reference conformance conformance/vectors.json`. A changed existing
  vector is a moved id.
- `./scripts/interop.sh`, `./scripts/differential.sh`, and
  `./scripts/fuzz-differential.sh`.
- `./scripts/try-demo.sh`. One command posts, commits, waits out a real epoch,
  reveals, and settles. The reveal epoch in the log is strictly later than
  the commitment epoch.
- `cargo test --test cipher_policy`. No AES crate and no TLS crate.
- `cargo clippy --all-targets -- -D warnings` and
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked --all-features`.

A reader who wants the design at the length of a module, rather than at the
length of this paper, starts at [architecture.md](architecture.md) and
[threat-model.md](threat-model.md). The fifteen-item evaluation of what a
volunteer network still lacks is [plan.md](plan.md).
