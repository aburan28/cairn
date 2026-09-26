# Cryptographic agility

*Every primitive here will eventually be weak, obsolete, or merely
unfashionable. The design assumes that rather than hoping otherwise.*

## The honest ladder

Agility is not one property. This crate has three layers of cryptography and
very different amounts of it at each, and claiming one number for all three
would be the useful thing to get wrong.

| layer | self-describing? | swappable? | what a swap costs today |
|---|---|---|---|
| **KEM suites** | yes — `Suite` is tagged on the wire | **yes**, additively | nothing. A new leg moves no id |
| **record signatures** | ed25519 is implied by the 64-hex submitter; ML-DSA-65 and SQIsign are extra fields, omitted when absent | the extra signatures, not the identity | replacing ed25519 moves every signed id |
| **content addressing** | in form — ids are `sha256:<hex>` | no | every id in the network moves at once |

The KEM row is the one a registry governs. Record signatures can carry a
second algorithm without moving an id; they cannot replace the first. The
rest of this document is what the other two would take, and why the answer
for the bottom one is not "swap it".

## What is built: the algorithm registry

`src/crypto/policy.rs`. A versioned statement of which suites are live, which
are leaving, and what either means for material already written.

```
Required   must be present. Structural, not security — see below
Accepted   usable for new material, verified on old
Deprecated refused for new material, still verified on old
Withdrawn  refused everywhere, history included. The emergency lever
```

### The rule that makes it safe: policy governs writes, never reads

A registry is a way to break a network if it is consulted at the wrong moment.
Deprecating a suite must not make yesterday's records undecodable — that is not
a migration, it is a retroactive fork, and every node that upgrades leaves the
network.

So **decoding never consults a policy.** `Bundle::from_value` and every other
decoder accept what they always accepted; a record that was admissible stays
admissible forever. **Producing new material does**: sealing, publishing an
identity, choosing what to encapsulate to. Those are choices still to be made.

`Withdrawn` is the single exception and is deliberately uncomfortable. It
refuses a suite historically, which *does* invalidate history, and is only
correct when honouring old material is worse than losing it — in practice, when
signatures an attacker can now forge would otherwise be honoured. Reaching for
it where `Deprecated` would do is how a registry breaks a network.

### `min_families` is the knob that answers cryptanalysis

Suites are classified by `Family` — the hardness assumption, not the label. A
bundle survives a break of one *assumption*, not one *scheme*, so counting
suites overstates how hedged it is.

The distinction is load-bearing right now: HQC is code-based and is **not** in
McEliece's family, because the 2026 Goppa attacks work by recovering a hidden
structured code and HQC has none to recover. "Both code-based" is a label, not
a correlation.

Raising `min_families` from 1 to 2 is the whole of "stop trusting any single
assumption", and it takes effect without editing a decoder. Policy version 1
does exactly that, in response to the syzygy distinguisher and the
subexponential and quasipolynomial key-recovery results that followed. None of
those is a practical break of `mceliece348864`, and version 1 is not a claim
that one is — it is the cheap half of not needing to find out.

### Version 0 exists on purpose

It records the rules as they stood before the registry did: McEliece required,
the others optional, no family minimum. Keeping it means the registry can
*describe* the past rather than pretend the network began with the current
policy — the same reason the ledger keeps superseded claims.

### Where it is enforced

- `SealedEnvelope::seal` — refuses a committee whose members failing the policy
  number `threshold` or more, because one family break then reconstructs the
  content key.
- `CommitteeKey::generate` — publishes `policy.suites_to_publish()`, so
  deprecating a suite stops new committee keys carrying it with no code change.
  Transport `PeerIdentity` is still McEliece-only (fixed hello framing); that
  gap is listed under Transport framing below.

An unknown policy version reads as `None`, never as a default. A node reading a
log written by a newer build must be able to tell *"I do not know these rules"*
from *"these rules refuse it"*; guessing between them is how one implementation
admits what another refuses.

## What is not built

### Signature agility

`submitter` being 64 lowercase hex *is* the ed25519 public key — there is no
suite tag, and the algorithm is inferred from the string's shape. Replacing
that key with a tagged format moves every signed record's id. That migration
is not done.

What is done is a second signature. A claim may carry `pq_key` and
`pq_signature` (ML-DSA-65). Both are omitted when absent, so a record written
before the field existed keeps its id, and the ed25519 signature covers
`pq_key` when it is present. Admission does not yet require the second
signature: a policy epoch that refused ed25519-only claims would fork every
log that predates it. SQIsign level 1 may sit beside both, in `sqisign_key`
and `sqisign_signature`, also omitted when absent, and only on a submitter
that is already an ed25519 key. It is not a sole signature. The
implementation is research-grade (`sqisign-rs`); there is no second
library, so the reference links that project's verifier rather than
ignoring the field.

Checkpoints were already ML-DSA-65 on their own. A claim can now carry both,
and the identity the submitter string names is still ed25519.

### Hash agility, and why replacement is the wrong frame

Every id is `sha256:<hex>`. Changing the hash moves every id in the network at
once, orphaning every citation, every funded bounty and every claim. This is the
deepest lock-in in the system and the one thing `AGENTS.md` says never to do.

The answer is not to swap it. It is to **append**:

1. Ids stay `sha256:` forever. They are names, and names do not have to be
   cryptographically current to be unique.
2. A **migration checkpoint** re-commits a log prefix under a new suite: *"every
   object reachable from state root R was re-committed under hash suite H2 and
   countersigned under signature suite S2 at time T."*
3. The old commitment is never deleted. A reader who trusts SHA-256 verifies the
   original; a reader who does not verifies the re-commitment; both agree on
   which objects they are talking about, because the *logical* id never moved.

That is §4.3's stable logical identity and §8.3's append-new-attestations, and
it is the same append-only discipline this repository already applies to
knowledge — applied to the cryptography carrying it. `src/checkpoint.rs` already
signs height, head and Merkle root with ML-DSA-65, so the object to extend
exists.

Not built: the re-commitment record, and the client rule for which commitment to
prefer.

### Transport framing

`transport::connect` still dials McEliece-only, because the hello is a fixed
`[32-byte id][96-byte ciphertext]` with no length prefix and no version field.
`PeerIdentity::accept` already reads either shape — the gap is framing, not
cryptography. See [p2p.md](p2p.md).

### Governance

The registry is a constant in one crate. §8.4 wants no single implementation
controlling it, which means the policy version belongs in the log with the same
append-only rules as everything else. Nothing here does that yet, and a registry
one party edits is a registry one party controls.

## The order these are worth doing

1. **Transport hello framing** — the only one where cryptography is already
   built and unused.
2. **Migration checkpoints** — unblocks hash and signature agility both, and
   needs no id to move.
3. **Signature suite tagging** — expensive, and cheap only *after* migration
   checkpoints exist.
4. **Policy in the log** — governance, once there is something worth governing.
