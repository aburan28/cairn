# Local storage

Where a node's data lives, who can read it, and how big it is allowed to get.

```sh
proofwork keygen                                  # 32-byte key at ~/.proofwork/key, 0600
proofwork --data-dir /Volumes/ext/pw post obj.json # data where you want it, sealed
proofwork --data-dir /Volumes/ext/pw store status
proofwork --data-dir /Volumes/ext/pw --max-size 20GB store gc
proofwork --data-dir /Volumes/ext/pw sync ~/Dropbox/pw-backup
proofwork --data-dir /Volumes/ext/pw store rekey    # fresh key, same root
```

## Encryption at rest

### What it defends against, stated narrowly

A node's data directory ends up in places its operator did not think hard about:
a cloud-synced folder, a laptop backup, an external drive, a machine that gets
sold. `proofwork sync` exists precisely to put a copy somewhere else, which makes
the question urgent rather than theoretical. Encrypting at rest makes those
copies inert.

It does **not** defend against an attacker with live access to a running node.
The key has to be readable for the node to work, so anyone who can run code as
the operator can read it. Claiming otherwise would be the oversold
confidentiality that [censorship.md](censorship.md) opens by warning about.

The property that makes this worth anything is therefore not the cipher — it is
that **the key can live somewhere the data does not.**

### This does not contradict public verifiability

[README](../README.md) says encrypting settled artifacts would destroy the
project, and that is still true. The distinction is *whose copy*:

| | encrypted? | why |
|---|---|---|
| artifacts the network publishes | **no** | anyone must be able to re-run the checker. Encrypt these and you are back to trusting an operator |
| a node's own copy on its own disk | **yes** | it is served decrypted on request; the ciphertext only protects the disk it sits on |

An encrypting node serves exactly what a non-encrypting one serves. Nothing about
the network's readability changes, which is why the next property matters.

### Encryption changes no hash, no root, and no audit result

The hash chain covers **plaintext**. Encryption is a storage concern; the chain
is an integrity one, and they are kept apart:

```
plain log and sealed log, same records
  → same entry hashes, same prev links, same Merkle root, same audit output
```

`encryption_changes_no_hash_no_root_and_no_audit_result` pins it. An operator can
turn this on without becoming undiffable against the rest of the network, and
`Ledger::verify_chain` needed no changes at all.

### Per line, not per file

The log is append-only, and that is load-bearing: it makes an append `O(1)` and a
torn tail detectable rather than corrupting. Encrypting the file as a unit would
mean decrypt-append-reencrypt-rewrite on every record — `O(n)` per append, a full
rewrite window in which a crash loses everything, and the end of "entry *n* is at
line *n*".

So each line is sealed on its own:

```
pwenc1:<nonce hex>:<ciphertext hex>
```

Two details are doing real work:

- **The AEAD associated data binds the line's position.** Without it, ciphertext
  lines are independent blobs an attacker could reorder, delete from the middle,
  or splice in from another log — and every line would still decrypt. The chain
  would catch it *afterwards*, and only if somebody ran `audit`. Binding the
  index makes it a decryption failure at the exact line.
- **Nonces are random, not derived from the index.** Deriving them would be
  smaller on disk and is a trap: truncate a log and append again — a crash, a
  restore, a resumed sync — and index 12 is reused under the same key.
  ChaCha20-Poly1305 does not merely leak under nonce reuse, it collapses.

### Keys

```sh
proofwork keygen                      # bare key, 0600
proofwork keygen --passphrase         # wrapped with argon2id
```

The default location is `~/.proofwork/key` — **outside the data directory, on
purpose.** The default has to be the safe one, because the unsafe one is
invisible: a key beside its ciphertext looks fine right up until the directory is
synced somewhere else, and then it was never encryption at all. `keygen` prints a
warning if you put it inside anyway, and `sync` refuses to copy it.

A passphrase is supplied through `$PROOFWORK_PASSPHRASE` or `--passphrase-file`,
never a prompt. Reading one without echoing it needs terminal control this crate
has no dependency for, and echoing a passphrase into shell history is worse than
not offering the option.

Argon2id at 64 MiB / 3 passes, with **the cost parameters stored in the file**, so
raising the defaults later does not orphan key files written today.

**There is no recovery path.** Lose the key and the log is unreadable. That is the
design, and `keygen` says so.

### Converting an existing log

```sh
proofwork store encrypt
```

Verifies the chain first (sealing a broken log would bake the breakage into
ciphertext), writes a new sealed file, **reads it back and compares every entry
and the Merkle root**, and only then swaps it in. The plaintext original is
renamed to `<log>.plaintext.bak` rather than deleted — this command must not be
able to destroy your only copy — and you are told, loudly, to remove it yourself.

### Rotating the key

```sh
proofwork store rekey
proofwork store rekey --new-passphrase-file ~/new-phrase   # and wrap the new one
```

Without this, rotating means decrypting the log by hand, generating a key,
re-encrypting, and swapping files: four destructive steps with the plaintext of
the whole log on disk in the middle. An operator who suspects their key has
leaked is exactly the operator who should not be improvising that at 2am.

The order below is chosen so that **no step leaves the store unreadable**, and
the plaintext never lands:

1. The new key is generated *in memory*. Nothing on disk has changed.
2. The log is re-sealed into `<log>.rekeying`. A crash here leaves a file nobody
   holds the key for — garbage, removed by the next run.
3. That file is reopened and required to re-derive the same entries and the same
   Merkle root. This is the proof, and it happens before anything moves.
4. `<key>` is renamed to `<key>.previous` and the new key written in its place.
   A failure here puts the old key back.
5. `<log>.rekeying` is renamed over `<log>`. A failure here puts the old key back
   too, so the untouched log still opens.

**The old key is kept; the old ciphertext is not** — the reverse of what `store
encrypt` does, and for a reason. `store encrypt` keeps the plaintext original
because it is the only copy of the data. Here the new file has already been
proved to hold the same entries under the same root, so keeping the old
ciphertext would only leave a copy readable by the key you are retiring. The
*key* is kept, at `<key>.previous`, because copies made before now — a `sync`
mirror, a backup, an external drive — are still sealed under it, and this command
cannot see them. It is never overwritten: a second rotation refuses while it is
there.

`--new-passphrase-file` is separate from `--passphrase-file` on purpose. The
commonest reason to rotate is that the old secret is suspect, and a command that
could only reuse it would be no help in the case it exists for. Give both to
change a passphrase, one to add or drop one; dropping one is a downgrade and is
said out loud.

Two things it will not do. It refuses a **plaintext** log rather than encrypting
it sideways — `store encrypt` is the command that converts a log, on purpose and
with its own warnings. And it refuses a log that does not `verify_chain` under
the current key, because re-sealing a broken log under a key whose predecessor is
about to be set aside turns a diagnosable problem into an archaeological one.

An empty or absent log rotates the key alone. Otherwise there would be no way to
rotate before the first record: `keygen` refuses to overwrite, which is the right
answer for `keygen` and leaves that case with no command at all.

### Handing someone a readable copy

```sh
proofwork store export --out /tmp/public.jsonl
```

The inverse of `store encrypt`, and it has to exist. The project's central claim
is that anyone holding a copy of the log can re-derive every settled result —
and until this existed, sealing a store was a one-way door out of it. `sync`
mirrors ciphertext by design, `log` prints a summary rather than records, and the
only route left was decrypting by hand.

It writes a copy and leaves the store sealed, because the need is to hand
somebody a log rather than to stop encrypting. It verifies the chain first, reads
the copy back and requires the same entries under the same root before reporting
success, and **refuses to overwrite** — the destination is by definition
somewhere you are about to share, so a silent overwrite would be a way to lose a
log to a typo. When the source was sealed it says out loud that the copy is not.

`scripts/rekey-demo.sh` is the end-to-end version of both commands: it rotates a
real store, then exports it and has the *independent* reference implementation
audit the result and agree on the root. That is the strongest available statement
that rotating a key changes every byte on disk and moves no record.

### What encryption covers, and what it does not

The log is sealed. Nothing else is, and that is a decision rather than a default.

The threat is the narrow one stated at the top: a copy of the data directory
reaching somewhere the operator did not intend. What sealing buys is that the
copy is inert.

| | sealed? | why |
|---|---|---|
| `log/` | **yes** | a stolen disk would otherwise yield the node's whole operating record in one readable file |
| `.proofwork/blobs/` | no | every byte *and every name* is something this node hands to any peer that asks. `p2p::code` serves them on request; the name is the content address the objective itself declares |
| `.proofwork/shards/` | no | erasure-coded pieces of a blob the network publishes, filed under that blob's digest. `k` of them *are* the blob, and the blob is public. See [shards.md](shards.md) |
| the `--population` file | no | gossiped candidates were shared with peers on purpose |
| `cache/`, `tmp/` | no | reclaimable by construction — a local copy of something fetchable, and scratch |

Note the asymmetry between the last two and eviction. Blobs and shards are both
plaintext, and only one of them is reclaimable: dropping a blob costs a
re-download, dropping the `k`-th surviving shard costs the blob. Shards are not
under `cache/`, so they are classified pinned and `store gc` refuses rather than
deletes.

**The residue, stated rather than waved away.** The set is not the contents. An
adversary holding the disk learns *which objectives this node works on* without
having to ask a peer and be observed doing it, and that difference in cost is
real. [threat-model.md](threat-model.md) carries it as not handled.

Closing it is possible and was rejected on the merits. Filing blobs under
`HMAC(key, address)` instead of `address` would hide the set while keeping O(1)
lookup — at the cost of the property that makes the store trustworthy in the
first place: *the name is the hash*, so a read re-hashes and refuses bytes that
do not match the name they were filed under, and integrity needs no second record
to keep in sync. An encrypted name means an index, and an index is exactly that
second record. Paying for it to hide a fact any peer will confirm on request is a
bad trade.

**The decision is checked, not just written down.** A decision that lives only in
prose decays the first time somebody adds a file, so
[`store::exposure`](../src/store/exposure.rs) classifies every file in a store as
sealed, plaintext for a stated reason, a key that should not be there, or
*unaccounted for*. `store status` reports the last two and **exits 1**:

```
at rest log sealed (1.7 KiB); 4.2 KiB plaintext by decision -- blobs, shards, cache, tmp
```

```
at rest log sealed (1.7 KiB); 0 B plaintext by decision -- blobs, shards, cache, tmp; 88 B UNACCOUNTED FOR
        KEY INSIDE THE STORE: /srv/pw/cache/notes.txt
        unaccounted plaintext: /srv/pw/inference-receipts.json
        Each is readable on any disk holding this directory.
        A key here makes everything beside it readable too, which
        is not encryption at all. Move it out of the store.
```

A future feature that writes plaintext state into a data directory trips this
instead of slipping past, and whoever adds it has to either seal it or put it in
the table above with a reason. Keys are found by **content, not filename** — the
same rule `sync` applies, and for the same reason.

## A data directory of your choosing

```
<data-dir>/
  log/proofwork.jsonl    PINNED       never evicted
  cache/                 RECLAIMABLE  evicted under pressure
  tmp/                   RECLAIMABLE  always safe to drop
```

`--data-dir`, or `$PROOFWORK_DATA`. **Not adopting it changes nothing**: without
it, the log is still a bare `proofwork.jsonl` in the working directory, and
`--log` / `$PROOFWORK_LOG` still override everything. Quietly relocating an
existing operator's log on upgrade would be the worst possible way to introduce
this.

## Blobs: the bytes an objective pins by hash

An objective commits to its checker by digest, and that digest is part of the
objective's id. The digest used to be a *check* on a file the operator already
happened to have, at a relative path under `--root`. So two nodes whose roots
differed disagreed — one Accepts, the other returns Unavailable — and "anyone
can re-derive every settled result from nothing but a copy of the log" quietly
needed a copy of the verifier tree as well.

[`src/blobs.rs`](../src/blobs.rs) closes that: the digest is a *name*, blobs live
in `.proofwork/blobs`, and `blob ls | need | publish | gc` is the operator's view
of what the log pins and what is missing. **The name is the hash**, so reads
re-hash and refuse bytes that do not match the name they were filed under, and
integrity needs no second record to keep in sync.

**At-rest encryption covers the log, and only the log — decided, not defaulted.**
See [the boundary](#what-encryption-covers-and-what-it-does-not) below for the
reasoning and for the check that keeps it honest.

A blob that is present but *corrupt* is `Unavailable`, never `Reject` and never
`INVALID_SPEC`: a damaged local cache is a fact about that disk, and letting it
refute honest work would be the same mistake as letting a missing Lean toolchain
refute a proof.

### Moving one between peers

There are two paths, against the same store, and they overlap:

- `p2p::code` moves a pinned blob **whole** over the existing McEliece session.
  This is what the daemon uses, and at `blobs::MAX_BLOB_BYTES` — 1 MiB — it is
  adequate.
- [`src/swarm/`](../src/swarm/) moves one in the BitTorrent shape: pieces, a
  manifest of piece hashes, bitfields, rarest-first, choking, endgame. Sized for
  artifacts the 1 MiB cap does not currently allow.

A third thing exists beside them and is not a transfer path:
[`src/shards/`](../src/shards/) splits a blob so that **no holder needs all of
it** — any `k` of `k + m` shards rebuild it, at `(k+m)/k` on disk against the
`f+1` replication charges for the same tolerance. What makes that safe rather
than merely cheap is a Merkle commitment per chunk, so a corrupt shard is caught
and *named* before it enters the linear combination that would otherwise smear
it across every output byte. See [shards.md](shards.md), including what is
deliberately not built: nothing moves a shard between peers yet.

What both get for free is the part BitTorrent cannot do: the digest an objective
already commits to *is* the swarm id, so there is no tracker and nothing to sign.
A manifest arrives from a stranger and is checked against a digest the log fixed
before the transfer started.

```sh
# On the node that has the code:
proofwork blob serve --identity transport.json --listen 0.0.0.0:9900
#   … prints an {addr, public} endpoint. The key is 261,120 bytes of Classic
#   McEliece public key, which is why a relayed peer record carries its 32-byte
#   id instead and something has to complete the hint before a dial.

# On the node that has only the log:
proofwork blob fetch --identity transport.json --peer seed-endpoint.json
```

`scripts/blob-demo.sh` runs both sides and then verifies a claim with what was
fetched. It is in CI because this path went a long time with **no caller in any
shipped binary**: `swarm::tcp` was complete, encrypted and end-to-end tested,
and a subsystem tested only against itself agrees with itself about conventions
nobody else uses. Two bugs were sitting in the seam, and neither was reachable
from either side's unit tests:

* `Handshake::encode` wrote a content address bare and `decode` returned it
  `sha256:`-prefixed, so the two ends of a session held different strings for
  the same blob. Every test used the prefixed spelling its own helpers produced;
  every *real* caller holds the bare one, which is what `blobs::address` and an
  objective's `checker_sha256` produce. Bare could never fetch anything, and the
  failure surfaced as "no peer could be reached" — which reads like a network
  fault and is not one.
* A blob's filename *is* its hash, so it never ends in `.py`, and Python's
  `spec_from_file_location` returns `None` for an extension it does not
  recognise. The content-addressed fallback — the entire reason this module
  exists — could not load a single fetched checker, so a node that fetched one
  answered `unavailable` on every claim: exactly the failure blobs were built to
  remove.

[discovery.md](discovery.md) is how a node finds a peer it was not given.

## The size cap

```sh
proofwork --max-size 20GB store gc
proofwork --max-size 20GiB store status
```

Both `GB` (10⁹) and `GiB` (2³⁰) are accepted and mean different things. A cap that
silently picked one would be off by 7% at the gigabyte — a real amount of
somebody's disk.

### The log is never evicted

This is the whole design. A size cap on a store holding the only copy of a
hash-linked log is an instruction to destroy evidence, and "delete the oldest
thing" would eat the log first, because the log *is* the oldest thing and the one
file that cannot be re-fetched.

So eviction only ever considers reclaimable content, and when that is not enough
the answer is a refusal naming the pinned bytes in the way:

```
error: store limit of 100 B cannot hold 1.8 KiB of data that must not be deleted
(the log and anything beside it). Raise the limit or move the store; proofwork
will not prune a hash-linked log to fit
```

**A cap smaller than your log stops your node; it does not prune your log.** The
refusal happens *before* anything is deleted, so a cap that cannot be met does
not cost you your cache on the way to failing.

Anything under a directory this module does not recognise is classified pinned.
A file it has never heard of is one whose loss it cannot reason about, so it does
not get to delete it.

### Blobs the log needs are pinned too

A blob is reclaimable by construction — it is named by its content, so losing one
is a re-download and never a lost record. That stops being true the moment an
objective in the log pins it: evicting the only local copy of an evaluator turns
this node into one that answers `Unavailable` for work it is paid to check, which
under availability sampling is a slash rather than an inconvenience.

Deliberately **not** a third class. The pin set moves individual blobs across the
existing line, so the rule stays sayable in one sentence:

> **A blob is reclaimable exactly when nothing needs it.**

`store status` and `store gc` compute the set from the log, and a cap that cannot
be met without one of those blobs gets the same refusal the log gets. **Every
posted objective counts, settled or not** — `audit --rerun` re-verifies settled
claims, so a node that dropped an evaluator when its objective closed would keep
the ability to earn and lose the ability to prove. The cost is that the set only
grows.

A log that cannot be read is not treated as "nothing is pinned". That answer would
let `gc` delete an evaluator on the strength of having been unable to check
whether anything wanted it, so it is a refusal instead.

### Eviction order, and what it costs

Oldest modification time first — not least-recently-*used*, because `atime` is
disabled or lazily updated on most modern filesystems, so a policy built on it is
built on a field that does not move.

The policy is age-ordered, not best-fit, so it can free more than the strict
minimum. That is the honest cost: the alternative would evict newly written
content ahead of stale content, which is backwards for a cache.

**What eviction costs is not disk, it is exposure.**
[node-incentives.md](node-incentives.md) models a node challenged to produce a
Merkle path against a published root: evict the content and the challenge fails,
and in a network paying for availability that is a slash. So `store gc` names
every path it removed rather than printing a byte count, and says:

```
note: evicted content can no longer answer an availability challenge.
```

The cap is a risk setting as much as a disk setting.

## Sync

```sh
proofwork sync ~/Dropbox/pw-backup
proofwork sync /Volumes/backup --prune --dry-run
```

One-way, idempotent, resumable. A file whose size and mtime match is left alone,
so a second run over an unchanged store copies nothing and an interrupted run
resumes rather than restarting. Size-and-mtime rather than hashing every file,
because hashing a hundred gigabytes to learn that nothing changed is why people
stop running their backups — and the case it could miss is one `audit` catches.

That means the copy has to **keep the source's modification time**, which
`fs::copy` does not do: it copies contents and permissions and says nothing about
timestamps. On Linux the destination lands with *now*, so nothing ever matches
and every run recopies the whole store; macOS's `copyfile` happens to carry the
timestamp across, which is why this was invisible until CI ran on ubuntu. The
timestamp is now set explicitly, and a destination filesystem that refuses one is
counted and reported rather than silently turning an incremental mirror into a
full one.

Three things it does that `cp -r` does not:

**It never decrypts.** It copies bytes and has no field to put a key in.

**It refuses to carry the key.** A key copied beside its ciphertext turns the
whole scheme into an elaborate way of storing plaintext, and it is a mistake that
looks like working software because everything still opens. Key files are
detected by **content, not filename** — somebody who renamed their key to
`notes.txt` is exactly who this has to catch.

**It withholds plaintext backups.** `store encrypt` leaves `<log>.plaintext.bak`
behind so it cannot destroy your only copy — and mirroring that file to a cloud
folder undoes the conversion with the very file that made it safe. This was a
real bug in the first draft, caught by running the two commands in sequence, and
`a_plaintext_backup_from_store_encrypt_is_never_mirrored` is the regression test.

Pruning is opt-in. A mirror that prunes by default turns a mistyped path into data
loss at the destination.

Mirroring an unencrypted store **warns rather than refusing** — it is the
operator's call, and refusing would push them toward `cp -r`, which has no
opinion at all.

## What this does not do

- **No integrity guarantee at the destination.** `sync` copies; it does not
  re-verify. Run `audit` against the copy, which is a one-line command and the
  only thing that actually proves the backup is good.
- **No cross-machine locking.** `Ledger::open_exclusive` takes an advisory lock
  that binds writers on one machine; two machines appending to one log over a
  synced folder or NFS are outside what an advisory lock promises, and nothing
  here detects it.
- **No rotation of anything but the log.** `store rekey` re-seals the log,
  because the log is the only thing at-rest encryption covers. The blob store and
  the `--population` file were never sealed — see the paragraph above on what
  that leaks.
- **No protection from a live attacker.** Stated at the top and worth repeating:
  anyone who can run code as the operator can read the key.
- **No encryption of anything the network publishes.** By design. See the table
  at the top.
