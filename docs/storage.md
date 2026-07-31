# Local storage

Where a node's data lives, who can read it, and how big it is allowed to get.

```sh
proofwork keygen                                  # 32-byte key at ~/.proofwork/key, 0600
proofwork --data-dir /Volumes/ext/pw post obj.json # data where you want it, sealed
proofwork --data-dir /Volumes/ext/pw store status
proofwork --data-dir /Volumes/ext/pw --max-size 20GB store gc
proofwork --data-dir /Volumes/ext/pw sync ~/Dropbox/pw-backup
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
- **No concurrent access.** One `Ledger` handle per log, unchanged from before.
  Two nodes on one synced folder will corrupt it, and nothing here detects that.
- **No key rotation.** Re-keying means decrypting and re-sealing the whole log,
  which is a command that does not exist yet.
- **No protection from a live attacker.** Stated at the top and worth repeating:
  anyone who can run code as the operator can read the key.
- **No encryption of anything the network publishes.** By design. See the table
  at the top.
