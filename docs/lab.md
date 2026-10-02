# The lab: a replicated research workspace

**Status: built** — `src/lab/`, `cairn lab …`, `cairn lab mcp`,
`tests/lab.rs`, `scripts/lab-demo.sh`, and the environment recipes in
`examples/lab/`. What is *not* built is listed at the end, not implied.

The ledger (`src/ledger.rs`) is where results are **settled**: one sequencer,
a hash chain, verifiers anyone can re-run, money. The lab is where research
**happens before that**: goals, hypotheses, protocols, run outputs, reviews,
task leases and messages between the agents doing the work. Different job,
different consistency requirement:

| state | writers | needs | mechanism |
|---|---|---|---|
| settlement — who was paid for what | one sequencer | total order | the ledger |
| population — candidates worth mutating | everyone | eventual convergence | `gossip.rs` |
| **workspace — records, leases, messages, runs** | **every agent, concurrently, offline** | **eventual convergence, every conflict visible** | **`lab/`, an op-based CRDT** |

Nothing in the lab moves money, settles a claim, or changes what the ledger
derives. A lab result reaches the ledger the way anything does: somebody posts
an objective or a claim, and a pinned verifier decides. The lab is the notebook;
the ledger is the journal.

## Why not git

The crypto-autoresearcher program ran its shared state through git and
GitHub. Measured against what it actually needed, that bought one useful
property — content addressing — and charged for it in the four places its
`CLAUDE.md` now spends most of its words:

1. **Identifier collisions.** Concurrent worktrees minted the same id from the
   same committed state and found out at merge time, when both records were
   immutable. The program fixed it by making ids random. A CRDT does not need
   the fix: two writers can both create `X`, the lab keeps both, and says so.
2. **Merge conflicts on files nobody edited "at the same place".** The goal head
   was "the one ledger file many campaigns write", so it conflicted every time,
   and the program sharded it into write-once files to stop that. Here a mutable
   file is a multi-value register: concurrent writes become *siblings* you can
   see and resolve, never a textual merge, and a fact nobody disputes never
   conflicts.
3. **Squash merges orphaning recorded commit SHAs.** Receipts here bind content
   (sha256 of bytes), and nothing ever rewrites an op.
4. **Coordination by polling a merge digest.** Leases and messages are typed ops,
   visible to a peer the moment it syncs — not the moment a PR merges.

And git's model of *who* wrote something is an unsigned free-text field. Every
lab op is signed by an ed25519 key, and only members admitted by the space's
admins can write.

## The model

A **space** is a set of signed **ops**. The space's identity is its genesis
op's id. A replica holds a subset of the ops; **merging two replicas is set
union**, and everything a reader sees — files, conflicts, leases, inboxes, run
receipts — is a deterministic function of the set. Union is commutative,
associative and idempotent, so two replicas holding the same ops agree on
everything, whatever order they learned them in, with no rounds and no leader.
`tests/lab.rs` checks exactly that against shuffled, duplicated, partitioned
deliveries.

### An op

```json
{
  "op": {
    "type": "cairn.lab.op", "version": 1,
    "space": "sha256:…",              // absent on genesis only
    "author": "<ed25519 public key, hex>",
    "lamport": 42,
    "deps": ["sha256:…", "sha256:…"], // the heads this author had seen
    "time": "2026-10-01T20:00:00+00:00",
    "body": { "kind": "files", … }
  },
  "sig": "<ed25519 over 'cairn/lab/op/v1\n' ‖ canonical(op)>"
}
```

- **The id is the digest of the canonical `op` object** (the same encoder as
  everything else in this crate, `src/canonical.rs`). The signature is outside
  the id and over a domain-prefixed message, because `Identity::sign_value`
  is deliberately not domain separated and a lab signature must never double
  as a signature on a ledger record.
- **`deps` make the set causally closed.** A replica stores an op only after
  everything it depends on, so every stored set is a downward-closed DAG and
  `lamport` is strictly greater than every dependency's. Ordering by
  `(lamport, id)` is therefore a total order every replica computes
  identically and that respects causality; every fold below uses it.
- **`time` is a claim, not evidence.** It is what a lease's expiry is measured
  from, and a reader's clock is what it is compared to. It never orders
  anything.

### Bodies

| kind | carries | semantics |
|---|---|---|
| `genesis` | name, founding members, policy | creates the space; its id is the space id |
| `members` | admit `{key, roles, peers}`, revoke `key` | admins only; see *Membership* |
| `policy` | `write_once`, `mutable`, `ignore` path globs | admins only; latest in `(lamport, id)` order wins |
| `files` | entries `{path, blob \| null, size, exec, pred}` | one multi-value register per path |
| `doc` | `doc`, fields `{key, value, pred}` | one multi-value register per `(doc, key)` |
| `claim` | `task`, `holder`, `ttl` | a lease; see *Leases* |
| `release` | `claim`, `outcome` | ends a lease; only its author or an admin |
| `msg` | `to`, `from`, `subject`, `body`, `refs` | a message to role addresses (`coordinator`, `all`) |
| `ack` | `msg`, `as` | marks a message handled by one address |
| `env` | `name`, `tree`, `manifest`, `pred` | names an execution environment by its tree digest |
| `run` | the run receipt, plus `files` entries for its outputs | an execution, atomically with what it produced |

### Registers: how a conflict stays visible

A file is a **multi-value register**. An entry names the entries it replaces in
`pred` (`"<op id>#<index>"`). The register's value is every entry that no other
entry replaces. One value is the normal case. Two or more means two writers
changed the same thing without seeing each other's change, and the lab reports
it as a conflict until somebody writes an entry whose `pred` names both.
Identical bytes from two writers are not a conflict. A `null` blob is a
deletion and conflicts with a concurrent edit like any other value.

`checkout` writes one value per path so tools that read files keep working —
the winner is a content value over a deletion, then the highest
`(lamport, id)`. Every other value goes next to it as
`PATH.lab-conflict-<id>`. A deterministic winner is a display rule, not a
resolution; `cairn lab conflicts` lists what is still open.

### Write-once paths

The research program's records are immutable: corrections supersede by adding a
file, never by editing one. The space's policy encodes that. A path matched by
`write_once` (and not by `mutable`) accepts only entries with an empty `pred`
and a blob; anything else is excluded and reported, never applied. Two
different first writes to one write-once path — the identifier-collision case —
are a conflict that stays open until a human decides, because nothing can
"supersede" an immutable record. `ignore` paths never enter the space at all
(`knowledge/INDEX.md`, `dispatch_plan.json`: generated, and the program already
refuses to commit them).

### Membership

Genesis names the founding members and their roles: `admin` (membership and
policy), `writer` (everything else), `reader` (sync only). A `members` op by an
admin admits or revokes.

- **An op is authorised by its causal past.** Its author must hold the needed
  role in the membership state folded from the membership ops among its
  ancestors. That is decided once, at ingest, and is the same on every replica,
  because the causal past of an op never changes.
- **Revocation also reaches sideways.** A revoked key could otherwise keep
  writing by choosing `deps` that never include the revocation. So once a
  revocation of `K` is in the set, every op by `K` that is *not* an ancestor of
  that revocation is excluded from every view. Concurrent mutual revocations
  are applied in `(lamport, id)` order and an already-revoked author's
  revocation is void, so the outcome is deterministic. This makes the views
  non-monotone — an op you saw can disappear when a revocation arrives — and
  that is the honest price: until the revocation reaches you, you cannot know.

### Leases

`claim` takes a task for `ttl` seconds from the claim's own `time`. A reader
evaluates every claim on a task at *its* `now`: released (with outcome),
expired, or live. Among live claims the holder is the first in `(lamport, id)`
order, so two agents who claimed concurrently learn after one sync which of
them holds it — the loser's claim reads `contended`, not `held`. A `completed`
release closes the task. This is advisory scheduling, exactly as the program's
`goal_lanes.py` claims were: a lease is never evidence and never a permission.

## Sync

Sync is set reconciliation. Each side hashes its op ids into 256 buckets by
first byte; buckets that agree are skipped, the ids of buckets that differ are
exchanged, and each side sends the ops the other lacks in `(lamport, id)` order
— which is causal order, so the receiver can apply them as they arrive. Then
each side fetches the blobs its valid entries reference and does not hold, in
chunks, and checks every chunk sequence against the address before keeping it.

Three carriers, one algorithm (`src/lab/sync.rs` writes it against a `Peer`
trait with three implementations):

- **Another directory** — `cairn lab sync --dir PATH`. A USB stick, an NFS
  mount, a cloud-synced folder.
- **A bundle file** — `cairn lab bundle --out F` / `cairn lab unbundle F`.
  Anything that moves a file moves a space, including email and, if you
  insist, git.
- **The network** — `cairn lab serve` and `cairn lab sync --peer
  ID@HOST:PORT`, over the same transport as `cairn p2p`: Classic McEliece to an
  AEAD channel, both ends authenticated. The server answers only peers whose
  transport id a member lists under `peers` (or an explicit `--allow`). Ops are
  verified on arrival regardless of which peer carried them, so a peer that may
  sync but not write can still relay a writer's ops — and cannot forge one.

## Execution environments

An **environment** is a root filesystem, identified by a digest over its tree:
every path, its type, its permission bits, its size, and the sha256 of its
bytes or its link target — not owners or timestamps, which change on every
extraction and say nothing about what a program computes. Importing one
(`cairn lab env import NAME --docker IMAGE | --podman IMAGE | --tar FILE |
--dir DIR [--move]`) puts it under `.cairn-lab/envs/<digest>/rootfs` and writes
an `env` op naming it, with a manifest blob recording where it came from (the
image id and repo digests, or the tarball's hash), the environment variables
and working directory it declares, and any `--env`, `--workdir` or `--note`
given. `--move` renames a tree built in place instead of copying gigabytes. A
peer that rebuilds the same image gets the same digest; one that does not, does
not, and nothing pretends otherwise. `cairn lab env verify NAME` re-digests the
tree on this machine.

`cairn lab exec --env NAME -- CMD …` runs a command in one:

| backend | boundary | chosen when |
|---|---|---|
| **gVisor** (`runsc`) | a user-space kernel between the program and the host; no network, read-only root, declared mounts only | `runsc` is on `PATH` and starts a sandbox (probed, like `bwrap` is) |
| **bubblewrap** | namespaces and the host kernel; same mounts, no network | `runsc` is unusable and `bwrap` works |
| none | none | only when asked for (`--sandbox none`, or `CAIRN_LAB_SANDBOX=none`), and the receipt says so; an MCP agent cannot ask |

Inputs are mounted read-only (a lab path prefix checked out to a scratch
directory, a single lab file as that file, or a host directory), one output
directory is writable (`/out`, also `$CAIRN_LAB_OUT`), `/tmp` is a tmpfs, and
the network is absent unless asked for — in which case the receipt says that
too.

**The environment's tree is never the runtime's root.** Each run gets an empty
root of its own with the environment's top-level entries bound into it
read-only, the same layout under gVisor and bubblewrap. gVisor's gofer creates a
missing mount point on the host, inside whatever directory the OCI root names,
before that root is made read-only — and through read-only binds too. Handed the
tree itself, one run with an input at `/work/x` left an empty `/work/x` in it,
and the environment stopped matching the digest every later receipt named;
`env verify` is what caught it. So a mount target at a new top-level path
(`/work`, `/in`, `/data`) is made in the run's own root; a top-level target the
environment already has *replaces* that entry rather than covering it (runsc
sorts mounts unstably, and an image's read-only `/out` once landed on top of the
run's writable one); a deeper target must already exist in the environment as
the same kind; and targets may neither repeat nor nest. Anything else is refused
before the run starts or is recorded. A wall-clock deadline kills the sandbox; a memory limit is a
cgroup limit under gVisor and a resident-set watchdog otherwise, **never**
`RLIMIT_AS` — algebra systems reserve far more address space than they touch,
and an address-space cap kills them for nothing (the research program paid for
that lesson once already).

When the command finishes, its stdout, stderr and every output file become blobs
and one `run` op records the receipt — environment name and digest, backend,
argv, mounts with their tree digests, limits, exit status or signal, timeout,
wall time — **together with** the output files as write-once `files` entries
under the publish prefix. One op, so a peer never sees outputs without the run
that produced them or a run without its outputs. A sandbox that failed to start
is recorded as `error`, never as an exit status: an infrastructure failure is
not a result, the same rule as `Unavailable` in the verifiers.

`examples/lab/environments/` has recipes: `numtheory` (PARI/GP 2.15.4 with
the SEA data, msolve 0.6.5, valgrind, python-flint, cypari2, numpy — what the
GFPN experiments need) and `sage` (the above plus SageMath 10.9 from
conda-forge at `/opt/conda-sage/envs/sage`, the path the GFPN anchor comparator
expects). `build.sh` builds either with docker; `sage/build-rootfs.sh` builds
Sage's tree without docker — micromamba run inside bubblewrap, so the conda
prefix baked into every file is the path it will run at — and holds the
gigabytes once, for `env import --dir … --move` to hand to the lab.

`cairn lab exec` exits `0` when the command succeeded; `1` when it failed, timed
out or hit its memory limit; `2` when the request was refused; and `3` when
nothing was learned — no sandbox works on this host, or the sandbox could not
start the command.

### Measured

On one 2026 cloud VM, gVisor `release-20260928.0`:

| run | wall |
|---|---|
| PARI/GP solves a 20-bit toy ECDLP, numtheory environment | 0.16 s |
| msolve solves a two-equation system | 0.21 s |
| SageMath 10.9: `import sage.all`, then `discrete_log` on a prime-order curve of order 1,001,389 | 3.1 s (2.6 s of it the import); 1.3 s under bubblewrap |
| the research program's GFPN anchor comparator, `k4a_anchor_system.py`, in `sage` | 5.1 s |

The comparator is the step that once failed a gate package with
`infrastructure_error` because its host had no Sage at the path it calls. In the
`sage` environment it ran to completion, and the four msolve systems it wrote are
byte-identical to the ones the program recorded for `RUN-GFPN-f5412a`. Both
environments still verified against their digests after every run.

## Using it for the crypto-autoresearcher program

```sh
cairn lab identity --out ~/.cairn/lab.identity.json
export CAIRN_LAB_IDENTITY=~/.cairn/lab.identity.json
cairn lab init --name ecdlp-program \
    --policy examples/lab/crypto-autoresearcher.policy.json
cairn lab commit ~/crypto-autoresearcher                 # first import
cairn lab checkout ~/work                                # anywhere else
# … the program's own tools read and write files under ~/work …
cairn lab commit ~/work                                  # signed, batched
cairn lab sync --peer <id>@host:9100                     # or --dir, or a bundle
```

`scripts/lab-demo.sh` runs that workflow end to end with two writers and checks
every step: a concurrent edit becoming a visible conflict and then resolved, an
immutable record refused, an identifier collision kept visible, a lease race,
a message, a revocation, all three sync carriers, and a run.

`commit` remembers what each file was when it was checked out, so an edit to a
mutable file supersedes *that* version — a concurrent edit that arrived in the
meantime becomes a visible sibling, not a silent overwrite. Editing a
write-once file is refused locally with the reason (add a correction instead),
before anything is signed. The memory is an index file,
`.cairn-lab-checkout.json`, at the top of the directory; add it to
`.gitignore` where the directory is also a git working tree.

Measured against the program's own records — `ledger/`, `knowledge/`, `docs/`,
`tools/` and `orchestration/` from its `main`, 20,859 files and 204 MB:

| step | wall |
|---|---|
| first `commit` (six signed ops) | 10.6 s |
| `commit` again with nothing changed | 1.4 s |
| `checkout` into an empty directory | 1.8 s — byte-identical, executable bits included |
| `verify` every signature and all 20,842 distinct blobs | 1.3 s |
| `clone --dir` a second replica | 13.7 s |
| `sync` two replicas already in step | 0.3 s |
| a concurrent edit of one goal record on two replicas | one sync, one visible conflict |

Most of the first commit and the clone is one `fsync` per blob, so an op never
names content a crash could tear; batching those is a known, unclaimed
speedup.

`cairn lab mcp` exposes the same operations to agents: read and list files,
write records, claim and release tasks, send and read messages, list
environments, and run a command in one. Every write is signed by the server's
identity, so an agent never holds the key, and every read is untrusted text
for the same reason objective statements are.

## What this does not do

- **Enforce the research program's own rules.** The lab authenticates who
  wrote what and keeps every conflict visible. Whether a hypothesis may change
  status, or who may approve a protocol, is the program's validator's job, and
  it reads the same files it always did.
- **Keep the workspace confidential at rest.** The store is plaintext on disk.
  The network carrier encrypts in transit; a bundle file does not. Encrypting
  the store with `store::atrest` is straightforward and not done.
- **Sync environment root filesystems.** They are gigabytes and rebuildable;
  their digests and manifests sync, the trees do not. Export one with `tar` if
  you must move it.
- **Make a revocation retroactive** for a replica that has not received it yet.
- **Make an environment reproducible.** The digest tells you two trees are the
  same; it cannot make two builds produce the same tree.
- **Isolate like a VM.** gVisor narrows the host kernel surface a program can
  reach to a small, memory-safe user-space kernel; it is not hardware
  virtualisation, and bubblewrap is the host kernel with namespaces.
