# Submitting challenges, and where knowledge lives

Two questions that turn out to be one. An objective is only checkable if the code
that checks it can be found, and the record that pins that code by hash and the
mechanism that distributes the bytes used to live in different worlds — one inside
the protocol, one on somebody's disk.

This document is what happens when a challenge is submitted, where every byte of
the resulting knowledge is stored, and how the format extends without breaking the
ids it has already issued. §3 is built; §5 says what is not, and why in that
order.

## 1. Submitting a challenge, as it works today

```sh
proofwork post examples/capset/objective.json
```

`Objective::from_value` decodes the record; `Node::post_objective` admits it. The
id is the SHA-256 of the whole canonical serialization, **verifier block
included**, which is the property everything else rests on: there is no operation
that edits a funded bounty's rules, because editing the evaluator produces a
different objective and the claims against the original stop resolving.

### What admission actually enforces

Four things, and it is worth knowing that it is four:

1. **The record decodes canonically.** Required fields present, no floats
   anywhere (`canonical::Value` has no float variant, so a divergent record is
   unconstructible rather than rejected), no unrecognised confidentiality class.
2. **The verifier `kind` is one this build can run.** `certificate`, `evaluator`,
   `lean`, `replay`. Anything else is refused at post time, because *an objective
   whose payout has no machine behind it is an opinion*.
3. **The id is not already posted.**
4. **A `ratchet`, if present, is coherent** — evaluator objectives only, and
   `ratchet.reward` must equal `objective.reward`.

### What admission does not enforce

- **The JSON Schemas in `spec/` are not wired into anything.** There is no
  reference to them anywhere in `src/`. `additionalProperties: false` and
  `format: date-time` are documentation, not a gate. This is a known open item on
  the Stage 0 list.
- **Per-kind verifier fields are not validated.** `objective.schema.json` says so
  in a `$comment`: per-kind fields are checked *by the verifier*, which returns
  `INVALID_SPEC` instead of a settling verdict. So an `evaluator` objective with
  no `evaluator_sha256` is admitted to the log and fails only when somebody
  submits against it. **That is a funded bounty nobody can ever win, with the
  money already escrowed**, and the failure surfaces on the submitter rather than
  on the author who caused it.
- **The pinned code is never located, fetched, or stored.** Resolution happens at
  verification time: `pinned()` joins the relative path onto the registry root,
  checks containment component-wise (so `/root-evil` does not pass as being inside
  `/root`), reads the file, hashes it, and compares against the declared digest. A
  missing file is `Unavailable`; a digest mismatch is `INVALID_SPEC`. Both are
  correct and neither settles — but neither happens until somebody has already
  done the work.
- **Nothing is sandboxed.** Pinned code runs as a subprocess. Already flagged as
  a launch blocker before third-party authorship opens, and worth repeating here
  because "how do users submit challenges" is precisely the question that turns it
  from a note into a blocker. Note also that `replay`'s `cwd` is a lexical join
  with *no* containment check, stated plainly in the code: the command is
  arbitrary anyway, so a containment check on its working directory would be
  security theatre rather than security.

### The authoring contract

[verification.md](verification.md) has the four rules that make a verifier
ungameable — the statement comes from the objective and never the submitter,
enumerate the escape hatches and screen them before the checker runs, score
invalid input rather than crashing on it, and be pure. Those are the hard part of
submitting a challenge and they are not mechanised, because they cannot be:
whether a verifier is a faithful encoding of its statement is a V4 question.

What *can* be mechanised is everything in the previous section, and the gap
between "the schema exists" and "the schema is enforced" is the whole of it.

## 2. Where knowledge lives, and the gap that was there

```text
<data-dir>/
  log/proofwork.jsonl    the hash-linked log        PINNED       never evicted
  cache/blobs/           content-addressed bytes    either       §3
  cache/                 re-fetchable content       RECLAIMABLE  evicted under pressure
  tmp/                   scratch                    RECLAIMABLE  always safe to drop
```

The log is a JSONL of `Entry { seq, prev, kind, payload, ts, hash }`. Objectives,
commitments, claims, verdicts, settlements and frontier records all go in it, and
**artifacts are inline in the claim, which is inline in the payload**. So the log
is not an index of the knowledge; the log *is* the knowledge.

That is a good decision at this scale and it is why audit works: `proofwork audit`
re-derives every settled result from the log alone, with no fetches.

`cache/` was classified and quota-managed and **written by nothing outside
tests** — a slot the design left open. §3 is what fills it.

### The second store, which the protocol did not manage

Verifier code is not in the log. It lived under `--root`, referenced by a relative
path and a SHA-256 that the objective's id commits to: not replicated, not
gossiped, not covered by the chain, and **not addressed by its hash** — the hash
was only ever used to *check* a file somebody already had.

Which made one sentence in the README not quite true:

> "anyone can independently re-derive every result the network has settled, from
> nothing but a copy of the log"

You needed a copy of the log **and** a copy of the verifier tree. Two nodes whose
`--root` differed would disagree: one Accepts, the other returns Unavailable. The
rule that `Unavailable` never settles is what kept that from being a consensus
failure — a real example of that rule earning its keep — but it meant **public
verifiability depended on out-of-band file distribution.**

For a single operator who authors every objective, that is fine and nobody
notices. It stops being fine at exactly the moment objective authorship opens,
which is the same moment the sandbox stops being optional and, per
[agent-market.md](agent-market.md), the same moment an agent can fund an objective
whose evaluator nobody else has.

## 3. Content addressing the rest of the way — `src/store/blobs.rs`

The missing piece was small, because the naming scheme was already right.

> **`evaluator_sha256` is a content address.** The objective already commits to
> the bytes. What was missing is somewhere to put them and an order in which to
> look.

**Built.** `src/store/blobs.rs` is the store, `cache/blobs/ab/cdef…` is the
layout, and `VerifierRegistry::with_blobs` is the resolution:

```sh
proofwork blob put examples/capset/evaluators/cap_set.py
proofwork blob ls          # what is held, what the log needs, what is absent
proofwork blob verify      # re-hash everything; the name is the integrity record
```

Three properties follow from filing bytes under their own digest, and each is a
test rather than a claim:

- **Verification is free and unavoidable.** `get` re-hashes what it read and
  refuses bytes that do not match the name they were filed under. There is no
  separate integrity record to keep in sync, because the filename *is* the
  integrity record.
- **Writes are idempotent**, and deliberately do not touch mtime — which is what
  the quota orders eviction by, so a redundant write would quietly promote a blob
  past older ones.
- **Two stores holding the same blob hold the same bytes**, which is what makes
  `sync` a backup rather than a snapshot of one machine's idea of the truth. A
  restored node can still verify.

**Resolution is by hash, then by path.** The blob store is asked first; a miss
falls through to `root.join(relative)` exactly as before. The relative path is now
a *hint* about where a human keeps a copy, and an objective stops depending on a
directory layout it cannot see. `tests/storage.rs` settles a real objective
against an **empty** verifier root with the checker resolved purely from its
digest — and the same node without the blob store answers `Unavailable`, which is
the control and was also every operator's situation before this existed.

Strictly backward compatible, and checked rather than asserted: no objective id
changes, `conformance/vectors.json` is byte-identical, and interop still agrees on
every root.

One implementation detail worth knowing, because it looks like a wart and is
load-bearing. A blob is filed under 62 hex characters and no extension, and
Python's `importlib.util.spec_from_file_location` picks a loader from the suffix —
so a blob handed to the harness directly loads as nothing at all. Blob-resolved
code is therefore materialized as `pinned.py` in a scratch directory that lives
exactly as long as the verification. That was the smaller fix than teaching the
harness about loaders, since the harness is shared with the Python reference and a
divergence there would be a real one. It buys a second thing worth having: pinned
code never learns where the blob store is, so a checker that goes looking cannot
read or scribble on blobs belonging to other objectives.

### The quota, and the pin set

`store/quota.rs` treated everything under `cache/` as Reclaimable. A blob that is
the only local copy of an objective's evaluator is not reclaimable in any useful
sense: evicting it makes the objective unverifiable on that node and, under
availability sampling, makes the operator slashable for content it was supposed to
be able to answer for.

The fix is deliberately **not a third class**. `Store::with_pinned_blobs` moves
individual blobs across the existing line, so the rule stays sayable in one
sentence: *a blob is reclaimable exactly when nothing needs it.* A cap that cannot
be met without one gets the same refusal the log gets, naming the pinned bytes in
the way, before anything is deleted.

**Every posted objective counts, settled or not.** The tempting narrower rule —
pin what an *open* objective needs — is wrong, and wrong in the direction that
matters: `audit --rerun` re-verifies settled claims, which is the re-derivation
this project's central claim is made of. A node that drops an evaluator the moment
its objective settles has kept the ability to earn and lost the ability to prove.
The cost is honest and stated where the set is computed: it only grows, so a
node's floor grows with the number of objectives it has ever seen. The alternative
is a store that cannot re-derive its own history.

### Still not built

**The `blob` record kind.** `Entry::kind` is an open set of strings, so a record
announcing `{sha256, size, media_type}` costs the ledger nothing — but an
announcement is only worth something to a network that can act on it, and there is
no transport. Building it now would be machinery for a message nobody sends.

**Fetch.** This is where a blob lives once a node has it; nothing here goes and
gets one. A blob arrives by `blob put`, or by `sync` carrying a store that already
had it.

**`post` requiring referenced blobs to be announced.** The right admission gate
once the record exists — checkable, unlike requiring them to be locally present —
and it changes which objectives are admissible, so it belongs with the schema work
in §5 rather than arriving on its own.


### Which knowledge goes where

The line is drawn by size and by whether the audit needs it, not by what the thing
is:

| knowledge | where | why |
|---|---|---|
| objectives, commitments, verdicts, settlements | **in the log**, inline | small, and `audit` must re-derive them from the log alone |
| artifacts | **in the log**, inline | the audit re-runs verifiers *against them*; a fetch in the audit path is a dependency the audit cannot have |
| verifier code, evaluators, checkers | **blob store**, announced in the log | large, shared across many objectives, already hash-pinned |
| datasets, held-out test sets, fixtures | **blob store**, announced in the log | large, and a held-out set may be published *after* settlement without changing the objective id |
| offers, gossip population | **neither** — gossip transport | high volume, no finality needed ([coordination.md](coordination.md)) |

The awkward row is artifacts, and it is worth being explicit rather than
discovering it later: inline artifacts mean the log grows with the corpus, and a
network that settles large artifacts (a big Lean development, a model checkpoint)
will want them in the blob store with only the hash inline. **That is a change to
what `audit` can do offline**, which is the property the whole project is built
on, so it should be a deliberate decision with a name — not something that happens
because somebody submitted a 200 MB artifact. Until then, inline is right and a
size cap on artifacts at admission is the cheap defence.

## 4. Standard *and* flexible: the extension contract

Three axes on which this format has to move, with very different costs. Two of
them the repo already answers well.

| axis | cost | mechanism | already? |
|---|---|---|---|
| **new record kinds** | free | `kind` is an open string; `ledger` never inspects a payload, and the rules about which kinds may follow which live in `node` | yes |
| **new fields on existing records** | free | absent ≠ null, and the default is *omitted* from the encoding, so digests stay byte-identical and no existing id is reissued | yes — `confidentiality` is the worked precedent |
| **new verifier kinds** | a release | `Kind` is a closed compile-time enum | yes, and deliberately |

The closed enum is the right call and should stay: a verifier is code every
contributor executes, so a runtime plugin loader is an attack surface pretending
to be a feature. What makes a closed enum survivable on a network where nodes
upgrade at different times is already in the code, and it is the single most
important line for extensibility here:

```rust
// Unknown kind is Unavailable, not InvalidSpec: another node, or a
// later version of this crate, may well know this verifier. Saying
// "your objective is broken" because *we* are old would be wrong.
```

> **An old node abstains; it never refutes.** That is the forward-compatibility
> guarantee, and it is the same rule as "a verifier that cannot run returns
> Unavailable" — which is why it needs no separate justification and why it
> extends to an unresolvable blob for free (a missing pinned file is already
> `Unavailable`).

### Wiring the schemas in, without making them a weapon

`spec/objective.schema.json` and `spec/claim.schema.json` should gate `post` and
`reveal`. One rule decides whether that is safe:

> **Schemas gate admission, never audit.** A schema that can reject a record
> already in the log rewrites history on a version bump.

So: validate on the way in, never on the way out, and never in `audit`. A record
that was admissible when it was written stays valid forever, which is the same
property the hash chain gives and would be silently undone by a validator that
runs over old entries.

The per-kind half is the more valuable one and it does not need JSON Schema at
all: **ask the verifier to check its own spec at post time.** The registry already
knows how — every `verify_*` returns `INVALID_SPEC` for a malformed spec — so
lifting that into a `validate_spec(&Value) -> Result<(), Verdict>` called from
`post_objective` turns "this bounty can never be won" from a discovery the first
submitter makes into a refusal the author gets. Same code path, same verdicts, one
step earlier.

Note what this does *not* do: it cannot check that the pinned code exists or
hashes correctly at post time, because the author's node may legitimately be the
only one that has it yet. That is what the blob store is for, and it is why the
two halves of this document are one question — **`post` should require the blobs
its objective references to be announced**, which is checkable, rather than
require them to be locally present, which is not.

## 5. Scope

**Admission gate** — cheap, self-contained, no format change.

- [ ] `spec/*.schema.json` enforced in `post` and `reveal`, on admission only.
- [ ] `validate_spec` on the verifier registry, called from `post_objective`, so
      a malformed verifier block is the author's error rather than the first
      submitter's.
- [ ] A size cap on inline artifacts, so the "artifacts move to blobs" decision
      is made deliberately rather than by whoever submits first.

**Blob store** — the missing half of content addressing. *(§3, built.)*

- [x] `cache/blobs/ab/cdef…`, self-verifying, deduplicating, atomically written.
- [x] Resolution order: blob store, then `root.join(path)`, then `Unavailable`.
- [x] Pin set in the quota, computed from the log by `Node::pinned_blobs` — a blob
      any posted objective needs is not an eviction candidate, and a cap that
      cannot be met without one is refused rather than met.
- [x] `proofwork blob put | ls | verify`, with `ls` naming the blobs the log needs
      and does not have.
- [ ] `blob` record kind: `{sha256, size, media_type}` announced in the log.
      Waiting on a transport — an announcement is worth nothing to a network that
      cannot act on it.
- [ ] `post` requires referenced blobs to be *announced*, not present. Waits on
      the record, and on the admission gate above.

**Then, and not before.**

- [ ] Blob fetch over the gossip transport (which does not exist yet — the merge
      law does, the wire protocol does not).
- [ ] Sandboxed verifier execution. Still the launch blocker, and now more urgent
      rather than less: a blob store makes distributing untrusted code *easier*,
      which is the whole point and also the risk. Materializing blob-resolved code
      into a scratch directory keeps a checker away from other objectives' blobs;
      it is not a jail and does not pretend to be one.

## Where this is wrong

- **Content addressing solves naming, not availability.** A blob store makes the
  bytes findable by hash and identical everywhere; it does nothing to guarantee
  anyone still has them. That is the availability service in
  [node-incentives.md](node-incentives.md), and it is the cheap half — the
  protocol holds a Merkle root, so a node that cannot answer has proved something
  about itself — but it is a separate mechanism and it is not built.
- **The pin set never shrinks.** The lifetime was chosen from what `audit --rerun`
  needs rather than from what settlement needs, which is the right call and has a
  price: a node's disk floor grows with every objective it has ever seen, and
  nothing releases a blob whose objective closed years ago. The lever that would
  fix it — release once enough *other* nodes demonstrably hold the blob — needs
  availability sampling, which is designed and not built. Until then the floor
  grows.
- **The pin set is only as good as the log the node has.** Digests come from
  `Node::pinned_blobs`, so a node that has not caught up pins less than it will
  need. `gc` on a stale log can therefore evict something the next sync makes
  load-bearing. The CLI refuses to compute a pin set from a log it cannot read,
  which covers the failure that would be silent; it does not cover this one.
- **Nothing here makes verifier authorship safe**, and a blob store distributing
  hash-pinned untrusted code to every contributor is a sandbox blocker with better
  logistics. The order in §5 reflects that; the risk is that the logistics land
  and the sandbox does not.
- **The artifacts-inline decision is deferred, not made.** This document says what
  the tradeoff is and declines to spend it, because the property being traded —
  `audit` needing nothing but the log — is the one the README leads with.
