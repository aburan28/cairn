# Submitting challenges, and where knowledge lives

Two questions that turn out to be one. An objective is only checkable if the code
that checks it can be found, and today the record that pins that code by hash and
the mechanism that distributes the bytes live in different worlds — one of them
inside the protocol, one of them on somebody's disk.

This document is what happens when a challenge is submitted, where every byte of
the resulting knowledge is stored, and what a standard-but-extensible answer looks
like given that the pieces are mostly already here.

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

## 2. Where knowledge lives today

```text
<data-dir>/
  log/proofwork.jsonl    the hash-linked log        PINNED       never evicted
  cache/                 re-fetchable content       RECLAIMABLE  evicted under pressure
  tmp/                   scratch                    RECLAIMABLE  always safe to drop
```

The log is a JSONL of `Entry { seq, prev, kind, payload, ts, hash }`. Objectives,
commitments, claims, verdicts, settlements and frontier records all go in it, and
**artifacts are inline in the claim, which is inline in the payload**. So the log
is not an index of the knowledge; the log *is* the knowledge.

That is a good decision at this scale and it is why audit works: `proofwork audit`
re-derives every settled result from the log alone, with no fetches.

`cache/` is classified, quota-managed, and **written by nothing outside tests**.
It is a slot the design left open and never filled.

### The second store, which the protocol does not manage

Verifier code is not in the log. It lives under `--root`, referenced by a relative
path and a SHA-256 that the objective's id commits to. It is not replicated, not
gossiped, not covered by the chain, and not addressed by its hash — the hash is
only ever used to *check* a file somebody already had.

Which makes one sentence in the README not quite true:

> "anyone can independently re-derive every result the network has settled, from
> nothing but a copy of the log"

You need a copy of the log **and** a copy of the verifier tree. Two nodes whose
`--root` differs will disagree: one Accepts, the other returns Unavailable. The
rule that `Unavailable` never settles is what keeps that from being a consensus
failure — it is a real example of that rule earning its keep — but it means
**public verifiability currently depends on out-of-band file distribution.**

For a single operator who authors every objective, that is fine and nobody
notices. It stops being fine at exactly the moment objective authorship opens,
which is the same moment the sandbox stops being optional and, per
[agent-market.md](agent-market.md), the same moment an agent can fund an objective
whose evaluator nobody else has.

## 3. The design: content addressing the rest of the way

The missing piece is small, because the naming scheme is already right.

> **`evaluator_sha256` is a content address.** The objective already commits to
> the bytes. What is missing is somewhere to put them and an order in which to
> look.

Three changes, none of which alters a single id:

**Blobs are a record kind.** `Entry::kind` is deliberately an open set of strings
— *"the log is a dumb, schema-agnostic transport, and the rules about which kinds
may follow which live in `node`"* — so a `blob` record announcing
`{sha256, size, media_type}` costs the ledger nothing. The bytes do not go in the
log; the announcement does.

**Bytes go in a content-addressed directory.** `cache/blobs/<sha256>` is the slot
`cache/` was classified for. Content addressing means the store is
self-verifying, deduplicating, and idempotent to sync — `store/mirror.rs` already
mirrors a directory and already refuses to carry key material, so it carries this
unchanged.

**Resolution is by hash, then by path.** Today the path is the identity and the
hash is the check. Invert it: look in the blob store first, fall back to
`root.join(relative)`, and if neither resolves return `Unavailable` exactly as
now. The relative path becomes a *hint* about where a human keeps it, and an
objective stops depending on a directory layout it cannot see.

This is strictly backward compatible. No objective id changes, no conformance
vector moves, and a node with the old layout and no blob store behaves exactly as
it does today.

### What has to change in the quota

`store/quota.rs` treats everything under `cache/` as Reclaimable. A blob that is
the only local copy of a live objective's evaluator is not reclaimable in any
useful sense: evicting it makes the objective unverifiable on that node and, in a
network that pays for availability, makes the operator slashable for content it
was supposed to be able to answer for. The quota already understands this — it
reports every path it dropped for exactly that reason — but it cannot currently
tell a blob that matters from scratch.

So the two-class split (`Pinned` / `Reclaimable`) needs a **pin set**: blobs
referenced by an objective that is posted and unsettled are pinned; everything
else is reclaimable. Same refusal behaviour as the log when the cap cannot be met,
same principle — *the cap is a risk setting as much as a disk setting.*

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

**Blob store** — the missing half of content addressing.

- [ ] `blob` record kind: `{sha256, size, media_type}` announced in the log.
- [ ] `cache/blobs/<sha256>`, self-verifying and deduplicating.
- [ ] Resolution order: blob store, then `root.join(path)`, then `Unavailable`.
- [ ] Pin set in the quota — blobs referenced by a posted, unsettled objective are
      not eviction candidates.
- [ ] `post` requires referenced blobs to be *announced*, not present.

**Then, and not before.**

- [ ] Blob fetch over the gossip transport (which does not exist yet — the merge
      law does, the wire protocol does not).
- [ ] Sandboxed verifier execution. Still the launch blocker; a blob store makes
      distributing untrusted code *easier*, which makes the sandbox more urgent
      rather than less.

## Where this is wrong

- **Content addressing solves naming, not availability.** A blob store makes the
  bytes findable by hash and identical everywhere; it does nothing to guarantee
  anyone still has them. That is the availability service in
  [node-incentives.md](node-incentives.md), and it is the cheap half — the
  protocol holds a Merkle root, so a node that cannot answer has proved something
  about itself — but it is a separate mechanism and it is not built.
- **The pin set assumes "posted and unsettled" is the right lifetime.** It is
  probably too short: `audit --rerun` re-verifies *settled* claims, so a node that
  evicts an evaluator the moment its objective settles can no longer perform the
  re-derivation that is the project's headline property. The honest version is
  that the pin set is a policy question with a slashing consequence, and the
  lifetime should come from what audit needs rather than from what settlement
  needs.
- **Nothing here makes verifier authorship safe**, and a blob store distributing
  hash-pinned untrusted code to every contributor is a sandbox blocker with better
  logistics. The order in §5 reflects that; the risk is that the logistics land
  and the sandbox does not.
- **The artifacts-inline decision is deferred, not made.** This document says what
  the tradeoff is and declines to spend it, because the property being traded —
  `audit` needing nothing but the log — is the one the README leads with.
