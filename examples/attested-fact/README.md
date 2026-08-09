# Attesting a fact — and the line this network cannot cross

> **This objective verifies provenance, not truth.** Accepting a claim here
> means the quotations are faithful and the sources are the ones the objective
> pinned. It says nothing whatever about whether the assertion is correct.

The worked example is *"James A. Garfield was assassinated"*. It is the right
example precisely because it is **not** the kind of thing this network can
settle, and the interesting question is what can honestly be built instead.

## Why no verifier can settle it

A verifier here is a pinned, deterministic program run against an artifact. It
can check a proof term, a circuit on every input pair, an UNSAT certificate, a
quotation. It cannot check what happened in 1881, because that is not a
function of the artifact.

Any checker claiming to would really be checking something else:

| what it would actually check | what that makes it |
|---|---|
| a designated source says so | an oracle for whoever controls the source |
| *N* sources agree | the same, plus a Sybil problem on sources |
| a trusted party signed an attestation | an oracle with extra steps |

None of those is verification, and labelling one "verified" would break the
guarantee the whole project rests on — *anyone can independently re-derive
every settled result from the log alone* — because nobody could re-derive it.
`docs/design/confidential-corpus.md` draws the same line: the boundary is not
"hard science versus soft", it is whether a verdict is a **function of the
artifact** or a **judgement about the world**.

## What this does settle, and why it is worth having

That an assertion is *faithfully sourced*:

1. every cited document is one the objective pins,
2. the text supplied really is that document — the checker re-hashes it,
3. every quote appears in it verbatim, after folding whitespace and nothing else,
4. at least two **distinct** documents support the assertion.

All four are decidable, cheap, and re-derivable by anyone, which is exactly the
shape the network needs. The record then says *this assertion is supported by
these documents, quoted without alteration*. A reader still judges whether the
sources are any good. What they no longer do is take the submitter's word for
what the sources say — and that is most of what makes a knowledge base
auditable rather than merely stored.

## Where the trust actually sits

In the pinned source set, and nowhere else. `SOURCES` in
[`checkers/provenance.py`](checkers/provenance.py) is a digest allowlist, and
that file is pinned by `checker_sha256` in the objective — so **which documents
count is part of the objective's identity**. Changing the source set means
posting a different objective, exactly as changing any other rule does.

That is the honest place for it. The trust is named, pinned, and auditable,
rather than hidden inside a checker that says "true".

The submitter supplies the source *text* and the checker re-derives its digest,
which is what removes the filesystem from the check entirely: the text either
hashes to a pinned id or it does not, and inventing a document cannot make it
hash to one of these.

## Run it

```sh
cargo build --release
LOG=/tmp/pw-attest.jsonl
export PROOFWORK_EPOCH_SECONDS=1

OID=$(./target/release/proofwork --log $LOG --root . \
        post examples/attested-fact/objective.json | head -1 | awk '{print $2}')

./target/release/proofwork --log $LOG --root . commit "$OID" \
  --submitter you --artifact examples/attested-fact/artifacts/sourced.json --nonce n1
sleep 1.1
./target/release/proofwork --log $LOG --root . reveal "$OID" \
  --submitter you --artifact examples/attested-fact/artifacts/sourced.json --nonce n1
```

Four artifacts, and the three refusals are the point:

| artifact | verdict |
|---|---|
| `sourced.json` | **accept** — two pinned sources, both quotes verbatim |
| `misquoted.json` | reject — a date altered inside the quote |
| `tampered-source.json` | reject — one word changed in the supplied text, so it no longer hashes to the id it cites |
| `one-source.json` | reject — one document is not corroboration |

Each refusal is a distinct failure mode: a misquote, a forged source, and a
lone citation. Run the last three against their own log — a plain objective
settles once, so a commitment after the first accept is correctly refused.

## If you want more than provenance

Two honest directions, neither of which is "make the checker decide":

- **Formalise it.** State the death date as a *named axiom* and prove
  consequences from it. The verifier checks the derivation; the trust stays
  localised in an axiom set anyone can read. This is what proof assistants do,
  and it works for any formal theory, not only mathematics.
- **Adjudicate it.** Stake and dispute, in the TrueBit or prediction-market
  shape. That resolves by argument rather than by verification, and it is a
  different system with a different threat model and a much worse cost profile.

What is *not* available is a pinned program that decides a historical question.
Saying so is the same discipline `docs/threat-model.md` applies to attacks: the
one thing this repository cannot afford is overstating what it checks.
