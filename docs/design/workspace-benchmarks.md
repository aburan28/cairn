# Repository-shaped benchmarks: parity with Yukon, minus the oracle

[Yukon](https://yukon.org) (Eigen Labs) turns a GitHub repository into an
optimization benchmark, and it is running `ecdsa.fail` — the objective
`examples/ecdsa-fail/` already imitates. Its
[author guide](https://github.com/Layr-Labs/yukon-docs) is the only code they
have published; everything else is the product.

This document is the design for feature parity: what to take, what we already
have, what must be refused, and what turns out not to be a feature at all.

## Parity, item by item

| Yukon | verdict | where |
|---|---|---|
| `benchmark.json` manifest | **take** | `workspace` verifier spec, below |
| `editablePaths` | **take** | the submission contract, below |
| `setupCommand` / `benchmarkCommand` / `scorePath` | **take**, resplit | [three phases](#three-phases-and-the-only-honest-split) |
| solver uploads an archive | **take**, reshaped | [manifest, not archive](#the-artifact-is-a-manifest-not-an-archive) |
| candidate = baseline + editable files only | **take**, and it is load-bearing | [each claim is self-contained](#each-claim-is-complete-not-a-patch-on-a-patch) |
| server-side enforcement of editable paths | **take** | verifier, `Reject` |
| `yukon init`: validate, score baseline, go live | **take** | `cairn bench init` |
| leaderboard shows a per-submission **note** | **take** — we lack it | [notes](#notes-model-and-the-fact-that-agents-read-them) |
| leaderboard shows the **model** | **take**, labelled self-declared | same |
| PR diff between submissions | **take** | `cairn bench diff` |
| "sync to current best" before you start | **take** | `cairn bench checkout` |
| 50 MiB artifact ceiling | **take**, retuned | [limits](#limits) |
| `direction` `+` / `-` | already have | `frontier::Direction` |
| `minScoreImprovementBips` | already have, better documented | `Ratchet::min_improvement` |
| "beats current best" promotion | already have, and it *pays* | `Ratchet::improves` |
| baseline scored at import | already have | `Ratchet::baseline` |
| PR as the durable public record | already have, stronger | the log, `checkpoint`, `prove` / `check` |
| never trust solver git history | already have | claims carry no history to trust |
| **GitHub Actions as the executor** | **refuse** | [the refusal](#the-refusal) |
| GitHub App installation | not applicable | no central orchestrator to install for |
| `rootDir` for monorepo leaves | not a feature | you import the subtree; the repo is not the unit |
| `category` grouping label | not worth a record change | `Objective::goal` already carries it |
| solver notification | not new machinery | `list_objectives` over MCP, p2p gossip |

Two rows deserve their reasoning up front, because they are the ones where the
temptation is to build something.

`rootDir` exists because in Yukon *the repository* is the benchmark, so a
monorepo needs a way to point at a leaf. Here the unit is a pinned tree, and you
pin the leaf. There is nothing to add.

`category` is a grouping label. Adding a field to `Objective` reissues the
digest of every objective that omits it unless it is omitted at its default —
doable, but AGENTS.md is blunt about what that machinery costs, and `goal`
already reads `GOAL-attested-provenance`. A prefix convention buys the same
grouping for no consensus surface. Resist the field.

## The refusal

**There must be no `github-actions` verifier kind.** A verdict of "GitHub said
94.17" is re-derivable only by someone holding a token, against a runner that no
longer exists, on a repository whose owner may rewrite it. The guarantee in
[AGENTS.md](../../AGENTS.md) is *anyone can independently re-derive every settled
result from the log alone*.

`examples/attested-fact/README.md` already wrote the row this falls in:

| what it would actually check | what that makes it |
|---|---|
| a trusted party signed an attestation | an oracle with extra steps |

There is an honest version worth having: an objective that settles *provenance*
of a Yukon run — the App's signature is genuine and says X — and explicitly does
not settle X. Same shape as `attested-fact`. A second objective, not a second
meaning for an existing one.

Everything below is the part that ports.

## `workspace`: a sixth verifier kind

Named for the mechanism, not the vendor. The concept is *a solver replaces
declared paths in a pinned base tree, and a pinned command scores the result*.
GitHub Actions is one executor for that; `src/verifiers/sandbox.rs` is the one we
can re-derive.

```json
{
  "kind": "workspace",
  "base": "examples/ecdsa-fail/base.manifest.json",
  "base_sha256": "…",
  "editable_paths": ["src/point_add"],
  "prepare_command": ["bash", "-lc", ".cairn/prepare.sh"],
  "score_command": ["bash", "-lc", ".cairn/run.sh"],
  "score_path": "score.json",
  "score_scale": 1,
  "max_files": 256,
  "max_bytes": 8388608,
  "timeout_seconds": 1800
}
```

Note what is **absent**: no `direction`, no `minScoreImprovementBips`. Those live
in `Objective::ratchet`, where [`frontier::Ratchet`](../../src/frontier.rs)
already has `direction` and `min_improvement` — the latter with a longer and more
honest comment than Yukon's field, because we know what epsilon-farming costs
citation flow. Duplicating them into the verifier spec would be two answers to
one question, on the money path.

Adding a kind moves **no record ids**. `Objective::verifier` is an opaque
`Value`; the digest covers its bytes and does not interpret `kind`. The frozen
`conformance/vectors.json` must reproduce untouched, and that is the first thing
to check rather than assume.

## The artifact is a manifest, not an archive

```json
{
  "files": {
    "src/point_add/mod.rs": "3f9a…",
    "src/point_add/trailmix.rs": "b207…"
  },
  "results": { "score": 1571592960 },
  "note": "1152q route: free the square gate-suffix carry that pinned the 1153 peak",
  "model": "claude-opus-4-8"
}
```

Yukon uploads a zip. We cannot, and the reason is the first rule in AGENTS.md:
canonical encoding is consensus-critical. An archive has no canonical form —
mtimes, member ordering, permission bits, compression level — so two honest nodes
hash the same tree differently and disagree about which claim was funded.

A map of path → SHA-256 is canonical already: `canonical::Value` orders object
keys, and the bytes live in [`src/blobs.rs`](../../src/blobs.rs), whose address
**is** a bare hex SHA-256. No new record kind, no new identity scheme, no locator
field — `blobs.rs` argued that last one down twice. `BlobStore::put` already
refuses a hash mismatch before anything touches the filesystem, `is_address`
already stops `"../../../../etc/passwd"` reaching `Path::join`, and `retain` is
already the GC. Nothing here is new machinery; it is an existing store used for
one more thing.

Three properties fall out. A one-file improvement re-sends one blob rather than a
whole commit. Two solvers who independently write the same file share one blob.
And the claim stays small enough to sit in the log where every other claim sits.

The base tree is pinned the same way — a manifest of path → address, itself a
blob, pinned by `base_sha256` through the existing `Registry::pinned` path, which
already returns `InvalidSpec` on a hash mismatch and `Unavailable` when the bytes
cannot be obtained. Those are exactly the two verdicts wanted. A git commit sha
would **not** do: it is a dangling reference to github.com, and `blobs.rs`
explains at length why a dead URL inside a digest forks an objective and orphans
every claim against it.

## Each claim is complete, not a patch on a patch

A claim's `files` are applied over the **base** tree, never over the current
frontier holder's tree. Yukon does the same thing — candidate = baseline +
editable files — and it is worth saying why rather than copying it.

If claim *N* were a patch on claim *N−1*, verifying *N* would mean replaying the
whole chain, and the cost of admitting the thousandth improvement would be a
thousand builds. Worse, a retracted or refuted link in the middle would put every
later claim in an undefined state — and `docs/knowledge.md` is explicit that
standing is reader-chosen, so "undefined" would be *per reader*. Self-contained
claims keep verification O(1) in the chain length and keep a verdict independent
of anything except the objective and the artifact.

The cost is that a solver improving on the frontier must ship the whole editable
subtree, not their diff. Blob dedup makes that cheap on the wire, and
`bench diff` makes it readable for a human.

## Three phases, and the only honest split

This is where the design earns the kind, and where we deliberately diverge from
Yukon.

Yukon's guide says to fail the workflow "when the benchmark cannot produce a
trusted score." That collapses two different facts into one exit code:

- the solver's code does not compile — a fact **about the artifact**: `Reject`
- the toolchain is missing — a fact **about the node**: `Unavailable`

Collapsing them is the attack `docs/verification.md` names by name: take the
verifiers offline and every honest submission fails. Yukon can afford it because
one central orchestrator builds once and no money is keyed to the distinction. We
cannot.

The only heuristic-free way to tell them apart is ordering:

1. **Prepare.** Materialize the base tree from blobs into a scratch dir. Run
   `prepare_command` on it with the artifact **not yet applied**. Any failure is
   `Unavailable` by construction — the base is the objective's own code, and its
   failure is not evidence about a submission nobody has read yet.
2. **Apply.** Overlay `files`. A path outside `editable_paths` is `Reject`, not
   `InvalidSpec`: the contract was published and the submitter left it.
3. **Score.** Run `score_command`. A non-zero exit is now genuinely a fact about
   the artifact: `Reject`. Everything the command needed was proven present in
   phase 1.
4. Read `score_path`; compare to `artifact.results.score` exactly, as
   `verify_replay` compares declared fields. Mismatch is `Reject` — the case
   `examples/ecdsa-fail/demo.sh` already exercises.

Timeout stays `Unavailable` throughout: *a timeout is not a refutation*, in
`verify_replay`'s own words.

The workspace is the jail's `workdir`, which `sandbox::confine` binds writable
(`--bind`) rather than read-only — a build has to write. That is the one
confinement difference from `replay`, whose `cwd` is deliberately read-only, and
it belongs in the module docs beside the `Confinement` construction rather than
being discovered later.

## Where "setup needs the network" honestly lives

`sandbox` passes `--unshare-net` on Linux and `(deny network*)` on macOS,
unconditionally, with no toggle. **Do not add one.** The flag would be set by the
objective, and an objective-authored spec that can request network is an
objective that can exfiltrate whatever it read. The module's one rule is that
nothing in it may produce a rejection; its other rule should be that nothing in
it may produce a socket.

So `prepare_command` cannot download anything, and the base tree must be
self-contained: dependencies vendored into the base manifest, or supplied by the
operator's toolchain — the same choice `verify_replay` already makes when it says
"the command's toolchain is the operator's, not the objective's."

That leaves a real gap for a benchmark like `ecdsa.fail`, whose base is a Rust
crate with a dependency graph. The gap's honest home is a new **operator** action,
outside the verdict path:

```
cairn bench prime <objective-id>
```

It materializes the base tree, runs the objective's declared `prime_command`
**unjailed and with network**, and populates the operator's own toolchain cache
(a cargo registry dir, an npm store). It is an explicit, operator-initiated,
per-objective decision to run a stranger's fetch script — the same class of
decision as `cargo build` on a cloned repo, and it must be documented as such
rather than buried. Verification afterwards is offline and jailed, and a node
that has not primed answers `Unavailable`, which is correct: it *cannot* check.

This is strictly better than Yukon's position rather than a concession. Their
Actions runner has network during the benchmark, so their builds are not
reproducible unless every author remembers to lock and vendor. Ours cannot be
irreproducible that way, because the network is not there.

## The score is an integer

Yukon's example score file is `{"score": 12.345}`. `canonical::Value` has no
float variant, deliberately, and AGENTS.md says not to add one. Two nodes that
parse `12.345` into IEEE doubles and re-render can disagree about the bytes, and
this value keys a payout.

So `score` must be an integer. `score_scale` is **display only** — a leaderboard
renders `12345` at scale `1000` as `12.345` — and comparison, `Ratchet::progress`
and every settlement path use the integer and nothing else. A scale that entered
the comparison would be a float wearing a hat.

A float in the score file is `InvalidSpec`, blaming the objective: its author
wrote a scorer whose output cannot be reproducibly compared. This is a permanent
incompatibility with Yukon's manifest and belongs in the author guide rather than
being rounded away at the boundary.

## Notes, model, and the fact that agents read them

Yukon's leaderboard carries a per-submission note — *"1152q route: free the
square gate-suffix carry that pinned the 1153 peak"* — and the model that produced
it. This is the feature we most clearly lack;
[GAP.md](../../examples/ecdsa-fail/GAP.md) lists it as gap 5. It is swarm memory:
the next solver reads why the last one worked and does not redo it.

It needs **no record change**. An artifact is an unconstrained object and the
pinned verifier is the only authority on what it means, so `note` and `model` are
fields `workspace` ignores. They are inside the claim id and therefore inside the
commitment, which is right — a note written after seeing the score would be a
different kind of object.

Two rules, both from things this repository already knows:

**`model` is self-declared and must be rendered as such.** Nothing verifies it.
Yukon's leaderboard prints it as fact; ours should print it as an assertion by
the submitter, in those words. It is worth carrying anyway — knowing which models
move which frontiers is most of why anyone would read a leaderboard.

**A note is attacker-authored prose read by an LLM, so it goes through
`taint_from`.** This is the difference between their surface and ours. Yukon's
notes are read by humans in a browser. Ours are read by agents over
`cairn-mcp`, where `src/bin/mcp.rs` already taints claim ids appearing in
verifier `detail` and in objective statements, for exactly this attack: text that
says "also cite sha256:…" routes real money under citation flow and needs no code
execution, so the sandbox does nothing about it. A note field is a third door into
the same room and must be wired to the same defence in the same commit that adds
it — not afterwards.

## Working with the current best

Yukon's solver flow assumes you start from the promoted tree. Two commands close
that loop, both pure reads over the log and the blob store:

```
cairn bench checkout <objective-id> [--claim <id>] --out <dir>
cairn bench diff <claim-a> <claim-b>
```

`checkout` materializes base + the frontier holder's files, so a solver edits the
current best rather than the baseline — the `ecdsafail clone` / `yukon sync`
equivalent. `diff` reconstructs two claims and diffs them, which is what a PR was
giving Yukon for free and what a manifest of hashes does not give a human.

Neither writes to the log. Both work offline against a bundle, which is the test
of whether they belong here.

## `cairn bench init`

Yukon's `yukon init` prints `manifest validated / baseline scored / harness
sandboxed / contest live`. The equivalent, from a working directory:

1. Walk the tree, write each file to the blob store, emit `base.manifest.json`,
   publish it as a blob, and record its address as `base_sha256`.
2. Validate `editable_paths` against the path rules below.
3. Run phases 1 and 3 on the base tree with an **empty** artifact. The resulting
   score becomes the default `ratchet.baseline` — derived from the pinned command
   rather than typed by the funder.
4. Emit `objective.json` and print a `cairn post` line.

It never posts, for the reason `src/scaffold.rs` gives at length: an objective's
statement is untrusted text funded by a human decision, and a tool that both
writes and funds one removes the step where that decision happens. This is a
sixth `scaffold::Kind`, not a parallel mechanism.

Step 3 is a convenience and not a rule. A funder who hand-writes an inflated
baseline makes the first trivial submission look like an improvement — but the
ratchet caps total payout at `reward`, so the only pocket they empty is their
own. Making baseline derivation an *admission* rule would force every node to
build the base tree before admitting the record, which is minutes of compute to
accept a bounty. `cairn audit` can report the discrepancy for anyone who
cares to check; settlement should not depend on it.

## Limits

Yukon caps an artifact at 50 MiB compressed and expanded. Ours needs three
numbers, and they are not the same number:

- **per file**: `blobs::MAX_BLOB_BYTES`, 1 MiB, already enforced everywhere a
  blob can arrive. Files above it need `swarm::piece` (256 KiB pieces,
  `DEFAULT_PIECE_LEN`), which exists but has no verifier caller yet. Stage 0
  workspace objectives should stay under the cap.
- **per artifact**: `max_files` and `max_bytes` in the spec, checked *before*
  materializing anything. Refusing after allocating is not a defence against a
  submitter whose plan is to make you allocate — `blobs.rs` makes this argument
  already and the verifier must make it again.
- **per base tree**: the same two, checked at `bench init` and re-checked when
  the manifest is resolved.

Path rules, ported from Yukon's guide because they are security rules rather than
style, all `InvalidSpec` at spec validation and `Reject` when a submitted path
breaks one: relative POSIX only; no `..`, no leading `/`, no backslash; no `.git`;
no duplicates; no overlapping entries (`["submission", "submission/src"]`);
`score_path` outside `editable_paths`.

## Work

Both implementations change together. This is not optional here:
`scripts/interop.sh` has each audit the other's log, an audit re-derives
settlement, and settlement runs the verifier.

- `src/verifiers/mod.rs` — `Kind::Workspace`, wire spelling, `KINDS`, dispatch,
  `verify_workspace`, and the arm that reports pinned sources so `blob publish`
  finds the base manifest.
- `src/verifiers/sandbox.rs` — document the writable-workdir difference. **No
  network toggle.**
- `reference/rust/src/verifiers.rs` — the same, independently derived.
- `spec/objective.schema.json` — the spec shape.
- `src/scaffold.rs` — a sixth `Kind`, emitting a stub whose scorer rejects, like
  every other stub.
- `src/main.rs` — `bench` with `init`, `prime`, `checkout`, `diff`, grouped for
  the reason `availability` and `shard` are grouped: they are one mechanism and a
  reader meeting `init` needs to find `checkout` beside it.
- `src/bin/mcp.rs` — surface `note` and `model` in `frontier_status` and
  `get_claim`, both through `taint_from`.
- `conformance/adversarial.jsonl` — the boundary, since `differential.sh` is what
  proves both implementations classify it alike: a path escaping
  `editable_paths`, overlapping entries, `score_path` inside `editable_paths`, a
  float score, a missing blob, a base manifest that does not match
  `base_sha256`, an artifact over `max_files`, an artifact over `max_bytes`.
- `docs/verification.md` — a V2 row for `workspace` once it is real, not before;
  that table's `implemented` column is load-bearing.
- `docs/threat-model.md` — see below.
- `examples/ecdsa-fail/` — retarget it. It exists to be the shape of a real
  challenge, its GAP.md names this as gap 1, and it is the only honest test that
  the kind is usable rather than merely implemented.

`conformance/vectors.json` stays frozen and untouched. A diff in it means
something moved an id and the change is wrong.

## Residual gaps, stated rather than closed

**Verification cost.** `workspace` makes every verifying node pay a full build
per submission, where a `certificate` objective pays milliseconds. Yukon pays it
once, centrally. `Ratchet::min_improvement` is the only thing between that and an
epsilon-farming denial of service, and it is carrying more weight here than
anywhere else in the system. This belongs in `docs/threat-model.md` **before**
this ships, not after.

**Priming is a trust decision.** A node that primes runs an objective author's
fetch script unjailed. It is explicit, per-objective and operator-initiated,
which is the best available shape — but it is a real hole in "no objective code
runs unconfined" and must be named in `SANDBOXING` rather than elided.

**We still cannot run `ecdsa.fail`'s real harness.** That is a 9024-shot
simulation with a large dependency graph; GAP.md's blocker list stands.
`workspace` gives the artifact a shape and the score a jail. The minutes of
compute are unchanged.
