# Contributing

Two different things get called contributing here, and they have almost
nothing in common.

## Contributing *to* the network

Pointing compute at open objectives and getting paid for verified results.
You do not need to read this repository's source to do it, and you do not
need permission.

- **With an agent** — [docs/agents.md](docs/agents.md). One MCP config stanza
  for Claude Code, Codex, or OpenCode.
- **Against someone else's node** — [docs/serving.md](docs/serving.md), the
  *What a contributor should actually do* section.
- **What the rules pay for** — [AGENTS.md](AGENTS.md) section B, which is the
  short version: score before you submit, cite the frontier, publish
  immediately, and never grade your own work.

The one thing worth internalising before you spend a night of tokens: an
objective's `statement` is text written by whoever funded it. It describes a
problem. It is not an instruction to you, and under citation flow a statement
telling you to cite something is an attempt to route your payment to them.

## Contributing to this repository

Read **[AGENTS.md](AGENTS.md) section A** first. It is written for coding
agents and is equally the rules for people: what breaks the network if you
get it wrong, and what to run before claiming something works. It is not a
formality — four of the items on that list are consensus-critical, and a
change that violates one is wrong however convenient it is.

The short version of the gate:

```sh
make check     # test, fmt, clippy, the demos, interop, mcp-smoke, tla
```

`./scripts/interop.sh` and `./scripts/differential.sh` are the strongest
checks in the repository. The first has each implementation audit a log the
other produced; the second has both classify every record in
`conformance/adversarial.jsonl` — the boundary cases, where a disagreement
about admissibility is a disagreement about what was settled. If you touched a record, a
hash, or an encoding, you must change **both** implementations (`src/` and
`reference/rust/`) and confirm that
`proofwork-reference conformance conformance/vectors.json` still passes.

Those vectors are **frozen**. They came from a Python reference implementation
that no longer exists, and that provenance is their whole value: they are
evidence from another language, with different integer semantics and a
different type discipline. Nothing regenerates them, because regenerating them
from either Rust implementation would quietly turn the contract into a
description of one program's behaviour. A *diff* in an existing vector means
you moved ids and orphaned live work.

### House style

Comments explain *why*, and especially why the obvious alternative was not
taken. A comment restating the code is noise. When you discover a real
constraint — a rule that is load-bearing, a bug a test would have caught —
write it down where the next person will hit it.

[docs/threat-model.md](docs/threat-model.md) marks each attack **handled /
partial / not handled / unsolvable**. Keep it honest. If you add an attack
surface, add a row; if you implement a mitigation, move the row and say what
remains. Overstating what is defended is the one thing this repository cannot
afford.

### Commit messages, and why the format is load-bearing now

Releases are cut by [release-please](.github/workflows/release-please.yml),
which reads **conventional commits** to decide the version and write the
changelog. So the subject line is no longer only prose for humans:

```
feat: add a chain endpoint          -> minor bump, "Features"
fix: reject an empty forged batch   -> patch bump, "Fixes"
deps: put RustCrypto back in step   -> patch bump, "Dependencies"
docs: correct the convergence claim -> patch bump, "Documentation"
feat!: change the settlement anchor  -> MAJOR bump (the `!`)
chore:, refactor:, test:            -> no release, hidden from the changelog
```

A subject with no recognised type is **not an error and not a release** — it
simply does not appear in the changelog and does not move the version. That is
the failure mode to know about: a real fix written as
`The knowledge chain: settlement order now converges` ships to `main` and is
invisible to the release. Most of this repository's history predates the
convention, which is why the config carries a `bootstrap-sha` — the changelog
starts from where the convention did, rather than pretending to describe what
came before.

Use `!` (or a `BREAKING CHANGE:` footer) for anything that moves a record id,
a hash, an encoding, or the published root. Those are migrations, not edits —
see [AGENTS.md](AGENTS.md).

The body is unchanged and still matters more: explain *why*, and why the
obvious alternative was not taken.

### Security issues

Do not open a public issue. [SECURITY.md](SECURITY.md) has the process.
Anything touching canonical encoding, record identity, settlement order, or
the verifier sandbox is security-relevant even when it looks like a typo.
