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

`./scripts/interop.sh` is the strongest check in the repository — each
implementation audits a log the other produced. If you touched a record, a
hash, or an encoding, you must also change **both** implementations,
regenerate `conformance/vectors.json` with `scripts/gen_conformance.py`, and
confirm every *pre-existing* vector is unchanged byte for byte. A diff in an
old vector means you moved ids and orphaned live work.

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

### Security issues

Do not open a public issue. [SECURITY.md](SECURITY.md) has the process.
Anything touching canonical encoding, record identity, settlement order, or
the verifier sandbox is security-relevant even when it looks like a typo.
