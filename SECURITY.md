# Security policy

This project executes verifier code written by whoever posted an objective.
That is a design feature, not an accident, and it is confined by an OS-level
sandbox (`verifiers::SANDBOXING` documents exactly what the jail does and does
not cover). It also means the security of the sandbox, and of the consensus
rules around it, is the whole ballgame. Reports are welcome and taken
seriously.

## Supported versions

The `main` branch only. Releases are cut by release-please from conventional
commits, so the version number is past 1.0 — but the project is at **Stage 0**
(one operator, no consensus) and that number carries no stability promise. No
release line receives backported fixes, and anything not on `main` should be
assumed unpatched.

## Reporting a vulnerability

Open a private security advisory on this repository:

> https://github.com/aburan28/cairn/security/advisories/new

There is no security email address — the advisory form is the only private
channel, and it is preferred over an issue because a sandbox escape published
as a public issue is an exploit with a walkthrough.

If the report is real, expect an honest acknowledgement and a fix on `main`;
pre-1.0 there is no embargo machinery beyond the advisory itself.

## Scope

In scope — the properties this project actually claims:

- **Sandbox escapes.** Objective-authored checker/evaluator code reaching the
  network, the filesystem outside its scratch directory, or the host
  environment, with `CAIRN_REQUIRE_SANDBOX` set.
- **Consensus splits.** Any input on which the two implementations — `src/` and
  the independent one in `reference/rust/` — disagree about a record's id, a
  Merkle root, a verdict, or a settlement. (The frozen conformance vectors came
  from a Python implementation that no longer exists; a disagreement with a
  vector is the same class of report.)
- **Canonical-encoding collisions.** Two semantically different objects with
  the same canonical bytes, or one object with two valid encodings.
- **Citation-flow theft.** Redirecting attribution or reward to someone who
  did not earn it, beyond the dilution attack already documented as unhandled
  in the threat model.
- **Commit–reveal breaks.** Learning an artifact before its reveal, replaying
  a commitment under another name, or grinding settlement order.

Out of scope:

- Denial of service against a node you operate yourself. You can always make
  your own node slow.
- Anything that requires `CAIRN_REQUIRE_SANDBOX` to be off. An
  unconfined child on a host with no sandbox mechanism is a documented,
  deliberate failure mode — the switch exists so operators can refuse it.
- Attacks already listed as **not handled** in the threat model. They are
  known, and stated there precisely so nobody mistakes them for solved.

## Known limitations

[docs/threat-model.md](docs/threat-model.md) marks every considered attack
**handled / partial / not handled / unsolvable**, and keeping that table
honest is a stated project rule. Read it before reporting: if your finding is
already a **not handled** row, a report will not tell us anything new — but a
fix would be very welcome.
