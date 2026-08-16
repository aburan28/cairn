# Bonded verification

*Who ran the checker, and what it costs them to lie.*

```sh
./scripts/attestation-demo.sh          # the whole mechanism, end to end
pw attest stand  --claim ID --status accept|reject --identity FILE
pw attest slash  (--attestation ID | --docket FILE) --catcher NAME
pw attest list
```

Implemented in [`records::Attestation`](../src/records.rs),
[`Node::post_attestation` and `Node::slash_attestation`](../src/node.rs), and
[`Docket::contradicted`](../src/canary.rs). Pinned by
[`tests/attestations.rs`](../tests/attestations.rs) and by the arena's
rubber-stamping trial.

## The gap this closes, and how it was found

Not by reading. `src/arena` played a rubber-stamper for money against the real
rules engine and returned the only **OPEN** verdict in the set. The docket
worked exactly as designed — it knew *which* verdicts were wrong for the price
of a map lookup — and it took nothing, because a Stage-0 log has one writer and
no record said **who ran the checker**. There was a culprit and no defendant.

`tests/arena.rs` pinned that as open on purpose, with a note saying the test
should start failing when a bond landed. It did.

## The record

One identity, one claim, one status, signed, with a bond behind it.

```json
{"attestor":"<ed25519 key>","claim_id":"sha256:…","created_at":"…",
 "signature":"…","status":"accept","type":"attestation"}
```

Three things about it are load-bearing, and each has a rule that would look
arbitrary without the reason.

**Signed, always.** An attestation by nobody has nobody to slash, which makes it
free, and a free attestation is rubber-stamping with a record attached.

**`accept` or `reject`, never `unavailable`.** A verifier that could not run says
nothing about the artifact — that rule holds everywhere in this crate, and here
it means the non-settling status is not *bondable*. Bonding it would put a price
on admitting a broken toolchain, and the cheapest response to that price is to
guess instead.

**Nothing at admission checks whether it is true.** That is the design and not a
shortcut. Asking would put the verification cost back exactly where the whole
mechanism took it out of: every node re-running every checker on every claim.
The expensive question is asked once, by somebody who already has evidence.

## The two halves, and why neither works alone

| | what it costs | what it produces |
|---|---|---|
| a canary docket | a map lookup — **1.2 µs** against 547 ms for a re-verifying audit | *which* verdicts are wrong |
| a bonded attestation | one verifier run, once, per catch | *who* is answerable, and something to take |

A docket without attestations names a claim and no party. Attestations without a
docket have evidence nobody can afford to find — and worse, the search for it is
exactly the universal re-verification the design exists to avoid.

Together the naming is free and only the taking is expensive, and the taking is
spent on a claim somebody already has good reason to believe is wrong.

## The bond

`VERIFICATION_BOND` is **50,000** units — the reference network's catch bounty
from [node-incentives.md](node-incentives.md), because the catcher is paid the
bond and the two numbers have to be the same one.

**Per attestation, not per attestor.** One bond covering a thousand statements
would be the same units staked a thousand times, and a stamper's whole advantage
is volume.

**And it comes back.** This is the part the first draft got wrong. A bond locked
for good would mean an operator holding `S` units could stand behind
`S / 50,000` verdicts in its *entire life* and then never verify again — the
network's total verification capacity fixed at `supply / bond`, forever. That is
a capital sink, not a service market, and the first version of this file
described the permanence as a feature. What actually makes volume its own limit
is that bonds are **concurrent**: standing behind a thousand claims at once needs
a thousand bonds, and waiting out the window to re-stake takes time a stamper
does not have.

### What the window closes on

`ATTESTATION_WINDOW_EPOCHS` is 6, the same as the challenge window and for the
same reason — it is how long somebody holding evidence has to bring it. The
interesting question is what "six epochs later" *means* to a rule that has to be
re-derivable from the log alone.

Two obvious answers are both wrong, in opposite directions:

- **an entry's `ts`** is operator-supplied advisory text that no rule
  constrains, so one forged future timestamp would release every live bond in
  the log at once and let their holders re-stake the same units;
- **log height** advances at whatever rate anybody appends, so stuffing the log
  with cheap records would run the window out on somebody who was about to bring
  evidence.

What the rule reads instead is the highest epoch any **`batch`** record names.
Batches are written by settlement, the audit already re-derives them, and moving
that number forward means actually draining epochs — which is the thing that
pays people. A log that has settled nothing keeps every bond live, which is the
safe direction.

## What the audit re-derives, and what it does not

The repository's characteristic bug is a rule enforced at admission and not
re-derivable by the audit, because a log can arrive from a peer. So:

**Every audit, cheap path.** Every *slash* is re-derived — signature, duplicate,
the claim exists, the attestor named matches, the units are exactly the bond,
the window was open, and the pinned verifier really does contradict what was
attested. That is one verifier run per slash, and there are as many slashes as
there are people caught.

**Only under `--rerun`.** Whether an *unslashed* attestation is true. Running
that routinely is precisely the cost the bond exists so that nobody pays. If the
cheap path did it, the mechanism would have bought nothing.

Both halves are pinned by injection:
`the_audit_names_a_slash_the_verifier_does_not_support` and
`a_false_attestation_is_found_by_the_rerunning_audit` each fail when the
corresponding block in `Node::audit_attestations` is reverted.

`reference/rust` re-derives everything the transcript decides on its own — who
may stand behind what, once, under signature; that a slash names an attestation
the log carries, takes from the identity that made it, takes exactly the bond,
and was written while the window was open. It runs no verifier and has none, so
whether an attestation is *true* is the primary's `--rerun` and is not claimed
here.

## What the arena reports now

At seed 1, `rubber-stamping` moved from **OPEN** to **CLOSED**:

```
CLOSED   attacker nets 8000 undefended, -92000 defended
  auditor   net  101300   held  10000 ->  112000   spent   700
  honest    net    6000   held 250000 ->  258000   spent  2000
  stamper   net  -92000   held 250000 ->  158000   spent     0   CAUGHT
```

The swing is 100,000 — two bonds, to the unit, for the two known-bad canaries
the stamper accepted. The honest operator staked exactly the same bonds on
exactly the same claims and kept all of them, which is the half that would be
easy to lose: a defence that punishes stamping by making *everybody* poorer has
distinguished nothing.

### The bug that turned up while wiring it

The arena's pinned checker was `artifact.get("ok") is True`. Every edit
`canary::Generator` makes is shape- and length-preserving over **numbers and
strings** — it has no move that flips a boolean — so no canary it could mint
would ever *fail* that checker. The rubber-stamping scenario had been running
against a docket with two known-good canaries and **zero known-bad ones**: a
trap with only the half that catches blind *rejection*, pointed at an attacker
that blindly accepts.

`Docket::mix` existed and said so; nothing was asking it. The scenario now
asserts both halves are present before it measures anything.

## Residual

**Nothing requires an attestation.** An operator that stands behind nothing
stakes nothing and risks nothing. What the mechanism prices is *lying*, not
*silence* — and pricing silence is the availability pool's shape, not this one's.
Whether verification should be paid rather than merely bonded is the question
[node-incentives.md](node-incentives.md) opens with, and it is still open.

**One node, many identities.** Stage 0's trust model. Two nodes that disagree
about what a verifier returned is a different problem, and
`tests/simulation.rs` is the harness for it.
