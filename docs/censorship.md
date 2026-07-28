# Censorship resistance and confidentiality

Assume censorship. Assume participants are identified, pressured, network-blocked,
and selectively dropped. Design for it.

But start by separating four properties that get bundled under "encrypt it",
because they need different mechanisms and one of them actively fights the point
of the system:

| property | means | mechanism |
|---|---|---|
| **confidentiality** | observers cannot read content | encryption |
| **unlinkability** | observers cannot tell *who* | pseudonyms, fresh keys, ZK |
| **censorship resistance** | your submission gets included | forced inclusion, blind inclusion |
| **availability** | content cannot be withheld from you | replication, gossip |

Encryption delivers exactly one of those four. The other three are what you
actually need against a censor, and two of them need the opposite of secrecy.

## The tension, stated plainly

proofwork's entire guarantee is **anyone can independently re-derive every result
the network has settled**. That requires settled artifacts to be public. Encrypt
them and nobody can re-verify anything; you are left trusting an operator's word,
which is precisely the thing the project exists to avoid.

So "heavily encrypted" cannot mean "encrypt everything". It means encrypting the
right things, at the right times, and being explicit about what must stay
readable.

**Must stay public, permanently:**

- the hash chain and log structure
- objective statements and verifier specs — otherwise nobody can check what was
  even asked
- verdicts, settlements, amounts, and the frontier — otherwise nobody can check
  who was paid, or that the pool was not overspent
- the artifact of a `public`-class objective

**Should be encrypted:**

- every artifact before its reveal
- the link from a submitter pseudonym to a human being
- everything in transit
- the artifact of an `embargoed` objective, until the embargo lifts
- the artifact of a `sealed` objective, permanently — which is only coherent
  with zero-knowledge verification (§6)

## 1. The censorship failure plain commit–reveal already has

Worth isolating, because it is the strongest argument for encryption here and it
is not obvious.

Commit–reveal requires **the submitter to act twice**: commit, then reveal. An
adversary who cannot forge or steal your work can still take it from you by
stopping the second action — a targeted DoS, a network block, a detention, a
seized laptop, or a sequencer that drops your reveal until the deadline passes.
Your commitment sits on the log proving you had the answer first, and you cannot
collect. The work was done, verified in principle, and unpaid.

That is a censorship attack that costs the attacker almost nothing and does not
require breaking any cryptography.

## 2. The fix: sealed submissions with threshold reveal

Submit the artifact **encrypted, at commit time**, and let a threshold committee
open it at the epoch boundary. The reveal then happens **without the submitter**.

```
commit    submitter publishes:
            commitment = H(artifact ‖ submitter ‖ nonce)      (as before)
            envelope   = ChaCha20-Poly1305(K, artifact)
            shares     = Shamir(K, t of n), share_i sealed to committee member i
                         via X25519 + AEAD
              ↓
epoch end  ≥ t committee members publish their shares
              ↓
reveal     anyone reconstructs K, decrypts, and checks the plaintext against
           the original commitment. Mismatch ⇒ invalid submission (and a
           slashable bond), because the commitment binds the plaintext.
```

The submitter can be offline, jailed, or firewalled and still be paid. That is
the property that matters.

It buys three things at once, which is why it is worth the complexity:

- **Reveal-window censorship dies.** Nothing is required of the submitter after
  commit.
- **In-flight front-running dies.** Nobody — including the sequencer and the
  committee members individually — sees your artifact while they could still act
  on it. This was an open item in `coordination.md`.
- **Selective censorship becomes visible.** A sequencer cannot see what it is
  dropping, so it cannot drop *only* the submissions it dislikes. It must include
  everything or censor indiscriminately, and indiscriminate censorship is
  detectable by everyone at once. Forcing an attacker from targeted to
  indiscriminate is most of the win.

The binding property is what makes this safe, and it is free: the commitment is
already over the plaintext, so a submitter who seals garbage is caught the moment
the committee opens it. No new trust is introduced on that axis.

### What the committee can and cannot do

- It **cannot** read a submission early unless `t` members collude.
- It **can**, with `t` colluding members, read early and front-run. Committee
  membership must therefore be diverse and rotated per epoch, and the threshold
  set high enough that collusion is expensive.
- It **can** refuse to publish shares, which stalls the reveal. This is a
  liveness failure, not a confidentiality one, and it is why `n − t` must be
  large enough to tolerate absentees. A permanently stalled epoch must fall back
  to submitter-initiated reveal rather than losing the submission.
- A **timelock/VDF** alternative removes the committee entirely at the cost of
  requiring sequential-work assumptions and much fiddlier parameter choice. The
  committee is the pragmatic first implementation; the interface should not
  assume it forever.

## 3. Unlinkability, and why it fights attribution

Encryption hides *what*. Against a state that wants to know **who is working on
X**, hiding *who* is the property that matters, and it is harder.

Practical layers, in increasing cost:

1. **Per-objective pseudonyms.** A fresh signing key per objective, so activity
   cannot be linked across objectives. Cheap, and it defeats the most common
   analysis.
2. **Fresh payout addresses**, never reused.
3. **Zero-knowledge submission**: prove "I know the key that made a valid
   commitment" without revealing which commitment. Real, and expensive.

Now the finding that no amount of cryptography removes:

> **Citation flow requires linkage.** If your claim cites mine and value flows
> to me, the graph connecting us is public *by construction* — that graph is the
> attribution mechanism.

You can hide the mapping from pseudonym to person. You cannot hide the pseudonym
graph, because paying people for being built upon is exactly what it is for.
Anonymity and mechanical attribution are in direct tension, and a design that
claims both without qualification is lying. Concretely: a participant who wants
maximal anonymity should expect to forfeit citation income, and the system should
let them choose that explicitly rather than discovering it later.

## 4. Metadata leaks that survive encryption

The log still shows, per epoch: which objectives received submissions, how many,
of what size, and when. Against a well-resourced observer that is often enough —
"the objective on <topic> got three submissions the day after the announcement"
identifies a small set of people.

Mitigations, none free:

- **Fixed-size envelopes** (pad to a bucket) so size leaks nothing.
- **Cover traffic**: participants submit decoys indistinguishable from real
  submissions. Costs bandwidth and verification time, and someone has to pay
  for it.
- **Batch boundaries only**: publish per-epoch aggregates rather than per-arrival
  timestamps.

Cover traffic is the only one that defeats a global observer, and it is the one
nobody wants to pay for. Say so rather than implying the mitigations are
complete.

## 5. The network layer

Encrypted content over a blocked network is still blocked. This is out of scope
for the library and must not be out of mind:

- No single submission endpoint. A central API is a single IP to block.
- Pluggable transports / Tor / mixnets for participants under active network
  censorship.
- **The gossip layer is already an asset here.** `gossip.rs` is a CRDT designed
  for partial connectivity and eventual convergence — a partitioned participant
  catches up automatically when reconnected, and there is no round or leader that
  a partition can stall. Censorship resistance was not why it was built that way,
  but it is a real dividend.

## 6. Confidentiality classes

Encryption should be a declared property of an objective, not a blanket default,
because each class trades away a different amount of public verifiability.

| class | artifact visibility | verification | use |
|---|---|---|---|
| `public` | revealed at epoch end | anyone re-runs the verifier | the default, and what the guarantee is written for |
| `embargoed` | revealed after N epochs | anyone re-runs it, later | dual-use results needing coordinated disclosure; priority is timestamped immediately by the commitment |
| `sealed` | never revealed | **zero-knowledge only** | results that must never be published |

`embargoed` is the important one and it is nearly free: the commitment already
timestamps your priority publicly while the content stays sealed. That is exactly
the mechanism responsible disclosure needs, and it directly addresses the
auto-publishing-zero-day problem flagged in `threat-model.md` — a settled result
no longer implies a published result.

`sealed` is honest about its cost: without revealing the artifact, the only way
to pay for it is a zero-knowledge proof that the pinned verifier accepts it.
That is feasible for simple arithmetic certificate checkers and infeasible today
for a Lean kernel or an arbitrary evaluator. The class exists in the schema so
the limitation is explicit rather than discovered later.

## 7. What encryption cannot fix

- **A sequencer that includes nothing.** Blind inclusion stops *targeted*
  censorship; it does nothing about total refusal. That needs forced inclusion
  via a base layer — still the primary unresolved threat, and still the main
  argument in `consensus.md`.
- **Coercion of a known participant.** That is an unlinkability problem, and
  cryptography helps only up to the point where someone knows your name anyway.
- **A verifier that must see the artifact.** ZK moves this, at a cost that rules
  out most verifiers today.
- **A legal order against the operator.** Stage 0 has one operator; encryption
  does not change who can be served a subpoena. Only decentralized inclusion
  does.

## 8. Threat model summary

| adversary | goal | defence | status |
|---|---|---|---|
| network observer | read submissions | transport encryption + sealed envelopes | designed |
| sequencer | drop submissions it dislikes | blind inclusion — it cannot see what it drops | designed |
| sequencer | drop everything | forced inclusion on a base layer | **unsolved at Stage 0** |
| competitor | front-run an in-flight artifact | threshold reveal; nobody sees it in time | designed |
| attacker | stop a submitter from revealing | committee reveals without them | designed |
| state | identify who worked on a topic | per-objective pseudonyms; ZK submission | partial — the citation graph is inherently public |
| global observer | traffic analysis | fixed-size envelopes, cover traffic | partial, and expensive |
| t colluding committee members | early decryption | rotation, diversity, high threshold | mitigated, not prevented |
| anyone | forge a sealed artifact | the commitment binds the plaintext | handled |
| legal process | force takedown | decentralized inclusion | unsolved at Stage 0 |
