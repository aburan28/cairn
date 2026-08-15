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

cairn's entire guarantee is **anyone can independently re-derive every result
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
commit    submitter publishes, in one `commitment` record:
            commitment = H(artifact ‖ submitter ‖ nonce)      (as before)
            envelope   = ChaCha20-Poly1305(K, {artifact, nonce, created_at,
                                               cites, signature})
            shares     = Shamir(K, t of n), share_i sealed to committee member i
                         by KEM (Classic McEliece, and any other suite that
                         member published — see kem.rs)
              ↓
epoch end  ≥ t committee members publish `committee_share` records
              ↓
reveal     anyone reconstructs K, decrypts, and checks the plaintext against
           the original commitment. Mismatch ⇒ invalid submission (and a
           slashable bond), because the commitment binds the plaintext.
```

The submitter can be offline, jailed, or firewalled and still be paid. That is
the property that matters.

**The whole claim is sealed, not only the artifact.** That looks like a detail
and is not. A claim whose `submitter` is an ed25519 key must be signed by that
key, and the committee does not hold it — so a payload of `{artifact, nonce}`
alone produced a reveal path that worked for anonymous nicknames and failed for
exactly the signed identities that earn citation income. Sealing the signature
costs 64 bytes. Sealing `cites` with it is what lets a sealed submission cite
the frontier, without which the mechanism would have been unusable on
progressive objectives — the ones where being censored costs the most.

### None of that is a promise: it is a rule

*Built*: `records::CommitteeShare`, `Node::committee_for`,
`Node::check_committee_share`, `Node::open_sealed`, and the same checks in
`reference/rust`. `tests/committee_reveal.rs` runs the scenario end to end.

Three nouns in "a threshold committee opens it at the epoch boundary" used to be
anchored to nothing a reader could check. Each is now derived from records:

| noun | was | is |
|---|---|---|
| **which committee** | whoever the submitter chose to seal to | the `COMMITTEE_SIZE` peers with the lowest `H(beacon(epoch, anchor) ‖ peer.transport)`, drawn from the log's own peer records |
| **the epoch boundary** | whatever a member's local clock said | a share's epoch comes from its `created_at` and must be strictly later than the commitment's — a comparison of two records an auditor re-reads |
| **the opening** | off-log, by agreement | `committee_share` records on the log, signed by the seat's identity, re-checked by every reader and by `audit` |

The draw is a pure function of public inputs, so nobody issues an invitation and
nobody can decline to send one — the same property `coordination.md` gets for
work assignment. A member computes their own seat; anyone recomputes anyone's.

And the *parameters* are the network's, not the submitter's. `threshold` travels
inside the envelope where the submitter writes it, so a submission sealed
one-of-five is one every drawn member opens alone the moment the epoch turns.
`Node::commit` therefore pins `t` and `n` against the constants the draw uses
and refuses anything else.

**What is still not checkable: which member lied.** A Shamir point cannot be
verified on its own, and the schemes that would fix that — Feldman, Pedersen —
rest on discrete log being hard in a group, which is precisely the assumption a
post-quantum network has declined to make. So a member who publishes garbage
cannot be identified, only routed around: `open_sealed` tries every `t`-subset
of the published shares, which is at most `C(5,3) = 10` AEAD checks and is
bounded because a committee has five seats and one share each. A liar costs the
network ten hashes and cannot stall a reveal that `t` honest members answered.

It buys three things at once, which is why it is worth the complexity:

- **Reveal-window censorship dies.** Nothing is required of the submitter after
  commit.
- **In-flight front-running dies at the source.** Epoch-batched commit–reveal
  already stops a competitor *acting* on what they see, because a reveal in
  epoch N+1 cannot be committed against until N+2. Sealing goes further: nobody
  — including the sequencer and the committee members individually — sees the
  artifact at all until it is too late to matter. The difference is whether the
  sequencer gets to know what it is about to settle.
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
- It **can**, with `t` colluding members, read early and front-run. Rotation is
  now mechanical — the draw mixes in the epoch beacon, so squatting a committee
  costs a fresh grinding effort each epoch — but three of five is three of five,
  and nothing here makes collusion impossible.
- It **can** refuse to publish shares, which stalls the reveal. This is a
  liveness failure, not a confidentiality one, and it is why `n − t` must be
  large enough to tolerate absentees. A permanently stalled epoch must fall back
  to submitter-initiated reveal rather than losing the submission — the plain
  path is unchanged and always available.
- A **timelock/VDF** alternative removes the committee entirely at the cost of
  requiring sequential-work assumptions and much fiddlier parameter choice. The
  committee is the pragmatic first implementation; the interface should not
  assume it forever.

**The Stage 0 caveat that swallows the others.** The committee is drawn from the
peer records in the log, and at Stage 0 nothing adds one but an operator's
bootstrap file. That is what makes a five-seat committee meaningful today, and
it is also the ceiling: the moment anyone can append a peer record, an attacker
who registers enough peers owns a majority of every drawn committee, and no
choice of `COMMITTEE_SIZE` fixes it. It needs identities that cost something,
which is the same Stage 2 problem `p2p.md` names for peer sampling and eclipse
resistance. Grinding for a seat does cost a McEliece keypair — the draw ranks on
the transport id, which is the hash of one — and a constant factor is not a
defence.

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

### Status

Implemented as `Objective.confidentiality` in both implementations
(`records.rs`, `records.py`) and in `spec/objective.schema.json`. Three
properties are worth stating because each is a decision rather than a detail:

- **`sealed` is refused, not downgraded.** `validate` errors rather than
  quietly treating the request as `embargoed`. A funder who asked for "never
  revealed" and silently got "revealed later" would be misled about the only
  thing they cared about.
- **An unknown class is refused, not defaulted.** Falling back to `public`
  would publish an artifact whose funder asked for something else, so an
  unrecognised value is an error on both the constructor and the decoder path.
- **The default is omitted from the canonical form.** `public` serialises to
  nothing, exactly like an unset `deadline` or `ratchet`. Emitting it would have
  changed the digest of every objective ever written — breaking the conformance
  vectors and orphaning every claim already posted against a live bounty. The
  conformance vectors pin this directly: one fixture writes `"public"`
  explicitly and must produce an id byte-identical to the fixture that omits it.

What is *not* implemented is any enforcement of the embargo itself. The class is
recorded in the objective's identity, so it cannot be changed mid-bounty, but
nothing in Stage 0 withholds an `embargoed` artifact at the appropriate time.
The hook it needs now exists: settlement is deferred to the close of the reveal
epoch and drains in batches, so "hold this one for N more epochs" has somewhere
to live that it did not before. Wiring `sealed.rs` and the class into that
drain is the remaining work. Declaring the class is the part that had to come
first, because it is part of the objective's id and therefore cannot be
retrofitted onto objectives already funded.

[`design/embargo-release.md`](design/embargo-release.md) designs that wiring.
Its main finding is that §2's committee cannot be reused as-is: shares are
sealed to the peers drawn at *commit* time, so a multi-epoch embargo freezes the
membership this section requires to be "diverse and rotated per epoch".

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
| network observer | read submissions | transport encryption + sealed envelopes | **built** |
| sequencer | drop submissions it dislikes | blind inclusion — it cannot see what it drops | **built** |
| sequencer | drop everything | forced inclusion on a base layer | **unsolved at Stage 0** |
| competitor | front-run an in-flight artifact | threshold reveal, and a share published before the commitment's epoch closes is refused | **built** |
| attacker | stop a submitter from revealing | committee reveals without them, from records | **built** |
| a member | publish for somebody else's seat | the draw names the identity, the signature proves it | **built** |
| a member | stall a reveal with a bad share | subset search over the published shares | mitigated — the liar is not identifiable, see above |
| a submitter | seal at a threshold one member can open | `t` and `n` pinned at commit against the network's constants | **built** |
| a quantum adversary | record now, decrypt later | shares sealed by KEM, never Diffie–Hellman | **built** |
| state | identify who worked on a topic | per-objective pseudonyms; ZK submission | partial — the citation graph is inherently public |
| global observer | traffic analysis | fixed-size envelopes, cover traffic | partial, and expensive |
| t colluding committee members | early decryption | per-epoch rotation by beacon, high threshold | mitigated, not prevented |
| an attacker who can register peers | own a majority of every committee | costly identities | **unsolved at Stage 0** — see above |
| anyone | forge a sealed artifact | the commitment binds the plaintext | handled |
| legal process | force takedown | decentralized inclusion | unsolved at Stage 0 |


## A note on the local disk

Everything above concerns what observers of the *network* can see. What a node
keeps on its own disk is a separate question with a separate answer: the local
store is encrypted at rest, and that is a property of the operator's copy rather
than of the protocol. It changes no hash, no Merkle root and no audit result, and
it deliberately does not extend to artifacts the network publishes -- those must
stay readable or the project's one guarantee evaporates. See
[storage.md](storage.md).
