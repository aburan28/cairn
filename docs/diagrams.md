# Diagrams

Architecture and detailed design, drawn from the code rather than from intent.
Every edge here corresponds to a real `use` or a real call; where the diagram
shows something unbuilt it is drawn dashed and labelled.

- [1. System context](#1-system-context) — who touches it and what crosses the boundary
- [2. Module architecture](#2-module-architecture) — the crate, and what depends on what
- [3. The settlement path](#3-the-settlement-path) — post → commit → reveal → settle
- [4. Objective lifecycle](#4-objective-lifecycle) — the state machine
- [5. The verdict taxonomy](#5-the-verdict-taxonomy) — why four statuses and only two settle
- [6. Sealed submission](#6-sealed-submission-and-threshold-reveal) — opening without the submitter
- [7. Storage layering](#7-storage-layering) — codec, quota, mirror
- [8. Money flow](#8-money-flow) — escrow, citation flow, the node fee
- [9. Trust boundaries](#9-trust-boundaries-and-sybil-surfaces) — and where sybil bites

---

## 1. System context

Four roles, one log. The property the whole design exists to deliver is the
dashed arrow at the bottom: **an auditor needs nothing but a copy of the log.**

```mermaid
flowchart TB
    funder["Funder<br/><i>escrows a bounty</i>"]
    agent["Submitter / AI agent<br/><i>produces artifacts</i>"]
    operator["Node operator<br/><i>re-verifies, stores, serves</i>"]
    auditor["Auditor<br/><i>anyone at all</i>"]

    subgraph pw["proofwork"]
        direction TB
        rules["Rules engine<br/>node.rs"]
        log[("Hash-linked log<br/>ledger.rs")]
        verify["Pinned verifiers<br/>verifiers/"]
        rules --- log
        rules --- verify
    end

    funder -->|"objective + verifier + reward"| rules
    agent -->|"commit, then reveal"| rules
    rules -->|"settlement"| agent
    operator -->|"re-runs every settled claim"| pw
    log -.->|"re-derive every result<br/>from nothing but this"| auditor
```

**What crosses the boundary and what does not.** An objective's verifier is
*part of its content-addressed id*, so a funder cannot change the rules of a
live bounty — doing so forks the objective and the claims against the original
stop resolving. That is not a guard; it is unrepresentable.

---

## 2. Module architecture

Solid edges are real dependencies. Note the two modules with **no inbound
arrows from the protocol core** — that is deliberate and load-bearing.

```mermaid
flowchart TD
    canonical["canonical<br/><i>content addressing<br/>no float variant</i>"]
    records["records<br/><i>Objective / Commitment / Claim</i>"]
    ledger["ledger<br/><i>append-only, hash-linked</i>"]
    node["node<br/><i>the rules engine</i>"]
    verifiers["verifiers<br/><i>certificate · evaluator<br/>lean · replay</i>"]
    frontier["frontier<br/><i>progressive bounties</i>"]
    attribution["attribution<br/><i>citation flow</i>"]
    gossip["gossip<br/><i>candidate CRDT</i>"]
    partition["partition<br/><i>coordinator-free assignment</i>"]
    sealed["sealed<br/><i>submissions openable<br/>without the submitter</i>"]
    crypto["crypto<br/><i>shamir · envelope · identity</i>"]
    store["store<br/><i>atrest · quota · mirror</i>"]
    incentive["incentive<br/><i>mechanism + game solvers</i>"]

    records --> canonical
    ledger --> canonical
    frontier --> canonical
    gossip --> canonical
    verifiers --> canonical
    sealed --> canonical
    attribution --> records
    sealed --> records
    sealed --> crypto
    node --> records
    node --> ledger
    node --> verifiers
    node --> frontier
    node --> canonical
    ledger --> store

    incentive -.->|"models, never calls"| node
    partition -.->|"pure function<br/>zero messages"| node

    style incentive stroke-dasharray: 5 5
    style partition stroke-dasharray: 5 5
```

Three things this picture is making a claim about:

**`canonical` is the root and depends on nothing.** It is the cross-implementation
contract — the reference implementation has to agree with it byte for byte — so it is
kept free of every other concern. Its `Value` has no float variant, which means
an object whose identity could differ between two honest nodes *cannot be
constructed*.

**`ledger → store` is the only new inbound edge.** At-rest encryption is a
storage concern; the hash chain is an integrity one. Sealing changes no entry
hash, no `prev` link, no Merkle root and no audit result, which is why
`verify_chain` needed no changes at all.

**`incentive` calls nothing.** It is a model of the node game, not a code path —
no canary is generated, no bond posted, no challenge issued. Drawing it
connected would be a lie about what runs.

---

## 3. The settlement path

The exact order in `Node::reveal`. Order is the design here: three of these
checks are only correct where they are.

```mermaid
sequenceDiagram
    autonumber
    actor S as Submitter
    participant N as node.rs
    participant L as ledger.rs
    participant V as verifiers/

    Note over S,N: t0 — fund
    S->>N: post(objective)
    N->>L: append "objective"

    Note over S,N: t1 — bind, reveal nothing
    S->>N: commit(H(artifact ‖ submitter ‖ nonce))
    N->>L: append "commitment"

    Note over S,N: t2 — reveal
    S->>N: reveal(claim, nonce, cites)
    N->>N: objective exists?
    N->>N: matching commitment?
    rect rgb(240, 235, 220)
        N->>N: duplicate? — computed BEFORE the append,<br/>or every claim is its own duplicate
    end
    N->>N: every citation resolvable?
    N->>N: ratchet? then the frontier it beat must be cited
    N->>L: append "claim"
    N->>V: run pinned verifier on the artifact
    V-->>N: Verdict: status, detail, score
    N->>L: append "verdict"

    alt verdict does not settle (unavailable / invalid spec)
        N-->>S: unsettled — objective stays open
    else rejected
        N-->>S: unsettled — a real answer, reached by a checker that ran
    else accepted
        alt progressive objective
            N->>L: append "frontier" + "settlement" (paid for distance moved)
        else duplicate artifact
            N-->>S: verifies fine, mints nothing
        else already settled
            N-->>S: unsettled
        else
            N->>L: append "settlement"
            N-->>S: settled, reward released
        end
    end
```

Why the shaded step is where it is: novelty is computed against the log
*before* the claim joins it. Move that line three statements later and every
claim becomes a duplicate of itself.

---

## 4. Objective lifecycle

```mermaid
stateDiagram-v2
    [*] --> Open: post — verifier pinned by hash
    Open --> Committed: commit — binds without revealing
    Committed --> Verifying: reveal
    Verifying --> Open: UNAVAILABLE — no toolchain, crash, timeout
    Verifying --> Open: REJECT — checked, and wrong
    Verifying --> Settled: ACCEPT — first novel artifact
    Verifying --> Advanced: ACCEPT — moves a progressive frontier
    Advanced --> Advanced: further improvement, must cite the frontier it beat
    Advanced --> Exhausted: pool fully paid out
    Settled --> [*]
    Exhausted --> [*]

    note right of Open
        UNAVAILABLE returns here, never to a
        refutation. "My Lean install is broken"
        must not become "your proof is wrong"
    end note

    note right of Advanced
        Payouts telescope on a cumulative curve,
        so the pool is identical however the
        curve is chopped — epsilon-farming pays
        exactly nothing extra
    end note
```

---

## 5. The verdict taxonomy

Four statuses, two of which move money. The split is the single most
consequential type decision in the crate.

```mermaid
flowchart TD
    run["run pinned verifier"] --> could{"could it run<br/>at all?"}
    could -->|"no: missing toolchain,<br/>crash, timeout"| unavail["UNAVAILABLE"]
    could -->|"spec is malformed"| badspec["INVALID_SPEC"]
    could -->|yes| ran{"what did<br/>it say?"}
    ran -->|"artifact is good"| acc["ACCEPT"]
    ran -->|"artifact is wrong"| rej["REJECT"]

    unavail --> nomove["settles nothing<br/>objective stays open"]
    badspec --> nomove
    acc --> moves["settles<br/>escrow may release"]
    rej --> moves

    style unavail fill:#f5e6cc,stroke:#b8860b
    style badspec fill:#f5e6cc,stroke:#b8860b
    style acc fill:#d9ead3,stroke:#38761d
    style rej fill:#d9ead3,stroke:#38761d
```

Collapsing `UNAVAILABLE` into `REJECT` would turn every infrastructure outage
into a claim about somebody's artifact — and hand an attacker a way to fail
every honest submission by taking verifiers offline.

---

## 6. Sealed submission and threshold reveal

Plain commit–reveal requires the submitter to act **twice**, and an adversary
who can neither forge nor steal your work can still take it by stopping the
second action. This is the fix.

```mermaid
sequenceDiagram
    autonumber
    actor S as Submitter
    participant SEAL as sealed.rs
    participant C as crypto/
    participant L as Log
    participant M as Committee (t of n)
    actor A as Anyone

    S->>SEAL: seal(artifact, nonce, committee, t)
    SEAL->>SEAL: commitment = H(artifact ‖ submitter ‖ nonce)
    SEAL->>C: ChaCha20-Poly1305(K, payload), aad = commitment
    C->>C: Shamir split K into t-of-n
    C->>C: seal share_i to member_i via ephemeral X25519
    SEAL->>L: append commitment + envelope + sealed shares

    Note over S: the submitter may now vanish —<br/>jailed, firewalled, offline

    Note over M,L: epoch boundary
    M->>L: ≥ t members publish their shares
    A->>C: reconstruct K from any t shares
    A->>SEAL: open(envelope, K)
    SEAL->>SEAL: re-derive H(artifact ‖ submitter ‖ nonce)
    alt matches the commitment
        SEAL-->>A: artifact, ready to verify
    else does not match
        SEAL-->>A: invalid submission — the sealer cheated
    end
```

**Binding, not secrecy, is the security argument.** The commitment already
hashes the plaintext, so a submitter who seals garbage is caught the moment the
committee opens it. Sealing moves **when** an artifact becomes public. It never
moves **whether**.

The two attacks this game admits pull the threshold in opposite directions:

```mermaid
flowchart LR
    subgraph vice["the committee sits in a vice"]
        direction TB
        low["low t<br/><b>t colluders open early</b><br/>and front-run the submission"]
        win["safe window<br/>V ≤ t·d·S′ &nbsp;and&nbsp; V ≤ (n−t+1)·S′"]
        high["high t<br/><b>n−t+1 colluders withhold</b><br/>and the reveal never opens"]
        low --> win --> high
    end
    gap["empty window ⇒ the committee is<br/>too small for the value it seals"]
    win -.-> gap
```

---

## 7. Storage layering

Where at-rest encryption sits, and what it deliberately does not touch.

```mermaid
flowchart TB
    node["node.rs<br/><i>rules engine</i>"]
    ledger["ledger.rs<br/><i>Entry, hash chain, Merkle root</i>"]
    codec{"Codec"}
    plain["Plain<br/>JSONL, one record per line"]
    sealedc["Sealed<br/>pwenc1:nonce:ciphertext<br/><i>aad binds the line index</i>"]
    file[("log/proofwork.jsonl")]

    node --> ledger
    ledger --> codec
    codec --> plain
    codec --> sealedc
    plain --> file
    sealedc --> file

    subgraph invariant["the invariant that keeps this local"]
        inv["entry hash, prev link, Merkle root and audit result<br/>are computed on PLAINTEXT and are identical either way"]
    end
    ledger -.-> invariant

    style invariant fill:#d9ead3,stroke:#38761d
```

The data directory, its two storage classes, and the mirror:

```mermaid
flowchart LR
    subgraph data["--data-dir"]
        direction TB
        logd["log/proofwork.jsonl<br/><b>PINNED</b> — never evicted"]
        cache["cache/<br/>RECLAIMABLE"]
        tmp["tmp/<br/>RECLAIMABLE"]
    end
    key["~/.proofwork/key<br/><b>outside the data dir,<br/>on purpose</b>"]
    dest[("chosen directory<br/>NAS · external disk · cloud folder")]

    key -.->|"unlocks"| logd
    data -->|"proofwork sync"| dest
    key -->|"NEVER copied"| blocked(("blocked"))

    quota["--max-size 20GB"] --> cache
    quota --> tmp
    quota -->|"cannot fit? REFUSE.<br/>never prune the log"| logd

    style logd fill:#f4cccc,stroke:#cc0000
    style key fill:#fff2cc,stroke:#bf9000
    style blocked fill:#f4cccc,stroke:#cc0000
```

A key beside its ciphertext looks fine right up until the folder is synced
somewhere else — and then it was never encryption at all. That is why the
default key path is outside the data directory, and why `sync` detects key files
by **content rather than filename**.

---

## 8. Money flow

Everything downstream of one rule: *a claim mints only if a bounty was escrowed
against that exact statement hash before any witness for it existed.*

```mermaid
flowchart TB
    funder["Funder"] -->|escrow| esc[("Escrow<br/>bound to the objective id")]
    esc -->|"verifier accepts"| settle["Settlement"]

    settle -->|"1 − δ"| winner["Settling claim's submitter"]
    settle -->|"δ, recursively,<br/>to max_depth"| cites["Cited claims<br/><i>conserves exactly;<br/>odd unit by sorted id</i>"]
    cites -->|"δ of δ …"| cites

    settle -->|"protocol fee φ"| pool["Node reward pool"]
    pool -->|verify_split| vp["Verification"]
    pool -->|availability_split| ap["Availability"]
    pool -->|custody_split| cp["Custody"]

    vp --> ops["Node operators<br/><i>split by STAKE, never per node</i>"]
    ap --> ops
    cp --> ops

    subgraph absent["deliberately absent"]
        mint["per-epoch subsidy / inflation"]
    end
    absent -.->|"would be the grinding attack<br/>wearing a different hat"| pool

    style absent stroke-dasharray: 5 5
    style mint fill:#f4cccc,stroke:#cc0000
```

Two consequences the diagram makes visible:

- **Security spend is proportional to settled value — and is zero at launch.**
  `proofwork incentives --settled 0` prints `fee pool supports no nodes`. Stated,
  not solved.
- **The pool decides how many nodes exist; it has no effect on whether they do
  the work.** A rubber-stamper collects the same share, so the pool cancels out
  of every honest-versus-lazy comparison.

---

## 9. Trust boundaries and sybil surfaces

```mermaid
flowchart TB
    subgraph trusted["needs no trust — checkable by anyone"]
        t1["artifact correctness<br/><i>re-run the pinned verifier</i>"]
        t2["log integrity<br/><i>hash chain + Merkle root</i>"]
        t3["attribution split<br/><i>integer, exact, deterministic</i>"]
        t4["work assignment<br/><i>pure function of beacon + id</i>"]
    end

    subgraph bounded["trusted within a stated bound"]
        b1["committee < t colluders"]
        b2["verifier purity and sandboxing"]
        b3["the beacon is not ground<br/><i>sequencer could; Stage 0 trusts it not to</i>"]
    end

    subgraph untrusted["not defended at Stage 0"]
        u1["sequencer inclusion<br/><i>censorship — the primary threat</i>"]
        u2["committee selection<br/><i>no mechanism exists at all</i>"]
        u3["judgement / retroactive prizes"]
    end

    style trusted fill:#d9ead3,stroke:#38761d
    style bounded fill:#fff2cc,stroke:#bf9000
    style untrusted fill:#f4cccc,stroke:#cc0000
```

Sybil resistance, surface by surface. The rule that generates every row:
**influence must be tied to something unforgeable or conserved under splitting** —
and this system has exactly two, verified artifacts and stake.

```mermaid
flowchart LR
    sybil(["one operator,<br/>k identities"]) --> sub["bounty submission"]
    sybil --> gos["gossip population"]
    sybil --> pool2["node reward pool"]
    sybil --> part["work partition"]
    sybil --> cite["citation flow"]
    sybil --> comm["committee seats"]

    sub --> r1["<b>pointless</b><br/>k identities still need<br/>k distinct valid artifacts;<br/>duplicates mint zero"]
    gos --> r2["<b>pointless</b><br/>ingest re-scores locally;<br/>you must do the real work"]
    pool2 --> r3["<b>neutral</b><br/>stake-weighted split;<br/>stake is conserved when split"]
    part --> r4["<b>partial</b><br/>assignment is advisory,<br/>so nothing is stolen —<br/>residual is coverage gaps"]
    cite --> r5["<b>REAL HOLE</b><br/>padding the cite list with<br/>sock puppets dilutes honest<br/>citees; bounded by δ"]
    comm --> r6["<b>BIGGEST HOLE</b><br/>no selection mechanism exists.<br/>Bonded seats would reduce it<br/>to the coalition bound"]

    style r1 fill:#d9ead3,stroke:#38761d
    style r2 fill:#d9ead3,stroke:#38761d
    style r3 fill:#d9ead3,stroke:#38761d
    style r4 fill:#fff2cc,stroke:#bf9000
    style r5 fill:#f4cccc,stroke:#cc0000
    style r6 fill:#f4cccc,stroke:#cc0000
```

---

## What these diagrams are not

They describe Stage 0 plus the two design modules built on top of it. Three
boxes above are drawn but not implemented — committee selection, the canary
generator, and forced inclusion — and each is labelled rather than quietly
rendered as though it ships. See [roadmap.md](roadmap.md) for the order worth
doing them in and [threat-model.md](threat-model.md) for what each one leaves
open until then.
