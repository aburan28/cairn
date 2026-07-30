---------------------------------- MODULE Sync ----------------------------------
(***************************************************************************)
(* Record anti-entropy: what crosses the wire, and what does not.           *)
(*                                                                         *)
(* Models src/p2p/sync.rs -- bucketed inventories, `want_from`, `serve`,    *)
(* `ingest`, and `reconcile`.                                              *)
(*                                                                         *)
(* THE RULE THIS MODULE EXISTS FOR                                         *)
(*                                                                         *)
(*   > `objective`, `commitment` and `claim` cross the wire. `verdict`,     *)
(*   > `settlement` and `frontier` are re-derived locally.                  *)
(*                                                                         *)
(* Accepting a `verdict` from a peer would be taking its word for a         *)
(* verification, and the entire proposition of this network is that nobody  *)
(* has to. Every claim the design makes about re-derivability collapses if  *)
(* a single derived record can be pushed in from outside, so it is checked  *)
(* against an adversary who can put arbitrary bytes on the wire rather than *)
(* against a peer that follows the protocol.                                *)
(*                                                                         *)
(* HOW THE ADVERSARY IS MODELLED                                           *)
(*                                                                         *)
(* `Receive` has no precondition on the sender at all: any record may       *)
(* arrive at any peer at any time, from anywhere. This deliberately         *)
(* over-approximates the network -- it includes messages no peer sent -- so *)
(* that the properties below rest on the *receiver's* checks and on nothing *)
(* else. A model in which records could only arrive from a peer that held   *)
(* them would be assuming half of what `ingest` is there to enforce.        *)
(*                                                                         *)
(* WHAT A COLLIDING DIGEST BUYS, AND WHAT IT COSTS                         *)
(*                                                                         *)
(* A bucket is exchanged only when the two sides' XOR digests differ. A     *)
(* peer that forges a digest to match yours makes the bucket look settled   *)
(* -- and `Inventory::differing` is symmetric, so the bucket is then        *)
(* skipped in *both* directions. `lies` models exactly that: concealment is *)
(* not a one-way filter, and `ConcealmentIsSymmetric` is what makes it      *)
(* self-defeating rather than free. Finding such a collision is assumed     *)
(* possible here, which is far more generous than reality: the digest is a  *)
(* XOR of SHA-256 ids, so it is granted for free rather than being made     *)
(* the attacker's problem.                                                  *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Peers,
    Evil,        \* the one peer that may forge a bucket digest
    Records,
    Kind,        \* [Records -> record kinds]
    Bucket,      \* [Records -> Buckets]
    Buckets,
    Initial      \* [Peers -> SUBSET Records]: who starts with what

(* src/p2p/sync.rs EXCHANGEABLE, verbatim. *)
Exchangeable(k) == k \in {"objective", "commitment", "claim"}

-----------------------------------------------------------------------------
(* THE INSTANCE. Function literals cannot live in a .cfg.                   *)
(*                                                                          *)
(*   r1  a claim, bucket 0, starts at p1                                    *)
(*   r2  an objective, bucket 1, starts at p2                               *)
(*   r3  a claim, bucket 1, starts at evil                                  *)
(*   d1  a verdict, bucket 0, starts at evil                                *)
(*                                                                          *)
(* Evil holds `d1` on purpose. An honest node cannot hold a derived record  *)
(* -- `Peer::insert` refuses the kind -- but Evil is not running our code,  *)
(* and a verdict it computed and wants believed is precisely the record it  *)
(* would push. Without it in Evil's hands the derived-kind guard is         *)
(* unreachable in this model and `OnlyInputsAreHeld` would pass because     *)
(* nothing ever tried, which is the failure mode a model check is supposed  *)
(* to avoid rather than exhibit.                                            *)
(*                                                                          *)
(* Note that `d1` is advertised through the ordinary bucket listing. Ids do *)
(* not carry kinds, so an honest peer *will* solicit it and only finds out  *)
(* what it is when the body arrives. That is the real shape of the attack:  *)
(* the refusal has to happen at ingest, not at want.                        *)
(*                                                                          *)
(* The layout is also chosen so that concealing bucket 1 costs the liar     *)
(* something: bucket 1 holds an honest record (r2) as well as the liar's    *)
(* own (r3). A bucket containing only the liar's records would make         *)
(* concealment free and the symmetry claim untestable.                      *)

KindI == [r \in Records |-> CASE r = "r2" -> "objective"
                              [] r = "d1" -> "verdict"
                              [] OTHER    -> "claim"]

BucketI == [r \in Records |-> IF r \in {"r1", "d1"} THEN 0 ELSE 1]

InitialI == [p \in Peers |-> CASE p = "p1" -> {"r1"}
                               [] p = "p2" -> {"r2"}
                               [] OTHER    -> {"r3", "d1"}]

-----------------------------------------------------------------------------

VARIABLES
    held,         \* [Peers -> SUBSET Records]
    outstanding,  \* [Peers -> SUBSET Records]: asked for, not yet arrived
    lies          \* SUBSET Buckets: buckets Evil forges a matching digest for

vars == <<held, outstanding, lies>>

Honest == Peers \ {Evil}

InBucket(b) == { r \in Records : Bucket[r] = b }

(* A forged digest makes the bucket look identical to both sides.          *)
Concealed(p, q, b) == (p = Evil \/ q = Evil) /\ b \in lies

(* `Inventory::differing`: buckets whose digests disagree. Modelled on the  *)
(* underlying id sets rather than on the XOR, because for honest peers the  *)
(* XOR differs exactly when the sets do -- an accidental collision between  *)
(* two honest inventories needs a SHA-256 collision, which is assumed away  *)
(* everywhere in this specification. Deliberate collisions are `lies`.      *)
Differs(p, q, b) ==
    /\ ~Concealed(p, q, b)
    /\ (held[p] \cap InBucket(b)) # (held[q] \cap InBucket(b))

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

Init ==
    /\ held = Initial
    /\ outstanding = [p \in Peers |-> {}]
    /\ lies \in SUBSET Buckets

(* `want_from`: p compares bucket contents with q and asks for what it is   *)
(* missing in the buckets that differ. Recording the request is the whole   *)
(* point -- it is what makes anything arriving unrequested refusable.       *)
Ask(p, q) ==
    /\ p # q
    /\ outstanding' =
         [outstanding EXCEPT ![p] =
             @ \cup { r \in held[q] : r \notin held[p] /\ Differs(p, q, Bucket[r]) }]
    /\ outstanding[p] # outstanding'[p]
    /\ UNCHANGED <<held, lies>>

(* `ingest`, with no assumption whatsoever about where the record came      *)
(* from. Two guards, and they refuse different attacks:                     *)
(*                                                                          *)
(*   - a derived kind is refused however it arrived, even solicited, because *)
(*     no peer may ever supply one;                                          *)
(*   - a record nobody asked for is refused, so a peer cannot push unbounded *)
(*     data by volunteering it.                                              *)
(*                                                                          *)
(* A record whose body does not hash to the id it was requested under is    *)
(* the same case as the second guard: it is simply a different record, and  *)
(* that different record is not outstanding. That identification is only    *)
(* sound because ids are content addresses, which is `Ledger`'s assumption  *)
(* about hashing carried over here.                                          *)
Receive(p, r) ==
    /\ Exchangeable(Kind[r])
    /\ r \in outstanding[p]
    /\ held' = [held EXCEPT ![p] = @ \cup {r}]
    /\ outstanding' = [outstanding EXCEPT ![p] = @ \ {r}]
    /\ UNCHANGED lies

(* The refused half, written as its own action so that TLC explores states  *)
(* reached by an attacker trying and failing, not only states reached by    *)
(* the protocol succeeding. Without it, `NoUnsolicitedAdmission` would hold *)
(* because nothing ever attempted a violation.                              *)
ReceiveRefused(p, r) ==
    /\ ~(Exchangeable(Kind[r]) /\ r \in outstanding[p])
    /\ UNCHANGED vars

Next ==
    \/ \E p \in Peers, q \in Peers : Ask(p, q)
    \/ \E p \in Peers, r \in Records : Receive(p, r) \/ ReceiveRefused(p, r)

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A p \in Peers, q \in Peers : WF_vars(Ask(p, q))
    /\ \A p \in Peers, r \in Records : WF_vars(Receive(p, r))

-----------------------------------------------------------------------------
(* Properties.                                                              *)

TypeOK ==
    /\ \A p \in Peers : held[p] \subseteq Records
    /\ \A p \in Peers : outstanding[p] \subseteq Records
    /\ lies \subseteq Buckets

(* DERIVED RECORDS NEVER CROSS THE WIRE.                                    *)
(*                                                                          *)
(* Stated as "no peer ever holds one" rather than "no peer ever sends one", *)
(* because a peer serves out of what it holds: if a derived record can      *)
(* never be admitted it can never be forwarded either, and the receiving    *)
(* end is the only end whose behaviour a node controls. A rule enforced on  *)
(* the sender would be a request; enforced on the receiver it is a rule.    *)
(*                                                                          *)
(* Quantified over honest peers only, because Evil holding a verdict is not *)
(* a violation of anything -- it is the premise. The claim is that Evil     *)
(* cannot get it into anyone else.                                          *)
OnlyInputsAreHeld ==
    \A p \in Honest : \A r \in held[p] : Exchangeable(Kind[r])

(* UNSOLICITED RECORDS ARE REFUSED.                                         *)
(*                                                                          *)
(* An action property, because "was asked for" is a fact about the state    *)
(* *before* the record arrived and no predicate on a single state can see   *)
(* it. Every record a peer admits was outstanding an instant earlier --     *)
(* which, with `Ask` as the only source of outstanding ids, bounds what a   *)
(* peer can be made to store by what it decided to want.                    *)
NoUnsolicitedAdmission ==
    [][ \A p \in Peers : (held'[p] \ held[p]) \subseteq outstanding[p] ]_vars

(* Nobody invents records. The union of everything held never exceeds the   *)
(* union of what the peers started with, so the wire adds nothing to the    *)
(* system that was not already in it -- the model's version of "ids are     *)
(* content addresses and a body that does not match its id is a different   *)
(* record".                                                                 *)
NoRecordsAppearFromNowhere ==
    UNION { held[p] : p \in Peers } \subseteq UNION { Initial[p] : p \in Peers }

(* CONCEALMENT IS SYMMETRIC, so a forged digest costs the liar its own      *)
(* gossip. A bucket Evil hides is a bucket Evil never receives in either.   *)
(* This is the whole answer to "why not lie about your inventory": the      *)
(* mechanism that hides your records from a peer hides theirs from you, and *)
(* there is no configuration in which the trade is favourable.              *)
ConcealmentIsSymmetric ==
    \A b \in lies :
        (held[Evil] \cap InBucket(b)) = (Initial[Evil] \cap InBucket(b))

(* HONEST PEERS CONVERGE -- and converge on everything honest peers hold,   *)
(* whatever Evil does. A liar can withhold its own records; it cannot keep  *)
(* two honest peers apart, because they reconcile with each other on a      *)
(* path it is not on. That is what "hides nothing from a re-verifying peer" *)
(* amounts to once the derived records are off the wire: the only thing     *)
(* left to withhold is an input, and an input any honest peer has reaches   *)
(* every honest peer.                                                       *)
HonestPeersConverge ==
    <>[] ( /\ \A p \in Honest, q \in Honest : held[p] = held[q]
           /\ \A p \in Honest : (UNION { Initial[q] : q \in Honest }) \subseteq held[p] )

=============================================================================
