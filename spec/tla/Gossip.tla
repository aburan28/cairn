--------------------------------- MODULE Gossip ---------------------------------
(***************************************************************************)
(* The population CRDT: bounded memory, no consensus, and still confluent.  *)
(*                                                                         *)
(* Models src/gossip.rs -- `Population::merge`, `insert`, `prune`, and the  *)
(* per-island top-K retention of docs/design-stage0-completion.md §6.       *)
(*                                                                         *)
(* THE CLAIM UNDER TEST                                                    *)
(*                                                                         *)
(* The module docs argue that dropping a candidate outside the top K is     *)
(* safe: if it is not in the top K of `A \cup B`, then K candidates beat    *)
(* it, and those all survive into `A \cup B \cup C`, so it is not in the    *)
(* top K there either. That argument is correct, and it is also exactly the *)
(* kind of argument that is correct until someone adds a tiebreak or makes  *)
(* retention depend on arrival. So it is not assumed here; it is checked,   *)
(* as `PruningNeverChangesTheAnswer` and -- more sharply -- as merge        *)
(* associativity, which is *false* for any retention rule that is not       *)
(* confluent. A non-confluent prune would leave the two bracketings of      *)
(* `A \sqcup B \sqcup C` disagreeing, and two nodes that received the same  *)
(* messages in different orders would then hold different populations with  *)
(* nothing in the protocol to reconcile them.                              *)
(*                                                                         *)
(* WHY RANK IS INJECTIVE                                                   *)
(*                                                                         *)
(* The implementation orders by `(score, content hash)`, so ties are        *)
(* impossible: two candidates with equal scores are separated by their      *)
(* digests, and every node separates them the same way. `Rank` here is      *)
(* injective for exactly that reason. This is not a convenience -- it is    *)
(* the assumption the whole module rests on, because with genuine ties      *)
(* "the top K" is not a function and pruning is not deterministic. Modelling*)
(* ties would show the design failing for a reason the design already       *)
(* rules out.                                                              *)
(*                                                                         *)
(* WHAT IS SIMPLIFIED: every node here shares one `Capacity`. The real      *)
(* `merge` takes the *smaller* of the two capacities, so that a peer        *)
(* claiming a large bound cannot widen yours. That is a bound-negotiation   *)
(* rule, not a retention rule, and it is unit-tested; folding it in would   *)
(* multiply the state space without touching confluence, which is what this *)
(* module is for.                                                           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Nodes,
    Candidates,
    Island,      \* [Candidates -> Islands]
    Rank,        \* [Candidates -> Nat], injective; lower is better
    Islands,
    Capacity     \* K, per island

-----------------------------------------------------------------------------
(* THE INSTANCE. Function literals cannot live in a .cfg.                   *)
(*                                                                          *)
(* Five candidates over two islands, three in one and two in the other,     *)
(* with K = 2. The three-candidate island is the point: it is the smallest  *)
(* island in which pruning ever discards anything, so it is where confluence*)
(* can fail. The two-candidate island is the control -- nothing is ever     *)
(* dropped there, and it catches a prune that discards when it should not.  *)

IslandI == [c \in Candidates |-> IF c \in {"x1", "x2", "x3"} THEN 0 ELSE 1]

RankI == [c \in Candidates |->
    CASE c = "x1" -> 1
      [] c = "x2" -> 2
      [] c = "x3" -> 3
      [] c = "x4" -> 4
      [] OTHER    -> 5]

-----------------------------------------------------------------------------
(* Retention.                                                               *)

Members(i) == { c \in Candidates : Island[c] = i }

(* The best K of a set: everything with fewer than K things beating it.     *)
(* Written as a filter rather than as "sort and truncate" because the       *)
(* filter makes the confluence argument visible -- membership depends only  *)
(* on how many members beat you, which is monotone in the set.              *)
Best(S) == { c \in S : Cardinality({ d \in S : Rank[d] < Rank[c] }) < Capacity }

PruneSet(S) == UNION { Best(S \cap Members(i)) : i \in Islands }

(* Tabulated over every subset. This is a constant-level definition, so TLC *)
(* evaluates it once for the whole run rather than per state, which is what *)
(* makes quantifying the algebraic laws over all subsets affordable.        *)
PruneTable == [S \in SUBSET Candidates |-> PruneSet(S)]

Prune(S) == PruneTable[S]

(* The join. Insert everything from both sides, then enforce the bound --   *)
(* `Population::merge` exactly.                                             *)
Merge(A, B) == Prune(A \cup B)

Pruned == { S \in SUBSET Candidates : Prune(S) = S }

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

VARIABLES
    held,        \* [Nodes -> SUBSET Candidates]: each node's population
    discovered   \* every candidate any node has ever generated

vars == <<held, discovered>>

Init ==
    /\ held = [n \in Nodes |-> {}]
    /\ discovered = {}

(* A node generates a candidate locally. Each candidate is generated once,  *)
(* by one node, which bounds the run; who generates what is left free, so   *)
(* TLC covers every distribution of the best candidates across nodes --     *)
(* including the case where one node generates everything good and another  *)
(* has only candidates it will have to drop.                                *)
Discover(n, c) ==
    /\ c \notin discovered
    /\ held' = [held EXCEPT ![n] = Prune(@ \cup {c})]
    /\ discovered' = discovered \cup {c}

(* One-directional anti-entropy: `n` sends its population to `m`, and `m`   *)
(* merges. One direction rather than a simultaneous swap because that is    *)
(* what a message is, and because a protocol that only converges when both  *)
(* halves are delivered atomically is not a gossip protocol.                *)
Gossip(n, m) ==
    /\ n # m
    /\ held' = [held EXCEPT ![m] = Merge(held[m], held[n])]
    /\ UNCHANGED discovered

Next ==
    \/ \E n \in Nodes, c \in Candidates : Discover(n, c)
    \/ \E n \in Nodes, m \in Nodes : Gossip(n, m)

(* Fair pairwise merge: every pair eventually exchanges, whenever doing so  *)
(* would change anything. Nobody is obliged to keep generating candidates,  *)
(* so `Discover` gets no fairness -- and it needs none, since there are     *)
(* finitely many candidates and convergence is asserted after the last one. *)
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A n \in Nodes, m \in Nodes : WF_vars(Gossip(n, m))

-----------------------------------------------------------------------------
(* The CRDT laws. Quantified over every subset, not merely over reachable   *)
(* node states: these are properties of the merge function, and a function  *)
(* that is only associative on the arguments this model happens to reach is *)
(* not associative.                                                         *)

MergeCommutes ==
    \A A \in SUBSET Candidates, B \in SUBSET Candidates : Merge(A, B) = Merge(B, A)

MergeAssociates ==
    \A A \in SUBSET Candidates, B \in SUBSET Candidates, C \in SUBSET Candidates :
        Merge(Merge(A, B), C) = Merge(A, Merge(B, C))

MergeIdempotent ==
    \A A \in Pruned : Merge(A, A) = A

(* THE CONFLUENCE LEMMA, stated exactly as the module docs state it:        *)
(* pruning early is indistinguishable from pruning late. Every other        *)
(* property in this module follows from it, and it is the one a future      *)
(* retention change would break first.                                      *)
PruningNeverChangesTheAnswer ==
    \A A \in SUBSET Candidates, B \in SUBSET Candidates :
        Prune(Prune(A) \cup B) = Prune(A \cup B)

-----------------------------------------------------------------------------
(* Properties of the running system.                                        *)

TypeOK ==
    /\ discovered \subseteq Candidates
    /\ \A n \in Nodes : held[n] \subseteq Candidates

(* BOUNDED MEMORY. No island ever holds more than K, at any node, at any    *)
(* time -- including in the instant after a merge that received more than K *)
(* from a peer. This is why `from_value` re-prunes instead of trusting the  *)
(* encoded shape: the bound is ours to enforce, not the sender's.           *)
BoundedMemory ==
    \A n \in Nodes, i \in Islands :
        Cardinality(held[n] \cap Members(i)) <= Capacity

(* NOTHING GOOD IS LOST. The union of what the nodes are holding retains    *)
(* the same top K, per island, as the set of everything ever generated.     *)
(* Bounded retention is exact rather than approximate: a candidate dropped  *)
(* by one node early was never going to survive anywhere.                   *)
(*                                                                          *)
(* Stated against `discovered` rather than against the union of the node    *)
(* states, because the union of the node states is what pruning has already *)
(* had its way with -- comparing it to itself would prove nothing.          *)
NoGoodCandidateIsLost ==
    Prune(UNION { held[n] : n \in Nodes }) = Prune(discovered)

(* CONVERGENCE. Under fair pairwise merge the nodes agree, and stay agreed. *)
(* No rounds, no leader, no voting: two nodes that have seen the same       *)
(* messages hold the same population, and `<>[]` says they get there and do *)
(* not drift apart afterwards.                                              *)
Converges ==
    <>[] ( \A n \in Nodes, m \in Nodes : held[n] = held[m] )

=============================================================================
