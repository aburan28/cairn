------------------------------- MODULE Attribution -------------------------------
(***************************************************************************)
(* Citation flow: paying the shoulders that were stood on.                  *)
(*                                                                         *)
(* Models src/attribution.rs `flow` -- a settled claim keeps `1 - delta` and *)
(* sends `delta` upstream, split among the claims it cites, recursively, to *)
(* a bounded depth, in exact integer arithmetic.                            *)
(*                                                                         *)
(* WHY THE ADVERSARY IS ALLOWED TO BUILD A CYCLE                           *)
(*                                                                         *)
(* Citations name content hashes, so a claim can only cite claims that      *)
(* already exist, and the citation graph is therefore acyclic. That is a    *)
(* real argument and it is checked below as `HonestCitationsAreAcyclic`.    *)
(*                                                                         *)
(* But the claim DAG is attacker-supplied, and "the input should be         *)
(* acyclic" is not a termination argument for code that walks it. The       *)
(* implementation says so and carries a per-frame ancestor path as its      *)
(* defence. So this module has `Rewire`, which points a claim's citations   *)
(* anywhere in the log including at itself, and then checks conservation on *)
(* the wreckage. Acyclicity is asserted only of graphs no adversary touched;*)
(* conservation is asserted of every graph.                                 *)
(*                                                                         *)
(* If the ancestor filter were dropped, `Flow` below would not terminate    *)
(* and TLC would not finish rather than reporting a violation. That is a    *)
(* real difference between the two properties and it is stated as such in   *)
(* docs/formal-model.md: termination is *observed*, not asserted.           *)
(*                                                                         *)
(* WHY delta IS A RATIONAL PAIR AND NOT A FRACTION                         *)
(*                                                                         *)
(* Same reason `canonical::Value` has no float variant. Two nodes that      *)
(* round differently disagree about who was paid, and a disagreement about  *)
(* money is a fork. `(amount * DeltaNum) \div DeltaDen` is what the         *)
(* implementation computes, truncation included, so the odd unit is a real  *)
(* unit that has to go somewhere -- which is what the remainder rule below  *)
(* is for.                                                                  *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    ClaimIds,
    Submitters,
    Submitter,    \* [ClaimIds -> Submitters]
    Idx,          \* [ClaimIds -> Nat], injective: the sorted-id order
    DeltaNum,
    DeltaDen,
    MaxDepth,
    Amounts,      \* the settlement amounts to check conservation over
    MaxRewires

-----------------------------------------------------------------------------
(* THE INSTANCE. Function literals cannot live in a .cfg.                   *)

SubmitterI == [c \in ClaimIds |-> IF c = "c1" THEN "s1"
                             ELSE IF c = "c2" THEN "s2"
                             ELSE "s3"]

IdxI == [c \in ClaimIds |-> IF c = "c1" THEN 1 ELSE IF c = "c2" THEN 2 ELSE 3]

-----------------------------------------------------------------------------

VARIABLES
    present,   \* claims in the log
    cites,     \* [ClaimIds -> SUBSET ClaimIds]
    rewires    \* how many times the adversary has rewired; 0 means honest

vars == <<present, cites, rewires>>

-----------------------------------------------------------------------------
(* The flow function.                                                       *)

Zero == [s \in Submitters |-> 0]
Plus(f, g) == [s \in Submitters |-> f[s] + g[s]]
Only(s, n) == [t \in Submitters |-> IF t = s THEN n ELSE 0]

(* TLA+ has no fold in the standard modules, so the sum is spelled out.     *)
RECURSIVE SumOver(_, _)
SumOver(S, f) ==
    IF S = {} THEN 0
    ELSE LET s == CHOOSE x \in S : TRUE IN f[s] + SumOver(S \ {s}, f)

Sum(f) == SumOver(Submitters, f)

(* Citations worth following: present in the log, and not already an        *)
(* ancestor on this path.                                                   *)
(*                                                                          *)
(* Both filters are load-bearing and they fail differently. Dropping an     *)
(* unresolvable id here rather than at the recursive call is what makes an  *)
(* unknown citation cost the citing claim nothing: its share is never split *)
(* off, so there is nothing to burn -- a claim citing only ghosts behaves   *)
(* exactly like a claim citing nobody. Dropping an ancestor is the cycle    *)
(* defence.                                                                 *)
Resolvable(id, path) == { c \in cites[id] : c \in present /\ c \notin path }

(* Ascending by id, because the odd units from an uneven split go to the    *)
(* earliest citations and every node must reproduce the same answer. Any    *)
(* rule conserves; only a rule derivable from the record itself keeps two   *)
(* nodes in agreement about who got the extra unit.                         *)
RECURSIVE SortIds(_)
SortIds(S) ==
    IF S = {} THEN <<>>
    ELSE LET m == CHOOSE x \in S : \A y \in S : Idx[x] <= Idx[y]
         IN  <<m>> \o SortIds(S \ {m})

RECURSIVE Flow(_, _, _)
RECURSIVE Children(_, _, _, _, _, _)

(* Sum of the recursive calls for citations at positions i..Len(ordered).   *)
Children(ordered, i, base, rem, depth, path) ==
    IF i > Len(ordered)
    THEN Zero
    ELSE LET portion == IF i - 1 < rem THEN base + 1 ELSE base
             here    == IF portion = 0
                        THEN Zero
                        ELSE Flow(ordered[i], portion, [depth |-> depth + 1, path |-> path])
         IN  Plus(here, Children(ordered, i + 1, base, rem, depth, path))

(* `ctx` bundles depth and the ancestor path so the operator takes three    *)
(* arguments; TLA+ recursion is by arity and keeping it at three keeps the  *)
(* mutual declaration above readable.                                        *)
Flow(id, amount, ctx) ==
    IF amount = 0
    THEN Zero
    ELSE LET cs == Resolvable(id, ctx.path)
             k  == Cardinality(cs)
         IN  IF ctx.depth >= MaxDepth \/ k = 0
             THEN Only(Submitter[id], amount)
             ELSE LET upstream == (amount * DeltaNum) \div DeltaDen
                      kept     == amount - upstream
                      base     == upstream \div k
                      rem      == upstream % k
                  IN  Plus(Only(Submitter[id], kept),
                           Children(SortIds(cs), 1, base, rem,
                                    ctx.depth, ctx.path \cup {id}))

Payouts(id, amount) == Flow(id, amount, [depth |-> 0, path |-> {}])

-----------------------------------------------------------------------------
(* Reachability, for the properties.                                        *)

(* Claims reachable from S in one to k citation hops -- strictly *hops*,    *)
(* so `id` itself is in the result only if some cycle returns to it. That   *)
(* is what lets one definition serve both the decay bound and the           *)
(* acyclicity check.                                                        *)
RECURSIVE Hops(_, _)
Hops(S, k) ==
    IF k <= 0
    THEN {}
    ELSE LET nxt == UNION { cites[c] \cap present : c \in S }
         IN  nxt \cup Hops(nxt, k - 1)

Within(id, k) == Hops({id}, k)

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

Init ==
    /\ present = {}
    /\ cites = [c \in ClaimIds |-> {}]
    /\ rewires = 0

(* Append a claim. It may cite anything already in the log and nothing      *)
(* else: a citation is a content hash, and naming a claim that does not     *)
(* exist yet requires inverting SHA-256. This one guard is the whole        *)
(* acyclicity argument, which is why it is worth stating as a model action  *)
(* rather than assuming the DAG is acyclic to begin with.                   *)
PostClaim(c) ==
    /\ c \notin present
    /\ \E cs \in SUBSET present :
         cites' = [cites EXCEPT ![c] = cs]
    /\ present' = present \cup {c}
    /\ UNCHANGED rewires

(* The attacker-supplied DAG. Not something the protocol permits -- it is   *)
(* what a corrupted log or a hostile peer hands the traversal, and the      *)
(* question is whether `flow` survives it.                                  *)
Rewire(c) ==
    /\ c \in present
    /\ rewires < MaxRewires
    /\ \E cs \in SUBSET present :
         cites' = [cites EXCEPT ![c] = cs]
    /\ rewires' = rewires + 1
    /\ UNCHANGED present

Next == \E c \in ClaimIds : PostClaim(c) \/ Rewire(c)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                              *)

TypeOK ==
    /\ present \subseteq ClaimIds
    /\ rewires \in 0..MaxRewires
    /\ \A c \in ClaimIds : cites[c] \subseteq ClaimIds

Honest == rewires = 0

(* CITATIONS POINT BACKWARDS, SO THE GRAPH IS ACYCLIC.                      *)
(*                                                                          *)
(* Derived rather than assumed: the only way a claim acquires citations is  *)
(* `PostClaim`, whose guard is "already in the log", and TLC checks that no *)
(* sequence of appends reaches a state where any claim reaches itself. The  *)
(* alternative -- declaring the graph acyclic in the model -- would have    *)
(* assumed the thing the citation rule exists to produce.                   *)
(*                                                                          *)
(* Conditioned on `Honest` because `Rewire` deliberately breaks it. That is *)
(* not a loophole: the properties below are asserted with no such guard.    *)
HonestCitationsAreAcyclic ==
    Honest => \A c \in present : c \notin Within(c, Cardinality(ClaimIds))

(* EXACT CONSERVATION. Payouts sum to precisely the amount settled -- on    *)
(* every graph, including the rewired ones with cycles in them. No value is *)
(* created and none is burned.                                              *)
(*                                                                          *)
(* Both halves are real. Creation would mint units the pool cannot fund;    *)
(* burning is just as bad, because a unit that vanishes makes the ledger's  *)
(* totals stop adding up and an auditor cannot tell that from theft.        *)
(*                                                                          *)
(* Quantified over a small set of amounts rather than all of Nat: this is   *)
(* bounded-checked. The amounts are chosen to include one that divides      *)
(* evenly at every hop and one that does not, since the uneven case is the  *)
(* only one where the remainder rule can lose a unit.                       *)
Conserves ==
    \A c \in present, amt \in Amounts : Sum(Payouts(c, amt)) = amt

(* Nothing is ever paid a negative amount -- the `saturating_sub` in the    *)
(* implementation, stated as a property rather than trusted to the type.    *)
NoNegativePayouts ==
    \A c \in present, amt \in Amounts, s \in Submitters : Payouts(c, amt)[s] >= 0

(* DECAY IS BOUNDED. Value stops after MaxDepth hops: nobody outside the    *)
(* neighbourhood the walk can reach is paid anything. This is what makes    *)
(* the walk terminate on a finite log, and it is also the economic          *)
(* statement -- a citation twenty hops back earns nothing, which is a       *)
(* deliberate choice and not an accident of the traversal.                  *)
DecayIsBounded ==
    \A c \in present, amt \in Amounts, s \in Submitters :
        (Payouts(c, amt)[s] > 0) =>
            \/ s = Submitter[c]
            \/ \E d \in Within(c, MaxDepth) : Submitter[d] = s

(* The settled claim always keeps something, provided delta < 1. This is    *)
(* the incentive statement: citing upstream costs a fixed fraction, so      *)
(* citing honestly is never worse than the alternative by more than delta,  *)
(* and a claim can never be drained to nothing by the citations it makes.   *)
SubmitterKeepsAShare ==
    (DeltaNum < DeltaDen) =>
        \A c \in present, amt \in Amounts :
            (amt > 0) => Payouts(c, amt)[Submitter[c]] > 0

=============================================================================
