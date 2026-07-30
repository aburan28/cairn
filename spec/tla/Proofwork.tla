-------------------------------- MODULE Proofwork --------------------------------
(***************************************************************************)
(* The composition, and the one guarantee the whole design exists for:      *)
(*                                                                         *)
(*   > Anyone can independently re-derive every settled result from the log *)
(*   > alone.                                                              *)
(*                                                                         *)
(* WHAT "RE-DERIVABLE" HAS TO MEAN TO BE WORTH ANYTHING                    *)
(*                                                                         *)
(* It is not enough that an auditor *can* compute a settlement sequence     *)
(* from the log. It has to be that the operator cannot get away with any    *)
(* other one. Those are different statements, and only the second is a      *)
(* guarantee: if two sequences both pass audit, then the operator picks     *)
(* between them, and which one it picks decides who is paid.                *)
(*                                                                         *)
(* So the property here is stated as *uniqueness*:                          *)
(*                                                                         *)
(*   for every sequence an operator could publish, if the log-only audit    *)
(*   accepts it, then it is the canonical sequence.                         *)
(*                                                                         *)
(* TLC quantifies over every candidate sequence at every reachable log, so  *)
(* an audit rule that failed to pin something down shows up as a second     *)
(* sequence passing. That is the failure mode a weaker property -- "the     *)
(* canonical sequence passes audit" -- would hide completely.               *)
(*                                                                         *)
(* WHAT THIS MODULE COMPOSES                                               *)
(*                                                                         *)
(*   Ledger        the log is append-only and its contents are what they    *)
(*                 say they are; assumed here, checked there.               *)
(*   Verification  a claim settles only on Accept; Unavailable does not.    *)
(*   CommitReveal  batch order inside an epoch is the beacon's, not the     *)
(*                 sequencer's.                                             *)
(*   Frontier      what each settlement pays, and that the pool telescopes. *)
(*   Attribution   is deliberately *not* recomposed: citation flow          *)
(*                 redistributes an already-fixed settlement amount, so it  *)
(*                 cannot change the pool total, and folding it in would    *)
(*                 multiply the state space to re-check a property          *)
(*                 Attribution.tla already checks in isolation.             *)
(*                                                                         *)
(* WHY ONLY INPUTS ARE IN THE LOG HERE                                     *)
(*                                                                         *)
(* `log` is a sequence of claims -- inputs. Verdicts, settlements and the   *)
(* frontier do not appear in it as things the auditor trusts; they are      *)
(* recomputed. That mirrors src/p2p/sync.rs, where the same split decides   *)
(* what crosses the wire, and it is the reason the guarantee is checkable   *)
(* at all: an auditor that read the operator's settlement records and       *)
(* believed them would be auditing nothing.                                 *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Claims,
    Ix,             \* [Claims -> Nat], injective: stands for the claim id
    Ep,             \* [Claims -> Epochs]: the epoch the claim was revealed in
    Score,          \* [Claims -> Int]: what the pinned verifier measured
    Verdict,        \* [Claims -> statuses]
    Cites,          \* [Claims -> SUBSET Claims]
    Baseline, Target, Reward, MinImprovement,
    MaxEpoch,
    RequireMaximal  \* TRUE: the audit refuses a sequence that skipped a settleable claim

ACCEPT == "accept"

-----------------------------------------------------------------------------
(* THE INSTANCE. Function literals cannot live in a .cfg.                   *)
(*                                                                          *)
(*   k1  epoch 0, score 2, accepted, cites nothing -- opens the frontier    *)
(*   k2  epoch 0, score 4, accepted, cites k1 -- a legal improvement        *)
(*   k3  epoch 1, score 6, accepted, cites nothing -- an improvement that   *)
(*       does *not* cite the frontier holder, so it must be refused however *)
(*       good its score is                                                  *)
(*   k4  epoch 1, score 6, verdict `unavailable` -- a result that would     *)
(*       take the pool to the target if a non-settling status could settle  *)
(*                                                                          *)
(* k3 and k4 are the two ways to be right and still not get paid, and they  *)
(* are the reason the audit cannot be "did the score go up".                *)

IxI == [c \in Claims |-> CASE c = "k1" -> 1 [] c = "k2" -> 2
                           [] c = "k3" -> 3 [] OTHER -> 4]

EpI == [c \in Claims |-> IF c \in {"k1", "k2"} THEN 0 ELSE 1]

ScoreI == [c \in Claims |-> CASE c = "k1" -> 2 [] c = "k2" -> 4 [] OTHER -> 6]

VerdictI == [c \in Claims |-> IF c = "k4" THEN "unavailable" ELSE ACCEPT]

CitesI == [c \in Claims |-> CASE c = "k2" -> {"k1"}
                              [] c = "k4" -> {"k2"}
                              [] OTHER    -> {}]

-----------------------------------------------------------------------------
(* The ratchet, from Frontier.tla. Duplicated rather than EXTENDed because  *)
(* Frontier is a state machine with its own variables and this module only  *)
(* needs its arithmetic; importing the machine would drag in a second copy  *)
(* of the frontier as a variable and put the two out of step.               *)

Span == Target - Baseline

Progress(s) ==
    CASE s <= Baseline -> 0
      [] s >= Target   -> Span
      [] OTHER         -> s - Baseline

Cumulative(s) == (Reward * Progress(s)) \div Span

-----------------------------------------------------------------------------
(* Settlement order: the beacon's, not the sequencer's.                     *)
(*                                                                          *)
(* `H(beacon(epoch, anchor) || claim_id)`, modelled the same way as in      *)
(* CommitReveal -- injective within an epoch, and rotating with it, which   *)
(* are the only two properties any rule here uses.                          *)
NumClaims == Cardinality(Claims)
Rank(e, c) == (Ix[c] + e) % NumClaims

Precedes(a, b) ==
    \/ Ep[a] < Ep[b]
    \/ (Ep[a] = Ep[b] /\ Rank(Ep[a], a) < Rank(Ep[b], b))

RECURSIVE SortClaims(_)
SortClaims(S) ==
    IF S = {} THEN <<>>
    ELSE LET m == CHOOSE x \in S : \A y \in S : ~Precedes(y, x)
         IN  <<m>> \o SortClaims(S \ {m})

-----------------------------------------------------------------------------
(* The canonical derivation: what an auditor computes from the log alone.   *)

Empty == [frontier |-> Baseline, live |-> FALSE, holder |-> "none",
          paid |-> 0, seq |-> <<>>]

Improves(st, c) ==
    IF st.live
    THEN Progress(Score[c]) - Progress(st.frontier) >= MinImprovement
    ELSE Progress(Score[c]) >= MinImprovement

(* The frontier citation rule from src/node.rs: once an objective has a     *)
(* frontier, *every* submission must cite the claim holding it -- not only  *)
(* improvements. It is what makes attribution mechanical rather than a      *)
(* judgement call, and it is checkable from the log, which is why it is a   *)
(* protocol rule and not etiquette.                                          *)
CitesFrontier(st, c) == (~st.live) \/ (st.holder \in Cites[c])

(* Would this claim settle, given the state so far? All three conditions,   *)
(* and they refuse different things: a non-settling verdict (Verification), *)
(* an insufficient improvement (Frontier), a missing citation (node.rs).    *)
Settleable(st, c) ==
    /\ Verdict[c] = ACCEPT
    /\ Improves(st, c)
    /\ CitesFrontier(st, c)

Apply(st, c) ==
    IF Settleable(st, c)
    THEN [frontier |-> Score[c], live |-> TRUE, holder |-> c,
          paid |-> st.paid + (Cumulative(Score[c]) - Cumulative(st.frontier)),
          seq |-> Append(st.seq, c)]
    ELSE st

RECURSIVE Fold(_, _)
Fold(st, s) ==
    IF s = <<>> THEN st ELSE Fold(Apply(st, Head(s)), Tail(s))

Range(s) == { s[i] : i \in 1..Len(s) }

(* The canonical settlement state for a log: sort the claims into beacon    *)
(* order and fold. Note that it takes the *set* of logged claims -- the     *)
(* order they were appended in is discarded before anything is decided,     *)
(* which is precisely what item 5 buys and what makes the result            *)
(* independent of the sequencer.                                            *)
Derive(logged) == Fold(Empty, SortClaims(logged))

-----------------------------------------------------------------------------
(* The audit: what a reader with only the log can check about a settlement  *)
(* sequence somebody published.                                             *)

RECURSIVE AuditFrom(_, _, _)
AuditFrom(st, s, logged) ==
    IF s = <<>>
    THEN \* Nothing left to justify. Everything still in the log that could
         \* have settled here must therefore not be settleable -- otherwise
         \* the publisher dropped a claim that was owed a payment, which is
         \* censorship and is visible from the log.
         (~RequireMaximal) \/ (\A c \in logged \ Range(st.seq) : ~Settleable(st, c))
    ELSE LET c == Head(s) IN
         /\ c \in logged
         /\ c \notin Range(st.seq)
         /\ Settleable(st, c)
         \* Beacon order: nothing still unsettled may precede this claim.
         /\ \A d \in logged \ (Range(st.seq) \cup {c}) : ~Precedes(d, c)
         /\ AuditFrom(Apply(st, c), Tail(s), logged)

Audit(s, logged) == AuditFrom(Empty, s, logged)

-----------------------------------------------------------------------------
(* Behaviour: an operator appending claims to the log.                      *)

VARIABLES
    epoch,
    log      \* the claims in the log, in the order the operator appended them

vars == <<epoch, log>>

(* The claims a reader finds in the log. Everything derived below is a      *)
(* function of this set and not of `log` itself -- which is the modelled    *)
(* form of "settlement order within an epoch is fixed by the beacon rather  *)
(* than by arrival". The append order is nonetheless carried as state, so   *)
(* TLC visits every one of them and checks every property against each: an  *)
(* order-dependent result would show up as the same set of claims yielding  *)
(* different answers in two different reachable states.                     *)
logged == Range(log)

Init ==
    /\ epoch = 0
    /\ log = <<>>

(* A claim enters the log in its own epoch. The operator chooses where in   *)
(* the epoch to put it, which is the lever this module is checking is dead. *)
Post(c) ==
    /\ c \notin logged
    /\ Ep[c] = epoch
    /\ log' = Append(log, c)
    /\ UNCHANGED epoch

Tick ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ UNCHANGED log

Next == Tick \/ \E c \in Claims : Post(c)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Every settlement sequence an operator could publish. Distinct claims, in *)
(* some order, of any length -- so the quantification below covers a        *)
(* reordering, an omission, an insertion, and any combination.              *)
RECURSIVE Orderings(_)
Orderings(S) ==
    IF S = {}
    THEN {<<>>}
    ELSE {<<>>} \cup UNION { { <<c>> \o t : t \in Orderings(S \ {c}) } : c \in S }

Candidates == Orderings(Claims)

-----------------------------------------------------------------------------
(* Properties.                                                              *)

TypeOK == epoch \in 0..MaxEpoch /\ logged \subseteq Claims /\ Len(log) <= Cardinality(Claims)

(* THE STAGE 0 GUARANTEE.                                                   *)
(*                                                                          *)
(* Exactly one settlement sequence survives an audit that reads nothing but *)
(* the log, and it is the one anybody re-derives. An operator that reorders *)
(* for profit, omits a claim it owes, or settles one it does not, publishes *)
(* something an auditor refuses -- and the auditor needs no cooperation, no *)
(* second source and no trust to see it.                                    *)
(*                                                                          *)
(* This is the property no unit test can state, and it is the reason this   *)
(* specification exists.                                                    *)
SettlementIsUniquelyDetermined ==
    \A s \in Candidates : Audit(s, logged) => (s = Derive(logged).seq)

(* The canonical sequence does pass -- soundness to go with the uniqueness  *)
(* above, and worth stating separately because a broken audit that accepts  *)
(* nothing at all would satisfy the property above vacuously.               *)
CanonicalSequencePassesAudit == Audit(Derive(logged).seq, logged)

(* THE POOL IS EXACTLY CONSERVED. Total settled equals the cumulative at    *)
(* the frontier the log establishes -- never more than the pool, and the    *)
(* same total however the claims were interleaved.                          *)
PoolIsExactlyConserved ==
    /\ Derive(logged).paid = Cumulative(Derive(logged).frontier)
    /\ Derive(logged).paid <= Reward

(* A non-settling verdict never moves money, composed rather than assumed:  *)
(* this is the same rule Verification.tla checks in isolation, restated     *)
(* here over the settlement sequence so that a composition bug -- a         *)
(* settlement path that forgot to consult the verdict -- would show up.     *)
NothingSettlesWithoutAccept ==
    \A c \in Range(Derive(logged).seq) : Verdict[c] = ACCEPT

(* Every settlement after the first cites the claim it displaced, so the    *)
(* attribution DAG the log induces is exactly the improvement history.      *)
EverySettlementCitesTheFrontier ==
    LET s == Derive(logged).seq
    IN  \A i \in 2..Len(s) : s[i-1] \in Cites[s[i]]

=============================================================================
