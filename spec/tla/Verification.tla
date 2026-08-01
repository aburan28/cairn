------------------------------ MODULE Verification ------------------------------
(***************************************************************************)
(* The four-status taxonomy, and the rule the whole network rests on.       *)
(*                                                                         *)
(*   > A verifier that cannot run returns Unavailable. Never Accept, never  *)
(*   > Reject.                                                             *)
(*                                                                         *)
(* Models src/verifiers/mod.rs: `Status::{Accept, Reject, Unavailable,      *)
(* InvalidSpec}`, `Status::settles`, and the V3 `statistical` kind of       *)
(* docs/design-stage0-completion.md §4.                                     *)
(*                                                                         *)
(* WHY THE STATUS IS A FUNCTION OF THE NODE'S CONDITION, NOT A CHOICE      *)
(*                                                                         *)
(* The interesting failure is not a verifier that returns the wrong answer  *)
(* -- nothing detects that, and the design does not claim to. It is a       *)
(* verifier that returns *an answer at all* when it could not run. So the   *)
(* verdict here is computed from the node's condition rather than chosen    *)
(* nondeterministically, and the properties then ask whether any reachable  *)
(* condition produces a settling verdict it should not have.                *)
(*                                                                         *)
(* The order of the two failure checks is the implementation's and it       *)
(* matters: the pinned code's hash is verified *before* the child process   *)
(* is spawned, so a tampered pin is `InvalidSpec` on every node, including  *)
(* nodes with no toolchain at all. A node that reported `Unavailable` for a *)
(* tampered objective would hide a broken objective behind an ordinary      *)
(* infrastructure excuse.                                                   *)
(*                                                                         *)
(* WHY THE SEED IS A CONSTANT                                              *)
(*                                                                         *)
(* §4 requires any Monte Carlo inside a statistical statistic to be driven  *)
(* by the objective's pinned seed, so two honest nodes agree bitwise.       *)
(* `SeedPinned` makes that a switch, because a property that holds either   *)
(* way is not evidence for the rule. With `SeedPinned = FALSE` -- each node *)
(* drawing its own seed -- TLC violates `HonestNodesAgree` on the artifact  *)
(* whose statistic is seed-sensitive. The shipped configuration is TRUE.    *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Nodes,
    Artifacts,
    Seeds,
    PinnedSeed,      \* the seed the objective carries, hence part of its id
    NodeSeed,        \* [Nodes -> Seeds]: what a node would pick unaided
    Score,           \* [Artifacts -> [Seeds -> Int]]: the pinned statistic
    Threshold,
    SeedPinned,      \* TRUE: every node uses PinnedSeed
    MaxDisruptions   \* how many times the adversary may break things

ACCEPT      == "accept"
REJECT      == "reject"
UNAVAILABLE == "unavailable"
INVALID     == "invalid_spec"

(* The one place where "may this move value" is decided.                    *)
Settles(s) == s \in {ACCEPT, REJECT}

-----------------------------------------------------------------------------
(* THE INSTANCE. Function literals cannot live in a .cfg, so the concrete   *)
(* scenario lives here and the .cfg substitutes it.                         *)
(*                                                                          *)
(*   good   clears the threshold under every seed -- settles Accept         *)
(*   seedy  fails under seed 0 and clears under seed 1                      *)
(*                                                                          *)
(* Two artifacts rather than three, because `seedy` under the pinned seed 0 *)
(* already makes Reject reachable, so a third artifact that is Reject for   *)
(* everyone would add states and no case. `seedy` carries both jobs: it is  *)
(* the settling rejection in the shipped configuration and it is the        *)
(* artifact on which the nodes disagree once the seed is unpinned.          *)

ScoreI ==
    [a \in Artifacts |->
        [s \in Seeds |->
            IF a = "good" THEN 5 ELSE (IF s = 0 THEN -5 ELSE 5) ]]

NodeSeedI == [n \in Nodes |-> IF n = "n1" THEN 0 ELSE 1]

-----------------------------------------------------------------------------

VARIABLES
    up,           \* [Nodes -> BOOLEAN]: is this node's toolchain present?
    specOk,       \* does the pinned code still match its hash?
    verdicts,     \* every verdict ever recorded, with the conditions that produced it
    settled,      \* artifacts whose objective has been closed by a settling verdict
    disruptions

vars == <<up, specOk, verdicts, settled, disruptions>>

SeedFor(n) == IF SeedPinned THEN PinnedSeed ELSE NodeSeed[n]

(* The pinned statistic's own answer, once the node can actually run it.    *)
(* `direction = maximize` with an integer threshold, exactly as `evaluator` *)
(* -- §4's point is that the statistical kind decides accept/reject the     *)
(* same way, and that the criterion is fixed by the objective's id rather   *)
(* than chosen after the data.                                              *)
Outcome(n, a) == IF Score[a][SeedFor(n)] >= Threshold THEN ACCEPT ELSE REJECT

(* The status this node reaches for this artifact right now.                *)
Status(n, a) ==
    CASE ~specOk -> INVALID
      [] ~up[n]  -> UNAVAILABLE
      [] OTHER   -> Outcome(n, a)

VerdictRec(n, a) == [node |-> n, art |-> a, status |-> Status(n, a)]

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

Init ==
    /\ up = [n \in Nodes |-> TRUE]
    /\ specOk = TRUE
    /\ verdicts = {}
    /\ settled = {}
    /\ disruptions = 0

(* The verifier-offline attack: take the checkers down so honest            *)
(* submissions "fail". Bounded, because an adversary who can disrupt        *)
(* forever defeats every liveness property of every system and the          *)
(* interesting question is what happens when the outage ends.               *)
Fail(n) ==
    /\ up[n]
    /\ disruptions < MaxDisruptions
    /\ up' = [up EXCEPT ![n] = FALSE]
    /\ disruptions' = disruptions + 1
    /\ UNCHANGED <<specOk, verdicts, settled>>

BreakSpec ==
    /\ specOk
    /\ disruptions < MaxDisruptions
    /\ specOk' = FALSE
    /\ disruptions' = disruptions + 1
    /\ UNCHANGED <<up, verdicts, settled>>

Recover(n) ==
    /\ ~up[n]
    /\ up' = [up EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<specOk, verdicts, settled, disruptions>>

FixSpec ==
    /\ ~specOk
    /\ specOk' = TRUE
    /\ UNCHANGED <<up, verdicts, settled, disruptions>>

(* Run the pinned verifier and record what happened. Everything is          *)
(* recorded, including the failures: a claim and its verdict are written to *)
(* the log before any settlement decision is taken, so an unverifiable      *)
(* submission leaves the same evidence trail as a winning one.              *)
Run(n, a) ==
    /\ VerdictRec(n, a) \notin verdicts
    /\ verdicts' = verdicts \cup {VerdictRec(n, a)}
    /\ UNCHANGED <<up, specOk, settled, disruptions>>

(* Only a settling verdict may close an objective.                          *)
Settle(a) ==
    /\ a \notin settled
    /\ \E v \in verdicts : v.art = a /\ Settles(v.status)
    /\ settled' = settled \cup {a}
    /\ UNCHANGED <<up, specOk, verdicts, disruptions>>

Next ==
    \/ \E n \in Nodes : Fail(n) \/ Recover(n)
    \/ BreakSpec \/ FixSpec
    \/ \E n \in Nodes, a \in Artifacts : Run(n, a)
    \/ \E a \in Artifacts : Settle(a)

(* Fairness on recovery and on making progress, none on the disruptions.    *)
(* An adversary is never obliged to stop attacking; it is bounded instead,  *)
(* by `MaxDisruptions`, which is the honest way to say that the liveness    *)
(* result below holds for outages that end and says nothing about one that  *)
(* does not.                                                                *)
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A n \in Nodes : WF_vars(Recover(n))
    /\ WF_vars(FixSpec)
    /\ WF_vars(\E n \in Nodes, a \in Artifacts : Run(n, a))
    /\ WF_vars(\E a \in Artifacts : Settle(a))

-----------------------------------------------------------------------------
(* Properties.                                                              *)

TypeOK ==
    /\ up \in [Nodes -> BOOLEAN]
    /\ specOk \in BOOLEAN
    /\ settled \subseteq Artifacts
    /\ disruptions \in 0..MaxDisruptions
    /\ \A v \in verdicts : v.status \in {ACCEPT, REJECT, UNAVAILABLE, INVALID}

(* `Unavailable` and `InvalidSpec` never settle. Nothing closes an          *)
(* objective except a real verdict about the artifact.                      *)
NonSettlingNeverCloses ==
    \A a \in settled : \E v \in verdicts : v.art = a /\ Settles(v.status)

(* A VERIFIER OUTAGE NEVER BECOMES A REJECTION.                             *)
(*                                                                          *)
(* Stated as "no node in a broken condition can reach a settling status",    *)
(* over every reachable state, rather than as "a down node returns           *)
(* Unavailable". The second names one status; the first forbids the whole    *)
(* class of mistakes, including one nobody thought to name.                  *)
(*                                                                          *)
(* Quantifying over reachable states rather than over recorded verdicts is   *)
(* not a weakening. `Status` is a function of the current condition alone,   *)
(* so every verdict any node could ever record is `Status(n, a)` in some     *)
(* reachable state, and an invariant that holds in all of them holds of      *)
(* every verdict that was ever recorded. The alternative -- a ghost field on *)
(* each verdict remembering the condition it was produced under -- states    *)
(* exactly the same thing and multiplies the number of distinct verdict      *)
(* records by four, which is enough to put this module past the two-minute   *)
(* budget.                                                                   *)
(*                                                                           *)
(* This is the invariant behind the threat-model row "verifier-offline       *)
(* attack": an adversary who takes every verifier down produces only         *)
(* non-settling verdicts, so it cannot fail an honest submission -- it can   *)
(* only delay it.                                                            *)
OutageIsNeverRejection ==
    \A n \in Nodes, a \in Artifacts :
        (~up[n] \/ ~specOk) => ~Settles(Status(n, a))

(* A tampered pin blames the objective, not the artifact and not the node.   *)
(* Note the quantifier includes nodes that are themselves down: the pin is   *)
(* checked before the spawn, so `InvalidSpec` wins over `Unavailable` and a  *)
(* broken objective cannot hide behind a broken machine.                     *)
TamperedPinIsInvalidSpec ==
    ~specOk => \A n \in Nodes, a \in Artifacts : Status(n, a) = INVALID

(* TWO HONEST NODES AGREE on any verdict that settles -- including the      *)
(* seeded statistical kind, which is the case §4 exists to make true.       *)
(* Non-settling statuses are deliberately excluded: one node saying         *)
(* `Unavailable` while another says `Accept` is not a disagreement about    *)
(* the artifact, it is two different facts about two different machines.    *)
HonestNodesAgree ==
    \A v1 \in verdicts, v2 \in verdicts :
        ( /\ v1.art = v2.art
          /\ Settles(v1.status)
          /\ Settles(v2.status) ) => v1.status = v2.status

(* THE OBJECTIVE STAYS OPEN. An outage delays settlement and does not       *)
(* prevent it: once the disruptions are exhausted and a node recovers, every*)
(* objective reaches a verdict and settles. Bounded-checked -- it holds for *)
(* outages bounded by MaxDisruptions and asserts nothing about a permanent  *)
(* one, which is the "verifier removal" row of docs/threat-model.md and is  *)
(* marked there as not handled.                                             *)
OutageIsRecoverable == <>(Artifacts \subseteq settled)

=============================================================================
