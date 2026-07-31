-------------------------------- MODULE Frontier --------------------------------
(***************************************************************************)
(* The ratchet: progressive bounties, and why publishing immediately is the *)
(* profitable move.                                                        *)
(*                                                                         *)
(* Models src/frontier.rs -- `Ratchet::progress`, `cumulative`, `payout`,   *)
(* `improves` -- and the settlement loop in src/node.rs that advances the   *)
(* frontier.                                                               *)
(*                                                                         *)
(* WHY THE ARITHMETIC IS MODELLED EXACTLY, TRUNCATION AND ALL              *)
(*                                                                         *)
(* The claim the design makes is not "payouts roughly telescope". It is     *)
(* that a hundred one-point improvements pay the same total as one          *)
(* hundred-point improvement, *to the unit*, in truncating integer          *)
(* arithmetic. That is a property of the specific formula                   *)
(*                                                                         *)
(*     cumulative(s) = reward * progress(s) \div span                       *)
(*     payout(a, b)  = cumulative(b) - cumulative(a)                        *)
(*                                                                         *)
(* and it would be false for the obvious alternative of rounding each step  *)
(* independently. So `\div` here is TLA+'s integer division and the numbers *)
(* are chosen so truncation actually bites: reward 10 over a span of 6      *)
(* pays 1, 3, 5, 6, 8, 10 -- five of the six steps lose a fraction. If the  *)
(* model used exact rationals the headline property would hold for a reason *)
(* the implementation does not have.                                        *)
(*                                                                         *)
(* WHAT IS NOT MODELLED: OVERFLOW                                          *)
(*                                                                         *)
(* src/frontier.rs forms `reward * progress` in `u128` and narrows back     *)
(* with a checked conversion, because the same product wraps in `u64` at    *)
(* realistic money scale. TLA+ integers are unbounded, so this module       *)
(* cannot express that bug and does not claim to have excluded it. It is    *)
(* covered by `a_huge_reward_times_a_huge_progress_does_not_wrap` and       *)
(* `realistic_money_scale_stays_exact` in that file's tests, which is the   *)
(* right tool: a width bug is a property of a machine type, not of a        *)
(* protocol. Recorded as an assumption in docs/formal-model.md.             *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Artifacts,
    Score,           \* [Artifacts -> Int]: the verifier's number for each
    Baseline,
    Target,
    Reward,          \* the whole pool
    Direction,       \* "maximize" or "minimize"
    MinImprovement,
    MaxSubmissions   \* bound on the length of an improvement path

MAXIMIZE == "maximize"

-----------------------------------------------------------------------------
(* THE INSTANCE. Function literals cannot live in a .cfg.                   *)
(*                                                                          *)
(* Seven artifacts over a span of six. Six of them sit at each score on the *)
(* curve, so TLC walks every way of chopping the span into steps -- one     *)
(* leap to the target, six single steps, and everything between. The        *)
(* seventh, `dup3`, has the same score as `a3`: it is a literal copy of     *)
(* someone else's result, which is the case "copying earns exactly zero"    *)
(* is about.                                                                *)

ScoreI == [a \in Artifacts |->
    CASE a = "a1" -> 1
      [] a = "a2" -> 2
      [] a = "a3" -> 3
      [] a = "a4" -> 4
      [] a = "a5" -> 5
      [] a = "a6" -> 6
      [] OTHER    -> 3]

-----------------------------------------------------------------------------

VARIABLES
    frontier,     \* best score known so far
    live,         \* has anything cleared the bar yet? (Rust: Option<i64>)
    paid,         \* everything this objective has paid out
    payments,     \* the artifacts that were paid, in order
    submissions   \* bound on the run

vars == <<frontier, live, paid, payments, submissions>>

Span == IF Direction = MAXIMIZE THEN Target - Baseline ELSE Baseline - Target

Raw(s) == IF Direction = MAXIMIZE THEN s - Baseline ELSE Baseline - s

(* Clamped at both ends, and both clamps do work. The lower one stops a     *)
(* below-baseline result from being negative progress that could claw money *)
(* back out of an append-only ledger; the upper one stops an overshoot from *)
(* minting progress the pool cannot fund.                                   *)
Progress(s) ==
    CASE Raw(s) <= 0    -> 0
      [] Raw(s) >= Span -> Span
      [] OTHER          -> Raw(s)

Cumulative(s) == (Reward * Progress(s)) \div Span

(* `saturating_sub`: a regression pays zero, never negative. Money already  *)
(* settled cannot be unsettled, so zero is the only safe floor.             *)
Payout(old, new) ==
    IF Cumulative(new) > Cumulative(old) THEN Cumulative(new) - Cumulative(old) ELSE 0

(* `Ratchet::improves`. The empty frontier is `Progress = 0`, which is what *)
(* `None` means in the Rust: it is not the same *fact* as a score sitting   *)
(* at the baseline, but it has the same progress, so the arithmetic here    *)
(* cannot tell them apart and nothing in this module should. The difference *)
(* that does matter -- an objective with no frontier has no claim to cite   *)
(* -- is a citation rule, and is modelled in Proofwork.                     *)
Gained(new) == IF live THEN Progress(new) - Progress(frontier) ELSE Progress(new)

Improves(new) == Gained(new) >= MinImprovement

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

Init ==
    /\ frontier = Baseline
    /\ live = FALSE
    /\ paid = 0
    /\ payments = <<>>
    /\ submissions = 0

(* One verified submission. Both branches are reachable and both matter:    *)
(* the second is what a duplicate, a regression, and an epsilon-improvement *)
(* all do, and the point is that all three take it.                         *)
Submit(a) ==
    /\ submissions < MaxSubmissions
    /\ submissions' = submissions + 1
    /\ IF Improves(Score[a])
       THEN /\ paid' = paid + Payout(frontier, Score[a])
            /\ frontier' = Score[a]
            /\ live' = TRUE
            /\ payments' = Append(payments, a)
       ELSE UNCHANGED <<frontier, live, paid, payments>>

Next == \E a \in Artifacts : Submit(a)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                              *)

TypeOK ==
    /\ paid \in 0..Reward
    /\ submissions \in 0..MaxSubmissions
    /\ Len(payments) <= MaxSubmissions

(* THE FRONTIER IS MONOTONE. An action property rather than an invariant,   *)
(* because "never moves backwards" is a statement about a *step* and no     *)
(* predicate on a single state can express it. Stated over `Progress`       *)
(* rather than over the raw score so that it reads the same under both      *)
(* directions -- under `minimize` a better score is a smaller number, and a *)
(* property written as `frontier' >= frontier` would silently invert.       *)
Monotone == [][ Progress(frontier') >= Progress(frontier) ]_vars

(* PAYOUTS TELESCOPE, EXACTLY.                                              *)
(*                                                                          *)
(* The total paid is the cumulative at the current frontier -- and the      *)
(* cumulative depends only on where the frontier *is*, never on how it got  *)
(* there. TLC explores every improvement path within the bound, so an       *)
(* invariant that holds in all of them is precisely the statement that step *)
(* count does not change the total. Note this is strictly stronger than     *)
(* checking a few paths sum to the same number: it pins the total after     *)
(* every prefix of every path, so a formula that agreed only at the target  *)
(* would fail here.                                                         *)
(*                                                                          *)
(* This is what makes slicing pointless in *direct* reward, and it is why   *)
(* an objective's pool cannot be drained by chopping an improvement into    *)
(* epsilons. It is not the whole slicing story: citation flow decays per    *)
(* hop, so a slicer still starves whoever they built on, which is           *)
(* `min_improvement`'s job and is bounded rather than solved. See           *)
(* docs/threat-model.md.                                                    *)
Telescopes == paid = Cumulative(frontier) \/ (~live /\ paid = 0)

(* THE POOL IS NEVER OVERSPENT, however finely the curve is chopped. This   *)
(* follows from Telescopes and `Progress <= Span`, but it is stated on its  *)
(* own because it is the property an auditor actually checks, and because   *)
(* a future change that broke it would be easier to spot failing here.      *)
PoolIsBounded == paid <= Reward

(* And exactly exhausted at the target, not one unit short. This is where   *)
(* truncation would show up if the formula rounded per step: six truncating *)
(* steps of 10/6 sum to 10 only because the roundings cancel.               *)
PoolExhaustedAtTarget == (Progress(frontier) = Span) => (paid = Reward)

(* A DUPLICATE NEVER PAYS TWICE.                                            *)
(*                                                                          *)
(* Stated over the sequence of paid artifacts rather than as "resubmitting  *)
(* pays zero", because the second is about one submission and this is about *)
(* all of them: no artifact can be made to pay a second time by any route,  *)
(* including being resubmitted after the frontier has moved past it and     *)
(* come back -- which it cannot, but the property does not assume that.     *)
(*                                                                          *)
(* `dup3` shares a score with `a3`, so this also covers the copy: whichever *)
(* of the two lands first is paid and the other earns nothing, which is the *)
(* rule stated to contributors as "copying earns exactly zero".             *)
NoDoublePay ==
    \A i \in 1..Len(payments), j \in 1..Len(payments) :
        (payments[i] = payments[j]) => i = j

(* A copy of a result already on the frontier is worth nothing. The direct  *)
(* statement of the contributor-facing rule, which NoDoublePay implies only *)
(* for artifacts that are literally the same record.                        *)
CopyingEarnsZero ==
    \A a \in Artifacts : (live /\ Progress(Score[a]) <= Progress(frontier)) => ~Improves(Score[a])

=============================================================================
