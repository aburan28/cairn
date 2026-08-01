------------------------------ MODULE CommitReveal ------------------------------
(***************************************************************************)
(* Epoch-batched commit-reveal, and the two people it is built to stop:     *)
(* the front-runner who copies a reveal, and the submitter who grinds his   *)
(* own place in the batch.                                                  *)
(*                                                                         *)
(* Models docs/design-stage0-completion.md §5 as shipped in src/node.rs    *)
(* (`Node::settle_due`):                                                    *)
(*                                                                         *)
(*   1. a commitment's epoch is `epoch_of(commitment.created_at)`;          *)
(*   2. a reveal is refused unless its epoch is strictly greater;           *)
(*   3. reveals settling in the same epoch are ordered by                   *)
(*      `H(beacon(epoch, anchor) || commitment_hash)` ascending, ties       *)
(*      broken by claim id, rather than by arrival.                         *)
(*                                                                         *)
(* WHY THE KEY IS THE COMMITMENT HASH AND NOT THE CLAIM ID                  *)
(*                                                                         *)
(* §5 originally said `claim_id`, and the implementation found that wrong   *)
(* before this module caught it. The anchor is the log head at the epoch's  *)
(* start, so by the time anyone reveals it is public and every submitter    *)
(* can compute their own rank. Any part of the key a submitter can still    *)
(* choose at that point is a part they can re-roll until it comes out       *)
(* first -- and a claim's id covers its `created_at` and its `cites`,       *)
(* neither of which the commitment binds and neither of which anything      *)
(* checks against the reveal. Restamping is free and unlimited, so keying   *)
(* on the claim id would make the ordering rule decorative against exactly  *)
(* the people it has to bind. The commitment hash covers only what was      *)
(* frozen an epoch earlier, when this anchor did not yet exist, so it       *)
(* leaves the submitter nothing to vary.                                    *)
(*                                                                         *)
(* The tie-break on claim id is modelled rather than assumed away, because  *)
(* the code makes the same choice for the same reason: two equal ranks      *)
(* falling back on arrival order would hand the sequencer back the lever    *)
(* the whole rule exists to remove.                                         *)
(*                                                                         *)
(* WHAT THE ADVERSARY CAN DO                                               *)
(*                                                                         *)
(* Eve is a front-runner and a grinder. She cannot break the commitment     *)
(* hash and she cannot see an artifact before it is revealed -- that is     *)
(* `Ledger` and the commitment binding, respectively, and assuming it here  *)
(* is not circular because neither depends on this module. What she *can*   *)
(* do is watch every reveal the moment it lands and immediately derive      *)
(* something from it, and choose freely among the reveal-time keys her own  *)
(* submission could carry. The questions this module answers are whether    *)
(* either is enough to get paid ahead of the person she copied.             *)
(*                                                                         *)
(* WHAT IS NOT MODELLED: THE ANCHOR                                         *)
(*                                                                         *)
(* The anchor is treated here as fixed before the epoch opens and outside   *)
(* anyone's choice. It is not, quite: it is the last entry of the previous  *)
(* epoch, so a submitter who lands the final append of their own commit     *)
(* epoch moves both halves of their rank at once and can grind the pair. It *)
(* is a race against every other appender rather than a free choice, and    *)
(* closing it needs an unpredictable beacon -- a VDF or a threshold         *)
(* signature -- rather than the log head. src/node.rs says so at            *)
(* `settle_due`, docs/threat-model.md carries it under "beacon grinding"    *)
(* as **not handled**, and docs/formal-model.md records it as an assumption *)
(* of this module. A green run here is evidence about the *key*, not about  *)
(* the beacon it is hashed with.                                            *)
(*                                                                         *)
(* WHY `EpochBatched` AND `OrderKey` ARE CONSTANTS RATHER THAN BAKED IN     *)
(*                                                                         *)
(* A property that would hold anyway is not evidence for the design that    *)
(* was added to obtain it. With `EpochBatched = FALSE` -- reveal permitted  *)
(* in the same epoch as the commitment -- TLC produces a trace in which Eve *)
(* settles a derived artifact in the same batch as its original and, when   *)
(* the beacon favours her, ahead of it. With `OrderKey = "claim"` TLC       *)
(* produces a trace in which a submitter picks the reveal-time key that     *)
(* sorts them ahead of a claim their commitment ranked behind. The shipped  *)
(* configuration is `TRUE` and `"commitment"`; see docs/formal-model.md for *)
(* both counterexamples.                                                    *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Agents,        \* everyone who may submit
    Artifacts,     \* the things they may submit
    Owner,         \* [Artifacts -> Agents]: who can produce this unaided
    Base,          \* [Artifacts -> Artifacts \cup {NoBase}]: what it derives from
    NoBase,        \* marker for "original work"
    AgentIx,       \* [Agents -> Nat], injective: a stable index per agent
    ArtIx,         \* [Artifacts -> Nat], injective: a stable index per artifact
    Keys,          \* the universe of ordering-key preimages
    CommitKey,     \* [Agents -> [Artifacts -> Keys]]: the commitment hash
    ClaimKeys,     \* [Agents -> [Artifacts -> SUBSET Keys]]: claim ids reachable by restamping
    MaxEpoch,
    EpochBatched,  \* TRUE: reveal must be a strictly later epoch than commit
    OrderKey       \* "commitment" (shipped) or "claim" (the rejected design)

VARIABLES
    epoch,
    commits,   \* {[who, art, ep]}
    claims,    \* {[who, art, ep, key]} -- reveals recorded in the log
    settled    \* sequence of claims, in the order value moved

vars == <<epoch, commits, claims, settled>>

COMMITMENT == "commitment"
CLAIM      == "claim"

-----------------------------------------------------------------------------
(* THE INSTANCE.                                                            *)
(*                                                                          *)
(* The scenario the bounds in CommitReveal.cfg describe, written here       *)
(* rather than in the .cfg because TLC's configuration parser accepts sets  *)
(* and scalars but not function literals. The .cfg substitutes these with   *)
(* `Owner <- OwnerI`, so the constants stay declared and swappable.         *)
(*                                                                          *)
(*   a1  alice's own work -- the thing worth copying                        *)
(*   a2  eve's own work -- so an epoch can hold two unrelated reveals and    *)
(*       the beacon ordering has something to order                          *)
(*   d1  derived from a1 -- eve's front-run attempt                          *)

OwnerI   == [a \in Artifacts |-> IF a = "a1" THEN "alice" ELSE "eve"]
BaseI    == [a \in Artifacts |-> IF a = "d1" THEN "a1" ELSE NoBase]
AgentIxI == [g \in Agents    |-> IF g = "alice" THEN 0 ELSE 1]
ArtIxI   == [a \in Artifacts |-> IF a = "a1" THEN 0 ELSE IF a = "a2" THEN 1 ELSE 2]

(* The commitment hash of each (submitter, artifact) pair: one value, fixed *)
(* an epoch before the anchor exists. The numbers are chosen so that in     *)
(* epoch 1 -- the first epoch in which two reveals can share a batch --     *)
(* alice's a1 (key 1, rank 2) ranks ahead of eve's a2 (key 4, rank 5).      *)
(* That is the order the commitments determine, and the order every         *)
(* property below is measured against.                                      *)
CommitKeyI ==
    [g \in Agents |->
        [a \in Artifacts |->
            CASE g = "alice" /\ a = "a1" -> 1
              [] g = "alice" /\ a = "d1" -> 2
              [] g = "eve"   /\ a = "a2" -> 4
              [] g = "eve"   /\ a = "d1" -> 3
              \* alice cannot hold a2 and eve cannot hold a1, but the
              \* function has to be total.
              [] OTHER                   -> 5]]

(* The claim ids the same submission could carry, one per choice of         *)
(* `created_at` and `cites`. More than one is the whole point: restamping   *)
(* is free, so the submitter reaches every one of these at no cost after    *)
(* the anchor is public. Three for eve's a2 rather than two so that one of  *)
(* them (key 0, rank 1 in epoch 1) sorts strictly ahead of alice's          *)
(* committed rank while the others do not -- a grinder who has to *pick*    *)
(* is a sharper counterexample than one whose every option wins.            *)
(*                                                                          *)
(* Alice can restamp too, and does not benefit: her alternative (key 3,     *)
(* rank 4) is worse than her commitment's. The attack is not that choice    *)
(* exists, it is that choice moves rank.                                    *)
(*                                                                          *)
(* Two or three options model "free and unlimited" exactly as well as the   *)
(* thirty the Rust test tries: the property below is that the set of ranks  *)
(* a submitter can reach is a singleton, and a second element falsifies it  *)
(* no less than a thirtieth would.                                          *)
ClaimKeysI ==
    [g \in Agents |->
        [a \in Artifacts |->
            CASE g = "alice" /\ a = "a1" -> {1, 3}
              [] g = "alice" /\ a = "d1" -> {2, 4}
              [] g = "eve"   /\ a = "a2" -> {0, 2, 4}
              [] g = "eve"   /\ a = "d1" -> {0, 3}
              [] OTHER                   -> {5}]]

-----------------------------------------------------------------------------

NumKeys == Cardinality(Keys)

ClaimIds == [who: Agents, art: Artifacts]

Range(s) == { s[i] : i \in 1..Len(s) }

-----------------------------------------------------------------------------
(* Beacon ordering.                                                         *)
(*                                                                         *)
(* `Rank` stands in for `H(beacon(epoch, anchor) || key)`. Two things about *)
(* the real function matter and both are reproduced here, and nothing else  *)
(* about it does:                                                           *)
(*                                                                         *)
(*   - it is injective in the key, so distinct keys rank distinctly and the *)
(*     batch has a total order;                                             *)
(*   - it depends on the epoch, so the order is not fixed across epochs and *)
(*     no key is permanently first.                                         *)
(*                                                                         *)
(* A rotation by epoch has exactly those two properties and is cheap to     *)
(* evaluate. Modelling SHA-256 itself would add nothing here; what the      *)
(* hash buys is unpredictability of the *rank* from the key, and a          *)
(* submitter who can enumerate keys enumerates ranks either way. That is    *)
(* the attack below, and it is modelled directly rather than through the    *)
(* hash.                                                                    *)
Rank(e, k) == (k + e) % NumKeys

(* The tie-break, matching `(ra, a_id).cmp(&(rb, b_id))` in `settle_due`.   *)
(* Injective over a batch: `Reveal` admits at most one claim per            *)
(* (submitter, artifact), so no two claims in one batch share an index.     *)
ClaimIx(cl) == AgentIx[cl.who] * Cardinality(Artifacts) + ArtIx[cl.art]

Before(e, x, y) ==
    \/ Rank(e, x.key) < Rank(e, y.key)
    \/ /\ Rank(e, x.key) = Rank(e, y.key)
       /\ ClaimIx(x) < ClaimIx(y)

(* Ascending by `Before`, which is a total order on a batch, so the minimum *)
(* is unique and the sort is deterministic.                                 *)
RECURSIVE SortByBeacon(_, _)
SortByBeacon(S, e) ==
    IF S = {}
    THEN <<>>
    ELSE LET m == CHOOSE x \in S : \A y \in S : x = y \/ Before(e, x, y)
         IN  <<m>> \o SortByBeacon(S \ {m}, e)

-----------------------------------------------------------------------------
(* What a submitter may put in the ordering key.                            *)
(*                                                                          *)
(* This one definition is the whole design decision. Under the shipped      *)
(* rule the key is the commitment hash and the set is a singleton: there is *)
(* no choice to make, and `Reveal`'s existential collapses. Under the       *)
(* rejected rule it is the claim id, and the set is every id the submitter  *)
(* can restamp their way to -- an unconstrained choice made *after* the     *)
(* anchor is public, which is what makes it grinding rather than luck.      *)
AvailableKeys(g, a) ==
    IF OrderKey = COMMITMENT THEN {CommitKey[g][a]} ELSE ClaimKeys[g][a]

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

Init ==
    /\ epoch = 0
    /\ commits = {}
    /\ claims = {}
    /\ settled = <<>>

Revealed(a) == \E c \in claims : c.art = a

(* Who can commit to what.                                                  *)
(*                                                                          *)
(* Original work: only its owner has it. Derived work: anyone, but only     *)
(* once the artifact it derives from is public -- which is the whole point. *)
(* Eve's advantage is modelled as maximal: she can derive instantly, in the *)
(* same instant the base reveal lands, with no work and no delay. If the    *)
(* protocol holds against that it holds against a slower attacker.          *)
CanHold(g, a) ==
    IF Base[a] = NoBase
    THEN Owner[a] = g
    ELSE Revealed(Base[a])

Committed(g, a) == \E k \in commits : k.who = g /\ k.art = a

Commit(g, a) ==
    /\ epoch < MaxEpoch
    /\ CanHold(g, a)
    /\ ~Committed(g, a)
    /\ commits' = commits \cup {[who |-> g, art |-> a, ep |-> epoch]}
    /\ UNCHANGED <<epoch, claims, settled>>

(* The epoch gate. `k.ep < epoch` is `RuleViolation::RevealBeforeEpoch`:    *)
(* nobody can act on a competitor's artifact inside the same epoch, because *)
(* by the time they have seen it, the epoch in which they could have        *)
(* committed has already closed.                                            *)
OpenedBy(k, e) == IF EpochBatched THEN k.ep < e ELSE k.ep <= e

(* The reveal, and the grinding attack.                                     *)
(*                                                                          *)
(* The existential over `AvailableKeys` is the attack: the submitter knows  *)
(* the epoch and therefore the anchor and therefore the rank each candidate *)
(* key would earn, and picks. TLC explores every choice, so the greedy      *)
(* submitter who takes the best one is among the behaviours checked -- no   *)
(* separate "adversary is optimal" action is needed, and modelling one      *)
(* would be weaker, since it would also have to be right about what optimal *)
(* means.                                                                    *)
(*                                                                          *)
(* Note that the key is chosen at *reveal* time and nothing carries it back *)
(* to the commitment. That asymmetry is the flaw in the original design     *)
(* stated as a state machine.                                               *)
Reveal(g, a) ==
    /\ epoch < MaxEpoch
    /\ \E k \in commits : k.who = g /\ k.art = a /\ OpenedBy(k, epoch)
    /\ ~\E c \in claims : c.who = g /\ c.art = a
    /\ \E key \in AvailableKeys(g, a) :
         claims' = claims \cup {[who |-> g, art |-> a, ep |-> epoch, key |-> key]}
    /\ UNCHANGED <<epoch, commits, settled>>

(* The epoch boundary settles the whole batch at once, in beacon order.     *)
(* This is the step that makes arrival order irrelevant: the sequencer sees *)
(* every reveal of the epoch before it orders any of them, so there is      *)
(* nothing left for it to reorder for profit.                               *)
Tick ==
    /\ epoch < MaxEpoch
    /\ LET batch == { c \in claims : c.ep = epoch } \ Range(settled)
       IN  settled' = settled \o SortByBeacon(batch, epoch)
    /\ epoch' = epoch + 1
    /\ UNCHANGED <<commits, claims>>

Next ==
    \/ \E g \in Agents, a \in Artifacts : Commit(g, a)
    \/ \E g \in Agents, a \in Artifacts : Reveal(g, a)
    \/ Tick

(* Weak fairness on `Tick` only. Nobody is obliged to submit anything, but  *)
(* an epoch that has begun must end -- that is a clock, not a promise about *)
(* participants.                                                            *)
Spec == Init /\ [][Next]_vars /\ WF_vars(Tick)

-----------------------------------------------------------------------------
(* Properties.                                                              *)

TypeOK ==
    /\ epoch \in 0..MaxEpoch
    /\ commits \subseteq [who: Agents, art: Artifacts, ep: 0..MaxEpoch]
    /\ claims \subseteq [who: Agents, art: Artifacts, ep: 0..MaxEpoch, key: Keys]
    /\ Range(settled) \subseteq claims

(* BINDING. No reveal without a matching prior commitment, in a strictly    *)
(* earlier epoch. The commitment hash binds the submitter, so this is also  *)
(* what stops a commitment being replayed under another name -- modelled    *)
(* here by keying commitments on `who`.                                     *)
Binding ==
    \A c \in claims :
        \E k \in commits : k.who = c.who /\ k.art = c.art /\ OpenedBy(k, c.ep)

(* NO IN-FLIGHT FRONT-RUNNING.                                              *)
(*                                                                          *)
(* Stated over the settlement *sequence* rather than over epochs, because   *)
(* "settles ahead of" is the thing that pays, and an epoch comparison would *)
(* quietly assume the batch ordering it is supposed to be checking. An      *)
(* artifact derived from another never appears earlier in `settled` than    *)
(* the artifact it was derived from.                                        *)
(*                                                                          *)
(* Note what this does and does not say. It does not say Eve cannot copy;   *)
(* she can, and `Frontier` is what makes the copy worth nothing. It says    *)
(* she cannot be *paid first*, which is the part ordering could otherwise   *)
(* decide.                                                                  *)
NoFrontRunning ==
    \A i \in 1..Len(settled), j \in 1..Len(settled) :
        (Base[settled[j].art] = settled[i].art) => i < j

(* SETTLEMENT ORDER IS A FUNCTION OF THE BEACON.                            *)
(*                                                                          *)
(* Within one epoch the settled order is ascending by `Before`, and epochs  *)
(* appear in order. TLC explores every interleaving of commits and reveals, *)
(* so an invariant that holds in all of them is exactly the statement that  *)
(* arrival-order permutations settle identically -- there is no reachable   *)
(* state in which a different arrival produced a different order.           *)
(*                                                                          *)
(* This says the sequencer did not reorder. It says nothing about where the *)
(* ranks came from, which is why the two properties below exist: this one   *)
(* holds just as well when the ranks are grindable, and holding then is     *)
(* precisely the failure this module previously had.                        *)
SettlementIsBeaconOrdered ==
    \A i \in 1..Len(settled), j \in 1..Len(settled) :
        i < j =>
            \/ settled[i].ep < settled[j].ep
            \/ /\ settled[i].ep = settled[j].ep
               /\ Before(settled[i].ep, settled[i], settled[j])

(* NOTHING LEFT TO GRIND.                                                   *)
(*                                                                          *)
(* Every key a submitter could have used earns the rank the one they did    *)
(* use earned. Stated over ranks and not over keys, because a submitter     *)
(* with several claim ids that happen to rank alike has gained nothing, and *)
(* an invariant about keys would call that a violation.                     *)
(*                                                                          *)
(* This is the mechanism. `OrderIsNotSubmitterChosen` below is the          *)
(* consequence, and both are worth checking: this one fails at the first    *)
(* reveal and names the field at fault, that one fails only when the choice *)
(* actually moved money and shows who took it from whom.                    *)
NothingToGrind ==
    \A c \in claims :
        \A k \in AvailableKeys(c.who, c.art) :
            Rank(c.ep, k) = Rank(c.ep, c.key)

(* THE BATCH ORDER IS NOT INFLUENCED BY ANYTHING A SUBMITTER CHOOSES AFTER  *)
(* THE ANCHOR IS KNOWN.                                                     *)
(*                                                                          *)
(* For every pair that settled in one batch, the later one could not have   *)
(* overtaken the earlier one by any choice available to it. The anchor is   *)
(* public throughout the reveal epoch, so "available to it" is the full set *)
(* -- there is no honest default to fall back on and no cost to trying      *)
(* another.                                                                  *)
(*                                                                          *)
(* Quantified over the settled sequence rather than over hypothetical       *)
(* batches so that a counterexample is a real one: two claims that really   *)
(* settled, in an order one of them really could have inverted. On a        *)
(* progressive objective that inversion decides which of them is paid for   *)
(* the whole span and which for the remainder, which is why this is a       *)
(* statement about money and not about tidiness.                            *)
OrderIsNotSubmitterChosen ==
    \A i \in 1..Len(settled), j \in 1..Len(settled) :
        (i < j /\ settled[i].ep = settled[j].ep) =>
            \A k \in AvailableKeys(settled[j].who, settled[j].art) :
                ~Before(settled[j].ep,
                        [settled[j] EXCEPT !.key = k],
                        settled[i])

(* Nothing settles twice, and nothing settles that was not revealed.        *)
NoDoubleSettlement ==
    \A i \in 1..Len(settled), j \in 1..Len(settled) :
        (settled[i] = settled[j]) => i = j

(* LIVENESS. A revealed claim is settled by the end of its own epoch --     *)
(* batching delays payment, it does not withhold it. Fairness is on the     *)
(* clock alone.                                                             *)
EveryRevealSettles ==
    \A cl \in ClaimIds :
        [] ( (\E c \in claims : c.who = cl.who /\ c.art = cl.art)
                => <> (\E k \in Range(settled) : k.who = cl.who /\ k.art = cl.art) )

=============================================================================
