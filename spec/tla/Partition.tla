-------------------------------- MODULE Partition --------------------------------
(***************************************************************************)
(* Work assignment without a coordinator.                                   *)
(*                                                                         *)
(* Models src/partition.rs -- `beacon`, `assign`, `epoch_of`,               *)
(* `Assignment::share`.                                                     *)
(*                                                                         *)
(* WHAT THIS MODULE CAN AND CANNOT ESTABLISH                               *)
(*                                                                         *)
(* Be clear about this one, because it is the module where it would be      *)
(* easiest to overclaim.                                                    *)
(*                                                                         *)
(* The design's central quantitative claim -- that mixing a per-epoch       *)
(* beacon into the draw *spreads nodes out*, so squatting a region costs a  *)
(* fresh grinding effort every epoch -- is a statistical property of        *)
(* HMAC-SHA256. It is not a protocol property, no model checker can         *)
(* establish it, and this module does not pretend to. It is marked          *)
(* **assumed** in docs/formal-model.md and it is what                       *)
(* `assignment_rotates_between_epochs` in src/partition.rs measures.        *)
(*                                                                         *)
(* What *is* protocol, and is checked here:                                 *)
(*                                                                         *)
(*   - the slices tile the space exactly -- no gaps, no overlaps, for every *)
(*     partition count including those that do not divide it. A gap leaves  *)
(*     items nobody searches; an overlap makes two nodes provably           *)
(*     responsible for the same item and destroys the "did you search your  *)
(*     region?" check that the whole scheme exists to enable;               *)
(*   - a malformed assignment covers nothing rather than covering somebody  *)
(*     else's region;                                                       *)
(*   - the draw lands inside the partition count;                           *)
(*   - the assignment is a pure function of public inputs, so any node can  *)
(*     recompute any peer's, for any past epoch, with no agreement and no   *)
(*     messages;                                                            *)
(*   - an assignment is bound to its own epoch and cannot be replayed into  *)
(*     another one, which is the mechanism that forces the rotation the     *)
(*     statistical claim is about;                                          *)
(*   - `epoch_of` is monotone and its epochs are contiguous, which is what  *)
(*     `CommitReveal`'s epoch gate silently depends on.                     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Nodes,
    Objectives,
    Draw,            \* [Nodes -> [Objectives -> [Epochs -> Nat]]]: the MAC output
    Space,           \* size of the assignment space
    PartitionCounts, \* every partition count the arithmetic is checked for
    Partitions,      \* the count the running system in this instance uses
    Epochs,
    EpochSeconds,
    Times            \* timestamps to check epoch_of over

-----------------------------------------------------------------------------
(* THE INSTANCE.                                                            *)
(*                                                                          *)
(* `Draw` stands for the first eight bytes of                               *)
(* `HMAC(beacon(epoch, anchor), node_id | objective_id)`. Only two things    *)
(* about it are used below and both are true of the real function: it is a  *)
(* function of `(node, objective, epoch)` and of nothing else, and its      *)
(* value is a non-negative integer that gets reduced modulo the partition   *)
(* count. Its *distribution* is deliberately not modelled -- see the header *)
(* -- so the table is an arbitrary spread of values rather than an attempt  *)
(* to imitate a hash.                                                       *)
(*                                                                          *)
(* Note that the epoch enters through the beacon, which is why `Draw` is    *)
(* indexed by it. That indexing is the modelled content of "the beacon      *)
(* rotates assignments": the epoch is an *input*, so an assignment cannot   *)
(* outlive the epoch it was drawn for. How far it moves is the assumed part.*)

DrawI ==
    [n \in Nodes |->
        [o \in Objectives |->
            [e \in Epochs |->
                (IF n = "n1" THEN 7 ELSE 13) * (e + 1) + (IF o = "o1" THEN 0 ELSE 5)]]]

-----------------------------------------------------------------------------
(* The assignment functions.                                                *)

Beacon(e) == <<"beacon", e>>

(* `assign`: the MAC draw reduced modulo the partition count.               *)
Assign(n, o, e, p) == Draw[n][o][e] % p

(* `Assignment::share`, verbatim including the truncating step and the      *)
(* last slice absorbing the remainder.                                      *)
Step(p) == Space \div p

Lo(i, p) == i * Step(p)
Hi(i, p) == IF i = p - 1 THEN Space ELSE (i + 1) * Step(p)

(* Half-open [lo, hi). Empty when the assignment is malformed: fail closed, *)
(* because a broken assignment searching nothing is recoverable and one     *)
(* claiming somebody else's region is not.                                  *)
Slice(i, p) ==
    IF p < 1 \/ i < 0 \/ i >= p
    THEN {}
    ELSE { x \in 0..(Space - 1) : Lo(i, p) <= x /\ x < Hi(i, p) }

(* `epoch_of`: floor division, so epochs are contiguous and monotone.       *)
EpochOf(t) == t \div EpochSeconds

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

(* Most of this module is arithmetic, and arithmetic has no state. The      *)
(* properties below that quantify over `Records` are checked over *every*   *)
(* well-formed assignment record rather than over the ones this small       *)
(* behaviour happens to produce -- which is both stronger and cheaper, and  *)
(* is why `published` is the only state worth carrying.                     *)
(*                                                                          *)
(* The state machine that remains exists for one property that genuinely is *)
(* temporal: an assignment recorded in an early epoch must still verify     *)
(* after the epoch has moved on, because "did you search your region?" is a *)
(* question asked later, by somebody who was not there.                     *)

VARIABLES
    epoch,
    published    \* assignments nodes have recorded

vars == <<epoch, published>>

Records == [node: Nodes, obj: Objectives, ep: Epochs,
            partition: 0..(Space - 1), partitions: PartitionCounts]

Init ==
    /\ epoch = 0
    /\ published = {}

Tick ==
    /\ epoch + 1 \in Epochs
    /\ epoch' = epoch + 1
    /\ UNCHANGED published

(* A node computes its own assignment and records it. No message is sent    *)
(* and no lock is taken: that is the entire point of the scheme, and it is  *)
(* why this action has no peer in its guard.                                *)
Claim(n, o) ==
    /\ published' = published \cup
         {[node |-> n, obj |-> o, ep |-> epoch,
           partition |-> Assign(n, o, epoch, Partitions),
           partitions |-> Partitions]}
    /\ UNCHANGED epoch

Next ==
    \/ Tick
    \/ \E n \in Nodes, o \in Objectives : Claim(n, o)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The check anyone can run against a published assignment.                 *)
(*                                                                          *)
(* Note that it takes the epoch it is being checked *for*, separately from  *)
(* the epoch the record claims. An implementation that read the epoch out   *)
(* of the record and used it for both would accept every replay, which is   *)
(* exactly the bug `AssignmentsCannotBeReplayed` is looking for.            *)
Verify(rec, e) ==
    /\ rec.ep = e
    /\ rec.partitions >= 1
    /\ rec.partition < rec.partitions
    /\ rec.partition = Assign(rec.node, rec.obj, e, rec.partitions)

-----------------------------------------------------------------------------
(* Properties.                                                              *)

TypeOK ==
    /\ epoch \in Epochs
    /\ published \subseteq Records

(* THE SLICES TILE THE SPACE. Every point belongs to exactly one slice, for *)
(* every partition count -- including the counts that do not divide the     *)
(* space, which is the whole reason the last slice absorbs the remainder.   *)
(*                                                                          *)
(* Stated point-by-point rather than as "the sizes sum to Space", because   *)
(* sizes summing correctly is consistent with two slices overlapping and a  *)
(* third being short. Exactly-one is the property the audit needs.          *)
SlicesTile ==
    \A p \in PartitionCounts :
        \A x \in 0..(Space - 1) :
            Cardinality({ i \in 0..(p - 1) : x \in Slice(i, p) }) = 1

(* A malformed assignment covers nothing. Reachable only through a struct   *)
(* literal in the implementation, which is why the constructor validates    *)
(* *and* `share` guards itself; both are modelled because the failure mode  *)
(* of the missing guard is silently claiming another node's region.         *)
MalformedCoversNothing ==
    \A p \in PartitionCounts : \A i \in 0..(Space + 1) :
        (i >= p) => Slice(i, p) = {}

(* The draw lands inside the partition count -- `x mod n < n`, stated so    *)
(* that a change to the reduction cannot quietly produce an out-of-range    *)
(* partition that `Slice` would then answer with an empty region.           *)
AssignmentInRange ==
    \A n \in Nodes, o \in Objectives : \A e \in Epochs, p \in PartitionCounts :
        Assign(n, o, e, p) \in 0..(p - 1)

(* PURE AND RECOMPUTABLE. Every published assignment still verifies against *)
(* its own epoch, in every later state -- so a peer, or an auditor years    *)
(* afterwards, can recompute it from public inputs with no agreement, no    *)
(* messages and no access to the node that made it.                         *)
(*                                                                          *)
(* What TLC establishes here is that nothing in the model's evolving state  *)
(* can invalidate a past assignment. Purity itself is enforced by           *)
(* construction -- `Assign` reads no variable -- so this is a check that    *)
(* the *protocol around* the pure function does not smuggle state in, not a *)
(* proof that the implementation's function is pure. That is a code         *)
(* property; see docs/formal-model.md.                                       *)
PublishedAssignmentsStayVerifiable ==
    \A rec \in published : Verify(rec, rec.ep)

(* AN ASSIGNMENT CANNOT BE REPLAYED INTO ANOTHER EPOCH.                     *)
(*                                                                          *)
(* This is the mechanism behind "epoch rotation bounds squatting". The      *)
(* statistical claim -- that a redraw is unlikely to land in the same place *)
(* -- is assumed; what is checked is that a redraw is *required*, because   *)
(* an assignment presented for an epoch it was not drawn for is refused     *)
(* however well formed it is. Without this, rotation would be decorative.   *)
(*                                                                          *)
(* Quantified over every record in the space, not only over records some    *)
(* node published: the squatter's forgery is not something an honest node   *)
(* would ever produce, so restricting to reachable records would check the  *)
(* attack against nothing.                                                  *)
AssignmentsCannotBeReplayed ==
    \A rec \in Records : \A e \in Epochs : (rec.ep # e) => ~Verify(rec, e)

(* EPOCHS ARE CONTIGUOUS AND MONOTONE IN TIME. `CommitReveal`'s gate -- a   *)
(* reveal must be in a strictly later epoch than its commitment -- is only  *)
(* a delay if time cannot move backwards through epochs, and only bounded   *)
(* if no epoch is skipped. Both halves are checked here because both are    *)
(* properties of the floor division rather than of the gate.                *)
EpochsAreMonotone ==
    \A t1 \in Times, t2 \in Times : (t1 <= t2) => EpochOf(t1) <= EpochOf(t2)

EpochsAreContiguous ==
    \A t \in Times :
        (t + EpochSeconds \in Times) => EpochOf(t + EpochSeconds) = EpochOf(t) + 1

=============================================================================
