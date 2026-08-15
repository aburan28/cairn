-------------------------------- MODULE Sealed --------------------------------
(***************************************************************************)
(* The sealed envelope and its threshold reveal: four primitives composed,  *)
(* and the four checks that hold the composition together.                  *)
(*                                                                         *)
(* Models `src/sealed.rs` over `src/crypto/{envelope,shamir,kem}.rs`, with  *)
(* the admission rules from `Node::committee_for` and                       *)
(* `Node::check_committee_share`. The design is docs/censorship.md §2 and   *)
(* the picture is docs/diagrams.md §6.                                      *)
(*                                                                         *)
(*   commit    commitment = H(artifact || submitter || nonce)               *)
(*             envelope   = AEAD(K, {artifact, nonce}), aad = commitment    *)
(*             shares     = Shamir(K, t of n), share_i sealed to member i   *)
(*   epoch end >= t members publish `committee_share` records               *)
(*   reveal    anyone reconstructs K, decrypts, re-derives H, compares      *)
(*                                                                         *)
(* WHY THIS MODULE EXISTS SEPARATELY FROM `CommitReveal`                    *)
(*                                                                         *)
(* `CommitReveal` checks the epoch-batched game assuming the submitter      *)
(* comes back to reveal. This one checks what happens when they never do,   *)
(* which is the attack that motivated sealing: an adversary who can neither *)
(* forge nor steal your work takes it by stopping your second action.       *)
(*                                                                         *)
(* Note what is *absent* below: there is no submitter action after `Seal`.  *)
(* That absence is the property, not an omission -- if `EventuallyOpens`    *)
(* holds, it held without the submitter ever being asked again.             *)
(*                                                                         *)
(* HOW THE FOUR PRIMITIVES ARE MODELLED, AND WHAT THAT ASSUMES              *)
(*                                                                         *)
(* Every one is *assumed*, in the sense docs/formal-model.md gives the      *)
(* word. Nothing here is evidence about a primitive; it is evidence about   *)
(* the protocol that composes them, which is the gap the primitives'        *)
(* individual assumptions do not cover.                                     *)
(*                                                                         *)
(*   hash commitment  `Commitment(s) == <<s.who, s.art>>`, a tuple, which   *)
(*                    is injective in its components and therefore exactly  *)
(*                    a collision-free hash -- the encoding `Hashing` uses  *)
(*                    and for the reason given there.                       *)
(*   AEAD             opens iff the key is the one it was sealed under and  *)
(*                    the associated data matches. Modelled by              *)
(*                    construction: no action produces a plaintext from a   *)
(*                    wrong key, so forgery is unrepresentable.             *)
(*   Shamir t-of-n    the key is recoverable from a share set iff the set   *)
(*                    holds >= t *correct* shares. Any t-1 reconstruct a    *)
(*                    well-formed wrong key, so "too few shares" and        *)
(*                    "forged shares" are the same observation -- which is  *)
(*                    why `SealedError::Envelope` is the only signal the    *)
(*                    open path has, and why it cannot say which member     *)
(*                    lied.                                                 *)
(*   KEM              share `k` is readable only by `Holder[k]`. Modelled   *)
(*                    as: a publisher who does not hold the seat cannot     *)
(*                    produce a good share, only a well-formed wrong one.   *)
(*                                                                         *)
(* THE NONCE IS NOT A VARIABLE, AND THE REASON IS NOT THAT IT DOES NOT      *)
(* MATTER                                                                   *)
(*                                                                         *)
(* It matters twice: it is what makes a guessable artifact unguessable from *)
(* the commitment, and it is sealed *inside* the envelope so that the       *)
(* committee -- who never learn it otherwise -- can re-derive the           *)
(* commitment at open time. Sealing only the artifact yields a plaintext    *)
(* nobody can check, which fails exactly when it is needed. Both are        *)
(* properties of what the payload *contains*, and at this abstraction they  *)
(* are the same thing as "the binding check can be performed at all", which *)
(* is `BindingChecked` below. Carrying a nonce as state would multiply the  *)
(* space by |Nonces| and could not make any property here fail.             *)
(*                                                                         *)
(* WHAT THE ADVERSARY CAN DO                                               *)
(*                                                                         *)
(* Four adversaries, and they are deliberately not the same person -- which *)
(* is why `Liars` and `Colluders` are separate constants rather than one     *)
(* "dishonest" set. docs/threat-model.md carries them as separate rows, and *)
(* they pull in opposite directions: a liar attacks the reveal, a colluder  *)
(* attacks the secrecy, and a set that did both would hide one behind the   *)
(* other.                                                                   *)
(*                                                                         *)
(*   a dishonest sealer   seals something other than what they committed    *)
(*                        to, and hopes to be paid for it                   *)
(*   a lying member       in `Liars`: holds a seat and answers with a       *)
(*                        well-formed wrong share, or not at all. Both      *)
(*                        consume the seat, so answering wrongly is the     *)
(*                        stronger attack and is what is modelled            *)
(*   a bystander          holds no seat and publishes anyway, to stall a    *)
(*                        reveal with noise                                 *)
(*   a colluding member   in `Colluders`: pools what they hold. At          *)
(*                        `Threshold` of them the artifact opens early --   *)
(*                        not a bug this module can rule out but the low    *)
(*                        side of the vice in docs/diagrams.md §6, with     *)
(*                        `NoEarlyLeakWithoutCapture` stating the exact     *)
(*                        condition under which it becomes possible          *)
(*                                                                         *)
(* WHY FOUR CHECKS ARE CONSTANTS RATHER THAN BAKED IN                       *)
(*                                                                         *)
(* A property that would hold anyway is not evidence for the check that was *)
(* added to obtain it -- the argument `CommitReveal` makes with             *)
(* `EpochBatched` and `OrderKey`. Each flag below ships as TRUE, and each   *)
(* has a falsification run at FALSE that TLC answers with a trace. See      *)
(* docs/formal-model.md for the four counterexamples in prose.              *)
(*                                                                         *)
(*   BindingChecked  open re-derives H from the recovered plaintext and     *)
(*                   refuses a mismatch (`SealedError::CommitmentMismatch`) *)
(*   AadBound        the envelope's associated data is compared against     *)
(*                   *this* submission's commitment                         *)
(*                   (`SealedError::EnvelopeNotBound`)                       *)
(*   SeatBound       a share must be signed by the identity the draw put in *)
(*                   that seat (`RuleViolation::SeatImpostor`)               *)
(*   EpochGated      a share must land in a strictly later epoch than its   *)
(*                   commitment (`RuleViolation::ShareBeforeEpoch`)          *)
(*                                                                         *)
(* WHAT IS NOT MODELLED                                                     *)
(*                                                                         *)
(* The committee *draw* is given here as `Holder`, a fixed injective map.   *)
(* Whether the draw is honest is `Partition`'s question and the beacon's,   *)
(* and docs/threat-model.md carries **committee capture** as **not          *)
(* handled**: the draw is over the log's peer records and is exactly as     *)
(* trustworthy as control of that set. Nothing here says otherwise.         *)
(*                                                                         *)
(* The economic window -- `V <= t*d*S'` and `V <= (n-t+1)*S'` from          *)
(* docs/diagrams.md §6 -- is a claim about the value of a bribe against the *)
(* value of a seat. It is numeric, it is about agents rather than about the *)
(* protocol, and no model checker has an opinion on it. What is checked     *)
(* here is the structural half: that `Threshold` colluders suffice to open  *)
(* early and that `n - Threshold + 1` suffice to withhold forever, which is *)
(* what makes the window a vice rather than a preference.                   *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Agents,          \* everyone who may seal a submission
    Artifacts,       \* what they may seal; at least two, so "something else" exists
    Members,         \* the peers a committee is drawn from
    Seats,           \* 1..n, the drawn seats
    Holder,          \* [Seats -> Members], injective: the draw, given
    Threshold,       \* t: how many shares reconstruct the key
    Liars,           \* SUBSET Members: seated members who answer with garbage,
                     \* or not at all -- both consume the seat and neither is
                     \* individually detectable
    Colluders,       \* SUBSET Members: who pools shares to read early
    MaxEpoch,
    BindingChecked,  \* TRUE ships. FALSE: open accepts whatever came out
    AadBound,        \* TRUE ships. FALSE: an envelope may be lifted between submissions
    SeatBound,       \* TRUE ships. FALSE: anyone may answer any seat
    EpochGated       \* TRUE ships. FALSE: a share may land in the commitment's own epoch

VARIABLES
    epoch,
    submissions,  \* {[who, art, honest, ep]} -- `honest` FALSE: sealed something else
    shares,       \* {[sub, seat, by, good, ep]}
    opened,       \* {[sub, got]} -- `got` is the artifact the opener ended up with
    leaked        \* {sub} -- read early by pooling colluders' shares

vars == <<epoch, submissions, shares, opened, leaked>>

-----------------------------------------------------------------------------
(* VOCABULARY.                                                              *)

\* Requires at least two artifacts: a dishonest sealer needs something else
\* to seal, and without one the binding check has nothing to catch.
Other(art) == CHOOSE y \in Artifacts : y # art

\* What actually comes out of the envelope, as against what the commitment
\* binds. Equal for an honest sealer; that inequality is the whole attack.
Content(s) == IF s.honest THEN s.art ELSE Other(s.art)

\* The commitment, as a tuple. See the header: injective, hence a perfect hash.
Commitment(s) == <<s.who, s.art>>

\* What an opener computes: the same hash, over what actually came out of the
\* envelope. Equal to the commitment exactly when the sealer was honest, which
\* is what makes the check cost one hash and catch everything it needs to.
RederivedCommitment(s) == <<s.who, Content(s)>>

GoodSharesFor(s) == {sh \in shares : sh.sub = s /\ sh.good}
SharesFor(s)     == {sh \in shares : sh.sub = s}

\* Shamir: >= t correct shares reconstruct the key, and nothing less does.
\* `open_sealed` tries every t-subset of what was published, so a liar's share
\* sitting alongside t good ones costs subsets to try and not the reveal.
Reconstructable(s) == Cardinality(GoodSharesFor(s)) >= Threshold

ColludingSeats == {k \in Seats : Holder[k] \in Colluders}
\* A seat answers honestly unless the member holding it lies. Withholding is
\* the same thing here as answering with garbage: the seat produces no good
\* share either way, and one share per seat means a garbage answer also
\* consumes the seat, so it is the stronger of the two attacks.
HonestSeats    == {k \in Seats : Holder[k] \notin Liars}

\* The low side of the vice: t colluding seats read every artifact early.
CommitteeCaptured == Cardinality(ColludingSeats) >= Threshold
\* The high side: n - t + 1 withholding seats mean t good shares never exist.
EnoughHonestSeats == Cardinality(HonestSeats) >= Threshold

IsOpened(s) == \E o \in opened : o.sub = s

-----------------------------------------------------------------------------
(* THE INSTANCE.                                                            *)

SubmissionSpace ==
    [who: Agents, art: Artifacts, honest: BOOLEAN, ep: 0..MaxEpoch]

ShareSpace ==
    [sub: SubmissionSpace, seat: Seats, by: Members, good: BOOLEAN,
     ep: 0..MaxEpoch]

OpenedSpace == [sub: SubmissionSpace, got: Artifacts]

\* The draw, given rather than derived: which member sits in which seat is
\* `Partition`'s question and the beacon's, not this module's. Injective,
\* because `committee_for` ranks distinct peers and refuses rather than
\* shrinking to fit when there are too few.
HolderI == [k \in Seats |-> IF k = 1 THEN "m1" ELSE IF k = 2 THEN "m2" ELSE "m3"]

TypeOK ==
    /\ epoch \in 0..MaxEpoch
    /\ submissions \subseteq SubmissionSpace
    /\ shares \subseteq ShareSpace
    /\ opened \subseteq OpenedSpace
    /\ leaked \subseteq SubmissionSpace

Init ==
    /\ epoch = 0
    /\ submissions = {}
    /\ shares = {}
    /\ opened = {}
    /\ leaked = {}

-----------------------------------------------------------------------------
(* ACTIONS.                                                                 *)

\* Seal once, and then never act again. One submission per agent bounds the
\* space; a second would be a second instance of a case already covered.
Seal(a, art, h) ==
    /\ epoch < MaxEpoch
    /\ ~\E s \in submissions : s.who = a
    /\ submissions' =
         submissions \cup {[who |-> a, art |-> art, honest |-> h, ep |-> epoch]}
    /\ UNCHANGED <<epoch, shares, opened, leaked>>

\* A member publishes a share for a seat.
\*
\* `good` is not free: producing the *real* share for seat k needs the KEM
\* secret that share was sealed to, which only Holder[k] has. A publisher who
\* is not the holder can still emit something well-formed -- a Shamir point is
\* not individually checkable -- and that is the bystander attack.
PublishShare(s, k, m, g) ==
    /\ s \in submissions
    /\ g => (m = Holder[k])
    \* A seated member who is not a liar follows the protocol. Without this an
    \* honest committee could stall itself, and the liveness question -- can
    \* `t` honest seats open it without the submitter -- would be unaskable.
    /\ (~g /\ m = Holder[k]) => (m \in Liars)
    /\ SeatBound => (m = Holder[k])
    /\ EpochGated => (epoch > s.ep)
    \* One share per seat, first wins: readers and appenders resolve a second
    \* the same way, so a duplicate buys no re-roll.
    /\ ~\E sh \in shares : sh.sub = s /\ sh.seat = k
    /\ shares' =
         shares \cup {[sub |-> s, seat |-> k, by |-> m, good |-> g, ep |-> epoch]}
    /\ UNCHANGED <<epoch, submissions, opened, leaked>>

\* Anyone opens. The submitter is not mentioned, which is the point.
Open(s) ==
    /\ s \in submissions
    /\ ~IsOpened(s)
    /\ Reconstructable(s)
    \* The binding check: re-derive the commitment from what came out and
    \* refuse a mismatch. With the check off, a dishonest sealer is paid for a
    \* plaintext their commitment never bound.
    /\ BindingChecked => (RederivedCommitment(s) = Commitment(s))
    /\ opened' = opened \cup {[sub |-> s, got |-> Content(s)]}
    /\ UNCHANGED <<epoch, submissions, shares, leaked>>

\* Lifting an envelope out of one submission and into another.
\*
\* The AEAD alone does not catch this: the associated data travels with the
\* envelope, so a transplanted envelope still authenticates against its own
\* aad. Comparing that aad to *this* submission's commitment is what turns
\* "this ciphertext is intact" into "this ciphertext is mine".
Transplant(s, donor) ==
    /\ ~AadBound
    /\ s \in submissions
    /\ donor \in submissions
    /\ donor # s
    /\ ~IsOpened(s)
    /\ Reconstructable(donor)
    /\ opened' = opened \cup {[sub |-> s, got |-> Content(donor)]}
    /\ UNCHANGED <<epoch, submissions, shares, leaked>>

\* Colluding members pool what they hold and read the plaintext early, without
\* publishing anything. Enabled only at t seats, which is the low side of the
\* vice stated as an enabling condition rather than asserted.
Collude(s) ==
    /\ CommitteeCaptured
    /\ s \in submissions
    /\ s \notin leaked
    /\ leaked' = leaked \cup {s}
    /\ UNCHANGED <<epoch, submissions, shares, opened>>

Tick ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ UNCHANGED <<submissions, shares, opened, leaked>>

\* Quantified over the constant space rather than over `submissions`, because
\* these appear under WF below and a fairness condition whose quantifier ranges
\* over a variable is a different formula in every state. Each action already
\* requires `s \in submissions`, so nothing is admitted that was not sealed.
OpenAny == \E s \in SubmissionSpace : Open(s)

HonestPublishAny ==
    \E s \in SubmissionSpace, k \in HonestSeats :
        PublishShare(s, k, Holder[k], TRUE)

Next ==
    \/ \E a \in Agents, art \in Artifacts, h \in BOOLEAN : Seal(a, art, h)
    \/ \E s \in SubmissionSpace, k \in Seats, m \in Members, g \in BOOLEAN :
            PublishShare(s, k, m, g)
    \/ OpenAny
    \/ \E s \in SubmissionSpace, d \in SubmissionSpace : Transplant(s, d)
    \/ \E s \in SubmissionSpace : Collude(s)
    \/ Tick

\* Fairness on opening and on honest members answering their seats: an honest
\* committee follows the protocol, and the liveness question is whether that is
\* enough *without the submitter*. Without these, "never opens" is a fair
\* behaviour and the property is vacuous.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(OpenAny)
    /\ WF_vars(HonestPublishAny)
    /\ WF_vars(Tick)

-----------------------------------------------------------------------------
(* SAFETY.                                                                  *)

\* Binding. Whatever is opened is what its commitment bound -- so a sealer who
\* seals garbage is caught by arithmetic, at the epoch boundary, for the price
\* of one hash. Falsified by BindingChecked = FALSE (the sealer is paid for
\* something else) and independently by AadBound = FALSE (someone else's
\* plaintext is attributed to this commitment).
OpenedMatchesItsCommitment ==
    \A o \in opened : o.got = o.sub.art

\* Threshold secrecy, on the publication path: nothing opens on fewer than t
\* correct shares. This is Shamir's information-theoretic property carried
\* through the composition -- t-1 shares do not open it *slowly*, they do not
\* open it.
NoOpenBelowThreshold ==
    \A o \in opened :
        \/ Cardinality(GoodSharesFor(o.sub)) >= Threshold
        \* A transplant opens on the donor's shares, which is the same
        \* arithmetic applied to the wrong submission -- caught as a binding
        \* failure above rather than counted as an early open here.
        \/ \E d \in submissions : d # o.sub /\ Reconstructable(d)

\* A share is only ever admitted from the identity the draw seated. Without
\* this a bystander fills t seats with noise and stalls every reveal they
\* choose to, because a Shamir point is not individually checkable.
\* Stated unguarded on purpose: an invariant written `SeatBound => ...` would
\* go vacuously true the moment the flag is turned off, and a falsification run
\* that reports success is worse than no falsification run. Falsified by
\* SeatBound = FALSE, which produces a bystander filling a seat it never held.
NoSeatImpostor ==
    \A sh \in shares : sh.by = Holder[sh.seat]

\* No share lands in its commitment's own epoch. A committee that could
\* publish immediately would open the artifact while the submission was still
\* in flight, which is the in-flight front-running that epoch batching exists
\* to close. Unguarded for the same reason as `NoSeatImpostor`. Falsified by
\* EpochGated = FALSE, which produces a share in the commitment's own epoch.
NoShareInCommitEpoch ==
    \A sh \in shares : sh.ep > sh.sub.ep

\* Reading early requires actually holding t seats. Nothing else -- not a
\* bystander, not a lying member, not the sequencer -- gets the plaintext
\* before the boundary.
NoEarlyLeakWithoutCapture ==
    leaked # {} => CommitteeCaptured

\* Nothing is read before the boundary. True in the shipped configuration
\* because no `Threshold`-sized set of members pools shares; the capture run
\* sets `Colluders` to `t` members and TLC answers with the early read. Paired
\* with `NoEarlyLeakWithoutCapture`, which says capture is the *only* route to
\* it -- not a bystander, not a liar, not the sequencer.
NothingLeaks == leaked = {}

\* One opening per submission: an open is not a payment, but a second one
\* would be a second artifact for one commitment.
NoDoubleOpen ==
    \A o1, o2 \in opened : o1.sub = o2.sub => o1.got = o2.got

-----------------------------------------------------------------------------
(* LIVENESS.                                                                *)

\* THE PROPERTY THE WHOLE DESIGN EXISTS FOR.
\*
\* A submission that was sealed opens, eventually, with no further action by
\* the submitter -- who has no action left to take, because this module gives
\* them none after `Seal`. Conditional on enough honest seats: with fewer than
\* t of them the high side of the vice bites and this fails, which is the
\* `Withheld` falsification run.
\* Split from `EventuallyOpens` so the withholding run has something to name.
\* Checked on its own only in that run, where `Liars` holds n - t + 1 seats and
\* TLC answers with the stall.
OpensRegardless ==
    \A s \in SubmissionSpace :
        (s \in submissions /\ s.honest) ~> IsOpened(s)

EventuallyOpens == EnoughHonestSeats => OpensRegardless

\* `s.honest` is not a weakening of the property, it is the other half of
\* binding: a submission whose plaintext does not match its commitment MUST
\* NOT open, and `OpenedMatchesItsCommitment` is what says so. TLC found this
\* the blunt way -- the first version of this property quantified over every
\* submission and produced a trace in which a dishonestly sealed one stalls
\* forever, which is the design working.
\*
\* A lying member costs subsets to try, never the reveal: `open_sealed`
\* enumerates every t-subset of the published shares, bounded by the committee
\* having fixed seats and one share each. That is inside `EventuallyOpens`
\* rather than beside it -- the shipped configuration seats a liar, so a run in
\* which the property holds is a run in which the liar failed to stall. Which
\* member lied stays unknowable, and that is Shamir rather than an omission:
\* attributing it needs a VSS whose hardness assumption this design declined to
\* make.

=============================================================================
