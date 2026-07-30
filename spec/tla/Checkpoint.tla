------------------------------- MODULE Checkpoint -------------------------------
(***************************************************************************)
(* Signed roots, and a reader who holds only a fragment.                    *)
(*                                                                         *)
(* Models src/checkpoint.rs (ML-DSA-65 over `(height, head, root,           *)
(* issued_at)`, `verify_against`) and the reader described in              *)
(* docs/design-stage0-completion.md §2, `proofwork verify --from`.          *)
(*                                                                         *)
(* WHY THIS MODULE EXISTS AT ALL                                           *)
(*                                                                         *)
(* `Ledger` proves that a rewritten log is caught by re-hashing *or* by     *)
(* comparing the head. The second half of that disjunction is doing real    *)
(* work -- it is the only thing that catches truncation -- and it is worth  *)
(* nothing unless the head a reader compares against is one the operator    *)
(* cannot have chosen after the fact. A signature over `(height, head,      *)
(* root)` is what makes the head an anchor instead of a rumour.             *)
(*                                                                         *)
(* HOW SIGNATURES ARE MODELLED, AND WHAT THAT ASSUMES                      *)
(*                                                                         *)
(* A signed checkpoint carries its signer, and `SigOk` checks the signer    *)
(* against the reader's pinned key. Forgery is therefore unrepresentable    *)
(* rather than hard: ML-DSA-65's EUF-CMA security is *assumed*, not         *)
(* checked, and nothing here says anything about an attacker who can forge  *)
(* one. The only thing checked is that the protocol *uses* the signature,   *)
(* i.e. that no path accepts a checkpoint the pinned key did not sign.      *)
(*                                                                         *)
(* `issued_at` is signed in the implementation but is not modelled: it is   *)
(* carried through `verify_against` untouched and no property here depends  *)
(* on it. Including it would multiply the state space by |Timestamps| to    *)
(* check nothing.                                                          *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, Hashing

CONSTANTS
    RootKey,    \* the key a reader has pinned out of band
    EveKey      \* any other key; an adversary who signs with it

(* "no checkpoint pinned yet", shaped like a checkpoint so that TLC can     *)
(* compare it with one -- it refuses to compare a record with a string. The *)
(* signer is a key nobody holds, so `SigOk` rejects it and the placeholder  *)
(* can never be mistaken for an anchor.                                     *)
NoCkpt == [signer |-> "k_nobody", height |-> 0, head |-> NoHash, root |-> <<>>]

VARIABLES
    opLog,      \* the operator's current file
    rdLog,      \* the reader's copy: a prefix, an extension, or a fork
    ckpt,       \* the checkpoint the reader has pinned, or NoCkpt
    anchor      \* ghost: the exact prefix `ckpt` was signed over

vars == <<opLog, rdLog, ckpt, anchor>>

-----------------------------------------------------------------------------
(* The reader's check: `proofwork verify --from`.                           *)

SigOk(c) == c.signer = RootKey

(*  1. the signature verifies against the pinned root key;                  *)
(*  2. the reader's log is at least `height` long -- a shorter log cannot    *)
(*     prove the checkpoint;                                                *)
(*  3. the reader's *prefix* at `height` reproduces the signed head and     *)
(*     root. A longer log is fine: the reader is verifying that its prefix  *)
(*     matches what the operator signed, not that it holds nothing after.   *)
VerifyFrom(c, l) ==
    /\ SigOk(c)
    /\ Len(l) >= c.height
    /\ HeadHash(SubSeq(l, 1, c.height)) = c.head
    /\ Root(SubSeq(l, 1, c.height)) = c.root

Sign(key, l) ==
    [signer |-> key, height |-> Len(l), head |-> HeadHash(l), root |-> Root(l)]

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

Init ==
    /\ opLog = <<>>
    /\ rdLog = <<>>
    /\ ckpt = NoCkpt
    /\ anchor = <<>>

OpExtend ==
    /\ Len(opLog) < MaxLen
    /\ \E body \in Payloads:
         opLog' = Append(opLog, MakeEntry(Len(opLog), HeadHash(opLog), body))
    /\ UNCHANGED <<rdLog, ckpt, anchor>>

(* The rollback attack: publish a shorter, internally valid chain.          *)
OpRollback ==
    /\ Len(opLog) > 0
    /\ \E k \in 0..(Len(opLog) - 1): opLog' = SubSeq(opLog, 1, k)
    /\ UNCHANGED <<rdLog, ckpt, anchor>>

(* The daemon signs the current state. The reader pins the latest one it    *)
(* has seen; `anchor` records what was actually signed so the properties    *)
(* below can talk about it.                                                 *)
OpSign ==
    /\ ckpt' = Sign(RootKey, opLog)
    /\ anchor' = opLog
    /\ UNCHANGED <<opLog, rdLog>>

(* The reader's own view. Any well-formed chain: it may be a prefix of the  *)
(* operator's log (a fragment), an extension of it, an unrelated fork, or   *)
(* the operator's log exactly. Modelled as a free choice rather than as     *)
(* incremental sync actions because the reader's provenance is irrelevant   *)
(* to the question -- what matters is only which of those cases the check   *)
(* accepts -- and the free choice covers all four in one action.            *)
RdAdopt ==
    /\ \E c \in WellFormedChains: rdLog' = c
    /\ UNCHANGED <<opLog, ckpt, anchor>>

Next == OpExtend \/ OpRollback \/ OpSign \/ RdAdopt

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                              *)

Pinned == ckpt # NoCkpt

TypeOK ==
    /\ Len(opLog) <= MaxLen
    /\ Len(rdLog) <= MaxLen
    /\ Pinned => (ckpt.height = Len(anchor) /\ ckpt.signer = RootKey)

(* THE HEADLINE.                                                            *)
(*                                                                          *)
(* `verify --from` accepts exactly when the reader's prefix at `height` is  *)
(* the prefix that was signed -- no more, no less.                          *)
(*                                                                          *)
(* Both directions matter and they fail differently. Left to right is       *)
(* soundness: nothing else can be made to pass, so a rolled-back or forked  *)
(* log is refused. Right to left is the part a naive implementation gets    *)
(* wrong: a reader holding *more* than the checkpoint covers must still     *)
(* accept, or every reader who has synced since the last checkpoint is told *)
(* their log is bad.                                                        *)
AcceptIffPrefixMatches ==
    Pinned =>
        ( VerifyFrom(ckpt, rdLog)
            <=> ( /\ Len(rdLog) >= ckpt.height
                  /\ SubSeq(rdLog, 1, ckpt.height) = anchor ) )

(* A reader holding less than the checkpoint covers cannot confirm it, and  *)
(* must say so rather than verifying what it does have and reporting        *)
(* success. This is design item §2 rule 2, stated on its own because it is  *)
(* the rule a fragment reader is most likely to drop.                       *)
ShortFragmentIsRefused ==
    (Pinned /\ Len(rdLog) < ckpt.height) => ~VerifyFrom(ckpt, rdLog)

(* The rollback row of docs/threat-model.md. An operator who publishes a    *)
(* shorter chain than it has signed for is caught by any reader still       *)
(* holding the older checkpoint, however internally valid the short chain.  *)
RollbackIsDetected ==
    (Pinned /\ rdLog = opLog /\ Len(opLog) < ckpt.height)
        => ~VerifyFrom(ckpt, rdLog)

(* The strongest forgery available to an adversary who cannot sign: a       *)
(* checkpoint whose payload is exactly right for the reader's own log, and  *)
(* which would therefore pass every content check. It is refused on the key *)
(* alone -- which is why the reader must pin the key out of band, and why   *)
(* a key merely embedded in the checkpoint file proves nothing.             *)
Forgery == Sign(EveKey, rdLog)
ForgedCheckpointIsRefused == ~VerifyFrom(Forgery, rdLog)

=============================================================================
