--------------------------------- MODULE Ledger ---------------------------------
(***************************************************************************)
(* The append-only hash-linked log, and an adversary who rewrites the file. *)
(*                                                                         *)
(* Models src/ledger.rs: `seq`, `prev`, the entry hash over                 *)
(* {seq, prev, kind, payload, ts}, `verify_chain`, `head`, and `root`.      *)
(*                                                                         *)
(* The hash abstraction, and what it assumes, is in `Hashing.tla`. Read     *)
(* that first: everything below is conditional on it.                       *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, Hashing

VARIABLES
    log,        \* the file on disk -- what a reader actually holds
    honestLog,  \* history variable: what the operator honestly appended
    tampered    \* has the adversary rewritten the file?

vars == <<log, honestLog, tampered>>

-----------------------------------------------------------------------------
(* Behaviour.                                                               *)

Init ==
    /\ log = <<>>
    /\ honestLog = <<>>
    /\ tampered = FALSE

(* The operator appends. `seq` is the count of what came before and `prev`  *)
(* is the current head, so the entry is fixed by the log it lands on.       *)
Extend ==
    /\ ~tampered
    /\ Len(log) < MaxLen
    /\ \E body \in Payloads:
         LET e == MakeEntry(Len(log), HeadHash(log), body) IN
           /\ log' = Append(log, e)
           /\ honestLog' = Append(honestLog, e)
    /\ UNCHANGED tampered

(* Every adversarial action rewrites the file only. `honestLog` is a        *)
(* history variable and stays as it was, which is what makes it possible to *)
(* ask "is this rewrite visible?" at all.                                   *)
(*                                                                          *)
(* Honest appends stop once the adversary has acted, and that is a stated   *)
(* bound rather than a claim: after a rewrite the two logs have already     *)
(* diverged, and appending equally to both preserves the divergence         *)
(* (hashing forward from different heads gives different heads). Modelling  *)
(* the continuation multiplies the state space and cannot reach a state     *)
(* where the rewrite has become invisible.                                  *)
(*                                                                          *)
(* The adversary is free to compose the actions below in any order.         *)

(* Truncate the tail. This is the attack `verify_chain` structurally cannot *)
(* catch: a shorter prefix of a valid chain is itself a valid chain.        *)
AdvTruncate ==
    /\ Len(log) > 0
    /\ \E k \in 0..(Len(log) - 1): log' = SubSeq(log, 1, k)
    /\ tampered' = TRUE
    /\ UNCHANGED honestLog

(* Edit an entry's content and leave the recorded hash alone -- the forgery *)
(* a "the file says so" reader would accept.                                *)
AdvEditKeepHash ==
    /\ \E i \in 1..Len(log), body \in Payloads:
         /\ body # log[i].payload
         /\ log' = [log EXCEPT ![i].payload = body]
    /\ tampered' = TRUE
    /\ UNCHANGED honestLog

(* Replace the file with any internally consistent chain at all.            *)
(*                                                                          *)
(* This stands in for "edit an entry and re-hash the suffix", and it is     *)
(* strictly stronger: re-hashing after an edit yields *some* well-formed    *)
(* chain, and this action offers every one of them -- including results of  *)
(* edit-and-rehash sequences that no bounded number of steps would reach.   *)
(*                                                                          *)
(* Modelling re-hashing as its own step was tried and rejected. It is not   *)
(* wrong, it is unbounded in practice: each re-hash mints hash values that  *)
(* nest the previous ones, so the reachable hash universe grows by a factor *)
(* of |Payloads| * MaxLen per step and TLC never finishes. This action      *)
(* reaches the same files -- all of them -- out of a set whose size is      *)
(* fixed by MaxLen alone.                                                   *)
AdvForge ==
    /\ \E c \in WellFormedChains: log' = c
    /\ tampered' = TRUE
    /\ UNCHANGED honestLog

(* Splice an entry out of the middle. Every surviving line still hashes     *)
(* correctly; what gives it away is the sequence gap and the broken link.   *)
AdvDelete ==
    /\ \E i \in 1..Len(log):
         log' = SubSeq(log, 1, i - 1) \o SubSeq(log, i + 1, Len(log))
    /\ tampered' = TRUE
    /\ UNCHANGED honestLog

AdvSwap ==
    /\ \E i \in 1..(Len(log) - 1):
         log' = [log EXCEPT ![i] = log[i + 1], ![i + 1] = log[i]]
    /\ tampered' = TRUE
    /\ UNCHANGED honestLog

Next ==
    \/ Extend
    \/ AdvTruncate
    \/ AdvEditKeepHash
    \/ AdvForge
    \/ AdvDelete
    \/ AdvSwap

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                              *)

TypeOK ==
    /\ tampered \in BOOLEAN
    /\ Len(log) <= MaxLen
    /\ Len(honestLog) <= MaxLen
    /\ \A i \in 1..Len(log): log[i].payload \in Payloads

(* An untouched log is internally consistent and is what the operator wrote.*)
ChainIntegrity == ~tampered => (VerifyChain(log) /\ log = honestLog)

(* THE HEADLINE.                                                            *)
(*                                                                          *)
(* Any divergence between the file and what was honestly appended is caught *)
(* by re-hashing the chain, or by comparing the published head, or both.    *)
(*                                                                          *)
(* Stated as a disjunction rather than as two separate invariants because   *)
(* neither half holds alone, and pretending otherwise is exactly the        *)
(* overstatement this repository cannot afford:                             *)
(*                                                                          *)
(*   - `VerifyChain` alone misses `AdvTruncate`: the prefix verifies.       *)
(*   - `HeadHash` alone misses `AdvEditKeepHash`: the tail entry is         *)
(*     untouched, so the head is unchanged, and only re-hashing entry i     *)
(*     notices.                                                             *)
(*                                                                          *)
(* Together they are complete at these bounds, and that pairing is the      *)
(* actual mechanism: the chain proves internal consistency, and the         *)
(* published head closes the truncation gap the chain structurally leaves   *)
(* open. `Checkpoint` is what makes the published head trustworthy.         *)
DetectedSomehow ==
    (log # honestLog) => (~VerifyChain(log) \/ HeadHash(log) # HeadHash(honestLog))

(* The sharper statement about rewrites specifically: an adversary who      *)
(* repairs the chain, so that `verify_chain` passes, has necessarily moved  *)
(* the head. Rewriting one entry means rewriting the entire suffix, and the *)
(* suffix ends at the value everyone pinned.                                *)
RepairedRewriteMovesHead ==
    (VerifyChain(log) /\ log # honestLog) => HeadHash(log) # HeadHash(honestLog)

(* The Merkle root is as strong an anchor as the head, which is what lets a *)
(* third party audit one settlement against a published root without        *)
(* holding the log. Note the guard: for a log that does *not* verify, the   *)
(* root proves nothing, because it is computed over the *recorded* hashes   *)
(* and an edit that leaves a stale hash in place leaves the root untouched. *)
(* That is a property of the mechanism, not a gap in the model, and it is   *)
(* the second half of why `DetectedSomehow` has to be a disjunction.        *)
RootPinsWellFormedLogs ==
    (VerifyChain(log) /\ Root(log) = Root(honestLog)) => log = honestLog

(* Append-only, as a step property: the operator never rewrites history.    *)
AppendOnly ==
    [][ /\ Len(honestLog') >= Len(honestLog)
        /\ \A i \in 1..Len(honestLog): honestLog'[i] = honestLog[i] ]_vars

=============================================================================
