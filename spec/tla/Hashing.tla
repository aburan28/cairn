-------------------------------- MODULE Hashing --------------------------------
(***************************************************************************)
(* The hash-linked log, as vocabulary. No variables and no behaviour: this  *)
(* module exists so that `Ledger`, `Checkpoint`, `Sync` and `Cairn`     *)
(* agree about what an entry hash *is*, rather than each carrying its own   *)
(* copy of the definition. Two copies of a rule become two different rules. *)
(*                                                                         *)
(* It has no .cfg and `scripts/tla.sh` does not run it, because there is    *)
(* nothing here to check -- only definitions the checked modules share.     *)
(*                                                                         *)
(* HOW HASHING IS MODELLED, AND WHAT THAT ASSUMES                          *)
(*                                                                         *)
(* An entry's hash is its body, verbatim: `HashOf(e) == <<e.seq, e.prev,    *)
(* e.payload>>`. A tuple is injective in its components, so this is exactly *)
(* a collision-free hash and nothing else. Every result in every module     *)
(* that uses this one is therefore conditional on SHA-256 being            *)
(* collision-free. Collisions are *assumed away*, not verified, and no      *)
(* amount of model checking says anything about an attacker who finds one.  *)
(*                                                                         *)
(* The obvious alternative was an opaque `Hashes` constant plus an          *)
(* injectivity ASSUME. It was rejected because the adversary then needs a   *)
(* domain of hash values to draw from, and either that domain contains      *)
(* hashes of bodies it cannot construct -- which models an attacker who can *)
(* invert SHA-256, a strictly different and much stronger adversary than    *)
(* the one the design defends against -- or it does not, in which case it   *)
(* is this encoding with more machinery on top.                            *)
(*                                                                         *)
(* WHY `kind` AND `ts` ARE FOLDED INTO `payload`                           *)
(*                                                                         *)
(* The real body covers five fields: seq, prev, kind, payload, ts. Every    *)
(* property stated anywhere here is about whether a change to the *covered* *)
(* content is detectable, and a hash over five fields detects strictly more *)
(* changes than a hash over three. Splitting them out multiplies the state  *)
(* space by |Kinds| * |Timestamps| and cannot make any property fail.       *)
(* `payload` stands for the whole covered content.                          *)
(***************************************************************************)
EXTENDS Integers, Sequences

CONSTANTS
    Payloads,   \* distinct record bodies an operator may append
    MaxLen      \* bound on log length; see spec/tla/README.md

(* The `prev` of the genesis entry. JSON `null` in the implementation, and  *)
(* deliberately not the empty string: an absent predecessor and a           *)
(* predecessor whose hash happens to be empty must not produce equal bytes. *)
(*                                                                         *)
(* A one-element tuple rather than a bare string, so that it inhabits the   *)
(* same value space as a hash (a three-element tuple) and can never equal   *)
(* one. TLC refuses to compare a string with a tuple at all, which would    *)
(* turn "genesis is not a hash" from a fact into a type error.              *)
NoHash == <<"genesis">>

HashOf(e) == <<e.seq, e.prev, e.payload>>

MakeEntry(s, p, body) ==
    [seq |-> s, prev |-> p, payload |-> body, hash |-> <<s, p, body>>]

(* The value a reader pins to detect a rewritten log. *)
HeadHash(l) == IF l = <<>> THEN NoHash ELSE l[Len(l)].hash

(* The Merkle root pins the whole log in one value. Modelled as the list of *)
(* entry hashes: a second-preimage-free Merkle tree is injective on its     *)
(* leaf list, which is what the implementation's promote-odd-node           *)
(* construction buys (Bitcoin CVE-2012-2459). Note what this means, and it  *)
(* is a property of the mechanism rather than a limitation of the model:    *)
(* the root is a function of the *recorded* hashes, so it cannot see an     *)
(* edit that left a stale hash behind. Only `VerifyChain` can.              *)
Root(l) == [i \in 1..Len(l) |-> l[i].hash]

(* verify_chain: seq counts from zero, prev links to the predecessor's      *)
(* recorded hash, and each hash is reproducible from the entry's content.   *)
(* All three, because they fail on different attacks.                       *)
VerifyChain(l) ==
    \A i \in 1..Len(l):
        /\ l[i].seq = i - 1
        /\ l[i].prev = (IF i = 1 THEN NoHash ELSE l[i-1].hash)
        /\ l[i].hash = HashOf(l[i])

(* The well-formed chain over a sequence of payloads. This is both what an  *)
(* honest operator produces and -- crucially -- the only shape an adversary *)
(* who wants `verify_chain` to pass can produce, because repairing one      *)
(* entry forces repairing every entry after it.                             *)
RECURSIVE Chain(_)
Chain(bodies) ==
    IF bodies = <<>>
    THEN <<>>
    ELSE LET front == Chain(SubSeq(bodies, 1, Len(bodies) - 1))
             body  == bodies[Len(bodies)]
         IN  Append(front, MakeEntry(Len(bodies) - 1, HeadHash(front), body))

(* Every well-formed chain of at most MaxLen entries: one per payload       *)
(* sequence, so |Payloads|^0 + ... + |Payloads|^MaxLen of them.             *)
WellFormedChains ==
    { Chain(s) : s \in UNION { [1..n -> Payloads] : n \in 0..MaxLen } }

=============================================================================
