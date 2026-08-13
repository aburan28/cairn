//! What the log says about a claim *after* its verifier has spoken: standing,
//! corroboration, contest, and a confidence number nobody has to agree with.
//!
//! # Why this is a view and not a consensus layer
//!
//! Everything else in this crate is careful to keep opinion out of settlement.
//! A verifier's `accept` mints value because it is reproducible; a majority's
//! belief mints nothing, because a network that votes on empirical truth has
//! built a popularity contest with a hash function bolted on. That refusal is
//! the design, and this module does not walk it back.
//!
//! What this module adds is the other half of the same honesty. A verified
//! artifact is not the end of a claim's life: it gets replicated, or it fails
//! to replicate; it gets narrowed to the scope it actually holds on; its author
//! withdraws it; a later result supersedes it. An append-only log that records
//! only the original verdict is not preserving that history, it is *hiding* it
//! behind the last thing that happened to be settled.
//!
//! So the split is:
//!
//! - **The log records what happened.** Verdicts, and typed [`Relation`]s
//!   asserted by claims that were themselves verified. Facts about who said
//!   what, all of them re-derivable.
//! - **This module computes what to make of it**, under a
//!   [`ConfidencePolicy`] the *reader* chooses. Two readers with different
//!   policies get different numbers from identical bytes, and neither is wrong.
//!   That is the point: a regulator demanding independent replication and a
//!   researcher scanning for leads are asking different questions of one graph.
//!
//! Nothing here is written to the log, nothing here moves money, and nothing
//! here can change a settled payout. If that ever stops being true, the
//! popularity contest is back.
//!
//! # Why a relation only counts when its author's own claim was accepted
//!
//! Anyone can append a claim saying "this refutes X". If that alone contested
//! X, contesting would be free and every frontier holder would wake up
//! contested. The grounding rule is that a relation is heard only from a claim
//! the *objective's pinned verifier accepted* — so asserting something about X
//! costs whatever it costs to produce a verified result, which is the only
//! scarce thing this network recognizes.
//!
//! Be precise about what that buys, because it is easy to overstate: the
//! verifier checked the **artifact**, not the relation. A claim that solves a
//! Ramsey bound and declares `refutes` on an unrelated claim has been verified
//! for the bound and not for the refutation. Acceptance is evidence that the
//! author did real work, not that the edge they drew is true. Which is exactly
//! why the output is a view: it reports *who with standing said what*, and lets
//! the reader weigh it.
//!
//! [`Relation::Retracts`] is the one exception, and it needs no verdict: it
//! counts only from the target's own submitter, so nobody else can spam it.
//! The cost is real and stated in [`Standing::Withdrawn`] — a per-objective
//! pseudonym cannot retract work it did under a different pseudonym.
//!
//! # No floats, here of all places
//!
//! Confidence is parts per thousand in a `u32`. A float would be the obvious
//! choice and it is refused for the same reason `canonical::Value` has no float
//! variant: two nodes that round differently report different confidence for
//! one claim, and the first thing anyone will do with a confidence number is
//! threshold it. Integer arithmetic makes "did it clear 0.75" a question with
//! one answer everywhere.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::records::{Claim, Relation};
use crate::verifiers::Status;

// ---------------------------------------------------------------------------
// What a relation does
// ---------------------------------------------------------------------------

/// The mechanical effect a [`Relation`] has on its target's standing.
///
/// Nine kinds collapse to four effects. The collapse is deliberate: the kinds
/// exist so a submitter can say what they actually found, and the effects exist
/// so this module has a small number of cases to get right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// Independent support: the target's result survived somebody else's
    /// attempt on it.
    Corroborates,
    /// Evidence against, of varying strength. The strength is not encoded here
    /// — [`ConfidencePolicy`] prices `refutes` and `fails_to_replicate`
    /// separately, and this enum only says which direction they point.
    Contests,
    /// The target has been replaced, corrected, or cut down to a smaller scope.
    /// Not the same as being wrong: a superseded claim was usually right about
    /// something.
    Supersedes,
    /// The target's own author took it back.
    Withdraws,
}

impl Relation {
    /// How this relation bears on the claim it names.
    ///
    /// `Generalizes` corroborates rather than supersedes, which is the one
    /// mapping here that is not obvious. Showing a result holds more broadly
    /// does not retire the narrower statement — the narrow one is still true,
    /// still cited, and still the thing somebody's proof depends on. Filing it
    /// under `Supersedes` would demote a claim for the crime of being extended,
    /// which gets the incentive exactly backwards.
    pub const fn effect(self) -> Effect {
        match self {
            Relation::Replicates | Relation::Generalizes => Effect::Corroborates,
            Relation::Refutes | Relation::FailsToReplicate | Relation::ConflictsWith => {
                Effect::Contests
            }
            Relation::Supersedes | Relation::Corrects | Relation::Narrows => Effect::Supersedes,
            Relation::Retracts => Effect::Withdraws,
        }
    }
}

// ---------------------------------------------------------------------------
// Standing
// ---------------------------------------------------------------------------

/// Where a claim stands once the log has been read whole.
///
/// # The precedence, and why it is this order
///
/// Exactly one of these applies, resolved in the order the variants are
/// declared. Two rules drive it:
///
/// 1. **The machine outranks the assertions.** [`Standing::Refuted`] comes from
///    the objective's own pinned verifier saying `reject`, which is
///    reproducible by anyone. No quantity of claims asserting otherwise moves
///    it, because that is the direction in which this whole system refuses to
///    take votes.
/// 2. **Among assertions, the narrower statement wins.** "Its author withdrew
///    it" says more than "somebody superseded it", which says more than
///    "somebody disputes it", which says more than "somebody reproduced it".
///    Reporting the vaguest applicable label would be technically true and
///    useless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Standing {
    /// The pinned verifier rejected the artifact. A machine verdict, and the
    /// end of the discussion.
    Refuted,
    /// No settling verdict is recorded. Covers a claim whose verdict was
    /// `unavailable` — the node could not check — which is emphatically not a
    /// rejection, the same distinction [`Status::settles`] exists to protect.
    Unverified,
    /// The submitter retracted their own claim.
    ///
    /// Only the target's own **key** can do this: a matching submitter
    /// *string* is not enough, because a nickname authenticates nothing and
    /// anybody may use one. Two limits follow, both deliberate:
    ///
    /// * A claim submitted under an unauthenticated nickname can never reach
    ///   this state. Nobody owns that name, so nobody is its author.
    /// * A per-objective pseudonym derives a different key per objective, so a
    ///   retraction must come from a claim on the same objective — the only
    ///   place that pseudonym appears. A real limit of pseudonymity, not an
    ///   oversight, and the alternative (letting a *different* key withdraw
    ///   your work) is not a trade anyone should want.
    Withdrawn,
    /// A later verified claim supersedes, corrects, or narrows it.
    Superseded,
    /// Verified claims dispute it, and nothing has resolved the dispute.
    Contested,
    /// Verified and independently reproduced by at least one other party.
    Corroborated,
    /// Verified, and nothing further has been said about it. The resting state
    /// of almost every claim in the log.
    Accepted,
}

impl Standing {
    pub const fn as_str(self) -> &'static str {
        match self {
            Standing::Refuted => "refuted",
            Standing::Unverified => "unverified",
            Standing::Withdrawn => "withdrawn",
            Standing::Superseded => "superseded",
            Standing::Contested => "contested",
            Standing::Corroborated => "corroborated",
            Standing::Accepted => "accepted",
        }
    }

    /// Whether the claim's own verification still stands, whatever has since
    /// been said about it.
    ///
    /// True for everything a verifier accepted, superseded and contested
    /// included. A superseded claim is not a wrong claim, and a reader looking
    /// for "did this pass its verifier" must not have that answer smuggled away
    /// by a later assertion.
    pub const fn was_verified(self) -> bool {
        matches!(
            self,
            Standing::Withdrawn
                | Standing::Superseded
                | Standing::Contested
                | Standing::Corroborated
                | Standing::Accepted
        )
    }
}

impl fmt::Display for Standing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Reproducibility of the evidence
// ---------------------------------------------------------------------------

/// Whether this node can still re-run the check that accepted a claim.
///
/// The network's one guarantee is that anyone can independently re-derive every
/// settled result. That guarantee has a dependency nothing else in the crate
/// tracks against a *claim*: the objective's pinned verifier code has to still
/// be fetchable. A hash proves the bytes you got are the bytes that were
/// pinned; it does not conjure the bytes.
///
/// So this is availability made visible at the knowledge layer, rather than
/// left as a storage-tier statistic. A claim whose verifier code has vanished
/// is still in the log, still settled, still paid — and no longer checkable,
/// which a reader deciding whether to build on it deserves to be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reproducible {
    /// The pinned code resolves here: the verdict can be re-derived locally.
    Yes,
    /// Pinned code is missing from this node's store and bundle. Says nothing
    /// about whether the network as a whole still has it — one node's want set
    /// is not a global availability proof, and treating it as one would let a
    /// node that simply has not synced yet declare the network's evidence lost.
    NotHere,
    /// Not determined. The default, so that a caller who has no store to check
    /// against is not silently reported as having lost everything.
    Unknown,
}

impl Reproducible {
    pub const fn as_str(self) -> &'static str {
        match self {
            Reproducible::Yes => "yes",
            Reproducible::NotHere => "not-here",
            Reproducible::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// The reader's weighting. Every number is parts per thousand.
///
/// This is the knob panel, and it is the reader's, not the network's. The
/// defaults below are a starting point with no authority whatsoever — they are
/// not "the" confidence function, and a client that ships its own is using this
/// module correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidencePolicy {
    /// Credit for the pinned verifier's `accept`.
    ///
    /// Deliberately short of 1000. A verified artifact is a machine-checked
    /// fact about an artifact, not a guarantee that the objective asked the
    /// right question — and leaving headroom is what lets independent
    /// replication mean something.
    pub verified: u32,
    /// Credit per independent corroboration.
    pub per_corroboration: u32,
    /// Ceiling on total corroboration credit, so that a large enough crowd
    /// cannot vote a claim to certainty. Without this the module would be a
    /// popularity contest with extra steps.
    pub max_corroboration: u32,
    /// Debit per independent `refutes`.
    pub per_refutation: u32,
    /// Debit per independent `fails_to_replicate` or `conflicts_with`.
    ///
    /// Lower than [`ConfidencePolicy::per_refutation`] by default: not
    /// reproducing a result is weaker evidence than demonstrating it false, and
    /// pricing them the same would make the cheap assertion as damaging as the
    /// expensive one.
    pub per_dispute: u32,
    /// Retained fraction once a claim has been superseded. Not zero: superseded
    /// work is usually still correct on its own terms, and zeroing it would
    /// punish being built upon.
    pub superseded_weight: u32,
    /// Retained fraction when the verdict cannot be re-derived here.
    pub unreproducible_weight: u32,
    /// Epochs per decay step. `0` disables decay entirely.
    pub decay_period: u64,
    /// Retained fraction per elapsed decay step.
    pub decay_retention: u32,
    /// How far back to walk citations when deciding whether two assertions came
    /// from correlated sources.
    ///
    /// **Zero by default, and that is not laziness.** At depth 1 or more, every
    /// claim on a ratcheted objective is correlated with every other one: the
    /// frontier citation rule *requires* them all to cite the same claim, so
    /// ancestry overlap is guaranteed by protocol and independence collapses to
    /// one class no matter how many genuinely separate parties contributed. The
    /// test is available for graphs where shared ancestry is informative, and
    /// off where it is structurally meaningless.
    pub independence_depth: u32,
}

impl Default for ConfidencePolicy {
    fn default() -> ConfidencePolicy {
        ConfidencePolicy {
            verified: 600,
            per_corroboration: 120,
            max_corroboration: 360,
            per_refutation: 300,
            per_dispute: 150,
            superseded_weight: 700,
            unreproducible_weight: 400,
            decay_period: 0,
            decay_retention: 950,
            independence_depth: 0,
        }
    }
}

impl ConfidencePolicy {
    /// A policy for a reader who wants replication before belief: acceptance
    /// alone is worth little, reproduction is worth a lot, and a single
    /// refutation is close to fatal.
    pub fn demanding() -> ConfidencePolicy {
        ConfidencePolicy {
            verified: 350,
            per_corroboration: 220,
            max_corroboration: 650,
            per_refutation: 800,
            per_dispute: 400,
            superseded_weight: 500,
            unreproducible_weight: 150,
            ..ConfidencePolicy::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One claim, with the log's verdict on it and the epoch it landed in.
///
/// A borrowed input struct rather than a trait: the caller
/// ([`crate::node::Node`]) already has all of this in hand, and a trait would
/// buy an abstraction over exactly one implementation.
#[derive(Debug, Clone, Copy)]
pub struct ClaimFacts<'a> {
    pub id: &'a str,
    pub claim: &'a Claim,
    /// The last verdict recorded against this claim, if any. `None` and
    /// `Some(Unavailable)` are both "not verified" and are deliberately not
    /// collapsed by the caller: an auditor wants to know which.
    pub verdict: Option<Status>,
    /// The epoch the claim was revealed in, derived from the record's own
    /// timestamp — never from a clock, for the reason stated across this crate.
    pub epoch: u64,
    pub reproducible: Reproducible,
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// One asserted edge, with who asserted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// The claim that carries the relation.
    pub by: String,
    pub kind: Relation,
    /// Whether this assertion was heard at all: `false` when its author's own
    /// claim was not accepted, or when a `retracts` came from somebody other
    /// than the target's submitter. Kept rather than filtered so that a reader
    /// can see what was said *and* why it did not count.
    pub grounded: bool,
    /// Which independence class this assertion fell into. Two assertions
    /// sharing a class counted once.
    pub class: usize,
}

/// Everything this module has to say about one claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeState {
    pub claim_id: String,
    pub standing: Standing,
    pub verdict: Option<Status>,
    pub reproducible: Reproducible,
    /// Distinct independent parties corroborating, after collapsing correlated
    /// sources.
    pub corroborations: u32,
    /// Distinct independent parties refuting.
    pub refutations: u32,
    /// Distinct independent parties disputing more weakly
    /// (`fails_to_replicate`, `conflicts_with`).
    pub disputes: u32,
    /// Claims that supersede, correct, or narrow this one.
    pub superseded_by: Vec<String>,
    /// The claim carrying the author's retraction, if there is one.
    pub retracted_by: Option<String>,
    /// Every relation pointed at this claim, grounded or not, in claim-id
    /// order.
    pub assertions: Vec<Assertion>,
    /// Parts per thousand, under the policy this was computed with.
    pub confidence: u32,
}

impl KnowledgeState {
    /// Confidence as a percentage, rounded down. For display only — thresholds
    /// belong on [`KnowledgeState::confidence`], which has not lost three
    /// digits.
    pub fn confidence_percent(&self) -> u32 {
        self.confidence / 10
    }
}

// ---------------------------------------------------------------------------
// The graph
// ---------------------------------------------------------------------------

/// The claim graph, indexed for standing queries.
///
/// Built once from a snapshot of facts and then queried, rather than recomputed
/// per claim: the inbound-relation index is the expensive part and it is shared
/// by every claim in the log.
pub struct KnowledgeGraph<'a> {
    facts: BTreeMap<&'a str, ClaimFacts<'a>>,
    /// target claim id -> the claims asserting something about it.
    inbound: BTreeMap<&'a str, Vec<(&'a str, Relation)>>,
}

impl<'a> KnowledgeGraph<'a> {
    /// Index a snapshot of the log.
    ///
    /// Later facts for a repeated id win, matching the log's own
    /// last-verdict-wins rule.
    pub fn new(facts: impl IntoIterator<Item = ClaimFacts<'a>>) -> KnowledgeGraph<'a> {
        let mut indexed: BTreeMap<&'a str, ClaimFacts<'a>> = BTreeMap::new();
        for fact in facts {
            indexed.insert(fact.id, fact);
        }
        let mut inbound: BTreeMap<&'a str, Vec<(&'a str, Relation)>> = BTreeMap::new();
        for (id, fact) in &indexed {
            for relation in &fact.claim.relations {
                // A relation naming a claim this snapshot does not contain is
                // dropped here rather than reported. It is not evidence of
                // anything: the log is append-only and a reader who is mid-sync
                // legitimately has the asserting claim and not yet the target.
                if let Some((target, _)) = indexed.get_key_value(relation.target.as_str()) {
                    inbound.entry(target).or_default().push((id, relation.kind));
                }
            }
        }
        // Sorted so the reported assertion order and the independence class
        // numbering are functions of the log, not of iteration order.
        for list in inbound.values_mut() {
            list.sort_unstable();
        }
        KnowledgeGraph {
            facts: indexed,
            inbound,
        }
    }

    pub fn contains(&self, claim_id: &str) -> bool {
        self.facts.contains_key(claim_id)
    }

    pub fn claim_ids(&self) -> impl Iterator<Item = &&'a str> {
        self.facts.keys()
    }

    /// The standing and confidence of one claim, as of `as_of_epoch`.
    ///
    /// `as_of_epoch` only drives decay, and only when
    /// [`ConfidencePolicy::decay_period`] is non-zero. It is a parameter rather
    /// than a clock read for the rule that holds everywhere in this crate: a
    /// value derived from the local time makes two nodes disagree about a log
    /// they both hold whole.
    pub fn state(
        &self,
        claim_id: &str,
        policy: &ConfidencePolicy,
        as_of_epoch: u64,
    ) -> Option<KnowledgeState> {
        let fact = self.facts.get(claim_id)?;
        let empty = Vec::new();
        let inbound = self.inbound.get(claim_id).unwrap_or(&empty);

        // -- which assertions are heard --------------------------------------
        let mut heard: Vec<(&'a str, Relation)> = Vec::new();
        let mut ungrounded: Vec<(&'a str, Relation)> = Vec::new();
        for (by, kind) in inbound {
            if self.is_grounded(by, kind, fact) {
                heard.push((by, *kind));
            } else {
                ungrounded.push((by, *kind));
            }
        }

        // -- collapse correlated sources -------------------------------------
        let classes = self.independence_classes(&heard, policy.independence_depth);

        let mut corroborating: BTreeSet<usize> = BTreeSet::new();
        let mut refuting: BTreeSet<usize> = BTreeSet::new();
        let mut disputing: BTreeSet<usize> = BTreeSet::new();
        let mut superseded_by: Vec<String> = Vec::new();
        let mut retracted_by: Option<String> = None;

        for (index, (by, kind)) in heard.iter().enumerate() {
            let class = classes[index];
            match kind.effect() {
                Effect::Corroborates => {
                    corroborating.insert(class);
                }
                Effect::Contests => {
                    if *kind == Relation::Refutes {
                        refuting.insert(class);
                    } else {
                        disputing.insert(class);
                    }
                }
                Effect::Supersedes => superseded_by.push((*by).to_string()),
                Effect::Withdraws => {
                    // First by claim id, so the answer does not depend on which
                    // of several retractions happened to be indexed first.
                    if retracted_by.is_none() {
                        retracted_by = Some((*by).to_string());
                    }
                }
            }
        }
        superseded_by.sort();

        let corroborations = corroborating.len() as u32;
        let refutations = refuting.len() as u32;
        let disputes = disputing.len() as u32;

        // -- standing ---------------------------------------------------------
        let standing = if fact.verdict == Some(Status::Reject) {
            Standing::Refuted
        } else if fact.verdict != Some(Status::Accept) {
            Standing::Unverified
        } else if retracted_by.is_some() {
            Standing::Withdrawn
        } else if !superseded_by.is_empty() {
            Standing::Superseded
        } else if refutations + disputes > 0 {
            Standing::Contested
        } else if corroborations > 0 {
            Standing::Corroborated
        } else {
            Standing::Accepted
        };

        // -- assertions, for the reader ---------------------------------------
        let mut assertions: Vec<Assertion> = heard
            .iter()
            .enumerate()
            .map(|(index, (by, kind))| Assertion {
                by: (*by).to_string(),
                kind: *kind,
                grounded: true,
                class: classes[index],
            })
            .chain(ungrounded.iter().map(|(by, kind)| Assertion {
                by: (*by).to_string(),
                kind: *kind,
                grounded: false,
                class: usize::MAX,
            }))
            .collect();
        assertions.sort_by(|a, b| a.by.cmp(&b.by).then(a.kind.cmp(&b.kind)));

        let confidence = confidence_of(
            standing,
            corroborations,
            refutations,
            disputes,
            fact.reproducible,
            fact.epoch,
            as_of_epoch,
            policy,
        );

        Some(KnowledgeState {
            claim_id: claim_id.to_string(),
            standing,
            verdict: fact.verdict,
            reproducible: fact.reproducible,
            corroborations,
            refutations,
            disputes,
            superseded_by,
            retracted_by,
            assertions,
            confidence,
        })
    }

    /// Whether an assertion is heard at all.
    ///
    /// `retracts` needs no verdict and needs a *cryptographically* equal
    /// submitter; everything else needs its author's claim to have been
    /// accepted. See the module docs for why acceptance is the price of being
    /// heard.
    ///
    /// # Why string equality is not enough for a retraction
    ///
    /// It was, in the first version of this module, and it was a hole. A
    /// submitter is either a 64-hex **public key**, which
    /// [`records::signed_submitter`] recognises and which the rules engine
    /// forces to carry a valid signature, or an **unauthenticated nickname**
    /// that stops nobody from using it —
    /// [`records::signed_submitter`]'s own docs say so. Comparing the strings
    /// therefore let anyone post a claim naming `alice` and retract alice's
    /// work: not the impersonation the rest of the crate already tolerates for
    /// nicknames (submitting *as* a name pays that name), but an integrity
    /// attack on somebody else's record, and one that reaches every reader
    /// including the agents reading `get_claim` over MCP.
    ///
    /// So a retraction grounds only when the name is a key. Two consequences,
    /// and both are the honest answer rather than a compromise:
    ///
    /// * **A nickname's work can never be retracted, including by whoever
    ///   submitted it.** An unauthenticated name has no owner, so there is
    ///   nobody who *is* its author. The alternative is letting a stranger
    ///   withdraw it, which is worse.
    /// * The signature is re-checked here rather than assumed from admission.
    ///   A graph can be built from any snapshot, and a predicate that decides
    ///   whether one party may silence another should not rest on the caller
    ///   having validated first. It costs one verification per retraction,
    ///   which is the rarest relation there is.
    ///
    /// [`records::signed_submitter`]: crate::records::signed_submitter
    fn is_grounded(&self, by: &str, kind: &Relation, target: &ClaimFacts<'a>) -> bool {
        let Some(author) = self.facts.get(by) else {
            return false;
        };
        if *kind == Relation::Retracts {
            return crate::records::signed_submitter(&target.claim.submitter).is_some()
                && author.claim.submitter == target.claim.submitter
                && author.claim.verify_signature().is_ok();
        }
        author.verdict == Some(Status::Accept)
    }

    /// Group asserting claims into independence classes by union-find.
    ///
    /// Returns one class index per entry of `heard`, positionally.
    ///
    /// Three merge rules, in increasing order of how much they assume:
    ///
    /// 1. **Same submitter.** One party, one voice. Unconditional.
    /// 2. **Same [`Claim::artifact_id`].** The identical artifact submitted
    ///    under two names is one piece of evidence wearing two hats — this is
    ///    "ten copies of the same press release are not ten sources", and the
    ///    crate already computes exactly this id to catch duplicate work.
    /// 3. **Shared citation ancestry**, only when `depth > 0`. See
    ///    [`ConfidencePolicy::independence_depth`] for why that is off by
    ///    default.
    ///
    /// None of this is sybil resistance and it must not be sold as such. A
    /// determined attacker makes distinct identities that submit distinct
    /// artifacts and cite nothing in common, and every rule here passes them as
    /// independent. What this defeats is the cheap version — one party
    /// resubmitting one result under several names — and what it buys against
    /// the expensive version is that the expensive version now costs a
    /// separately verified result per voice.
    fn independence_classes(&self, heard: &[(&'a str, Relation)], depth: u32) -> Vec<usize> {
        let n = heard.len();
        let mut parent: Vec<usize> = (0..n).collect();

        fn find(parent: &mut [usize], mut x: usize) -> usize {
            while parent[x] != x {
                parent[x] = parent[parent[x]];
                x = parent[x];
            }
            x
        }
        fn union(parent: &mut [usize], a: usize, b: usize) {
            let (ra, rb) = (find(parent, a), find(parent, b));
            if ra != rb {
                // Lower index wins, so class numbering is a function of the
                // sorted assertion list rather than of merge order.
                let (low, high) = if ra < rb { (ra, rb) } else { (rb, ra) };
                parent[high] = low;
            }
        }

        let mut ancestry: Vec<BTreeSet<&str>> = Vec::with_capacity(n);
        for (by, _) in heard {
            ancestry.push(if depth == 0 {
                BTreeSet::new()
            } else {
                self.ancestors(by, depth)
            });
        }

        for i in 0..n {
            for j in (i + 1)..n {
                let (Some(a), Some(b)) = (self.facts.get(heard[i].0), self.facts.get(heard[j].0))
                else {
                    continue;
                };
                let same_party = a.claim.submitter == b.claim.submitter;
                let same_work = a.claim.artifact_id() == b.claim.artifact_id();
                let shared_ancestry =
                    depth > 0 && ancestry[i].intersection(&ancestry[j]).next().is_some();
                if same_party || same_work || shared_ancestry {
                    union(&mut parent, i, j);
                }
            }
        }
        (0..n).map(|i| find(&mut parent, i)).collect()
    }

    /// Claims reachable by following `cites` up to `depth` hops.
    ///
    /// Breadth-first with a visited set rather than recursion. Citations point
    /// backwards only, so a cycle should be impossible — but "should" is not an
    /// argument when the graph is attacker-supplied, and this walk runs on
    /// every pair of assertions.
    fn ancestors(&self, from: &str, depth: u32) -> BTreeSet<&'a str> {
        let mut seen: BTreeSet<&'a str> = BTreeSet::new();
        let mut frontier: Vec<&'a str> = match self.facts.get_key_value(from) {
            Some((id, _)) => vec![id],
            None => return seen,
        };
        for _ in 0..depth {
            let mut next = Vec::new();
            for id in frontier {
                let Some(fact) = self.facts.get(id) else {
                    continue;
                };
                for cited in &fact.claim.cites {
                    if let Some((cited_id, _)) = self.facts.get_key_value(cited.as_str()) {
                        if seen.insert(cited_id) {
                            next.push(*cited_id);
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        seen
    }
}

/// The confidence arithmetic, split out so it can be read and tested without a
/// graph.
///
/// Order is load-bearing and is the reason this is one function rather than a
/// chain of methods: credit, then debit, then the multiplicative weights, then
/// decay. Applying the superseded weight *before* subtracting refutations would
/// make a superseded claim harder to argue down, which is backwards.
#[allow(clippy::too_many_arguments)]
fn confidence_of(
    standing: Standing,
    corroborations: u32,
    refutations: u32,
    disputes: u32,
    reproducible: Reproducible,
    epoch: u64,
    as_of_epoch: u64,
    policy: &ConfidencePolicy,
) -> u32 {
    // A withdrawn claim is zero regardless of how well it verified. Its author
    // is the one party whose say-so about their own work needs no corroboration
    // -- they are not asserting a fact about the world, they are declining to
    // stand behind their own submission.
    if standing == Standing::Withdrawn {
        return 0;
    }
    // Neither of these earns positive confidence, and neither is the other:
    // `Refuted` is a machine verdict, `Unverified` is an absence of one. They
    // agree on the number and on nothing else, which is why the caller gets
    // `standing` alongside it.
    if !standing.was_verified() {
        return 0;
    }

    let mut score = u64::from(policy.verified);
    score += u64::from(corroborations)
        .saturating_mul(u64::from(policy.per_corroboration))
        .min(u64::from(policy.max_corroboration));
    let debit = u64::from(refutations).saturating_mul(u64::from(policy.per_refutation))
        + u64::from(disputes).saturating_mul(u64::from(policy.per_dispute));
    score = score.saturating_sub(debit);

    if standing == Standing::Superseded {
        score = score * u64::from(policy.superseded_weight) / 1000;
    }
    if reproducible == Reproducible::NotHere {
        score = score * u64::from(policy.unreproducible_weight) / 1000;
    }

    if policy.decay_period > 0 && as_of_epoch > epoch {
        let steps = (as_of_epoch - epoch) / policy.decay_period;
        // Capped, and the cap costs nothing: at 950/1000 per step the score is
        // already zero long before 64 steps, and an uncapped loop would let a
        // far-future `as_of_epoch` spin for u64 iterations.
        for _ in 0..steps.min(64) {
            if score == 0 {
                break;
            }
            score = score * u64::from(policy.decay_retention) / 1000;
        }
    }

    score.min(1000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::Value;
    use crate::crypto::identity::Identity;

    fn claim(submitter: &str, n: i128) -> Claim {
        Claim::new(
            "sha256:obj",
            submitter,
            Value::object([("n", Value::Int(n))]),
            "nonce",
            "2026-08-13T00:00:00+00:00",
            vec![],
        )
        .expect("valid claim")
    }

    fn relating(submitter: &str, n: i128, kind: Relation, target: &str) -> Claim {
        claim(submitter, n)
            .relating(vec![crate::records::ClaimRelation::new(kind, target)])
            .expect("valid claim")
    }

    fn facts<'a>(id: &'a str, claim: &'a Claim, verdict: Option<Status>) -> ClaimFacts<'a> {
        ClaimFacts {
            id,
            claim,
            verdict,
            epoch: 0,
            reproducible: Reproducible::Yes,
        }
    }

    #[test]
    fn a_verified_claim_nobody_has_spoken_about_is_accepted() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let graph = KnowledgeGraph::new([facts(&id, &subject, Some(Status::Accept))]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.standing, Standing::Accepted);
        assert_eq!(state.confidence, 600);
    }

    #[test]
    fn the_verifiers_reject_outranks_every_assertion_to_the_contrary() {
        let subject = claim("alice", 1);
        let id = subject.id();
        // Ten separate, verified parties insisting it replicates.
        let boosters: Vec<Claim> = (0..10)
            .map(|i| relating(&format!("booster{i}"), 100 + i, Relation::Replicates, &id))
            .collect();
        let booster_ids: Vec<String> = boosters.iter().map(Claim::id).collect();
        let mut all = vec![facts(&id, &subject, Some(Status::Reject))];
        for (bid, booster) in booster_ids.iter().zip(&boosters) {
            all.push(facts(bid, booster, Some(Status::Accept)));
        }
        let graph = KnowledgeGraph::new(all);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        // This is the whole design in one assertion: no quantity of agreement
        // overturns a reproducible machine verdict.
        assert_eq!(state.standing, Standing::Refuted);
        assert_eq!(state.confidence, 0);
    }

    #[test]
    fn an_unverified_assertion_is_recorded_and_not_heard() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let attacker = relating("mallory", 2, Relation::Refutes, &id);
        let attacker_id = attacker.id();
        let graph = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            // No verdict: the attacker's own claim never passed anything.
            facts(&attacker_id, &attacker, None),
        ]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.standing, Standing::Accepted);
        assert_eq!(state.refutations, 0);
        // Visible, but marked as not counting.
        assert_eq!(state.assertions.len(), 1);
        assert!(!state.assertions[0].grounded);
    }

    #[test]
    fn unavailable_is_not_reject_here_either() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let graph = KnowledgeGraph::new([facts(&id, &subject, Some(Status::Unavailable))]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        // Not `Refuted`. A verifier that could not run has refuted nothing, and
        // collapsing the two here would reintroduce at the knowledge layer the
        // attack `verifiers::Status` exists to close.
        assert_eq!(state.standing, Standing::Unverified);
    }

    #[test]
    fn one_party_under_ten_names_corroborates_once() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let sock_puppets: Vec<Claim> = (0..10)
            .map(|_| relating("sybil", 7, Relation::Replicates, &id))
            .collect();
        let ids: Vec<String> = sock_puppets.iter().map(Claim::id).collect();
        let mut all = vec![facts(&id, &subject, Some(Status::Accept))];
        for (sid, sock) in ids.iter().zip(&sock_puppets) {
            all.push(facts(sid, sock, Some(Status::Accept)));
        }
        let graph = KnowledgeGraph::new(all);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.corroborations, 1);
    }

    #[test]
    fn the_same_artifact_under_different_names_is_one_source() {
        let subject = claim("alice", 1);
        let id = subject.id();
        // Different submitters, byte-identical artifacts: one press release,
        // two mastheads.
        let first = relating("outlet-a", 42, Relation::Replicates, &id);
        let second = relating("outlet-b", 42, Relation::Replicates, &id);
        let (first_id, second_id) = (first.id(), second.id());
        assert_eq!(first.artifact_id(), second.artifact_id());
        let graph = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            facts(&first_id, &first, Some(Status::Accept)),
            facts(&second_id, &second, Some(Status::Accept)),
        ]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.corroborations, 1);
    }

    #[test]
    fn genuinely_independent_corroboration_counts_separately_and_is_capped() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let others: Vec<Claim> = (0..6)
            .map(|i| relating(&format!("lab{i}"), 200 + i, Relation::Replicates, &id))
            .collect();
        let ids: Vec<String> = others.iter().map(Claim::id).collect();
        let mut all = vec![facts(&id, &subject, Some(Status::Accept))];
        for (oid, other) in ids.iter().zip(&others) {
            all.push(facts(oid, other, Some(Status::Accept)));
        }
        let graph = KnowledgeGraph::new(all);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.corroborations, 6);
        assert_eq!(state.standing, Standing::Corroborated);
        // 600 + min(6*120, 360) -- the cap is what stops a crowd voting a claim
        // to certainty.
        assert_eq!(state.confidence, 960);
    }

    #[test]
    fn only_the_submitter_can_retract_their_own_work() {
        let author = Identity::from_secret_bytes([7u8; 32]);
        let subject = claim("placeholder", 1).signed_with(&author);
        let id = subject.id();

        let stranger = Identity::from_secret_bytes([9u8; 32]);
        let impostor = relating("placeholder", 3, Relation::Retracts, &id).signed_with(&stranger);
        let impostor_id = impostor.id();
        let graph = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            // Accepted, so it is not the verdict doing the refusing here.
            facts(&impostor_id, &impostor, Some(Status::Accept)),
        ]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.standing, Standing::Accepted);
        assert_eq!(state.retracted_by, None);

        let withdrawal = relating("placeholder", 4, Relation::Retracts, &id).signed_with(&author);
        let withdrawal_id = withdrawal.id();
        let graph = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            // No verdict at all: withdrawing your own work needs no permission.
            facts(&withdrawal_id, &withdrawal, None),
        ]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.standing, Standing::Withdrawn);
        assert_eq!(state.confidence, 0);
    }

    #[test]
    fn a_nickname_cannot_be_impersonated_into_retracting_somebody_elses_work() {
        // The hole this closes. `submitter` is either a public key the rules
        // engine forces a signature for, or a nickname anybody may use. String
        // equality treated the second as proof of authorship, so a stranger
        // posting a claim named "alice" could withdraw alice's work -- a
        // different and worse thing than the nickname impersonation this crate
        // already tolerates, because it destroys somebody else's standing
        // rather than merely paying their name.
        let subject = claim("alice", 1);
        let id = subject.id();
        let impostor = relating("alice", 3, Relation::Retracts, &id);
        let impostor_id = impostor.id();
        let graph = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            facts(&impostor_id, &impostor, Some(Status::Accept)),
        ]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(
            state.standing,
            Standing::Accepted,
            "an unauthenticated name was allowed to retract"
        );
        assert_eq!(state.retracted_by, None);
        // Still reported, marked as not heard -- the reader sees the attempt.
        assert_eq!(state.assertions.len(), 1);
        assert!(!state.assertions[0].grounded);
    }

    #[test]
    fn a_retraction_carrying_a_broken_signature_is_not_heard() {
        // Belt to the braces above: the graph may be built from a snapshot
        // nobody validated, so the predicate that decides whether one party may
        // silence another re-checks the signature itself.
        let author = Identity::from_secret_bytes([11u8; 32]);
        let subject = claim("placeholder", 1).signed_with(&author);
        let id = subject.id();

        let mut forged = relating("placeholder", 5, Relation::Retracts, &id).signed_with(&author);
        // Same key-shaped name, signature no longer covering these bytes.
        forged.artifact = Value::object([("n", Value::Int(999))]);
        let forged_id = forged.id();

        let graph = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            facts(&forged_id, &forged, Some(Status::Accept)),
        ]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.standing, Standing::Accepted);
        assert_eq!(state.retracted_by, None);
    }

    #[test]
    fn superseded_is_not_refuted_and_keeps_most_of_its_confidence() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let better = relating("bob", 5, Relation::Supersedes, &id);
        let better_id = better.id();
        let graph = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            facts(&better_id, &better, Some(Status::Accept)),
        ]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.standing, Standing::Superseded);
        assert_eq!(state.superseded_by, vec![better_id]);
        assert!(state.standing.was_verified());
        assert_eq!(state.confidence, 420); // 600 * 700/1000
    }

    #[test]
    fn generalizing_a_result_corroborates_it_rather_than_retiring_it() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let wider = relating("bob", 6, Relation::Generalizes, &id);
        let wider_id = wider.id();
        let graph = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            facts(&wider_id, &wider, Some(Status::Accept)),
        ]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.standing, Standing::Corroborated);
    }

    #[test]
    fn a_refutation_weighs_more_than_a_failure_to_reproduce() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let policy = ConfidencePolicy::default();

        let doubter = relating("bob", 8, Relation::FailsToReplicate, &id);
        let doubter_id = doubter.id();
        let soft = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            facts(&doubter_id, &doubter, Some(Status::Accept)),
        ])
        .state(&id, &policy, 0)
        .expect("known claim");

        let refuter = relating("bob", 9, Relation::Refutes, &id);
        let refuter_id = refuter.id();
        let hard = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            facts(&refuter_id, &refuter, Some(Status::Accept)),
        ])
        .state(&id, &policy, 0)
        .expect("known claim");

        assert_eq!(soft.standing, Standing::Contested);
        assert_eq!(hard.standing, Standing::Contested);
        assert!(hard.confidence < soft.confidence);
        assert_eq!(soft.confidence, 450); // 600 - 150
        assert_eq!(hard.confidence, 300); // 600 - 300
    }

    #[test]
    fn evidence_that_cannot_be_re_derived_here_is_worth_less() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let mut fact = facts(&id, &subject, Some(Status::Accept));
        fact.reproducible = Reproducible::NotHere;
        let graph = KnowledgeGraph::new([fact]);
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        // Still accepted -- the verdict happened and is in the log. Just no
        // longer checkable here, which is a fact about availability and is
        // reported as one.
        assert_eq!(state.standing, Standing::Accepted);
        assert_eq!(state.reproducible, Reproducible::NotHere);
        assert_eq!(state.confidence, 240); // 600 * 400/1000
    }

    #[test]
    fn decay_is_driven_by_the_epoch_argument_and_is_off_by_default() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let graph = KnowledgeGraph::new([facts(&id, &subject, Some(Status::Accept))]);

        let fresh = graph
            .state(&id, &ConfidencePolicy::default(), 10_000)
            .expect("known claim");
        assert_eq!(fresh.confidence, 600, "default policy does not decay");

        let decaying = ConfidencePolicy {
            decay_period: 10,
            decay_retention: 500,
            ..ConfidencePolicy::default()
        };
        let aged = graph.state(&id, &decaying, 30).expect("known claim");
        assert_eq!(aged.confidence, 75); // 600 halved three times

        // Far-future readings terminate rather than spinning.
        let ancient = graph.state(&id, &decaying, u64::MAX).expect("known claim");
        assert_eq!(ancient.confidence, 0);
    }

    #[test]
    fn a_relation_pointing_at_a_claim_outside_the_snapshot_is_ignored() {
        let subject = relating("alice", 1, Relation::Refutes, "sha256:not-in-this-log");
        let id = subject.id();
        let graph = KnowledgeGraph::new([facts(&id, &subject, Some(Status::Accept))]);
        assert!(graph
            .state("sha256:not-in-this-log", &ConfidencePolicy::default(), 0)
            .is_none());
        let state = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(state.standing, Standing::Accepted);
    }

    #[test]
    fn shared_ancestry_merges_sources_only_when_the_policy_asks_for_it() {
        let root = claim("root", 1);
        let root_id = root.id();

        // Two different parties, both building on `root`, both replicating the
        // subject.
        let subject = claim("alice", 2);
        let id = subject.id();
        let build = |who: &str, n: i128| -> Claim {
            Claim::new(
                "sha256:obj",
                who,
                Value::object([("n", Value::Int(n))]),
                "nonce",
                "2026-08-13T00:00:00+00:00",
                vec![root_id.clone()],
            )
            .expect("valid claim")
            .relating(vec![crate::records::ClaimRelation::new(
                Relation::Replicates,
                &id,
            )])
            .expect("valid claim")
        };
        let (first, second) = (build("lab-a", 10), build("lab-b", 11));
        let (first_id, second_id) = (first.id(), second.id());
        let snapshot = [
            facts(&root_id, &root, Some(Status::Accept)),
            facts(&id, &subject, Some(Status::Accept)),
            facts(&first_id, &first, Some(Status::Accept)),
            facts(&second_id, &second, Some(Status::Accept)),
        ];
        let graph = KnowledgeGraph::new(snapshot);

        let independent = graph
            .state(&id, &ConfidencePolicy::default(), 0)
            .expect("known claim");
        assert_eq!(independent.corroborations, 2, "depth 0 counts both");

        let strict = ConfidencePolicy {
            independence_depth: 1,
            ..ConfidencePolicy::default()
        };
        let merged = graph.state(&id, &strict, 0).expect("known claim");
        assert_eq!(merged.corroborations, 1, "a shared parent collapses them");
    }

    #[test]
    fn class_numbering_does_not_depend_on_insertion_order() {
        let subject = claim("alice", 1);
        let id = subject.id();
        let one = relating("lab-a", 20, Relation::Replicates, &id);
        let two = relating("lab-b", 21, Relation::Replicates, &id);
        let (one_id, two_id) = (one.id(), two.id());

        let forward = KnowledgeGraph::new([
            facts(&id, &subject, Some(Status::Accept)),
            facts(&one_id, &one, Some(Status::Accept)),
            facts(&two_id, &two, Some(Status::Accept)),
        ])
        .state(&id, &ConfidencePolicy::default(), 0)
        .expect("known claim");
        let backward = KnowledgeGraph::new([
            facts(&two_id, &two, Some(Status::Accept)),
            facts(&one_id, &one, Some(Status::Accept)),
            facts(&id, &subject, Some(Status::Accept)),
        ])
        .state(&id, &ConfidencePolicy::default(), 0)
        .expect("known claim");
        assert_eq!(forward, backward);
    }

    #[test]
    fn every_relation_kind_has_an_effect_and_a_round_trip() {
        for kind in Relation::ALL {
            assert_eq!(Relation::from_wire(kind.as_str()), Some(kind));
            // Exhaustive by construction: `effect` has no catch-all arm, so a
            // tenth kind will not compile until it is priced here.
            let _ = kind.effect();
        }
        assert_eq!(Relation::from_wire("endorses"), None);
    }
}
