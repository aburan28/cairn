//! The algorithm registry: which cryptographic suites are live, which are on
//! their way out, and what that means for material already written.
//!
//! # Why a registry rather than a constant
//!
//! Every primitive here will eventually be weak, obsolete, or merely
//! unfashionable, and the design has to assume that rather than hope. The
//! mechanism for *adding* a suite already exists and is good: [`Bundle`]
//! combines legs additively, so a new one is never a negotiation and never a
//! downgrade. What was missing is the other
//! half — **governance**. Nothing could say "McEliece is on its way out, keep
//! verifying it, stop sealing new work to it alone", so that decision lived as
//! hardcoded predicates that had to be edited, released and deployed in step.
//!
//! This module is that statement, versioned, in one place.
//!
//! # The rule that makes agility safe: policy governs *writes*, never *reads*
//!
//! A registry is a way to break a network if it is consulted at the wrong
//! moment. Deprecating a suite must not make yesterday's records undecodable —
//! that is not a migration, it is a retroactive fork, and every node that
//! upgrades leaves the network.
//!
//! So:
//!
//! - **Decoding never consults a policy.** [`Bundle::from_value`] and every
//!   other decoder accept what they always accepted. A record that was
//!   admissible stays admissible forever.
//! - **Producing new material does.** Sealing, publishing an identity, choosing
//!   what to encapsulate to — those ask the policy, because those are choices
//!   still to be made.
//!
//! [`Status::Withdrawn`] is the single exception and it is deliberately
//! uncomfortable to use: it refuses a suite *even historically*, which does
//! invalidate history and is only correct when the alternative is honouring
//! signatures an attacker can forge. It exists because the emergency it answers
//! is real, and it is named so that reaching for it is a visible act rather
//! than a quiet edit.
//!
//! # What this governs, and what it cannot
//!
//! It governs **KEM suites**, because that is the layer whose mechanism is
//! already agile. The other two layers of this crate are not, and saying so
//! here is more useful than implying otherwise:
//!
//! | layer | self-describing? | swappable? | what a swap would cost |
//! |---|---|---|---|
//! | KEM suites | yes — [`Suite`] is tagged on the wire | **yes**, additively | nothing; a new leg moves no id |
//! | record signatures | **no** — the algorithm is implied by the submitter being 64 hex, which *is* an ed25519 key | no | every submitter string changes, so every signed record's id moves |
//! | content addressing | in form — ids are `sha256:<hex>` | no | every id in the network moves at once |
//!
//! The bottom row is the real lock-in, and the answer is not to swap it. It is
//! the migration checkpoint of `docs/knowledge.md`'s ancestry: ids stay what
//! they are forever, and a new suite is *appended* as an additional commitment
//! over the same objects. Replacement moves ids; attestation does not. That is
//! the same append-only discipline the rest of this repository applies to
//! knowledge, applied to the cryptography that carries it.
//!
//! See `docs/agility.md`.

use std::collections::BTreeSet;
use std::fmt;

use super::kem::{Bundle, Family, Suite};

/// Where a suite stands in the current policy.
///
/// Ordered from most to least permitted, and the order is meaningful: a
/// caller may ask whether a status is "at least" usable for new material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    /// Must be present in every bundle. A *structural* requirement, not a
    /// security one — today it holds only because
    /// [`Bundle::id`](super::kem::Bundle::id) is the hash of the McEliece leg,
    /// so a bundle without one has no peer id. When identity stops naming a
    /// suite, this status should stop being used.
    Required,
    /// Usable for new material, and verified on old.
    Accepted,
    /// **Refused for new material, still verified on old.** The ordinary way a
    /// suite leaves: nothing already written stops working, and nothing new is
    /// written to it.
    Deprecated,
    /// Refused everywhere, historical material included.
    ///
    /// This *invalidates history* and is the emergency lever, not the migration
    /// path — correct only when honouring old material is worse than losing it,
    /// which in practice means signatures an attacker can now forge. Reaching
    /// for this where [`Status::Deprecated`] would do is how a registry breaks
    /// a network.
    Withdrawn,
}

impl Status {
    /// May new material be produced under this suite?
    pub const fn usable_now(self) -> bool {
        matches!(self, Status::Required | Status::Accepted)
    }

    /// May material already written under this suite still be verified?
    ///
    /// True for everything but [`Status::Withdrawn`], which is the whole
    /// difference between deprecating a suite and revoking it.
    pub const fn verifiable(self) -> bool {
        !matches!(self, Status::Withdrawn)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Required => "required",
            Status::Accepted => "accepted",
            Status::Deprecated => "deprecated",
            Status::Withdrawn => "withdrawn",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a bundle does not satisfy a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A suite the policy no longer accepts for new material.
    NotUsable { suite: Suite, status: Status },
    /// A suite the policy requires is absent.
    Missing { suite: Suite },
    /// The bundle spans too few hardness families.
    TooFewFamilies { got: usize, want: usize },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::NotUsable { suite, status } => write!(
                f,
                "suite {suite} is {status} under this policy and may not be used \
                 for new material; material already written under it is \
                 unaffected"
            ),
            PolicyError::Missing { suite } => {
                write!(f, "this policy requires a {suite} leg and none is present")
            }
            PolicyError::TooFewFamilies { got, want } => write!(
                f,
                "this bundle spans {got} hardness famil(y/ies) and the policy \
                 requires {want}: one cryptanalytic result would open everything \
                 sealed to it"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// One version of the network's algorithm rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Which version of the rules this is. Monotonic, and the number a record
    /// would name if it wanted to say which rules it was written under.
    pub version: u32,
    mceliece: Status,
    ml_kem_768: Status,
    hqc_128: Status,
    /// Distinct [`Family`] count a bundle must span to carry new material.
    ///
    /// The knob that actually responds to cryptanalysis. Raising it from 1 to 2
    /// is the whole of "stop trusting any single assumption", and it can be
    /// raised without touching a decoder.
    pub min_families: usize,
}

/// Every policy version, oldest first.
///
/// An ordered list rather than a map, because "what were the rules at version
/// N" must have exactly one answer and versions must not be reorderable.
///
/// # Why version 0 is here at all
///
/// It is the rules as they stood before this module existed: McEliece required,
/// the others optional, no family minimum. Keeping it means the registry can
/// *describe* the past rather than pretend the network began with the current
/// policy — which is the same reason the ledger keeps superseded claims.
pub const POLICIES: &[Policy] = &[
    Policy {
        version: 0,
        mceliece: Status::Required,
        ml_kem_768: Status::Accepted,
        hqc_128: Status::Accepted,
        min_families: 1,
    },
    Policy {
        version: 1,
        // Still required, and still for the structural reason: peer ids are the
        // hash of this leg. Not an assertion that Goppa codes are healthy --
        // `min_families` below is where that judgement lives.
        mceliece: Status::Required,
        ml_kem_768: Status::Accepted,
        hqc_128: Status::Accepted,
        // Raised in response to the 2026 cryptanalysis of binary Goppa codes:
        // the syzygy distinguisher and the subexponential and quasipolynomial
        // key-recovery results after it. None is a practical break of
        // `mceliece348864`, and this is not a claim that one is. It is the
        // cheap half of not needing to find out -- see `Family`.
        min_families: 2,
    },
];

impl Policy {
    /// The rules new material must satisfy.
    pub fn current() -> Policy {
        *POLICIES.last().expect("the registry is never empty")
    }

    /// The rules as they stood at `version`, for reading historical material.
    ///
    /// `None` for a version this build has never heard of, which is a real
    /// case: a node reading a log written by a newer build must be able to tell
    /// "I do not know these rules" from "these rules refuse it". Guessing
    /// between the two is how one implementation admits what another refuses.
    pub fn at(version: u32) -> Option<Policy> {
        POLICIES.iter().copied().find(|p| p.version == version)
    }

    /// This policy's status for one suite.
    pub const fn status(&self, suite: Suite) -> Status {
        match suite {
            Suite::McEliece => self.mceliece,
            Suite::MlKem768 => self.ml_kem_768,
            Suite::Hqc128 => self.hqc_128,
        }
    }

    /// May new material be produced under `suite`?
    pub const fn allows(&self, suite: Suite) -> bool {
        self.status(suite).usable_now()
    }

    /// May material already written under `suite` still be verified?
    pub const fn verifies(&self, suite: Suite) -> bool {
        self.status(suite).verifiable()
    }

    /// Is this bundle fit to carry **new** material under these rules?
    ///
    /// Never call this on the decode path. A bundle that fails here is not
    /// malformed and not refused — it is a bundle whose owner should publish
    /// another leg, and everything already sealed to it stays valid.
    pub fn admits(&self, bundle: &Bundle) -> Result<(), PolicyError> {
        for suite in bundle.suites() {
            if !self.allows(suite) {
                return Err(PolicyError::NotUsable {
                    suite,
                    status: self.status(suite),
                });
            }
        }
        for suite in [Suite::McEliece, Suite::MlKem768, Suite::Hqc128] {
            if self.status(suite) == Status::Required && bundle.key_for(suite).is_none() {
                return Err(PolicyError::Missing { suite });
            }
        }
        let families: BTreeSet<Family> = bundle.families();
        if families.len() < self.min_families {
            return Err(PolicyError::TooFewFamilies {
                got: families.len(),
                want: self.min_families,
            });
        }
        Ok(())
    }

    /// The suites a node should publish to satisfy these rules.
    ///
    /// What `generate` should reach for, so that "what does a fresh identity
    /// carry" has one answer and it is this file's.
    pub fn suites_to_publish(&self) -> Vec<Suite> {
        [Suite::McEliece, Suite::MlKem768, Suite::Hqc128]
            .into_iter()
            .filter(|suite| self.allows(*suite))
            .collect()
    }
}

impl Default for Policy {
    fn default() -> Policy {
        Policy::current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::envelope::CommitteeKey;
    use rand_core::OsRng;

    #[test]
    fn versions_are_ordered_unique_and_reachable() {
        let mut seen = BTreeSet::new();
        let mut previous: Option<u32> = None;
        for policy in POLICIES {
            assert!(seen.insert(policy.version), "duplicate policy version");
            if let Some(prev) = previous {
                assert!(policy.version > prev, "policy versions must increase");
            }
            previous = Some(policy.version);
            assert_eq!(Policy::at(policy.version), Some(*policy));
        }
        assert_eq!(Policy::current().version, previous.expect("non-empty"));
    }

    #[test]
    fn an_unknown_version_is_none_rather_than_a_guess() {
        // A node reading a log written by a newer build must be able to tell
        // "I do not know these rules" from "these rules refuse it".
        assert_eq!(Policy::at(9_999), None);
    }

    #[test]
    fn deprecating_a_suite_refuses_new_material_and_keeps_verifying_old() {
        let live = Policy::current();
        assert!(live.allows(Suite::Hqc128));
        assert!(live.verifies(Suite::Hqc128));

        let retiring = Policy {
            hqc_128: Status::Deprecated,
            ..live
        };
        assert!(!retiring.allows(Suite::Hqc128), "no new material");
        assert!(
            retiring.verifies(Suite::Hqc128),
            "history must keep verifying -- deprecation is not revocation"
        );

        // Withdrawal is the one that does invalidate history, which is why it
        // is a separate status and not a stronger flavour of the same one.
        let revoked = Policy {
            hqc_128: Status::Withdrawn,
            ..live
        };
        assert!(!revoked.allows(Suite::Hqc128));
        assert!(!revoked.verifies(Suite::Hqc128));
    }

    #[test]
    fn the_family_minimum_is_what_responds_to_cryptanalysis() {
        let goppa_only = CommitteeKey::generate_over(&[Suite::McEliece], &mut OsRng).public();
        let hedged = CommitteeKey::generate(&mut OsRng).public();

        // Version 0: the rules before this module existed. A McEliece-only
        // bundle was fine, and the registry says so rather than pretending the
        // network always required two families.
        let v0 = Policy::at(0).expect("version 0");
        assert!(v0.admits(&goppa_only).is_ok());

        let v1 = Policy::current();
        assert_eq!(
            v1.admits(&goppa_only),
            Err(PolicyError::TooFewFamilies { got: 1, want: 2 })
        );
        assert!(v1.admits(&hedged).is_ok());
    }

    #[test]
    fn a_bundle_carrying_a_deprecated_suite_is_refused_for_new_material() {
        let hedged = CommitteeKey::generate(&mut OsRng).public();
        let retiring = Policy {
            hqc_128: Status::Deprecated,
            ..Policy::current()
        };
        assert_eq!(
            retiring.admits(&hedged),
            Err(PolicyError::NotUsable {
                suite: Suite::Hqc128,
                status: Status::Deprecated,
            })
        );
        // And the message says the part that matters: old material is fine.
        let message = retiring.admits(&hedged).unwrap_err().to_string();
        assert!(message.contains("already written"), "{message}");
    }

    #[test]
    fn what_to_publish_follows_the_policy_rather_than_a_constant() {
        assert_eq!(
            Policy::current().suites_to_publish(),
            crate::crypto::kem::SUITES.to_vec()
        );

        let retiring = Policy {
            hqc_128: Status::Deprecated,
            ..Policy::current()
        };
        assert_eq!(
            retiring.suites_to_publish(),
            vec![Suite::McEliece, Suite::MlKem768],
            "a deprecated suite is not published, and needs no code change to stop"
        );
    }

    #[test]
    fn a_required_suite_that_is_absent_is_named() {
        let ml_only = Bundle::new([CommitteeKey::generate(&mut OsRng)
            .public()
            .key_for(Suite::MlKem768)
            .expect("ml-kem leg")
            .clone()]);
        // `Bundle::new` enforces the mandatory leg structurally, so this cannot
        // even be built -- the structural rule and the policy rule agree today
        // and the policy one is what will outlive it.
        assert!(ml_only.is_err());
    }
}
