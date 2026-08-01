//! Population anti-entropy: gossiping candidates, as a separate message family.
//!
//! # Why this is not the record protocol
//!
//! [`super::sync`] reconciles the *log's* inputs — objectives, commitments,
//! claims. Those are consensus-relevant: a claim that reaches you changes what
//! settles. Candidates are not. A [`Candidate`] is a scored artifact somebody
//! thought was worth mutating; nothing is owed for it, nothing settles because
//! of it, and losing one costs a little search progress and nothing else.
//!
//! Keeping the two families apart is a security boundary, not tidiness. The
//! record path refuses `verdict`, `settlement` and `frontier` outright, because
//! importing a peer's conclusion is exactly the trust this project removes. If
//! candidates travelled in record buckets, a peer could offer a `candidate`
//! that decoded as something else, or push population volume against the
//! record ceilings. They travel under their own AEAD context string
//! ([`CONTEXT`]), so a population frame cannot even be opened as a record
//! frame, and they carry their own limits.
//!
//! # Scores are re-derived, never imported
//!
//! A gossiped score is an assertion. An inflated one would crowd genuine
//! candidates out of a bounded population, which is a cheap denial of service
//! against the search itself. [`ingest_candidates`] therefore runs the local
//! scorer over every arrival and keeps only what reproduces — the same rule as
//! [`crate::gossip::ingest`], which it delegates to.
//!
//! # Why there is no bucket scheme here
//!
//! A population holds at most `islands × capacity` candidates by construction
//! (256 with the defaults), so the whole id list fits in one message and the
//! XOR-bucket summary the record protocol needs would be pure overhead. The
//! digest is still sent first: two peers already in sync compare one hash and
//! send nothing else.

use std::collections::BTreeSet;
use std::fmt;

use crate::canonical::Value;
use crate::gossip::{Candidate, GossipError, Population};
use crate::obj;

/// AEAD context for population frames.
///
/// Distinct from the record protocol's, so a frame sealed for one family fails
/// to open under the other. That is the mechanical half of "never mixed into
/// record buckets": a confusion attack does not get as far as the decoder.
pub const CONTEXT: &[u8] = b"proofwork/p2p/pop/v1";

/// Why a population message was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopError {
    /// A message did not decode.
    Malformed { detail: String },
    /// A peer offered more than the configured ceiling in one message.
    TooMany { limit: usize, got: usize },
    /// A candidate body was not decodable as one.
    BadCandidate { detail: String },
}

impl fmt::Display for PopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PopError::Malformed { detail } => write!(f, "malformed population message: {detail}"),
            PopError::TooMany { limit, got } => {
                write!(
                    f,
                    "population message carries {got} items, limit is {limit}"
                )
            }
            PopError::BadCandidate { detail } => write!(f, "not a candidate: {detail}"),
        }
    }
}

impl std::error::Error for PopError {}

impl From<GossipError> for PopError {
    fn from(error: GossipError) -> PopError {
        PopError::BadCandidate {
            detail: error.to_string(),
        }
    }
}

/// Ceilings, checked *before* allocating.
///
/// The defaults are generous against an honest peer running the default bounds
/// (`DEFAULT_ISLANDS * DEFAULT_CAPACITY` is 256) and tight against a peer that
/// has decided to send a million of something.
#[derive(Debug, Clone, Copy)]
pub struct PopLimits {
    pub max_ids_per_message: usize,
    pub max_candidates_per_message: usize,
}

impl Default for PopLimits {
    fn default() -> PopLimits {
        PopLimits {
            max_ids_per_message: 4_096,
            max_candidates_per_message: 512,
        }
    }
}

/// A population protocol message.
///
/// Deliberately a separate type from [`super::sync::Message`] rather than three
/// more variants on it. A shared enum would mean one decoder, one ceiling and
/// one `match` covering both families, and the first person to add a variant
/// would have to notice that half of them must never reach the record path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopMessage {
    /// "Here is my population digest and every candidate id in it."
    ///
    /// The digest is the early-out: equal digests mean equal id sets, and the
    /// exchange stops. The ids travel with it rather than in a second round
    /// because the set is bounded by construction — see the module docs.
    Digest { digest: String, ids: Vec<String> },
    /// "Send me these." Ids the sender does not hold.
    Want { ids: Vec<String> },
    /// The bodies.
    Records { candidates: Vec<Candidate> },
    /// Nothing further.
    Done,
}

impl PopMessage {
    pub fn to_value(&self) -> Value {
        let strings = |ids: &Vec<String>| {
            Value::Array(ids.iter().map(|i| Value::string(i.clone())).collect())
        };
        match self {
            PopMessage::Digest { digest, ids } => obj! {
                "t" => Value::string("pop_digest"),
                "digest" => Value::string(digest.clone()),
                "ids" => strings(ids),
            },
            PopMessage::Want { ids } => obj! {
                "t" => Value::string("pop_want"),
                "ids" => strings(ids),
            },
            PopMessage::Records { candidates } => obj! {
                "t" => Value::string("pop_records"),
                "candidates" => Value::Array(candidates.iter().map(Candidate::to_value).collect()),
            },
            PopMessage::Done => obj! { "t" => Value::string("pop_done") },
        }
    }

    /// Decode, enforcing `limits` **before** building any vector.
    ///
    /// The ceiling is applied to the declared array length rather than after
    /// collecting, because "refuse it after allocating it" is not a defence
    /// against a peer whose whole plan is to make you allocate.
    pub fn from_value(value: &Value, limits: PopLimits) -> Result<PopMessage, PopError> {
        let bad = |detail: String| PopError::Malformed { detail };
        let ids = |field: &str, limit: usize| -> Result<Vec<String>, PopError> {
            let items = value
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| bad(format!("{field} is not an array")))?;
            if items.len() > limit {
                return Err(PopError::TooMany {
                    limit,
                    got: items.len(),
                });
            }
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| bad(format!("{field} contains a non-string")))
                })
                .collect()
        };
        match value.get("t").and_then(Value::as_str) {
            Some("pop_digest") => Ok(PopMessage::Digest {
                digest: value
                    .get("digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("pop_digest has no digest".into()))?
                    .to_string(),
                ids: ids("ids", limits.max_ids_per_message)?,
            }),
            Some("pop_want") => Ok(PopMessage::Want {
                ids: ids("ids", limits.max_ids_per_message)?,
            }),
            Some("pop_records") => {
                let items = value
                    .get("candidates")
                    .and_then(Value::as_array)
                    .ok_or_else(|| bad("candidates is not an array".into()))?;
                if items.len() > limits.max_candidates_per_message {
                    return Err(PopError::TooMany {
                        limit: limits.max_candidates_per_message,
                        got: items.len(),
                    });
                }
                let mut candidates = Vec::with_capacity(items.len());
                for item in items {
                    candidates.push(Candidate::from_value(item)?);
                }
                Ok(PopMessage::Records { candidates })
            }
            Some("pop_done") => Ok(PopMessage::Done),
            other => Err(bad(format!("unknown population message type {other:?}"))),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_value().canonical_string().into_bytes()
    }

    pub fn decode(bytes: &[u8], limits: PopLimits) -> Result<PopMessage, PopError> {
        let text = std::str::from_utf8(bytes).map_err(|_| PopError::Malformed {
            detail: "not UTF-8".into(),
        })?;
        let value = Value::from_json(text).map_err(|e| PopError::Malformed {
            detail: e.to_string(),
        })?;
        PopMessage::from_value(&value, limits)
    }
}

/// The digest message for a population.
pub fn digest_message(population: &Population) -> PopMessage {
    let mut ids: Vec<String> = population.iter().map(Candidate::id).collect();
    ids.sort();
    PopMessage::Digest {
        digest: population.digest(),
        ids,
    }
}

/// Which of a peer's ids this population lacks.
pub fn missing_from(population: &Population, offered: &[String]) -> Vec<String> {
    offered
        .iter()
        .filter(|id| population.get(id).is_none())
        .cloned()
        .collect()
}

/// Answer a `Want`, skipping ids not held.
///
/// A peer asking for a candidate that has since been pruned is out of date, not
/// hostile: the population is bounded, so entries legitimately disappear
/// between one round and the next.
pub fn serve(population: &Population, ids: &[String], limits: PopLimits) -> Vec<Candidate> {
    ids.iter()
        .filter_map(|id| population.get(id).cloned())
        .take(limits.max_candidates_per_message)
        .collect()
}

/// What an ingest actually did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PopReport {
    /// Candidates whose claimed score reproduced locally, and were kept.
    pub accepted: usize,
    /// Candidates whose score did not reproduce, or that nobody asked for.
    pub refused: usize,
    /// Candidates already held.
    pub duplicates: usize,
}

/// Take candidates from a peer, re-scoring every one.
///
/// `wanted` is the id set this side actually asked for. Anything outside it is
/// dropped without being scored: scoring is the expensive operation, and a peer
/// that can make you run it by volunteering candidates has a denial of service
/// whether or not any of them are accepted.
///
/// `rescore` returns `None` to mean *I could not score this*, which is a
/// refusal. A scorer that fell over says nothing about the candidate, and
/// recording the peer's number because the local one was unavailable is exactly
/// the import this module exists to prevent — the same rule as `Unavailable` is
/// never `Reject` on the verification side.
pub fn ingest_candidates<F>(
    population: &mut Population,
    wanted: &BTreeSet<String>,
    candidates: Vec<Candidate>,
    mut rescore: F,
) -> PopReport
where
    F: FnMut(&Candidate) -> Option<i64>,
{
    let mut report = PopReport::default();
    for candidate in candidates {
        let id = candidate.id();
        if !wanted.contains(&id) {
            report.refused += 1;
            continue;
        }
        if population.get(&id).is_some() {
            report.duplicates += 1;
            continue;
        }
        let artifact_score = rescore(&candidate);
        if crate::gossip::ingest(population, candidate, |_| artifact_score) {
            report.accepted += 1;
        } else {
            report.refused += 1;
        }
    }
    report
}

/// Run a full population reconciliation between two local populations.
///
/// The reference driver, and what the tests check convergence against. It also
/// documents the message order a networked implementation must follow; see
/// [`super::session::reconcile_population`].
pub fn reconcile<F>(
    a: &mut Population,
    b: &mut Population,
    limits: PopLimits,
    mut rescore: F,
) -> (PopReport, PopReport)
where
    F: FnMut(&Candidate) -> Option<i64>,
{
    if a.digest() == b.digest() {
        return (PopReport::default(), PopReport::default());
    }
    let (offer_a, offer_b) = (digest_message(a), digest_message(b));
    let ids_of = |message: &PopMessage| match message {
        PopMessage::Digest { ids, .. } => ids.clone(),
        _ => Vec::new(),
    };
    let want_a = missing_from(a, &ids_of(&offer_b));
    let want_b = missing_from(b, &ids_of(&offer_a));
    let to_a = serve(b, &want_a, limits);
    let to_b = serve(a, &want_b, limits);

    let set_a: BTreeSet<String> = want_a.into_iter().collect();
    let set_b: BTreeSet<String> = want_b.into_iter().collect();
    let report_a = ingest_candidates(a, &set_a, to_a, &mut rescore);
    let report_b = ingest_candidates(b, &set_b, to_b, &mut rescore);
    (report_a, report_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(n: i128, score: i64) -> Candidate {
        Candidate::new("obj", Value::object([("n", Value::Int(n))]), score, "who")
    }

    /// The honest scorer for the fixtures: the score *is* `n`.
    fn honest(candidate: &Candidate) -> Option<i64> {
        candidate
            .artifact
            .get("n")
            .and_then(Value::as_i128)
            .and_then(|n| i64::try_from(n).ok())
    }

    fn population(range: std::ops::Range<i128>) -> Population {
        let mut p = Population::default();
        for n in range {
            p.add(candidate(n, n as i64));
        }
        p
    }

    // -- the boundary between the two message families ----------------------

    #[test]
    fn population_frames_use_a_different_aead_context_than_records() {
        // The mechanical half of "never mixed into record buckets": a frame
        // sealed for one family does not open under the other, so a confusion
        // attack fails before any decoder sees the bytes.
        use crate::p2p::handshake::PeerIdentity;
        let responder = PeerIdentity::generate();
        let initiator = [3u8; 32];
        let (ct, mut client) = responder.to_public().initiate(initiator);
        let mut server = responder.accept(initiator, &ct).unwrap();

        let message = PopMessage::Want {
            ids: vec![candidate(1, 1).id()],
        };
        let (n, frame) = client.seal(&message.encode(), CONTEXT).unwrap();
        assert!(
            server
                .open(n, &frame, crate::p2p::session::RECORD_CONTEXT)
                .is_err(),
            "a population frame opened as a record frame"
        );
        let plain = server.open(n, &frame, CONTEXT).unwrap();
        assert_eq!(
            PopMessage::decode(&plain, PopLimits::default()).unwrap(),
            message
        );
    }

    #[test]
    fn a_candidate_is_not_a_record_and_cannot_become_one() {
        // The other half. Even if a population body reached the record path,
        // `candidate` is not an exchangeable record kind.
        let record = crate::p2p::sync::Record::new("candidate", candidate(1, 1).to_value());
        assert!(matches!(
            crate::p2p::sync::Peer::new().insert(record),
            Err(crate::p2p::sync::SyncError::NotExchangeable { .. })
        ));
    }

    // -- convergence --------------------------------------------------------

    #[test]
    fn disjoint_populations_converge() {
        let mut a = population(0..10);
        let mut b = population(10..20);
        let (ra, rb) = reconcile(&mut a, &mut b, PopLimits::default(), honest);
        assert_eq!(ra.refused, 0);
        assert_eq!(rb.refused, 0);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a, b);
    }

    #[test]
    fn already_synced_populations_send_nothing() {
        let mut a = population(0..10);
        let mut b = population(0..10);
        let (ra, rb) = reconcile(&mut a, &mut b, PopLimits::default(), |_| {
            panic!("a synced pair must not score anything")
        });
        assert_eq!(ra, PopReport::default());
        assert_eq!(rb, PopReport::default());
    }

    #[test]
    fn reconciliation_is_idempotent() {
        let mut a = population(0..5);
        let mut b = population(5..10);
        reconcile(&mut a, &mut b, PopLimits::default(), honest);
        let before = a.digest();
        reconcile(&mut a, &mut b, PopLimits::default(), honest);
        assert_eq!(a.digest(), before);
    }

    // -- the peer's score is never taken on trust ---------------------------

    #[test]
    fn an_inflated_score_is_dropped_rather_than_believed() {
        // The attack this defends: a bounded population plus a peer willing to
        // claim a huge score is a denial of service against the search, because
        // the liar's entries evict everyone else's.
        let mut theirs = Population::default();
        theirs.add(candidate(1, 1_000_000));
        let mut mine = population(0..1);
        let (report, _) = reconcile(&mut mine, &mut theirs, PopLimits::default(), honest);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.refused, 1);
        assert!(mine.get(&candidate(1, 1_000_000).id()).is_none());
    }

    #[test]
    fn a_scorer_that_cannot_answer_is_a_refusal_not_an_acceptance() {
        // `Unavailable` is never `Accept`, here as everywhere else: a scorer
        // that fell over says nothing about the candidate.
        let mut mine = Population::default();
        let wanted: BTreeSet<String> = [candidate(1, 1).id()].into_iter().collect();
        let report = ingest_candidates(&mut mine, &wanted, vec![candidate(1, 1)], |_| None);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.refused, 1);
        assert!(mine.is_empty());
    }

    #[test]
    fn unsolicited_candidates_are_dropped_before_they_are_scored() {
        // Scoring is the expensive half. A peer that can make you run it by
        // volunteering candidates has a denial of service whether or not any of
        // them are ultimately kept.
        let mut mine = Population::default();
        let mut scored = 0;
        let report = ingest_candidates(&mut mine, &BTreeSet::new(), vec![candidate(1, 1)], |_| {
            scored += 1;
            Some(1)
        });
        assert_eq!(report.refused, 1);
        assert_eq!(scored, 0, "an unsolicited candidate was scored");
        assert!(mine.is_empty());
    }

    // -- ceilings -----------------------------------------------------------

    #[test]
    fn oversized_messages_are_refused_before_allocation() {
        let limits = PopLimits {
            max_ids_per_message: 4,
            max_candidates_per_message: 2,
        };
        let ids = PopMessage::Want {
            ids: (0..10).map(|n| candidate(n, n as i64).id()).collect(),
        };
        assert!(matches!(
            PopMessage::decode(&ids.encode(), limits),
            Err(PopError::TooMany { limit: 4, got: 10 })
        ));

        let bodies = PopMessage::Records {
            candidates: (0..10).map(|n| candidate(n, n as i64)).collect(),
        };
        assert!(matches!(
            PopMessage::decode(&bodies.encode(), limits),
            Err(PopError::TooMany { limit: 2, got: 10 })
        ));

        let digest = PopMessage::Digest {
            digest: "sha256:x".into(),
            ids: (0..10).map(|n| candidate(n, n as i64).id()).collect(),
        };
        assert!(matches!(
            PopMessage::decode(&digest.encode(), limits),
            Err(PopError::TooMany { .. })
        ));
    }

    // -- framing ------------------------------------------------------------

    #[test]
    fn every_message_round_trips_through_canonical_bytes() {
        let limits = PopLimits::default();
        for message in [
            digest_message(&population(0..3)),
            PopMessage::Want {
                ids: vec![candidate(1, 1).id()],
            },
            PopMessage::Records {
                candidates: vec![candidate(1, 1), candidate(2, 2)],
            },
            PopMessage::Done,
        ] {
            let bytes = message.encode();
            assert_eq!(PopMessage::decode(&bytes, limits).unwrap(), message);
            assert_eq!(message.encode(), bytes);
        }
    }

    #[test]
    fn malformed_frames_are_refused_not_guessed() {
        let limits = PopLimits::default();
        for bad in [
            &b"not json"[..],
            b"{}",
            br#"{"t":"want","ids":[]}"#,
            br#"{"t":"pop_want","ids":[1]}"#,
            br#"{"t":"pop_digest","ids":[]}"#,
            br#"{"t":"pop_records","candidates":[{"objective_id":"o"}]}"#,
        ] {
            assert!(
                PopMessage::decode(bad, limits).is_err(),
                "{:?} should not decode",
                std::str::from_utf8(bad)
            );
        }
    }
}
