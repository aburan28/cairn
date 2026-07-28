//! The candidate population: a CRDT, deliberately not a consensus problem.
//!
//! The single most expensive mistake available here is running the whole network
//! through one agreement protocol. Three kinds of shared state live in a
//! research network and they have three completely different consistency
//! requirements:
//!
//! - **frontier** -- who holds the best score. Payment depends on it, so it
//!   needs a total order; but it changes only on improvement, so it is
//!   low-volume. This is the *only* part that needs consensus. See
//!   [`crate::frontier`].
//! - **population** -- the pile of scored candidates worth mutating. High
//!   volume, order-irrelevant, loss-tolerant, and divergence between nodes is
//!   actively *useful* (it preserves search diversity). Gossip. This module.
//! - **work split** -- which region a node searches. Needs no agreement at all;
//!   see [`crate::partition`].
//!
//! Pushing the population through consensus would cost orders of magnitude in
//! throughput to buy a property the workload does not want. So the population is
//! a join-semilattice: nodes gossip whatever they have, merges are commutative,
//! associative and idempotent, and any two nodes that have seen the same set of
//! messages agree -- with no rounds, no leader and no voting.
//!
//! # Bounded, and still confluent
//!
//! Keeping every candidate forever is not an option, so each island retains only
//! its top K. That pruning is safe: if a candidate is not in the top K of
//! `A ∪ B`, then K candidates in `A ∪ B` beat it, and those all survive into
//! `A ∪ B ∪ C`, so it is not in the top K of the larger union either. Dropping
//! it early therefore never changes the answer, and [`Population::merge`] stays
//! associative. Ties break on the content hash so the order is total and every
//! node prunes identically.
//!
//! # Islands
//!
//! Retention is per-island rather than global, so one strong candidate cannot
//! wipe out the diversity the search depends on -- the island model FunSearch
//! uses, expressed as a data structure instead of a scheduler.
//!
//! # What the Rust port changes
//!
//! Nothing about the lattice. Two boundaries move, both because Python's
//! integers are unbounded and Rust's are not:
//!
//! - `score` is an [`i64`]. The reference implementation checks at runtime that
//!   it is an `int` and not a `bool`; here that is the type. A record written by
//!   the Python implementation carrying a score outside `i64` is *refused* by
//!   [`Candidate::from_value`] rather than truncated -- a truncated score is a
//!   different candidate with the same wire bytes, which is precisely the
//!   silent disagreement this crate exists to prevent.
//! - No arithmetic is performed on scores anywhere in this module. They are
//!   compared and hashed, never summed or scaled, so there is no overflow path
//!   to check. The only division is the island modulus, and it is guarded
//!   against a zero divisor even though [`Population::new`] makes zero islands
//!   unconstructible.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::canonical::Value;

/// Default island count. Diversity is cheap; eight buckets is enough that one
/// hot lineage cannot evict the rest.
pub const DEFAULT_ISLANDS: u32 = 8;
/// Default per-island retention. Bounded memory is the point; the exact bound
/// is a tuning parameter, not a protocol constant.
pub const DEFAULT_CAPACITY: usize = 32;

/// Number of hex characters of the artifact id that select an island. Eight hex
/// digits is 32 bits, which is exactly a [`u32`] -- so the parse cannot overflow
/// and needs no fallback that would differ from the reference implementation.
const ISLAND_HEX_DIGITS: usize = 8;

// -- errors ----------------------------------------------------------------

/// Everything that can go wrong in this module. Nothing here panics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipError {
    /// Zero islands. The reference implementation refuses `islands < 1`; the
    /// unsigned type rules out the negative half, so only zero is left. Zero
    /// would also make the island modulus a division by zero.
    ZeroIslands,
    /// Zero capacity. A population that retains nothing is not a bounded
    /// population, it is a discard.
    ZeroCapacity,
    /// [`Population::merge`] across different island counts. The same candidate
    /// hashes to different islands under different counts, so the union would
    /// not be well defined and per-island retention would not be either.
    IslandCountMismatch { left: u32, right: u32 },
    /// The value being decoded is not an object.
    NotAnObject { record: &'static str },
    /// A required field is absent. The reference implementation raises
    /// `KeyError` here; a typed error is the Rust equivalent.
    MissingField {
        record: &'static str,
        field: &'static str,
    },
    /// A field is present with the wrong shape. Booleans land here too:
    /// [`Value::as_i128`] refuses them, which reproduces the reference
    /// implementation's explicit `isinstance(score, bool)` rejection. `True` is
    /// not a score of one.
    InvalidField {
        record: &'static str,
        field: &'static str,
        expected: &'static str,
    },
    /// An integer field outside the range this crate represents it in. Python's
    /// ints are unbounded, so a record it wrote can legitimately carry a value
    /// no field here can hold; refusing it beats truncating it.
    OutOfRange { field: &'static str, value: i128 },
}

impl fmt::Display for GossipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GossipError::ZeroIslands => write!(f, "islands must be at least 1"),
            GossipError::ZeroCapacity => write!(f, "capacity must be at least 1"),
            GossipError::IslandCountMismatch { left, right } => write!(
                f,
                "cannot merge populations with different island counts ({left} and {right})"
            ),
            GossipError::NotAnObject { record } => write!(f, "{record}: expected an object"),
            GossipError::MissingField { record, field } => {
                write!(f, "{record}: missing required field `{field}`")
            }
            GossipError::InvalidField {
                record,
                field,
                expected,
            } => write!(f, "{record}: field `{field}` must be {expected}"),
            GossipError::OutOfRange { field, value } => {
                write!(f, "field `{field}` is out of range for this build: {value}")
            }
        }
    }
}

impl std::error::Error for GossipError {}

// -- candidate -------------------------------------------------------------

/// A scored artifact worth building on. Not a claim; nothing is owed for it.
///
/// The fields are public because a candidate is a plain record, but treat one as
/// frozen once it has been gossiped: its [`id`](Candidate::id) is a function of
/// its contents, so a mutated candidate is a *different* candidate. A
/// [`Population`] owns its copies, so no mutation on your side can corrupt one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub objective_id: String,
    /// The artifact itself. The reference implementation annotates this as a
    /// dict but never checks at runtime, so any canonical value is accepted
    /// here too -- the digest is well defined for all of them.
    pub artifact: Value,
    /// The score *claimed* by whoever sent this. Not a verified fact; see
    /// [`ingest`].
    pub score: i64,
    pub origin: String,
}

impl Candidate {
    pub fn new(
        objective_id: impl Into<String>,
        artifact: Value,
        score: i64,
        origin: impl Into<String>,
    ) -> Candidate {
        Candidate {
            objective_id: objective_id.into(),
            artifact,
            score,
            origin: origin.into(),
        }
    }

    /// Identity includes the claimed score, and must.
    ///
    /// A gossiped score is an *assertion by a peer*, not a verified fact, and
    /// two peers can gossip the same artifact with different scores -- one
    /// honestly, one lying to crowd better candidates out of the population. If
    /// identity ignored the score, merge would have to pick a winner between two
    /// values that are equal under the key, and any tiebreak not derived from
    /// the values themselves (insertion order, arrival time, sender) destroys
    /// convergence: two nodes seeing the same messages in different orders end
    /// up with different populations and never find out.
    ///
    /// Keeping the score in the identity makes disagreement *representable* --
    /// both entries survive, side by side, which is what lets a node notice a
    /// peer is lying instead of silently absorbing it. See [`ingest`].
    pub fn id(&self) -> String {
        Value::object([
            ("objective_id", Value::string(self.objective_id.as_str())),
            ("artifact", self.artifact.clone()),
            ("score", Value::Int(i128::from(self.score))),
        ])
        .digest()
    }

    /// Identity of the artifact alone, ignoring any claimed score.
    pub fn artifact_id(&self) -> String {
        Value::object([
            ("objective_id", Value::string(self.objective_id.as_str())),
            ("artifact", self.artifact.clone()),
        ])
        .digest()
    }

    /// Which island this candidate belongs to.
    ///
    /// Keyed by [`artifact_id`](Candidate::artifact_id), *not* by
    /// [`id`](Candidate::id): an artifact's honest and inflated variants must
    /// land in the same island so they compete directly for one slot rather than
    /// occupying two.
    ///
    /// `islands` of zero is clamped to one rather than dividing by zero. That
    /// case is unreachable through a [`Population`], whose constructor rejects
    /// it, but this method is callable on its own and a panic in a gossip
    /// receive loop takes the node down.
    pub fn island(&self, islands: u32) -> u32 {
        let id = self.artifact_id();
        let start = id.len().saturating_sub(ISLAND_HEX_DIGITS);
        // The digest is ASCII hex, so this slice is always on a char boundary
        // and always parses; the fallbacks exist so that a malformed id degrades
        // to island 0 instead of aborting the process.
        let tail = id.get(start..).unwrap_or("");
        let bucket = u32::from_str_radix(tail, 16).unwrap_or(0);
        bucket % islands.max(1)
    }

    /// Total order: score first, then content hash so ties break identically on
    /// every node. Without a total order, pruning is not deterministic and merge
    /// stops converging.
    ///
    /// Rust compares `String` by UTF-8 bytes and Python compares `str` by code
    /// point; the ids are ASCII hex, so the two orders coincide.
    pub fn rank(&self) -> (i64, String) {
        (self.score, self.id())
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("objective_id", Value::string(self.objective_id.as_str())),
            ("artifact", self.artifact.clone()),
            ("score", Value::Int(i128::from(self.score))),
            ("origin", Value::string(self.origin.as_str())),
        ])
    }

    /// Decode a candidate. Every field is required, matching the reference
    /// implementation's `data["..."]` indexing.
    pub fn from_value(value: &Value) -> Result<Candidate, GossipError> {
        const RECORD: &str = "candidate";
        if value.as_object().is_none() {
            return Err(GossipError::NotAnObject { record: RECORD });
        }
        let objective_id = required_string(value, RECORD, "objective_id")?;
        let origin = required_string(value, RECORD, "origin")?;
        let artifact = value
            .get("artifact")
            .ok_or(GossipError::MissingField {
                record: RECORD,
                field: "artifact",
            })?
            .clone();
        let raw_score = value
            .get("score")
            .ok_or(GossipError::MissingField {
                record: RECORD,
                field: "score",
            })?
            .as_i128()
            .ok_or(GossipError::InvalidField {
                record: RECORD,
                field: "score",
                expected: "an integer",
            })?;
        let score = i64::try_from(raw_score).map_err(|_| GossipError::OutOfRange {
            field: "score",
            value: raw_score,
        })?;
        Ok(Candidate {
            objective_id,
            artifact,
            score,
            origin,
        })
    }
}

// -- population ------------------------------------------------------------

/// A bounded join-semilattice of candidates, replicated by gossip.
///
/// Internally: island index -> (candidate id -> candidate). Two invariants hold
/// everywhere and the ranking code depends on both:
///
/// 1. a bucket's key is exactly `candidate.id()`, so ranking can read the id off
///    the map key instead of re-hashing the candidate;
/// 2. a candidate lives in the bucket for `candidate.island(self.islands)`, so
///    an id appears at most once in the whole population.
///
/// `BTreeMap` rather than a hash map so iteration order is deterministic. Nothing
/// observable depends on it -- every reader sorts -- but a deterministic order
/// makes a divergence reproducible instead of a Heisenbug.
#[derive(Debug, Clone)]
pub struct Population {
    islands: u32,
    capacity: usize,
    by_island: BTreeMap<u32, BTreeMap<String, Candidate>>,
}

impl Population {
    /// An empty population. Both bounds must be positive: zero islands has no
    /// bucket to hash into, zero capacity retains nothing.
    pub fn new(islands: u32, capacity: usize) -> Result<Population, GossipError> {
        if islands < 1 {
            return Err(GossipError::ZeroIslands);
        }
        if capacity < 1 {
            return Err(GossipError::ZeroCapacity);
        }
        Ok(Population {
            islands,
            capacity,
            by_island: BTreeMap::new(),
        })
    }

    /// Build a population from an iterator of candidates: insert everything,
    /// then prune once.
    ///
    /// Pruning once at the end and pruning after every insert give the same
    /// answer, which is worth spelling out because the two are not obviously
    /// equal. If `x` is dropped at some step, K candidates better than `x` were
    /// present at that step; each of those can only ever be replaced by
    /// something better still, so from then on at least K candidates beat `x`
    /// forever. `x` was therefore never going to be in the final top K. Bounded
    /// streaming retention is exact, not approximate.
    pub fn with_candidates<I>(
        islands: u32,
        capacity: usize,
        candidates: I,
    ) -> Result<Population, GossipError>
    where
        I: IntoIterator<Item = Candidate>,
    {
        let mut population = Population::new(islands, capacity)?;
        for candidate in candidates {
            population.insert(candidate);
        }
        population.prune();
        Ok(population)
    }

    pub fn islands(&self) -> u32 {
        self.islands
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    // -- lattice -----------------------------------------------------------

    /// Insert without pruning. Private: an unpruned population violates the
    /// capacity bound, so it must not be observable from outside.
    fn insert(&mut self, candidate: Candidate) {
        let island = candidate.island(self.islands);
        let id = candidate.id();
        let bucket = self.by_island.entry(island).or_default();
        match bucket.get(&id) {
            // Identical content from two peers -- the id covers objective,
            // artifact and score, so only `origin` can differ. Keep the
            // lexicographically smaller origin: it is a function of the values,
            // so every node picks the same one, whereas "first one seen" would
            // make the result depend on delivery order.
            Some(existing) if existing.origin <= candidate.origin => {}
            _ => {
                bucket.insert(id, candidate);
            }
        }
    }

    /// Enforce top-K per island. See the module docs for why dropping early
    /// never changes a later answer.
    fn prune(&mut self) {
        let capacity = self.capacity;
        for bucket in self.by_island.values_mut() {
            if bucket.len() <= capacity {
                continue;
            }
            // The map key *is* the candidate id, so the rank key needs no
            // re-hashing. Descending: highest score first, ties to the larger
            // id, exactly as `sorted(..., key=rank, reverse=True)` does.
            let mut ranked: Vec<(i64, String)> = bucket
                .iter()
                .map(|(id, candidate)| (candidate.score, id.clone()))
                .collect();
            ranked.sort_by(|left, right| right.cmp(left));
            let kept: BTreeSet<String> = ranked
                .into_iter()
                .take(capacity)
                .map(|(_, id)| id)
                .collect();
            bucket.retain(|id, _| kept.contains(id));
        }
    }

    /// Add one candidate, then re-enforce the bound.
    pub fn add(&mut self, candidate: Candidate) {
        self.insert(candidate);
        self.prune();
    }

    /// Join. Commutative, associative, idempotent -- order never matters.
    ///
    /// The merged capacity is the *smaller* of the two. Taking the larger would
    /// let a peer widen your bound by claiming a big one, and the smaller bound
    /// is the one both sides can reproduce.
    pub fn merge(&self, other: &Population) -> Result<Population, GossipError> {
        if other.islands != self.islands {
            return Err(GossipError::IslandCountMismatch {
                left: self.islands,
                right: other.islands,
            });
        }
        // Both bounds are already validated and `min` of two positives is
        // positive, so this cannot violate the constructor's invariants.
        let mut merged = Population {
            islands: self.islands,
            capacity: self.capacity.min(other.capacity),
            by_island: BTreeMap::new(),
        };
        for candidate in self.iter() {
            merged.insert(candidate.clone());
        }
        for candidate in other.iter() {
            merged.insert(candidate.clone());
        }
        merged.prune();
        Ok(merged)
    }

    // -- reading -----------------------------------------------------------

    /// Every retained candidate, in no meaningful order. Readers that care
    /// about order sort for themselves.
    pub fn iter(&self) -> impl Iterator<Item = &Candidate> + '_ {
        self.by_island.values().flat_map(|bucket| bucket.values())
    }

    /// The retained candidate with this id, if this population holds it.
    ///
    /// A linear scan over the islands rather than a direct lookup: the island a
    /// candidate lives in depends on *this* population's island count, so an id
    /// from a peer configured differently would miss.
    pub fn get(&self, id: &str) -> Option<&Candidate> {
        self.by_island.values().find_map(|bucket| bucket.get(id))
    }

    pub fn len(&self) -> usize {
        self.by_island.values().map(BTreeMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_island.values().all(BTreeMap::is_empty)
    }

    /// The `k` best candidates across all islands, best first.
    pub fn top(&self, k: usize) -> Vec<&Candidate> {
        let mut keyed = self.ranked();
        keyed.truncate(k);
        keyed
    }

    pub fn best(&self) -> Option<&Candidate> {
        self.ranked().into_iter().next()
    }

    /// The members of one island, best first. An empty island -- or an index
    /// beyond `islands` -- yields an empty vector rather than an error; asking
    /// about a bucket nobody has filled is not a mistake.
    pub fn island_members(&self, index: u32) -> Vec<&Candidate> {
        let bucket = match self.by_island.get(&index) {
            Some(bucket) => bucket,
            None => return Vec::new(),
        };
        rank_desc(bucket)
    }

    /// Every candidate, best first, across all islands.
    fn ranked(&self) -> Vec<&Candidate> {
        let mut keyed: Vec<((i64, &str), &Candidate)> = self
            .by_island
            .values()
            .flat_map(|bucket| {
                bucket
                    .iter()
                    .map(|(id, candidate)| ((candidate.score, id.as_str()), candidate))
            })
            .collect();
        keyed.sort_by(|left, right| right.0.cmp(&left.0));
        keyed.into_iter().map(|(_, candidate)| candidate).collect()
    }

    /// Content address of the whole population -- cheap gossip reconciliation.
    ///
    /// Two peers exchange digests; equal digests mean there is nothing to send.
    /// Computed over the sorted ids only, so it is independent of island layout
    /// and of the order candidates arrived in.
    pub fn digest(&self) -> String {
        let mut ids: Vec<&str> = self
            .by_island
            .values()
            .flat_map(|bucket| bucket.keys().map(String::as_str))
            .collect();
        ids.sort_unstable();
        Value::array(ids.into_iter().map(Value::string)).digest()
    }

    /// Wire form. Candidates are sorted by id so two nodes holding the same
    /// population serialize to the same bytes.
    pub fn to_value(&self) -> Value {
        // `i128::try_from` on a `usize` cannot fail on any platform this crate
        // builds for; the saturating fallback is here so the encoder has no
        // panicking path at all.
        let capacity = i128::try_from(self.capacity).unwrap_or(i128::MAX);
        let by_id: BTreeMap<&str, &Candidate> = self
            .by_island
            .values()
            .flat_map(|bucket| {
                bucket
                    .iter()
                    .map(|(id, candidate)| (id.as_str(), candidate))
            })
            .collect();
        let candidates: Vec<Value> = by_id
            .into_values()
            .map(|candidate| candidate.to_value())
            .collect();
        Value::object([
            ("islands", Value::Int(i128::from(self.islands))),
            ("capacity", Value::Int(capacity)),
            ("candidates", Value::Array(candidates)),
        ])
    }

    /// Decode a population. Re-inserts and re-prunes rather than trusting the
    /// encoded shape: a peer can send more than `capacity` candidates per
    /// island, and the bound is ours to enforce, not theirs.
    pub fn from_value(value: &Value) -> Result<Population, GossipError> {
        const RECORD: &str = "population";
        if value.as_object().is_none() {
            return Err(GossipError::NotAnObject { record: RECORD });
        }
        let islands = required_u32(value, RECORD, "islands")?;
        let capacity = required_usize(value, RECORD, "capacity")?;
        let raw = value.get("candidates").ok_or(GossipError::MissingField {
            record: RECORD,
            field: "candidates",
        })?;
        let items = raw.as_array().ok_or(GossipError::InvalidField {
            record: RECORD,
            field: "candidates",
            expected: "an array",
        })?;
        let mut candidates = Vec::with_capacity(items.len());
        for item in items {
            candidates.push(Candidate::from_value(item)?);
        }
        Population::with_candidates(islands, capacity, candidates)
    }
}

impl Default for Population {
    /// The reference implementation's default bounds, which Rust cannot express
    /// as default arguments. Both constants are positive, so unlike
    /// [`Population::new`] this cannot fail.
    fn default() -> Population {
        Population {
            islands: DEFAULT_ISLANDS,
            capacity: DEFAULT_CAPACITY,
            by_island: BTreeMap::new(),
        }
    }
}

/// Equality is by retained contents, ignoring `islands` and `capacity`.
///
/// This is what the CRDT laws are stated over: two nodes agree when they hold
/// the same candidates, and the bounds they were configured with are local
/// policy, not shared state. Comparing them would make
/// `a.merge(b) == b.merge(a)` fail for two nodes with different capacities even
/// though both ended up holding exactly the same candidates.
impl PartialEq for Population {
    fn eq(&self, other: &Population) -> bool {
        // Ids are unique within a population -- an id determines its island --
        // so equal sizes plus "every entry of mine is in yours, unchanged" is
        // exactly the reference implementation's `{c.id: c} == {c.id: c}`.
        if self.len() != other.len() {
            return false;
        }
        for bucket in self.by_island.values() {
            for (id, candidate) in bucket {
                match other.get(id) {
                    Some(found) if found == candidate => {}
                    _ => return false,
                }
            }
        }
        true
    }
}

impl Eq for Population {}

impl<'a> IntoIterator for &'a Population {
    type Item = &'a Candidate;
    type IntoIter = std::vec::IntoIter<&'a Candidate>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter().collect::<Vec<_>>().into_iter()
    }
}

// -- gossip is untrusted ---------------------------------------------------

/// Add a gossiped candidate only if its claimed score is locally reproducible.
///
/// **Gossip is untrusted.** A peer can assert any score it likes, and an
/// inflated one would otherwise crowd genuine candidates out of a bounded
/// population -- a cheap and effective denial of service against the search
/// itself.
///
/// The defence is the same property the whole network is built on: for the
/// objectives worth running here, checking costs one evaluation, which is the
/// evaluation the node was going to spend on this candidate anyway. So verify on
/// ingest and drop what does not reproduce. Untrusted input plus free
/// verification is not a hard problem; it only becomes one if you skip the
/// verification because it looked like overhead.
///
/// `rescore` returns [`Option`] where the reference implementation catches
/// exceptions, and the meaning is the same: **a scorer that cannot produce an
/// answer means reject, never accept.** A crash while scoring a peer's candidate
/// says nothing about the candidate and must not be recorded as a score of its
/// own. (A `rescore` that genuinely panics is not caught here: `catch_unwind`
/// cannot be relied on -- it does nothing under `panic = "abort"` -- so the
/// contract is that a scorer signals failure with `None`.)
///
/// Returns `true` if the candidate was accepted.
pub fn ingest<F>(population: &mut Population, candidate: Candidate, rescore: F) -> bool
where
    F: FnOnce(&Value) -> Option<i64>,
{
    match rescore(&candidate.artifact) {
        Some(observed) if observed == candidate.score => {
            population.add(candidate);
            true
        }
        _ => false,
    }
}

// -- helpers ---------------------------------------------------------------

fn rank_desc(bucket: &BTreeMap<String, Candidate>) -> Vec<&Candidate> {
    let mut keyed: Vec<((i64, &str), &Candidate)> = bucket
        .iter()
        .map(|(id, candidate)| ((candidate.score, id.as_str()), candidate))
        .collect();
    keyed.sort_by(|left, right| right.0.cmp(&left.0));
    keyed.into_iter().map(|(_, candidate)| candidate).collect()
}

fn required_string(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<String, GossipError> {
    match value.get(field) {
        None => Err(GossipError::MissingField { record, field }),
        Some(found) => found
            .as_str()
            .map(str::to_string)
            .ok_or(GossipError::InvalidField {
                record,
                field,
                expected: "a string",
            }),
    }
}

fn required_int(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<i128, GossipError> {
    match value.get(field) {
        None => Err(GossipError::MissingField { record, field }),
        Some(found) => found.as_i128().ok_or(GossipError::InvalidField {
            record,
            field,
            expected: "an integer",
        }),
    }
}

fn required_u32(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<u32, GossipError> {
    let raw = required_int(value, record, field)?;
    u32::try_from(raw).map_err(|_| GossipError::OutOfRange { field, value: raw })
}

fn required_usize(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<usize, GossipError> {
    let raw = required_int(value, record, field)?;
    usize::try_from(raw).map_err(|_| GossipError::OutOfRange { field, value: raw })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- fixtures ----------------------------------------------------------

    fn cand(score: i64, tag: &str) -> Candidate {
        Candidate::new(
            "obj",
            crate::obj! { "tag" => Value::string(tag) },
            score,
            "n0",
        )
    }

    fn cand_from(score: i64, tag: &str, origin: &str) -> Candidate {
        Candidate::new(
            "obj",
            crate::obj! { "tag" => Value::string(tag) },
            score,
            origin,
        )
    }

    fn pop(candidates: Vec<Candidate>) -> Population {
        Population::with_candidates(4, 8, candidates).expect("valid bounds")
    }

    fn small(candidates: Vec<Candidate>) -> Population {
        Population::with_candidates(2, 3, candidates).expect("valid bounds")
    }

    /// A deterministic LCG (the constants are Knuth's MMIX). No `rand` crate is
    /// available and randomised property tests must be reproducible anyway --
    /// a failure nobody can replay is not a failure anybody fixes.
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Lcg {
            Lcg(seed)
        }

        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // High bits: the low bits of an LCG have short periods.
            (self.0 >> 33) as u32
        }

        /// Uniform-enough integer in `0..n`. `n == 0` yields 0 rather than
        /// dividing by zero.
        fn below(&mut self, n: u32) -> u32 {
            if n == 0 {
                0
            } else {
                self.next_u32() % n
            }
        }
    }

    // -- conformance vectors ----------------------------------------------
    //
    // Copied from conformance/vectors.json, which was generated from the Python
    // reference implementation. If these disagree, this module cannot
    // interoperate and nothing else in it matters.

    #[test]
    fn ids_match_the_reference_implementation() {
        let cases: [(&str, i64, &str, &str); 6] = [
            (
                "a",
                0,
                "sha256:75fdfc69b4066436e9d7dbb0d65e772a2161de6105e0c7bdbe50d999ef5475c0",
                "sha256:031d1cbb9c7cc8dbbf4fa4be6e7592429d508c4c02d231de7a4eee1b4a5c23ff",
            ),
            (
                "bb",
                0,
                "sha256:7ad2c5e7ca0f21c9c71c26e917e9b9c91b30f8a248c7c8f58ec043d5e9d44340",
                "sha256:10b4f93e2b65938b308749f7f145db7d2218f1cb7510eca513c4d38b7d2e6d97",
            ),
            // Non-ASCII stays raw UTF-8 in the canonical bytes; if this one
            // passes, the encoder is not \u-escaping behind our back.
            (
                "\u{1f600}",
                0,
                "sha256:48dad7304ba6c53be9c275b2c37a10e56aa8a79e2f14285a5747ec9b6e4ee57c",
                "sha256:171803c5dc3f3205b785fea93cb2a901d2103ea5d3a5154bf7bce9347f35b4eb",
            ),
            (
                "a",
                999,
                "sha256:fd560e3e327dd7e152991e5ee8a342893da61fc154e23b7b7f61d0e5d0300ff4",
                "sha256:031d1cbb9c7cc8dbbf4fa4be6e7592429d508c4c02d231de7a4eee1b4a5c23ff",
            ),
            // 10^12: past u32, and the case a careless port truncates.
            (
                "a",
                1_000_000_000_000,
                "sha256:baeb74b4f384b1fd1c3b67c2f55e07b277eec5d6d9dfb45e9cd7275831da5082",
                "sha256:031d1cbb9c7cc8dbbf4fa4be6e7592429d508c4c02d231de7a4eee1b4a5c23ff",
            ),
            (
                "\u{1f600}",
                1_000_000_000_000,
                "sha256:3e8ebf36cb95cbcd3510a84c052e4d56f87bfce1f631ec4aa42f3b94870e8be8",
                "sha256:171803c5dc3f3205b785fea93cb2a901d2103ea5d3a5154bf7bce9347f35b4eb",
            ),
        ];
        for (tag, score, id, artifact_id) in cases {
            let candidate = cand(score, tag);
            assert_eq!(candidate.id(), id, "id for {tag}/{score}");
            assert_eq!(
                candidate.artifact_id(),
                artifact_id,
                "artifact_id for {tag}/{score}"
            );
        }
    }

    #[test]
    fn island_assignments_match_the_reference_implementation() {
        // (tag, islands, expected island) straight out of the vectors.
        let cases: [(&str, u32, u32); 12] = [
            ("a", 1, 0),
            ("a", 2, 1),
            ("a", 4, 3),
            ("a", 8, 7),
            ("a", 64, 63),
            ("bb", 8, 7),
            ("bb", 64, 23),
            ("\u{1f600}", 2, 1),
            ("\u{1f600}", 4, 3),
            ("\u{1f600}", 8, 3),
            ("\u{1f600}", 64, 43),
            ("\u{1f600}", 1, 0),
        ];
        for (tag, islands, expected) in cases {
            assert_eq!(cand(0, tag).island(islands), expected, "{tag} % {islands}");
        }
    }

    #[test]
    fn island_is_independent_of_the_claimed_score() {
        // The whole point of keying islands by artifact: an inflated variant
        // competes with the honest one for the same slot instead of taking a
        // second one.
        for islands in [1u32, 2, 4, 8, 64] {
            assert_eq!(
                cand(0, "a").island(islands),
                cand(1_000_000_000_000, "a").island(islands)
            );
        }
    }

    #[test]
    fn population_digest_matches_the_reference_implementation() {
        let empty = Population::new(4, 8).expect("valid bounds");
        assert_eq!(
            empty.digest(),
            "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
        let two = pop(vec![cand(1, "a"), cand(2, "b")]);
        assert_eq!(
            two.digest(),
            "sha256:77fa03457952f4c968fc32019c59687fba2009e8a6fa6ddba72b5c0f07db0d89"
        );
    }

    // -- the CRDT laws -----------------------------------------------------

    #[test]
    fn merge_is_commutative() {
        let a = pop(vec![cand(1, "a"), cand(2, "b")]);
        let b = pop(vec![cand(3, "c")]);
        assert_eq!(
            a.merge(&b).expect("same island count"),
            b.merge(&a).expect("same island count")
        );
    }

    #[test]
    fn merge_is_associative() {
        let a = pop(vec![cand(1, "a")]);
        let b = pop(vec![cand(2, "b")]);
        let c = pop(vec![cand(3, "c")]);
        let left = a
            .merge(&b)
            .expect("same island count")
            .merge(&c)
            .expect("same island count");
        let right = a
            .merge(&b.merge(&c).expect("same island count"))
            .expect("same island count");
        assert_eq!(left, right);
    }

    #[test]
    fn merge_is_idempotent() {
        let a = pop(vec![cand(1, "a"), cand(2, "b")]);
        assert_eq!(a.merge(&a).expect("same island count"), a);
    }

    #[test]
    fn pruning_preserves_associativity() {
        // The load-bearing property: bounded retention must not make merge order
        // matter. If it did, two nodes seeing the same messages in different
        // orders would end up with different populations and never notice.
        let mut rng = Lcg::new(1234);
        for round in 0..200 {
            let mut groups: Vec<Population> = Vec::with_capacity(3);
            for _ in 0..3 {
                let count = 1 + rng.below(12);
                let members: Vec<Candidate> = (0..count)
                    .map(|_| {
                        let score = i64::from(rng.below(51));
                        cand(score, &format!("t{}", rng.below(100)))
                    })
                    .collect();
                groups.push(small(members));
            }
            let (a, b, c) = match groups.as_slice() {
                [a, b, c] => (a, b, c),
                _ => panic!("built exactly three groups"),
            };
            let left = a
                .merge(b)
                .expect("same island count")
                .merge(c)
                .expect("same island count");
            let right = a
                .merge(&b.merge(c).expect("same island count"))
                .expect("same island count");
            assert_eq!(left, right, "round {round}");
            // Commutativity under pruning too, same cases.
            assert_eq!(
                a.merge(b).expect("same island count"),
                b.merge(a).expect("same island count"),
                "round {round}"
            );
        }
    }

    #[test]
    fn gossip_converges_regardless_of_delivery_order() {
        let mut rng = Lcg::new(99);
        let messages: Vec<Candidate> = (0..40)
            .map(|i| cand(i64::from(rng.below(101)), &format!("t{i}")))
            .collect();
        let mut finals: Vec<Population> = Vec::new();
        for _ in 0..12 {
            let mut shuffled = messages.clone();
            // Fisher-Yates with the LCG: every replica sees the same messages
            // in a different order.
            let len = shuffled.len();
            for i in (1..len).rev() {
                let j = rng.below((i + 1) as u32) as usize;
                shuffled.swap(i, j);
            }
            let mut node = Population::new(4, 5).expect("valid bounds");
            for message in shuffled {
                let one = Population::with_candidates(4, 5, vec![message]).expect("valid bounds");
                node = node.merge(&one).expect("same island count");
            }
            finals.push(node);
        }
        let first = finals.first().cloned().expect("twelve replicas");
        assert!(finals.iter().all(|f| *f == first));
        assert!(finals.iter().all(|f| f.digest() == first.digest()));
    }

    // -- bounded retention -------------------------------------------------

    #[test]
    fn capacity_is_enforced_per_island() {
        let mut population = Population::new(2, 3).expect("valid bounds");
        for i in 0..50 {
            population.add(cand(i, &format!("t{i}")));
        }
        for island in 0..2 {
            assert!(population.island_members(island).len() <= 3);
        }
        assert!(population.len() <= 6);
    }

    #[test]
    fn best_candidates_survive_pruning() {
        let mut population = Population::new(1, 3).expect("valid bounds");
        for i in 0..20 {
            population.add(cand(i, &format!("t{i}")));
        }
        let scores: Vec<i64> = population.top(3).iter().map(|c| c.score).collect();
        assert_eq!(scores, vec![19, 18, 17]);
        assert_eq!(population.best().map(|c| c.score), Some(19));
    }

    #[test]
    fn islands_preserve_diversity() {
        // A run of strong candidates must not evict every weaker island:
        // diversity is what the search depends on, so retention is per island,
        // not global.
        let mut population = Population::new(4, 2).expect("valid bounds");
        for i in 0..200 {
            population.add(cand(i, &format!("t{i}")));
        }
        let occupied = (0..4)
            .filter(|i| !population.island_members(*i).is_empty())
            .count();
        assert!(occupied > 1, "expected more than one occupied island");
    }

    #[test]
    fn ties_break_deterministically() {
        let same_score: Vec<Candidate> = (0..20).map(|i| cand(7, &format!("t{i}"))).collect();
        let first = small(same_score.clone());
        let mut rng = Lcg::new(0);
        for _ in 0..10 {
            let mut shuffled = same_score.clone();
            for i in (1..shuffled.len()).rev() {
                let j = rng.below((i + 1) as u32) as usize;
                shuffled.swap(i, j);
            }
            assert_eq!(small(shuffled), first);
        }
    }

    #[test]
    fn streaming_and_batch_retention_agree() {
        // `add` prunes on every insert, `with_candidates` prunes once at the
        // end. If those differed, a node's population would depend on whether
        // it was restored from a snapshot or built message by message.
        let members: Vec<Candidate> = (0..40).map(|i| cand(i % 7, &format!("t{i}"))).collect();
        let batch = small(members.clone());
        let mut streamed = Population::new(2, 3).expect("valid bounds");
        for member in members {
            streamed.add(member);
        }
        assert_eq!(batch, streamed);
    }

    // -- disagreement is representable -------------------------------------

    #[test]
    fn identical_artifact_from_two_peers_converges() {
        let left = pop(vec![cand_from(5, "a", "alice")]);
        let right = pop(vec![cand_from(5, "a", "bob")]);
        assert_eq!(
            left.merge(&right).expect("same island count"),
            right.merge(&left).expect("same island count")
        );
        assert_eq!(left.merge(&right).expect("same island count").len(), 1);
        // The smaller origin wins, in either merge order: it is a function of
        // the values, so every node picks the same one.
        let merged = right.merge(&left).expect("same island count");
        assert_eq!(
            merged.best().map(|c| c.origin.as_str()),
            Some("alice"),
            "the lexicographically smaller origin must survive"
        );
    }

    #[test]
    fn same_artifact_at_two_scores_converges() {
        // One peer is lying about this artifact's score. Merge must still
        // converge: both entries are representable and every node keeps the
        // same ones.
        let honest = cand_from(5, "a", "alice");
        let inflated = cand_from(999, "a", "mallory");
        assert_eq!(honest.artifact_id(), inflated.artifact_id());
        assert_ne!(honest.id(), inflated.id());
        assert_eq!(honest.island(4), inflated.island(4));
        let left = pop(vec![honest]);
        let right = pop(vec![inflated]);
        assert_eq!(
            left.merge(&right).expect("same island count"),
            right.merge(&left).expect("same island count")
        );
        assert_eq!(left.merge(&right).expect("same island count").len(), 2);
    }

    #[test]
    fn merging_different_island_counts_is_refused() {
        let a = Population::with_candidates(2, 8, vec![cand(1, "x")]).expect("valid bounds");
        let b = Population::with_candidates(4, 8, vec![cand(1, "x")]).expect("valid bounds");
        assert_eq!(
            a.merge(&b),
            Err(GossipError::IslandCountMismatch { left: 2, right: 4 })
        );
    }

    #[test]
    fn merge_takes_the_smaller_capacity() {
        let a = Population::new(2, 3).expect("valid bounds");
        let b = Population::new(2, 9).expect("valid bounds");
        assert_eq!(a.merge(&b).expect("same island count").capacity(), 3);
        assert_eq!(b.merge(&a).expect("same island count").capacity(), 3);
    }

    // -- digests and round trips -------------------------------------------

    #[test]
    fn digest_detects_equality_cheaply() {
        let a = pop(vec![cand(1, "a"), cand(2, "b")]);
        let b = pop(vec![cand(2, "b"), cand(1, "a")]);
        assert_eq!(a.digest(), b.digest());
        assert_ne!(a.digest(), pop(vec![cand(1, "a")]).digest());
    }

    #[test]
    fn round_trips_through_value() {
        let population = pop(vec![cand(1, "a"), cand(9, "b"), cand(4, "c")]);
        let decoded = Population::from_value(&population.to_value()).expect("valid encoding");
        assert_eq!(decoded, population);
        assert_eq!(decoded.islands(), 4);
        assert_eq!(decoded.capacity(), 8);
        // Encoding is canonical: same contents, same bytes.
        assert_eq!(
            decoded.to_value().canonical_bytes(),
            population.to_value().canonical_bytes()
        );
    }

    #[test]
    fn candidate_round_trips_through_value() {
        let candidate = cand_from(-7, "a", "alice");
        let decoded = Candidate::from_value(&candidate.to_value()).expect("valid encoding");
        assert_eq!(decoded, candidate);
        assert_eq!(decoded.id(), candidate.id());
    }

    // -- boundaries: what Python's bignums would have let through ----------

    #[test]
    fn extreme_scores_are_representable_and_ordered() {
        // No arithmetic happens on scores here, so the extremes must simply
        // work: no overflow, no wraparound, correct order.
        let mut population = Population::new(1, 4).expect("valid bounds");
        population.add(cand(i64::MIN, "low"));
        population.add(cand(i64::MAX, "high"));
        population.add(cand(0, "mid"));
        let scores: Vec<i64> = population.top(3).iter().map(|c| c.score).collect();
        assert_eq!(scores, vec![i64::MAX, 0, i64::MIN]);
        assert_eq!(population.best().map(|c| c.score), Some(i64::MAX));
    }

    #[test]
    fn a_score_outside_i64_is_refused_rather_than_truncated() {
        // Python's ints are unbounded, so a peer running the reference
        // implementation can emit this. Truncating would produce a *different*
        // candidate carrying the same wire bytes -- a silent divergence.
        let too_big = i128::from(i64::MAX) + 1;
        let encoded = crate::obj! {
            "objective_id" => Value::string("obj"),
            "artifact" => crate::obj! { "tag" => Value::string("a") },
            "score" => Value::Int(too_big),
            "origin" => Value::string("n0"),
        };
        assert_eq!(
            Candidate::from_value(&encoded),
            Err(GossipError::OutOfRange {
                field: "score",
                value: too_big
            })
        );
    }

    #[test]
    fn a_boolean_score_is_not_an_integer() {
        // The reference implementation checks `isinstance(score, bool)` first
        // because Python says `True == 1`. Here `as_i128` refuses booleans.
        let encoded = crate::obj! {
            "objective_id" => Value::string("obj"),
            "artifact" => crate::obj! { "tag" => Value::string("a") },
            "score" => Value::Bool(true),
            "origin" => Value::string("n0"),
        };
        assert!(matches!(
            Candidate::from_value(&encoded),
            Err(GossipError::InvalidField { field: "score", .. })
        ));
    }

    #[test]
    fn missing_fields_are_refused() {
        let encoded = crate::obj! {
            "objective_id" => Value::string("obj"),
            "score" => Value::Int(1),
            "origin" => Value::string("n0"),
        };
        assert_eq!(
            Candidate::from_value(&encoded),
            Err(GossipError::MissingField {
                record: "candidate",
                field: "artifact"
            })
        );
        assert!(Candidate::from_value(&Value::string("nope")).is_err());
        assert!(Population::from_value(&Value::Int(3)).is_err());
    }

    #[test]
    fn degenerate_bounds_are_refused() {
        assert_eq!(Population::new(0, 4), Err(GossipError::ZeroIslands));
        assert_eq!(Population::new(4, 0), Err(GossipError::ZeroCapacity));
        assert!(Population::with_candidates(0, 1, vec![]).is_err());
        let encoded = crate::obj! {
            "islands" => Value::Int(0),
            "capacity" => Value::Int(4),
            "candidates" => Value::Array(Vec::new()),
        };
        assert_eq!(
            Population::from_value(&encoded),
            Err(GossipError::ZeroIslands)
        );
    }

    #[test]
    fn zero_islands_does_not_divide_by_zero() {
        // Unreachable through `Population`, which refuses zero islands, but
        // `island` is callable on its own and a panic in a receive loop takes
        // the node down.
        assert_eq!(cand(1, "a").island(0), 0);
    }

    #[test]
    fn an_oversized_capacity_is_refused_rather_than_wrapping() {
        let huge = i128::from(u64::MAX) * 4;
        let encoded = crate::obj! {
            "islands" => Value::Int(4),
            "capacity" => Value::Int(huge),
            "candidates" => Value::Array(Vec::new()),
        };
        assert_eq!(
            Population::from_value(&encoded),
            Err(GossipError::OutOfRange {
                field: "capacity",
                value: huge
            })
        );
    }

    // -- gossip is untrusted -----------------------------------------------

    fn real_score(artifact: &Value) -> Option<i64> {
        let tag = artifact.get("tag").and_then(Value::as_str).unwrap_or("");
        i64::try_from(tag.chars().count()).ok()
    }

    #[test]
    fn ingest_accepts_an_honest_candidate() {
        let mut population = Population::new(2, 4).expect("valid bounds");
        assert!(ingest(&mut population, cand(3, "abc"), real_score));
        assert_eq!(population.len(), 1);
    }

    #[test]
    fn ingest_rejects_an_inflated_score() {
        // Without this, a peer asserts score = 10^9 and evicts every genuine
        // candidate from a bounded population -- a cheap DoS on the search
        // itself.
        let mut population = Population::new(2, 4).expect("valid bounds");
        assert!(!ingest(
            &mut population,
            cand(1_000_000_000, "abc"),
            real_score
        ));
        assert!(population.is_empty());
        assert_eq!(population.len(), 0);
    }

    #[test]
    fn ingest_rejects_a_candidate_whose_scorer_fails() {
        // A scorer that cannot answer says nothing about the candidate. `None`
        // is reject, never accept -- the Rust spelling of the reference
        // implementation's bare `except`.
        let mut population = Population::new(2, 4).expect("valid bounds");
        assert!(!ingest(&mut population, cand(1, "a"), |_| None));
        assert!(population.is_empty());
    }

    #[test]
    fn ingest_does_not_let_an_inflated_score_evict_real_candidates() {
        // The attack in full: fill a tiny population with honest candidates,
        // then have a peer gossip an enormous score for a worthless artifact.
        let mut population = Population::new(1, 2).expect("valid bounds");
        assert!(ingest(&mut population, cand(1, "a"), real_score));
        assert!(ingest(&mut population, cand(2, "bb"), real_score));
        let before = population.digest();
        assert!(!ingest(&mut population, cand(i64::MAX, "junk"), real_score));
        assert_eq!(population.digest(), before);
        assert_eq!(population.best().map(|c| c.score), Some(2));
    }

    // -- internal invariants -----------------------------------------------

    #[test]
    fn bucket_keys_are_candidate_ids() {
        // The ranking code reads ids off the map keys instead of re-hashing.
        // That is only sound while this holds.
        let mut population = Population::new(4, 8).expect("valid bounds");
        for i in 0..20 {
            population.add(cand(i, &format!("t{i}")));
        }
        for (island, bucket) in &population.by_island {
            for (id, candidate) in bucket {
                assert_eq!(*id, candidate.id());
                assert_eq!(*island, candidate.island(population.islands()));
            }
        }
    }

    #[test]
    fn equality_ignores_local_bounds() {
        // Capacity is local policy, not shared state; two nodes holding the
        // same candidates agree even if they were configured differently.
        let a = Population::with_candidates(2, 8, vec![cand(1, "a")]).expect("valid bounds");
        let b = Population::with_candidates(2, 5, vec![cand(1, "a")]).expect("valid bounds");
        assert_eq!(a, b);
    }
}
