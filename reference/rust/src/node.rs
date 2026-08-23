//! The rules: what may be posted, what settles, and what mints nothing.
//!
//! Ported from the protocol's behaviour, not from the primary implementation's
//! source. Where the two disagree, one of them is wrong and the disagreement
//! is the finding -- that is the entire reason this crate exists.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::canonical::{short, Value};
use crate::drand;
use crate::frontier::Ratchet;
use crate::ledger::{Ledger, Proof};
use crate::partition::{assign, beacon, epoch_of, epoch_seconds, settlement_rank, COMMITTEE_SIZE};
use crate::records::{
    signed_submitter, Availability, AvailabilityPool, Claim, Commitment, CommitteeShare, Objective,
    PeerRecord, Undertaking, MAX_UNDERTAKING_HEIGHT,
};
use crate::time::{timestamp, unix_seconds};
use crate::verifiers::{self, Status, Verdict};

pub const OBJECTIVE: &str = "objective";
pub const COMMITMENT: &str = "commitment";
pub const CLAIM: &str = "claim";
pub const VERDICT: &str = "verdict";
pub const SETTLEMENT: &str = "settlement";
pub const FRONTIER: &str = "frontier";
pub const BATCH: &str = "batch";
pub const BEACON: &str = "beacon";
pub const PEER: &str = "peer";
pub const UNDERTAKING: &str = "undertaking";
pub const AVAILABILITY: &str = "availability";
pub const AVAILABILITY_POOL: &str = "availability_pool";
pub const AVAILABILITY_SETTLEMENT: &str = "availability_settlement";
pub const COMMITTEE_SHARE: &str = "committee_share";
pub const ISSUANCE: &str = "issuance";
pub const CHALLENGE: &str = "challenge";
pub const BISECTION: &str = "bisection";
pub const CHALLENGE_SETTLEMENT: &str = "challenge_settlement";
pub const ATTESTATION: &str = "attestation";
pub const VERIFICATION_SLASH: &str = "verification_slash";

/// What standing behind one verdict costs. Mirrors the primary's
/// `node::VERIFICATION_BOND`, and per *attestation* rather than per attestor
/// for the reason stated there: one bond covering a thousand statements would
/// be the same units staked a thousand times.
///
/// The number is duplicated rather than shared, like every other consensus
/// constant in this crate. Two implementations that read the same file agree
/// about it by construction, which is the one thing a second opinion must not
/// do.
pub const VERIFICATION_BOND: u64 = 50_000;

/// How long an attestation stays open to a slash, after which its bond returns.
/// Mirrors the primary's `node::ATTESTATION_WINDOW_EPOCHS`.
///
/// The clock is the log's own: the highest epoch any `batch` record below the
/// point in question names. Not an entry's `ts`, which is advisory text its own
/// author writes, and not log height, which anybody can advance for the price
/// of an append.
pub const ATTESTATION_WINDOW_EPOCHS: u64 = 6;

/// Whether an attestation record in the log is signed by the identity it names.
///
/// The signing payload is rebuilt field by field from the record's own bytes
/// rather than round-tripped through a decoder shared with the primary. That is
/// the discipline the whole crate is for: two implementations that agree
/// because they run the same code agree about nothing, and the one question
/// worth asking here is whether the *format* is what both believe it is.
///
/// An unsigned attestation is not merely irregular, it is free — there is
/// nobody to take a bond from — so this answer decides money as well as
/// admissibility.
fn attestation_is_signed(payload: &Value) -> bool {
    let field = |key: &str| payload.get(key).and_then(Value::as_str).unwrap_or_default();
    let attestor = field("attestor");
    if signed_submitter(attestor).is_none() {
        return false;
    }
    let signing = Value::object([
        ("type", Value::string("attestation")),
        ("attestor", Value::string(attestor)),
        ("claim_id", Value::string(field("claim_id"))),
        ("created_at", Value::string(field("created_at"))),
        ("status", Value::string(field("status"))),
    ]);
    let signature = payload.get("signature").and_then(Value::as_str);
    crate::records::verify_record_signature("attestation", attestor, &signing, signature).is_ok()
}

/// How long a claim's trace stays open to objection, and how long a party has
/// to answer before silence decides against them. Mirrors the primary's
/// `node::CHALLENGE_WINDOW_EPOCHS`; the two crates disagreeing about this
/// number would mean disagreeing about who forfeited.
pub const CHALLENGE_WINDOW_EPOCHS: u64 = 6;

#[derive(Debug, Clone)]
pub struct Outcome {
    pub claim_id: String,
    pub verdict: Verdict,
    pub settled: bool,
    pub reward: u64,
    pub note: String,
    pub pending_epoch: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct FrontierEntry {
    pub objective_id: String,
    pub claim_id: String,
    pub holder: String,
    pub score: i64,
    pub paid_cumulative: u64,
}

impl FrontierEntry {
    fn to_value(&self) -> Value {
        Value::object([
            ("objective_id", Value::string(self.objective_id.clone())),
            ("claim_id", Value::string(self.claim_id.clone())),
            ("holder", Value::string(self.holder.clone())),
            ("score", Value::Int(i128::from(self.score))),
            (
                "paid_cumulative",
                Value::Int(i128::from(self.paid_cumulative)),
            ),
        ])
    }

    fn from_value(value: &Value) -> Option<FrontierEntry> {
        Some(FrontierEntry {
            objective_id: value.get("objective_id")?.as_str()?.to_string(),
            claim_id: value.get("claim_id")?.as_str()?.to_string(),
            holder: value.get("holder")?.as_str()?.to_string(),
            score: value.get("score")?.as_i64()?,
            paid_cumulative: value.get("paid_cumulative")?.as_u64()?,
        })
    }
}

pub struct Node {
    pub ledger: Ledger,
    root: PathBuf,
}

impl Node {
    pub fn new(ledger: Ledger, root: impl Into<PathBuf>) -> Node {
        Node {
            ledger,
            root: root.into(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn epoch_of_ts(&self, record: &str, ts: &str) -> Result<u64, String> {
        unix_seconds(ts)
            .map(|seconds| epoch_of(seconds, epoch_seconds()))
            // Refused, never defaulted: a record whose epoch is unknown cannot
            // be placed in a batch, and "treat it as now" would hand a
            // submitter a free choice of batch by writing garbage.
            .ok_or_else(|| {
                format!("{record} timestamp {ts:?} is not an RFC-3339 instant, so the epoch it settles in cannot be derived")
            })
    }

    // -- reads -----------------------------------------------------------

    pub fn objectives(&self) -> BTreeMap<String, Objective> {
        let mut out = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(OBJECTIVE) {
            if let Ok(objective) = Objective::from_value(&entry.payload) {
                out.insert(objective.id(), objective);
            }
        }
        out
    }

    pub fn settlement_of(&self, objective_id: &str) -> Option<&Value> {
        self.ledger
            .entries_of_kind(SETTLEMENT)
            .into_iter()
            .find(|entry| {
                entry.payload.get("objective_id").and_then(Value::as_str) == Some(objective_id)
            })
            .map(|entry| &entry.payload)
    }

    /// What `identity` could still bond, reading only the first `positions`
    /// entries of the log.
    ///
    /// Held minus committed. *Held* is what the genesis prefix issued this
    /// identity, plus settlements naming it as submitter, plus availability
    /// payouts naming it. *Committed* is every bond it has staked and every
    /// reward it has offered by funding an objective or a pool.
    ///
    /// The issuance half is what makes any of it scarce. Without it a funder
    /// named a reward and the settlement paid it, so units were free to make
    /// and weighing anything by them bought nothing.
    ///
    /// Bounded by position rather than taken over the whole log, because the
    /// rule this feeds is about what a record could afford *when it was
    /// written*. Reading the whole log would let a later payout retroactively
    /// justify a bond that was unfunded at the time, and let a later bond
    /// retroactively bankrupt one that was funded.
    ///
    /// Locked reads the raw undertaking entries -- decodable and signed,
    /// nothing more -- precisely because the affordability rule is what it
    /// feeds. Filtering on affordability here would be circular, and counting
    /// an unaffordable bond against its own author is self-correcting: a forged
    /// `u64::MAX` drives that identity's balance to zero and every promise it
    /// makes, that one included, fails the check.
    pub fn spendable_within(&self, identity: &str, positions: u64) -> u128 {
        self.held_within(identity, positions)
            .saturating_sub(self.committed_within(identity, positions))
    }

    /// What the log says `identity` holds, before its commitments: issued at
    /// genesis, plus settled, plus availability payouts.
    fn held_within(&self, identity: &str, positions: u64) -> u128 {
        let mut paid = self.issued_within(identity, positions);
        for entry in self.ledger.entries() {
            if entry.seq >= positions {
                break;
            }
            match entry.kind.as_str() {
                SETTLEMENT
                    if entry.payload.get("submitter").and_then(Value::as_str) == Some(identity) =>
                {
                    if let Some(reward) = entry.payload.get("reward").and_then(Value::as_u64) {
                        paid = paid.saturating_add(u128::from(reward));
                    }
                }
                AVAILABILITY_SETTLEMENT => {
                    for row in entry
                        .payload
                        .get("paid")
                        .and_then(Value::as_array)
                        .unwrap_or(&[])
                    {
                        if row.get("identity").and_then(Value::as_str) == Some(identity) {
                            if let Some(reward) = row.get("reward").and_then(Value::as_u64) {
                                paid = paid.saturating_add(u128::from(reward));
                            }
                        }
                    }
                }
                // What a won dispute pays the winner. Not new money -- every
                // unit is debited from the loser in `committed_within` -- but a
                // second implementation that did not know about it would report
                // the winner as overdrawn and certify the loser as solvent,
                // which is worse than not looking at all.
                CHALLENGE_SETTLEMENT
                    if entry.payload.get("winner").and_then(Value::as_str) == Some(identity) =>
                {
                    if let Some(units) = entry.payload.get("units").and_then(Value::as_u64) {
                        paid = paid.saturating_add(u128::from(units));
                    }
                }
                // The catch bounty: a slashed verification bond goes to
                // whoever produced the evidence. Same shape as a won dispute
                // and not new money either -- the attestor is debited for it
                // in `committed_within`.
                VERIFICATION_SLASH
                    if entry.payload.get("catcher").and_then(Value::as_str) == Some(identity) =>
                {
                    if let Some(units) = entry.payload.get("units").and_then(Value::as_u64) {
                        paid = paid.saturating_add(u128::from(units));
                    }
                }
                _ => {}
            }
        }
        paid
    }

    /// What `identity` has put at risk or parted with: bonds staked, plus
    /// rewards offered by funding an objective or an availability pool.
    ///
    /// Rewards are charged in full at post time and never returned: the units
    /// go to whoever settles the objective, so releasing them back as the
    /// settlement lands would credit the same money twice.
    fn committed_within(&self, identity: &str, positions: u64) -> u128 {
        let mut committed = 0u128;
        for entry in self.ledger.entries_of_kind(UNDERTAKING) {
            if entry.seq >= positions {
                break;
            }
            let Ok(record) = Undertaking::from_value(&entry.payload) else {
                continue;
            };
            if record.identity != identity || record.verify_signature().is_err() {
                continue;
            }
            committed = committed.saturating_add(u128::from(record.bond));
        }
        // A bond behind a *live* dispute is spent-but-not-gone: it can be
        // lost, so it must not also be staked elsewhere. Released once the
        // dispute settles, because the settlement record then says where it
        // went -- and the loser is debited by the same pass.
        let decided: BTreeSet<String> = self
            .ledger
            .entries_of_kind(CHALLENGE_SETTLEMENT)
            .into_iter()
            .filter(|entry| entry.seq < positions)
            .filter_map(|entry| {
                entry
                    .payload
                    .get("challenge_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        for entry in self.ledger.entries_of_kind(CHALLENGE) {
            if entry.seq >= positions {
                break;
            }
            if entry.payload.get("challenger").and_then(Value::as_str) != Some(identity) {
                continue;
            }
            if decided.contains(&entry.payload.digest()) {
                continue;
            }
            if let Some(bond) = entry.payload.get("bond").and_then(Value::as_u64) {
                committed = committed.saturating_add(u128::from(bond));
            }
        }
        for entry in self.ledger.entries_of_kind(CHALLENGE_SETTLEMENT) {
            if entry.seq >= positions {
                break;
            }
            if entry.payload.get("loser").and_then(Value::as_str) != Some(identity) {
                continue;
            }
            if let Some(units) = entry.payload.get("units").and_then(Value::as_u64) {
                committed = committed.saturating_add(u128::from(units));
            }
        }
        // A verification bond, live until the attestation it stands behind is
        // slashed. Counted per attestation, and an attestation whose signature
        // does not verify is skipped: it stakes nothing because there is nobody
        // to take it from, and the audit reports it separately.
        let slashed: BTreeSet<String> = self
            .ledger
            .entries_of_kind(VERIFICATION_SLASH)
            .into_iter()
            .filter(|entry| entry.seq < positions)
            .filter_map(|entry| {
                entry
                    .payload
                    .get("attestation_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        let settled_to = self.settled_epoch_within(positions);
        for entry in self.ledger.entries_of_kind(ATTESTATION) {
            if entry.seq >= positions {
                break;
            }
            if entry.payload.get("attestor").and_then(Value::as_str) != Some(identity) {
                continue;
            }
            if !attestation_is_signed(&entry.payload) || slashed.contains(&entry.payload.digest()) {
                continue;
            }
            // Released once the window has shut, or verification would be a
            // one-shot: an operator could stand behind `S / bond` verdicts in
            // its whole life and then never verify again.
            if !self.attestation_window_open(&entry.payload, settled_to) {
                continue;
            }
            committed = committed.saturating_add(u128::from(VERIFICATION_BOND));
        }
        for entry in self.ledger.entries_of_kind(VERIFICATION_SLASH) {
            if entry.seq >= positions {
                break;
            }
            if entry.payload.get("attestor").and_then(Value::as_str) != Some(identity) {
                continue;
            }
            if let Some(units) = entry.payload.get("units").and_then(Value::as_u64) {
                committed = committed.saturating_add(u128::from(units));
            }
        }
        for entry in self.ledger.entries() {
            if entry.seq >= positions {
                break;
            }
            let offered = match entry.kind.as_str() {
                OBJECTIVE => entry
                    .payload
                    .get("funder")
                    .and_then(Value::as_str)
                    .filter(|funder| *funder == identity)
                    .and_then(|_| entry.payload.get("reward").and_then(Value::as_u64))
                    .map(u128::from),
                AVAILABILITY_POOL => AvailabilityPool::from_value(&entry.payload)
                    .ok()
                    .filter(|pool| pool.funder == identity)
                    .map(|pool| pool.ceiling()),
                _ => None,
            };
            if let Some(offered) = offered {
                committed = committed.saturating_add(offered);
            }
        }
        committed
    }

    /// Disputes, re-derived rather than trusted.
    ///
    /// Deliberately parsed field by field out of `Value` instead of through a
    /// shared record type: this crate exists to be a second opinion on the
    /// *rules*, and sharing the primary's decoder would make the two agree
    /// about a malformed record by construction.
    ///
    /// No stepper runs here, and this crate has none. What it can check is
    /// everything the transcript decides on its own -- who may object, to what,
    /// by when, with what staked, and that every move opens the root its author
    /// committed to. Whether the disputed *step* reproduces is the one question
    /// that needs execution, and the primary's `audit --rerun` is where that
    /// belongs.
    fn audit_challenges(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let text = |value: &Value, key: &str| -> String {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };

        // Claims by id, so a challenge can be checked against what it disputes.
        let mut claims: BTreeMap<String, Value> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            claims.insert(entry.payload.digest(), entry.payload.clone());
        }

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut challenges: BTreeMap<String, Value> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(CHALLENGE) {
            let id = entry.payload.digest();
            challenges.insert(id.clone(), entry.payload.clone());
            let claim_id = text(&entry.payload, "claim_id");
            let challenger = text(&entry.payload, "challenger");
            if !seen.insert(format!("{claim_id}|{challenger}")) {
                problems.push(format!(
                    "entry {}: {} already has a live objection to claim {}",
                    entry.seq,
                    short(&challenger),
                    short(&claim_id)
                ));
            }
            if entry
                .payload
                .get("bond")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                == 0
            {
                problems.push(format!(
                    "entry {}: a challenge with no bond is a free objection",
                    entry.seq
                ));
            }
            let Some(claim) = claims.get(&claim_id) else {
                problems.push(format!(
                    "entry {}: challenges claim {}, which is not in this log",
                    entry.seq,
                    short(&claim_id)
                ));
                continue;
            };
            let artifact = claim.get("artifact").cloned().unwrap_or(Value::Null);
            let root = text(&artifact, "trace_root");
            let states = artifact
                .get("trace_states")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if root.is_empty() {
                problems.push(format!(
                    "entry {}: claim {} commits to no trace, so there is nothing to bisect",
                    entry.seq,
                    short(&claim_id)
                ));
                continue;
            }
            if root == text(&entry.payload, "root") {
                problems.push(format!(
                    "entry {}: the challenge agrees with the claim it disputes",
                    entry.seq
                ));
            }
            let challenged = entry
                .payload
                .get("states")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if states != challenged {
                problems.push(format!(
                    "entry {}: claim commits to {states} states, challenge to {challenged}",
                    entry.seq
                ));
            }
            // The window, from the two records' own timestamps.
            if let (Ok(opened), Ok(claimed)) = (
                self.epoch_of_ts("challenge", &text(&entry.payload, "created_at")),
                self.epoch_of_ts("claim", &text(claim, "created_at")),
            ) {
                let closes = claimed.saturating_add(CHALLENGE_WINDOW_EPOCHS);
                if opened > closes {
                    problems.push(format!(
                        "entry {}: opened in epoch {opened}, after the window on claim {} shut at {closes}",
                        entry.seq,
                        short(&claim_id)
                    ));
                }
            }
        }

        for entry in self.ledger.entries_of_kind(BISECTION) {
            let challenge_id = text(&entry.payload, "challenge_id");
            let Some(challenge) = challenges.get(&challenge_id) else {
                problems.push(format!(
                    "entry {}: no challenge {}",
                    entry.seq,
                    short(&challenge_id)
                ));
                continue;
            };
            let claim_id = text(challenge, "claim_id");
            let Some(claim) = claims.get(&claim_id) else {
                continue;
            };
            let mover = text(&entry.payload, "mover");
            let artifact = claim.get("artifact").cloned().unwrap_or(Value::Null);
            let root = if mover == text(claim, "submitter") {
                text(&artifact, "trace_root")
            } else if mover == text(challenge, "challenger") {
                text(challenge, "root")
            } else {
                problems.push(format!(
                    "entry {}: {} is not a party to {}",
                    entry.seq,
                    short(&mover),
                    short(&challenge_id)
                ));
                continue;
            };
            let states = artifact
                .get("trace_states")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let index = entry
                .payload
                .get("index")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let siblings: Vec<String> = entry
                .payload
                .get("path")
                .and_then(Value::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect();
            let leaf = entry
                .payload
                .get("state")
                .cloned()
                .unwrap_or(Value::Null)
                .digest();
            let path = crate::canonical::Inclusion {
                index,
                leaves: states,
                siblings,
            };
            // The check the whole game rests on: a party that could answer with
            // a state it never committed to would win every dispute by playing
            // whatever beats the other side this round.
            if !path.verify(&leaf, &root) {
                problems.push(format!(
                    "entry {}: the move at state {index} does not open the root its author committed to",
                    entry.seq
                ));
            }
        }

        let mut decided: BTreeSet<String> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(CHALLENGE_SETTLEMENT) {
            let id = text(&entry.payload, "challenge_id");
            if !decided.insert(id.clone()) {
                problems.push(format!(
                    "entry {}: challenge {} settled twice",
                    entry.seq,
                    short(&id)
                ));
            }
            let Some(challenge) = challenges.get(&id) else {
                problems.push(format!(
                    "entry {}: settles challenge {}, which is not in this log",
                    entry.seq,
                    short(&id)
                ));
                continue;
            };
            let claim_id = text(challenge, "claim_id");
            let Some(claim) = claims.get(&claim_id) else {
                continue;
            };
            let winner = text(&entry.payload, "winner");
            let loser = text(&entry.payload, "loser");
            let submitter = text(claim, "submitter");
            let challenger = text(challenge, "challenger");
            let parties = [submitter.as_str(), challenger.as_str()];
            if !parties.contains(&winner.as_str())
                || !parties.contains(&loser.as_str())
                || winner == loser
            {
                problems.push(format!(
                    "entry {}: settled between {} and {}, who are not the two parties",
                    entry.seq,
                    short(&winner),
                    short(&loser)
                ));
                continue;
            }
            let units = entry
                .payload
                .get("units")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let ceiling = if loser == challenger {
                challenge.get("bond").and_then(Value::as_u64).unwrap_or(0)
            } else {
                self.objective_of_claim(claim)
                    .and_then(|objective| objective.get("reward").and_then(Value::as_u64))
                    .unwrap_or(0)
            };
            if units > ceiling {
                problems.push(format!(
                    "entry {}: moved {units} against a ceiling of {ceiling}",
                    entry.seq
                ));
            }
        }

        problems
    }

    /// The epoch this log has settled up to, reading its first `positions`
    /// entries. Zero if nothing has settled yet, which keeps every bond live —
    /// the safe direction.
    fn settled_epoch_within(&self, positions: u64) -> u64 {
        self.ledger
            .entries_of_kind(BATCH)
            .into_iter()
            .filter(|entry| entry.seq < positions)
            .filter_map(|entry| entry.payload.get("epoch").and_then(Value::as_u64))
            .max()
            .unwrap_or(0)
    }

    /// Whether an attestation record is still open to a slash at settled epoch
    /// `now`. A `created_at` this crate cannot parse keeps the window open, so
    /// a malformed timestamp is never a way to release a bond early.
    fn attestation_window_open(&self, payload: &Value, now: u64) -> bool {
        let created = payload
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match self.epoch_of_ts("attestation", created) {
            Ok(opened) => now <= opened.saturating_add(ATTESTATION_WINDOW_EPOCHS),
            Err(_) => true,
        }
    }

    /// Bonded attestations, re-derived rather than trusted.
    ///
    /// **What this crate can and cannot check, stated rather than implied.**
    /// No verifier runs here and this crate has none, so whether an attestation
    /// is *true* is not a question it can ask — that is the primary's
    /// `audit --rerun`, and the run of the pinned checker is the whole of the
    /// evidence.
    ///
    /// Everything else the transcript decides on its own: who may stand behind
    /// what, once, under signature; that a slash names an attestation the log
    /// actually carries, and takes from the identity that made it, and takes
    /// exactly the bond. That last one matters most here. A slash moves fifty
    /// thousand units out of somebody's balance on a record anybody can append,
    /// and a second implementation that certified the log clean by not knowing
    /// about the record kind would be worse than one that never looked.
    fn audit_attestations(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let text = |value: &Value, key: &str| -> String {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let claims: BTreeSet<String> = self
            .ledger
            .entries_of_kind(CLAIM)
            .into_iter()
            .map(|entry| entry.payload.digest())
            .collect();

        let mut attestations: BTreeMap<String, Value> = BTreeMap::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(ATTESTATION) {
            let claim_id = text(&entry.payload, "claim_id");
            let attestor = text(&entry.payload, "attestor");
            let status = text(&entry.payload, "status");
            attestations.insert(entry.payload.digest(), entry.payload.clone());

            if !attestation_is_signed(&entry.payload) {
                problems.push(format!(
                    "entry {}: attestation by {} is not signed by the identity it names;                      an attestation nobody signed has nobody to slash, which makes it free",
                    entry.seq,
                    short(&attestor)
                ));
            }
            // `unavailable` says the attestor's machine could not run the
            // check, which is a fact about the attestor. Bonding it would put a
            // price on admitting a broken toolchain.
            if status != "accept" && status != "reject" {
                problems.push(format!(
                    "entry {}: attestation stands behind {status:?}, which is not a                      settling status and is not bondable",
                    entry.seq
                ));
            }
            if !seen.insert(format!("{claim_id}|{attestor}")) {
                problems.push(format!(
                    "entry {}: {} stood behind claim {} twice",
                    entry.seq,
                    short(&attestor),
                    short(&claim_id)
                ));
            }
            if !claims.contains(&claim_id) {
                problems.push(format!(
                    "entry {}: attests to claim {}, which is not in this log",
                    entry.seq,
                    short(&claim_id)
                ));
            }
            // Affordable at *this* point in the log, the way an undertaking's
            // bond is checked above. Neither conservation sum covers it: both
            // are whole-log totals, so an attestor that was broke here and paid
            // later balances exactly, and the bond it staked in between was
            // money it did not have.
            let spendable = self.spendable_within(&attestor, entry.seq);
            if u128::from(VERIFICATION_BOND) > spendable {
                problems.push(format!(
                    "entry {}: attestation bonds {VERIFICATION_BOND} units against a \
                     balance of {spendable}",
                    entry.seq
                ));
            }
        }

        let mut slashed: BTreeSet<String> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(VERIFICATION_SLASH) {
            let id = text(&entry.payload, "attestation_id");
            if !slashed.insert(id.clone()) {
                problems.push(format!(
                    "entry {}: attestation {} slashed twice",
                    entry.seq,
                    short(&id)
                ));
            }
            let Some(record) = attestations.get(&id) else {
                problems.push(format!(
                    "entry {}: slashes attestation {}, which is not in this log",
                    entry.seq,
                    short(&id)
                ));
                continue;
            };
            if text(&entry.payload, "attestor") != text(record, "attestor") {
                problems.push(format!(
                    "entry {}: takes a bond from an identity the attestation does not name",
                    entry.seq
                ));
            }
            if text(&entry.payload, "claim_id") != text(record, "claim_id") {
                problems.push(format!(
                    "entry {}: slashes an attestation about a different claim",
                    entry.seq
                ));
            }
            let units = entry
                .payload
                .get("units")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if units != VERIFICATION_BOND {
                problems.push(format!(
                    "entry {}: took {units} against a verification bond of {}",
                    entry.seq, VERIFICATION_BOND
                ));
            }
            if !self.attestation_window_open(record, self.settled_epoch_within(entry.seq)) {
                problems.push(format!(
                    "entry {}: slashes attestation {} after its window shut, when the \
                     bond had already returned",
                    entry.seq,
                    short(&id)
                ));
            }
        }
        problems
    }

    /// The objective record a claim names, as raw bytes.
    fn objective_of_claim(&self, claim: &Value) -> Option<Value> {
        let wanted = claim.get("objective_id").and_then(Value::as_str)?;
        self.ledger
            .entries_of_kind(OBJECTIVE)
            .into_iter()
            .find(|entry| entry.payload.digest() == wanted)
            .map(|entry| entry.payload.clone())
    }

    /// Conservation per identity **and per tier**, re-derived.
    ///
    /// The whole-balance check above is not enough on its own: an identity can
    /// hold exactly what it has promised in total while having promised units
    /// of a tier it never earned. That log balances and is still a forgery,
    /// because the promise it makes is one the units behind it cannot keep.
    ///
    /// Tiers are computed here from the objective records rather than read from
    /// a field, for the reason the primary does the same: a tier written down
    /// beside the verifier is a second place it can be wrong.
    ///
    /// Universal units — the genesis reserve, availability payouts, and both
    /// sides of a dispute slash — cover any tier. Everything a *settlement*
    /// mints is typed by its objective's verifier kind.
    fn audit_tiers(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if !self.declares_supply() {
            return problems;
        }
        let positions = self.ledger.entries().len() as u64;

        // Objective id -> (verifier kind, funder, reward).
        let mut objectives: BTreeMap<String, (String, String, u64)> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(OBJECTIVE) {
            let kind = entry
                .payload
                .get("verifier")
                .and_then(|verifier| verifier.get("kind"))
                .and_then(Value::as_str)
                .unwrap_or("certificate")
                .to_string();
            let funder = entry
                .payload
                .get("funder")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let reward = entry
                .payload
                .get("reward")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            objectives.insert(entry.payload.digest(), (kind, funder, reward));
        }

        // (identity, tier) -> held, and the same for committed. "universal" is
        // spelled out rather than being a variant, because this crate's job is
        // to agree with the other one's *answers*, not to share its types.
        let mut held: BTreeMap<(String, String), u128> = BTreeMap::new();
        let mut committed: BTreeMap<(String, String), u128> = BTreeMap::new();
        let mut credit = |who: &str, tier: &str, units: u128| {
            let slot = held.entry((who.to_string(), tier.to_string())).or_insert(0);
            *slot = slot.saturating_add(units);
        };

        let genesis = self.genesis_prefix();
        for entry in self.ledger.entries_of_kind(ISSUANCE) {
            if entry.seq >= genesis {
                continue;
            }
            if let (Some(holder), Some(units)) = (
                entry.payload.get("holder").and_then(Value::as_str),
                entry.payload.get("units").and_then(Value::as_u64),
            ) {
                credit(holder, "universal", u128::from(units));
            }
        }
        for entry in self.ledger.entries() {
            match entry.kind.as_str() {
                SETTLEMENT => {
                    let (Some(who), Some(reward)) = (
                        entry.payload.get("submitter").and_then(Value::as_str),
                        entry.payload.get("reward").and_then(Value::as_u64),
                    ) else {
                        continue;
                    };
                    let tier = entry
                        .payload
                        .get("objective_id")
                        .and_then(Value::as_str)
                        .and_then(|id| objectives.get(id))
                        .map(|(kind, _, _)| kind.clone())
                        .unwrap_or_else(|| "certificate".to_string());
                    credit(who, &tier, u128::from(reward));
                }
                AVAILABILITY_SETTLEMENT => {
                    for row in entry
                        .payload
                        .get("paid")
                        .and_then(Value::as_array)
                        .unwrap_or(&[])
                    {
                        if let (Some(who), Some(reward)) = (
                            row.get("identity").and_then(Value::as_str),
                            row.get("reward").and_then(Value::as_u64),
                        ) {
                            credit(who, "universal", u128::from(reward));
                        }
                    }
                }
                CHALLENGE_SETTLEMENT => {
                    let units = u128::from(
                        entry
                            .payload
                            .get("units")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                    );
                    if let Some(winner) = entry.payload.get("winner").and_then(Value::as_str) {
                        credit(winner, "universal", units);
                    }
                    if let Some(loser) = entry.payload.get("loser").and_then(Value::as_str) {
                        let slot = committed
                            .entry((loser.to_string(), "universal".to_string()))
                            .or_insert(0);
                        *slot = slot.saturating_add(units);
                    }
                }
                OBJECTIVE => {
                    if let Some((kind, funder, reward)) = objectives.get(&entry.payload.digest()) {
                        let slot = committed.entry((funder.clone(), kind.clone())).or_insert(0);
                        *slot = slot.saturating_add(u128::from(*reward));
                    }
                }
                _ => {}
            }
        }
        // Service bonds are universal. `committed_within` already resolves live
        // challenge bonds against the settlements that released them, so the
        // whole of it is reused rather than re-walked -- minus the objective
        // rewards, which are typed above.
        let mut names: BTreeSet<String> = BTreeSet::new();
        for (name, _) in held.keys() {
            names.insert(name.clone());
        }
        for (name, _) in committed.keys() {
            names.insert(name.clone());
        }
        for name in &names {
            let typed_rewards: u128 = objectives
                .values()
                .filter(|(_, funder, _)| funder == name)
                .map(|(_, _, reward)| u128::from(*reward))
                .fold(0u128, |sum, reward| sum.saturating_add(reward));
            let service = self
                .committed_within(name, positions)
                .saturating_sub(typed_rewards);
            let slot = committed
                .entry((name.clone(), "universal".to_string()))
                .or_insert(0);
            *slot = slot.saturating_add(service);
        }

        for name in names {
            let universal_held = held
                .get(&(name.clone(), "universal".to_string()))
                .copied()
                .unwrap_or(0);
            // Every tier's shortfall falls on the one pool that can cover it.
            let mut drawn = committed
                .get(&(name.clone(), "universal".to_string()))
                .copied()
                .unwrap_or(0);
            let mut shortfalls: Vec<String> = Vec::new();
            for tier in ["certificate", "evaluator", "lean", "replay", "statistical"] {
                let owes = committed
                    .get(&(name.clone(), tier.to_string()))
                    .copied()
                    .unwrap_or(0);
                let has = held
                    .get(&(name.clone(), tier.to_string()))
                    .copied()
                    .unwrap_or(0);
                if owes > has {
                    drawn = drawn.saturating_add(owes - has);
                    shortfalls.push(format!("{tier}: promised {owes} against {has} held"));
                }
            }
            if drawn > universal_held {
                problems.push(format!(
                    "{}: promises exceed holdings once tiers are kept apart ({}); \
                     units earned in one tier do not convert into another",
                    short(&name),
                    shortfalls.join("; ")
                ));
            }
        }
        problems
    }

    /// What the genesis prefix issued `identity`.
    ///
    /// Only the run of issuance records at the very front of the log counts. An
    /// issuance below it is a mint and is reported by [`Node::audit`] rather
    /// than credited, or the record that exists to make money scarce would be
    /// the cheapest way to make more. Position rather than a signature is what
    /// authorises it: in a log's opening bytes there is nobody else it could
    /// be.
    fn issued_within(&self, identity: &str, positions: u64) -> u128 {
        let mut issued = 0u128;
        for entry in self.ledger.entries() {
            if entry.kind != ISSUANCE || entry.seq >= positions {
                break;
            }
            if entry.payload.get("holder").and_then(Value::as_str) == Some(identity) {
                if let Some(units) = entry.payload.get("units").and_then(Value::as_u64) {
                    issued = issued.saturating_add(u128::from(units));
                }
            }
        }
        issued
    }

    /// Does this log declare a money supply? See [`Node::issued_within`].
    pub fn declares_supply(&self) -> bool {
        self.ledger
            .entries()
            .first()
            .is_some_and(|entry| entry.kind == ISSUANCE)
    }

    /// How many entries of this log are its genesis prefix.
    fn genesis_prefix(&self) -> u64 {
        self.ledger
            .entries()
            .iter()
            .take_while(|entry| entry.kind == ISSUANCE)
            .count() as u64
    }

    pub fn frontier_of(&self, objective_id: &str) -> Option<FrontierEntry> {
        // The *last* frontier entry wins: the log records every advance, and
        // the current holder is whoever moved it most recently.
        self.ledger
            .entries_of_kind(FRONTIER)
            .into_iter()
            .rfind(|entry| {
                entry.payload.get("objective_id").and_then(Value::as_str) == Some(objective_id)
            })
            .and_then(|entry| FrontierEntry::from_value(&entry.payload))
    }

    /// Claims whose recorded verdict is `accept`.
    pub fn accepted_claims(&self) -> BTreeMap<String, Claim> {
        let accepted: BTreeSet<String> = self
            .ledger
            .entries_of_kind(VERDICT)
            .into_iter()
            .filter(|entry| {
                entry
                    .payload
                    .get("verdict")
                    .and_then(|v| v.get("status"))
                    .and_then(Value::as_str)
                    == Some("accept")
            })
            .filter_map(|entry| {
                entry
                    .payload
                    .get("claim_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        let mut out = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            if let Ok(claim) = Claim::from_value(&entry.payload) {
                let id = claim.id();
                if accepted.contains(&id) {
                    out.insert(id, claim);
                }
            }
        }
        out
    }

    fn drained_epochs(&self) -> BTreeSet<u64> {
        self.ledger
            .entries_of_kind(BATCH)
            .into_iter()
            .filter_map(|entry| entry.payload.get("epoch").and_then(Value::as_u64))
            .collect()
    }

    /// Epochs holding accepted claims that can never be paid, because a later
    /// epoch settled first.
    ///
    /// Empty when the synchrony assumption behind
    /// [`FINALITY_EPOCHS`](crate::partition::FINALITY_EPOCHS) held. Non-empty
    /// means it did not: those records turned up after a later batch was
    /// written, and this node's payouts are a strict subset of what a peer
    /// that received them in time paid. Reported by `audit`, because a fork
    /// nobody is told about is the failure the delay exists to replace.
    pub fn late_epochs(&self) -> Vec<u64> {
        let drained = self.drained_epochs();
        let Some(floor) = drained.iter().copied().max() else {
            return Vec::new();
        };
        self.accepted_claims_by_epoch()
            .iter()
            .map(|(epoch, _)| *epoch)
            .filter(|epoch| *epoch <= floor && !drained.contains(epoch))
            .collect::<BTreeSet<u64>>()
            .into_iter()
            .collect()
    }

    /// The log head as of the epoch's *start*.
    ///
    /// Derived from the log rather than a clock, so an auditor reaches the
    /// same value. `positions` bounds the scan to the log as it stood at a
    /// given length, which is what stops a later back-dated append changing
    /// the anchor of a batch that already settled.
    /// The settlement anchor: the head of this log's **epoch chain**.
    ///
    /// Independently derived from the same rule the primary implements, and
    /// the rule is worth restating rather than referring to, since the point
    /// of this crate is that it does not read the other one.
    ///
    /// It used to be the hash of the last ledger entry before `epoch`, which
    /// broke the invariant multi-operator settlement depends on: two nodes
    /// holding the same records must pay in the same order. An entry hash
    /// covers `seq`, `prev` and the local write time, so two nodes with
    /// byte-identical records get different anchors, different beacons, and
    /// different orders -- while both logs audit clean, because each is
    /// internally consistent.
    ///
    /// The chain is content only. Each link commits to the link before it, the
    /// epoch, and the *sorted* claim ids of that batch -- sorted, so a link
    /// cannot depend on the ordering it is used to produce. It folds in **file
    /// order**, not epoch order, so a batch for an older epoch appended later
    /// leaves earlier links untouched instead of retroactively faulting them.
    ///
    /// A recorded `beacon` for `epoch` displaces the chain head entirely. The
    /// chain is what a sequencer can steer by choosing what to append, and
    /// steering it steers the settlement order; a beacon drawn somewhere the
    /// sequencer does not control is the point of the record. The chain
    /// remains the fallback, so every log written before beacons existed --
    /// including `launch/cairn.jsonl` -- derives exactly what it always
    /// did.
    ///
    /// `epoch` was unused when the head covered every batch written before
    /// this one. It is used now, because a beacon names the epoch it orders.
    fn anchor_of_epoch(&self, epoch: u64, positions: Option<usize>) -> String {
        if let Some(value) = self.epoch_beacon(epoch, positions) {
            return value;
        }
        let entries = self.ledger.entries();
        let entries = match positions {
            Some(limit) => &entries[..limit.min(entries.len())],
            None => entries,
        };
        let mut head = String::new();
        for entry in entries {
            if entry.kind != BATCH {
                continue;
            }
            // `u64`-range only, matching the primary. Folding a negative or
            // oversized epoch would put a link in the chain that nobody
            // recomputing `H({prev, epoch, claims})` from the published values
            // could reproduce.
            let Some(epoch) = entry
                .payload
                .get("epoch")
                .and_then(Value::as_i128)
                .filter(|value| u64::try_from(*value).is_ok())
            else {
                continue;
            };
            let mut claims: Vec<String> = match entry.payload.get("claims") {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect(),
                _ => Vec::new(),
            };
            claims.sort();
            head = Value::object(vec![
                ("prev", Value::string(head)),
                ("epoch", Value::Int(epoch)),
                (
                    "claims",
                    Value::Array(claims.into_iter().map(Value::String).collect()),
                ),
            ])
            .digest();
        }
        head
    }

    /// The beacon ordering `epoch`, if the log holds an admissible one.
    ///
    /// Two conditions, both re-derived here rather than trusted from whoever
    /// wrote the record, because this crate exists to check the other one
    /// rather than agree with it:
    ///
    /// - it must have been **written in the epoch it orders**. Written
    ///   earlier, the value exists while commitments for that epoch can still
    ///   be made, so a submitter can grind a commitment hash against a beacon
    ///   they already hold. Written later, whoever wrote it has already read
    ///   the reveals, and choosing the draw is choosing who is paid first.
    ///   Only a draw at the boundary is unknown to every committer and
    ///   unchosen by the writer.
    /// - there must be exactly **one**. Taking the first rather than the last
    ///   is what makes that so: a second record cannot displace the first, so
    ///   appending one buys no re-roll of the order. The audit reports the
    ///   duplicate; the reader must still be total on a log that contains one.
    ///
    /// An entry this crate cannot place in time does not order anything, for
    /// the same reason it does not move `anchor_at`: it is not evidence about
    /// where a boundary was.
    fn epoch_beacon(&self, epoch: u64, positions: Option<usize>) -> Option<String> {
        let entries = self.ledger.entries();
        let entries = match positions {
            Some(limit) => &entries[..limit.min(entries.len())],
            None => entries,
        };
        entries
            .iter()
            .filter(|entry| entry.kind == BEACON)
            .filter(|entry| {
                entry
                    .payload
                    .get("orders")
                    .and_then(Value::as_i128)
                    .and_then(|value| u64::try_from(value).ok())
                    == Some(epoch)
            })
            .filter(|entry| {
                unix_seconds(&entry.ts)
                    .is_some_and(|seconds| epoch_of(seconds, epoch_seconds()) == epoch)
            })
            .find_map(|entry| entry.payload.get("value").and_then(Value::as_str))
            .map(String::from)
    }

    /// The anchor of `epoch`, measuring epochs with an explicit length. The two
    /// callers need different ones -- see `sampled_index`.
    fn anchor_at(&self, epoch: u64, positions: Option<usize>, seconds_per_epoch: u64) -> String {
        let mut anchor = String::new();
        let entries = self.ledger.entries();
        let entries = match positions {
            Some(limit) => &entries[..limit.min(entries.len())],
            None => entries,
        };
        for entry in entries {
            // An entry this node cannot place in time is not evidence about
            // where the boundary was, so it does not move the anchor.
            if let Some(seconds) = unix_seconds(&entry.ts) {
                if epoch_of(seconds, seconds_per_epoch) < epoch {
                    anchor = entry.hash.clone();
                }
            }
        }
        anchor
    }

    /// A commitment by record id, with the position it sits at.
    fn commitment_at(&self, commitment_id: &str) -> Option<(usize, Commitment)> {
        self.ledger
            .entries_of_kind(COMMITMENT)
            .into_iter()
            .filter_map(|entry| {
                Commitment::from_value(&entry.payload)
                    .ok()
                    .map(|record| (entry.seq as usize, record))
            })
            .find(|(_, record)| record.id() == commitment_id)
    }

    /// Who holds a share of every submission sealed in `epoch`: the
    /// `COMMITTEE_SIZE` registered peers with the lowest
    /// `H(beacon(epoch, anchor) ‖ transport)`, as `(seat, transport, identity)`.
    ///
    /// Bounded at `positions` so a peer record appended later cannot join a
    /// committee that has already been sealed to, and one appended earlier
    /// cannot be evicted from it. Ranked on the **transport** id rather than
    /// the ed25519 identity because the transport id names the McEliece key a
    /// share is actually sealed to, and because grinding for a seat then costs
    /// a McEliece keypair rather than an ed25519 one.
    ///
    /// Tie-broken on the transport id as well as the rank: two peers with the
    /// same rank would otherwise keep map order, which is a lever back to
    /// whoever picks their key. A collision needs a SHA-256 preimage; that is
    /// not a reason to leave the order undefined.
    ///
    /// Returns fewer than `COMMITTEE_SIZE` seats when fewer peers are
    /// registered. The primary refuses to *draw* one that short — a smaller
    /// committee silently lowers the collusion threshold — but an audit is
    /// reading a log that already exists, and reporting "seat not drawn" for
    /// every share is the same finding said more usefully.
    fn committee_for(&self, epoch: u64, positions: usize) -> Vec<(u8, String, String)> {
        let size = self.committee_size_at(epoch, positions);
        self.committee_of_size(epoch, size, positions)
    }

    /// The draw itself, for a size somebody else picked.
    fn committee_of_size(
        &self,
        epoch: u64,
        size: u8,
        positions: usize,
    ) -> Vec<(u8, String, String)> {
        // `EPOCH_SECONDS`, the constant, never `epoch_seconds()`: the override
        // is a demo affordance, the anchor moves with the epoch length, and a
        // consensus rule keyed on an environment variable is not one.
        let anchor = self.anchor_at(epoch, Some(positions), crate::partition::EPOCH_SECONDS);

        let mut current: BTreeMap<String, PeerRecord> = BTreeMap::new();
        for entry in self.ledger.entries().iter().take(positions) {
            if entry.kind != PEER {
                continue;
            }
            let Ok(record) = PeerRecord::from_value(&entry.payload) else {
                continue;
            };
            if record.verify_signature().is_err() {
                continue;
            }
            match current.get(&record.identity) {
                Some(held) if held.seq > record.seq => {}
                _ => {
                    current.insert(record.identity.clone(), record);
                }
            }
        }

        let mut ranked: Vec<(String, PeerRecord)> = current
            .into_values()
            .map(|peer| (settlement_rank(epoch, &anchor, &peer.transport), peer))
            .collect();
        ranked.sort_by(|(ra, a), (rb, b)| (ra, &a.transport).cmp(&(rb, &b.transport)));
        ranked
            .into_iter()
            .take(usize::from(size))
            .enumerate()
            .map(|(i, (_, peer))| ((i as u8) + 1, peer.transport, peer.identity))
            .collect()
    }

    /// The committee size in force for `epoch`, derived independently.
    ///
    /// The primary's `Node::committee_size_at`, recomputed rather than trusted.
    /// This is the sharpest reason for a second implementation to exist: the
    /// draw is consensus, so a crate that kept using a fixed five while the
    /// other grew the committee would disagree about which published shares came
    /// from a seat that exists — and would say so about an honest member.
    ///
    /// Derived from the epoch's boundary prefix, so it is fixed before the
    /// epoch's first record and every reader gets the same number.
    fn committee_size_at(&self, epoch: u64, positions: usize) -> u8 {
        let boundary = self.epoch_boundary(epoch, positions);
        let peers = self.peers_within(boundary);
        let floor = COMMITTEE_SIZE;
        if peers <= usize::from(floor) {
            return floor;
        }
        let carried = self.sealed_value_in(epoch.saturating_sub(1), boundary);
        if carried == 0 {
            return floor;
        }
        let ceiling = crate::partition::MAX_COMMITTEE_SIZE.min(peers.min(255) as u8);
        let mut size = floor;
        while size < ceiling {
            if self.custody_guard(epoch, size, positions) >= carried {
                return size;
            }
            size = size.saturating_add(1);
        }
        size
    }

    /// How many entries the log held strictly before `epoch` began.
    fn epoch_boundary(&self, epoch: u64, positions: usize) -> usize {
        let mut boundary = 0;
        for (index, entry) in self.ledger.entries().iter().take(positions).enumerate() {
            match crate::time::parse_rfc3339(&entry.ts) {
                Some(seconds)
                    if seconds >= 0
                        && epoch_of(seconds as u64, crate::partition::EPOCH_SECONDS) < epoch =>
                {
                    boundary = index + 1;
                }
                _ => continue,
            }
        }
        boundary
    }

    /// Distinct peer identities registered below `positions`.
    fn peers_within(&self, positions: usize) -> usize {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for entry in self.ledger.entries().iter().take(positions) {
            if entry.kind != PEER {
                continue;
            }
            let Ok(record) = PeerRecord::from_value(&entry.payload) else {
                continue;
            };
            if record.verify_signature().is_err() {
                continue;
            }
            seen.insert(record.identity);
        }
        seen.len()
    }

    /// The value one epoch's committee could take by opening early: the sum
    /// over every sealed commitment in it.
    fn sealed_value_in(&self, epoch: u64, positions: usize) -> u128 {
        let mut total = 0u128;
        for entry in self.ledger.entries().iter().take(positions) {
            if entry.kind != COMMITMENT || entry.payload.get("envelope").is_none() {
                continue;
            }
            let Some(created) = entry.payload.get("created_at").and_then(Value::as_str) else {
                continue;
            };
            let Ok(at) = self.epoch_of_ts("commitment", created) else {
                continue;
            };
            if at != epoch {
                continue;
            }
            let Some(wanted) = entry.payload.get("objective_id").and_then(Value::as_str) else {
                continue;
            };
            if let Some(reward) = self
                .ledger
                .entries_of_kind(OBJECTIVE)
                .into_iter()
                .find(|objective| objective.payload.digest() == wanted)
                .and_then(|objective| objective.payload.get("reward").and_then(Value::as_u64))
            {
                total = total.saturating_add(u128::from(reward));
            }
        }
        total
    }

    /// `d * (sum of the threshold smallest stakes among the drawn seats)`.
    ///
    /// A cartel forms out of the **cheapest** `t` members, so the sum of the `t`
    /// smallest is what it risks — not `t` times an average, which with one rich
    /// member and four poor ones reports a committee as safe that is not.
    fn custody_guard(&self, epoch: u64, size: u8, positions: usize) -> u128 {
        let boundary = self.epoch_boundary(epoch, positions) as u64;
        let seats = self.committee_of_size(epoch, size, positions);
        if seats.len() < usize::from(size) {
            return 0;
        }
        let mut stakes: Vec<u128> = seats
            .iter()
            .map(|(_, _, identity)| self.spendable_within(identity, boundary))
            .collect();
        stakes.sort_unstable();
        let threshold = usize::from(crate::partition::threshold_for(size));
        let cheapest: u128 = stakes
            .iter()
            .take(threshold)
            .fold(0u128, |sum, stake| sum.saturating_add(*stake));
        cheapest
            .saturating_mul(crate::partition::DETECTION_NUM)
            .saturating_div(crate::partition::DETECTION_DEN)
    }

    /// Which entry this undertaking must produce in `epoch`.
    ///
    /// A pure function of the log: nobody issues this challenge and nobody has
    /// to receive it, so nobody can decline to. `assign` is reused rather than
    /// reimplemented because `conformance/vectors.json` pins it, which is what
    /// makes the two implementations agree about which entry was asked for.
    ///
    /// `None` when the height is outside what the format allows. This crate's
    /// `assign` reduces modulo a `u64` where the primary's takes a `u32`, which
    /// is a difference that must not become a disagreement: below
    /// `MAX_UNDERTAKING_HEIGHT` both reduce the same eight MAC bytes modulo the
    /// same number, and the bound is re-checked here rather than assumed from
    /// the decoder so the two stay pinned together even if one is called with a
    /// record the other would not have accepted.
    fn sampled_index(
        &self,
        undertaking: &Undertaking,
        epoch: u64,
        positions: usize,
    ) -> Option<u64> {
        if undertaking.height == 0 || undertaking.height > MAX_UNDERTAKING_HEIGHT {
            return None;
        }
        // `EPOCH_SECONDS`, the constant, never the `CAIRN_EPOCH_SECONDS`
        // override: that is a demo affordance, and a demo affordance must not
        // decide whether a record is admissible. Reading it here made the same
        // log audit clean or dirty depending on an environment variable --
        // measured at six failures in ten.
        // Bounded by *position*, the same way a batch's anchor is: unbounded,
        // the anchor is the last entry the whole log holds, so every later
        // append moves the sampled index and an answer that was right when it
        // was written becomes wrong two entries later.
        let beacon = beacon(
            epoch,
            &self.anchor_at(epoch, Some(positions), crate::partition::EPOCH_SECONDS),
        );
        assign(
            &undertaking.identity,
            &undertaking.id(),
            &beacon,
            undertaking.height,
        )
        .ok()
    }

    fn accepted_claims_by_epoch(&self) -> Vec<(u64, Claim)> {
        self.accepted_claims_by_epoch_within(None)
    }

    /// The same, as the log stood at `positions` entries.
    ///
    /// `None` means the whole log, which is what settling wants -- it is
    /// deciding what to pay *now*. Auditing a batch wants the bound, because a
    /// record appended after the batch could not have influenced it whatever
    /// timestamp it carries.
    fn accepted_claims_by_epoch_within(&self, positions: Option<usize>) -> Vec<(u64, Claim)> {
        let entries = self.ledger.entries();
        let entries = match positions {
            Some(limit) => &entries[..limit.min(entries.len())],
            None => entries,
        };

        // The verdicts carry the bound too, not only the claims. A claim
        // already in the log when a batch was written, whose accepting verdict
        // arrived afterwards, was correctly left out of that batch -- counting
        // it now faults an honest batch exactly as a back-dated claim would.
        let mut accepted: BTreeSet<String> = BTreeSet::new();
        for entry in entries.iter().filter(|entry| entry.kind == VERDICT) {
            let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
                continue;
            };
            let is_accept = entry
                .payload
                .get("verdict")
                .and_then(|v| v.get("status"))
                .and_then(Value::as_str)
                == Some("accept");
            if is_accept {
                accepted.insert(claim_id.to_string());
            } else {
                // A later verdict supersedes an earlier one, a withdrawal of
                // acceptance included.
                accepted.remove(claim_id);
            }
        }

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        for entry in entries.iter().filter(|entry| entry.kind == CLAIM) {
            let Ok(claim) = Claim::from_value(&entry.payload) else {
                continue;
            };
            let id = claim.id();
            if !accepted.contains(&id) || !seen.insert(id) {
                continue;
            }
            let Some(seconds) = unix_seconds(&entry.ts) else {
                continue;
            };
            out.push((epoch_of(seconds, epoch_seconds()), claim));
        }
        out
    }

    fn artifact_ids_before(&self, objective_id: &str, epoch: u64) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            let Some(seconds) = unix_seconds(&entry.ts) else {
                continue;
            };
            if epoch_of(seconds, epoch_seconds()) >= epoch {
                continue;
            }
            if let Ok(claim) = Claim::from_value(&entry.payload) {
                if claim.objective_id == objective_id {
                    out.insert(claim.artifact_id());
                }
            }
        }
        out
    }

    fn matching_commitment(&self, claim: &Claim) -> Option<Value> {
        let target = claim.commitment_hash();
        self.ledger
            .entries_of_kind(COMMITMENT)
            .into_iter()
            .find(|entry| {
                let payload = &entry.payload;
                payload.get("objective_id").and_then(Value::as_str) == Some(&claim.objective_id)
                    && payload.get("submitter").and_then(Value::as_str) == Some(&claim.submitter)
                    && payload.get("hash").and_then(Value::as_str) == Some(target.as_str())
            })
            .map(|entry| entry.payload.clone())
    }

    fn recorded_verdict(&self, claim_id: &str) -> Option<Verdict> {
        self.ledger
            .entries_of_kind(VERDICT)
            .into_iter()
            .rfind(|entry| entry.payload.get("claim_id").and_then(Value::as_str) == Some(claim_id))
            .and_then(|entry| entry.payload.get("verdict").and_then(Verdict::from_value))
    }

    // -- writes ----------------------------------------------------------

    pub fn post_objective(&mut self, objective: &Objective, ts: &str) -> Result<String, String> {
        let kind = objective
            .verifier_kind()
            .ok_or("objective needs a verifier with a 'kind'")?;
        // Asked of the verifier module rather than answered from a list kept
        // here. The list kept here went stale -- it still named two kinds after
        // three more were implemented, so this crate refused to post
        // objectives it could verify perfectly well, and every interop round
        // for those kinds could only run in one direction.
        if !verifiers::implements(kind) {
            return Err(format!(
                "this reference implements {}; kind {kind:?} is not one",
                verifiers::KINDS.join(", ")
            ));
        }
        let id = objective.id();
        if self.objectives().contains_key(&id) {
            return Err("objective already posted".into());
        }
        if let Some(block) = &objective.ratchet {
            let ratchet = Ratchet::from_value(block)?;
            if kind != "evaluator" {
                return Err("a ratchet objective needs a score-producing verifier".into());
            }
            if ratchet.reward != objective.reward {
                return Err("ratchet reward and objective reward disagree".into());
            }
        }
        self.ledger.append(OBJECTIVE, objective.to_value(), ts)?;
        Ok(id)
    }

    pub fn commit(&mut self, commitment: &Commitment, ts: &str) -> Result<String, String> {
        commitment.verify_signature().map_err(|e| e.to_string())?;
        let declared = self.epoch_of_ts("commitment", &commitment.created_at)?;
        let now = self.epoch_of_ts("commit", ts)?;
        if declared != now {
            return Err(format!(
                "commitment declares epoch {declared} but was admitted in epoch {now}; \
                 commit-reveal ordering uses the admission epoch"
            ));
        }
        self.settle_due(now, ts)?;

        let objectives = self.objectives();
        let objective = objectives
            .get(&commitment.objective_id)
            .ok_or("commitment references an unknown objective")?;
        if objective.require_signed_submitter && signed_submitter(&commitment.submitter).is_none() {
            return Err(format!(
                "objective {} accepts only signed identities, and {:?} is not one",
                short(&commitment.objective_id),
                commitment.submitter
            ));
        }
        // A progressive objective stays open after a settlement; a pass/fail
        // one does not.
        if objective.ratchet.is_none() && self.settlement_of(&commitment.objective_id).is_some() {
            return Err("objective already settled".into());
        }
        let entry = self.ledger.append(COMMITMENT, commitment.to_value(), ts)?;
        Ok(entry.hash)
    }

    pub fn reveal(&mut self, claim: &Claim, ts: &str) -> Result<Outcome, String> {
        claim.verify_signature().map_err(|e| e.to_string())?;
        let reveal_epoch = self.epoch_of_ts("reveal", ts)?;
        // Drain first: an epoch that closed while this node was idle must
        // settle before this claim's checks read the frontier, or an
        // improvement would be measured against a stale one.
        self.settle_due(reveal_epoch, ts)?;

        let objectives = self.objectives();
        let objective = objectives
            .get(&claim.objective_id)
            .ok_or("claim references an unknown objective")?
            .clone();

        if objective.require_signed_submitter && signed_submitter(&claim.submitter).is_none() {
            return Err(format!(
                "objective {} accepts only signed identities, and {:?} is not one",
                short(&claim.objective_id),
                claim.submitter
            ));
        }
        let commitment = self
            .matching_commitment(claim)
            .ok_or("no matching prior commitment: commit H(artifact‖submitter‖nonce) first")?;
        let created_at = commitment
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let commit_epoch = self.epoch_of_ts("commitment", created_at)?;
        // Strictly later, so the reveal that would be copied is public before
        // a competitor's commitment can be written.
        if reveal_epoch <= commit_epoch {
            return Err(format!(
                "reveal is in epoch {reveal_epoch} but its commitment is in epoch \
                 {commit_epoch}; a reveal must wait for a strictly later epoch"
            ));
        }
        if self.drained_epochs().contains(&reveal_epoch) {
            return Err(format!(
                "epoch {reveal_epoch} has already settled; a reveal cannot join a batch \
                 that has been paid"
            ));
        }
        let accepted = self.accepted_claims();
        for cited in &claim.cites {
            if !accepted.contains_key(cited) {
                return Err(format!(
                    "citation {cited} is not an accepted claim in this log; citations point \
                     backwards only"
                ));
            }
        }
        // A relation's target must already be in the log -- but, unlike a
        // citation, it need *not* be accepted: refuting a claim the verifier
        // rejected is a legitimate thing to record. Existence only, so that
        // admission stays a consensus rule and how much an assertion counts
        // for stays a reader's question.
        if !claim.relations.is_empty() {
            let known: BTreeSet<String> = self
                .ledger
                .entries_of_kind(CLAIM)
                .into_iter()
                .filter_map(|entry| Claim::from_value(&entry.payload).ok().map(|c| c.id()))
                .collect();
            for relation in &claim.relations {
                if !known.contains(&relation.target) {
                    return Err(format!(
                        "relation target {} is not a claim in this log; relations point \
                         backwards only",
                        relation.target
                    ));
                }
            }
        }
        // Once a frontier exists on a ratcheted objective, *every* claim must
        // cite the holder -- not only improvements.
        if objective.ratchet.is_some() {
            if let Some(held) = self.frontier_of(&claim.objective_id) {
                if !claim.cites.contains(&held.claim_id) {
                    return Err(format!(
                        "an improvement must cite the frontier it improves on ({})",
                        held.claim_id
                    ));
                }
            }
        }

        let claim_id = claim.id();
        self.ledger.append(CLAIM, claim.to_value(), ts)?;
        let verdict = verifiers::run(&self.root, &objective.verifier, &claim.artifact);
        self.ledger.append(
            VERDICT,
            Value::object([
                ("claim_id", Value::string(claim_id.clone())),
                ("objective_id", Value::string(claim.objective_id.clone())),
                ("verdict", verdict.to_value()),
            ]),
            ts,
        )?;

        let note = if !verdict.status.settles() {
            "verdict does not settle"
        } else if !verdict.accepted() {
            "rejected"
        } else {
            return Ok(Outcome {
                claim_id,
                verdict,
                settled: false,
                reward: 0,
                note: format!(
                    "accepted; settles once epoch {reveal_epoch} closes and clears the {}-epoch finality delay",
                    crate::partition::finality_epochs()
                ),
                pending_epoch: Some(reveal_epoch),
            });
        };
        Ok(Outcome {
            claim_id,
            verdict,
            settled: false,
            reward: 0,
            note: note.to_string(),
            pending_epoch: None,
        })
    }

    /// Settle every reveal epoch that has closed and waited out the finality
    /// delay, in beacon order, oldest first.
    ///
    /// Three filters. Closed (`epoch < now_epoch`), because an open epoch can
    /// still take reveals. Final (`epoch + finality_epochs() < now_epoch`), so
    /// eligibility depends on the clock rather than on when this node happened
    /// to hear about the work. And newer than anything already paid, because
    /// an epoch settling after a later one would be anchored on a chain head
    /// that already contains that later epoch -- reordering payouts an auditor
    /// has already read. Those are refused and surface in [`Self::late_epochs`].
    pub fn settle_due(&mut self, now_epoch: u64, ts: &str) -> Result<Vec<Outcome>, String> {
        let drained = self.drained_epochs();
        let floor = drained.iter().copied().max();
        let delay = crate::partition::finality_epochs();
        let pending = self.accepted_claims_by_epoch();
        let due: BTreeSet<u64> = pending
            .iter()
            .map(|(epoch, _)| *epoch)
            .filter(|epoch| !drained.contains(epoch))
            .filter(|epoch| epoch.saturating_add(delay) < now_epoch)
            .filter(|epoch| floor.is_none_or(|settled| *epoch > settled))
            .collect();

        let mut outcomes = Vec::new();
        for epoch in due {
            let anchor = self.anchor_of_epoch(epoch, None);
            let mut batch: Vec<Claim> = pending
                .iter()
                .filter(|(candidate, _)| *candidate == epoch)
                .map(|(_, claim)| claim.clone())
                .collect();
            // Keyed on the *commitment* hash, not the claim id: by reveal time
            // the anchor is public, and a claim id covers `created_at` and
            // `cites`, which a submitter could re-roll until one sorted first.
            // Ties break on the id so append order never leaks back in.
            batch.sort_by_key(|claim| {
                (
                    settlement_rank(epoch, &anchor, &claim.commitment_hash()),
                    claim.id(),
                )
            });
            let mut consumed: BTreeSet<String> = BTreeSet::new();
            let mut order = Vec::with_capacity(batch.len());
            for claim in batch {
                order.push(Value::string(claim.id()));
                outcomes.push(self.settle_one(&claim, epoch, &consumed, ts)?);
                consumed.insert(claim.artifact_id());
            }
            self.ledger.append(
                BATCH,
                Value::object([
                    ("epoch", Value::Int(i128::from(epoch))),
                    ("anchor", Value::string(anchor)),
                    ("claims", Value::Array(order)),
                ]),
                ts,
            )?;
        }
        Ok(outcomes)
    }

    pub fn settle_at(&mut self, ts: &str) -> Result<Vec<Outcome>, String> {
        let now = self.epoch_of_ts("settle", ts)?;
        self.settle_due(now, ts)
    }

    fn settle_one(
        &mut self,
        claim: &Claim,
        epoch: u64,
        consumed: &BTreeSet<String>,
        ts: &str,
    ) -> Result<Outcome, String> {
        let claim_id = claim.id();
        let verdict = self.recorded_verdict(&claim_id).unwrap_or_else(|| {
            Verdict::new(
                Status::Accept,
                "recorded acceptance",
                Value::object(Vec::<(String, Value)>::new()),
            )
        });
        let objectives = self.objectives();
        let Some(objective) = objectives.get(&claim.objective_id).cloned() else {
            return Ok(unsettled(
                claim_id,
                verdict,
                "objective is no longer readable",
            ));
        };

        if let Some(block) = &objective.ratchet {
            // A single bad objective must not wedge settlement for every other
            // objective in the same epoch, so this is an unsettled outcome
            // rather than an error.
            let Ok(ratchet) = Ratchet::from_value(block) else {
                return Ok(unsettled(
                    claim_id,
                    verdict,
                    "objective carries an unusable ratchet",
                ));
            };
            let held = self.frontier_of(&claim.objective_id);
            return self.settle_improvement(claim, verdict, &ratchet, held, ts);
        }

        let artifact_id = claim.artifact_id();
        if consumed.contains(&artifact_id)
            || self
                .artifact_ids_before(&claim.objective_id, epoch)
                .contains(&artifact_id)
        {
            return Ok(unsettled(
                claim_id,
                verdict,
                "duplicate artifact mints nothing",
            ));
        }
        if self.settlement_of(&claim.objective_id).is_some() {
            return Ok(unsettled(claim_id, verdict, "objective already settled"));
        }
        self.ledger.append(
            SETTLEMENT,
            Value::object([
                ("objective_id", Value::string(claim.objective_id.clone())),
                ("claim_id", Value::string(claim_id.clone())),
                ("submitter", Value::string(claim.submitter.clone())),
                ("reward", Value::Int(i128::from(objective.reward))),
            ]),
            ts,
        )?;
        Ok(Outcome {
            claim_id,
            verdict,
            settled: true,
            reward: objective.reward,
            note: "settled".into(),
            pending_epoch: None,
        })
    }

    fn settle_improvement(
        &mut self,
        claim: &Claim,
        verdict: Verdict,
        ratchet: &Ratchet,
        held: Option<FrontierEntry>,
        ts: &str,
    ) -> Result<Outcome, String> {
        let claim_id = claim.id();
        let Some(score) = verdict.score() else {
            return Ok(unsettled(
                claim_id,
                verdict,
                "verifier produced no integer score",
            ));
        };
        let previous = held.as_ref().map(|held| held.score);
        if !ratchet.improves(previous, score) {
            return Ok(unsettled(
                claim_id,
                verdict,
                &format!(
                    "score {score} does not improve on {previous:?} by at least {}",
                    ratchet.min_improvement
                ),
            ));
        }
        let reward = ratchet.payout(previous, score);
        let paid_cumulative = held.as_ref().map_or(0, |held| held.paid_cumulative) + reward;
        self.ledger.append(
            FRONTIER,
            FrontierEntry {
                objective_id: claim.objective_id.clone(),
                claim_id: claim_id.clone(),
                holder: claim.submitter.clone(),
                score,
                paid_cumulative,
            }
            .to_value(),
            ts,
        )?;
        if reward > 0 {
            self.ledger.append(
                SETTLEMENT,
                Value::object([
                    ("objective_id", Value::string(claim.objective_id.clone())),
                    ("claim_id", Value::string(claim_id.clone())),
                    ("submitter", Value::string(claim.submitter.clone())),
                    ("reward", Value::Int(i128::from(reward))),
                ]),
                ts,
            )?;
        }
        Ok(Outcome {
            claim_id,
            verdict,
            settled: reward > 0,
            reward,
            note: if reward > 0 {
                "frontier advanced".into()
            } else {
                "verified but paid nothing".into()
            },
            pending_epoch: None,
        })
    }

    // -- audit -----------------------------------------------------------

    /// Re-derive everything the log claims, from the artifacts themselves.
    pub fn audit(&self, rerun: bool) -> Vec<String> {
        let mut problems = self.ledger.verify_chain();
        let objectives = self.objectives();

        // Every record must decode and re-encode to its own bytes, and carry a
        // valid signature when its submitter names a key.
        for entry in self.ledger.entries() {
            let re_encoded = match entry.kind.as_str() {
                OBJECTIVE => Objective::from_value(&entry.payload)
                    .map(|r| r.to_value())
                    .map_err(|e| e.to_string()),
                COMMITMENT => Commitment::from_value(&entry.payload)
                    .and_then(|r| {
                        r.verify_signature()?;
                        Ok(r.to_value())
                    })
                    .map_err(|e| e.to_string()),
                CLAIM => Claim::from_value(&entry.payload)
                    .and_then(|r| {
                        r.verify_signature()?;
                        Ok(r.to_value())
                    })
                    .map_err(|e| e.to_string()),
                // A peer record settles nothing, so a bad one cannot cost
                // money -- but a reader must be told rather than left to
                // wonder why a peer the log names is never dialled.
                PEER => PeerRecord::from_value(&entry.payload)
                    .and_then(|r| {
                        r.verify_signature()?;
                        Ok(r.to_value())
                    })
                    .map_err(|e| e.to_string()),
                // A committee share settles nothing directly -- the claim it
                // opens is an ordinary claim and re-derives the same way -- but
                // it is the evidence that a reveal happened without the
                // submitter, and evidence nobody checks is decoration.
                COMMITTEE_SHARE => CommitteeShare::from_value(&entry.payload)
                    .and_then(|r| {
                        r.validate()?;
                        r.verify_signature()?;
                        Ok(r.to_value())
                    })
                    .map_err(|e| e.to_string()),
                _ => continue,
            };
            match re_encoded {
                Ok(value) if value == entry.payload => {}
                Ok(_) => problems.push(format!(
                    "entry {}: {} does not re-encode to its own bytes",
                    entry.seq, entry.kind
                )),
                Err(error) => problems.push(format!("entry {}: {error}", entry.seq)),
            }
        }

        // Committee shares, beyond the structural pass above: the seat must be
        // one the epoch's draw actually produced, held by the identity that
        // signed, published in an epoch strictly later than the commitment's.
        //
        // Ported for the reason every rule here is ported -- an admission rule
        // one implementation applies and the other does not is a rule two nodes
        // disagree about while both report a clean log. This one guards the
        // reveal path that runs *without the submitter*, so a share nobody
        // checks is a claim somebody was paid for on evidence that does not
        // hold up.
        let mut committee_seats: BTreeSet<(String, u8)> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(COMMITTEE_SHARE) {
            let record = match CommitteeShare::from_value(&entry.payload) {
                Ok(record) => record,
                // Already reported by the re-encode pass, with the decoder's
                // own message.
                Err(_) => continue,
            };
            if record.validate().is_err() || record.verify_signature().is_err() {
                continue;
            }
            let at = entry.seq as usize;
            let Some((commit_at, commitment)) = self.commitment_at(&record.commitment) else {
                problems.push(format!(
                    "entry {}: committee_share names commitment {} which is not in this log",
                    entry.seq,
                    short(&record.commitment)
                ));
                continue;
            };
            if commitment.envelope.is_none() {
                problems.push(format!(
                    "entry {}: committee_share opens commitment {}, which carries no envelope",
                    entry.seq,
                    short(&record.commitment)
                ));
                continue;
            }
            if at >= entry.seq as usize {
                problems.push(format!(
                    "entry {}: committee_share precedes the commitment it opens",
                    entry.seq
                ));
                continue;
            }
            let (Some(commit_seconds), Some(share_seconds)) = (
                unix_seconds(&commitment.created_at),
                unix_seconds(&record.created_at),
            ) else {
                problems.push(format!(
                    "entry {}: committee_share or its commitment carries an unreadable timestamp",
                    entry.seq
                ));
                continue;
            };
            let commit_epoch = epoch_of(commit_seconds, epoch_seconds());
            let share_epoch = epoch_of(share_seconds, epoch_seconds());
            // An embargo is this rule with a longer arm. A committee share is
            // what opens a sealed artifact, so an objective that declared
            // "revealed after N epochs" is enforced here or nowhere -- and
            // derived here independently, because an embargo the two
            // implementations disagreed about is a committee opening an
            // artifact one of them still thinks is shut.
            let embargo = self
                .objectives()
                .get(&commitment.objective_id)
                .filter(|objective| objective.confidentiality == "embargoed")
                .and_then(|objective| objective.embargo_epochs)
                .unwrap_or(0);
            let opens_at = commit_epoch.saturating_add(embargo);
            if share_epoch <= opens_at {
                problems.push(format!(
                    "entry {}: committee_share is in epoch {share_epoch} but its commitment \
                     opens at epoch {opens_at}; a committee must wait for a strictly later \
                     epoch, and longer still under an embargo",
                    entry.seq
                ));
                continue;
            }
            match self
                .committee_for(commit_epoch, commit_at)
                .iter()
                .find(|(seat, _, _)| *seat == record.seat)
            {
                None => problems.push(format!(
                    "entry {}: seat {} was not drawn for commitment {}",
                    entry.seq,
                    record.seat,
                    short(&record.commitment)
                )),
                Some((_, _, identity)) if *identity != record.identity => {
                    problems.push(format!(
                        "entry {}: seat {} of commitment {} belongs to another identity",
                        entry.seq,
                        record.seat,
                        short(&record.commitment)
                    ));
                }
                Some(_) => {}
            }
            if !committee_seats.insert((record.commitment.clone(), record.seat)) {
                problems.push(format!(
                    "entry {}: seat {} of commitment {} published twice",
                    entry.seq,
                    record.seat,
                    short(&record.commitment)
                ));
            }
        }

        // Availability. Ported because an audit that skips a record kind
        // certifies it: this crate reported "log verified" over a log full of
        // availability settlements without checking one of them, which is the
        // same drift that let `println!` survive here after the primary had
        // fixed it -- an independent implementation stays honest only where
        // something compares it.
        let promises: BTreeMap<String, Undertaking> = self
            .ledger
            .entries_of_kind(UNDERTAKING)
            .into_iter()
            // `seq` is the number of entries below the record, which is the
            // height it was required to name: a promise covers the whole log
            // as it stood, because a promiser who could choose promised one
            // entry and took a full share.
            .filter_map(|entry| {
                Undertaking::from_value(&entry.payload)
                    .ok()
                    .filter(|record| record.height == entry.seq)
            })
            .filter(|record| record.verify_signature().is_ok())
            .filter(|record| {
                usize::try_from(record.height)
                    .ok()
                    .and_then(|height| self.ledger.root_at(height))
                    .as_deref()
                    == Some(record.root.as_str())
            })
            .map(|record| (record.id(), record))
            .collect();

        // The money supply, derived here rather than taken from the primary's
        // word. Two faults: a mint below the genesis prefix, and an identity
        // that has committed more than the log says it holds. Together they are
        // the statement that no unit exists which the supply did not issue —
        // and without them every other number here is weighed in a currency
        // anyone can make.
        let genesis = self.genesis_prefix();
        for entry in self.ledger.entries_of_kind(ISSUANCE) {
            if entry.seq < genesis {
                continue;
            }
            problems.push(format!(
                "entry {}: issues units after the genesis prefix ended at entry \
                 {genesis}; a supply is declared in a log's opening entries or it is \
                 not a supply",
                entry.seq
            ));
        }
        if self.declares_supply() {
            let positions = self.ledger.entries().len() as u64;
            let mut names: BTreeSet<String> = BTreeSet::new();
            for entry in self.ledger.entries() {
                for key in ["holder", "funder", "submitter", "identity"] {
                    if let Some(name) = entry.payload.get(key).and_then(Value::as_str) {
                        names.insert(name.to_string());
                    }
                }
            }
            // `spendable_within` saturates at zero, so it cannot report an
            // overdraft on its own. Recomputing the two sides here is the point
            // of a second implementation: the primary reports the same fault
            // from its own arithmetic, and the two agreeing is evidence.
            for name in names {
                let holds = self.held_within(&name, positions);
                let owes = self.committed_within(&name, positions);
                if owes > holds {
                    problems.push(format!(
                        "{} has committed {owes} units against {holds} issued or paid; \
                         a unit nobody issued is money made by naming it",
                        short(&name)
                    ));
                }
            }
        }

        problems.append(&mut self.audit_challenges());
        problems.append(&mut self.audit_attestations());
        problems.append(&mut self.audit_tiers());

        for entry in self.ledger.entries_of_kind(UNDERTAKING) {
            match Undertaking::from_value(&entry.payload) {
                Err(error) => problems.push(format!("entry {}: {error}", entry.seq)),
                Ok(record) => {
                    if let Err(error) = record.verify_signature() {
                        problems.push(format!("entry {}: {error}", entry.seq));
                    } else if record.height != entry.seq {
                        problems.push(format!(
                            "entry {}: undertaking promises {} entries where the log below \
                             it had {}; the size of a promise is not the promiser's to choose",
                            entry.seq, record.height, entry.seq
                        ));
                    } else if u128::from(record.bond)
                        > self.spendable_within(&record.identity, entry.seq)
                    {
                        problems.push(format!(
                            "entry {}: undertaking bonds {} units against a balance of {}",
                            entry.seq,
                            record.bond,
                            self.spendable_within(&record.identity, entry.seq)
                        ));
                    } else if !promises.contains_key(&record.id()) {
                        problems.push(format!(
                            "entry {}: undertaking names {} entries rooted at {}, which no \
                             prefix of this log is",
                            entry.seq,
                            record.height,
                            short(&record.root)
                        ));
                    }
                }
            }
        }

        let mut answered: BTreeSet<(String, u64)> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(AVAILABILITY) {
            let record = match Availability::from_value(&entry.payload) {
                Ok(record) => record,
                Err(error) => {
                    problems.push(format!("entry {}: {error}", entry.seq));
                    continue;
                }
            };
            if let Err(error) = record.verify_signature() {
                problems.push(format!("entry {}: {error}", entry.seq));
                continue;
            }
            let Some(promise) = promises.get(&record.undertaking) else {
                problems.push(format!(
                    "entry {}: answers undertaking {}, which this log does not hold",
                    entry.seq,
                    short(&record.undertaking)
                ));
                continue;
            };
            // The draw keys on the promiser, so an impostor's path would be
            // arithmetically right. The rule has to be stated, not derived.
            if promise.identity != record.identity {
                problems.push(format!(
                    "entry {}: {} answered a promise made by {}",
                    entry.seq,
                    short(&record.identity),
                    short(&promise.identity)
                ));
                continue;
            }
            match self.sampled_index(promise, record.epoch, entry.seq as usize) {
                None => problems.push(format!(
                    "entry {}: undertaking {} cannot be sampled",
                    entry.seq,
                    short(&record.undertaking)
                )),
                Some(index) => {
                    // The leaf comes from the entry the *answerer* sent, not
                    // from this node's copy. Recomputing it locally -- which is
                    // what this did at first -- means an answerer needs only
                    // the hashes every path is derivable from, and is paid for
                    // storing a hash tree rather than a log.
                    //
                    // The index is derived, never read from the record: an
                    // answerer who could name it would answer whichever entry
                    // it happened to keep.
                    let checked = Proof::from_parts(
                        &record.entry,
                        usize::try_from(index).unwrap_or(usize::MAX),
                        usize::try_from(promise.height).unwrap_or(usize::MAX),
                        record.path.clone(),
                    )
                    .map_or_else(
                        || Err(String::from("the answer carries no readable entry")),
                        |proof: Proof| proof.check(&promise.root),
                    );
                    if let Err(why) = checked {
                        problems.push(format!(
                            "entry {}: answer to {} for epoch {} does not check: {why}",
                            entry.seq,
                            short(&record.undertaking),
                            record.epoch
                        ));
                    }
                }
            }
            if !answered.insert((record.undertaking.clone(), record.epoch)) {
                problems.push(format!(
                    "entry {}: undertaking {} was already answered for epoch {}",
                    entry.seq,
                    short(&record.undertaking),
                    record.epoch
                ));
            }
        }

        // The money. Every settlement's own arithmetic re-derived, and the
        // running total against what was funded -- in `u128`, because a wrapped
        // sum turns an overspent pool into a small number.
        let pools: Vec<AvailabilityPool> = self
            .ledger
            .entries_of_kind(AVAILABILITY_POOL)
            .into_iter()
            .filter_map(|entry| AvailabilityPool::from_value(&entry.payload).ok())
            .collect();
        let funded = pools
            .iter()
            .fold(0u128, |total, pool| total.saturating_add(pool.ceiling()));
        let offered = |epoch: u64| -> u128 {
            pools
                .iter()
                .filter(|pool| pool.covers(epoch))
                .fold(0u128, |total, pool| {
                    total.saturating_add(u128::from(pool.per_epoch))
                })
        };
        let mut spent_total = 0u128;
        for entry in self.ledger.entries_of_kind(AVAILABILITY_SETTLEMENT) {
            let rows = entry.payload.get("paid").and_then(Value::as_array);
            let unpaid = entry.payload.get("unpaid").and_then(Value::as_i128);
            let epoch = entry.payload.get("epoch").and_then(Value::as_u64);
            let (Some(rows), Some(unpaid), Some(epoch)) = (rows, unpaid, epoch) else {
                problems.push(format!(
                    "entry {}: availability settlement is missing paid, unpaid or epoch",
                    entry.seq
                ));
                continue;
            };
            if unpaid < 0 {
                problems.push(format!(
                    "entry {}: availability settlement has a negative remainder",
                    entry.seq
                ));
                continue;
            }
            // Summed row by row: a total taken from a summary field would agree
            // with itself while disagreeing with the payments beside it. And
            // one row per identity, because two rows for one key is a second
            // helping for one epoch's work.
            let mut spent = 0u128;
            let mut bad = false;
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for row in rows {
                match row.get("reward").and_then(Value::as_i128) {
                    Some(reward) if reward >= 0 => spent = spent.saturating_add(reward as u128),
                    _ => bad = true,
                }
                if let Some(who) = row.get("identity").and_then(Value::as_str) {
                    if !seen.insert(who) {
                        problems.push(format!(
                            "entry {}: {} is paid twice in one settlement",
                            entry.seq,
                            short(who)
                        ));
                    }
                }
            }
            if bad {
                problems.push(format!(
                    "entry {}: a payment is missing or negative",
                    entry.seq
                ));
                continue;
            }
            spent_total = spent_total.saturating_add(spent);
            let accounted = spent.saturating_add(unpaid as u128);
            if accounted != offered(epoch) {
                problems.push(format!(
                    "entry {}: epoch {epoch} offered {} but the settlement accounts for \
                     {accounted}",
                    entry.seq,
                    offered(epoch)
                ));
            }
        }
        if spent_total > funded {
            problems.push(format!(
                "availability pool overspent: {spent_total} paid against {funded} funded"
            ));
        }

        // Every verdict record must be readable. This is structural, not a
        // re-run: a verdict naming no claim, or carrying a status no
        // implementation recognises, is a malformed log whether or not this
        // node can run the verifier. It used to be skipped in silence by the
        // re-run loop below, which meant a log could carry a verdict that
        // settles nothing anywhere and still audit clean.
        for entry in self.ledger.entries_of_kind(VERDICT) {
            let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
                problems.push(format!("entry {}: verdict has no claim_id", entry.seq));
                continue;
            };
            if entry
                .payload
                .get("verdict")
                .and_then(Verdict::from_value)
                .is_none()
            {
                problems.push(format!(
                    "entry {}: verdict for {} has no readable status",
                    entry.seq,
                    short(claim_id)
                ));
            }
        }

        // Every settlement must name a claim whose recorded verdict accepted.
        let accepted = self.accepted_claims();
        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
                problems.push(format!("entry {}: settlement has no claim_id", entry.seq));
                continue;
            };
            if !accepted.contains_key(claim_id) {
                problems.push(format!(
                    "entry {}: settlement pays {} which has no accepting verdict",
                    entry.seq,
                    short(claim_id)
                ));
            }
        }

        // Every claim opens a commitment, and every claim has a verdict.
        //
        // The first is the commit-reveal scheme itself: a claim with no
        // matching commitment was never bound to an epoch, so its submitter
        // could have read everyone else's reveal before writing it. That is the
        // one thing the scheme exists to prevent, and the independent auditor
        // did not check it -- it looked only from verdicts and settlements
        // *back* to claims, which cannot see a claim nothing points at.
        let mut seen_claims: BTreeSet<String> = BTreeSet::new();
        let with_verdict: BTreeSet<String> = self
            .ledger
            .entries_of_kind(VERDICT)
            .into_iter()
            .filter_map(|entry| {
                entry
                    .payload
                    .get("claim_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            let Ok(claim) = Claim::from_value(&entry.payload) else {
                // Reported above by the re-encode pass.
                continue;
            };
            let claim_id = claim.id();
            if !seen_claims.insert(claim_id.clone()) {
                continue;
            }
            if self.matching_commitment(&claim).is_none() {
                problems.push(format!(
                    "claim {}: no matching commitment",
                    short(&claim_id)
                ));
            }
            if !with_verdict.contains(&claim_id) {
                problems.push(format!("claim {}: no verdict recorded", short(&claim_id)));
            }
            if !objectives.contains_key(&claim.objective_id) {
                problems.push(format!(
                    "claim {}: names unknown objective {}",
                    short(&claim_id),
                    short(&claim.objective_id)
                ));
            }
        }

        // A peer record only supersedes by advancing its identity's sequence.
        //
        // The log is append-only and a peer's address is not, so `seq` is what
        // lets a mutable hint live in an immutable log. Without the check, a
        // replayed old record puts a stale address back in front of a current
        // one -- the record is perfectly signed, which is exactly why signature
        // verification alone does not cover it.
        let mut peer_seqs: BTreeMap<String, u64> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(PEER) {
            let record = match PeerRecord::from_value(&entry.payload) {
                Ok(record) => record,
                // Reported by the re-encode pass above with the decoder's own
                // message.
                Err(_) => continue,
            };
            // A record whose signature does not verify is not a statement by
            // anybody, so its sequence does not participate -- and the failure
            // is already reported by the pass above. Letting it count would
            // mean anyone could make the audit accuse an identity of replaying
            // its own records by appending an unsigned forgery, which is a
            // finding manufactured out of nothing.
            if record.verify_signature().is_err() {
                continue;
            }
            if let Some(held) = peer_seqs.get(&record.identity) {
                if record.seq <= *held {
                    problems.push(format!(
                        "entry {}: peer {} seq {} does not advance {held}",
                        entry.seq,
                        short(&record.identity),
                        record.seq
                    ));
                }
            }
            let slot = peer_seqs
                .entry(record.identity.clone())
                .or_insert(record.seq);
            *slot = (*slot).max(record.seq);
        }

        // No objective pays out more than it funded, and a plain one pays once.
        //
        // The most consequential invariant in the file, and this crate did not
        // check it at all. Everything above is about whether a *record* is
        // well-formed; this is about whether the money adds up, and an
        // independent auditor that re-derives every id and every root while
        // taking the arithmetic on faith is checking the easy half. An operator
        // could have overspent a pool by any amount and the reference would
        // have said "log verified".
        //
        // `i128` throughout, and a total that cannot be represented is a
        // problem rather than a wrap: a wrapped sum resets an overspent pool to
        // something small and hides exactly the fault being looked for.
        let mut settled_once: BTreeSet<String> = BTreeSet::new();
        let mut paid: BTreeMap<String, i128> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            let Some(objective_id) = entry.payload.get("objective_id").and_then(Value::as_str)
            else {
                problems.push(format!(
                    "entry {}: settlement has no objective_id",
                    entry.seq
                ));
                continue;
            };
            let objective = objectives.get(objective_id);
            // A ratcheted objective pays each improvement, so more than one
            // settlement is the design rather than a fault. Every other kind
            // closes when it pays.
            let progressive = objective.is_some_and(|o| o.ratchet.is_some());
            if !settled_once.insert(objective_id.to_string()) && !progressive {
                problems.push(format!(
                    "objective {}: settled more than once",
                    short(objective_id)
                ));
            }
            let reward = match entry.payload.get("reward") {
                Some(Value::Int(reward)) => *reward,
                // Absent is not zero and a string is not a number. A settlement
                // whose amount cannot be read is not one whose amount is
                // harmless.
                _ => {
                    problems.push(format!(
                        "entry {}: settlement of {} has no integer reward",
                        entry.seq,
                        short(objective_id)
                    ));
                    continue;
                }
            };
            let running = paid.entry(objective_id.to_string()).or_insert(0);
            match running.checked_add(reward) {
                Some(total) => *running = total,
                None => problems.push(format!(
                    "objective {}: settled rewards overflow any representable total",
                    short(objective_id)
                )),
            }
        }
        for (objective_id, total) in &paid {
            let Some(objective) = objectives.get(objective_id) else {
                problems.push(format!(
                    "settlement references unknown objective {}",
                    short(objective_id)
                ));
                continue;
            };
            if *total < 0 {
                problems.push(format!(
                    "objective {}: settled rewards sum to a negative total {total}",
                    short(objective_id)
                ));
            } else if *total > i128::from(objective.reward) {
                problems.push(format!(
                    "objective {}: paid {total} against a pool of {}",
                    short(objective_id),
                    objective.reward
                ));
            }
        }

        // A ratcheted objective's frontier only ever moves forward.
        //
        // The frontier is the running record of the best result so far, and
        // every payout is the *distance* from the previous one. A frontier that
        // slid backwards means somebody was paid for a regression, and the
        // pool-total check above cannot see it: the sum can stay under the
        // ceiling while the money went to the wrong claims in the wrong order.
        // `improves` is asked rather than a bare comparison, because
        // `direction` decides which way is forward and `min_improvement` is
        // what stops a thousand claims each advancing by one unit.
        for (objective_id, objective) in &objectives {
            let Some(block) = &objective.ratchet else {
                continue;
            };
            let ratchet = match Ratchet::from_value(block) {
                Ok(ratchet) => ratchet,
                Err(error) => {
                    problems.push(format!(
                        "objective {}: ratchet cannot be decoded ({error})",
                        short(objective_id)
                    ));
                    continue;
                }
            };
            let mut best: Option<i64> = None;
            for entry in self.ledger.entries_of_kind(FRONTIER) {
                if entry.payload.get("objective_id").and_then(Value::as_str)
                    != Some(objective_id.as_str())
                {
                    continue;
                }
                // Absent is not zero. A frontier entry with no readable score
                // records no position at all, and treating it as the origin
                // would let the next entry "improve" on a number nobody wrote.
                let Some(score) = entry.payload.get("score").and_then(Value::as_i64) else {
                    problems.push(format!(
                        "objective {}: frontier entry {} has no recordable score",
                        short(objective_id),
                        entry.seq
                    ));
                    continue;
                };
                if let Some(previous) = best {
                    if !ratchet.improves(Some(previous), score) {
                        problems.push(format!(
                            "objective {}: frontier moved to {score} without improving on \
                             {previous}",
                            short(objective_id)
                        ));
                    }
                }
                best = Some(score);
            }
        }

        // A beacon that is not admissible orders nothing -- `epoch_beacon`
        // already skips it, so the batch falls back to the epoch chain and the
        // anchor check below still passes. That is the right settlement
        // behaviour and the wrong silence: the record is in the log, it looks
        // like it governs an epoch, and only an audit that says otherwise
        // tells anyone it does not.
        let mut beacon_epochs: BTreeSet<u64> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(BEACON) {
            let Some(orders) = entry.payload.get("orders").and_then(Value::as_u64) else {
                problems.push(format!("entry {}: beacon orders no epoch", entry.seq));
                continue;
            };
            if !beacon_epochs.insert(orders) {
                problems.push(format!(
                    "entry {}: a second beacon for epoch {orders}; whoever writes it \
                     would re-roll the settlement order after reading the first",
                    entry.seq
                ));
            }
            // The timing is the security property, so it is re-derived rather
            // than taken from the record: drawn before the epoch, a committer
            // grinds against a value they already hold; drawn after it opens,
            // the writer has read the reveals.
            let drawn = unix_seconds(&entry.ts).map(|seconds| epoch_of(seconds, epoch_seconds()));
            if drawn != Some(orders) {
                problems.push(format!(
                    "entry {}: beacon orders epoch {orders} but was drawn in {}, \
                     so it orders nothing",
                    entry.seq,
                    drawn.map_or_else(|| "an unreadable epoch".to_string(), |e| e.to_string())
                ));
            }
            // A drand beacon does not get to say which round it is. The round
            // is a function of the epoch, so this is the one provenance field
            // in any beacon record that a reader holding only the log can
            // check -- an Ethereum `block` needs the chain and this needs
            // arithmetic. Re-derived here rather than compared against the
            // primary implementation's answer, which is the entire job.
            if entry.payload.get("source").and_then(Value::as_str) == Some(drand::SOURCE) {
                let names = drand::round_for_epoch(orders, epoch_seconds());
                if entry.payload.get("block").and_then(Value::as_u64) != Some(names) {
                    problems.push(format!(
                        "entry {}: drand beacon for epoch {orders} names a round other than \
                         {names}, which is the round that epoch names",
                        entry.seq
                    ));
                }
                // The pairing, against the round the record claims rather than
                // the one the epoch names -- so "a real round, but not this
                // epoch's" and "not a round at all" stay separate accusations.
                //
                // Reported and never consulted when settling. A pairing is the
                // one check here where this crate and the primary could be made
                // to disagree, and a disagreement on the settlement path is a
                // silent fork; a disagreement in an audit report is a failing
                // `differential.sh`.
                let claimed = entry
                    .payload
                    .get("block")
                    .and_then(Value::as_u64)
                    .unwrap_or(names);
                if !entry
                    .payload
                    .get("value")
                    .and_then(Value::as_str)
                    .is_some_and(|value| drand::verify(claimed, value))
                {
                    problems.push(format!(
                        "entry {}: drand beacon for epoch {orders} does not carry round \
                         {claimed}'s signature, so its anchor is a value somebody chose",
                        entry.seq
                    ));
                }
            }
        }

        // Every batch must name the anchor the log actually had at its epoch's
        // start, and the order the beacon produces.
        let mut batches = 0usize;
        let mut faulted: BTreeSet<u64> = BTreeSet::new();
        let mut drained: BTreeSet<u64> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(BATCH) {
            // Reported rather than skipped. A batch with no epoch settles
            // claims into no period at all -- it cannot be checked against an
            // anchor or a beacon order, so passing over it silently is the
            // audit declining to look at the one record that decides a payment
            // round.
            let Some(epoch) = entry.payload.get("epoch").and_then(Value::as_u64) else {
                problems.push(format!("entry {}: batch has no epoch", entry.seq));
                continue;
            };
            batches += 1;
            // An epoch settles once. Two batches for the same one is either a
            // double payment or a rewritten history, and the pool ceiling only
            // notices if the second one pushes the total over.
            if !drained.insert(epoch) {
                problems.push(format!(
                    "entry {}: epoch {epoch} settled in more than one batch",
                    entry.seq
                ));
            }
            let recorded_anchor = entry
                .payload
                .get("anchor")
                .and_then(Value::as_str)
                .unwrap_or_default();
            // Bounded to the log as it stood when the batch was written, so a
            // later back-dated append cannot turn an honest batch into a
            // permanent audit failure.
            let expected = self.anchor_of_epoch(epoch, Some(entry.seq as usize));
            if expected != recorded_anchor {
                faulted.insert(epoch);
                problems.push(format!(
                    "entry {}: batch anchor is {}, expected {}",
                    entry.seq,
                    short(recorded_anchor),
                    short(&expected)
                ));
            }
            // Named rather than defaulted to empty. A batch with no claim list
            // and a batch that settled nobody are different records, and the
            // membership check below would otherwise report the first as an
            // ordering fault -- a true finding under a misleading name.
            let Some(Value::Array(items)) = entry.payload.get("claims") else {
                faulted.insert(epoch);
                problems.push(format!(
                    "entry {}: batch for epoch {epoch} has no claim list",
                    entry.seq
                ));
                continue;
            };
            let listed: Vec<String> = items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            // An empty batch is always forged, and it is not harmless.
            //
            // A drain writes a batch only for an epoch that has accepted
            // claims, so an honest batch always names at least one. But every
            // batch is a link in the epoch chain, and the chain head is the
            // anchor later batches sort against -- so an empty batch for an
            // epoch nobody claimed in moves that head while trivially matching
            // its own (empty) claim list. Both implementations passed one
            // clean, which handed an operator an unlimited re-roll of the
            // order every later epoch is paid in.
            if listed.is_empty() {
                faulted.insert(epoch);
                problems.push(format!(
                    "entry {}: batch for epoch {epoch} settles no claims, so it cannot \
                     have come from a drain -- an empty batch still moves the epoch chain",
                    entry.seq
                ));
                continue;
            }
            // Membership is derived from the log, not read back out of the
            // batch. Re-sorting the list the batch itself supplied is a check
            // that a batch which *omitted* a claim always passes -- and which
            // claims are in an epoch's batch is precisely what decides who gets
            // paid that epoch, so it is the last thing an independent
            // implementation should take on faith from the record it is
            // auditing.
            //
            // Bounded to the log as it stood when the batch was written, for
            // the same reason the anchor is: a peer can append a claim dated
            // into an epoch that already paid, and an unbounded scan would call
            // an honest batch wrong forever.
            let mut expected_order: Vec<String> = self
                .accepted_claims_by_epoch_within(Some(entry.seq as usize))
                .into_iter()
                .filter(|(candidate, _)| *candidate == epoch)
                .map(|(_, claim)| claim.id())
                .collect();
            expected_order.sort_by_key(|id| {
                let commitment_hash = accepted
                    .get(id)
                    .map(|claim| claim.commitment_hash())
                    .unwrap_or_default();
                (
                    settlement_rank(epoch, recorded_anchor, &commitment_hash),
                    id.clone(),
                )
            });
            if expected_order != listed {
                faulted.insert(epoch);
                problems.push(format!(
                    "entry {}: batch for epoch {epoch} settled {} claim(s) in an order the \
                     beacon does not produce",
                    entry.seq,
                    listed.len()
                ));
            }
        }

        // Every batch faulting at once usually means the auditor and the writer
        // disagree about how long an epoch is, not that anybody was paid out of
        // turn. Epochs are derived from timestamps and never stored, so a log
        // written under `CAIRN_EPOCH_SECONDS=1` audits as thoroughly broken
        // under the default 600 -- both implementations agree, and both are
        // right.
        //
        // The primary prints this note; this crate did not, which is the wrong
        // way round. A reader auditing with the *independent* implementation is
        // exactly the reader with no reason to trust a reassuring explanation
        // from the primary, and they were the one left staring at a wall of
        // anchor mismatches that reads like proof the project's central claim
        // is false.
        if batches > 0 && faulted.len() == batches {
            problems.push(format!(
                "note: every batch in this log looks wrong, which is more often a mismatched \
                 epoch length than a dishonest operator. Epochs are derived from record \
                 timestamps and never stored, so a log written with a different \
                 CAIRN_EPOCH_SECONDS (this audit used {}) cannot be re-derived without it.",
                crate::partition::epoch_seconds()
            ));
        }

        // Accepted claims stranded behind a later batch. Nothing in this log is
        // wrong -- which is why it has to be said. It means records arrived
        // outside the finality window, and a peer that got them in time paid
        // claims this node never will.
        let late = self.late_epochs();
        if !late.is_empty() {
            problems.push(format!(
                "note: {} epoch(s) hold accepted claims that can never settle, because a later \
                 epoch was paid first: {}. Records for them arrived more than CAIRN_\
                 FINALITY_EPOCHS (this audit used {}) after their epoch closed. Every batch in \
                 this log is correctly derived; what is wrong is that a peer which received \
                 those records on time has paid claims this node never will.",
                late.len(),
                late.iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                crate::partition::finality_epochs()
            ));
        }

        if rerun {
            // Which claims actually got paid. A claim that settled and can no
            // longer be re-verified is a different thing from one that never
            // settled, and the difference is the whole point of the exercise:
            // money moved on the strength of a verdict this node cannot now
            // reproduce.
            let paid: std::collections::BTreeSet<String> = self
                .ledger
                .entries_of_kind(SETTLEMENT)
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .payload
                        .get("claim_id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect();

            // The claim the whole design makes: re-run the pinned verifier and
            // check the log's own verdict still holds.
            for entry in self.ledger.entries_of_kind(VERDICT) {
                let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
                    continue;
                };
                let Some(recorded) = entry.payload.get("verdict").and_then(Verdict::from_value)
                else {
                    continue;
                };
                // Only settled verdicts are re-checked: an `unavailable` was
                // never a statement about the artifact.
                if !recorded.status.settles() {
                    continue;
                }
                let Some(claim) = accepted.get(claim_id).cloned().or_else(|| {
                    self.ledger
                        .entries_of_kind(CLAIM)
                        .into_iter()
                        .filter_map(|e| Claim::from_value(&e.payload).ok())
                        .find(|c| c.id() == claim_id)
                }) else {
                    continue;
                };
                let Some(objective) = objectives.get(&claim.objective_id) else {
                    continue;
                };
                let fresh = verifiers::run(&self.root, &objective.verifier, &claim.artifact);
                // A verifier this node cannot run says nothing *about the
                // artifact* -- `Unavailable` is never `Reject`. But it says
                // something about **this audit**, and staying silent was a
                // divergence from the primary that hid a real gap: an entire
                // verifier kind this crate did not implement produced
                // `Unavailable` for every claim, every one was skipped, and the
                // run still reported "every settled claim re-verified". Correct
                // behaviours composing into a false statement.
                //
                // So: skipped is fine for a verdict the log did not settle
                // either, and a problem for one it did. The summary line says
                // "every settled claim re-verified"; if that cannot be done,
                // the line is false and the audit has to say so.
                //
                // Gating this on *payment* was the first version and it left a
                // hole one rung down: a `reject` never pays, so a rejection no
                // other node could reproduce passed every audit in silence.
                // That is the worse direction. A payment somebody will
                // eventually contest; a rejected submitter has no money to
                // point at and no way to show the rejection was not
                // reproducible.
                if !fresh.status.settles() {
                    if paid.contains(claim_id) {
                        problems.push(format!(
                            "claim {}: was settled but can no longer be re-verified ({}: {})",
                            short(claim_id),
                            fresh.status.as_str(),
                            fresh.detail
                        ));
                    } else {
                        problems.push(format!(
                            "claim {}: recorded {} but can no longer be re-verified ({}: {})",
                            short(claim_id),
                            recorded.status.as_str(),
                            fresh.status.as_str(),
                            fresh.detail
                        ));
                    }
                    continue;
                }
                if fresh.status != recorded.status {
                    problems.push(format!(
                        "claim {}: recorded {} but re-runs as {}",
                        short(claim_id),
                        recorded.status.as_str(),
                        fresh.status.as_str()
                    ));
                }
            }
        }
        problems
    }
}

fn unsettled(claim_id: String, verdict: Verdict, note: &str) -> Outcome {
    Outcome {
        claim_id,
        verdict,
        settled: false,
        reward: 0,
        note: note.to_string(),
        pending_epoch: None,
    }
}

/// Now, for callers that do not want to import the time module.
pub fn now() -> String {
    timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::Undertaking;

    const TS: &str = "2026-07-28T00:00:00+00:00";

    fn scratch(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("pw-ref-{tag}-{}-{nanos}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("scratch");
        path
    }

    /// The audit really checks these records, rather than reporting clean over
    /// a kind it skips.
    ///
    /// This test exists because that is exactly what this crate did when the
    /// records were first added on the primary side: it printed *log verified*
    /// over a log full of availability settlements without checking one of
    /// them. A green audit from an implementation that is not looking is worse
    /// than no second implementation at all, because it is quoted as agreement.
    #[test]
    fn the_audit_is_not_vacuous_about_availability() {
        let dir = scratch("availability");
        let mut ledger = Ledger::open(dir.join("log.jsonl")).expect("open");
        ledger
            .append("note", Value::string("one"), TS)
            .expect("append");
        // A settlement paying the fixture's identity, so its bond is
        // affordable. Without it the audit reports the *bond* and stops, and
        // the root check below -- the branch this test exists for -- would
        // never run while the test still looked like it was exercising it.
        ledger
            .append(
                SETTLEMENT,
                Value::object([
                    ("claim_id", Value::string("00".repeat(32))),
                    ("objective_id", Value::string("11".repeat(32))),
                    ("reward", Value::Int(1000)),
                    (
                        "submitter",
                        Value::string(
                            "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61",
                        ),
                    ),
                ]),
                TS,
            )
            .expect("append");
        ledger
            .append("note", Value::string("two"), TS)
            .expect("append");
        let root = ledger.root_at(3).expect("root");

        // A *genuinely signed* undertaking, lifted from a log the primary
        // implementation wrote, naming a root that is not a prefix root of
        // this log. Signed matters: an unsigned record is reported for its
        // signature and the loop moves on, so it would never reach the root
        // check -- and this crate cannot sign, by design. Borrowing a real
        // record from the other implementation is the honest way to exercise
        // the branch, and it doubles as a decode test against its bytes.
        //
        // These exact bytes are pinned on the other side too, by
        // `the_signed_undertaking_the_reference_crate_pins_is_still_what_this_crate_writes`.
        // A borrowed constant rots silently -- add a field to the record and
        // this copy becomes one the primary would no longer write, so the two
        // implementations stop being compared on the same bytes while both
        // still pass. That test fails first and names this file.
        const SIGNED: &str = r#"{"bond":500,"created_at":"2026-08-14T00:00:00+00:00","height":3,"identity":"197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61","root":"sha256:30ffa4f80f8e0198fd85844b9a63b682f11f1bca7a67532aaaae0f20d17e78ed","signature":"bac8259da5214a3026e01f1e912988a1cb4fd6969085a6ad0cddb6a43af99ee1a6202b4df610dd2e8df8472c34f6a7985d3ee0ed2ea37d1094f1f64ef15d4f06","type":"undertaking"}"#;
        let borrowed = Value::from_json(SIGNED).expect("the fixture is canonical JSON");
        let decoded = Undertaking::from_value(&borrowed).expect("and it decodes here");
        decoded
            .verify_signature()
            .expect("and its signature verifies in this implementation too");
        ledger.append(UNDERTAKING, borrowed, TS).expect("append");

        // A settlement whose arithmetic does not close, and which pays out of a
        // pool nobody funded.
        ledger
            .append(
                AVAILABILITY_SETTLEMENT,
                Value::object([
                    ("epoch", Value::Int(0)),
                    ("anchor", Value::string("")),
                    (
                        "paid",
                        Value::Array(vec![Value::object([
                            ("identity", Value::string("cd".repeat(32))),
                            ("reward", Value::Int(500)),
                            ("undertaking", Value::string("x")),
                        ])]),
                    ),
                    ("silent", Value::Array(Vec::new())),
                    ("share", Value::Int(500)),
                    ("unpaid", Value::Int(0)),
                ]),
                TS,
            )
            .expect("append");

        let node = Node::new(ledger, ".");
        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("no prefix of this log is")),
            "a signed promise about a root this log never had went unreported: {problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("overspent")),
            "the unfunded payout went unreported: {problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("accounts for")),
            "the arithmetic mismatch went unreported: {problems:?}"
        );
        // And the check is not simply always-failing: this log's own root at
        // that height is a value the same code path accepts.
        assert_eq!(node.ledger.root_at(3).as_deref(), Some(root.as_str()));
        assert_ne!(root, decoded.root, "the fixture must name a different root");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bond the log never funded is named here too.
    ///
    /// The rule the availability pool is divided by: a promise's share is
    /// proportional to what it staked, so a stake nobody paid for is a share of
    /// somebody else's money. It is the one number in an undertaking that the
    /// record cannot establish about itself — what the identity has been paid
    /// is written below it — which is exactly why a second implementation has
    /// to derive it independently rather than take the first one's word.
    ///
    /// A slash the log carries no attestation for is a taking with no target.
    ///
    /// The case a second implementation exists for. `verification_slash` is a
    /// record kind this crate could have ignored entirely and still reported
    /// "log verified" — over fifty thousand units moved out of somebody's
    /// balance by an append anybody can write. That is exactly how availability
    /// settlements went unchecked here for a while.
    #[test]
    fn a_slash_pointing_at_no_attestation_is_reported() {
        let dir = scratch("orphan-slash");
        let mut ledger = Ledger::open(dir.join("log.jsonl")).expect("open");
        ledger
            .append(
                VERIFICATION_SLASH,
                Value::object([
                    ("attestation_id", Value::string("sha256:nothing")),
                    ("attestor", Value::string("victim")),
                    ("catcher", Value::string("thief")),
                    ("claim_id", Value::string("sha256:also-nothing")),
                    ("units", Value::Int(i128::from(VERIFICATION_BOND))),
                ]),
                TS,
            )
            .expect("append");

        let node = Node::new(ledger, ".");
        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("which is not in this log")),
            "a slash with no attestation behind it went unreported: {problems:?}"
        );
        // And the money is accounted for, which is the half a check on the
        // record's *shape* would miss. A crate that did not know this kind
        // would report the catcher holding nothing and the loser holding
        // everything, and certify both.
        assert_eq!(
            node.spendable_within("thief", 1),
            u128::from(VERIFICATION_BOND),
            "the catcher's bounty was not credited"
        );
        assert_eq!(
            node.committed_within("victim", 1),
            u128::from(VERIFICATION_BOND),
            "the loser was not debited"
        );
    }

    /// An attestation nobody signed stakes nothing, and both crates say so.
    ///
    /// The two questions are one question. If this crate counted the bond, its
    /// balances would differ from the primary's on the same bytes — and two
    /// implementations disagreeing about a balance disagree about what settled.
    #[test]
    fn an_unsigned_attestation_is_named_and_stakes_nothing() {
        let dir = scratch("unsigned-attestation");
        let mut ledger = Ledger::open(dir.join("log.jsonl")).expect("open");
        const KEY: &str = "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61";
        ledger
            .append(
                ATTESTATION,
                Value::object([
                    ("type", Value::string("attestation")),
                    ("attestor", Value::string(KEY)),
                    ("claim_id", Value::string("sha256:whatever")),
                    ("created_at", Value::string(TS)),
                    ("status", Value::string("accept")),
                ]),
                TS,
            )
            .expect("append");

        let node = Node::new(ledger, ".");
        let problems = node.audit(false);
        assert!(
            problems.iter().any(|p| p.contains("is not signed")),
            "an unsigned attestation went unreported: {problems:?}"
        );
        assert_eq!(
            node.committed_within(KEY, 1),
            0,
            "an attestation nobody signed staked a bond"
        );
    }

    /// Same bytes as the fixture above, in a log that does *not* pay their
    /// author. That is the whole difference, so what is reported is the
    /// balance and not the shape.
    #[test]
    fn a_bond_the_log_never_funded_is_reported() {
        let dir = scratch("unfunded-bond");
        let mut ledger = Ledger::open(dir.join("log.jsonl")).expect("open");
        for note in ["one", "two", "three"] {
            ledger
                .append("note", Value::string(note), TS)
                .expect("append");
        }
        const SIGNED: &str = r#"{"bond":500,"created_at":"2026-08-14T00:00:00+00:00","height":3,"identity":"197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61","root":"sha256:30ffa4f80f8e0198fd85844b9a63b682f11f1bca7a67532aaaae0f20d17e78ed","signature":"bac8259da5214a3026e01f1e912988a1cb4fd6969085a6ad0cddb6a43af99ee1a6202b4df610dd2e8df8472c34f6a7985d3ee0ed2ea37d1094f1f64ef15d4f06","type":"undertaking"}"#;
        let borrowed = Value::from_json(SIGNED).expect("the fixture is canonical JSON");
        ledger.append(UNDERTAKING, borrowed, TS).expect("append");

        let node = Node::new(ledger, ".");
        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("bonds 500 units against a balance of 0")),
            "a bond nobody funded went unreported: {problems:?}"
        );
        // The height rule is satisfied, so this is not that fault wearing a
        // different message: the record sits at seq 3 and promises 3.
        assert!(
            !problems
                .iter()
                .any(|p| p.contains("not the promiser's to choose")),
            "the fixture tripped the size rule instead: {problems:?}"
        );
        assert_eq!(
            node.spendable_within(
                "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61",
                3,
            ),
            0
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
