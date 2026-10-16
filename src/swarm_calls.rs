//! Swarm calls: pointing volunteered compute at an objective, and letting an
//! objective that matters more take a machine from one that matters less.
//!
//! Prototype. `docs/design/swarm-calls.md` is the design this implements the
//! node-local half of; read it before extending this file.
//!
//! # What it is
//!
//! People install cairn and share their machines (`CAIRN_SHARE_RESOURCES`,
//! `cairn agent`, `cairn work`). Until now each worker chose its own objective.
//! A **call** is an operator saying "send machines here": an objective, how
//! many workers it wants, and until when. A volunteer asks the node for
//! **advice** -- stay, start, or yield what you are on for something that
//! outranks it -- and reports back what it **contributed**.
//!
//! # Why it cannot be a lock, and is not
//!
//! Everything here is node-local, in memory, and advisory, exactly like
//! [`crate::lease`]: the rules engine never reads it, settlement never reads
//! it, and a volunteer that ignores the advice is paid for a verified result
//! exactly as before. `docs/design/network-coordination.md` §3 is the argument
//! and it applies unchanged: the moment advice became a refusal, the swarm
//! would be a reservation table, a single point of censorship.
//!
//! # Why the ranking is money, not a number someone typed
//!
//! A call's [`bid`] is the objective's open, escrowed reward divided by the
//! workers already on it plus one -- the Goals page's "where compute is scarce"
//! figure, from the same two sources. Nobody can raise a bid by declaring it:
//! only funding the objective (which is escrowed on the log before any work)
//! or fewer workers on it moves it. That is what makes preemption safe to
//! offer: taking a machine from someone else's objective costs the caller real
//! escrow, and stays possible only while the margin is wide ([`YIELD_MARGIN`]).
//!
//! # Accounting, and what it is not
//!
//! The [`Ledger`] records *contributions*: core-seconds a volunteer reports
//! having given an objective, and core-seconds lost when it yielded before a
//! checkpoint (**displaced**), charged to the call that took the machine. It is
//! self-reported, capped, and labelled so. It is never a balance and moves no
//! money: a volunteer is paid by settlement, for verified results, as before.
//! What it gives is the evidence a later, consensus-level design would need to
//! price preemption -- see the design doc's "Accounting" section.

use std::collections::BTreeMap;

use crate::canonical::Value;
use crate::scheduling::{matches, ResourceOffer, ResourceRequirements};

/// Most calls a node holds. A node's operator raises them; a few dozen open
/// at once is already more than a swarm can usefully be split across.
pub const MAX_CALLS: usize = 64;

/// The longest a call stays open without being raised again: one week.
pub const MAX_CALL_SECONDS: u64 = 7 * 24 * 3_600;

/// A call outranks a volunteer's current objective only by this margin,
/// numerator over denominator: 3/2, half as much again per worker. Without a
/// margin two objectives with nearly equal bids would trade machines back and
/// forth, and each trade throws away work since the last checkpoint.
pub const YIELD_MARGIN: (u128, u128) = (3, 2);

/// How long a yielding volunteer is given to checkpoint before it stops.
pub const CHECKPOINT_GRACE_SECONDS: u64 = 120;

/// The fewest seconds a volunteer stays on anything before it may be asked
/// to yield, whatever it asked for itself. A machine that changes objective
/// every minute does nothing but warm caches.
pub const MIN_HOLD_FLOOR_SECONDS: u64 = 600;

/// Yields per volunteer per hour, past which it is told to stay.
pub const MAX_YIELDS_PER_HOUR: u32 = 4;

/// Largest single contribution report: a day on 1,024 cores. Anything past it
/// is refused rather than clamped -- a number that large is a lie or a bug.
pub const MAX_REPORT_CORE_SECONDS: u64 = 24 * 3_600 * 1_024;

/// Most (volunteer, objective) rows the ledger keeps.
pub const MAX_LEDGER_ROWS: usize = 65_536;

/// An operator's request that volunteers work an objective.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub objective_id: String,
    /// Workers wanted on it. Once that many are live, the call stops
    /// attracting more; it does not push anyone off.
    pub want: u64,
    pub raised_at: u64,
    pub until: u64,
    pub note: String,
}

impl Call {
    pub fn open_at(&self, now: u64) -> bool {
        now < self.until
    }
}

/// Why a call was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    Full,
    BadWant,
    BadDuration,
    NoteTooLong,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Full => write!(f, "this node already holds {MAX_CALLS} calls"),
            CallError::BadWant => write!(f, "want must be between 1 and 100000 workers"),
            CallError::BadDuration => write!(
                f,
                "for_seconds must be between 60 and {MAX_CALL_SECONDS} (one week)"
            ),
            CallError::NoteTooLong => write!(f, "note is at most 280 characters"),
        }
    }
}

/// The calls a node holds.
#[derive(Debug, Default)]
pub struct Calls {
    calls: BTreeMap<String, Call>,
}

impl Calls {
    /// Raise a call, or renew one on the same objective. Expired calls are
    /// dropped first, so they never count against the cap.
    pub fn raise(
        &mut self,
        objective_id: &str,
        want: u64,
        for_seconds: u64,
        note: &str,
        now: u64,
    ) -> Result<&Call, CallError> {
        if !(1..=100_000).contains(&want) {
            return Err(CallError::BadWant);
        }
        if !(60..=MAX_CALL_SECONDS).contains(&for_seconds) {
            return Err(CallError::BadDuration);
        }
        if note.chars().count() > 280 {
            return Err(CallError::NoteTooLong);
        }
        self.expire(now);
        if !self.calls.contains_key(objective_id) && self.calls.len() >= MAX_CALLS {
            return Err(CallError::Full);
        }
        let raised_at = self
            .calls
            .get(objective_id)
            .map_or(now, |existing| existing.raised_at);
        self.calls.insert(
            objective_id.to_string(),
            Call {
                objective_id: objective_id.to_string(),
                want,
                raised_at,
                until: now.saturating_add(for_seconds),
                note: note.to_string(),
            },
        );
        Ok(&self.calls[objective_id])
    }

    /// End a call. Whether there was one.
    pub fn withdraw(&mut self, objective_id: &str) -> bool {
        self.calls.remove(objective_id).is_some()
    }

    pub fn expire(&mut self, now: u64) {
        self.calls.retain(|_, call| call.open_at(now));
    }

    pub fn open(&self, now: u64) -> Vec<&Call> {
        self.calls.values().filter(|c| c.open_at(now)).collect()
    }
}

/// What the log and the roster say about an objective, supplied by the caller
/// so this module reads neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    pub objective_id: String,
    /// Escrowed reward still payable on it.
    pub open_reward: u128,
    /// Workers heartbeating to it now.
    pub live_workers: u64,
    /// Settled or otherwise closed: nothing left to pay for.
    pub closed: bool,
    pub requirements: ResourceRequirements,
}

/// Open reward per worker if one more joins: the Goals page's scarcity
/// figure, which is also what a call bids. Integer division, so every reader
/// of one log and one roster ranks alike.
pub fn bid(open_reward: u128, live_workers: u64) -> u128 {
    open_reward / (u128::from(live_workers) + 1)
}

/// A volunteer asking what to do, as it describes itself. Self-reported, like
/// everything a worker says; the advice it gets back is advice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volunteer {
    pub name: String,
    pub offer: ResourceOffer,
    /// The objective it is working now, if any.
    pub current: Option<String>,
    /// How long it has been on `current`.
    pub held_for: u64,
    /// Whether it agrees to be asked to yield at all. A volunteer that says
    /// no is only ever told to start or stay.
    pub preemptible: bool,
    /// Its own minimum stay; raised to [`MIN_HOLD_FLOOR_SECONDS`].
    pub min_hold: u64,
    /// Yields it reports in the last hour.
    pub yields_last_hour: u32,
}

/// What a volunteer is advised to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advice {
    /// No open call fits this machine; keep doing whatever it chose.
    Idle { reason: String },
    /// Keep working `objective_id`.
    Stay {
        objective_id: String,
        reason: String,
    },
    /// Nothing to leave: start `objective_id`.
    Start { objective_id: String, bid: u128 },
    /// Checkpoint `from` within `checkpoint_within` seconds, release its lease
    /// as `preempted`, and start `to`.
    Yield {
        from: String,
        to: String,
        from_bid: u128,
        to_bid: u128,
        checkpoint_within: u64,
    },
}

impl Advice {
    pub fn to_value(&self) -> Value {
        let int = |n: u128| Value::Int(i128::try_from(n).unwrap_or(i128::MAX));
        match self {
            Advice::Idle { reason } => Value::object([
                ("action", Value::string("idle")),
                ("reason", Value::string(reason.clone())),
            ]),
            Advice::Stay {
                objective_id,
                reason,
            } => Value::object([
                ("action", Value::string("stay")),
                ("objective_id", Value::string(objective_id.clone())),
                ("reason", Value::string(reason.clone())),
            ]),
            Advice::Start { objective_id, bid } => Value::object([
                ("action", Value::string("start")),
                ("objective_id", Value::string(objective_id.clone())),
                ("bid", int(*bid)),
            ]),
            Advice::Yield {
                from,
                to,
                from_bid,
                to_bid,
                checkpoint_within,
            } => Value::object([
                ("action", Value::string("yield")),
                ("from", Value::string(from.clone())),
                ("to", Value::string(to.clone())),
                ("from_bid", int(*from_bid)),
                ("to_bid", int(*to_bid)),
                (
                    "checkpoint_within_seconds",
                    Value::Int(i128::from(*checkpoint_within)),
                ),
            ]),
        }
    }
}

/// An open call with its bid, as both [`advise`] and `GET /swarm` see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranked<'a> {
    pub call: &'a Call,
    pub opening: &'a Opening,
    pub bid: u128,
    /// As many live workers as it wants: it attracts no more.
    pub full: bool,
}

/// Every open call on an open, funded objective, highest bid first; ties by
/// objective id so every reader agrees.
pub fn ranked<'a>(calls: &'a Calls, openings: &'a [Opening], now: u64) -> Vec<Ranked<'a>> {
    let by_id: BTreeMap<&str, &Opening> = openings
        .iter()
        .map(|o| (o.objective_id.as_str(), o))
        .collect();
    let mut out: Vec<Ranked<'a>> = calls
        .open(now)
        .into_iter()
        .filter_map(|call| {
            let opening = by_id.get(call.objective_id.as_str())?;
            (!opening.closed && opening.open_reward > 0).then(|| Ranked {
                call,
                opening,
                bid: bid(opening.open_reward, opening.live_workers),
                full: opening.live_workers >= call.want,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.bid
            .cmp(&a.bid)
            .then_with(|| a.call.objective_id.cmp(&b.call.objective_id))
    });
    out
}

/// Advise one volunteer. Pure: the same calls, openings, volunteer and time
/// give the same advice on every node.
pub fn advise(volunteer: &Volunteer, calls: &Calls, openings: &[Opening], now: u64) -> Advice {
    let ranked = ranked(calls, openings, now);
    let best = ranked
        .iter()
        .filter(|r| !r.full || volunteer.current.as_deref() == Some(r.call.objective_id.as_str()))
        .find(|r| matches(&r.opening.requirements, &volunteer.offer));
    let Some(best) = best else {
        return match &volunteer.current {
            Some(current) => Advice::Stay {
                objective_id: current.clone(),
                reason: "no open call this machine can serve outranks it".into(),
            },
            None => Advice::Idle {
                reason: "no open call this machine can serve".into(),
            },
        };
    };
    let Some(current) = &volunteer.current else {
        return Advice::Start {
            objective_id: best.call.objective_id.clone(),
            bid: best.bid,
        };
    };
    if *current == best.call.objective_id {
        return Advice::Stay {
            objective_id: current.clone(),
            reason: "already on the highest call it can serve".into(),
        };
    }
    // What the volunteer is on now is worth what its own objective bids, call
    // or no call. One that is closed or unknown is worth nothing: there is no
    // reward left to lose, so moving is starting, not yielding.
    let current_bid = openings
        .iter()
        .find(|o| &o.objective_id == current)
        .filter(|o| !o.closed && o.open_reward > 0)
        // It is one of the live workers already counted; its own bid is the
        // open reward over the workers including it.
        .map(|o| o.open_reward / u128::from(o.live_workers.max(1)));
    let Some(current_bid) = current_bid else {
        return Advice::Start {
            objective_id: best.call.objective_id.clone(),
            bid: best.bid,
        };
    };
    let stay = |reason: &str| Advice::Stay {
        objective_id: current.clone(),
        reason: reason.to_string(),
    };
    if !volunteer.preemptible {
        return stay("this machine does not take preemption");
    }
    let (num, den) = YIELD_MARGIN;
    if best.bid.saturating_mul(den) < current_bid.saturating_mul(num) {
        return stay("no call outranks the current objective by the yield margin");
    }
    if volunteer.held_for < volunteer.min_hold.max(MIN_HOLD_FLOOR_SECONDS) {
        return stay("held for less than its minimum stay");
    }
    if volunteer.yields_last_hour >= MAX_YIELDS_PER_HOUR {
        return stay("yielded too often in the last hour");
    }
    Advice::Yield {
        from: current.clone(),
        to: best.call.objective_id.clone(),
        from_bid: current_bid,
        to_bid: best.bid,
        checkpoint_within: CHECKPOINT_GRACE_SECONDS,
    }
}

// -- contributions ---------------------------------------------------------------------

/// How a stretch of contributed work ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// Still running, or finished normally.
    Worked,
    /// Yielded to the call on `by`; `unsaved` core-seconds since the last
    /// checkpoint were lost and are charged to that call.
    Yielded { by: String, unsaved: u64 },
}

/// One report from a volunteer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub volunteer: String,
    pub objective_id: String,
    pub core_seconds: u64,
    pub ended: Ended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    TooLarge,
    UnsavedExceedsWork,
    Full,
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::TooLarge => write!(
                f,
                "core_seconds is at most {MAX_REPORT_CORE_SECONDS} (a day on 1024 cores) per report"
            ),
            ReportError::UnsavedExceedsWork => {
                write!(f, "unsaved_core_seconds cannot exceed core_seconds")
            }
            ReportError::Full => write!(f, "the contribution ledger is full"),
        }
    }
}

/// Totals for one volunteer on one objective.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Row {
    /// Core-seconds it reports giving the objective.
    pub contributed: u64,
    /// Core-seconds of that it lost when asked to yield, before a checkpoint.
    pub displaced: u64,
    pub yields: u32,
}

/// Reported contributions, node-local and in memory. Never a balance.
#[derive(Debug, Default)]
pub struct Ledger {
    rows: BTreeMap<(String, String), Row>,
    /// Core-seconds each call displaced by taking machines: the cost its
    /// preemption imposed on other objectives.
    displaced_by: BTreeMap<String, u64>,
}

impl Ledger {
    pub fn record(&mut self, report: &Report) -> Result<(), ReportError> {
        if report.core_seconds > MAX_REPORT_CORE_SECONDS {
            return Err(ReportError::TooLarge);
        }
        if let Ended::Yielded { unsaved, .. } = &report.ended {
            if *unsaved > report.core_seconds {
                return Err(ReportError::UnsavedExceedsWork);
            }
        }
        let key = (report.volunteer.clone(), report.objective_id.clone());
        if !self.rows.contains_key(&key) && self.rows.len() >= MAX_LEDGER_ROWS {
            return Err(ReportError::Full);
        }
        let row = self.rows.entry(key).or_default();
        row.contributed = row.contributed.saturating_add(report.core_seconds);
        if let Ended::Yielded { by, unsaved } = &report.ended {
            row.displaced = row.displaced.saturating_add(*unsaved);
            row.yields = row.yields.saturating_add(1);
            let charged = self.displaced_by.entry(by.clone()).or_insert(0);
            *charged = charged.saturating_add(*unsaved);
        }
        Ok(())
    }

    /// Core-seconds contributed to an objective, by every volunteer.
    pub fn contributed_to(&self, objective_id: &str) -> u64 {
        self.rows
            .iter()
            .filter(|((_, o), _)| o == objective_id)
            .fold(0u64, |sum, (_, row)| sum.saturating_add(row.contributed))
    }

    /// Core-seconds a call's preemptions threw away elsewhere.
    pub fn displaced_by(&self, objective_id: &str) -> u64 {
        self.displaced_by.get(objective_id).copied().unwrap_or(0)
    }

    /// Per volunteer: what it contributed and lost, across objectives.
    pub fn by_volunteer(&self) -> BTreeMap<&str, Row> {
        let mut out: BTreeMap<&str, Row> = BTreeMap::new();
        for ((volunteer, _), row) in &self.rows {
            let total = out.entry(volunteer.as_str()).or_default();
            total.contributed = total.contributed.saturating_add(row.contributed);
            total.displaced = total.displaced.saturating_add(row.displaced);
            total.yields = total.yields.saturating_add(row.yields);
        }
        out
    }

    pub fn to_value(&self) -> Value {
        let int = |n: u64| Value::Int(i128::from(n));
        Value::object([
            (
                "volunteers",
                Value::Array(
                    self.by_volunteer()
                        .into_iter()
                        .map(|(name, row)| {
                            Value::object([
                                ("volunteer", Value::string(name)),
                                ("contributed_core_seconds", int(row.contributed)),
                                ("displaced_core_seconds", int(row.displaced)),
                                ("yields", Value::Int(i128::from(row.yields))),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "note",
                Value::string(
                    "Reported by volunteers, unverified and capped. A contribution is a record of \
                     compute given, never a balance: volunteers are paid by settlement, for \
                     verified results.",
                ),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn opening(id: &str, reward: u128, live: u64) -> Opening {
        Opening {
            objective_id: id.into(),
            open_reward: reward,
            live_workers: live,
            closed: false,
            requirements: ResourceRequirements::default(),
        }
    }

    fn volunteer(current: Option<&str>) -> Volunteer {
        Volunteer {
            name: "gpu-box-1".into(),
            offer: ResourceOffer {
                cpus: Some(16),
                gpus: Some(1),
                ..Default::default()
            },
            current: current.map(String::from),
            held_for: 3_600,
            preemptible: true,
            min_hold: 0,
            yields_last_hour: 0,
        }
    }

    fn calls(entries: &[(&str, u64)]) -> Calls {
        let mut c = Calls::default();
        for (id, want) in entries {
            c.raise(id, *want, 3_600, "", NOW).unwrap();
        }
        c
    }

    #[test]
    fn the_bid_is_the_goals_pages_scarcity_figure() {
        assert_eq!(bid(1_000, 0), 1_000);
        assert_eq!(bid(1_000, 3), 250);
        assert_eq!(bid(0, 5), 0);
        assert_eq!(
            bid(u128::MAX, u64::MAX),
            u128::MAX / (u128::from(u64::MAX) + 1)
        );
    }

    #[test]
    fn an_idle_machine_starts_the_highest_call_it_can_serve() {
        let c = calls(&[("rich", 10), ("poor", 10)]);
        let o = [opening("rich", 9_000, 2), opening("poor", 1_000, 0)];
        assert_eq!(
            advise(&volunteer(None), &c, &o, NOW),
            Advice::Start {
                objective_id: "rich".into(),
                bid: 3_000
            }
        );
    }

    #[test]
    fn a_call_it_cannot_serve_is_passed_over() {
        let c = calls(&[("needs-gpus", 10), ("cpu", 10)]);
        let mut gpus = opening("needs-gpus", 100_000, 0);
        gpus.requirements.gpus = Some(8);
        let o = [gpus, opening("cpu", 10, 0)];
        assert_eq!(
            advise(&volunteer(None), &c, &o, NOW),
            Advice::Start {
                objective_id: "cpu".into(),
                bid: 10
            }
        );
    }

    #[test]
    fn a_full_call_attracts_nobody_new_but_keeps_who_it_has() {
        let c = calls(&[("full", 2)]);
        let o = [opening("full", 9_000, 2)];
        assert!(matches!(
            advise(&volunteer(None), &c, &o, NOW),
            Advice::Idle { .. }
        ));
        assert!(matches!(
            advise(&volunteer(Some("full")), &c, &o, NOW),
            Advice::Stay { .. }
        ));
    }

    #[test]
    fn a_closed_or_unfunded_objective_is_never_called() {
        let c = calls(&[("settled", 10), ("unfunded", 10)]);
        let mut settled = opening("settled", 9_000, 0);
        settled.closed = true;
        let o = [settled, opening("unfunded", 0, 0)];
        assert!(matches!(
            advise(&volunteer(None), &c, &o, NOW),
            Advice::Idle { .. }
        ));
    }

    #[test]
    fn yielding_needs_the_margin_the_stay_and_the_volunteers_consent() {
        let c = calls(&[("urgent", 10)]);
        // The volunteer is one of 4 on "steady": its work is worth 4000/4 = 1000.
        let steady = opening("steady", 4_000, 4);

        // 1400 per worker is not half as much again as 1000: stay.
        let o = [steady.clone(), opening("urgent", 1_400, 0)];
        assert!(matches!(
            advise(&volunteer(Some("steady")), &c, &o, NOW),
            Advice::Stay { .. }
        ));

        // 1500 is exactly the margin: yield, with the checkpoint grace.
        let o = [steady.clone(), opening("urgent", 1_500, 0)];
        assert_eq!(
            advise(&volunteer(Some("steady")), &c, &o, NOW),
            Advice::Yield {
                from: "steady".into(),
                to: "urgent".into(),
                from_bid: 1_000,
                to_bid: 1_500,
                checkpoint_within: CHECKPOINT_GRACE_SECONDS,
            }
        );

        // The same outranking, refused for each of the three protections.
        let mut unwilling = volunteer(Some("steady"));
        unwilling.preemptible = false;
        assert!(matches!(
            advise(&unwilling, &c, &o, NOW),
            Advice::Stay { .. }
        ));
        let mut fresh = volunteer(Some("steady"));
        fresh.held_for = MIN_HOLD_FLOOR_SECONDS - 1;
        assert!(matches!(advise(&fresh, &c, &o, NOW), Advice::Stay { .. }));
        let mut patient = volunteer(Some("steady"));
        patient.min_hold = 7_200;
        assert!(
            matches!(advise(&patient, &c, &o, NOW), Advice::Stay { .. }),
            "its own minimum counts too"
        );
        let mut churned = volunteer(Some("steady"));
        churned.yields_last_hour = MAX_YIELDS_PER_HOUR;
        assert!(matches!(advise(&churned, &c, &o, NOW), Advice::Stay { .. }));
    }

    #[test]
    fn leaving_finished_work_is_starting_not_yielding() {
        let c = calls(&[("next", 10)]);
        let mut done = opening("done", 9_000, 1);
        done.closed = true;
        let o = [done, opening("next", 10, 0)];
        let mut v = volunteer(Some("done"));
        v.held_for = 0;
        v.preemptible = false;
        assert_eq!(
            advise(&v, &c, &o, NOW),
            Advice::Start {
                objective_id: "next".into(),
                bid: 10
            }
        );
    }

    #[test]
    fn calls_expire_renew_and_are_capped() {
        let mut c = Calls::default();
        c.raise("a", 3, 60, "", NOW).unwrap();
        assert_eq!(c.open(NOW + 59).len(), 1);
        assert!(c.open(NOW + 60).is_empty());
        // Renewing keeps when it was first raised.
        c.raise("a", 5, 600, "", NOW + 30).unwrap();
        assert_eq!(c.open(NOW + 100)[0].raised_at, NOW);
        assert_eq!(c.open(NOW + 100)[0].want, 5);
        assert_eq!(c.raise("b", 0, 600, "", NOW), Err(CallError::BadWant));
        assert_eq!(c.raise("b", 1, 59, "", NOW), Err(CallError::BadDuration));
        assert_eq!(
            c.raise("b", 1, 600, &"x".repeat(281), NOW),
            Err(CallError::NoteTooLong)
        );
        for i in 0..MAX_CALLS - 1 {
            c.raise(&format!("o{i}"), 1, 600, "", NOW).unwrap();
        }
        assert_eq!(
            c.raise("one-too-many", 1, 600, "", NOW),
            Err(CallError::Full)
        );
        // An expired call frees its slot.
        assert!(c.raise("one-too-many", 1, 600, "", NOW + 10_000).is_ok());
        assert!(c.withdraw("one-too-many"));
        assert!(!c.withdraw("one-too-many"));
    }

    #[test]
    fn displaced_work_is_charged_to_the_call_that_took_the_machine() {
        let mut l = Ledger::default();
        l.record(&Report {
            volunteer: "gpu-box-1".into(),
            objective_id: "steady".into(),
            core_seconds: 10_000,
            ended: Ended::Yielded {
                by: "urgent".into(),
                unsaved: 900,
            },
        })
        .unwrap();
        l.record(&Report {
            volunteer: "gpu-box-1".into(),
            objective_id: "urgent".into(),
            core_seconds: 5_000,
            ended: Ended::Worked,
        })
        .unwrap();
        assert_eq!(l.contributed_to("steady"), 10_000);
        assert_eq!(l.contributed_to("urgent"), 5_000);
        assert_eq!(l.displaced_by("urgent"), 900);
        assert_eq!(l.displaced_by("steady"), 0);
        let me = &l.by_volunteer()["gpu-box-1"];
        assert_eq!((me.contributed, me.displaced, me.yields), (15_000, 900, 1));
    }

    #[test]
    fn impossible_reports_are_refused_not_clamped() {
        let mut l = Ledger::default();
        let big = Report {
            volunteer: "v".into(),
            objective_id: "o".into(),
            core_seconds: MAX_REPORT_CORE_SECONDS + 1,
            ended: Ended::Worked,
        };
        assert_eq!(l.record(&big), Err(ReportError::TooLarge));
        let backwards = Report {
            volunteer: "v".into(),
            objective_id: "o".into(),
            core_seconds: 10,
            ended: Ended::Yielded {
                by: "x".into(),
                unsaved: 11,
            },
        };
        assert_eq!(l.record(&backwards), Err(ReportError::UnsavedExceedsWork));
        assert_eq!(l.contributed_to("o"), 0);
    }
}
