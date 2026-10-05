//! Advisory task leases: a worker says *I am on task T of objective O for
//! the next N seconds*, this node keeps that in memory, and anyone reading
//! the node sees who holds what and where two workers collided.
//!
//! # Why a lease when there is a partition function
//!
//! [`crate::partition`] divides a search with no messages at all, and that
//! stays the mechanism work is assigned by: a pure function of the epoch
//! beacon, the node id and the objective id, which anyone can recompute for
//! anyone. `docs/coordination.md` is right that a *dispatcher* is a wound the
//! network does not need to inflict on itself, and nothing here is one.
//!
//! What the function cannot answer is what is happening *now*. A slice
//! assigned to a worker that went home is a hole nobody can see until the
//! epoch turns. A straggler that finished its slice early cannot tell which
//! unworked unit is safe to pick up. Two workers that both chose unit 4,017
//! find out when the second one's artifact verifies fine and mints nothing.
//! The heartbeat roster ([`crate::progress`]) shows the first of these; a
//! lease shows all three, by letting a worker announce a task before it
//! starts it and read back whether somebody else announced it first.
//!
//! The lab answers the same question for agents sharing a space
//! ([`crate::lab`]'s `claim` and `release` ops), as signed CRDT ops that
//! merge across machines. This is the worker-facing, HTTP-fed version for a
//! fleet that reports to one node, and it borrows the lab's vocabulary --
//! `task`, `holder`, `ttl`, `held`/`contended`, outcomes `completed`,
//! `failed`, `abandoned` -- so a reader who knows one knows the other.
//!
//! # What a lease is not
//!
//! **Not a lock.** Nothing here prevents anybody from working anything: the
//! rules engine does not read this table, `work_assignment` does not consult
//! it, and a claim on a unit somebody else leased pays exactly as it would
//! otherwise. `held: false` is advice to work something else, not a refusal.
//!
//! **Not a record.** Never appended, never gossiped, forgotten on restart,
//! exactly like a heartbeat, and for the same reason: a record that reserved
//! work would be a reservation system, with everything `docs/coordination.md`
//! says about those.
//!
//! **Not evidence.** Anyone can lease anything under any name. A lease is a
//! statement of intent and the roster is where intent is visible; what was
//! *done* is in the log and nowhere else.
//!
//! So the worst a false lease does is mislead a worker who trusts the roster
//! into working something else -- a bounded cost that falls on the liar's
//! own objective, since the lease squats a unit the liar is not walking and
//! the partition function has already handed that unit to somebody. A bonded
//! lease would be a market, and `docs/agent-market.md` says why there is not
//! one here.
//!
//! # Bounds
//!
//! The same discipline as the heartbeat roster: capped per objective, per
//! task and overall, refused past the cap rather than evicting, names
//! printable and short, a TTL between one second and a day, and anything
//! released or expired is forgotten after [`FORGET_SECONDS`].

use std::collections::BTreeMap;
use std::fmt;

use crate::canonical::Value;
use crate::time::format_iso8601_utc;

/// A lease asked for without a `ttl_seconds` lasts one default epoch.
pub const DEFAULT_TTL_SECONDS: u64 = 600;
/// The longest lease this node will keep. A task that takes longer is
/// renewed, which is also how a worker that is still alive says so.
pub const MAX_TTL_SECONDS: u64 = 86_400;
/// Released and expired leases are dropped this long after they ended.
pub const FORGET_SECONDS: u64 = 86_400;

pub const MAX_OBJECTIVES: usize = 256;
pub const MAX_TASKS_PER_OBJECTIVE: usize = 4096;
/// Live, expired and released leases on one task together. Many names on
/// one task is a flood or a very popular unit, and both are visible at this
/// size.
pub const MAX_LEASES_PER_TASK: usize = 64;

const MAX_NAME_LEN: usize = 128;
const MAX_TEXT_LEN: usize = 200;

/// How a holder ended its lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The task is done; nobody needs to take it.
    Completed,
    /// The holder tried and could not; somebody else may.
    Failed,
    /// The holder stopped without a result; somebody else may.
    Abandoned,
}

impl Outcome {
    pub fn parse(text: &str) -> Option<Outcome> {
        Some(match text {
            "completed" => Outcome::Completed,
            "failed" => Outcome::Failed,
            "abandoned" => Outcome::Abandoned,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Completed => "completed",
            Outcome::Failed => "failed",
            Outcome::Abandoned => "abandoned",
        }
    }
}

/// What a worker posts to `POST /lease`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub objective_id: String,
    /// The unit of work, named by the worker: `unit:4017`, `range:0-1023`,
    /// `sieve-stage-2`. Free text, because what a task is belongs to the
    /// objective and not to this node; the `units` field below is the
    /// structured form for a divided search.
    pub task: String,
    /// The worker's name -- the same string it submits claims and heartbeats
    /// under, so a reader can put the three on one row.
    pub holder: String,
    pub ttl: u64,
    /// The unit range `[first, end)` this task covers, when it is one.
    pub units: Option<(u64, u64)>,
    /// The epoch the holder believes it is in.
    pub epoch: Option<u64>,
    /// Anything the holder wants a reader to see beside the lease.
    pub note: Option<String>,
    /// Whether an enrolled fleet member signed it. Set by the node after it
    /// verified the signature, never read from the body.
    pub member: bool,
}

/// What a worker posts to `POST /lease/release`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub objective_id: String,
    pub task: String,
    pub holder: String,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    NotAnObject,
    Missing(&'static str),
    Invalid {
        field: &'static str,
        expected: &'static str,
    },
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeaseError::NotAnObject => write!(f, "a lease is a JSON object"),
            LeaseError::Missing(field) => write!(f, "missing required field `{field}`"),
            LeaseError::Invalid { field, expected } => {
                write!(f, "field `{field}` must be {expected}")
            }
        }
    }
}

impl std::error::Error for LeaseError {}

pub const CLAIM_FIELDS: &[&str] = &[
    "objective_id",
    "task",
    "holder",
    "ttl_seconds",
    "units",
    "epoch",
    "note",
];

pub const RELEASE_FIELDS: &[&str] = &["objective_id", "task", "holder", "outcome"];

fn text_field(
    object: &BTreeMap<String, Value>,
    field: &'static str,
    max: usize,
) -> Result<Option<String>, LeaseError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() && s.chars().count() <= max => {
            if s.chars().any(char::is_control) {
                return Err(LeaseError::Invalid {
                    field,
                    expected: "printable text",
                });
            }
            Ok(Some(s.clone()))
        }
        Some(_) => Err(LeaseError::Invalid {
            field,
            expected: "a non-empty string of at most a couple hundred characters",
        }),
    }
}

fn count_field(
    object: &BTreeMap<String, Value>,
    field: &'static str,
) -> Result<Option<u64>, LeaseError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or(LeaseError::Invalid {
            field,
            expected: "a non-negative integer",
        }),
    }
}

impl Claim {
    /// Decode a claim. Returns it and the names of fields it did not
    /// understand, so a misspelling is reported back to the client that
    /// made it rather than silently dropped.
    pub fn from_value(value: &Value) -> Result<(Claim, Vec<String>), LeaseError> {
        let object = value.as_object().ok_or(LeaseError::NotAnObject)?;
        let ignored = object
            .keys()
            .filter(|key| !CLAIM_FIELDS.contains(&key.as_str()))
            .cloned()
            .collect();
        let objective_id = text_field(object, "objective_id", MAX_NAME_LEN)?
            .ok_or(LeaseError::Missing("objective_id"))?;
        let task = text_field(object, "task", MAX_NAME_LEN)?.ok_or(LeaseError::Missing("task"))?;
        let holder =
            text_field(object, "holder", MAX_NAME_LEN)?.ok_or(LeaseError::Missing("holder"))?;
        let ttl = match count_field(object, "ttl_seconds")? {
            None => DEFAULT_TTL_SECONDS,
            Some(ttl) if (1..=MAX_TTL_SECONDS).contains(&ttl) => ttl,
            Some(_) => {
                return Err(LeaseError::Invalid {
                    field: "ttl_seconds",
                    expected: "between 1 and 86400 (a day); renew a lease that must outlast it",
                })
            }
        };
        let units =
            match object.get("units") {
                None | Some(Value::Null) => None,
                Some(range) => {
                    let bounds = range.as_object().ok_or(LeaseError::Invalid {
                        field: "units",
                        expected: "an object {first, end}",
                    })?;
                    let bound = |key: &str| bounds.get(key).and_then(Value::as_u64);
                    match (bound("first"), bound("end")) {
                        (Some(first), Some(end)) if first <= end => Some((first, end)),
                        _ => return Err(LeaseError::Invalid {
                            field: "units",
                            expected:
                                "an object {first, end} of non-negative integers with first <= end",
                        }),
                    }
                }
            };
        Ok((
            Claim {
                objective_id,
                task,
                holder,
                ttl,
                units,
                epoch: count_field(object, "epoch")?,
                note: text_field(object, "note", MAX_TEXT_LEN)?,
                member: false,
            },
            ignored,
        ))
    }
}

impl Release {
    pub fn from_value(value: &Value) -> Result<(Release, Vec<String>), LeaseError> {
        let object = value.as_object().ok_or(LeaseError::NotAnObject)?;
        let ignored = object
            .keys()
            .filter(|key| !RELEASE_FIELDS.contains(&key.as_str()))
            .cloned()
            .collect();
        let objective_id = text_field(object, "objective_id", MAX_NAME_LEN)?
            .ok_or(LeaseError::Missing("objective_id"))?;
        let task = text_field(object, "task", MAX_NAME_LEN)?.ok_or(LeaseError::Missing("task"))?;
        let holder =
            text_field(object, "holder", MAX_NAME_LEN)?.ok_or(LeaseError::Missing("holder"))?;
        let outcome = text_field(object, "outcome", MAX_NAME_LEN)?
            .ok_or(LeaseError::Missing("outcome"))
            .and_then(|text| {
                Outcome::parse(&text).ok_or(LeaseError::Invalid {
                    field: "outcome",
                    expected: "one of completed, failed, abandoned",
                })
            })?;
        Ok((
            Release {
                objective_id,
                task,
                holder,
                outcome,
            },
            ignored,
        ))
    }
}

/// One holder's lease on one task, as kept.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lease {
    holder: String,
    /// When this holder first claimed the task.
    since: u64,
    /// The last claim or renewal.
    renewed_at: u64,
    expires_at: u64,
    ttl: u64,
    units: Option<(u64, u64)>,
    epoch: Option<u64>,
    note: Option<String>,
    released: Option<(u64, Outcome)>,
    /// Whether the last claim or renewal was signed by an enrolled member.
    member: bool,
}

impl Lease {
    fn live(&self, now: u64) -> bool {
        self.released.is_none() && self.expires_at > now
    }

    /// When this lease stopped mattering: its release, or its expiry.
    fn ended_at(&self, now: u64) -> Option<u64> {
        match self.released {
            Some((at, _)) => Some(at),
            None if self.expires_at <= now => Some(self.expires_at),
            None => None,
        }
    }
}

/// Every lease on one task, in arrival order. Arrival at *this node* --
/// which is the only order a process-local roster can have, and is said so
/// in the payload.
#[derive(Debug, Default)]
struct TaskLeases {
    leases: Vec<Lease>,
}

impl TaskLeases {
    /// The holder: the earliest-arrived live lease.
    fn holder(&self, now: u64) -> Option<&Lease> {
        self.leases.iter().find(|lease| lease.live(now))
    }

    /// Who released this task `completed`, if anyone.
    fn completed_by(&self) -> Option<&Lease> {
        self.leases
            .iter()
            .find(|lease| matches!(lease.released, Some((_, Outcome::Completed))))
    }

    fn position(&self, holder: &str) -> Option<usize> {
        self.leases.iter().position(|lease| lease.holder == holder)
    }
}

/// The roster is full; the lease was not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterFull(pub &'static str);

impl fmt::Display for RosterFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RosterFull {}

/// Why a claim or release was not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Full(RosterFull),
    /// Somebody released this task `completed`; the claim was not kept.
    /// The log, not this roster, decides whether the task is really done.
    AlreadyCompleted {
        by: String,
        at: u64,
    },
    /// A release for a lease this node does not hold.
    NoSuchLease,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Full(full) => write!(f, "{full}"),
            Refusal::AlreadyCompleted { by, at } => write!(
                f,
                "`{by}` released this task as completed at {}; as far as this node knows there \
                 is nothing left to do. The log is the authority on whether that is true.",
                iso(*at)
            ),
            Refusal::NoSuchLease => write!(
                f,
                "this node holds no lease on that task by that holder; a restart forgets every \
                 lease, so claim again if the work is still yours"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// The answer to a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    /// Whether the claimant holds the task now.
    pub held: bool,
    /// Whether this was a renewal of a lease the claimant already had.
    pub renewed: bool,
    pub holder: String,
    pub expires_at: u64,
    /// The other live claimants on the task, in arrival order.
    pub contended_with: Vec<String>,
}

/// Every lease this process has been sent and not yet forgotten.
#[derive(Debug, Default)]
pub struct Leases {
    objectives: BTreeMap<String, BTreeMap<String, TaskLeases>>,
}

impl Leases {
    /// Take or renew a lease. The earliest live claim on a task holds it.
    pub fn claim(&mut self, claim: Claim, now: u64) -> Result<Standing, Refusal> {
        self.forget(now);
        let is_new_objective = !self.objectives.contains_key(&claim.objective_id);
        if is_new_objective && self.objectives.len() >= MAX_OBJECTIVES {
            return Err(Refusal::Full(RosterFull(
                "this node is holding leases for as many objectives as it will; try again when \
                 one goes quiet",
            )));
        }
        let tasks = self
            .objectives
            .entry(claim.objective_id.clone())
            .or_default();
        let is_new_task = !tasks.contains_key(&claim.task);
        if is_new_task && tasks.len() >= MAX_TASKS_PER_OBJECTIVE {
            return Err(Refusal::Full(RosterFull(
                "this node is holding leases on as many tasks of this objective as it will; \
                 try again when some are released or expire",
            )));
        }
        let task = tasks.entry(claim.task.clone()).or_default();
        if let Some(done) = task.completed_by() {
            let (at, _) = done.released.expect("completed means released");
            return Err(Refusal::AlreadyCompleted {
                by: done.holder.clone(),
                at,
            });
        }
        let expires_at = now.saturating_add(claim.ttl);
        let renewed = match task.position(&claim.holder) {
            Some(index) => {
                let lease = &mut task.leases[index];
                let was_live = lease.live(now);
                // A holder that comes back after expiring or releasing has a
                // fresh lease, and goes to the back of the queue: it gave the
                // task up, and whoever claimed meanwhile holds it.
                if !was_live {
                    let mut fresh = task.leases.remove(index);
                    fresh.since = now;
                    fresh.released = None;
                    task.leases.push(fresh);
                }
                let lease = task
                    .leases
                    .iter_mut()
                    .find(|lease| lease.holder == claim.holder)
                    .expect("just placed");
                lease.renewed_at = now;
                lease.expires_at = expires_at;
                lease.ttl = claim.ttl;
                lease.units = claim.units;
                lease.epoch = claim.epoch;
                lease.note = claim.note.clone();
                lease.member = claim.member;
                was_live
            }
            None => {
                if task.leases.len() >= MAX_LEASES_PER_TASK {
                    return Err(Refusal::Full(RosterFull(
                        "this node is holding as many leases on this task as it will",
                    )));
                }
                task.leases.push(Lease {
                    holder: claim.holder.clone(),
                    since: now,
                    renewed_at: now,
                    expires_at,
                    ttl: claim.ttl,
                    units: claim.units,
                    epoch: claim.epoch,
                    note: claim.note.clone(),
                    released: None,
                    member: claim.member,
                });
                false
            }
        };
        let holder = task.holder(now).expect("the claim just made is live");
        let held = holder.holder == claim.holder;
        let contended_with = task
            .leases
            .iter()
            .filter(|lease| lease.live(now) && lease.holder != claim.holder)
            .map(|lease| lease.holder.clone())
            .collect();
        Ok(Standing {
            held,
            renewed,
            holder: holder.holder.clone(),
            expires_at,
            contended_with,
        })
    }

    /// End a lease. Only the lease's own holder can, and only once.
    pub fn release(&mut self, release: Release, now: u64) -> Result<(), Refusal> {
        self.forget(now);
        let lease = self
            .objectives
            .get_mut(&release.objective_id)
            .and_then(|tasks| tasks.get_mut(&release.task))
            .and_then(|task| {
                task.leases
                    .iter_mut()
                    .find(|lease| lease.holder == release.holder && lease.released.is_none())
            })
            .ok_or(Refusal::NoSuchLease)?;
        lease.released = Some((now, release.outcome));
        Ok(())
    }

    /// Drop leases that ended more than [`FORGET_SECONDS`] ago, then tasks
    /// and objectives with nothing left.
    fn forget(&mut self, now: u64) {
        for tasks in self.objectives.values_mut() {
            for task in tasks.values_mut() {
                task.leases.retain(|lease| {
                    lease
                        .ended_at(now)
                        .is_none_or(|ended| now.saturating_sub(ended) <= FORGET_SECONDS)
                });
            }
            tasks.retain(|_, task| !task.leases.is_empty());
        }
        self.objectives.retain(|_, tasks| !tasks.is_empty());
    }

    /// Objectives with any lease on the roster.
    pub fn objectives(&self) -> impl Iterator<Item = &String> {
        self.objectives.keys()
    }

    /// Every task of one objective, as `GET /leases/{id}` answers it.
    pub fn report(&self, objective_id: &str, now: u64) -> Value {
        let mut tasks = Vec::new();
        let (mut held, mut contended, mut expired, mut released, mut completed) =
            (0i128, 0i128, 0i128, 0i128, 0i128);
        if let Some(roster) = self.objectives.get(objective_id) {
            for (name, task) in roster {
                let holder = task.holder(now);
                let done = task.completed_by();
                let mut rows = Vec::new();
                for lease in &task.leases {
                    let status = if lease.released.is_some() {
                        released += 1;
                        if matches!(lease.released, Some((_, Outcome::Completed))) {
                            completed += 1;
                        }
                        "released"
                    } else if lease.expires_at <= now {
                        expired += 1;
                        "expired"
                    } else if holder.is_some_and(|h| h.holder == lease.holder) {
                        held += 1;
                        "held"
                    } else {
                        contended += 1;
                        "contended"
                    };
                    rows.push(lease_value(lease, status, now));
                }
                tasks.push(Value::object([
                    ("task", Value::string(name.clone())),
                    (
                        "status",
                        Value::string(if done.is_some() {
                            "completed"
                        } else if holder.is_some() {
                            "held"
                        } else {
                            "open"
                        }),
                    ),
                    (
                        "holder",
                        match holder {
                            Some(lease) => Value::string(lease.holder.clone()),
                            None => Value::Null,
                        },
                    ),
                    (
                        "completed_by",
                        match done {
                            Some(lease) => Value::string(lease.holder.clone()),
                            None => Value::Null,
                        },
                    ),
                    ("leases", Value::Array(rows)),
                ]));
            }
        }
        Value::object([
            ("objective_id", Value::string(objective_id)),
            ("generated_at", Value::string(iso(now))),
            ("tasks", Value::Array(tasks)),
            ("held", Value::Int(held)),
            ("contended", Value::Int(contended)),
            ("expired", Value::Int(expired)),
            ("released", Value::Int(released)),
            ("completed", Value::Int(completed)),
            (
                "default_ttl_seconds",
                Value::Int(i128::from(DEFAULT_TTL_SECONDS)),
            ),
            ("max_ttl_seconds", Value::Int(i128::from(MAX_TTL_SECONDS))),
            (
                "note",
                Value::string(
                    "Advisory leases posted to POST /lease and held in this node's memory. The \
                     earliest live claim on a task holds it, by arrival at this node; a lease \
                     is never a record, never a lock, never evidence of work, and nothing that \
                     moves money reads it. What was done is in the log.",
                ),
            ),
        ])
    }
}

fn lease_value(lease: &Lease, status: &str, now: u64) -> Value {
    Value::object([
        ("holder", Value::string(lease.holder.clone())),
        ("status", Value::string(status)),
        ("since", Value::string(iso(lease.since))),
        ("renewed_at", Value::string(iso(lease.renewed_at))),
        ("expires_at", Value::string(iso(lease.expires_at))),
        (
            "expires_in_seconds",
            Value::Int(i128::from(lease.expires_at.saturating_sub(now))),
        ),
        ("ttl_seconds", Value::Int(i128::from(lease.ttl))),
        (
            "units",
            match lease.units {
                Some((first, end)) => Value::object([
                    ("first", Value::Int(i128::from(first))),
                    ("end", Value::Int(i128::from(end))),
                ]),
                None => Value::Null,
            },
        ),
        (
            "epoch",
            match lease.epoch {
                Some(epoch) => Value::Int(i128::from(epoch)),
                None => Value::Null,
            },
        ),
        (
            "note",
            match &lease.note {
                Some(note) => Value::string(note.clone()),
                None => Value::Null,
            },
        ),
        (
            "released",
            match lease.released {
                Some((at, outcome)) => Value::object([
                    ("at", Value::string(iso(at))),
                    ("outcome", Value::string(outcome.as_str())),
                ]),
                None => Value::Null,
            },
        ),
        ("member", Value::Bool(lease.member)),
    ])
}

fn iso(unix: u64) -> String {
    format_iso8601_utc(i64::try_from(unix).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(task: &str, holder: &str, ttl: u64) -> Claim {
        Claim {
            objective_id: "sha256:obj".into(),
            task: task.into(),
            holder: holder.into(),
            ttl,
            units: None,
            epoch: None,
            note: None,
            member: false,
        }
    }

    fn release(task: &str, holder: &str, outcome: Outcome) -> Release {
        Release {
            objective_id: "sha256:obj".into(),
            task: task.into(),
            holder: holder.into(),
            outcome,
        }
    }

    fn task<'a>(report: &'a Value, name: &str) -> &'a Value {
        report
            .get("tasks")
            .and_then(Value::as_array)
            .expect("tasks")
            .iter()
            .find(|task| task.get("task").and_then(Value::as_str) == Some(name))
            .expect("the task")
    }

    #[test]
    fn the_first_live_claim_holds_and_a_second_is_contended() {
        let mut leases = Leases::default();
        let first = leases
            .claim(claim("unit:7", "alice", 600), 1_000)
            .expect("kept");
        assert!(first.held);
        assert!(!first.renewed);
        assert!(first.contended_with.is_empty());
        assert_eq!(first.expires_at, 1_600);

        let second = leases
            .claim(claim("unit:7", "bob", 600), 1_010)
            .expect("kept");
        assert!(!second.held);
        assert_eq!(second.holder, "alice");
        assert_eq!(second.contended_with, vec!["alice".to_string()]);

        let report = leases.report("sha256:obj", 1_020);
        assert_eq!(report.get("held").unwrap(), &Value::Int(1));
        assert_eq!(report.get("contended").unwrap(), &Value::Int(1));
        let unit = task(&report, "unit:7");
        assert_eq!(unit.get("status").unwrap().as_str(), Some("held"));
        assert_eq!(unit.get("holder").unwrap().as_str(), Some("alice"));
    }

    #[test]
    fn a_renewal_extends_and_an_expired_holder_loses_to_whoever_claimed_meanwhile() {
        let mut leases = Leases::default();
        leases.claim(claim("u", "alice", 100), 0).expect("kept");
        let renewed = leases.claim(claim("u", "alice", 100), 50).expect("kept");
        assert!(renewed.held && renewed.renewed);
        assert_eq!(renewed.expires_at, 150);

        // alice lapses; bob claims; alice comes back and is behind bob.
        let bob = leases.claim(claim("u", "bob", 100), 200).expect("kept");
        assert!(bob.held);
        let alice = leases.claim(claim("u", "alice", 100), 210).expect("kept");
        assert!(!alice.held);
        assert!(
            !alice.renewed,
            "a lapsed lease comes back fresh, not renewed"
        );
        assert_eq!(alice.holder, "bob");

        let report = leases.report("sha256:obj", 220);
        let rows = task(&report, "u")
            .get("leases")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(rows[0].get("holder").unwrap().as_str(), Some("bob"));
        assert_eq!(rows[0].get("status").unwrap().as_str(), Some("held"));
        assert_eq!(rows[1].get("holder").unwrap().as_str(), Some("alice"));
        assert_eq!(rows[1].get("status").unwrap().as_str(), Some("contended"));
    }

    #[test]
    fn a_release_ends_the_lease_and_completed_closes_the_task() {
        let mut leases = Leases::default();
        leases.claim(claim("u", "alice", 600), 0).expect("kept");
        leases.claim(claim("u", "bob", 600), 1).expect("kept");
        leases
            .release(release("u", "alice", Outcome::Abandoned), 2)
            .expect("released");
        // bob inherits the task once alice lets go.
        let report = leases.report("sha256:obj", 3);
        assert_eq!(
            task(&report, "u").get("holder").unwrap().as_str(),
            Some("bob")
        );
        assert_eq!(report.get("released").unwrap(), &Value::Int(1));

        leases
            .release(release("u", "bob", Outcome::Completed), 4)
            .expect("released");
        let report = leases.report("sha256:obj", 5);
        assert_eq!(
            task(&report, "u").get("status").unwrap().as_str(),
            Some("completed")
        );
        assert_eq!(
            task(&report, "u").get("completed_by").unwrap().as_str(),
            Some("bob")
        );
        assert_eq!(report.get("completed").unwrap(), &Value::Int(1));

        match leases.claim(claim("u", "carol", 600), 6) {
            Err(Refusal::AlreadyCompleted { by, at }) => {
                assert_eq!(by, "bob");
                assert_eq!(at, 4);
            }
            other => panic!("a completed task refuses new claims: {other:?}"),
        }
    }

    #[test]
    fn only_the_holder_releases_and_only_once() {
        let mut leases = Leases::default();
        leases.claim(claim("u", "alice", 600), 0).expect("kept");
        assert_eq!(
            leases.release(release("u", "mallory", Outcome::Completed), 1),
            Err(Refusal::NoSuchLease)
        );
        leases
            .release(release("u", "alice", Outcome::Failed), 2)
            .expect("released");
        assert_eq!(
            leases.release(release("u", "alice", Outcome::Completed), 3),
            Err(Refusal::NoSuchLease),
            "a lease ends once"
        );
        assert_eq!(
            leases.release(release("nope", "alice", Outcome::Failed), 3),
            Err(Refusal::NoSuchLease)
        );
    }

    #[test]
    fn ended_leases_are_forgotten_after_a_day_and_the_roster_refuses_past_its_caps() {
        let mut leases = Leases::default();
        leases.claim(claim("u", "alice", 10), 0).expect("kept");
        assert_eq!(leases.objectives().count(), 1);
        // Expired at 10, forgotten at 10 + a day.
        leases
            .claim(claim("v", "bob", 10), 10 + FORGET_SECONDS + 1)
            .expect("kept");
        let report = leases.report("sha256:obj", 10 + FORGET_SECONDS + 2);
        assert_eq!(report.get("tasks").unwrap().as_array().unwrap().len(), 1);

        let mut crowded = Leases::default();
        for n in 0..MAX_LEASES_PER_TASK {
            crowded
                .claim(claim("hot", &format!("w{n}"), 600), 0)
                .expect("kept");
        }
        assert!(matches!(
            crowded.claim(claim("hot", "late", 600), 0),
            Err(Refusal::Full(_))
        ));
        // A holder already on the task renews even when it is full.
        crowded.claim(claim("hot", "w3", 600), 1).expect("renewal");
    }

    #[test]
    fn claims_decode_with_defaults_and_refuse_what_they_cannot_keep() {
        let (claim, ignored) = Claim::from_value(
            &Value::from_json(
                r#"{"objective_id":"sha256:o","task":"unit:1","holder":"gpu-7",
                    "units":{"first":1,"end":9},"epoch":5,"colour":"blue"}"#,
            )
            .unwrap(),
        )
        .expect("decodes");
        assert_eq!(claim.ttl, DEFAULT_TTL_SECONDS);
        assert_eq!(claim.units, Some((1, 9)));
        assert_eq!(claim.epoch, Some(5));
        assert_eq!(ignored, vec!["colour".to_string()]);

        let too_long = Value::from_json(
            r#"{"objective_id":"sha256:o","task":"t","holder":"h","ttl_seconds":100000}"#,
        )
        .unwrap();
        assert!(matches!(
            Claim::from_value(&too_long),
            Err(LeaseError::Invalid {
                field: "ttl_seconds",
                ..
            })
        ));
        let no_task = Value::from_json(r#"{"objective_id":"sha256:o","holder":"h"}"#).unwrap();
        assert_eq!(
            Claim::from_value(&no_task).unwrap_err(),
            LeaseError::Missing("task")
        );
        let bad_outcome = Value::from_json(
            r#"{"objective_id":"sha256:o","task":"t","holder":"h","outcome":"done"}"#,
        )
        .unwrap();
        assert!(matches!(
            Release::from_value(&bad_outcome),
            Err(LeaseError::Invalid {
                field: "outcome",
                ..
            })
        ));
    }
}
