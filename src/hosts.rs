//! The host roster: machines that registered their hardware with this node.
//!
//! A *worker* heartbeat ([`crate::progress`]) says what one process is doing
//! on one objective. A *host* registration says what a machine **is**: how
//! many CPUs and how much memory it has, which GPUs are in it, and which
//! sandboxes it can run executor jobs under. `cairn agent run` posts one to
//! `POST /hosts` every interval; `GET /hosts` lists them and `GET /network`
//! sums them under `compute.hosts`, so an operator can answer "what hardware
//! is on this network right now" before any objective is being worked at all.
//!
//! # The same trust story as a heartbeat, stated once more
//!
//! A registration is **not a record**: never appended, never gossiped, never
//! verified, forgotten on restart, and never evidence of anything. Anyone can
//! post one under any name and claim any hardware. The reader labels it as
//! reported, the server bounds how many it will hold and how large each may
//! be, and nothing downstream reads it for money -- the rules engine does not
//! know this table exists. What a false registration buys its author is a
//! wrong number on a page; what it costs the node is a bounded allocation.
//!
//! # Why the hardware block is kept opaque
//!
//! The agent reports its probe as a nested object -- CPUs, memory, every GPU
//! with its vendor and memory, the sandboxes it found and which engine drives
//! each. That shape will grow as hosts grow stranger, and a server that
//! validated every field would refuse the next field anybody added. So the
//! server holds the object as posted, caps its encoded size, lifts out the
//! few integers it sums, and hands the rest back verbatim: the agent and the
//! page agree on the shape, and the node in between is a bounded mailbox.

use std::collections::BTreeMap;
use std::fmt;

use crate::canonical::Value;
use crate::progress::{Liveness, FORGET_SECONDS};
use crate::time::format_iso8601_utc;

/// Registrations this node will hold at once. Past this the server answers
/// 429 and keeps what it has, exactly as the heartbeat roster does.
pub const MAX_HOSTS: usize = 4096;

/// The canonical encoding of one registration may not exceed this. A probe
/// of a 64-GPU box is a few kilobytes; a flood is not.
pub const MAX_ENCODED_BYTES: usize = 16 * 1024;

const MAX_NAME_LEN: usize = 128;
const MAX_TEXT_LEN: usize = 200;
const MAX_ROLES: usize = 8;
const MAX_OBJECTIVES: usize = 64;

/// The fields a registration may carry at the top level. Anything else is
/// named back to the poster under `ignored`, so a misspelling is noticed by
/// the client that made it.
const FIELDS: [&str; 7] = [
    "host",
    "agent",
    "roles",
    "hardware",
    "sandboxes",
    "jobs",
    "objectives",
];

/// What a host posts to `POST /hosts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The machine's name, as its operator wants it on a page. Workers on it
    /// should heartbeat under names that mention it, but nothing enforces
    /// that: a host and a worker are different facts.
    pub host: String,
    /// The agent that posted, with its version: `cairn-agent/1.15.3`.
    pub agent: Option<String>,
    /// Roles the operator declared the host for. The same words as
    /// [`crate::network::Role`], and the same hint-not-permission rule.
    pub roles: Vec<String>,
    /// The probe, as posted. See the module docs for why it is opaque.
    pub hardware: Value,
    /// Which sandboxes the host can run jobs under, keyed by name:
    /// `runsc`, `kata`, `bwrap`, each with whatever the agent found out.
    pub sandboxes: Value,
    /// Job counters: `running`, `capacity`, `completed`, `failed`.
    pub jobs: Value,
    /// Objectives the host is currently running jobs for.
    pub objectives: Vec<String>,
    /// Whether an enrolled fleet member signed it. Set by the node after it
    /// verified the signature, never read from the body.
    pub member: bool,
}

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    NotAnObject,
    Missing(&'static str),
    Invalid {
        field: &'static str,
        expected: &'static str,
    },
    TooLarge {
        bytes: usize,
    },
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationError::NotAnObject => write!(f, "a registration is a JSON object"),
            RegistrationError::Missing(field) => write!(f, "missing required field `{field}`"),
            RegistrationError::Invalid { field, expected } => {
                write!(f, "field `{field}` must be {expected}")
            }
            RegistrationError::TooLarge { bytes } => write!(
                f,
                "registration is {bytes} bytes encoded; at most {MAX_ENCODED_BYTES} is held"
            ),
        }
    }
}

impl std::error::Error for RegistrationError {}

impl Registration {
    /// Decode a registration. Returns it and the names of any top-level
    /// fields it did not understand.
    pub fn from_value(value: &Value) -> Result<(Registration, Vec<String>), RegistrationError> {
        let object = value.as_object().ok_or(RegistrationError::NotAnObject)?;
        let encoded = value.canonical_bytes().len();
        if encoded > MAX_ENCODED_BYTES {
            return Err(RegistrationError::TooLarge { bytes: encoded });
        }
        let ignored = object
            .keys()
            .filter(|key| !FIELDS.contains(&key.as_str()))
            .cloned()
            .collect();

        let text = |field: &'static str, max: usize| -> Result<Option<String>, RegistrationError> {
            match object.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s))
                    if !s.is_empty()
                        && s.chars().count() <= max
                        && !s.chars().any(char::is_control) =>
                {
                    Ok(Some(s.clone()))
                }
                Some(_) => Err(RegistrationError::Invalid {
                    field,
                    expected: "a non-empty printable string of at most a couple hundred characters",
                }),
            }
        };
        let names = |field: &'static str, max: usize| -> Result<Vec<String>, RegistrationError> {
            match object.get(field) {
                None | Some(Value::Null) => Ok(Vec::new()),
                Some(Value::Array(items)) if items.len() <= max => items
                    .iter()
                    .map(|item| match item {
                        Value::String(s)
                            if !s.is_empty()
                                && s.chars().count() <= MAX_NAME_LEN
                                && !s.chars().any(char::is_control) =>
                        {
                            Ok(s.clone())
                        }
                        _ => Err(RegistrationError::Invalid {
                            field,
                            expected: "an array of short printable strings",
                        }),
                    })
                    .collect(),
                Some(_) => Err(RegistrationError::Invalid {
                    field,
                    expected: "a short array of strings",
                }),
            }
        };
        let object_field = |field: &'static str| -> Result<Value, RegistrationError> {
            match object.get(field) {
                None | Some(Value::Null) => Ok(Value::object(Vec::<(&str, Value)>::new())),
                Some(value @ Value::Object(_)) => Ok(value.clone()),
                Some(_) => Err(RegistrationError::Invalid {
                    field,
                    expected: "an object",
                }),
            }
        };

        let host = text("host", MAX_NAME_LEN)?.ok_or(RegistrationError::Missing("host"))?;
        let registration = Registration {
            host,
            agent: text("agent", MAX_TEXT_LEN)?,
            roles: names("roles", MAX_ROLES)?,
            hardware: object_field("hardware")?,
            sandboxes: object_field("sandboxes")?,
            jobs: object_field("jobs")?,
            objectives: names("objectives", MAX_OBJECTIVES)?,
            member: false,
        };
        Ok((registration, ignored))
    }

    fn int(value: &Value, key: &str) -> Option<u64> {
        value.get(key).and_then(Value::as_u64)
    }

    /// Logical CPUs, as the host reported them.
    pub fn cpus(&self) -> Option<u64> {
        Self::int(&self.hardware, "cpus")
    }

    pub fn memory_mb(&self) -> Option<u64> {
        Self::int(&self.hardware, "memory_mb")
    }

    /// How many GPUs the host listed.
    pub fn gpus(&self) -> u64 {
        self.hardware
            .get("gpus")
            .and_then(Value::as_array)
            .map(|gpus| gpus.len() as u64)
            .unwrap_or(0)
    }

    /// Sandboxes the host reported as usable (`"usable": true` under the
    /// sandbox's name), in name order.
    pub fn usable_sandboxes(&self) -> Vec<String> {
        self.sandboxes
            .as_object()
            .map(|table| {
                table
                    .iter()
                    .filter(|(_, facts)| facts.get("usable").and_then(Value::as_bool) == Some(true))
                    .map(|(name, _)| name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn jobs_running(&self) -> u64 {
        Self::int(&self.jobs, "running").unwrap_or(0)
    }

    pub fn jobs_capacity(&self) -> u64 {
        Self::int(&self.jobs, "capacity").unwrap_or(0)
    }
}

/// Why a registration could not be held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Full {
    pub hosts: usize,
}

impl fmt::Display for Full {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this node holds registrations for {} hosts, the most it will; it kept what it had",
            self.hosts
        )
    }
}

impl std::error::Error for Full {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    registration: Registration,
    first_seen: u64,
    received_at: u64,
    /// Registrations received this process lifetime, so a restart on the
    /// host side shows as a counter that keeps climbing here.
    posts: u64,
}

/// One host as a page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub registration: Registration,
    pub status: Liveness,
    pub age_seconds: u64,
    pub first_seen: u64,
    pub received_at: u64,
    pub posts: u64,
}

/// Every host that registered with this node, keyed by name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Roster {
    hosts: BTreeMap<String, Seen>,
}

impl Roster {
    /// Record a registration received at `now`. A host that was already
    /// known is updated in place; a new one is refused past [`MAX_HOSTS`].
    pub fn record(&mut self, registration: Registration, now: u64) -> Result<Liveness, Full> {
        self.forget(now);
        match self.hosts.get_mut(&registration.host) {
            Some(seen) => {
                seen.registration = registration;
                seen.received_at = now;
                seen.posts += 1;
            }
            None => {
                if self.hosts.len() >= MAX_HOSTS {
                    return Err(Full {
                        hosts: self.hosts.len(),
                    });
                }
                self.hosts.insert(
                    registration.host.clone(),
                    Seen {
                        registration,
                        first_seen: now,
                        received_at: now,
                        posts: 1,
                    },
                );
            }
        }
        Ok(Liveness::Live)
    }

    fn forget(&mut self, now: u64) {
        self.hosts
            .retain(|_, seen| now.saturating_sub(seen.received_at) <= FORGET_SECONDS);
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Every host with its standing at `now`, live first, then by name.
    pub fn list(&self, now: u64) -> Vec<Listed> {
        let mut rows: Vec<Listed> = self
            .hosts
            .values()
            .map(|seen| {
                let age = now.saturating_sub(seen.received_at);
                Listed {
                    registration: seen.registration.clone(),
                    status: Liveness::of_age(age),
                    age_seconds: age,
                    first_seen: seen.first_seen,
                    received_at: seen.received_at,
                    posts: seen.posts,
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            let rank = |status: Liveness| match status {
                Liveness::Live => 0,
                Liveness::Stale => 1,
                Liveness::Gone => 2,
            };
            rank(a.status)
                .cmp(&rank(b.status))
                .then_with(|| a.registration.host.cmp(&b.registration.host))
        });
        rows
    }

    /// The roster as `GET /hosts` and `GET /network` publish it: every host
    /// as a row, and the live ones summed.
    pub fn summary(&self, now: u64) -> Value {
        let rows = self.list(now);
        let (mut live, mut stale, mut gone) = (0i128, 0i128, 0i128);
        let (mut cpus, mut memory_mb, mut gpus) = (0u128, 0u128, 0u128);
        let (mut running, mut capacity) = (0u128, 0u128);
        let mut by_sandbox: BTreeMap<String, i128> = BTreeMap::new();
        let mut hosts = Vec::new();
        for row in &rows {
            let reg = &row.registration;
            match row.status {
                Liveness::Live => {
                    live += 1;
                    cpus += u128::from(reg.cpus().unwrap_or(0));
                    memory_mb += u128::from(reg.memory_mb().unwrap_or(0));
                    gpus += u128::from(reg.gpus());
                    running += u128::from(reg.jobs_running());
                    capacity += u128::from(reg.jobs_capacity());
                    for name in reg.usable_sandboxes() {
                        *by_sandbox.entry(name).or_default() += 1;
                    }
                }
                Liveness::Stale => stale += 1,
                Liveness::Gone => gone += 1,
            }
            hosts.push(row.to_value());
        }
        Value::object([
            ("hosts", Value::Array(hosts)),
            ("registered", Value::Int(rows.len() as i128)),
            ("live", Value::Int(live)),
            ("stale", Value::Int(stale)),
            ("gone", Value::Int(gone)),
            ("cpus", Value::Int(cpus as i128)),
            ("memory_mb", Value::Int(memory_mb as i128)),
            ("gpus", Value::Int(gpus as i128)),
            (
                "jobs",
                Value::object([
                    ("running", Value::Int(running as i128)),
                    ("capacity", Value::Int(capacity as i128)),
                ]),
            ),
            (
                "sandboxes",
                Value::array(by_sandbox.into_iter().map(|(name, hosts)| {
                    Value::object([
                        ("sandbox", Value::string(name)),
                        ("hosts", Value::Int(hosts)),
                    ])
                })),
            ),
            (
                "live_within_seconds",
                Value::Int(i128::from(crate::progress::LIVE_SECONDS)),
            ),
            (
                "stale_within_seconds",
                Value::Int(i128::from(crate::progress::STALE_SECONDS)),
            ),
            (
                "note",
                Value::string(
                    "Machines that registered with this node over POST /hosts, as they \
                     described themselves: CPUs, memory, GPUs and the sandboxes each can run \
                     jobs under. Summed over live hosts. Held in this process's memory, \
                     forgotten after a day, verified by nobody, and never a record -- a worker \
                     on one of these hosts is paid for what the log shows it submitted, not \
                     for being listed here.",
                ),
            ),
        ])
    }
}

impl Listed {
    pub fn to_value(&self) -> Value {
        let reg = &self.registration;
        let iso =
            |unix: u64| Value::string(format_iso8601_utc(i64::try_from(unix).unwrap_or(i64::MAX)));
        Value::object([
            ("host", Value::string(reg.host.clone())),
            (
                "agent",
                match &reg.agent {
                    Some(agent) => Value::string(agent.clone()),
                    None => Value::Null,
                },
            ),
            ("status", Value::string(self.status.as_str())),
            ("age_seconds", Value::Int(i128::from(self.age_seconds))),
            ("first_seen", iso(self.first_seen)),
            ("received_at", iso(self.received_at)),
            ("posts", Value::Int(i128::from(self.posts))),
            (
                "roles",
                Value::array(reg.roles.iter().map(|role| Value::string(role.clone()))),
            ),
            ("hardware", reg.hardware.clone()),
            ("sandboxes", reg.sandboxes.clone()),
            (
                "usable_sandboxes",
                Value::array(reg.usable_sandboxes().into_iter().map(Value::string)),
            ),
            ("jobs", reg.jobs.clone()),
            (
                "objectives",
                Value::array(reg.objectives.iter().map(|id| Value::string(id.clone()))),
            ),
            ("member", Value::Bool(reg.member)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(host: &str, cpus: u64, gpus: usize) -> Registration {
        let gpus: Vec<Value> = (0..gpus)
            .map(|index| {
                Value::object([
                    ("index", Value::Int(index as i128)),
                    ("vendor", Value::string("nvidia")),
                    ("model", Value::string("NVIDIA A100-SXM4-80GB")),
                    ("memory_mb", Value::Int(81920)),
                ])
            })
            .collect();
        let text = Value::object([
            ("host", Value::string(host)),
            ("agent", Value::string("cairn-agent/test")),
            ("roles", Value::array([Value::string("executor")])),
            (
                "hardware",
                Value::object([
                    ("cpus", Value::Int(i128::from(cpus))),
                    ("memory_mb", Value::Int(256_000)),
                    ("gpus", Value::Array(gpus)),
                ]),
            ),
            (
                "sandboxes",
                Value::object([
                    ("runsc", Value::object([("usable", Value::Bool(true))])),
                    ("kata", Value::object([("usable", Value::Bool(false))])),
                ]),
            ),
            (
                "jobs",
                Value::object([("running", Value::Int(1)), ("capacity", Value::Int(4))]),
            ),
        ]);
        Registration::from_value(&text).expect("decodes").0
    }

    #[test]
    fn a_registration_decodes_and_names_what_it_ignored() {
        let value = Value::from_json(
            r#"{"host":"box-1","hardware":{"cpus":8,"memory_mb":1024,"gpus":[]},"colour":"blue"}"#,
        )
        .unwrap();
        let (reg, ignored) = Registration::from_value(&value).unwrap();
        assert_eq!(reg.host, "box-1");
        assert_eq!(reg.cpus(), Some(8));
        assert_eq!(reg.gpus(), 0);
        assert_eq!(ignored, vec!["colour".to_string()]);
        assert!(reg.usable_sandboxes().is_empty());
    }

    #[test]
    fn a_registration_without_a_host_or_with_a_bad_one_is_refused() {
        let missing = Value::from_json(r#"{"hardware":{}}"#).unwrap();
        assert_eq!(
            Registration::from_value(&missing).unwrap_err(),
            RegistrationError::Missing("host")
        );
        let control = Value::from_json("{\"host\":\"a\\u0007b\"}").unwrap();
        assert!(matches!(
            Registration::from_value(&control).unwrap_err(),
            RegistrationError::Invalid { field: "host", .. }
        ));
        let not_object = Value::from_json(r#"{"host":"x","hardware":[1]}"#).unwrap();
        assert!(matches!(
            Registration::from_value(&not_object).unwrap_err(),
            RegistrationError::Invalid {
                field: "hardware",
                ..
            }
        ));
        let huge = format!(
            r#"{{"host":"x","hardware":{{"pad":"{}"}}}}"#,
            "a".repeat(MAX_ENCODED_BYTES)
        );
        assert!(matches!(
            Registration::from_value(&Value::from_json(&huge).unwrap()).unwrap_err(),
            RegistrationError::TooLarge { .. }
        ));
    }

    #[test]
    fn the_roster_sums_live_hosts_only_and_forgets_the_old() {
        let mut roster = Roster::default();
        roster.record(registration("a", 64, 8), 1_000).unwrap();
        roster.record(registration("b", 32, 0), 1_000).unwrap();
        // `b` posts again: the same row, updated, and the post count climbs.
        roster.record(registration("b", 48, 1), 1_100).unwrap();
        assert_eq!(roster.len(), 2);

        let summary = roster.summary(1_100);
        assert_eq!(summary.get("live").unwrap().as_i128(), Some(2));
        assert_eq!(summary.get("cpus").unwrap().as_i128(), Some(112));
        assert_eq!(summary.get("gpus").unwrap().as_i128(), Some(9));
        assert_eq!(
            summary
                .get("jobs")
                .unwrap()
                .get("capacity")
                .unwrap()
                .as_i128(),
            Some(8)
        );
        let sandboxes = summary.get("sandboxes").unwrap().as_array().unwrap();
        assert_eq!(sandboxes.len(), 1, "{sandboxes:?}");
        assert_eq!(sandboxes[0].get("sandbox").unwrap().as_str(), Some("runsc"));
        assert_eq!(sandboxes[0].get("hosts").unwrap().as_i128(), Some(2));
        let rows = summary.get("hosts").unwrap().as_array().unwrap();
        assert_eq!(rows[1].get("posts").unwrap().as_i128(), Some(2));

        // Later: `a` is gone and counted as such, not summed.
        let later = roster.summary(1_100 + crate::progress::STALE_SECONDS + 1);
        assert_eq!(later.get("live").unwrap().as_i128(), Some(0));
        assert_eq!(later.get("gone").unwrap().as_i128(), Some(2));
        assert_eq!(later.get("cpus").unwrap().as_i128(), Some(0));

        // A day on, a new post drops the forgotten ones first.
        roster
            .record(registration("c", 1, 0), 1_100 + FORGET_SECONDS + 1)
            .unwrap();
        assert_eq!(roster.len(), 1);
    }

    #[test]
    fn the_roster_refuses_past_its_cap_and_keeps_what_it_has() {
        let mut roster = Roster::default();
        for n in 0..MAX_HOSTS {
            roster
                .record(registration(&format!("h{n}"), 1, 0), 5)
                .unwrap();
        }
        let full = roster
            .record(registration("one-more", 1, 0), 5)
            .unwrap_err();
        assert_eq!(full.hosts, MAX_HOSTS);
        // A known host can still update itself.
        roster.record(registration("h0", 2, 0), 6).unwrap();
        assert_eq!(roster.len(), MAX_HOSTS);
    }
}
