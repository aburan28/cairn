//! Progress of a divided search, as a reader can see it.
//!
//! A piecework objective pays for a search nobody finishes in one sitting: a
//! distributed Pollard rho produces a distinguished orbit every few million
//! steps, a claim carries a batch of them, and the search is "done" when a
//! collision falls out of the table. Somebody running that search across a
//! fleet wants to know what every worker is doing *now*, and the log cannot
//! tell them: a claim lands an epoch after the work, a settlement an epoch
//! after that, and a trail that is two hours into its walk has written
//! nothing anywhere.
//!
//! So this module answers from two sources and keeps them apart, because they
//! are not the same kind of fact and a page that blended them would be
//! inventing one.
//!
//! **Settled** is derived from the log, the way every other number this node
//! publishes is. Every settlement names its submitter and its claim; the claim
//! carries the artifact; the artifact's elements carry their witness. From
//! that alone: paid units per worker, the steps those units cost (the witness
//! counters sum to the trail length, so the step count is *in the record*,
//! not estimated), when each worker was first and last paid, and which part of
//! the unit space the paid seeds came from. Anyone with a copy of the log
//! recomputes all of it.
//!
//! **Reported** is what workers say about themselves, posted as heartbeats to
//! `POST /progress` and held in memory by the node that received them. A
//! heartbeat is **not a record**: it is never appended to the log, never
//! gossiped, never verified, and never evidence of work -- the same rule
//! `docs/design/inference-capabilities.md` states for routing hints. It is
//! how an operator sees that a worker is alive, which unit range it took this
//! epoch, how fast it says it is walking, and how many orbits it is holding
//! for its next batch. Anyone can post one under any name. The reader labels
//! them as reported, the server bounds how many it will hold, and nothing
//! downstream reads them for money.
//!
//! The thresholds for *live* and *stale* are the ECC2K-130 campaign's own
//! (`aburan28/crypto`, `ecc2k130/aws/controlplane/config.py`), so a worker that
//! runs that client and this one at once is judged the same way by both.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::canonical::Value;
use crate::node::Node;
use crate::piecework::Piecework;
use crate::time::{format_iso8601_utc, parse_rfc3339};

/// A worker whose last heartbeat is at most this old is **live**. Three
/// missed minute-heartbeats, the same lease the campaign's control plane uses.
pub const LIVE_SECONDS: u64 = 180;

/// Older than [`LIVE_SECONDS`] and at most this old is **stale**: the worker
/// may be between checkpoints or mid-restart. The campaign counts a slot as
/// walking for this long after its last checkpoint.
pub const STALE_SECONDS: u64 = 1800;

/// A heartbeat older than this is dropped from the roster. A day: long enough
/// that an operator who looks in the morning sees who went quiet overnight,
/// short enough that a roster is never a list of everyone who ever posted.
pub const FORGET_SECONDS: u64 = 86_400;

/// The window a measured rate is taken over. The oldest sample within it is
/// the base; a rate over a shorter span than [`MIN_RATE_SPAN_SECONDS`] is not
/// reported, since two heartbeats a second apart measure jitter.
pub const RATE_WINDOW_SECONDS: u64 = 3600;
pub const MIN_RATE_SPAN_SECONDS: u64 = 30;

/// Bounds on what the roster will hold. Heartbeats are unauthenticated, so
/// these are what stop a stranger from making the node allocate without
/// limit: once a bound is hit the server answers 429 and keeps what it has.
pub const MAX_OBJECTIVES: usize = 256;
pub const MAX_WORKERS_PER_OBJECTIVE: usize = 4096;
/// Samples kept per worker for the rate measurement.
const MAX_SAMPLES: usize = 64;

/// How finely the unit space is binned for the coverage strip, by default and
/// at most. 1024 integers is a small response; a reader wanting finer detail
/// has the log.
pub const DEFAULT_BINS: usize = 128;
pub const MAX_BINS: usize = 1024;

/// Hourly buckets returned, most recent first. Thirty days.
const MAX_HOURS: usize = 720;

const MAX_NAME_LEN: usize = 128;
const MAX_TEXT_LEN: usize = 200;

// -- heartbeats --------------------------------------------------------------

/// What a worker says about itself. Every count is cumulative for the
/// worker's current session, so a restart shows as the count falling; the
/// rate the server measures is taken only across increases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    pub objective_id: String,
    /// The worker's name. Use the same string as the claims' `submitter` so
    /// the reader can put reported and settled figures on one row.
    pub worker: String,
    /// The epoch the worker believes it is in.
    pub epoch: Option<u64>,
    /// The unit range `[first, end)` the worker took this epoch, as
    /// `work_assignment` handed it out.
    pub units: Option<(u64, u64)>,
    /// The unit it is walking right now.
    pub unit: Option<u64>,
    /// Group operations walked this session.
    pub steps: u64,
    /// Trails finished (reached a distinguished point) this session.
    pub trails: u64,
    /// Trails abandoned at the step cap this session.
    pub capped: u64,
    /// Units found and not yet submitted -- the next batch, filling up.
    pub units_pending: u64,
    /// Units submitted this session, by the worker's own count.
    pub units_submitted: u64,
    /// The rate the worker measures for itself, in steps per second.
    pub steps_per_second: Option<u64>,
    /// The job's `trail_bits`, so the node can bin paid seeds by unit. Pinned
    /// by the job document, so every worker on one objective sends the same
    /// value; the node keeps the latest it saw.
    pub trail_bits: Option<u32>,
    pub device: Option<String>,
    pub lanes: Option<u64>,
    pub client: Option<String>,
}

/// Why a heartbeat was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatError {
    NotAnObject,
    Missing(&'static str),
    Invalid {
        field: &'static str,
        expected: &'static str,
    },
}

impl fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeartbeatError::NotAnObject => write!(f, "a heartbeat is a JSON object"),
            HeartbeatError::Missing(field) => write!(f, "heartbeat is missing {field:?}"),
            HeartbeatError::Invalid { field, expected } => {
                write!(f, "heartbeat field {field:?} must be {expected}")
            }
        }
    }
}

impl std::error::Error for HeartbeatError {}

/// The fields a heartbeat may carry. Anything else is ignored and named in
/// the response, so a misspelled field is noticed by the client that sent it
/// rather than refused by a node older than the client.
pub const HEARTBEAT_FIELDS: &[&str] = &[
    "objective_id",
    "worker",
    "epoch",
    "units",
    "unit",
    "steps",
    "trails",
    "capped",
    "units_pending",
    "units_submitted",
    "steps_per_second",
    "trail_bits",
    "device",
    "lanes",
    "client",
];

impl Heartbeat {
    /// Decode a heartbeat. Returns the heartbeat and the names of any fields
    /// it did not understand.
    pub fn from_value(value: &Value) -> Result<(Heartbeat, Vec<String>), HeartbeatError> {
        let object = value.as_object().ok_or(HeartbeatError::NotAnObject)?;
        let ignored = object
            .keys()
            .filter(|key| !HEARTBEAT_FIELDS.contains(&key.as_str()))
            .cloned()
            .collect();

        let text = |field: &'static str, max: usize| -> Result<Option<String>, HeartbeatError> {
            match object.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.is_empty() && s.chars().count() <= max => {
                    Ok(Some(s.clone()))
                }
                Some(_) => Err(HeartbeatError::Invalid {
                    field,
                    expected: "a non-empty string of at most a couple hundred characters",
                }),
            }
        };
        let count = |field: &'static str| -> Result<Option<u64>, HeartbeatError> {
            match object.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => value.as_u64().map(Some).ok_or(HeartbeatError::Invalid {
                    field,
                    expected: "a non-negative integer",
                }),
            }
        };

        let objective_id =
            text("objective_id", MAX_NAME_LEN)?.ok_or(HeartbeatError::Missing("objective_id"))?;
        let worker = text("worker", MAX_NAME_LEN)?.ok_or(HeartbeatError::Missing("worker"))?;
        // A name that is not printable is a name nobody can read off a page or
        // match against a settlement's `submitter`.
        if worker.chars().any(char::is_control) {
            return Err(HeartbeatError::Invalid {
                field: "worker",
                expected: "printable text",
            });
        }
        let steps = count("steps")?.ok_or(HeartbeatError::Missing("steps"))?;

        let units =
            match object.get("units") {
                None | Some(Value::Null) => None,
                Some(range) => {
                    let bounds = range.as_object().ok_or(HeartbeatError::Invalid {
                        field: "units",
                        expected: "an object {first, end}",
                    })?;
                    let bound = |key: &str| bounds.get(key).and_then(Value::as_u64);
                    match (bound("first"), bound("end")) {
                        (Some(first), Some(end)) if first <= end => Some((first, end)),
                        _ => return Err(HeartbeatError::Invalid {
                            field: "units",
                            expected:
                                "an object {first, end} of non-negative integers with first <= end",
                        }),
                    }
                }
            };

        let trail_bits = match count("trail_bits")? {
            None => None,
            Some(bits) if bits < 64 => Some(bits as u32),
            Some(_) => {
                return Err(HeartbeatError::Invalid {
                    field: "trail_bits",
                    expected: "an integer below 64",
                })
            }
        };

        Ok((
            Heartbeat {
                objective_id,
                worker,
                epoch: count("epoch")?,
                units,
                unit: count("unit")?,
                steps,
                trails: count("trails")?.unwrap_or(0),
                capped: count("capped")?.unwrap_or(0),
                units_pending: count("units_pending")?.unwrap_or(0),
                units_submitted: count("units_submitted")?.unwrap_or(0),
                steps_per_second: count("steps_per_second")?,
                trail_bits,
                device: text("device", MAX_TEXT_LEN)?,
                lanes: count("lanes")?,
                client: text("client", MAX_TEXT_LEN)?,
            },
            ignored,
        ))
    }
}

/// Live, stale or gone, by the age of the last heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Live,
    Stale,
    Gone,
}

impl Liveness {
    pub fn of_age(age: u64) -> Liveness {
        if age <= LIVE_SECONDS {
            Liveness::Live
        } else if age <= STALE_SECONDS {
            Liveness::Stale
        } else {
            Liveness::Gone
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Liveness::Live => "live",
            Liveness::Stale => "stale",
            Liveness::Gone => "gone",
        }
    }
}

/// One worker's standing on the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    first_at: u64,
    received_at: u64,
    /// `(received_at, steps)` of recent heartbeats, oldest first, for the
    /// measured rate. Cleared when `steps` falls, which is a restart.
    samples: Vec<(u64, u64)>,
    heartbeat: Heartbeat,
}

impl Seen {
    /// Steps per second over the window, from the server's own clock and the
    /// worker's own counter -- so a worker that lies about its rate is still
    /// held to the counter it reports, and one that lies about the counter
    /// is at least held to a consistent story over time.
    fn measured_rate(&self, now: u64) -> Option<u64> {
        let (last_at, last_steps) = *self.samples.last()?;
        let base = self
            .samples
            .iter()
            .find(|(at, _)| now.saturating_sub(*at) <= RATE_WINDOW_SECONDS)?;
        let span = last_at.saturating_sub(base.0);
        if span < MIN_RATE_SPAN_SECONDS || last_steps < base.1 {
            return None;
        }
        Some((last_steps - base.1) / span)
    }
}

/// The roster is full; the heartbeat was not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterFull(pub &'static str);

impl fmt::Display for RosterFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RosterFull {}

/// Every heartbeat this process has been sent and not yet forgotten.
#[derive(Debug, Default)]
pub struct Board {
    objectives: BTreeMap<String, BTreeMap<String, Seen>>,
}

impl Board {
    /// Keep a heartbeat. Returns how the worker now reads.
    pub fn record(&mut self, heartbeat: Heartbeat, now: u64) -> Result<Liveness, RosterFull> {
        self.forget(now);
        let is_new_objective = !self.objectives.contains_key(&heartbeat.objective_id);
        if is_new_objective && self.objectives.len() >= MAX_OBJECTIVES {
            return Err(RosterFull(
                "this node is holding heartbeats for as many objectives as it will; \
                 try again when one goes quiet",
            ));
        }
        let workers = self
            .objectives
            .entry(heartbeat.objective_id.clone())
            .or_default();
        match workers.get_mut(&heartbeat.worker) {
            Some(seen) => {
                if heartbeat.steps < seen.heartbeat.steps {
                    // A counter that fell is a restarted worker. A rate across
                    // the restart would be negative or wild; start over.
                    seen.samples.clear();
                }
                seen.samples.push((now, heartbeat.steps));
                if seen.samples.len() > MAX_SAMPLES {
                    seen.samples.remove(0);
                }
                seen.received_at = now;
                seen.heartbeat = heartbeat;
            }
            None => {
                if workers.len() >= MAX_WORKERS_PER_OBJECTIVE {
                    return Err(RosterFull(
                        "this node is holding heartbeats for as many workers on this \
                         objective as it will; try again when one goes quiet",
                    ));
                }
                workers.insert(
                    heartbeat.worker.clone(),
                    Seen {
                        first_at: now,
                        received_at: now,
                        samples: vec![(now, heartbeat.steps)],
                        heartbeat,
                    },
                );
            }
        }
        Ok(Liveness::Live)
    }

    /// Drop everything older than [`FORGET_SECONDS`].
    fn forget(&mut self, now: u64) {
        for workers in self.objectives.values_mut() {
            workers.retain(|_, seen| now.saturating_sub(seen.received_at) <= FORGET_SECONDS);
        }
        self.objectives.retain(|_, workers| !workers.is_empty());
    }

    /// The most recent `trail_bits` any worker on this objective declared.
    pub fn trail_bits(&self, objective_id: &str) -> Option<u32> {
        self.objectives
            .get(objective_id)?
            .values()
            .filter(|seen| seen.heartbeat.trail_bits.is_some())
            .max_by_key(|seen| seen.received_at)
            .and_then(|seen| seen.heartbeat.trail_bits)
    }

    /// Workers on an objective, as the reader shows them: the `reported`
    /// half of `GET /progress/{id}`.
    pub fn report(&self, objective_id: &str, now: u64) -> Value {
        let mut workers = Vec::new();
        let (mut live, mut stale, mut gone) = (0i128, 0i128, 0i128);
        let mut steps_per_second: u128 = 0;
        let mut steps: u128 = 0;
        let mut units_pending: u128 = 0;
        if let Some(roster) = self.objectives.get(objective_id) {
            for seen in roster.values() {
                let age = now.saturating_sub(seen.received_at);
                let liveness = Liveness::of_age(age);
                let measured = seen.measured_rate(now);
                match liveness {
                    Liveness::Live => {
                        live += 1;
                        steps_per_second +=
                            u128::from(measured.or(seen.heartbeat.steps_per_second).unwrap_or(0));
                        steps += u128::from(seen.heartbeat.steps);
                        units_pending += u128::from(seen.heartbeat.units_pending);
                    }
                    Liveness::Stale => stale += 1,
                    Liveness::Gone => gone += 1,
                }
                workers.push(worker_value(seen, age, liveness, measured));
            }
        }
        Value::object([
            ("workers", Value::Array(workers)),
            ("live", Value::Int(live)),
            ("stale", Value::Int(stale)),
            ("gone", Value::Int(gone)),
            ("steps_per_second", Value::Int(steps_per_second as i128)),
            ("steps", Value::Int(steps as i128)),
            ("units_pending", Value::Int(units_pending as i128)),
            ("live_within_seconds", Value::Int(i128::from(LIVE_SECONDS))),
            (
                "stale_within_seconds",
                Value::Int(i128::from(STALE_SECONDS)),
            ),
            (
                "note",
                Value::string(
                    "Self-reported by workers over POST /progress and held in this node's \
                     memory. Not a record, not verified, not evidence of work: a worker is \
                     paid for what the log settles, which is the `settled` block beside this.",
                ),
            ),
        ])
    }
}

fn worker_value(seen: &Seen, age: u64, liveness: Liveness, measured: Option<u64>) -> Value {
    let hb = &seen.heartbeat;
    let opt_int = |value: Option<u64>| {
        value
            .map(|v| Value::Int(i128::from(v)))
            .unwrap_or(Value::Null)
    };
    let opt_str = |value: &Option<String>| {
        value
            .as_ref()
            .map(|v| Value::string(v.clone()))
            .unwrap_or(Value::Null)
    };
    Value::object([
        ("worker", Value::string(hb.worker.clone())),
        ("status", Value::string(liveness.as_str())),
        ("first_seen_at", Value::string(iso(seen.first_at))),
        ("received_at", Value::string(iso(seen.received_at))),
        ("age_seconds", Value::Int(i128::from(age))),
        ("epoch", opt_int(hb.epoch)),
        (
            "units",
            match hb.units {
                Some((first, end)) => Value::object([
                    ("first", Value::Int(i128::from(first))),
                    ("end", Value::Int(i128::from(end))),
                ]),
                None => Value::Null,
            },
        ),
        ("unit", opt_int(hb.unit)),
        ("steps", Value::Int(i128::from(hb.steps))),
        ("trails", Value::Int(i128::from(hb.trails))),
        ("capped", Value::Int(i128::from(hb.capped))),
        ("units_pending", Value::Int(i128::from(hb.units_pending))),
        (
            "units_submitted",
            Value::Int(i128::from(hb.units_submitted)),
        ),
        ("reported_steps_per_second", opt_int(hb.steps_per_second)),
        ("measured_steps_per_second", opt_int(measured)),
        ("device", opt_str(&hb.device)),
        ("lanes", opt_int(hb.lanes)),
        ("client", opt_str(&hb.client)),
    ])
}

fn iso(unix: u64) -> String {
    format_iso8601_utc(i64::try_from(unix).unwrap_or(i64::MAX))
}

// -- the fleet, across objectives -------------------------------------------------

/// One live or stale worker as the network page lists it, whichever objective
/// it is on. The per-objective view is [`Board::report`]; this is the roster
/// read sideways, for "what hardware is on this network right now".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetWorker {
    pub objective_id: String,
    pub worker: String,
    pub status: Liveness,
    pub age_seconds: u64,
    pub device: Option<String>,
    pub lanes: Option<u64>,
    pub client: Option<String>,
    /// The node's measured rate when it has one, else what the worker said.
    pub steps_per_second: Option<u64>,
    pub epoch: Option<u64>,
    pub units: Option<(u64, u64)>,
}

/// A coarse class for a worker's self-described `device`, so a page can sum
/// a fleet by kind without every reader inventing its own regex.
///
/// Workers name their hardware freely (`--device` on the reference worker),
/// so this is a heuristic over tokens and it says so in its own name: a
/// worker that calls its box `rig-3` is `other`, and that is the right
/// answer. Apple silicon is its own class because its GPU is on the die and
/// a token like `gpu` beside `apple` means the same chip, not a card.
pub fn device_class(device: &str) -> &'static str {
    let lower = device.to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    let has = |needles: &[&str]| tokens.iter().any(|token| needles.contains(token));
    let starts = |prefixes: &[&str]| {
        tokens
            .iter()
            .any(|token| prefixes.iter().any(|prefix| token.starts_with(prefix)))
    };
    let apple_chip = starts(&["m1", "m2", "m3", "m4", "m5"]) && has(&["max", "pro", "ultra"]);
    if has(&["apple", "metal"]) || apple_chip {
        return "apple";
    }
    if has(&["fpga", "xilinx", "alveo", "stratix", "arria", "versal"]) {
        return "fpga";
    }
    if has(&[
        "gpu", "nvidia", "geforce", "rtx", "gtx", "tesla", "cuda", "radeon", "instinct", "rocm",
        "a100", "h100", "h200", "b200", "l40", "l40s", "a10", "a30", "a40", "t4", "v100", "p100",
        "mi300", "mi300x", "mi250", "mi250x", "arc",
    ]) {
        return "gpu";
    }
    if has(&[
        "cpu",
        "xeon",
        "epyc",
        "ryzen",
        "threadripper",
        "core",
        "i3",
        "i5",
        "i7",
        "i9",
        "graviton",
        "ampere",
        "altra",
        "neoverse",
        "arm64",
        "aarch64",
        "x86",
        "x86_64",
        "amd64",
        "avx2",
        "avx512",
        "cores",
        "vcpu",
        "vcpus",
    ]) {
        return "cpu";
    }
    "other"
}

impl Board {
    /// Every worker on every objective, with its standing at `now`. Gone
    /// workers are included with their status so a page can say "and 12 that
    /// stopped reporting" rather than silently shrinking the fleet.
    pub fn fleet(&self, now: u64) -> Vec<FleetWorker> {
        let mut fleet = Vec::new();
        for (objective_id, roster) in &self.objectives {
            for seen in roster.values() {
                let age = now.saturating_sub(seen.received_at);
                let hb = &seen.heartbeat;
                fleet.push(FleetWorker {
                    objective_id: objective_id.clone(),
                    worker: hb.worker.clone(),
                    status: Liveness::of_age(age),
                    age_seconds: age,
                    device: hb.device.clone(),
                    lanes: hb.lanes,
                    client: hb.client.clone(),
                    steps_per_second: seen.measured_rate(now).or(hb.steps_per_second),
                    epoch: hb.epoch,
                    units: hb.units,
                });
            }
        }
        fleet
    }
}

// -- settled -----------------------------------------------------------------

/// Per-worker totals derived from the log.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Tally {
    claims_paid: u64,
    elements: u64,
    units_paid: u64,
    reward: u128,
    steps: u128,
    first_paid_at: Option<u64>,
    last_paid_at: Option<u64>,
    /// Claims revealed, whatever their verdict.
    claims: u64,
    /// Claims whose last verdict was not an acceptance.
    rejected: u64,
    /// Commitments this submitter made that no claim has opened yet: work in
    /// flight, by count. A commitment is opened by a claim from the same
    /// submitter, so the difference is an approximation that is exact when
    /// nobody abandons a commitment.
    in_flight: u64,
}

impl Tally {
    fn fields(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("claims_paid", Value::Int(i128::from(self.claims_paid))),
            ("claims", Value::Int(i128::from(self.claims))),
            ("rejected", Value::Int(i128::from(self.rejected))),
            ("in_flight", Value::Int(i128::from(self.in_flight))),
            ("elements", Value::Int(i128::from(self.elements))),
            ("units_paid", Value::Int(i128::from(self.units_paid))),
            ("reward", Value::Int(self.reward as i128)),
            ("steps", Value::Int(self.steps as i128)),
            (
                "first_paid_at",
                self.first_paid_at
                    .map(|t| Value::string(iso(t)))
                    .unwrap_or(Value::Null),
            ),
            (
                "last_paid_at",
                self.last_paid_at
                    .map(|t| Value::string(iso(t)))
                    .unwrap_or(Value::Null),
            ),
        ]
    }

    fn to_value(&self, name: &str) -> Value {
        let mut fields = vec![("submitter", Value::string(name))];
        fields.extend(self.fields());
        Value::object(fields)
    }
}

/// The steps one element of a batch cost, read off the record.
///
/// A version 2 element carries the witness `j`, eight branch counters whose
/// sum is the trail length. A version 1 element carries `steps` outright.
/// Anything else is unknown, and unknown is reported as zero with the
/// method saying so rather than estimated from a density the node does not
/// know.
fn element_steps(element: &Value) -> Option<u64> {
    if let Some(Value::Array(counts)) = element.get("j") {
        let mut total: u64 = 0;
        for count in counts {
            total = total.saturating_add(count.as_u64()?);
        }
        return Some(total);
    }
    element.get("steps").and_then(Value::as_u64)
}

/// The unit an element's seed came from, given the job's seed layout.
fn element_unit(element: &Value, trail_bits: u32) -> Option<u64> {
    let seed = element.get("seed")?.as_str()?;
    let seed = u64::from_str_radix(seed, 16).ok()?;
    Some(seed >> trail_bits)
}

/// Everything the log says about one objective's search, for `GET /progress/{id}`.
///
/// `trail_bits` lets paid seeds be binned by unit; without it the coverage
/// strip is absent rather than guessed. `now` decides the last-hour and
/// last-day windows.
pub fn settled(
    node: &Node,
    objective_id: &str,
    piecework: Option<&Piecework>,
    trail_bits: Option<u32>,
    bins: usize,
    now: u64,
) -> Value {
    let ledger = node.ledger();
    let claims = node.all_claims();

    // Claims on this objective, by id, with who revealed them and how many
    // units each carries.
    let mut by_submitter: BTreeMap<String, Tally> = BTreeMap::new();
    let mut claim_submitter: BTreeMap<&str, &str> = BTreeMap::new();
    for (claim_id, claim) in &claims {
        if claim.objective_id != objective_id {
            continue;
        }
        claim_submitter.insert(claim_id.as_str(), claim.submitter.as_str());
        by_submitter
            .entry(claim.submitter.clone())
            .or_default()
            .claims += 1;
    }

    // Work in flight: commitments nobody has opened yet.
    for entry in ledger.entries_of_kind("commitment") {
        if entry.payload.get("objective_id").and_then(Value::as_str) != Some(objective_id) {
            continue;
        }
        if let Some(submitter) = entry.payload.get("submitter").and_then(Value::as_str) {
            by_submitter
                .entry(submitter.to_string())
                .or_default()
                .in_flight += 1;
        }
    }
    for tally in by_submitter.values_mut() {
        tally.in_flight = tally.in_flight.saturating_sub(tally.claims);
    }

    // Rejections: the last verdict on each claim.
    let mut last_verdict: BTreeMap<&str, bool> = BTreeMap::new();
    for entry in ledger.entries_of_kind("verdict") {
        let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
            continue;
        };
        if !claim_submitter.contains_key(claim_id) {
            continue;
        }
        let accepted = entry
            .payload
            .get("verdict")
            .and_then(|v| v.get("status"))
            .and_then(Value::as_str)
            == Some("accept");
        last_verdict.insert(claim_id, accepted);
    }
    for (claim_id, accepted) in &last_verdict {
        if !accepted {
            if let Some(submitter) = claim_submitter.get(claim_id) {
                by_submitter
                    .entry((*submitter).to_string())
                    .or_default()
                    .rejected += 1;
            }
        }
    }

    // Settlements: the paid half, and everything derived from the artifacts.
    let items = piecework.and_then(|p| p.items.as_deref());
    let unit_price = piecework.map(|p| p.unit_price).unwrap_or(0);
    let units = piecework.and_then(|p| p.units);
    let bins = bins.clamp(1, MAX_BINS);
    let mut coverage: Vec<u64> = vec![0; bins];
    let mut units_touched: BTreeSet<u64> = BTreeSet::new();
    let mut unbinned: u64 = 0;
    let mut hourly: BTreeMap<u64, (u64, u64, u128)> = BTreeMap::new();
    let mut total = Tally::default();
    let mut last_hour = (0u64, 0u64, 0u128);
    let mut last_day = (0u64, 0u64, 0u128);
    let mut steps_known = true;

    for entry in ledger.entries_of_kind("settlement") {
        if entry.payload.get("objective_id").and_then(Value::as_str) != Some(objective_id) {
            continue;
        }
        let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
            continue;
        };
        let submitter = entry
            .payload
            .get("submitter")
            .and_then(Value::as_str)
            .or_else(|| claim_submitter.get(claim_id).copied())
            .unwrap_or("?")
            .to_string();
        let reward = entry
            .payload
            .get("reward")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let at = parse_rfc3339(&entry.ts)
            .and_then(|s| u64::try_from(s).ok())
            .unwrap_or(0);

        let elements: Vec<&Value> = match (claims.get(claim_id), items) {
            (Some(claim), Some(items)) => match claim.artifact.get(items) {
                Some(Value::Array(elements)) => elements.iter().collect(),
                _ => Vec::new(),
            },
            (Some(claim), None) => vec![&claim.artifact],
            (None, _) => Vec::new(),
        };
        // What the pool paid for, in units: the claim's own count, or fewer
        // when some of its units were duplicates or the pool ran dry under it.
        // `settle_unit` pays unit_price per novel unit, capped by the pool.
        let units_paid = if unit_price == 0 {
            elements.len() as u64
        } else {
            (reward.div_ceil(unit_price)).min(elements.len() as u64)
        };
        let mut steps: u128 = 0;
        for element in &elements {
            match element_steps(element) {
                Some(s) => steps += u128::from(s),
                None => steps_known = false,
            }
            if let (Some(bits), Some(units)) = (trail_bits, units) {
                match element_unit(element, bits) {
                    Some(unit) if unit < units => {
                        units_touched.insert(unit);
                        let bin = (u128::from(unit) * bins as u128 / u128::from(units)) as usize;
                        coverage[bin.min(bins - 1)] += 1;
                    }
                    _ => unbinned += 1,
                }
            }
        }

        let tally = by_submitter.entry(submitter).or_default();
        for t in [&mut *tally, &mut total] {
            t.claims_paid += 1;
            t.elements += elements.len() as u64;
            t.units_paid += units_paid;
            t.reward += u128::from(reward);
            t.steps += steps;
            t.first_paid_at = Some(t.first_paid_at.map_or(at, |f| f.min(at)));
            t.last_paid_at = Some(t.last_paid_at.map_or(at, |l| l.max(at)));
        }
        let hour = hourly.entry(at - at % 3600).or_default();
        hour.0 += 1;
        hour.1 += units_paid;
        hour.2 += steps;
        if now.saturating_sub(at) < 3600 {
            last_hour.0 += 1;
            last_hour.1 += units_paid;
            last_hour.2 += steps;
        }
        if now.saturating_sub(at) < 86_400 {
            last_day.0 += 1;
            last_day.1 += units_paid;
            last_day.2 += steps;
        }
    }
    total.claims = by_submitter.values().map(|t| t.claims).sum();
    total.rejected = by_submitter.values().map(|t| t.rejected).sum();
    total.in_flight = by_submitter.values().map(|t| t.in_flight).sum();

    let window = |(claims, units, steps): (u64, u64, u128)| {
        Value::object([
            ("claims_paid", Value::Int(i128::from(claims))),
            ("units_paid", Value::Int(i128::from(units))),
            ("steps", Value::Int(steps as i128)),
        ])
    };
    let mut hours: Vec<Value> = hourly
        .iter()
        .rev()
        .take(MAX_HOURS)
        .map(|(start, (claims, units, steps))| {
            Value::object([
                ("hour", Value::string(iso(*start))),
                ("claims_paid", Value::Int(i128::from(*claims))),
                ("units_paid", Value::Int(i128::from(*units))),
                ("steps", Value::Int(*steps as i128)),
            ])
        })
        .collect();
    hours.reverse();

    let mut workers: Vec<Value> = by_submitter
        .iter()
        .map(|(name, tally)| tally.to_value(name))
        .collect();
    // Most paid first; the roster is for seeing who is carrying the search.
    workers.sort_by(|a, b| {
        let paid = |v: &Value| v.get("units_paid").and_then(Value::as_i128).unwrap_or(0);
        paid(b).cmp(&paid(a))
    });

    let coverage_value = match (trail_bits, units) {
        (Some(bits), Some(units)) => Value::object([
            ("bins", Value::Int(bins as i128)),
            ("units", Value::Int(i128::from(units))),
            ("trail_bits", Value::Int(i128::from(bits))),
            (
                "counts",
                Value::Array(coverage.iter().map(|c| Value::Int(i128::from(*c))).collect()),
            ),
            ("units_touched", Value::Int(units_touched.len() as i128)),
            ("unbinned", Value::Int(i128::from(unbinned))),
            (
                "method",
                Value::string("unit = seed >> trail_bits, bin = unit * bins / units; one count per element of each paid claim"),
            ),
        ]),
        _ => Value::Null,
    };

    let mut fields = vec![
        ("workers", Value::Array(workers)),
        ("hourly", Value::Array(hours)),
        ("last_hour", window(last_hour)),
        ("last_day", window(last_day)),
        ("coverage", coverage_value),
        (
            "steps_method",
            Value::string(if steps_known {
                "sum of each paid element's witness counters `j` (version 2) or its `steps` field (version 1); exact for the trails that produced paid units, and nothing for capped or unpaid trails"
            } else {
                "some paid elements carry neither witness counters nor a steps field; their steps are counted as zero"
            }),
        ),
        (
            "note",
            Value::string(
                "Derived from this node's log: settlements joined to the claims they paid. \
                 Anyone with the log recomputes it; nothing here is reported by a worker.",
            ),
        ),
    ];
    // The totals go first so a reader skimming the object sees them before
    // the per-worker list.
    let mut head = total.fields();
    head.append(&mut fields);
    Value::object(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_class_is_a_heuristic_over_tokens_and_says_other_when_unsure() {
        assert_eq!(device_class("NVIDIA GeForce RTX 4090"), "gpu");
        assert_eq!(device_class("8x H100 SXM"), "gpu");
        assert_eq!(device_class("AMD Instinct MI300X"), "gpu");
        assert_eq!(device_class("Apple M3 Max"), "apple");
        assert_eq!(device_class("apple-m2-gpu"), "apple");
        assert_eq!(device_class("Xilinx Alveo U250"), "fpga");
        assert_eq!(device_class("AMD EPYC 9654 96-Core"), "cpu");
        assert_eq!(device_class("Intel Core i9-13900K"), "cpu");
        assert_eq!(device_class("64 vCPU"), "cpu");
        assert_eq!(device_class("rig-3"), "other");
        assert_eq!(device_class("m2"), "other", "a bare token is not a chip");
    }

    #[test]
    fn the_fleet_reads_the_roster_sideways_across_objectives() {
        let mut board = Board::default();
        let mut a = hb("gpu-7", 1000);
        a.device = Some("NVIDIA RTX 4090".into());
        a.lanes = Some(128);
        board.record(a, 1_000).unwrap();
        let mut b = hb("cpu-1", 10);
        b.objective_id = "sha256:p".into();
        b.device = Some("EPYC".into());
        board.record(b, 1_000).unwrap();
        let fleet = board.fleet(1_000 + LIVE_SECONDS + 1);
        assert_eq!(fleet.len(), 2);
        let gpu = fleet.iter().find(|w| w.worker == "gpu-7").unwrap();
        assert_eq!(gpu.objective_id, "sha256:o");
        assert_eq!(gpu.status, Liveness::Stale);
        assert_eq!(gpu.lanes, Some(128));
        assert_eq!(
            gpu.steps_per_second,
            Some(1000),
            "one sample measures nothing, so the reported rate stands in"
        );
        assert_eq!(gpu.device.as_deref().map(device_class), Some("gpu"));
        let cpu = fleet.iter().find(|w| w.worker == "cpu-1").unwrap();
        assert_eq!(cpu.objective_id, "sha256:p");
        assert_eq!(cpu.device.as_deref().map(device_class), Some("cpu"));
    }

    fn hb(worker: &str, steps: u64) -> Heartbeat {
        Heartbeat {
            objective_id: "sha256:o".into(),
            worker: worker.into(),
            epoch: Some(7),
            units: Some((0, 512)),
            unit: Some(3),
            steps,
            trails: 2,
            capped: 0,
            units_pending: 5,
            units_submitted: 16,
            steps_per_second: Some(1000),
            trail_bits: Some(16),
            device: None,
            lanes: None,
            client: Some("test".into()),
        }
    }

    #[test]
    fn a_heartbeat_decodes_and_names_what_it_ignored() {
        let value = Value::from_json(
            r#"{"objective_id":"sha256:o","worker":"alice","steps":12,"units":{"first":0,"end":8},
                "trail_bits":16,"steps_per_sec":9,"client":"x"}"#,
        )
        .unwrap();
        let (heartbeat, ignored) = Heartbeat::from_value(&value).expect("decodes");
        assert_eq!(heartbeat.worker, "alice");
        assert_eq!(heartbeat.units, Some((0, 8)));
        assert_eq!(heartbeat.trail_bits, Some(16));
        assert_eq!(
            heartbeat.steps_per_second, None,
            "the misspelled field is not read"
        );
        assert_eq!(ignored, vec!["steps_per_sec".to_string()]);
    }

    #[test]
    fn a_heartbeat_is_refused_for_what_cannot_be_read() {
        let bad = [
            (r#"[]"#, "a heartbeat is a JSON object"),
            (r#"{"worker":"a","steps":1}"#, "missing \"objective_id\""),
            (r#"{"objective_id":"o","steps":1}"#, "missing \"worker\""),
            (r#"{"objective_id":"o","worker":"a"}"#, "missing \"steps\""),
            (
                r#"{"objective_id":"o","worker":"a","steps":-1}"#,
                "\"steps\" must be",
            ),
            (
                r#"{"objective_id":"o","worker":"a","steps":1,"units":{"first":9,"end":1}}"#,
                "\"units\" must be",
            ),
            (
                r#"{"objective_id":"o","worker":"a","steps":1,"trail_bits":64}"#,
                "\"trail_bits\" must be",
            ),
            (
                r#"{"objective_id":"o","worker":"a\u0007","steps":1}"#,
                "printable",
            ),
        ];
        for (text, expect) in bad {
            let value = Value::from_json(text).unwrap();
            let why = Heartbeat::from_value(&value).expect_err(text).to_string();
            assert!(why.contains(expect), "{text}: {why}");
        }
    }

    #[test]
    fn the_board_measures_a_rate_and_ages_workers_out() {
        let mut board = Board::default();
        board.record(hb("alice", 0), 1_000).unwrap();
        // Too soon for a rate: thirty seconds is the floor.
        board.record(hb("alice", 10_000), 1_010).unwrap();
        let report = board.report("sha256:o", 1_010);
        let alice = &report.get("workers").unwrap().as_array().unwrap()[0];
        assert_eq!(alice.get("measured_steps_per_second"), Some(&Value::Null));
        assert_eq!(alice.get("status").and_then(Value::as_str), Some("live"));
        // A minute on: (70_000 - 0) / 70 = 1000 steps a second, from the
        // counter and the clock, whatever the worker said about itself.
        board.record(hb("alice", 70_000), 1_070).unwrap();
        let report = board.report("sha256:o", 1_070);
        let alice = &report.get("workers").unwrap().as_array().unwrap()[0];
        assert_eq!(
            alice.get("measured_steps_per_second"),
            Some(&Value::Int(1000))
        );
        assert_eq!(report.get("live"), Some(&Value::Int(1)));
        assert_eq!(report.get("steps_per_second"), Some(&Value::Int(1000)));

        // Quiet for four minutes: stale, and out of the live totals.
        let report = board.report("sha256:o", 1_070 + LIVE_SECONDS + 60);
        assert_eq!(report.get("live"), Some(&Value::Int(0)));
        assert_eq!(report.get("stale"), Some(&Value::Int(1)));
        assert_eq!(report.get("steps_per_second"), Some(&Value::Int(0)));
        // Quiet for an hour: gone, still listed.
        let report = board.report("sha256:o", 1_070 + STALE_SECONDS + 60);
        assert_eq!(report.get("gone"), Some(&Value::Int(1)));
        // A day later the next write forgets her.
        board
            .record(hb("bob", 1), 1_070 + FORGET_SECONDS + 1)
            .unwrap();
        let report = board.report("sha256:o", 1_070 + FORGET_SECONDS + 1);
        let names: Vec<&str> = report
            .get("workers")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.get("worker").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["bob"]);
    }

    #[test]
    fn a_restart_resets_the_rate_window_instead_of_going_negative() {
        let mut board = Board::default();
        board.record(hb("alice", 500_000), 0).unwrap();
        board.record(hb("alice", 560_000), 60).unwrap();
        // The counter fell: a restart. No rate until a new span is measured.
        board.record(hb("alice", 100), 120).unwrap();
        let report = board.report("sha256:o", 120);
        let alice = &report.get("workers").unwrap().as_array().unwrap()[0];
        assert_eq!(alice.get("measured_steps_per_second"), Some(&Value::Null));
        board.record(hb("alice", 6_100), 180).unwrap();
        let report = board.report("sha256:o", 180);
        let alice = &report.get("workers").unwrap().as_array().unwrap()[0];
        assert_eq!(
            alice.get("measured_steps_per_second"),
            Some(&Value::Int(100))
        );
    }

    #[test]
    fn the_board_is_bounded() {
        let mut board = Board::default();
        for i in 0..MAX_WORKERS_PER_OBJECTIVE {
            board.record(hb(&format!("w{i}"), 1), 0).unwrap();
        }
        assert!(board.record(hb("one-too-many", 1), 0).is_err());
        // An existing worker is still updated.
        board.record(hb("w0", 2), 1).unwrap();
        for i in 1..MAX_OBJECTIVES {
            let mut other = hb("x", 1);
            other.objective_id = format!("sha256:{i}");
            board.record(other, 0).unwrap();
        }
        let mut extra = hb("x", 1);
        extra.objective_id = "sha256:extra".into();
        assert!(board.record(extra, 0).is_err());
    }

    #[test]
    fn trail_bits_come_from_the_latest_worker_that_declared_them() {
        let mut board = Board::default();
        let mut silent = hb("quiet", 1);
        silent.trail_bits = None;
        board.record(silent, 10).unwrap();
        assert_eq!(board.trail_bits("sha256:o"), None);
        board.record(hb("alice", 1), 5).unwrap();
        let mut later = hb("bob", 1);
        later.trail_bits = Some(12);
        board.record(later, 20).unwrap();
        assert_eq!(board.trail_bits("sha256:o"), Some(12));
        assert_eq!(board.trail_bits("sha256:other"), None);
    }

    #[test]
    fn element_steps_read_the_witness_or_the_field_and_nothing_else() {
        let v2 = Value::from_json(r#"{"x":"1","seed":"10000","j":[1,2,3,4,5,6,7,8]}"#).unwrap();
        assert_eq!(element_steps(&v2), Some(36));
        let v1 = Value::from_json(r#"{"x":"1","y":"2","a":"3","b":"4","steps":25209,"walker":0}"#)
            .unwrap();
        assert_eq!(element_steps(&v1), Some(25209));
        let bare = Value::from_json(r#"{"x":"1"}"#).unwrap();
        assert_eq!(element_steps(&bare), None);
        let broken = Value::from_json(r#"{"j":[1,"two"]}"#).unwrap();
        assert_eq!(element_steps(&broken), None);
    }

    #[test]
    fn element_unit_is_the_seed_above_the_trail_bits() {
        let element = Value::from_json(r#"{"seed":"30007"}"#).unwrap();
        // 0x30007 = (3 << 16) | 7
        assert_eq!(element_unit(&element, 16), Some(3));
        assert_eq!(element_unit(&element, 0), Some(0x30007));
        let bad = Value::from_json(r#"{"seed":"0xzz"}"#).unwrap();
        assert_eq!(element_unit(&bad, 16), None);
    }
}
