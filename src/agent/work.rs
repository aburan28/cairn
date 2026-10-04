//! `cairn work`: put this machine to work on one objective, with any solver.
//!
//! Until this existed the only worker was `orbit_worker.py`, which is one
//! search's walker welded to the four HTTP calls every worker makes. A second
//! machine on somebody's LAN that wanted to help on a different objective had
//! to reimplement the commit/reveal clock, the heartbeat, and the citation
//! rule before it could try a single candidate. This is those four calls and
//! that clock, with the *search* left to a command the operator supplies:
//!
//! ```text
//! cairn work --node http://192.168.1.20:8080 --objective sha256:… \
//!            --worker garage-gpu -- ./my-solver --threads 8
//! ```
//!
//! # The solver contract
//!
//! Each round the solver is started once, with this round's assignment as one
//! line of JSON on stdin and in `CAIRN_ASSIGNMENT`, plus `CAIRN_NODE`,
//! `CAIRN_OBJECTIVE`, `CAIRN_WORKER`, `CAIRN_EPOCH` and
//! `CAIRN_EPOCH_ENDS_IN` (seconds). It prints zero or more candidate
//! artifacts on stdout, **one JSON object per line**, and exits. Exit 0 with
//! no output means "nothing this round" and is not an error. Its stderr is
//! passed through. A non-zero exit discards that round's output: a solver
//! that crashed half-way has printed half of something.
//!
//! The assignment is `GET /work_assignment`: this worker's partition of the
//! search for this epoch, and on a divided search the unit range it owns. It
//! is a pure function of public inputs (`docs/coordination.md`), so two
//! workers with different names take different slices without talking.
//!
//! # What it does with an artifact
//!
//! Commits it in this epoch and reveals it in a later one, because a reveal in
//! the commitment's own epoch is refused -- that rule is what stops a watcher
//! copying an answer between its commitment and its reveal. If the objective
//! has a frontier, the reveal cites the claim holding it, which every
//! submission against a ratchet must. Neither call is retried blindly: a 429
//! (the node's queue is full) is held and tried again; any other refusal is
//! printed and dropped, because the node has already said no to that record.
//!
//! It never grades anything. The node runs the objective's pinned verifier at
//! admission, and that verdict is the only one that pays; a worker's opinion
//! of its own output is worth nothing here, which is the point.
//!
//! # Why it heartbeats
//!
//! `POST /progress` every `--heartbeat` seconds while the solver runs is what
//! puts this machine on the objective's roster as *working now*. It is
//! self-reported and moves no money; it is how the people running a search
//! can see which machines are on it.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::RngCore;

use super::http::{self, NodeUrl};
use super::AgentError;
use crate::canonical::Value;
use crate::crypto::identity::Identity;
use crate::records::{commitment_hash, Claim, Commitment};

const CLIENT: &str = concat!("cairn-work/", env!("CARGO_PKG_VERSION"));
const NODE_TIMEOUT: Duration = Duration::from_secs(20);

/// Post nothing in the last few seconds of an epoch: the node drains its queue
/// every five, and a commitment admitted after the boundary lands in the next
/// epoch, which would make its reveal one epoch later than planned.
const DEFAULT_MARGIN_SECONDS: u64 = 8;

const USAGE: &str = "\
cairn work — put this machine to work on one objective, with your own solver

USAGE
    cairn work --node URL --objective ID --worker NAME [options] -- SOLVER [ARGS]...

    --node URL           the node's HTTP address, e.g. http://192.168.1.20:8080
    --objective ID       the objective to work (sha256:…)
    --worker NAME        your name on the roster and, unless --identity is given,
                         the submitter on every record
    --identity FILE      sign commitments and claims with this identity; the
                         submitter becomes its public key (`cairn identity`)
    --partitions N       how many ways the search is split (default 8)
    --rounds N           stop after N solver runs (default: run until stopped)
    --heartbeat SECONDS  how often to report in while the solver runs (default 30)
    --device TEXT        what this machine is, for the roster
    --margin SECONDS     post nothing this close to an epoch's end (default 8)

THE SOLVER
    Started once per round. Gets the assignment as one line of JSON on stdin and in
    $CAIRN_ASSIGNMENT, plus $CAIRN_NODE $CAIRN_OBJECTIVE $CAIRN_WORKER $CAIRN_EPOCH
    $CAIRN_EPOCH_ENDS_IN. Prints candidate artifacts on stdout, one JSON object per
    line, and exits 0. No output is fine. A non-zero exit discards the round.

    Every candidate is committed this epoch and revealed after the epoch turns; the
    node's pinned verifier decides what pays. Score candidates locally first
    (`cairn try`, or score_candidate over MCP): a rejected claim earns nothing.

EXIT CODES
    0 done   1 the solver kept failing   2 bad usage   3 the node could not be reached
";

#[derive(Debug, Clone)]
pub struct Options {
    pub node: NodeUrl,
    pub objective: String,
    pub worker: String,
    pub identity: Option<Identity>,
    pub partitions: u64,
    pub rounds: Option<u64>,
    pub heartbeat: Duration,
    pub device: Option<String>,
    pub margin: u64,
    pub solver: Vec<String>,
}

/// Entry point: `cairn work ARGS…`. Returns the process exit code.
pub fn main(args: Vec<String>) -> i32 {
    let options = match parse(&args) {
        Ok(Some(options)) => options,
        Ok(None) => {
            print!("{USAGE}");
            return 0;
        }
        Err(message) => {
            eprintln!("cairn work: {message}\n\n{USAGE}");
            return 2;
        }
    };
    match Worker::new(options).and_then(|mut worker| worker.run()) {
        Ok(()) => 0,
        Err(WorkError::Solver(message)) => {
            eprintln!("cairn work: {message}");
            1
        }
        Err(WorkError::Agent(AgentError::Invalid(message))) => {
            eprintln!("cairn work: {message}");
            2
        }
        Err(WorkError::Agent(error)) => {
            eprintln!("cairn work: {error}");
            3
        }
    }
}

/// `Ok(None)` is `--help`.
pub fn parse(args: &[String]) -> Result<Option<Options>, String> {
    let split = args.iter().position(|a| a == "--");
    let (flags, solver) = match split {
        Some(at) => (&args[..at], args[at + 1..].to_vec()),
        None => (args, Vec::new()),
    };
    let mut node = None;
    let mut objective = None;
    let mut worker = None;
    let mut identity_path: Option<String> = None;
    let mut partitions = 8u64;
    let mut rounds = None;
    let mut heartbeat = 30u64;
    let mut device = None;
    let mut margin = DEFAULT_MARGIN_SECONDS;

    let mut i = 0;
    while i < flags.len() {
        let flag = flags[i].as_str();
        if flag == "--help" || flag == "-h" {
            return Ok(None);
        }
        let value = || -> Result<&String, String> {
            flags
                .get(i + 1)
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        let number = |text: &str| -> Result<u64, String> {
            text.parse::<u64>()
                .map_err(|_| format!("{flag}: {text:?} is not a non-negative integer"))
        };
        match flag {
            "--node" => node = Some(value()?.clone()),
            "--objective" => objective = Some(value()?.clone()),
            "--worker" => worker = Some(value()?.clone()),
            "--identity" => identity_path = Some(value()?.clone()),
            "--partitions" => partitions = number(value()?)?,
            "--rounds" => rounds = Some(number(value()?)?),
            "--heartbeat" => heartbeat = number(value()?)?,
            "--device" => device = Some(value()?.clone()),
            "--margin" => margin = number(value()?)?,
            other => return Err(format!("unknown option {other:?}")),
        }
        i += 2;
    }

    let node = NodeUrl::parse(&node.ok_or("--node is required")?).map_err(|e| e.to_string())?;
    let objective = objective.ok_or("--objective is required")?;
    if !objective.starts_with("sha256:") {
        return Err(format!(
            "--objective {objective:?} should be an id, sha256:…"
        ));
    }
    let worker = worker.ok_or("--worker is required")?;
    // `|` separates the fields of a commitment hash's preimage; a name holding
    // one could collide with another submitter's commitment.
    if worker.is_empty() || worker.contains('|') || worker.chars().any(char::is_control) {
        return Err("--worker must be printable text without `|`".into());
    }
    if partitions == 0 {
        return Err("--partitions must be at least 1".into());
    }
    if heartbeat == 0 {
        return Err("--heartbeat must be at least 1 second".into());
    }
    if solver.is_empty() {
        return Err("no solver: put the command after `--`".into());
    }
    let identity = identity_path.map(|path| load_identity(&path)).transpose()?;
    Ok(Some(Options {
        node,
        objective,
        worker,
        identity,
        partitions,
        rounds,
        heartbeat: Duration::from_secs(heartbeat),
        device,
        margin,
        solver,
    }))
}

/// The identity file `cairn identity --out` writes: `{"secret": hex, "public": hex}`.
fn load_identity(path: &str) -> Result<Identity, String> {
    let text = crate::secret_file::read_to_string(std::path::Path::new(path))
        .map_err(|error| format!("{path}: {error}"))?;
    let value = Value::from_json(&text).map_err(|error| format!("{path}: {error}"))?;
    let secret = value
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}: identity file needs a \"secret\" hex field"))?;
    let bytes = crate::hex::decode(secret)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| format!("{path}: \"secret\" must be 32 bytes of hex"))?;
    let identity = Identity::from_secret_bytes(bytes);
    if let Some(declared) = value.get("public").and_then(Value::as_str) {
        if declared != identity.submitter_id() {
            return Err(format!(
                "{path}: \"public\" does not match \"secret\"; this file would sign as {}",
                identity.submitter_id()
            ));
        }
    }
    Ok(identity)
}

#[derive(Debug)]
pub enum WorkError {
    Agent(AgentError),
    Solver(String),
}

impl From<AgentError> for WorkError {
    fn from(error: AgentError) -> WorkError {
        WorkError::Agent(error)
    }
}

/// A committed artifact waiting for its epoch to pass.
struct Pending {
    epoch: u64,
    artifact: Value,
    nonce: String,
}

struct Worker {
    options: Options,
    submitter: String,
    epoch_seconds: u64,
    pending: Vec<Pending>,
    committed: u64,
    revealed: u64,
    rounds: u64,
}

impl Worker {
    fn new(options: Options) -> Result<Worker, WorkError> {
        let submitter = match &options.identity {
            Some(identity) => identity.submitter_id(),
            None => options.worker.clone(),
        };
        Ok(Worker {
            options,
            submitter,
            epoch_seconds: 0,
            pending: Vec::new(),
            committed: 0,
            revealed: 0,
            rounds: 0,
        })
    }

    fn run(&mut self) -> Result<(), WorkError> {
        let first = self.assignment()?;
        say(&format!(
            "{} on {} at {}, epochs of {} s{}",
            self.options.worker,
            short(&self.options.objective),
            self.options.node.as_str(),
            self.epoch_seconds,
            if self.submitter != self.options.worker {
                format!(", signing as {}", short(&self.submitter))
            } else {
                String::new()
            }
        ));
        let mut next = Some(first);
        let mut failures = 0u32;
        loop {
            self.reveal_due()?;
            let more_rounds = self.options.rounds.is_none_or(|limit| self.rounds < limit);
            if !more_rounds {
                if self.pending.is_empty() {
                    say(&format!(
                        "done: {} round(s), {} committed, {} revealed",
                        self.rounds, self.committed, self.revealed
                    ));
                    return Ok(());
                }
                self.sleep_to_next_epoch();
                continue;
            }
            if !self.safe_to_post() {
                self.sleep_to_next_epoch();
                continue;
            }
            let assignment = match next.take() {
                Some(assignment) => assignment,
                None => self.assignment()?,
            };
            let started = Instant::now();
            match self.solve(&assignment) {
                Ok(artifacts) => {
                    failures = 0;
                    self.rounds += 1;
                    if artifacts.is_empty() {
                        say(&format!("round {}: nothing", self.rounds));
                    }
                    for artifact in artifacts {
                        self.commit(artifact)?;
                    }
                }
                Err(message) => {
                    failures += 1;
                    self.rounds += 1;
                    say(&format!("round {}: {message}", self.rounds));
                    if failures >= 3 {
                        return Err(WorkError::Solver(format!(
                            "the solver failed {failures} rounds running; stopping"
                        )));
                    }
                }
            }
            // A solver that answers instantly would otherwise spin the node
            // with assignments; one round a second is plenty for anything
            // that finishes that fast.
            if let Some(rest) = Duration::from_secs(1).checked_sub(started.elapsed()) {
                thread::sleep(rest);
            }
        }
    }

    fn assignment(&mut self) -> Result<Value, WorkError> {
        let path = format!(
            "/work_assignment?objective_id={}&node_id={}&partitions={}",
            encode(&self.options.objective),
            encode(&self.options.worker),
            self.options.partitions
        );
        let response = http::get(&self.options.node, &path, NODE_TIMEOUT)?;
        if !response.ok() {
            return Err(AgentError::Node(format!(
                "work_assignment answered {}",
                response.error_text()
            ))
            .into());
        }
        let seconds = response
            .body
            .get("epoch_seconds")
            .and_then(Value::as_u64)
            .filter(|s| *s > 0)
            .ok_or_else(|| AgentError::Node("work_assignment carried no epoch_seconds".into()))?;
        self.epoch_seconds = seconds;
        Ok(response.body)
    }

    fn epoch(&self) -> u64 {
        now_seconds() / self.epoch_seconds.max(1)
    }

    fn seconds_left(&self) -> u64 {
        let length = self.epoch_seconds.max(1);
        length - now_seconds() % length
    }

    fn safe_to_post(&self) -> bool {
        // An epoch shorter than the margin would never be safe; post anyway
        // rather than hang on a demo node with five-second epochs.
        self.seconds_left() > self.options.margin.min(self.epoch_seconds / 2)
    }

    fn sleep_to_next_epoch(&self) {
        thread::sleep(Duration::from_secs(self.seconds_left() + 1));
    }

    /// Run the solver once over `assignment`, heartbeating while it runs.
    fn solve(&self, assignment: &Value) -> Result<Vec<Value>, String> {
        let line = assignment.canonical_string();
        let epoch = assignment
            .get("epoch")
            .and_then(Value::as_u64)
            .unwrap_or(self.epoch());
        let ends_in = assignment
            .get("epoch_ends_in_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(self.seconds_left());
        let mut child = Command::new(&self.options.solver[0])
            .args(&self.options.solver[1..])
            .env("CAIRN_NODE", self.options.node.as_str())
            .env("CAIRN_OBJECTIVE", &self.options.objective)
            .env("CAIRN_WORKER", &self.options.worker)
            .env("CAIRN_EPOCH", epoch.to_string())
            .env("CAIRN_EPOCH_ENDS_IN", ends_in.to_string())
            .env("CAIRN_ASSIGNMENT", &line)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("could not start {:?}: {e}", self.options.solver[0]))?;
        if let Some(mut stdin) = child.stdin.take() {
            // A solver that ignores stdin closes it; that is not an error.
            let _ = writeln!(stdin, "{line}");
        }

        let stop = Arc::new(AtomicBool::new(false));
        let found = Arc::new(AtomicU64::new(0));
        let beat = {
            let stop = Arc::clone(&stop);
            let found = Arc::clone(&found);
            let body = self.heartbeat_body(assignment);
            let node = self.options.node.clone();
            let every = self.options.heartbeat;
            thread::spawn(move || {
                let mut last: Option<Instant> = None;
                while !stop.load(Ordering::SeqCst) {
                    if last.is_none_or(|at| at.elapsed() >= every) {
                        let mut body = body.clone();
                        if let Value::Object(map) = &mut body {
                            map.insert(
                                "units_pending".into(),
                                Value::Int(i128::from(found.load(Ordering::SeqCst))),
                            );
                        }
                        if let Err(error) = http::post_json(&node, "/progress", &body, NODE_TIMEOUT)
                        {
                            say(&format!("heartbeat: {error}"));
                        }
                        last = Some(Instant::now());
                    }
                    thread::sleep(Duration::from_millis(250));
                }
            })
        };

        let mut artifacts = Vec::new();
        let mut problems = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            for (n, line) in BufReader::new(stdout).lines().enumerate() {
                let Ok(line) = line else { break };
                let text = line.trim();
                if text.is_empty() {
                    continue;
                }
                match Value::from_json(text) {
                    Ok(value) if value.as_object().is_some() => {
                        artifacts.push(value);
                        found.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(_) => problems.push(format!("line {}: not a JSON object", n + 1)),
                    // `canonical::Value` has no floats, on purpose; say so
                    // here rather than letting the node refuse it later.
                    Err(error) => problems.push(format!("line {}: {error}", n + 1)),
                }
            }
        }
        let status = child
            .wait()
            .map_err(|e| format!("waiting for the solver: {e}"));
        stop.store(true, Ordering::SeqCst);
        let _ = beat.join();
        let status = status?;
        for problem in &problems {
            say(&format!("solver output skipped, {problem}"));
        }
        if !status.success() {
            return Err(format!(
                "the solver exited with {status}; discarding {} candidate(s) it printed",
                artifacts.len()
            ));
        }
        Ok(artifacts)
    }

    fn heartbeat_body(&self, assignment: &Value) -> Value {
        let mut body = BTreeMap::from([
            (
                "objective_id".to_string(),
                Value::string(self.options.objective.clone()),
            ),
            (
                "worker".to_string(),
                Value::string(self.options.worker.clone()),
            ),
            ("steps".to_string(), Value::Int(0)),
            ("epoch".to_string(), Value::Int(i128::from(self.epoch()))),
            (
                "units_submitted".to_string(),
                Value::Int(i128::from(self.revealed)),
            ),
            ("client".to_string(), Value::string(CLIENT)),
        ]);
        if let Some(units) = assignment.get("units").filter(|u| !u.is_null()) {
            if let (Some(first), Some(end)) = (
                units.get("first").and_then(Value::as_u64),
                units.get("end").and_then(Value::as_u64),
            ) {
                body.insert(
                    "units".to_string(),
                    Value::object([
                        ("first", Value::Int(i128::from(first))),
                        ("end", Value::Int(i128::from(end))),
                    ]),
                );
            }
        }
        if let Some(device) = &self.options.device {
            body.insert("device".to_string(), Value::string(device.clone()));
        }
        Value::Object(body)
    }

    fn commit(&mut self, artifact: Value) -> Result<(), WorkError> {
        let nonce = nonce();
        let hash = commitment_hash(&self.options.objective, &self.submitter, &artifact, &nonce);
        let mut record = Commitment::new(
            self.options.objective.clone(),
            self.submitter.clone(),
            hash,
            timestamp(),
        );
        if let Some(identity) = &self.options.identity {
            record = record.signed_with(identity);
        }
        let epoch = self.epoch();
        loop {
            let response = http::post_json(
                &self.options.node,
                "/submit?kind=commitment",
                &record.to_value(),
                NODE_TIMEOUT,
            )?;
            match response.status {
                202 | 200 => {
                    self.committed += 1;
                    self.pending.push(Pending {
                        epoch,
                        artifact,
                        nonce,
                    });
                    say(&format!("committed a candidate in epoch {epoch}"));
                    return Ok(());
                }
                429 => {
                    say("the node's queue is full; trying the commitment again shortly");
                    thread::sleep(Duration::from_secs(5));
                    if !self.safe_to_post() {
                        say("the epoch is closing; dropping this candidate");
                        return Ok(());
                    }
                }
                _ => {
                    say(&format!("commitment refused: {}", response.error_text()));
                    return Ok(());
                }
            }
        }
    }

    /// Reveal every commitment whose epoch has passed.
    fn reveal_due(&mut self) -> Result<(), WorkError> {
        if self.pending.is_empty() || !self.safe_to_post() {
            return Ok(());
        }
        let current = self.epoch();
        let (due, waiting): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| p.epoch < current);
        self.pending = waiting;
        if due.is_empty() {
            return Ok(());
        }
        let cites = self.must_cite()?;
        for pending in due {
            let claim = Claim::new(
                self.options.objective.clone(),
                self.submitter.clone(),
                pending.artifact.clone(),
                pending.nonce.clone(),
                timestamp(),
                cites.clone(),
            );
            let mut claim = match claim {
                Ok(claim) => claim,
                Err(error) => {
                    say(&format!("not a valid claim, dropping it: {error:?}"));
                    continue;
                }
            };
            if let Some(identity) = &self.options.identity {
                claim = claim.signed_with(identity);
            }
            let response = http::post_json(
                &self.options.node,
                "/submit?kind=claim",
                &claim.to_value(),
                NODE_TIMEOUT,
            )?;
            match response.status {
                202 | 200 => {
                    self.revealed += 1;
                    say(&format!(
                        "revealed the candidate from epoch {}; the verifier decides at admission",
                        pending.epoch
                    ));
                }
                429 => {
                    say("the node's queue is full; holding the reveal");
                    self.pending.push(pending);
                }
                _ => say(&format!("reveal refused: {}", response.error_text())),
            }
        }
        Ok(())
    }

    /// The claim a submission must cite, if the objective has a frontier.
    /// Read fresh before every batch of reveals: the frontier moves.
    fn must_cite(&self) -> Result<Vec<String>, WorkError> {
        let response = http::get(
            &self.options.node,
            &format!("/frontier/{}", self.options.objective),
            NODE_TIMEOUT,
        )?;
        if !response.ok() {
            return Ok(Vec::new());
        }
        Ok(response
            .body
            .get("frontier")
            .filter(|f| !f.is_null())
            .and_then(|f| f.get("must_cite"))
            .and_then(Value::as_str)
            .map(|id| vec![id.to_string()])
            .unwrap_or_default())
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn timestamp() -> String {
    crate::time::format_iso8601_utc(i64::try_from(now_seconds()).unwrap_or(i64::MAX))
}

fn nonce() -> String {
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    crate::hex::encode(&bytes)
}

/// Percent-encode a query value: everything but unreserved characters and `:`,
/// which ids carry and the node's query parser takes as is.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn short(id: &str) -> String {
    crate::canonical::short(id)
}

fn say(text: &str) {
    let now = timestamp();
    eprintln!("{} {text}", &now[11..19]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn the_solver_is_everything_after_the_separator() {
        let options = parse(&args(
            "--node http://10.0.0.2:8080 --objective sha256:ab --worker w1 -- ./solve --fast",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(options.solver, vec!["./solve", "--fast"]);
        assert_eq!(options.node.port, 8080);
        assert_eq!(options.partitions, 8);
    }

    #[test]
    fn a_worker_name_that_could_forge_a_commitment_preimage_is_refused() {
        let error = parse(&args(
            "--node http://h:1 --objective sha256:ab --worker a|b -- x",
        ))
        .unwrap_err();
        assert!(error.contains('|'), "{error}");
    }

    #[test]
    fn a_missing_solver_or_bad_id_is_a_usage_error() {
        assert!(
            parse(&args("--node http://h:1 --objective sha256:ab --worker w"))
                .unwrap_err()
                .contains("solver")
        );
        assert!(
            parse(&args("--node http://h:1 --objective ab --worker w -- x"))
                .unwrap_err()
                .contains("sha256")
        );
        assert!(parse(&args("--help")).unwrap().is_none());
    }

    #[test]
    fn query_values_are_percent_encoded_but_ids_survive() {
        assert_eq!(encode("sha256:ab12"), "sha256:ab12");
        assert_eq!(encode("garage gpu&x=1"), "garage%20gpu%26x%3D1");
    }

    #[test]
    fn a_heartbeat_names_the_units_this_worker_holds() {
        let worker = Worker::new(
            parse(&args(
                "--node http://h:1 --objective sha256:ab --worker w --device m2 -- x",
            ))
            .unwrap()
            .unwrap(),
        )
        .unwrap();
        let assignment =
            Value::from_json(r#"{"epoch":3,"units":{"first":4,"end":9,"of":64}}"#).unwrap();
        let body = worker.heartbeat_body(&assignment);
        let (heartbeat, ignored) = crate::progress::Heartbeat::from_value(&body).unwrap();
        assert!(ignored.is_empty(), "the node would ignore {ignored:?}");
        assert_eq!(heartbeat.units, Some((4, 9)));
        assert_eq!(heartbeat.worker, "w");
    }
}
