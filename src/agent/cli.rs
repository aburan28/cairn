//! `cairn agent …`: the host agent from a shell, and the loop a service runs.
//!
//! Hand-parsed like the rest of the binary. Exit codes follow the lab's:
//! `0` done, `1` a job failed, `2` bad usage, `3` nothing could be learned --
//! no sandbox works here, no node could be reached, no systemd to install
//! into -- which is a fact about this host and not about any job.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::http::{self, NodeUrl};
use super::job::{self, Job, Receipt};
use super::probe::Inventory;
use super::sandbox::{Names, Preference, Sandboxes};
use super::service::{self, Install};
use super::{AgentError, DATA_ENV, DEFAULT_DATA_DIR, DEFAULT_INTERVAL_SECONDS};
use crate::canonical::Value;

pub const NODES_ENV: &str = "CAIRN_AGENT_NODES";
pub const NAME_ENV: &str = "CAIRN_AGENT_NAME";
pub const ROLES_ENV: &str = "CAIRN_AGENT_ROLES";
pub const SANDBOX_ENV: &str = "CAIRN_AGENT_SANDBOX";
pub const INTERVAL_ENV: &str = "CAIRN_AGENT_INTERVAL";
pub const PARALLEL_ENV: &str = "CAIRN_AGENT_PARALLEL";

/// How long one request to a node may take. Registrations are small and a
/// node that takes longer than this is one to report, not wait for.
const NODE_TIMEOUT: Duration = Duration::from_secs(15);

const USAGE: &str = "\
cairn agent — put this Linux host on the network as a place executor jobs run

USAGE
    cairn agent <command> [options]

    probe [--json]                  what this machine is: CPUs, memory, GPUs, and which
                                    sandboxes (kata, runsc, bwrap) can run a job here
    run --node URL [--node URL]...  register with each node every --interval seconds and
        [--name HOST] [--roles R,R] run jobs dropped into <data>/jobs/queue, each under
        [--data-dir DIR]            gVisor or Kata; the loop a service runs
        [--interval SECONDS] [--sandbox PREF] [--parallel N] [--once]
    exec (--image IMAGE | --rootfs DIR) [--sandbox PREF] [--cpus N] [--memory MB]
         [--gpus N] [--pids N] [--timeout SECONDS] [--network] [--env K=V]...
         [--input SRC[:TARGET]]... [--cwd DIR] [--objective ID --task T]
         [--data-dir DIR] [--json] -- COMMAND [ARGS]...
                                    run one job now and print its receipt
    submit FILE [--data-dir DIR]    validate a job spec and queue it for `run`
    jobs [--data-dir DIR] [--json]  queued, running and finished jobs, with receipts
    install --node URL [--node URL]... [--name HOST] [--roles R,R] [--user USER]
            [--data-dir DIR] [--sandbox PREF] [--interval S] [--parallel N]
            [--print] [--no-start]  write cairn-agent.service and its environment file,
                                    create the user, enable and start it (root)
    uninstall [--data-dir DIR] [--purge]
                                    stop, disable and remove the service; --purge also
                                    removes the data directory

SANDBOX PREFERENCE (--sandbox, CAIRN_AGENT_SANDBOX, or a job's `sandbox`)
    auto        gVisor if it works here, else Kata, else bubblewrap   (default)
    strongest   Kata, else gVisor
    kata | runsc | bwrap            exactly that one
    none        unconfined; only ever by explicit request, and the receipt says so

ENVIRONMENT  (flags win; these are what the service's environment file sets)
    CAIRN_AGENT_NODES      comma-separated node URLs      CAIRN_AGENT_NAME       host name
    CAIRN_AGENT_ROLES      declared roles (executor)      CAIRN_AGENT_DATA       /var/lib/cairn-agent
    CAIRN_AGENT_SANDBOX    preference (auto)              CAIRN_AGENT_INTERVAL   seconds (60)
    CAIRN_AGENT_PARALLEL   jobs at once (1)
    CAIRN_AGENT_KATA_RUNTIME / CAIRN_AGENT_RUNSC_RUNTIME   the engine's names for them
    CAIRN_AGENT_ENGINE     prefer docker, podman or nerdctl when several answer

EXIT CODES
    0 done   1 a job failed   2 bad usage   3 nothing was learned: no sandbox works
    here, no node answered, or there is no systemd to install into
";

/// Entry point: `cairn agent ARGS…`. Returns the process exit code.
pub fn main(args: Vec<String>) -> i32 {
    crate::logging::init();
    let mut out = io::stdout().lock();
    match run(args, &mut out) {
        Ok(code) => code,
        Err(AgentError::Invalid(message)) => {
            eprintln!("cairn agent: {message}\n\nrun `cairn agent help` for usage");
            2
        }
        Err(error @ AgentError::Unavailable(_)) | Err(error @ AgentError::Node(_)) => {
            eprintln!("cairn agent: {error}");
            3
        }
        Err(error) => {
            eprintln!("cairn agent: {error}");
            1
        }
    }
}

// -- argument parsing -------------------------------------------------------------

#[derive(Default, Debug)]
struct Parsed {
    values: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
    positional: Vec<String>,
    trailing: Vec<String>,
}

impl Parsed {
    fn one(&self, flag: &str) -> Option<&str> {
        self.values
            .get(flag)
            .and_then(|v| v.last())
            .map(String::as_str)
    }

    fn many(&self, flag: &str) -> Vec<String> {
        self.values.get(flag).cloned().unwrap_or_default()
    }

    fn switch(&self, flag: &str) -> bool {
        self.switches.iter().any(|s| s == flag)
    }

    fn u64(&self, flag: &str, env: Option<&str>, default: u64) -> Result<u64, AgentError> {
        let text = match self.one(flag) {
            Some(text) => Some(text.to_string()),
            None => env.and_then(|name| std::env::var(name).ok()),
        };
        match text {
            None => Ok(default),
            Some(text) => text.trim().parse::<u64>().map_err(|_| {
                AgentError::Invalid(format!(
                    "--{flag} needs a non-negative integer, not {text:?}"
                ))
            }),
        }
    }
}

fn parse(args: &[String], with_values: &[&str], switches: &[&str]) -> Result<Parsed, AgentError> {
    let mut parsed = Parsed::default();
    let mut items = args.iter();
    while let Some(item) = items.next() {
        if item == "--" {
            parsed.trailing.extend(items.cloned());
            break;
        }
        if let Some(flag) = item.strip_prefix("--") {
            let (flag, inline) = match flag.split_once('=') {
                Some((f, v)) => (f, Some(v.to_string())),
                None => (flag, None),
            };
            if with_values.contains(&flag) {
                let value = match inline {
                    Some(v) => v,
                    None => items
                        .next()
                        .cloned()
                        .ok_or_else(|| AgentError::Invalid(format!("--{flag} needs a value")))?,
                };
                parsed
                    .values
                    .entry(flag.to_string())
                    .or_default()
                    .push(value);
            } else if switches.contains(&flag) {
                parsed.switches.push(flag.to_string());
            } else {
                return Err(AgentError::Invalid(format!("unknown option --{flag}")));
            }
        } else {
            parsed.positional.push(item.clone());
        }
    }
    Ok(parsed)
}

fn env_or(flag: Option<&str>, env: &str) -> Option<String> {
    flag.map(str::to_string)
        .or_else(|| std::env::var(env).ok())
        .filter(|v| !v.trim().is_empty())
}

fn data_dir(parsed: &Parsed) -> PathBuf {
    PathBuf::from(
        env_or(parsed.one("data-dir"), DATA_ENV).unwrap_or_else(|| DEFAULT_DATA_DIR.to_string()),
    )
}

fn nodes(parsed: &Parsed) -> Result<Vec<NodeUrl>, AgentError> {
    let mut texts = parsed.many("node");
    if texts.is_empty() {
        if let Ok(list) = std::env::var(NODES_ENV) {
            texts.extend(
                list.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    texts.iter().map(|t| NodeUrl::parse(t)).collect()
}

fn preference(parsed: &Parsed) -> Result<Preference, AgentError> {
    match env_or(parsed.one("sandbox"), SANDBOX_ENV) {
        Some(text) => Preference::parse(&text),
        None => Ok(Preference::Auto),
    }
}

fn host_name(parsed: &Parsed, inventory: &Inventory) -> String {
    env_or(parsed.one("name"), NAME_ENV).unwrap_or_else(|| inventory.hostname.clone())
}

fn roles(parsed: &Parsed) -> Result<Vec<String>, AgentError> {
    let text = env_or(parsed.one("roles"), ROLES_ENV).unwrap_or_else(|| "executor".to_string());
    let roles: Vec<String> = text
        .split(',')
        .map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty())
        .collect();
    for role in &roles {
        if crate::network::Role::parse(role).is_none() {
            return Err(AgentError::Invalid(format!(
                "unknown role {role:?}; the roles are coordinator, executor, verifier, relay"
            )));
        }
    }
    Ok(roles)
}

// -- commands -----------------------------------------------------------------

fn run(args: Vec<String>, out: &mut impl io::Write) -> Result<i32, AgentError> {
    let command = args.first().cloned().unwrap_or_else(|| "help".to_string());
    let rest = &args[1.min(args.len())..];
    match command.as_str() {
        "help" | "--help" | "-h" => {
            out.write_all(USAGE.as_bytes())?;
            Ok(0)
        }
        "probe" => probe(rest, out),
        "run" => run_loop(rest, out),
        "exec" => exec(rest, out),
        "submit" => submit(rest, out),
        "jobs" => jobs(rest, out),
        "install" => install(rest, out),
        "uninstall" => uninstall(rest, out),
        other => Err(AgentError::Invalid(format!("unknown command {other:?}"))),
    }
}

fn probe(args: &[String], out: &mut impl io::Write) -> Result<i32, AgentError> {
    let parsed = parse(args, &[], &["json"])?;
    let inventory = Inventory::probe();
    let sandboxes = Sandboxes::probe(&Names::from_env());
    if parsed.switch("json") {
        let value = Value::object([
            ("agent", Value::string(super::CLIENT)),
            ("hardware", inventory.to_value()),
            ("sandboxes", sandboxes.to_value()),
        ]);
        writeln!(out, "{}", value.canonical_string())?;
        return Ok(0);
    }
    writeln!(out, "{} on {}", super::CLIENT, inventory.hostname)?;
    writeln!(
        out,
        "  {}/{} kernel {}",
        inventory.os,
        inventory.arch,
        inventory.kernel.as_deref().unwrap_or("?")
    )?;
    writeln!(
        out,
        "  cpus: {} ({}; {} socket(s), {} numa node(s)) [{}]",
        inventory
            .cpus
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into()),
        inventory.cpu_model.as_deref().unwrap_or("unknown model"),
        inventory
            .sockets
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into()),
        inventory
            .numa_nodes
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into()),
        inventory.cpu_features.join(" ")
    )?;
    writeln!(
        out,
        "  memory: {} MiB{}",
        inventory
            .memory_mb
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into()),
        match (inventory.cgroup_cpus, inventory.cgroup_memory_mb) {
            (None, None) => String::new(),
            (cpus, memory) => format!(
                " (cgroup caps: {} cpus, {} MiB)",
                cpus.map(|n| n.to_string()).unwrap_or_else(|| "no".into()),
                memory.map(|n| n.to_string()).unwrap_or_else(|| "no".into())
            ),
        }
    )?;
    if inventory.gpus.is_empty() {
        writeln!(out, "  gpus: none")?;
    }
    for gpu in &inventory.gpus {
        writeln!(
            out,
            "  gpu {}: {} {} {}{}",
            gpu.index,
            gpu.vendor,
            gpu.model.as_deref().unwrap_or("?"),
            gpu.memory_mb
                .map(|mb| format!("{mb} MiB "))
                .unwrap_or_default(),
            gpu.bus.as_deref().unwrap_or("")
        )?;
    }
    writeln!(out, "  kvm: {}", if inventory.kvm { "yes" } else { "no" })?;
    writeln!(out, "sandboxes:")?;
    for found in [&sandboxes.kata, &sandboxes.runsc, &sandboxes.bwrap] {
        let via: Vec<String> = found
            .via
            .iter()
            .map(|via| match via {
                super::sandbox::Via::Native => "native".to_string(),
                super::sandbox::Via::Engine { engine, runtime } => format!("{engine}:{runtime}"),
            })
            .collect();
        writeln!(
            out,
            "  {:<6} {} {}",
            found.kind.as_str(),
            if found.usable { "usable" } else { "unusable" },
            if found.usable {
                format!(
                    "via {}{}{}",
                    via.join(", "),
                    if found.gpu { ", gpu" } else { "" },
                    found
                        .version
                        .as_deref()
                        .map(|v| format!(" ({v})"))
                        .unwrap_or_default()
                )
            } else {
                found.why.clone().unwrap_or_default()
            },
        )?;
    }
    for engine in &sandboxes.engines {
        writeln!(
            out,
            "  engine {} {} runtimes: {}",
            engine.name,
            engine.version.as_deref().unwrap_or(""),
            engine.runtimes.join(", ")
        )?;
    }
    Ok(0)
}

// -- the loop ---------------------------------------------------------------------

/// A job in flight.
struct Running {
    job: Job,
    dir: PathBuf,
    handle: JoinHandle<Receipt>,
    leased_on: Vec<usize>,
}

struct Loop {
    nodes: Vec<NodeUrl>,
    node_ok: Vec<bool>,
    name: String,
    roles: Vec<String>,
    data: PathBuf,
    interval: Duration,
    preference: Preference,
    parallel: usize,
    inventory: Inventory,
    sandboxes: Sandboxes,
    running: Vec<Running>,
    completed: u64,
    failed: u64,
}

impl Loop {
    fn registration(&self) -> Value {
        let objectives: std::collections::BTreeSet<String> = self
            .running
            .iter()
            .filter_map(|r| r.job.objective_id.clone())
            .collect();
        Value::object([
            ("host", Value::string(self.name.clone())),
            ("agent", Value::string(super::CLIENT)),
            (
                "roles",
                Value::array(self.roles.iter().map(|r| Value::string(r.clone()))),
            ),
            ("hardware", self.inventory.to_value()),
            ("sandboxes", self.sandboxes.to_value()),
            (
                "jobs",
                Value::object([
                    ("running", Value::Int(self.running.len() as i128)),
                    ("capacity", Value::Int(self.parallel as i128)),
                    ("completed", Value::Int(i128::from(self.completed))),
                    ("failed", Value::Int(i128::from(self.failed))),
                    ("sandbox", Value::string(self.preference.as_str())),
                ]),
            ),
            (
                "objectives",
                Value::array(objectives.into_iter().map(Value::string)),
            ),
        ])
    }

    /// Post the registration to every node. Returns how many accepted it.
    fn register(&mut self) -> usize {
        let body = self.registration();
        let mut accepted = 0;
        for (index, node) in self.nodes.iter().enumerate() {
            match http::post_json(node, "/hosts", &body, NODE_TIMEOUT) {
                Ok(response) if response.ok() => {
                    accepted += 1;
                    if !self.node_ok[index] {
                        log::info!("agent: registered with {}", node.as_str());
                        self.node_ok[index] = true;
                    }
                    if let Some(ignored) = response.body.get("ignored").and_then(Value::as_array) {
                        if !ignored.is_empty() {
                            log::warn!(
                                "agent: {} ignored registration fields {}",
                                node.as_str(),
                                Value::Array(ignored.to_vec()).canonical_string()
                            );
                        }
                    }
                }
                Ok(response) => {
                    if self.node_ok[index] {
                        log::warn!(
                            "agent: {} refused the registration: {}",
                            node.as_str(),
                            response.error_text()
                        );
                        self.node_ok[index] = false;
                    }
                }
                Err(error) => {
                    if self.node_ok[index] {
                        log::warn!("agent: {error}; will keep trying");
                        self.node_ok[index] = false;
                    }
                }
            }
        }
        accepted
    }

    fn lease_body(&self, job: &Job) -> Option<Value> {
        let (objective_id, task) = (job.objective_id.as_ref()?, job.task.as_ref()?);
        let ttl = (job.timeout.as_secs() + 2 * self.interval.as_secs())
            .clamp(1, crate::lease::MAX_TTL_SECONDS);
        Some(Value::object([
            ("objective_id", Value::string(objective_id.clone())),
            ("task", Value::string(task.clone())),
            ("holder", Value::string(self.name.clone())),
            ("ttl_seconds", Value::Int(i128::from(ttl))),
            (
                "note",
                Value::string(format!("{} job {}", super::CLIENT, job.id)),
            ),
        ]))
    }

    /// Claim (or renew) the job's lease on every node; remember which took it.
    fn lease(&self, job: &Job) -> Vec<usize> {
        let Some(body) = self.lease_body(job) else {
            return Vec::new();
        };
        let mut held_on = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            match http::post_json(node, "/lease", &body, NODE_TIMEOUT) {
                Ok(response) if response.ok() => {
                    held_on.push(index);
                    if response.body.get("held") == Some(&Value::Bool(false)) {
                        log::warn!(
                            "agent: {} says job {} ({}) is held by {}; running it anyway -- a \
                             lease is advice, and this job was queued here",
                            node.as_str(),
                            job.id,
                            job.task.as_deref().unwrap_or(""),
                            response
                                .body
                                .get("held_by")
                                .and_then(Value::as_str)
                                .unwrap_or("somebody")
                        );
                    }
                }
                Ok(response) => log::debug!(
                    "agent: {} would not lease job {}: {}",
                    node.as_str(),
                    job.id,
                    response.error_text()
                ),
                Err(error) => log::debug!("agent: lease: {error}"),
            }
        }
        held_on
    }

    fn release(&self, job: &Job, on: &[usize], outcome: &str) {
        let (Some(objective_id), Some(task)) = (&job.objective_id, &job.task) else {
            return;
        };
        let body = Value::object([
            ("objective_id", Value::string(objective_id.clone())),
            ("task", Value::string(task.clone())),
            ("holder", Value::string(self.name.clone())),
            ("outcome", Value::string(outcome)),
        ]);
        for index in on {
            if let Some(node) = self.nodes.get(*index) {
                if let Err(error) = http::post_json(node, "/lease/release", &body, NODE_TIMEOUT) {
                    log::debug!("agent: release: {error}");
                }
            }
        }
    }

    /// Move finished jobs to `done/`, release their leases, count them.
    fn reap(&mut self) {
        let mut index = 0;
        while index < self.running.len() {
            if !self.running[index].handle.is_finished() {
                index += 1;
                continue;
            }
            let running = self.running.remove(index);
            let receipt = match running.handle.join() {
                Ok(receipt) => receipt,
                Err(_) => {
                    log::error!("agent: job {} panicked in its runner", running.job.id);
                    self.failed += 1;
                    self.release(&running.job, &running.leased_on, "abandoned");
                    let _ = move_dir(&running.dir, &self.data.join("jobs/done"));
                    continue;
                }
            };
            if receipt.succeeded() {
                self.completed += 1;
                log::info!(
                    "agent: job {} completed under {} in {} ms",
                    receipt.job_id,
                    receipt.sandbox.as_str(),
                    receipt.wall_ms
                );
            } else {
                self.failed += 1;
                log::warn!(
                    "agent: job {} {}: exit {:?}{}{}",
                    receipt.job_id,
                    receipt.lease_outcome(),
                    receipt.exit_status,
                    if receipt.timed_out { ", timed out" } else { "" },
                    receipt
                        .error
                        .as_deref()
                        .map(|e| format!(", {e}"))
                        .unwrap_or_default()
                );
            }
            self.release(&running.job, &running.leased_on, receipt.lease_outcome());
            if let Err(error) = move_dir(&running.dir, &self.data.join("jobs/done")) {
                log::error!("agent: {error}");
            }
        }
    }

    /// Start queued jobs up to the parallel limit.
    fn start_queued(&mut self) {
        while self.running.len() < self.parallel {
            let Some(spec) = oldest_spec(&self.data.join("jobs/queue")) else {
                break;
            };
            let job = match Job::from_file(&spec) {
                Ok(job) => job,
                Err(error) => {
                    log::warn!("agent: {}: {error}; moved aside", spec.display());
                    let aside = self.data.join("jobs/done").join(format!(
                        "{}.invalid",
                        spec.file_name().unwrap_or_default().to_string_lossy()
                    ));
                    let _ = fs::rename(&spec, &aside);
                    continue;
                }
            };
            let dir = self.data.join("jobs/running").join(&job.id);
            if dir.exists() || self.data.join("jobs/done").join(&job.id).exists() {
                log::warn!(
                    "agent: job {} already ran or is running; refusing to run it twice -- \
                     give it a new id",
                    job.id
                );
                let _ = fs::rename(
                    &spec,
                    self.data
                        .join("jobs/done")
                        .join(format!("{}.duplicate", job.id)),
                );
                continue;
            }
            if let Err(error) =
                fs::create_dir_all(&dir).and_then(|()| fs::rename(&spec, dir.join("job.json")))
            {
                log::error!("agent: {}: {error}", dir.display());
                break;
            }
            let leased_on = self.lease(&job);
            log::info!(
                "agent: starting job {}{}{}",
                job.id,
                job.image
                    .as_deref()
                    .map(|i| format!(" (image {i})"))
                    .unwrap_or_default(),
                job.rootfs
                    .as_deref()
                    .map(|r| format!(" (rootfs {})", r.display()))
                    .unwrap_or_default()
            );
            let (thread_job, thread_sandboxes, thread_dir, host) = (
                job.clone(),
                self.sandboxes.clone(),
                dir.clone(),
                self.name.clone(),
            );
            let handle = std::thread::spawn(move || {
                job::run(&thread_job, &thread_sandboxes, &thread_dir, &host)
            });
            self.running.push(Running {
                job,
                dir,
                handle,
                leased_on,
            });
        }
    }

    /// Renew every running job's lease on every node. A node that was down
    /// at claim time and is back now takes the lease here, which is why the
    /// confirmed set is recomputed rather than kept.
    fn renew_leases(&mut self) {
        let jobs: Vec<Job> = self.running.iter().map(|r| r.job.clone()).collect();
        let held: Vec<Vec<usize>> = jobs.iter().map(|job| self.lease(job)).collect();
        for (running, held_on) in self.running.iter_mut().zip(held) {
            running.leased_on = held_on;
        }
    }
}

fn oldest_spec(queue: &Path) -> Option<PathBuf> {
    let mut specs: Vec<(std::time::SystemTime, PathBuf)> = fs::read_dir(queue)
        .ok()?
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|e| e == "json")
                .unwrap_or(false)
                && !entry.file_name().to_string_lossy().starts_with('.')
        })
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    specs.sort();
    specs.into_iter().next().map(|(_, path)| path)
}

fn move_dir(from: &Path, into: &Path) -> Result<(), AgentError> {
    fs::create_dir_all(into)?;
    let target = into.join(from.file_name().unwrap_or_default());
    fs::rename(from, &target).map_err(|e| {
        AgentError::Io(format!(
            "could not move {} to {}: {e}",
            from.display(),
            target.display()
        ))
    })
}

/// Count receipts already in `done/`, so a restarted agent reports its
/// history rather than zero.
fn count_done(done: &Path) -> (u64, u64) {
    let (mut completed, mut failed) = (0, 0);
    if let Ok(entries) = fs::read_dir(done) {
        for entry in entries.flatten() {
            let receipt = entry.path().join("receipt.json");
            let Ok(text) = fs::read_to_string(&receipt) else {
                continue;
            };
            match Value::from_json(&text)
                .ok()
                .and_then(|v| v.get("succeeded").and_then(Value::as_bool))
            {
                Some(true) => completed += 1,
                _ => failed += 1,
            }
        }
    }
    (completed, failed)
}

fn run_loop(args: &[String], out: &mut impl io::Write) -> Result<i32, AgentError> {
    let parsed = parse(
        args,
        &[
            "node", "name", "roles", "data-dir", "interval", "sandbox", "parallel",
        ],
        &["once"],
    )?;
    let nodes = nodes(&parsed)?;
    if nodes.is_empty() {
        return Err(AgentError::Invalid(format!(
            "no node to register with: pass --node http://host:port or set {NODES_ENV}"
        )));
    }
    let data = data_dir(&parsed);
    for sub in ["jobs/queue", "jobs/running", "jobs/done", "runsc"] {
        fs::create_dir_all(data.join(sub))
            .map_err(|e| AgentError::Io(format!("{}: {e}", data.join(sub).display())))?;
    }
    let interval = Duration::from_secs(
        parsed
            .u64("interval", Some(INTERVAL_ENV), DEFAULT_INTERVAL_SECONDS)?
            .max(5),
    );
    let parallel = parsed.u64("parallel", Some(PARALLEL_ENV), 1)?.max(1) as usize;
    let inventory = Inventory::probe();
    let sandboxes = Sandboxes::probe(&Names::from_env());
    let name = host_name(&parsed, &inventory);
    let roles = roles(&parsed)?;
    let preference = preference(&parsed)?;
    let (completed, failed) = count_done(&data.join("jobs/done"));
    let usable: Vec<&str> = [&sandboxes.kata, &sandboxes.runsc, &sandboxes.bwrap]
        .into_iter()
        .filter(|f| f.usable)
        .map(|f| f.kind.as_str())
        .collect();
    log::info!(
        "agent: {} as {:?} ({}), {} cpus, {} MiB, {} gpu(s); sandboxes: {}; data {}",
        super::CLIENT,
        name,
        roles.join(","),
        inventory.cpus.unwrap_or(0),
        inventory.memory_mb.unwrap_or(0),
        inventory.gpus.len(),
        if usable.is_empty() {
            "NONE (jobs will be refused unless they ask for `none`)".to_string()
        } else {
            usable.join(", ")
        },
        data.display()
    );
    // Any job left in `running/` by a previous process is not running now.
    if let Ok(entries) = fs::read_dir(data.join("jobs/running")) {
        for entry in entries.flatten() {
            log::warn!(
                "agent: {} was running when the last agent stopped; moved to done/ without a \
                 receipt",
                entry.file_name().to_string_lossy()
            );
            let _ = move_dir(&entry.path(), &data.join("jobs/done"));
        }
    }
    let mut state = Loop {
        node_ok: vec![true; nodes.len()],
        nodes,
        name,
        roles,
        data,
        interval,
        preference,
        parallel,
        inventory,
        sandboxes,
        running: Vec::new(),
        completed,
        failed,
    };
    let once = parsed.switch("once");
    let accepted = state.register();
    if once && accepted == 0 {
        return Err(AgentError::Node(
            "no node accepted the registration (see the warnings above)".into(),
        ));
    }
    let mut last_register = Instant::now();
    loop {
        state.reap();
        state.start_queued();
        if once && state.running.is_empty() && oldest_spec(&state.data.join("jobs/queue")).is_none()
        {
            state.register();
            writeln!(
                out,
                "registered with {} node(s); {} completed, {} failed",
                accepted, state.completed, state.failed
            )?;
            return Ok(if state.failed > failed { 1 } else { 0 });
        }
        if last_register.elapsed() >= state.interval {
            state.renew_leases();
            state.register();
            last_register = Instant::now();
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

// -- one-off commands --------------------------------------------------------------

fn exec(args: &[String], out: &mut impl io::Write) -> Result<i32, AgentError> {
    let parsed = parse(
        args,
        &[
            "image",
            "rootfs",
            "sandbox",
            "cpus",
            "memory",
            "gpus",
            "pids",
            "timeout",
            "env",
            "input",
            "cwd",
            "objective",
            "task",
            "data-dir",
            "id",
        ],
        &["network", "json"],
    )?;
    if parsed.trailing.is_empty() {
        return Err(AgentError::Invalid(
            "exec needs a command after `--`".into(),
        ));
    }
    let mut spec: Vec<(&str, Value)> = vec![(
        "argv",
        Value::array(parsed.trailing.iter().map(|a| Value::string(a.clone()))),
    )];
    let mut text = |key: &'static str, flag: &str| {
        if let Some(value) = parsed.one(flag) {
            spec.push((key, Value::string(value.to_string())));
        }
    };
    text("id", "id");
    text("image", "image");
    text("rootfs", "rootfs");
    text("cwd", "cwd");
    text("objective_id", "objective");
    text("task", "task");
    if let Some(value) = env_or(parsed.one("sandbox"), SANDBOX_ENV) {
        spec.push(("sandbox", Value::string(value)));
    }
    for (key, flag) in [
        ("cpus", "cpus"),
        ("memory_mb", "memory"),
        ("gpus", "gpus"),
        ("pids", "pids"),
        ("timeout_seconds", "timeout"),
    ] {
        if parsed.one(flag).is_some() {
            spec.push((key, Value::Int(i128::from(parsed.u64(flag, None, 0)?))));
        }
    }
    if parsed.switch("network") {
        spec.push(("network", Value::Bool(true)));
    }
    let env: BTreeMap<String, Value> = parsed
        .many("env")
        .iter()
        .map(|pair| {
            pair.split_once('=')
                .map(|(k, v)| (k.to_string(), Value::string(v.to_string())))
                .ok_or_else(|| AgentError::Invalid(format!("--env {pair:?} is not KEY=VALUE")))
        })
        .collect::<Result<_, _>>()?;
    if !env.is_empty() {
        spec.push(("env", Value::Object(env)));
    }
    let inputs: Vec<Value> = parsed
        .many("input")
        .iter()
        .map(|item| {
            let (source, target) = match item.split_once(':') {
                Some((s, t)) => (s, Some(t)),
                None => (item.as_str(), None),
            };
            let mut fields = vec![("source", Value::string(source.to_string()))];
            if let Some(target) = target {
                fields.push(("target", Value::string(target.to_string())));
            }
            Value::object(fields)
        })
        .collect();
    if !inputs.is_empty() {
        spec.push(("inputs", Value::Array(inputs)));
    }
    let fallback = format!("exec-{}", crate::time::unix_seconds());
    let job = Job::from_value(&Value::object(spec), &fallback)?;
    let data = data_dir(&parsed);
    let dir = data.join("jobs/done").join(&job.id);
    if dir.exists() {
        return Err(AgentError::Invalid(format!(
            "job {} already has a directory at {}; pass a new --id",
            job.id,
            dir.display()
        )));
    }
    fs::create_dir_all(&dir).map_err(|e| AgentError::Io(format!("{}: {e}", dir.display())))?;
    fs::create_dir_all(data.join("runsc"))?;
    fs::write(
        dir.join("job.json"),
        format!("{}\n", job.to_value().canonical_string()),
    )?;
    let inventory = Inventory::probe();
    let sandboxes = Sandboxes::probe(&Names::from_env());
    let receipt = job::run(&job, &sandboxes, &dir, &inventory.hostname);
    if parsed.switch("json") {
        writeln!(out, "{}", receipt.to_value().canonical_string())?;
    } else {
        writeln!(
            out,
            "job {}: {} under {} ({}){}{}; {} ms; receipt {}",
            receipt.job_id,
            receipt.lease_outcome(),
            receipt.sandbox.as_str(),
            receipt.via,
            match receipt.exit_status {
                Some(status) => format!("; exit {status}"),
                None => String::new(),
            },
            receipt
                .error
                .as_deref()
                .map(|e| format!("; {e}"))
                .unwrap_or_default(),
            receipt.wall_ms,
            dir.join("receipt.json").display()
        )?;
    }
    Ok(if receipt.succeeded() {
        0
    } else if receipt.error.is_some() {
        3
    } else {
        1
    })
}

fn submit(args: &[String], out: &mut impl io::Write) -> Result<i32, AgentError> {
    let parsed = parse(args, &["data-dir"], &[])?;
    let file = parsed
        .positional
        .first()
        .ok_or_else(|| AgentError::Invalid("submit needs a job file".into()))?;
    let job = Job::from_file(Path::new(file))?;
    let queue = data_dir(&parsed).join("jobs/queue");
    fs::create_dir_all(&queue).map_err(|e| AgentError::Io(format!("{}: {e}", queue.display())))?;
    let target = queue.join(format!("{}.json", job.id));
    if target.exists() {
        return Err(AgentError::Invalid(format!(
            "job {} is already queued at {}",
            job.id,
            target.display()
        )));
    }
    // Written from the decoded job rather than copied: what the loop reads
    // is exactly what was validated here, with the id filled in.
    fs::write(&target, format!("{}\n", job.to_value().canonical_string()))?;
    writeln!(out, "queued job {} at {}", job.id, target.display())?;
    Ok(0)
}

fn jobs(args: &[String], out: &mut impl io::Write) -> Result<i32, AgentError> {
    let parsed = parse(args, &["data-dir"], &["json"])?;
    let data = data_dir(&parsed);
    let list = |sub: &str| -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(data.join(sub))
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    };
    let queued: Vec<String> = list("jobs/queue")
        .into_iter()
        .filter_map(|n| n.strip_suffix(".json").map(str::to_string))
        .collect();
    let running = list("jobs/running");
    let done: Vec<(String, Option<Value>)> = list("jobs/done")
        .into_iter()
        .map(|name| {
            let receipt =
                fs::read_to_string(data.join("jobs/done").join(&name).join("receipt.json"))
                    .ok()
                    .and_then(|t| Value::from_json(&t).ok());
            (name, receipt)
        })
        .collect();
    if parsed.switch("json") {
        let value = Value::object([
            ("data", Value::string(data.display().to_string())),
            (
                "queued",
                Value::array(queued.into_iter().map(Value::string)),
            ),
            (
                "running",
                Value::array(running.into_iter().map(Value::string)),
            ),
            (
                "done",
                Value::array(done.into_iter().map(|(name, receipt)| {
                    Value::object([
                        ("id", Value::string(name)),
                        ("receipt", receipt.unwrap_or(Value::Null)),
                    ])
                })),
            ),
        ]);
        writeln!(out, "{}", value.canonical_string())?;
        return Ok(0);
    }
    writeln!(out, "jobs under {}", data.display())?;
    writeln!(out, "  queued ({}): {}", queued.len(), queued.join(" "))?;
    writeln!(out, "  running ({}): {}", running.len(), running.join(" "))?;
    writeln!(out, "  done ({}):", done.len())?;
    for (name, receipt) in done {
        match receipt {
            Some(receipt) => writeln!(
                out,
                "    {name}: {} under {} exit {} in {} ms",
                if receipt.get("succeeded") == Some(&Value::Bool(true)) {
                    "completed"
                } else {
                    "failed"
                },
                receipt
                    .get("sandbox")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                receipt
                    .get("exit_status")
                    .and_then(Value::as_i128)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".into()),
                receipt.get("wall_ms").and_then(Value::as_i128).unwrap_or(0)
            )?,
            None => writeln!(out, "    {name}: no receipt")?,
        }
    }
    Ok(0)
}

fn install(args: &[String], out: &mut impl io::Write) -> Result<i32, AgentError> {
    let parsed = parse(
        args,
        &[
            "node", "name", "roles", "user", "data-dir", "sandbox", "interval", "parallel",
        ],
        &["print", "no-start"],
    )?;
    let nodes = nodes(&parsed)?;
    if nodes.is_empty() {
        return Err(AgentError::Invalid(format!(
            "install needs at least one --node http://host:port (or {NODES_ENV})"
        )));
    }
    let inventory = Inventory::probe();
    let name = host_name(&parsed, &inventory);
    let roles = roles(&parsed)?;
    let preference = preference(&parsed)?;
    let interval = parsed.u64("interval", Some(INTERVAL_ENV), DEFAULT_INTERVAL_SECONDS)?;
    let parallel = parsed.u64("parallel", Some(PARALLEL_ENV), 1)?.max(1);
    let data_dir = data_dir(&parsed);
    let user = parsed
        .one("user")
        .map(str::to_string)
        .unwrap_or_else(|| service::DEFAULT_USER.to_string());
    let exec = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| AgentError::Io(format!("where is this binary: {e}")))?;
    let mut env = vec![
        (
            NODES_ENV.to_string(),
            nodes
                .iter()
                .map(|n| n.as_str().to_string())
                .collect::<Vec<_>>()
                .join(","),
        ),
        (NAME_ENV.to_string(), name),
        (ROLES_ENV.to_string(), roles.join(",")),
        (DATA_ENV.to_string(), data_dir.display().to_string()),
        (SANDBOX_ENV.to_string(), preference.as_str().to_string()),
        (INTERVAL_ENV.to_string(), interval.to_string()),
        (PARALLEL_ENV.to_string(), parallel.to_string()),
        ("CAIRN_LOG_LEVEL".to_string(), "info".to_string()),
    ];
    for passthrough in [
        super::sandbox::KATA_RUNTIME_ENV,
        super::sandbox::RUNSC_RUNTIME_ENV,
        super::sandbox::ENGINE_ENV,
    ] {
        if let Ok(value) = std::env::var(passthrough) {
            if !value.trim().is_empty() {
                env.push((passthrough.to_string(), value));
            }
        }
    }
    let groups =
        service::supplementary_groups(&fs::read_to_string("/etc/group").unwrap_or_default());
    let plan = Install {
        exec,
        user,
        data_dir: data_dir.clone(),
        env,
        groups,
    };
    if parsed.switch("print") {
        writeln!(out, "# {}\n{}", service::UNIT_PATH, plan.unit())?;
        writeln!(out, "# {}\n{}", service::ENV_FILE, plan.env_file())?;
        return Ok(0);
    }
    let done = service::install(&plan, !parsed.switch("no-start"))?;
    for line in done {
        writeln!(out, "{line}")?;
    }
    writeln!(
        out,
        "follow it with: journalctl -u {} -f ; queue a job with: cairn agent submit JOB.json \
         --data-dir {}",
        service::UNIT_NAME,
        data_dir.display()
    )?;
    Ok(0)
}

fn uninstall(args: &[String], out: &mut impl io::Write) -> Result<i32, AgentError> {
    let parsed = parse(args, &["data-dir"], &["purge"])?;
    let done = service::uninstall(&data_dir(&parsed), parsed.switch("purge"))?;
    for line in done {
        writeln!(out, "{line}")?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_parse_with_values_switches_and_a_trailing_command() {
        let args: Vec<String> = [
            "--node",
            "http://a:1",
            "--node=http://b:2",
            "--json",
            "pos",
            "--",
            "sh",
            "-c",
            "--x",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = parse(&args, &["node"], &["json"]).unwrap();
        assert_eq!(parsed.many("node"), ["http://a:1", "http://b:2"]);
        assert!(parsed.switch("json"));
        assert_eq!(parsed.positional, ["pos"]);
        assert_eq!(parsed.trailing, ["sh", "-c", "--x"]);
        assert!(parse(&["--wat".to_string()], &[], &[]).is_err());
        assert!(parse(&["--node".to_string()], &["node"], &[]).is_err());
    }

    #[test]
    fn help_and_unknown_commands_behave() {
        let mut out = Vec::new();
        assert_eq!(run(vec!["help".into()], &mut out).unwrap(), 0);
        assert!(String::from_utf8(out).unwrap().contains("cairn agent"));
        assert!(matches!(
            run(vec!["frobnicate".into()], &mut Vec::new()),
            Err(AgentError::Invalid(_))
        ));
        assert!(matches!(
            run(vec!["run".into()], &mut Vec::new()),
            Err(AgentError::Invalid(message)) if message.contains("--node")
        ));
    }

    #[test]
    fn roles_are_checked_against_the_networks_vocabulary() {
        let parsed = parse(
            &["--roles".to_string(), "Executor, verifier".to_string()],
            &["roles"],
            &[],
        )
        .unwrap();
        assert_eq!(roles(&parsed).unwrap(), ["executor", "verifier"]);
        let parsed = parse(
            &["--roles".to_string(), "boss".to_string()],
            &["roles"],
            &[],
        )
        .unwrap();
        assert!(roles(&parsed).is_err());
    }

    #[test]
    fn the_queue_hands_out_the_oldest_spec_and_done_is_counted() {
        let dir = std::env::temp_dir().join(format!("cairn-agent-queue-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("queue")).unwrap();
        fs::create_dir_all(dir.join("done/a")).unwrap();
        fs::create_dir_all(dir.join("done/b")).unwrap();
        fs::write(dir.join("done/a/receipt.json"), r#"{"succeeded":true}"#).unwrap();
        fs::write(dir.join("done/b/receipt.json"), r#"{"succeeded":false}"#).unwrap();
        assert_eq!(count_done(&dir.join("done")), (1, 1));
        assert_eq!(oldest_spec(&dir.join("queue")), None);
        fs::write(dir.join("queue/.hidden.json"), "{}").unwrap();
        fs::write(dir.join("queue/notes.txt"), "x").unwrap();
        fs::write(dir.join("queue/first.json"), "{}").unwrap();
        assert_eq!(
            oldest_spec(&dir.join("queue")),
            Some(dir.join("queue/first.json"))
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
