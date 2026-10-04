//! What a node *is* on the network: the roles it declares, the hardware it
//! runs on, and the roles the log shows identities actually playing.
//!
//! Behind `GET /network`, which is the one route the reader's Network page
//! reads. Three facts live here and each has a different trust story, which
//! is why the payload keeps them in three fields rather than one list:
//!
//! - **Declared roles** ([`Roles`], from `CAIRN_ROLES`) are what the operator
//!   *says* this node is for. A routing hint, exactly as a worker's
//!   capability advertisement in `src/compute.rs` is: never evidence, never checked
//!   by any rule, and the page labels them as declared.
//! - **Hardware** ([`Hardware`]) is what this process can see of its own
//!   machine, probed once at startup. The node does not use a GPU and macOS
//!   offers no way to cap one, so there is no GPU field here; a *worker's*
//!   hardware arrives in its heartbeats and is summed on the compute side of
//!   the same route.
//! - **Evidenced roles** ([`evidenced`]) are derived from the log: who funded
//!   objectives, who had claims accepted, who stood behind verdicts under
//!   bond. Anyone with the log recomputes them, and that is the only sense in
//!   which the network has coordinators, executors and verifiers today --
//!   as things identities *did*, not titles they hold.
//!
//! # Why roles are a hint and not a permission
//!
//! The research program this network grew out of has a coordinator that alone
//! may change official state, executors that alone may run experiments, and
//! validators independent of both (`orchestration/roles.yaml` in
//! `crypto-autoresearcher`). Those are authority boundaries enforced by a
//! harness that controls every tool call. A network of strangers has no such
//! harness: the only authority here is the pinned verifier's verdict, and the
//! one thing a role must never become is a second one. A node declaring
//! `coordinator` gets no say over what settles; a node declaring `verifier`
//! is believed exactly as far as the bond behind each of its attestations.
//! What a declaration buys is *legibility* -- a reader sees what the operator
//! intends the node for and can check it against what the node can do
//! ([`Roles::warnings`]) and what the log shows it doing ([`evidenced`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::canonical::Value;
use crate::node::Node;

/// Comma-separated roles this node declares.
pub const ROLES_ENV: &str = "CAIRN_ROLES";

/// What a node can declare itself for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Posts and funds objectives, divides them into piecework, accepts
    /// submissions, hands out work assignments and keeps the lease roster
    /// its workers coordinate through.
    Coordinator,
    /// Runs workers: takes assignments, posts heartbeats and leases, submits
    /// claims. The workers themselves are separate processes; the node is
    /// where they report.
    Executor,
    /// Runs pinned verifiers and stands behind verdicts under bond
    /// (`cairn attest stand`), so that a wrong verdict has somebody to slash.
    Verifier,
    /// Holds and serves the log and reconciles with peers, and does nothing
    /// else. Most nodes are this whether they say so or not.
    Relay,
}

impl Role {
    pub const ALL: [Role; 4] = [
        Role::Coordinator,
        Role::Executor,
        Role::Verifier,
        Role::Relay,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Coordinator => "coordinator",
            Role::Executor => "executor",
            Role::Verifier => "verifier",
            Role::Relay => "relay",
        }
    }

    pub fn parse(text: &str) -> Option<Role> {
        Some(match text.trim().to_ascii_lowercase().as_str() {
            "coordinator" => Role::Coordinator,
            "executor" => Role::Executor,
            "verifier" => Role::Verifier,
            "relay" => Role::Relay,
            _ => return None,
        })
    }

    /// One sentence for a reader: what a node in this role does.
    pub fn duty(self) -> &'static str {
        match self {
            Role::Coordinator => {
                "posts and funds objectives, accepts submissions, hands out work \
                 assignments and keeps the lease roster workers coordinate through"
            }
            Role::Executor => {
                "runs workers that take assignments, heartbeat, lease tasks and submit \
                 claims to this node"
            }
            Role::Verifier => {
                "runs pinned verifiers and stands behind verdicts under bond, so a wrong \
                 verdict has somebody answerable"
            }
            Role::Relay => "holds and serves the log and reconciles it with peers",
        }
    }

    /// Where in the log a reader would see this role being played.
    pub fn evidence(self) -> &'static str {
        match self {
            Role::Coordinator => "objectives funded, under `funder`",
            Role::Executor => "claims accepted, under `submitter`",
            Role::Verifier => "attestations posted, under `attestor`",
            Role::Relay => "nothing in the log; sessions on GET /sessions",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolesError {
    pub unknown: String,
}

impl fmt::Display for RolesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{ROLES_ENV} names an unknown role {:?}; the roles are {}",
            self.unknown,
            Role::ALL
                .iter()
                .map(|role| role.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for RolesError {}

/// The roles a node declares, deduplicated and ordered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roles(BTreeSet<Role>);

impl Roles {
    /// Parse `coordinator,executor`. Empty text declares nothing, which is
    /// what an undeclared node is; an unknown name is refused rather than
    /// skipped, because a node that quietly dropped `verifer` would look
    /// exactly like one that was never meant to verify.
    pub fn parse(text: &str) -> Result<Roles, RolesError> {
        let mut roles = BTreeSet::new();
        for part in text.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match Role::parse(part) {
                Some(role) => {
                    roles.insert(role);
                }
                None => {
                    return Err(RolesError {
                        unknown: part.to_string(),
                    })
                }
            }
        }
        Ok(Roles(roles))
    }

    /// From [`ROLES_ENV`]. Unset declares nothing.
    pub fn from_env() -> Result<Roles, RolesError> {
        match std::env::var(ROLES_ENV) {
            Ok(text) => Roles::parse(&text),
            Err(_) => Ok(Roles::default()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, role: Role) -> bool {
        self.0.contains(&role)
    }

    pub fn iter(&self) -> impl Iterator<Item = Role> + '_ {
        self.0.iter().copied()
    }

    /// Declarations the node's own configuration contradicts. Not refusals:
    /// an operator may well declare a role before finishing the setup for
    /// it, and the page is where they find out what is missing.
    pub fn warnings(&self, facts: &NodeFacts) -> Vec<String> {
        let mut out = Vec::new();
        if self.contains(Role::Coordinator) && !facts.accepts_submissions {
            out.push(
                "declares coordinator but accepts no submissions (started without --queue): \
                 workers can heartbeat and lease here, and must submit claims elsewhere"
                    .to_string(),
            );
        }
        if self.contains(Role::Verifier) && facts.servable_kinds.is_empty() {
            out.push(
                "declares verifier but can serve no verifier kind on this host; GET /verifiers \
                 says why for each"
                    .to_string(),
            );
        }
        if self.contains(Role::Relay) && !facts.runs_p2p {
            out.push(
                "declares relay but this process runs no p2p service (a plain `cairn serve`); \
                 it publishes a log it does not reconcile"
                    .to_string(),
            );
        }
        out
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            (
                "declared",
                Value::array(self.iter().map(|role| Value::string(role.as_str()))),
            ),
            ("source", Value::string(ROLES_ENV)),
            (
                "known",
                Value::array(Role::ALL.iter().map(|role| {
                    Value::object([
                        ("role", Value::string(role.as_str())),
                        ("duty", Value::string(role.duty())),
                        ("evidence", Value::string(role.evidence())),
                    ])
                })),
            ),
        ])
    }
}

/// What the serving process knows about itself, for [`Roles::warnings`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeFacts {
    pub accepts_submissions: bool,
    pub runs_p2p: bool,
    pub servable_kinds: Vec<String>,
}

/// This machine, as the process sees it. Probed once; nothing here changes
/// while the process runs, and a request handler should not be reading
/// `/proc` or spawning `sysctl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardware {
    /// Logical CPUs the process may use, from the scheduler's point of view
    /// (an affinity mask or a cgroup quota lowers it below the socket count).
    pub cpus: Option<u64>,
    pub memory_mb: Option<u64>,
    pub os: &'static str,
    pub arch: &'static str,
    /// What the operator lets one verifier's process tree keep busy.
    pub verifier_cpus: Option<u64>,
    /// What the operator lets one verifier's process tree hold.
    pub verifier_memory_mb: Option<u64>,
}

impl Hardware {
    pub fn probe() -> Hardware {
        Hardware {
            cpus: std::thread::available_parallelism()
                .ok()
                .map(|n| n.get() as u64),
            memory_mb: total_memory_mb(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            verifier_cpus: env_u64(crate::verifiers::limits::CPUS_ENV),
            verifier_memory_mb: env_u64(crate::verifiers::sandbox::MEMORY_ENV),
        }
    }

    pub fn to_value(&self) -> Value {
        let opt = |value: Option<u64>| match value {
            Some(n) => Value::Int(i128::from(n)),
            None => Value::Null,
        };
        Value::object([
            ("cpus", opt(self.cpus)),
            ("memory_mb", opt(self.memory_mb)),
            ("os", Value::string(self.os)),
            ("arch", Value::string(self.arch)),
            (
                "verifier_limits",
                Value::object([
                    ("cpus", opt(self.verifier_cpus)),
                    ("memory_mb", opt(self.verifier_memory_mb)),
                ]),
            ),
            (
                "note",
                Value::string(
                    "This process's own machine, probed at startup. The node runs verifiers \
                     on it and nothing else; a worker's hardware is what the worker reports \
                     in its heartbeats, under `compute`.",
                ),
            ),
        ])
    }
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
}

/// Total physical memory, in MiB, where the platform says so cheaply.
///
/// Linux: `/proc/meminfo`. macOS: `sysctl -n hw.memsize`, one process spawn
/// at startup. Anywhere else: unknown, reported as `null` rather than
/// guessed -- a wrong number here would be the kind a reader multiplies.
#[cfg(target_os = "linux")]
fn total_memory_mb() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_mb(&text)
}

#[cfg(target_os = "macos")]
fn total_memory_mb() -> Option<u64> {
    let output = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    let bytes: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()?;
    Some(bytes / (1024 * 1024))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn total_memory_mb() -> Option<u64> {
    None
}

/// `MemTotal:       16314372 kB` -> 15932.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_meminfo_mb(text: &str) -> Option<u64> {
    let line = text.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

/// Identities the log shows playing each role, with how much of it.
///
/// Recomputed from the log on every request, like everything under
/// `derived` on `GET /progress/{id}`: a funder is somebody who funded, a
/// submitter somebody whose claim was accepted, an attestor somebody who
/// stood behind a verdict. Relays leave nothing in the log and are not here.
pub fn evidenced(node: &Node) -> Value {
    let mut coordinators: BTreeMap<String, (u64, u128, u64)> = BTreeMap::new();
    for objective in node.objectives().values() {
        let entry = coordinators.entry(objective.funder.clone()).or_default();
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(u128::from(objective.reward));
        if objective.piecework.is_some() {
            entry.2 += 1;
        }
    }
    let mut executors: BTreeMap<String, (u64, BTreeSet<String>)> = BTreeMap::new();
    for claim in node.accepted_claims().values() {
        let entry = executors.entry(claim.submitter.clone()).or_default();
        entry.0 += 1;
        entry.1.insert(claim.objective_id.clone());
    }
    let slashed = node.slashed_attestations();
    let mut verifiers: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for (id, attestation) in node.attestations() {
        let entry = verifiers.entry(attestation.attestor.clone()).or_default();
        entry.0 += 1;
        if slashed.contains(&id) {
            entry.1 += 1;
        }
    }

    let mut coordinator_rows: Vec<Value> = coordinators
        .into_iter()
        .map(|(funder, (objectives, reward, piecework))| {
            Value::object([
                ("identity", Value::string(funder)),
                ("objectives", Value::Int(i128::from(objectives))),
                ("reward_total", Value::Int(reward as i128)),
                ("piecework", Value::Int(i128::from(piecework))),
            ])
        })
        .collect();
    coordinator_rows.sort_by_key(|row| {
        std::cmp::Reverse(row.get("objectives").and_then(Value::as_i128).unwrap_or(0))
    });
    let mut executor_rows: Vec<Value> = executors
        .into_iter()
        .map(|(submitter, (claims, objectives))| {
            Value::object([
                ("identity", Value::string(submitter)),
                ("accepted_claims", Value::Int(i128::from(claims))),
                ("objectives", Value::Int(objectives.len() as i128)),
            ])
        })
        .collect();
    executor_rows.sort_by_key(|row| {
        std::cmp::Reverse(
            row.get("accepted_claims")
                .and_then(Value::as_i128)
                .unwrap_or(0),
        )
    });
    let mut verifier_rows: Vec<Value> = verifiers
        .into_iter()
        .map(|(attestor, (attestations, slashed))| {
            Value::object([
                ("identity", Value::string(attestor)),
                ("attestations", Value::Int(i128::from(attestations))),
                ("slashed", Value::Int(i128::from(slashed))),
            ])
        })
        .collect();
    verifier_rows.sort_by_key(|row| {
        std::cmp::Reverse(
            row.get("attestations")
                .and_then(Value::as_i128)
                .unwrap_or(0),
        )
    });

    Value::object([
        ("coordinators", capped(coordinator_rows)),
        ("executors", capped(executor_rows)),
        ("verifiers", capped(verifier_rows)),
        (
            "note",
            Value::string(
                "Recomputed from this node's log: funders of objectives, submitters of \
                 accepted claims, attestors of verdicts. Roles here are what identities did, \
                 not titles they hold; a node's declared roles are under `node.roles` and are \
                 a hint.",
            ),
        ),
    ])
}

/// At most this many identities per evidenced role, with the rest counted.
/// A log with ten thousand submitters is a fact worth one number, not a
/// ten-thousand-row payload on a page that wanted a summary.
const MAX_EVIDENCED_ROWS: usize = 64;

fn capped(mut rows: Vec<Value>) -> Value {
    let total = rows.len();
    rows.truncate(MAX_EVIDENCED_ROWS);
    Value::object([
        ("total", Value::Int(total as i128)),
        ("shown", Value::Int(rows.len() as i128)),
        ("identities", Value::Array(rows)),
    ])
}

/// Where this node's HTTP side can be reached from, for `GET /network`.
///
/// The page that tells somebody how to add a second machine needs an address
/// that machine can dial, and the node is the only party that knows what it
/// bound. Three answers, and the reader shows each differently:
///
/// - bound to loopback: nothing on the LAN can reach it, and the page says
///   how to change that instead of printing a URL that will not connect;
/// - bound to a specific address: that address;
/// - bound to `0.0.0.0` / `::`: every address this host has on a local
///   network, from [`local_addresses`].
///
/// Advice to a reader, like everything else under `node`: nothing that
/// settles reads it.
pub fn reach(bound: Option<std::net::SocketAddr>) -> Value {
    let Some(bound) = bound else {
        return Value::object([("bound", Value::Null), ("lan", Value::Bool(false))]);
    };
    let ip = bound.ip();
    let addresses: Vec<std::net::IpAddr> = if ip.is_loopback() {
        Vec::new()
    } else if ip.is_unspecified() {
        local_addresses()
    } else {
        vec![ip]
    };
    let urls = addresses.iter().map(|address| {
        Value::string(match address {
            std::net::IpAddr::V4(v4) => format!("http://{v4}:{}", bound.port()),
            std::net::IpAddr::V6(v6) => format!("http://[{v6}]:{}", bound.port()),
        })
    });
    Value::object([
        ("bound", Value::string(bound.to_string())),
        ("lan", Value::Bool(!ip.is_loopback())),
        ("urls", Value::array(urls)),
    ])
}

/// This host's addresses on its local networks, best first, without asking
/// the operating system for its interface list.
///
/// A UDP `connect` sends nothing; it only asks the kernel which source
/// address it would route from. Asking once toward each private range and
/// once toward a documentation address therefore names the interface each
/// would use -- the LAN one on a home network, the right one of several on a
/// multi-homed box -- with no packet leaving and no `getifaddrs` binding to
/// write. A host with no route to a range simply contributes nothing for it,
/// which is how this still answers on a LAN with no internet at all.
pub fn local_addresses() -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};
    const PROBES: [Ipv4Addr; 4] = [
        Ipv4Addr::new(192, 0, 2, 1), // TEST-NET-1: the default route, if any
        Ipv4Addr::new(192, 168, 255, 254), // the home-router ranges
        Ipv4Addr::new(10, 255, 255, 254),
        Ipv4Addr::new(172, 31, 255, 254),
    ];
    let mut found: Vec<IpAddr> = Vec::new();
    for probe in PROBES {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        if socket.connect((probe, 9)).is_err() {
            continue;
        }
        if let Ok(local) = socket.local_addr() {
            let ip = local.ip();
            let usable = match ip {
                IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified() && !v4.is_link_local(),
                IpAddr::V6(_) => false,
            };
            if usable && !found.contains(&ip) {
                found.push(ip);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_loopback_bind_offers_no_lan_url() {
        let value = reach(Some("127.0.0.1:8080".parse().unwrap()));
        assert_eq!(value.get("lan").and_then(Value::as_bool), Some(false));
        assert_eq!(
            value
                .get("urls")
                .and_then(Value::as_array)
                .map(<[Value]>::len),
            Some(0)
        );
    }

    #[test]
    fn a_specific_bind_is_its_own_url() {
        let value = reach(Some("192.168.7.9:8081".parse().unwrap()));
        assert_eq!(value.get("lan").and_then(Value::as_bool), Some(true));
        let urls = value.get("urls").and_then(Value::as_array).unwrap();
        assert_eq!(urls[0].as_str(), Some("http://192.168.7.9:8081"));
    }

    #[test]
    fn local_addresses_never_include_loopback_or_unspecified() {
        for ip in local_addresses() {
            assert!(!ip.is_loopback() && !ip.is_unspecified(), "{ip}");
        }
    }

    use super::*;

    #[test]
    fn roles_parse_deduplicate_and_refuse_strangers() {
        let roles = Roles::parse(" verifier, Coordinator ,verifier,").expect("parses");
        assert_eq!(
            roles.iter().collect::<Vec<_>>(),
            vec![Role::Coordinator, Role::Verifier]
        );
        assert!(Roles::parse("").expect("empty is none").is_empty());
        let error = Roles::parse("coordinator,verifer").unwrap_err();
        assert_eq!(error.unknown, "verifer");
        assert!(error
            .to_string()
            .contains("coordinator, executor, verifier, relay"));
    }

    #[test]
    fn warnings_name_what_the_configuration_contradicts() {
        let roles = Roles::parse("coordinator,verifier,relay,executor").unwrap();
        let bare = NodeFacts::default();
        let warnings = roles.warnings(&bare);
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(warnings[0].contains("coordinator"));
        assert!(warnings[1].contains("verifier"));
        assert!(warnings[2].contains("relay"));

        let equipped = NodeFacts {
            accepts_submissions: true,
            runs_p2p: true,
            servable_kinds: vec!["certificate".into()],
        };
        assert!(roles.warnings(&equipped).is_empty());
    }

    #[test]
    fn meminfo_is_read_in_mib() {
        let text = "MemTotal:       16314372 kB\nMemFree:         1234 kB\n";
        assert_eq!(parse_meminfo_mb(text), Some(15932));
        assert_eq!(parse_meminfo_mb("nothing here"), None);
    }

    #[test]
    fn the_probe_knows_at_least_the_platform() {
        let hardware = Hardware::probe();
        assert!(!hardware.os.is_empty() && !hardware.arch.is_empty());
        let value = hardware.to_value();
        assert!(value.get("cpus").is_some());
        assert!(value.get("verifier_limits").is_some());
    }

    #[test]
    fn every_role_has_a_duty_and_a_place_to_look() {
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
            assert!(!role.duty().is_empty());
            assert!(!role.evidence().is_empty());
        }
    }
}
