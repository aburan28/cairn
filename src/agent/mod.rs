//! `cairn agent`: the host-side agent that puts a Linux machine on the
//! network as a place executor jobs can run.
//!
//! A *node* (`cairn run`, `cairn p2p --serve`) holds the log and runs pinned
//! verifiers. A *worker* (`orbit_worker.py`, the GPU client in
//! `aburan28/crypto`) walks a search and submits claims. This is the third
//! thing, the one the research program's executors need and nothing here
//! provided: a long-running process on a box with hardware, installed once
//! under systemd, that
//!
//! 1. **probes** what the machine is -- CPUs, memory, NUMA, every GPU, and
//!    which sandboxes can run untrusted code here ([`probe`], [`sandbox`]);
//! 2. **registers** that with one or more nodes over `POST /hosts`, every
//!    interval, so the network's readers can see the capacity before any
//!    objective is worked ([`crate::hosts`] is the node's half);
//! 3. **runs jobs** dropped into its spool, each inside gVisor or Kata
//!    Containers (or bubblewrap, where that is all there is), with the
//!    resources the job asked for and a receipt saying exactly which jail
//!    held it ([`job`]); while a job runs for an objective, the agent leases
//!    the task on the node so the roster shows it.
//!
//! # What it deliberately is not
//!
//! **Not a dispatcher.** Nothing on the network pushes work to an agent.
//! `docs/coordination.md` says why a dispatcher is a wound, and this module
//! does not inflict one: a job arrives as a file in the agent's spool,
//! written by whatever the operator trusts to write there -- the research
//! program's own dispatcher, a cron job, a hand. The node sees the job only
//! as an advisory lease and a line in a registration, which is advice to
//! readers and permission to nobody.
//!
//! **Not a verifier.** A job's output proves nothing. If it is a candidate,
//! something still submits it and the objective's pinned verifier still
//! grades it. A receipt here says what ran, where, under which jail, with
//! what exit status; it is a fact about this host and never a fact about a
//! result.
//!
//! **Not trusted by the node.** A registration is held in the node's memory
//! like a heartbeat, bounded, unverified, and forgotten. See
//! [`crate::hosts`].
//!
//! # Why gVisor and Kata, and why both
//!
//! An executor job is code the operator did not write, by definition, and
//! the node's bubblewrap jail is namespaces over the host kernel: every
//! syscall the job makes reaches the kernel the agent runs on. gVisor puts a
//! user-space kernel in between; Kata puts a hardware-virtualised one. Kata
//! is the stronger boundary and the one a GPU job usually needs (VFIO
//! passthrough), and it needs a container engine and a hypervisor to exist;
//! gVisor runs from one static binary over a directory and is what a box
//! without `/dev/kvm` can offer. The agent probes both, prefers Kata when a
//! job asks for the strongest jail, gVisor by default, and says in every
//! receipt which one it got -- so a reader comparing results across hosts
//! can see when two differ in how far their job was from the metal.

pub mod cli;
pub mod http;
pub mod job;
pub mod probe;
pub mod sandbox;
pub mod service;
pub mod work;

use std::fmt;

/// What the agent calls itself in registrations and leases.
pub const CLIENT: &str = concat!("cairn-agent/", env!("CARGO_PKG_VERSION"));

/// Where the agent keeps its spool, receipts and state. Overridden by
/// `--data-dir` or [`DATA_ENV`].
pub const DEFAULT_DATA_DIR: &str = "/var/lib/cairn-agent";
pub const DATA_ENV: &str = "CAIRN_AGENT_DATA";

/// Seconds between registrations. Under the node's live threshold
/// (`progress::LIVE_SECONDS`, 180 s) with two misses to spare, the same
/// margin the worker heartbeat keeps.
pub const DEFAULT_INTERVAL_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// Bad input: a flag, a job spec, a URL.
    Invalid(String),
    /// The host cannot do what was asked: no sandbox, no engine, no systemd.
    Unavailable(String),
    /// A node could not be reached or answered something other than success.
    Node(String),
    Io(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Invalid(m) => write!(f, "invalid: {m}"),
            AgentError::Unavailable(m) => write!(f, "unavailable on this host: {m}"),
            AgentError::Node(m) => write!(f, "node: {m}"),
            AgentError::Io(m) => write!(f, "i/o: {m}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<std::io::Error> for AgentError {
    fn from(error: std::io::Error) -> AgentError {
        AgentError::Io(error.to_string())
    }
}
