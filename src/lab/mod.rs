//! The lab: a replicated research workspace, as an op-based CRDT.
//!
//! The ledger settles results; the lab is where the work that produces them is
//! kept while it happens — records, protocols, run outputs, reviews, leases on
//! tasks, and messages between the agents doing it. `docs/lab.md` is the
//! design. The short version:
//!
//! - A **space** is a set of signed [`op::Op`]s. Merging two replicas is set
//!   union, and every view ([`state::State`]) is a deterministic function of
//!   the set, so replicas that hold the same ops agree with no coordination.
//! - Ops are **causally closed** ([`store::Lab::ingest`] refuses an op whose
//!   dependencies it does not hold), which makes `(lamport, id)` a total order
//!   that respects causality and is the same everywhere.
//! - Files and doc fields are **multi-value registers**: concurrent writes stay
//!   visible as siblings until somebody resolves them, so a conflict is never
//!   silently lost and never a textual merge.
//! - Every op is **authorised by its causal past**: its author held the role it
//!   needed in the membership the op could see.
//! - [`mod@env`] and [`exec`] run commands in content-addressed root filesystems
//!   under gVisor (or bubblewrap), and record the receipt and the outputs as
//!   one op.
//!
//! # What the lab is not allowed to touch
//!
//! Nothing here reads or writes the ledger, mints, settles or moves the
//! frontier. The lab is a workspace; the ledger is the settlement layer, and a
//! lab result reaches it only the ordinary way — as an objective or a claim a
//! pinned verifier checks. That boundary is why the lab can be multi-writer
//! and eventually consistent at all.

pub mod api;
pub mod cli;
pub mod env;
pub mod exec;
pub mod glob;
pub mod mcp;
pub mod op;
pub mod state;
pub mod store;
pub mod sync;
pub mod tree;

use std::fmt;

/// Every way a lab operation can fail.
///
/// `Refused` is the one to read carefully: it means the lab understood the
/// request and declined it on the rules — an unauthorised author, a write to an
/// immutable path, an op whose dependencies are missing. It is never used for
/// an infrastructure failure, which is `Io`, or for a host that lacks what the
/// request needs, which is `Unavailable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabError {
    /// The filesystem or a subprocess failed.
    Io(String),
    /// An op or a request could not be parsed or does not verify.
    Invalid(String),
    /// The request was understood and the rules decline it.
    Refused(String),
    /// Something named does not exist here.
    NotFound(String),
    /// The store on disk is not one this implementation wrote, or was damaged.
    Corrupt(String),
    /// This host cannot do what was asked: no sandbox works here, say. A fact
    /// about the machine, never about the request or the program — the
    /// verifiers' `Unavailable` — and kept apart from `Io` so a caller can say
    /// "nothing was learned" instead of "it failed".
    Unavailable(String),
}

impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabError::Io(m) => write!(f, "i/o: {m}"),
            LabError::Invalid(m) => write!(f, "invalid: {m}"),
            LabError::Refused(m) => write!(f, "refused: {m}"),
            LabError::NotFound(m) => write!(f, "not found: {m}"),
            LabError::Corrupt(m) => write!(f, "corrupt store: {m}"),
            LabError::Unavailable(m) => write!(f, "unavailable on this host: {m}"),
        }
    }
}

impl std::error::Error for LabError {}

impl From<std::io::Error> for LabError {
    fn from(error: std::io::Error) -> LabError {
        LabError::Io(error.to_string())
    }
}

impl From<op::OpError> for LabError {
    fn from(error: op::OpError) -> LabError {
        LabError::Invalid(error.0)
    }
}

/// The directory a lab lives in when nothing names one: `./.cairn-lab`, or
/// `$CAIRN_LAB`.
pub const DEFAULT_DIR: &str = ".cairn-lab";

/// Environment variable naming the lab directory.
pub const LAB_ENV: &str = "CAIRN_LAB";
