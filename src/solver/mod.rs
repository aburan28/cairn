//! Solver packages: the program an objective's author publishes so that
//! anyone can work on it by pressing one button.
//!
//! Until this existed, contributing compute meant finding a search program on
//! disk and pointing `cairn work` at it. That asked the one person least able
//! to judge a program — somebody who just wants to help — to choose and trust
//! one, and it ran whatever they chose with their whole account: no jail, the
//! operator's environment, no timeout. The only objective a contributor could
//! join without choosing anything was the one the app had hard-wired by digest.
//!
//! A **solver package** is a directory with a `solver.json` manifest naming
//! every file in it by SHA-256. The digest of the canonical manifest is the
//! package's id, so one hash pins the program, its data, its arguments and its
//! tests, exactly as `checker_sha256` pins a checker. An objective pins its
//! package in the place verifiers already ignore,
//!
//! ```json
//! "verifier": { "kind": "certificate", …,
//!   "capabilities": { "worker": { "mode": "package", "package": "sha256:…" } } }
//! ```
//!
//! which keeps it inside the objective's id and funding signature without a
//! new record field ([`crate::scheduling`]). A package written later for an
//! objective that pinned none names that objective in its manifest instead,
//! and a node offers it as an *approach*; a pin, when there is one, wins.
//!
//! # The interface: `cairn-solver/v1`
//!
//! A process ABI, not a library one, so a solver can be written in anything
//! that runs on the target. It is the contract `cairn work` always had, made
//! exact and enforced:
//!
//! - **Started once per round** with no arguments but the manifest's own, in
//!   the package directory, which is read-only.
//! - **Input**: the round's assignment (`GET /work_assignment`) as one line of
//!   canonical JSON on stdin, also in `CAIRN_ASSIGNMENT`; plus `CAIRN_ABI`,
//!   `CAIRN_OBJECTIVE`, `CAIRN_WORKER`, `CAIRN_EPOCH`, `CAIRN_EPOCH_ENDS_IN`,
//!   `CAIRN_ROUND`, `CAIRN_THREADS` (and `OMP_NUM_THREADS`,
//!   `RAYON_NUM_THREADS`), `CAIRN_ROUND_SECONDS`, and `TMPDIR`/`HOME`, a
//!   private scratch directory deleted after the round. Nothing else.
//! - **Output**: zero or more candidate artifacts on stdout, one JSON object
//!   per line, at most [`manifest::MAX_CANDIDATES`], no floats. Exit 0. Exit
//!   0 with no output means "nothing this round". Any other exit discards the
//!   round. stderr is a log.
//! - **Bounds**: `resources.round_seconds` of wall clock (then the round is
//!   killed and discarded), `resources.memory_mb`, and the CPU threads the
//!   contributor offered, held by the jail rather than trusted to the solver.
//! - **Nothing else**: no network of any kind, no file outside the package
//!   and the scratch directory, no environment from the contributor's
//!   session. Enforced by the kernel through [`crate::verifiers::sandbox`], the
//!   jail pinned checkers already run in. A package never runs unjailed
//!   unless the operator explicitly asks for it on a development machine.
//!
//! A solver never submits, signs, cites or talks to the node. `cairn work`
//! does all four outside the jail, under the contributor's own key, so a
//! hostile package can waste the cycles it was given and nothing more: it
//! cannot redirect payment, it cannot read the key, and the node's pinned
//! verifier is still the only thing that decides what a candidate is worth.
//!
//! # "It has to pass"
//!
//! A manifest must carry known-answer tests: an assignment and either the
//! exact candidates it must print or a requirement that the objective's
//! pinned verifier accept what it prints. They are run, in the jail, by:
//!
//! - `cairn solver check`, on the author's machine, before anything leaves it;
//! - `cairn solver add` and `cairn post`, on the node, before the node will
//!   offer the package or admit an objective that pins it;
//! - every worker, on its own platform, before the first round it runs.
//!
//! The last is the one that matters most. A node on Linux cannot run a macOS
//! build, so what it proves is the format, the hashes and the targets it can
//! run; the Mac that is about to run the macOS build proves the rest itself.

pub mod check;
pub mod cli;
pub mod fetch;
pub mod manifest;
pub mod package;
pub mod run;
pub mod store;

pub use manifest::{Manifest, Platform, ABI};
pub use package::Package;

/// The file every package directory has at its top.
pub const MANIFEST_FILE: &str = "solver.json";
