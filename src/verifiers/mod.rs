//! The verifier interface -- the load-bearing abstraction of the network.
//!
//! An objective is not admissible until its verifier is written, pinned by hash,
//! and runnable by any contributor *before* they start work. A task whose payout
//! is somebody's opinion gets gamed the week the network has value.
//!
//! # The single most important rule in this crate
//!
//! > A verifier that cannot run returns [`Status::Unavailable`]. Never
//! > [`Status::Accept`], never [`Status::Reject`].
//!
//! A missing toolchain, an absent file, a crashed checker, a timeout, or output
//! nobody can parse is an *infrastructure fact*. It is not a fact about the
//! artifact. Collapsing it into `Reject` turns "my Lean install is broken" into
//! "your proof is wrong" -- and on a network with money attached that is an
//! attack: take the verifiers offline and every honest submission fails.
//!
//! Only `Accept` and `Reject` settle ([`Status::settles`] is the one place this
//! is decided). `Unavailable` and `InvalidSpec` record what happened, move
//! nothing, and leave the objective open for a node that can actually run the
//! check. Every error path below returns one of the two non-settling statuses;
//! this is the single easiest thing in the codebase to get wrong.
//!
//! The split between the two non-settling statuses is also load bearing:
//!
//! - [`Status::InvalidSpec`] blames the *objective*: a tampered pin, a
//!   non-integer threshold, a field that cannot be compared reproducibly. The
//!   objective needs fixing (which, since the verifier is part of the
//!   objective's identity, means posting a different objective).
//! - [`Status::Unavailable`] blames *this node*: no `lean`, no `python3`, a
//!   crash, a timeout. Another node may well reach a verdict.
//!
//! # Six verifiers
//!
//! | kind | what it proves | cost |
//! |---|---|---|
//! | `certificate` | an NP witness recomputes | milliseconds |
//! | `evaluator` | a pinned deterministic score clears a threshold | one evaluation |
//! | `statistical` | a pinned, seeded test statistic clears a threshold | one evaluation |
//! | `lean` | a proof-assistant kernel accepted the proof | seconds to minutes |
//! | `replay` | a pinned computation reproduces its declared fields | a full re-run |
//! | `workspace` | files over a pinned base tree reproduce a declared score | a build and a run |
//!
//! # Jailed subprocess, not in-process execution
//!
//! Pinned checker and evaluator source runs as a **subprocess inside an OS
//! jail**. Neither reference implementation does this — the Python one this
//! crate replaced `exec`d in-process, and `reference/rust` spawns an
//! interpreter with no jail at all. That is the correct division of labour: a
//! reference implementation exists to be an independent second opinion on the
//! *rules*, and it is not something anybody should point at a stranger's code.
//! Two reasons this one is jailed, both real:
//!
//! 1. *Security.* In-process execution gives a malicious objective author the
//!    address space of every contributor who touches the objective -- their
//!    keys, their ledger, their filesystem handles. The jail in
//!    [`sandbox`] removes the network and the filesystem too; [`SANDBOXING`]
//!    states precisely what is left.
//! 2. *Practicality.* The pinned checkers in `examples/` are Python. Rust cannot
//!    `exec` them; it can spawn an interpreter that can.
//!
//! The hash is verified **before** the subprocess is spawned, so tampered code
//! is never executed at all. A hash mismatch is [`Status::InvalidSpec`] rather
//! than `Reject`: the checker's hash is part of the objective's identity, so a
//! file that no longer matches its pin means the *objective* is broken, not that
//! the submitted artifact is bad.
//!
//! The other consequence of the subprocess design is a liveness one:
//! in-process execution of a looping checker hangs the node forever, while every
//! child spawned here runs under a wall-clock bound and is killed on expiry.
//! Expiry yields `Unavailable`, so a slow checker can never become a rejection.

pub mod limits;
pub mod sandbox;
pub mod workspace;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::blobs::{self, BlobStore};
use crate::canonical::Value;
use sandbox::Confinement;

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// The four things a verifier may conclude.
///
/// Two of them settle and two of them do not; see the module documentation for
/// why that distinction is the security property this file exists to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    /// The artifact does what it claims. Mints value.
    Accept,
    /// The artifact does *not* do what it claims. A real, negative verdict.
    Reject,
    /// The verifier could not reach a verdict. Settles nothing, refutes nothing.
    Unavailable,
    /// The objective's verifier spec is itself malformed or tampered with.
    InvalidSpec,
}

impl Status {
    /// The wire spelling, as recorded in the ledger. Consensus-relevant: an
    /// auditor compares this string against a re-verification.
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Accept => "accept",
            Status::Reject => "reject",
            Status::Unavailable => "unavailable",
            Status::InvalidSpec => "invalid_spec",
        }
    }

    /// Decode a wire spelling. `None` for anything unrecognized -- an unknown
    /// status must never be silently coerced into a settling one.
    pub fn from_wire(text: &str) -> Option<Status> {
        match text {
            "accept" => Some(Status::Accept),
            "reject" => Some(Status::Reject),
            "unavailable" => Some(Status::Unavailable),
            "invalid_spec" => Some(Status::InvalidSpec),
            _ => None,
        }
    }

    /// Only a real verdict may move value or close an objective.
    ///
    /// Everything else in this module is in service of keeping this predicate
    /// honest. If an infrastructure failure could reach `Reject`, an attacker
    /// who can break verifiers can fail every honest submission.
    pub fn settles(&self) -> bool {
        matches!(self, Status::Accept | Status::Reject)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// A verdict plus everything a third party needs to re-derive it.
///
/// Recorded verbatim in the ledger. The audit path re-runs the verifier and
/// compares [`Status`]; `detail` is for humans and `evidence` is for whoever
/// wants to check the work without re-running it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub status: Status,
    pub detail: String,
    /// Always a [`Value::Object`]. Empty when there is nothing to show.
    pub evidence: Value,
}

impl Verdict {
    pub fn new(status: Status, detail: impl Into<String>, evidence: Value) -> Verdict {
        Verdict {
            status,
            detail: detail.into(),
            evidence,
        }
    }

    /// A verdict with no evidence beyond its own text.
    pub fn plain(status: Status, detail: impl Into<String>) -> Verdict {
        Verdict::new(status, detail, empty_object())
    }

    pub fn accept(detail: impl Into<String>) -> Verdict {
        Verdict::plain(Status::Accept, detail)
    }

    pub fn reject(detail: impl Into<String>) -> Verdict {
        Verdict::plain(Status::Reject, detail)
    }

    /// The verifier could not run. Use this for *every* infrastructure failure.
    pub fn unavailable(detail: impl Into<String>) -> Verdict {
        Verdict::plain(Status::Unavailable, detail)
    }

    /// The objective's own verifier specification is broken.
    pub fn invalid_spec(detail: impl Into<String>) -> Verdict {
        Verdict::plain(Status::InvalidSpec, detail)
    }

    /// Builder form, so the constructors above stay readable at call sites.
    pub fn with_evidence(mut self, evidence: Value) -> Verdict {
        self.evidence = evidence;
        self
    }

    pub fn accepted(&self) -> bool {
        self.status == Status::Accept
    }

    /// Convenience for [`Status::settles`]; the node checks this before paying.
    pub fn settles(&self) -> bool {
        self.status.settles()
    }

    /// The integer score, when the verifier produced one.
    ///
    /// The ratchet reads the score from `evidence["score"]` -- that is the
    /// contract between [`crate::verifiers`] and [`crate::frontier`]. `None`
    /// covers "no score" and "a score that is not an integer" alike, and a
    /// [`Value::Bool`] is not an integer here even though Python's `bool` is a
    /// subclass of `int` (the reference implementation has to test for that
    /// explicitly; the canonical value type makes it structural).
    pub fn score(&self) -> Option<i64> {
        self.evidence.get("score").and_then(Value::as_i64)
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("status", Value::string(self.status.as_str())),
            ("detail", Value::string(self.detail.clone())),
            ("evidence", self.evidence.clone()),
        ])
    }

    /// Decode a recorded verdict. `None` if it is not a well-formed verdict
    /// object -- an unreadable record must not decode into a settling verdict.
    pub fn from_value(value: &Value) -> Option<Verdict> {
        let status = Status::from_wire(value.get("status").and_then(Value::as_str)?)?;
        let detail = value
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let evidence = match value.get("evidence") {
            Some(Value::Object(map)) => Value::Object(map.clone()),
            _ => empty_object(),
        };
        Some(Verdict {
            status,
            detail,
            evidence,
        })
    }
}

fn empty_object() -> Value {
    Value::Object(BTreeMap::new())
}

// ---------------------------------------------------------------------------
// Verifier kinds and directions
// ---------------------------------------------------------------------------

/// Which verifier a spec routes to.
///
/// The reference implementation keeps a runtime registry keyed by string. Here
/// the set is closed and known at compile time, so dispatch is a `match` on an
/// enum and "unknown kind" is handled in exactly one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Certificate,
    Evaluator,
    Lean,
    Replay,
    Statistical,
    Workspace,
}

impl Kind {
    /// Every kind this build can dispatch, in wire-spelling order.
    ///
    /// The published `spec/objective.schema.json` enum has to list exactly
    /// these, so the schema tests iterate this rather than a second literal;
    /// one list cannot drift from itself.
    pub const ALL: &'static [Kind] = &[
        Kind::Certificate,
        Kind::Evaluator,
        Kind::Lean,
        Kind::Replay,
        Kind::Statistical,
        Kind::Workspace,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Certificate => "certificate",
            Kind::Evaluator => "evaluator",
            Kind::Lean => "lean",
            Kind::Replay => "replay",
            Kind::Statistical => "statistical",
            Kind::Workspace => "workspace",
        }
    }

    pub fn parse(text: &str) -> Option<Kind> {
        match text {
            "certificate" => Some(Kind::Certificate),
            "evaluator" => Some(Kind::Evaluator),
            "lean" => Some(Kind::Lean),
            "replay" => Some(Kind::Replay),
            "statistical" => Some(Kind::Statistical),
            "workspace" => Some(Kind::Workspace),
            _ => None,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which way a better evaluator score points.
///
/// Deliberately *not* `frontier::Direction`, even though the wire spellings are
/// identical: the verification layer must not depend on the payout layer. The
/// two agree through the strings `"maximize"` / `"minimize"`, which is the only
/// contract an objective author can see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Maximize,
    Minimize,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Maximize => "maximize",
            Direction::Minimize => "minimize",
        }
    }

    pub fn parse(text: &str) -> Option<Direction> {
        match text {
            "maximize" => Some(Direction::Maximize),
            "minimize" => Some(Direction::Minimize),
            _ => None,
        }
    }

    /// Does `score` clear `threshold` in this direction?
    ///
    /// A comparison, never a subtraction: `score - threshold` can overflow
    /// `i64` when the two straddle zero at the extremes, and there is no reason
    /// to compute a difference nobody needs.
    pub fn clears(&self, score: i64, threshold: i64) -> bool {
        match self {
            Direction::Maximize => score >= threshold,
            Direction::Minimize => score <= threshold,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Exactly what the jail around objective-authored code does and does not do.
///
/// Reproduced in `docs/threat-model.md`. Keep the two saying the same thing:
/// the whole value of that document is that it is not marketing.
pub const SANDBOXING: &str = "\
Objective-authored code -- pinned checkers, evaluators, and statistics, replay \
commands, and Lean on submitted proof text -- runs in a child process inside an \
OS jail: bubblewrap on Linux, a seatbelt profile on macOS. Enforced by the \
kernel: no network of any kind (including unix sockets to a local daemon), no \
reads outside declared bundle, toolchain, and system paths, nothing written to \
the host outside a scratch directory that is deleted when the check finishes \
(under bubblewrap a write to a path the jail does not show from the host lands \
on its own tmpfs and is discarded with it; seatbelt refuses it), a wall-clock \
deadline, and best-effort RLIMIT_CPU/RLIMIT_AS. While the child runs the node \
also measures its process tree and holds it to a CPU cap (CAIRN_SANDBOX_CPUS, \
by pausing it) and, on macOS, which has no RLIMIT_AS, to the memory cap; a \
process that leaves both the tree and its process group escapes that \
measurement, as it escapes the deadline's kill. Every child process gets a \
scrubbed environment, so objective code cannot return the operator's credentials \
in verdict evidence. Raw child output is retained only by digest. \
Directories a spec can name (replay's cwd, \
lean's project_root) resolve against the objective root and are refused when \
they escape it, including through symlinks, so a record cannot choose which host paths are bound into its \
own jail. \
\
It is NOT a VM boundary, and two gaps are real. (1) A kernel or policy bug is \
still an escape; gVisor/Firecracker/WASM would bound that and are not \
implemented. (2) On a host with no jail mechanism \
the child runs as before, unconfined; set CAIRN_REQUIRE_SANDBOX=1 to make \
that Unavailable instead. When a jailed run fails, the verdict's evidence names \
the mechanism, so an operator can tell a broken jail from a broken checker.";

/// Wall-clock bound for pinned checkers and evaluators when the spec is silent.
///
/// The reference implementation has no bound at all here, because it never
/// spawns anything. A bound is required once a child process is involved, and
/// it can only ever produce `Unavailable`.
pub const DEFAULT_PINNED_TIMEOUT_SECONDS: u64 = 300;
/// Matches the reference implementation's `lean` default.
pub const DEFAULT_LEAN_TIMEOUT_SECONDS: u64 = 120;
/// Matches the reference implementation's `replay` default.
pub const DEFAULT_REPLAY_TIMEOUT_SECONDS: u64 = 600;
/// Upper bound on any spec-declared timeout. An objective that asks a node to
/// block for longer than a day is a liveness attack on the network, not a
/// verifier; refusing it is a spec judgement, so it is `InvalidSpec`.
pub const MAX_TIMEOUT_SECONDS: u64 = 86_400;

/// Substrings that make a `replay` field machine-dependent. Denied in specs.
///
/// Wall-clock, CPU seconds, and memory high-water are properties of the machine
/// that ran the job, not of the computation, so two honest nodes disagree about
/// them by construction. A cost claim denominated in seconds is a claim about
/// somebody's hardware and cannot be settled by re-execution.
pub const TIME_LIKE: &[&str] = &[
    "time",
    "seconds",
    "duration",
    "elapsed",
    "latency",
    "throughput",
    "memory",
    "rss",
    "flops",
    "timestamp",
    "date",
];

/// How often the timeout loop checks on a child. Small enough that a fast
/// checker is not noticeably delayed, large enough not to spin a core.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Ceiling on what one verification may write to stdout and stderr together.
///
/// Only its digest is retained as evidence, so this is not a limit on anything
/// useful -- it is the bound that stops an objective's checker from
/// filling the operator's disk (and then the node's memory, when the capture
/// is read back) by printing for its whole CPU budget. 8 MiB is far more than
/// any real checker emits and far less than a `df` moves.
const MAX_CAPTURED_BYTES: u64 = 8 * 1024 * 1024;

/// Wall-clock ceiling for a caller that answers a human or an agent while it
/// waits. See [`VerifierRegistry::interactive`].
pub const INTERACTIVE_TIMEOUT_SECONDS: u64 = 120;

/// The Lean binary, when it is not the `lean` on `PATH`. The same variable
/// the reference implementation reads. Point it at the toolchain's *real*
/// binary (`<prefix>/bin/lean`), not elan's `~/.elan/bin/lean` proxy: the
/// proxy finds the toolchain through `$HOME`, which the jail scrubs.
pub const LEAN_ENV: &str = "CAIRN_LEAN";

/// A directory the operator grants the Lean jail to read, in full: the
/// toolchain's installation prefix. Needed when that prefix is under the
/// operator's home, as every elan install is (`~/.elan/toolchains/...`),
/// because a runtime root beneath a home directory is deliberately never
/// allow-listed on its own (`sandbox::narrow_runtime_root`). This is an
/// explicit operator decision about one directory, made outside any
/// objective; a record still cannot choose what its own jail binds.
pub const LEAN_ROOT_ENV: &str = "CAIRN_LEAN_ROOT";

/// The interpreter pinned checkers, evaluators and statistics run under, when
/// it is not the `python3` on `PATH`. Name the interpreter itself, not a
/// version manager's shim (`~/.pyenv/shims/python3`, asdf's, mise's): a shim
/// re-execs through the manager's files under the operator's home, which the
/// jail never shows, so it is refused before it runs. `pyenv which python3`,
/// `asdf which python3` and `mise which python3` each print the real one.
pub const PYTHON_ENV: &str = "CAIRN_PYTHON";

/// A directory the operator grants the pinned-code jail to read, in full: the
/// Python interpreter's installation prefix (`pyenv prefix`). Needed when that
/// prefix is under the operator's home, for the same reason as
/// [`LEAN_ROOT_ENV`] and with the same limit: an operator decision about one
/// directory, never something an objective can ask for.
pub const PYTHON_ROOT_ENV: &str = "CAIRN_PYTHON_ROOT";

/// A screen applied to submitted Lean proof text before Lean ever runs.
#[derive(Debug, Clone, Copy)]
struct Screen {
    /// The literal token searched for.
    token: &'static str,
    /// Require non-word neighbours around the token (the reference
    /// implementation's `\b...\b`). `false` for `@[implemented_by`, which is
    /// matched as a bare substring because `[` is not a word character.
    whole_word: bool,
    /// The reference implementation's regex spelling, recorded as evidence so a
    /// Python node and a Rust node produce the same `pattern` field.
    pattern: &'static str,
    why: &'static str,
}

/// Each of these produces a file the kernel accepts while proving nothing, or
/// proves it by a route outside the kernel. This is the "verifier gaming"
/// attack in its most concrete form: the artifact satisfies the checker while
/// missing the goal. Every verifier needs its own version of this list, and
/// writing it *is* the real work of authoring an objective.
const FORBIDDEN: &[Screen] = &[
    Screen {
        token: "sorry",
        whole_word: true,
        pattern: r"\bsorry\b",
        why: "contains `sorry`: an explicit hole, proves nothing",
    },
    Screen {
        token: "admit",
        whole_word: true,
        pattern: r"\badmit\b",
        why: "contains `admit`: an explicit hole, proves nothing",
    },
    Screen {
        token: "axiom",
        whole_word: true,
        pattern: r"\baxiom\b",
        why: "declares an axiom: adds a trusted assumption",
    },
    Screen {
        token: "@[implemented_by",
        whole_word: false,
        pattern: "@\\[implemented_by",
        why: "replaces an implementation outside the kernel",
    },
    // The rest guard the axiom audit rather than the proof itself. The audit
    // appends `#print axioms` after the proof, and a proof may write
    // commands after its term; one that redefines how `#print axioms` or
    // `#eval` elaborate, runs metaprograms that do, or stops the file before
    // the audit, would make the audit say what the proof chose. A proof term
    // needs none of these.
    Screen {
        token: "macro",
        whole_word: true,
        pattern: r"\bmacro\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "macro_rules",
        whole_word: true,
        pattern: r"\bmacro_rules\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "elab",
        whole_word: true,
        pattern: r"\belab\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "elab_rules",
        whole_word: true,
        pattern: r"\belab_rules\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "syntax",
        whole_word: true,
        pattern: r"\bsyntax\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "command_elab",
        whole_word: true,
        pattern: r"\bcommand_elab\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "term_elab",
        whole_word: true,
        pattern: r"\bterm_elab\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "run_cmd",
        whole_word: true,
        pattern: r"\brun_cmd\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "run_elab",
        whole_word: true,
        pattern: r"\brun_elab\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "run_meta",
        whole_word: true,
        pattern: r"\brun_meta\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "run_tac",
        whole_word: true,
        pattern: r"\brun_tac\b",
        why: METAPROGRAM,
    },
    // A term that runs an elaborator: from inside a proof, it can put a
    // theorem in the environment the kernel never checked and prove the
    // objective from it. The kernel replay refuses that whatever spelling
    // reaches it; this screen refuses the spelling that was shown to.
    Screen {
        token: "by_elab",
        whole_word: true,
        pattern: r"\bby_elab\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "initialize",
        whole_word: true,
        pattern: r"\binitialize\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "builtin_initialize",
        whole_word: true,
        pattern: r"\bbuiltin_initialize\b",
        why: METAPROGRAM,
    },
    Screen {
        token: "#eval",
        whole_word: false,
        pattern: "#eval",
        why: METAPROGRAM,
    },
    Screen {
        token: "#exit",
        whole_word: false,
        pattern: "#exit",
        why: METAPROGRAM,
    },
    Screen {
        token: "skipKernelTC",
        whole_word: false,
        pattern: "skipKernelTC",
        why: "turns off the kernel's type check",
    },
];

/// Why a proof that writes or runs metaprograms is refused. Shared wording
/// with the reference implementation.
const METAPROGRAM: &str = "defines or runs a metaprogram: a proof term needs none, and one could \
     put a declaration in the environment the kernel never checked";

/// The axioms every Lean proof may use: the three the core library itself
/// rests on. Anything else -- `sorryAx`, an axiom a metaprogram added, the
/// compiler trust `native_decide` brings -- has to be allowed by the
/// objective.
const LEAN_STANDARD_AXIOMS: &[&str] = &["propext", "Classical.choice", "Quot.sound"];

/// What `native_decide` rests on, allowed only with `allow_native_decide`:
/// `Lean.ofReduceBool` and `Lean.trustCompiler` on older toolchains, and on
/// newer ones an axiom of its own per use, named under the declaration that
/// used it (see [`is_native_decide_axiom`]).
const LEAN_NATIVE_AXIOMS: &[&str] = &["Lean.ofReduceBool", "Lean.trustCompiler"];

/// The kernel replay, run by `lean --run` after a claim compiles. The file is
/// the protocol's: both implementations embed it unchanged, and it says in
/// its own header what it checks and why.
const KERNEL_REPLAY: &str = include_str!("../../spec/lean/KernelReplay.lean");

/// The module name a claim and its statement are both compiled as. One name
/// for both, because `private` declarations are named after their module and
/// the replay compares the two compiles declaration by declaration.
const LEAN_MODULE: &str = "CairnProof";

/// Where a word starts in `text`, under the same rule as the screens.
fn find_word(text: &str, word: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(found) = text[from..].find(word) {
        let start = from + found;
        let end = start + word.len();
        let clear_before = start == 0 || !is_word_byte(bytes[start - 1]);
        let clear_after = end == bytes.len() || !is_word_byte(bytes[end]);
        if clear_before && clear_after {
            return Some(start);
        }
        from = start + word.len();
    }
    None
}

/// The identifier that follows position `at`, up to whitespace or the
/// characters that begin a binder or a type.
fn lean_identifier_after(text: &str, at: usize) -> Option<String> {
    let name: String = text[at..]
        .trim_start()
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, ':' | '(' | '{' | '[' | '⦃'))
        .collect();
    (!name.is_empty()).then_some(name)
}

/// The theorem the replay holds to the statement: the first `theorem` or
/// `lemma` the objective's statement declares. `None` for an `example`, which
/// has no name to ask about; the claim is then still replayed and held to the
/// statement's declarations, but there is no theorem whose axioms to read.
fn lean_theorem_name(statement: &str) -> Option<String> {
    let at = ["theorem", "lemma"]
        .iter()
        .filter_map(|keyword| find_word(statement, keyword).map(|at| (at, keyword.len())))
        .min()?;
    lean_identifier_after(statement, at.0 + at.1)
}

/// Is `name` an axiom `native_decide` added for one use, as Lean 4.2x and
/// later name them: `<declaration>._native.native_decide.ax_<i>_<j>`?
///
/// Allowed only when the objective allows `native_decide`, and then on the
/// same footing as `Lean.ofReduceBool`: the objective chose to trust the
/// compiler, and what the compiler asserted is exactly what nothing here can
/// check. A metaprogram could plant an axiom under this name; on an objective
/// that did not opt in it is refused like any other, and one that did opt in
/// had already accepted code the kernel never sees.
fn is_native_decide_axiom(name: &str) -> bool {
    name.contains("._native.native_decide.ax_")
}

/// A fresh marker for one replay: 128 random bits, so nothing else on the
/// output can be mistaken for the replay's report.
fn audit_marker() -> String {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    format!("cairn-kernel-replay-{}", crate::hex::encode(&bytes))
}

/// What the kernel replay reported, read from the lines that start with its
/// marker.
#[derive(Debug, PartialEq, Eq)]
enum KernelReplay {
    /// No terminal line: the replay did not run here (the driver did not
    /// elaborate on this Lean, or the process died). A fact about the node.
    NoReport,
    /// `fail`: the claim is not what the statement asked for, or the kernel
    /// refused one of its declarations.
    Refused(String),
    /// `unavailable`: the kernel ran out of time, stack or memory replaying
    /// it. A fact about the node.
    Unavailable(String),
    /// `ok`, with what the theorem rests on (`axioms`), the axioms the
    /// claim's module declared that the statement's did not (`added`), and
    /// the ones the statement itself declared (`pinned`).
    Passed {
        axioms: Vec<String>,
        added: Vec<String>,
        pinned: Vec<String>,
    },
}

fn read_kernel_replay(output: &str, marker: &str) -> KernelReplay {
    let (mut axioms, mut added, mut pinned) = (Vec::new(), Vec::new(), Vec::new());
    for line in output.lines() {
        let Some(report) = line
            .strip_prefix(marker)
            .and_then(|rest| rest.strip_prefix(' '))
        else {
            continue;
        };
        let (word, rest) = report.split_once(' ').unwrap_or((report, ""));
        match word {
            "ok" => {
                return KernelReplay::Passed {
                    axioms,
                    added,
                    pinned,
                }
            }
            "fail" => return KernelReplay::Refused(rest.to_string()),
            "unavailable" => return KernelReplay::Unavailable(rest.to_string()),
            "axiom" => axioms.push(rest.to_string()),
            "added-axiom" => added.push(rest.to_string()),
            "pinned" => pinned.push(rest.to_string()),
            _ => {}
        }
    }
    KernelReplay::NoReport
}

/// The axioms a proof of this objective may use, or why the spec is
/// malformed: the standard set, `native_decide`'s when the objective opts
/// in, and the objective's own `allowed_axioms`. The preamble's own axioms
/// are added per claim from what the replay reports the statement declared.
fn lean_allowed_axioms(spec: &Value, allow_native_decide: bool) -> Result<Vec<String>, Verdict> {
    let mut exact: Vec<String> = LEAN_STANDARD_AXIOMS.iter().map(|a| a.to_string()).collect();
    if allow_native_decide {
        exact.extend(LEAN_NATIVE_AXIOMS.iter().map(|a| a.to_string()));
    }
    match spec.get("allowed_axioms") {
        None => {}
        Some(Value::Array(items)) => {
            for item in items {
                match item.as_str() {
                    Some(name) if !name.trim().is_empty() => exact.push(name.trim().to_string()),
                    _ => {
                        return Err(Verdict::invalid_spec(
                            "allowed_axioms must be a list of axiom names",
                        ))
                    }
                }
            }
        }
        Some(_) => {
            return Err(Verdict::invalid_spec(
                "allowed_axioms must be a list of axiom names",
            ))
        }
    }
    Ok(exact)
}

/// The verdict once the claim compiled cleanly: the kernel replay decides.
///
/// A replay that did not report is Unavailable, not Reject or Accept: it is
/// this node's check, and when it cannot run nothing is learned about the
/// proof -- but nothing is paid either.
fn lean_replay_verdict(
    replay: KernelReplay,
    allowed: &[String],
    allow_native_decide: bool,
    evidence: Value,
) -> Verdict {
    let with = |field: &str, value: Value| -> Value {
        let mut map = evidence.as_object().cloned().unwrap_or_default();
        map.insert(field.to_string(), value);
        Value::Object(map)
    };
    match replay {
        KernelReplay::NoReport => Verdict::new(
            Status::Unavailable,
            "the kernel replay did not report: this node's Lean could not run it",
            evidence,
        ),
        KernelReplay::Unavailable(why) => Verdict::new(
            Status::Unavailable,
            format!("the kernel replay could not finish here ({why}); that is not a refutation"),
            evidence,
        ),
        KernelReplay::Refused(why) => Verdict::new(
            Status::Reject,
            format!("the kernel replay refused the claim: {why}"),
            evidence,
        ),
        KernelReplay::Passed {
            axioms,
            added,
            pinned,
        } => {
            let listed = Value::Array(axioms.iter().map(|a| Value::string(a.as_str())).collect());
            // A proof may not declare an axiom: the `axiom` screen refuses
            // the keyword, so one here was put there by a metaprogram. The
            // one exception is what `native_decide` adds, on an objective
            // that allowed it.
            if let Some(axiom) = added
                .iter()
                .find(|name| !(allow_native_decide && is_native_decide_axiom(name)))
            {
                return Verdict::new(
                    Status::Reject,
                    format!("the proof declares axiom {axiom}; a proof may not add axioms"),
                    with("axioms", listed),
                );
            }
            let refused = axioms.iter().find(|name| {
                !allowed.iter().any(|a| a == *name)
                    && !pinned.iter().any(|a| a == *name)
                    && !(allow_native_decide && is_native_decide_axiom(name))
            });
            match refused {
                Some(axiom) => Verdict::new(
                    Status::Reject,
                    format!(
                        "the theorem depends on axiom {axiom}, which the objective does not allow"
                    ),
                    with("axioms", listed),
                ),
                None => Verdict::new(
                    Status::Accept,
                    "kernel accepted the proof",
                    with("axioms", listed),
                ),
            }
        }
    }
}

/// Why a Lean proof that does not open with `:=` is refused. Shared wording
/// with the reference implementation, which refuses the same text.
const LEAN_PROOF_MUST_OPEN_WITH_ASSIGN: &str =
    "the proof must begin with `:=`; text before it would extend the objective's statement";

/// `native_decide` discharges goals via compiled evaluation, trusting the
/// compiler and runtime rather than the kernel. A known soundness escape hatch,
/// allowed only when the objective explicitly opts in.
const NATIVE_DECIDE: Screen = Screen {
    token: "native_decide",
    whole_word: true,
    pattern: r"\bnative_decide\b",
    why: "uses `native_decide`: trusts the compiler, not the kernel",
};

/// The program handed to `python3 -c`. It loads the pinned file by path, feeds
/// it the artifact from stdin, and prints exactly one JSON object.
///
/// A third argument, when present, is the `statistical` kind's pinned seed and
/// is passed to the entrypoint as a second parameter. It is `argv`-carried
/// rather than folded into the stdin artifact because the seed belongs to the
/// *objective* and the artifact belongs to the submitter; merging them would
/// let a submitter who controls the artifact choose the seed.
///
/// Three details are load bearing:
///
/// - The module is loaded with `importlib.util.spec_from_file_location`, so the
///   file is executed from the path whose hash this process already verified --
///   not from an importable name that could resolve elsewhere on `sys.path`.
/// - Anything the pinned module prints is redirected to stderr while it runs, so
///   a chatty checker cannot corrupt the result channel and be misread as
///   "unparseable output" (which would report `Unavailable` for a checker that
///   worked fine).
/// - `bool` is checked before `int`, because in Python `bool` *is* an `int` and
///   a checker returning `True` must not be read as the score 1.
///
/// Any uncaught exception in the pinned code becomes a traceback and a non-zero
/// exit, which the caller reports as `Unavailable` -- a crashed checker is an
/// infrastructure fact, exactly as in the reference implementation.
const HARNESS: &str = r##"import importlib.machinery
import importlib.util
import json
import sys


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: <pinned file> <entrypoint>\n")
        return 2
    path = sys.argv[1]
    entrypoint = sys.argv[2]
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else None
    artifact = json.load(sys.stdin)
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        # The loader is named rather than inferred from the extension. A blob's
        # filename is its hash, so it never ends in `.py`, and
        # `spec_from_file_location` returns None for an extension it does not
        # recognise -- which made the content-addressed fallback, the entire
        # reason `blobs` exists, unable to load anything. A node that fetched a
        # pinned checker from a peer got `unavailable` on every claim: exactly
        # the failure the blob store was built to remove.
        loader = importlib.machinery.SourceFileLoader("pinned_verifier", path)
        spec = importlib.util.spec_from_file_location("pinned_verifier", path, loader=loader)
        if spec is None or spec.loader is None:
            sys.stderr.write("cannot load pinned module from %s\n" % (path,))
            return 3
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        func = getattr(module, entrypoint, None)
        if not callable(func):
            sys.stderr.write("no callable entrypoint %r\n" % (entrypoint,))
            return 4
        result = func(artifact) if seed is None else func(artifact, seed)
    finally:
        sys.stdout = real_stdout
    if isinstance(result, tuple):
        if len(result) < 2:
            sys.stderr.write("entrypoint returned a %d-tuple\n" % (len(result),))
            return 5
        ok = result[0]
        if isinstance(ok, bool):
            out = {"ok": ok, "detail": str(result[1])}
        else:
            out = {"bad_return": type(ok).__name__}
    elif isinstance(result, bool):
        out = {"ok": result, "detail": ""}
    elif isinstance(result, int):
        out = {"score": result}
    elif isinstance(result, (dict, list)):
        # A structured return. No verifier kind accepts one -- a checker owes a
        # bool and an evaluator an int -- so for those this is still an error,
        # and `value_type` is carried so the diagnostic can name the type
        # exactly as `bad_return` used to. What it is *for* is the stepper in
        # `crate::challenge`, whose whole job is to return the next state.
        out = {"value": result, "value_type": type(result).__name__}
    else:
        out = {"bad_return": type(result).__name__}
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return 0


sys.exit(main())
"##;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Why a pin could not be turned into a runnable path on this node.
///
/// Internal, and separate from [`Verdict`] on purpose: the same resolution
/// answers two different questions — "what status does this verification get"
/// and "which blob should I ask a peer for" — and the second one needs to
/// distinguish a broken objective (never fetch) from absent code (fetch).
#[derive(Debug, Clone, PartialEq, Eq)]
enum PinFailure {
    /// The declared path leaves the bundle root. A broken objective, and
    /// deliberately not rescuable from the store.
    Escape,
    /// A bundle file exists and hashes to something else. Not rescuable from
    /// the store: a cached blob must not shadow an edited bundle file.
    Mismatch { actual: String },
    /// Neither the bundle nor the store has a copy. The only fetchable case.
    Absent { detail: String },
}

/// A pinned code file named by a verifier spec: where the objective says it is,
/// and the content address the objective's identity commits to.
///
/// Extracted here rather than at each call site because the field names differ
/// per kind (`checker_sha256`, `evaluator_sha256`, `statistic.sha256`) and three
/// copies of that knowledge would drift. Every consumer that has to answer
/// "which blobs does this objective need" — publishing, the wire protocol's want
/// set, garbage collection — goes through [`pinned_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedCode {
    /// `"checker"`, `"evaluator"`, or `"statistic"`, for diagnostics.
    pub role: &'static str,
    /// Bundle-relative path, as written in the objective.
    pub path: String,
    /// Bare lowercase hex SHA-256 — the blob's content address.
    pub sha256: String,
}

/// Every pinned code file a verifier spec names, in a fixed order.
///
/// `replay` and `lean` produce nothing, and that is a real limitation rather
/// than an oversight: a `replay` spec names a command, and a `lean` spec needs a
/// proof-assistant toolchain. Neither is a blob, so neither is made portable by
/// content-addressing the code. `docs/verification.md` says so where an
/// objective author will read it.
pub fn pinned_code(spec: &Value) -> Vec<PinnedCode> {
    let mut out = Vec::new();
    let mut push = |role: &'static str, path: Option<&str>, sha: Option<&str>| {
        if let (Some(path), Some(sha)) = (path, sha) {
            out.push(PinnedCode {
                role,
                path: path.to_string(),
                sha256: sha.to_string(),
            });
        }
    };
    match spec.get("kind").and_then(Value::as_str) {
        Some("certificate") => push(
            "checker",
            spec.get("checker").and_then(Value::as_str),
            spec.get("checker_sha256").and_then(Value::as_str),
        ),
        Some("evaluator") => push(
            "evaluator",
            spec.get("evaluator").and_then(Value::as_str),
            spec.get("evaluator_sha256").and_then(Value::as_str),
        ),
        Some("statistical") => {
            if let Some(statistic) = spec.get("statistic") {
                push(
                    "statistic",
                    statistic.get("path").and_then(Value::as_str),
                    statistic.get("sha256").and_then(Value::as_str),
                );
            }
        }
        // The manifest only. The files it names are blobs too, but finding
        // them means reading the manifest, and this function reads specs.
        Some("workspace") => push(
            "base manifest",
            spec.get("base").and_then(Value::as_str),
            spec.get("base_sha256").and_then(Value::as_str),
        ),
        _ => {}
    }
    out
}

/// Dispatches a verifier spec to the verifier it names.
///
/// `root` is the objective bundle root. Pinned checker and evaluator paths are
/// resolved against it and may not escape it; see `VerifierRegistry::pinned`.
///
/// `blobs` is the content-addressed fallback for code this node never had a
/// bundle for — the mechanism that lets a peer holding only the log obtain the
/// checker and re-derive settlement. It is consulted *after* the bundle, so an
/// operator editing a checker in place still sees a mismatch reported against
/// their edit rather than silently shadowed by a cached copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierRegistry {
    root: PathBuf,
    blobs: BlobStore,
    lean_binary: String,
    /// A directory the operator granted the Lean jail to read, beyond the
    /// binary's own installation prefix: [`LEAN_ROOT_ENV`]. Operator-declared,
    /// never objective-declared, which is what keeps "a record cannot choose
    /// which host paths are bound into its own jail" true.
    lean_root: Option<PathBuf>,
    python_binary: String,
    /// The Python counterpart of `lean_root`: [`PYTHON_ROOT_ENV`].
    python_root: Option<PathBuf>,
    /// Ceiling applied to every spec-declared timeout, when set. See
    /// [`VerifierRegistry::interactive`].
    timeout_ceiling: Option<Duration>,
}

impl Default for VerifierRegistry {
    fn default() -> VerifierRegistry {
        VerifierRegistry::new(".")
    }
}

impl VerifierRegistry {
    pub fn new(root: impl Into<PathBuf>) -> VerifierRegistry {
        let root = root.into();
        VerifierRegistry {
            blobs: BlobStore::under(&root),
            root,
            lean_binary: std::env::var(LEAN_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "lean".to_string()),
            lean_root: std::env::var_os(LEAN_ROOT_ENV)
                .map(PathBuf::from)
                .filter(|path| !path.as_os_str().is_empty()),
            python_binary: std::env::var(PYTHON_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "python3".to_string()),
            python_root: std::env::var_os(PYTHON_ROOT_ENV)
                .map(PathBuf::from)
                .filter(|path| !path.as_os_str().is_empty()),
            timeout_ceiling: None,
        }
    }

    /// Cap every verification at [`INTERACTIVE_TIMEOUT_SECONDS`].
    ///
    /// For a caller that answers a human or an agent while it waits. An
    /// objective may declare a timeout of up to a day, which is a reasonable
    /// bound for a batch audit and a liveness attack on a single-threaded
    /// server: one hostile objective would make `proofwork-mcp` stop answering
    /// `ping` and look dead to its client.
    ///
    /// Deliberately not the default. Settlement and `audit` must honour the
    /// objective's own bound, or a slow-but-honest verifier would settle
    /// differently depending on who ran it -- which is the one thing no part
    /// of this crate may do.
    pub fn interactive(mut self) -> VerifierRegistry {
        self.timeout_ceiling = Some(Duration::from_secs(INTERACTIVE_TIMEOUT_SECONDS));
        self
    }

    /// Apply the interactive ceiling, when one is set.
    fn bounded(&self, timeout: Duration) -> Duration {
        match self.timeout_ceiling {
            Some(ceiling) => timeout.min(ceiling),
            None => timeout,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The blob store this registry falls back to, and publishes into.
    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    /// Keep the blob cache somewhere other than under the bundle root.
    ///
    /// Wanted by a node whose root is read-only, and by tests that need two
    /// nodes with genuinely separate stores while sharing one checkout.
    pub fn with_blob_dir(mut self, dir: impl Into<PathBuf>) -> VerifierRegistry {
        self.blobs = BlobStore::at(dir);
        self
    }

    /// Override the Lean binary. Useful for a node with a pinned toolchain, and
    /// for tests that need a binary that is guaranteed absent.
    pub fn with_lean_binary(mut self, binary: impl Into<String>) -> VerifierRegistry {
        self.lean_binary = binary.into();
        self
    }

    /// Grant the Lean jail one more readable directory: the toolchain's
    /// installation prefix, when it lives somewhere the jail would otherwise
    /// refuse. See [`LEAN_ROOT_ENV`].
    pub fn with_lean_root(mut self, root: Option<PathBuf>) -> VerifierRegistry {
        self.lean_root = root;
        self
    }

    /// Override the interpreter that runs pinned checkers and evaluators.
    pub fn with_python_binary(mut self, binary: impl Into<String>) -> VerifierRegistry {
        self.python_binary = binary.into();
        self
    }

    /// Grant the pinned-code jail the interpreter's installation prefix. See
    /// [`PYTHON_ROOT_ENV`].
    pub fn with_python_root(mut self, root: Option<PathBuf>) -> VerifierRegistry {
        self.python_root = root;
        self
    }

    /// Why the interpreter found at `found` cannot run under a jail, in the
    /// words a verdict and `GET /verifiers` both use, or `None` when it can.
    ///
    /// Only asked when there is a jail: unconfined, a shim finds its manager
    /// and a home-directory interpreter its library, and refusing them there
    /// would turn a node that works into one that does not.
    fn python_refusal(&self, found: &Path, jailed: bool) -> Option<String> {
        if !jailed {
            return None;
        }
        let problem = sandbox::interpreter_problem(found, self.python_root.as_deref())?;
        Some(match problem {
            sandbox::Unjailable::Shim { found, what } => format!(
                "'{}' is a version-manager shim ({what}) that re-execs through files under \
                 the home directory, which the jail does not show; every pinned check would \
                 be unavailable. Set {PYTHON_ENV} to the interpreter it runs (`pyenv which \
                 python3`, `asdf which python3`, `mise which python3`) and \
                 {PYTHON_ROOT_ENV} to that interpreter's prefix (`pyenv prefix`), or put a \
                 directly installed python3 first on PATH",
                found.display()
            ),
            sandbox::Unjailable::UnderHome {
                interpreter,
                prefix,
            } => format!(
                "'{}' is under a home directory, which the jail never allow-lists on its \
                 own, so it would run without its standard library. Set {PYTHON_ROOT_ENV}={} \
                 to grant its prefix, or use a python3 installed outside the home directory",
                interpreter.display(),
                match &prefix {
                    Some(prefix) => prefix.display().to_string(),
                    None => "<its installation prefix>".to_string(),
                }
            ),
        })
    }

    /// Every kind this build can answer to, in sorted order.
    pub fn kinds() -> &'static [&'static str] {
        &[
            "certificate",
            "evaluator",
            "lean",
            "replay",
            "statistical",
            "workspace",
        ]
    }

    /// Whether an objective naming this kind can be posted at all. The node
    /// refuses an objective whose verifier nothing here can run, because an
    /// objective whose payout has no machine behind it is an opinion.
    pub fn supports(kind: &str) -> bool {
        Kind::parse(kind).is_some()
    }

    /// What this node can run *right now*: each kind, the toolchain it
    /// needs, where that toolchain resolves on this process's `PATH`, and the
    /// jail. Served as `GET /verifiers` and printed at startup, so an
    /// operator -- or Cairn.app -- learns "this node has no Lean" from the
    /// node itself, before a proof comes back `unavailable`.
    ///
    /// Resolution is repeated on every call, deliberately: `PATH` is fixed
    /// for the process's life but what is *on* it is not, and a toolchain
    /// installed into a directory already on the path is found by the next
    /// verification, so it should be found by the next report too. Only the
    /// version string is cached, per resolved binary, since asking for it
    /// spawns a process.
    ///
    /// This is a report about the node, never about any artifact: nothing in
    /// it settles anything, and a kind listed as unservable here still
    /// answers `Unavailable` -- not `Reject` -- when asked.
    pub fn readiness(&self) -> Value {
        self.readiness_under(sandbox::mechanism(), sandbox::required())
    }

    /// [`VerifierRegistry::readiness`] for a given jail, so a test can ask
    /// what a seatbelt host would report from a host without one.
    fn readiness_under(&self, mechanism: sandbox::Mechanism, required: bool) -> Value {
        let lean = which(&self.lean_binary);
        let python = which(&self.python_binary);
        let jailed = mechanism.is_jail();
        let python_problem = python
            .as_deref()
            .and_then(|found| self.python_refusal(found, jailed));

        let tool = |binary: &str, found: &Option<PathBuf>, serves: &[&str]| {
            Value::object([
                ("binary", Value::string(binary)),
                (
                    "path",
                    match found {
                        Some(path) => Value::string(path.to_string_lossy()),
                        None => Value::Null,
                    },
                ),
                ("available", Value::Bool(found.is_some())),
                (
                    "version",
                    match found.as_deref().and_then(version_of) {
                        Some(version) => Value::string(version),
                        None => Value::Null,
                    },
                ),
                (
                    "serves",
                    Value::array(serves.iter().map(|kind| Value::string(*kind))),
                ),
            ])
        };

        // Why a kind cannot run here, in the words its verdict would use.
        let mut unservable: Vec<(&str, Value)> = Vec::new();
        let mut servable: Vec<Value> = Vec::new();
        for kind in Self::kinds() {
            let reason = if required && !jailed {
                Some(format!(
                    "{} is set and no sandbox mechanism is usable here",
                    sandbox::REQUIRE_ENV
                ))
            } else {
                match *kind {
                    "certificate" | "evaluator" | "statistical" if python.is_none() => {
                        Some(format!(
                            "'{}' not on PATH; install Python 3 to run pinned checkers",
                            self.python_binary
                        ))
                    }
                    "certificate" | "evaluator" | "statistical" if python_problem.is_some() => {
                        python_problem.clone()
                    }
                    "lean" if lean.is_none() => Some(format!(
                        "'{}' not on PATH; install a Lean toolchain to verify",
                        self.lean_binary
                    )),
                    _ => None,
                }
            };
            match reason {
                Some(why) => unservable.push((kind, Value::string(why))),
                None => servable.push(Value::string(*kind)),
            }
        }

        let mut sandbox_fields = vec![
            ("mechanism", Value::string(mechanism.as_str())),
            ("jail", Value::Bool(jailed)),
            ("required", Value::Bool(required)),
        ];
        match &mechanism {
            sandbox::Mechanism::Bubblewrap(path) | sandbox::Mechanism::Seatbelt(path) => {
                sandbox_fields.push(("path", Value::string(path.to_string_lossy())));
            }
            sandbox::Mechanism::None(why) => {
                sandbox_fields.push(("why", Value::string(*why)));
            }
        }

        Value::object([
            (
                "kinds",
                Value::array(Self::kinds().iter().map(|kind| Value::string(*kind))),
            ),
            (
                "toolchains",
                Value::object([
                    ("lean", {
                        let mut row = tool(&self.lean_binary, &lean, &["lean"]);
                        if let Value::Object(fields) = &mut row {
                            fields.insert(
                                String::from("granted_root"),
                                match &self.lean_root {
                                    Some(root) => Value::string(root.to_string_lossy()),
                                    None => Value::Null,
                                },
                            );
                        }
                        row
                    }),
                    ("python3", {
                        let mut row = tool(
                            &self.python_binary,
                            &python,
                            &["certificate", "evaluator", "statistical"],
                        );
                        if let Value::Object(fields) = &mut row {
                            fields.insert(
                                String::from("granted_root"),
                                match &self.python_root {
                                    Some(root) => Value::string(root.to_string_lossy()),
                                    None => Value::Null,
                                },
                            );
                            // Found is not the same as runnable: a shim is
                            // found and cannot run in the jail. Why, or null.
                            fields.insert(
                                String::from("problem"),
                                match &python_problem {
                                    Some(why) => Value::string(why.as_str()),
                                    None => Value::Null,
                                },
                            );
                        }
                        row
                    }),
                ]),
            ),
            ("sandbox", Value::object(sandbox_fields)),
            ("servable", Value::array(servable)),
            ("unservable", Value::object(unservable)),
            (
                "note",
                Value::string(
                    "What this node can run now, from its own PATH and jail probe. A kind \
                     listed under unservable answers `unavailable` to every claim here, which \
                     settles nothing: another node may verify it. `replay` and `workspace` \
                     depend on whatever command the objective pins, so they are listed as \
                     servable whenever the jail permits them.",
                ),
            ),
        ])
    }

    /// Run a pinned entrypoint that maps one value to another, under the same
    /// hash pin and the same jail as a checker.
    ///
    /// Not a verifier and deliberately not reachable from [`VerifierRegistry::run`]:
    /// it returns a value rather than a verdict, and nothing it produces
    /// settles anything by itself. It exists for [`crate::challenge::Stepper`],
    /// where a *step* of a computation is exactly a value-to-value function and
    /// the adjudication that follows is what settles.
    ///
    /// It shares the whole spawn path with the verifiers — hash checked before
    /// the subprocess exists, scrubbed environment, memory cap, wall-clock
    /// bound — because the code being run is a stranger's either way, and a
    /// second, laxer path to executing pinned code would be the weakest one an
    /// attacker has to find.
    ///
    /// Failures come back as a non-settling [`Verdict`] for the same reason
    /// they do everywhere else: an absent interpreter is a fact about this
    /// node, and a dispute it cannot adjudicate must stay open rather than
    /// resolve against whoever happens to be accused.
    pub fn transform(
        &self,
        role: &str,
        pinned: &str,
        declared_sha256: &str,
        entrypoint: &str,
        input: &Value,
        timeout: Duration,
    ) -> Result<Value, Verdict> {
        let path = self.pinned(role, pinned, declared_sha256)?;
        let harvest =
            self.run_pinned(role, &path, entrypoint, input, self.bounded(timeout), None)?;
        match harvest {
            Harvest::Json { raw, type_name } => Value::from_json(&raw).map_err(|error| {
                // A float in a state is not a bad node, it is a spec that
                // cannot be adjudicated: two honest machines can disagree about
                // its bytes, so no dispute over it can ever be settled. Naming
                // it `invalid_spec` rather than `unavailable` says which party
                // has to fix it.
                Verdict::invalid_spec(format!(
                    "{role} returned a {type_name} that is not canonically \
                     representable: {error}"
                ))
            }),
            Harvest::Boolean { .. } => Err(Verdict::invalid_spec(format!(
                "{role} returned bool, expected an object or a list"
            ))),
            Harvest::Score(_) | Harvest::ScoreOutOfRange(_) => Err(Verdict::invalid_spec(format!(
                "{role} returned int, expected an object or a list"
            ))),
            Harvest::BadReturn(kind) => Err(Verdict::invalid_spec(format!(
                "{role} returned {kind}, expected an object or a list"
            ))),
        }
    }

    /// Verify `artifact` against `spec`.
    ///
    /// Total: every path returns a [`Verdict`], and every failure path returns a
    /// non-settling one. There is no error type because there is no caller
    /// action distinct from "record the verdict".
    pub fn run(&self, spec: &Value, artifact: &Value) -> Verdict {
        let kind = match spec.get("kind").and_then(Value::as_str) {
            Some(kind) => kind,
            None => return Verdict::invalid_spec("verifier spec has no 'kind'"),
        };
        match Kind::parse(kind) {
            Some(Kind::Certificate) => self.verify_certificate(spec, artifact),
            Some(Kind::Evaluator) => self.verify_evaluator(spec, artifact),
            Some(Kind::Lean) => self.verify_lean(spec, artifact),
            Some(Kind::Replay) => self.verify_replay(spec, artifact),
            Some(Kind::Statistical) => self.verify_statistical(spec, artifact),
            Some(Kind::Workspace) => self.verify_workspace(spec, artifact),
            // Unknown kind is Unavailable, not InvalidSpec: another node, or a
            // later version of this crate, may well know this verifier. Saying
            // "your objective is broken" because *we* are old would be wrong.
            None => Verdict::unavailable(format!(
                "no verifier registered for kind '{kind}'; known: [{}]",
                Self::kinds().join(", ")
            )),
        }
    }

    // -- certificate --------------------------------------------------------

    /// Certificate verification: re-check an NP witness by recomputation.
    ///
    /// The cheapest and soundest shape the network supports. A claimed
    /// counterexample, witness, construction, collision, or assignment is
    /// checked in milliseconds by code that knows nothing about how it was
    /// found -- and *how* it was found is both irrelevant and unverifiable,
    /// which is exactly the point.
    ///
    /// Spec: `{kind, checker, checker_sha256, entrypoint}`, where the pinned
    /// file exposes `check(artifact) -> bool | (bool, detail)`.
    fn verify_certificate(&self, spec: &Value, artifact: &Value) -> Verdict {
        let mut missing = Vec::new();
        for key in ["checker", "checker_sha256", "entrypoint"] {
            if spec.get(key).and_then(Value::as_str).is_none() {
                missing.push(key);
            }
        }
        if !missing.is_empty() {
            return Verdict::invalid_spec(format!("missing spec fields: [{}]", missing.join(", ")));
        }
        let checker = match spec.get("checker").and_then(Value::as_str) {
            Some(value) => value,
            None => return Verdict::invalid_spec("missing spec fields: [checker]"),
        };
        let declared = match spec.get("checker_sha256").and_then(Value::as_str) {
            Some(value) => value,
            None => return Verdict::invalid_spec("missing spec fields: [checker_sha256]"),
        };
        let entrypoint = match spec.get("entrypoint").and_then(Value::as_str) {
            Some(value) => value,
            None => return Verdict::invalid_spec("missing spec fields: [entrypoint]"),
        };
        let timeout = match spec_timeout(spec, DEFAULT_PINNED_TIMEOUT_SECONDS) {
            Ok(timeout) => self.bounded(timeout),
            Err(verdict) => return verdict,
        };

        let path = match self.pinned("checker", checker, declared) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        let outcome = match self.run_pinned("checker", &path, entrypoint, artifact, timeout, None) {
            Ok(outcome) => outcome,
            Err(verdict) => return verdict,
        };

        let evidence = Value::object([("checker_sha256", Value::string(declared))]);
        match outcome {
            Harvest::Boolean { ok, detail } => {
                let detail = if detail.is_empty() {
                    if ok {
                        "certificate verified".to_string()
                    } else {
                        "certificate does not check out".to_string()
                    }
                } else {
                    detail
                };
                let status = if ok { Status::Accept } else { Status::Reject };
                Verdict::new(status, detail, evidence)
            }
            // A checker whose answer is not a bool is a broken checker, and the
            // checker is part of the objective -- so the objective is what is
            // invalid. Reading a non-bool as truthy is how a checker that
            // returns a diagnostic string accepts everything.
            Harvest::Score(_) | Harvest::ScoreOutOfRange(_) => {
                Verdict::invalid_spec("checker returned int, expected bool")
            }
            Harvest::BadReturn(kind)
            | Harvest::Json {
                type_name: kind, ..
            } => Verdict::invalid_spec(format!("checker returned {kind}, expected bool")),
        }
    }

    // -- evaluator ----------------------------------------------------------

    /// Evaluator verification: score a candidate against a pinned fitness
    /// function.
    ///
    /// The FunSearch / AlphaEvolve shape, and the best value-per-check in the
    /// system: verification costs exactly one evaluation -- the same evaluation
    /// the network was going to run anyway -- so verification is free rather
    /// than merely cheap.
    ///
    /// Spec: `{kind, evaluator, evaluator_sha256, entrypoint, threshold,
    /// direction}`, where the pinned file exposes `score(artifact) -> int`.
    ///
    /// **Integers only, both sides.** IEEE-754 arithmetic does not reproduce
    /// bitwise across heterogeneous hardware, so a float score can compare
    /// differently on two honest nodes and they will disagree about whether the
    /// threshold was met. Scale the score and say so in the objective
    /// statement. A float threshold cannot even be constructed here, because
    /// [`Value`] has no float variant.
    fn verify_evaluator(&self, spec: &Value, artifact: &Value) -> Verdict {
        let evaluator = match required_str(spec, "evaluator") {
            Ok(value) => value,
            Err(verdict) => return verdict,
        };
        let declared = match required_str(spec, "evaluator_sha256") {
            Ok(value) => value,
            Err(verdict) => return verdict,
        };
        let entrypoint = match required_str(spec, "entrypoint") {
            Ok(value) => value,
            Err(verdict) => return verdict,
        };

        let threshold = match spec_threshold(spec) {
            Ok(threshold) => threshold,
            Err(verdict) => return verdict,
        };
        let direction = match spec_direction(spec) {
            Ok(direction) => direction,
            Err(verdict) => return verdict,
        };
        let timeout = match spec_timeout(spec, DEFAULT_PINNED_TIMEOUT_SECONDS) {
            Ok(timeout) => self.bounded(timeout),
            Err(verdict) => return verdict,
        };

        let path = match self.pinned("evaluator", evaluator, declared) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        let outcome = match self.run_pinned("evaluator", &path, entrypoint, artifact, timeout, None)
        {
            Ok(outcome) => outcome,
            Err(verdict) => return verdict,
        };
        score_verdict(
            outcome,
            threshold,
            direction,
            "evaluator",
            Value::object([("evaluator_sha256", Value::string(declared))]),
        )
    }

    // -- statistical --------------------------------------------------------

    /// Statistical verification: a pinned, seeded test statistic clears a
    /// pinned threshold.
    ///
    /// The whole point is *pre-registration*. The statistic and the rejection
    /// threshold are fields of the objective, so they are inside the
    /// objective's digest: choosing the criterion after seeing the data means
    /// posting a different objective, with a different id, that funded nothing
    /// and cites nothing. That is the only defence this network has against the
    /// oldest fraud in empirical work, and it costs nothing to enforce because
    /// identity already covers the verifier block.
    ///
    /// Spec: `{kind, statistic: {path, sha256}, entrypoint, threshold,
    /// direction, seed}`, where the pinned file exposes
    /// `statistic(artifact, seed) -> int`.
    ///
    /// Two rules beyond the evaluator's:
    ///
    /// - **The seed is pinned, and it comes from the objective.** Resampling,
    ///   permutation tests, and bootstraps are the normal shape of a test
    ///   statistic and they are all randomised. A statistic whose randomness a
    ///   submitter could choose is a statistic a submitter can grind against
    ///   until it clears; a statistic whose randomness is unpinned makes two
    ///   honest nodes disagree, which is worse. `seed` defaults to 0 rather
    ///   than being required, so the common deterministic case stays terse and
    ///   the field stays omitted-on-default in the objective's digest.
    /// - **Integers only**, for the same reason as the evaluator: IEEE-754 does
    ///   not reproduce bitwise across hosts, so a p-value must arrive scaled
    ///   (parts per million, say) and the objective statement must say so.
    ///
    /// Stage 0 admits only statistics cheap enough to re-run locally. A
    /// resampling test that needs a compute committee is Stage 2.
    fn verify_statistical(&self, spec: &Value, artifact: &Value) -> Verdict {
        let statistic = match spec.get("statistic") {
            Some(Value::Object(map)) => map,
            _ => {
                return Verdict::invalid_spec(
                    "statistical spec needs a 'statistic' object with 'path' and 'sha256'",
                )
            }
        };
        let relative = match statistic.get("path").and_then(Value::as_str) {
            Some(path) => path,
            None => return Verdict::invalid_spec("missing spec field 'statistic.path'"),
        };
        let declared = match statistic.get("sha256").and_then(Value::as_str) {
            Some(sha) => sha,
            None => return Verdict::invalid_spec("missing spec field 'statistic.sha256'"),
        };
        let entrypoint = match required_str(spec, "entrypoint") {
            Ok(entrypoint) => entrypoint,
            Err(verdict) => return verdict,
        };
        let threshold = match spec_threshold(spec) {
            Ok(threshold) => threshold,
            Err(verdict) => return verdict,
        };
        let direction = match spec_direction(spec) {
            Ok(direction) => direction,
            Err(verdict) => return verdict,
        };
        // Absent means 0, and writing `"seed": 0` must mean the same thing --
        // otherwise the two spellings would be two objectives.
        let seed = match spec.get("seed") {
            None | Some(Value::Null) => 0i64,
            Some(Value::Int(raw)) => match i64::try_from(*raw) {
                Ok(seed) => seed,
                Err(_) => {
                    return Verdict::invalid_spec(format!(
                        "seed {raw} is outside the signed 64-bit range every node can represent"
                    ))
                }
            },
            Some(_) => {
                return Verdict::invalid_spec(
                    "seed must be an integer; a seed two nodes could read differently \
                     is not a seed",
                )
            }
        };
        let timeout = match spec_timeout(spec, DEFAULT_PINNED_TIMEOUT_SECONDS) {
            Ok(timeout) => self.bounded(timeout),
            Err(verdict) => return verdict,
        };

        let path = match self.pinned("statistic", relative, declared) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        let outcome = match self.run_pinned(
            "statistic",
            &path,
            entrypoint,
            artifact,
            timeout,
            Some(seed),
        ) {
            Ok(outcome) => outcome,
            Err(verdict) => return verdict,
        };
        score_verdict(
            outcome,
            threshold,
            direction,
            "statistic",
            Value::object([
                ("statistic_sha256", Value::string(declared)),
                // Recorded so an auditor re-running this does not have to
                // guess which seed produced the number.
                ("seed", Value::Int(i128::from(seed))),
            ]),
        )
    }

    // -- lean ---------------------------------------------------------------

    /// Lean verification: the proof-assistant kernel is the arbiter.
    ///
    /// The one class of general research output where "prove things as
    /// currency" is literally rather than metaphorically true. The trust
    /// assumption is kernel soundness and nothing else -- no hardware vendor, no
    /// stake, no committee.
    ///
    /// The submitted proof text is appended to the **pinned statement from the
    /// objective**, so a submitter cannot prove a different, easier theorem and
    /// collect. If the submitter supplied both halves, the verifier would be
    /// checking a question they chose.
    ///
    /// Ordering below is deliberate and matches the reference implementation:
    /// the escape-hatch screens run *before* the toolchain lookup, so a `sorry`
    /// proof is rejected on a node with no Lean installed at all. That is sound
    /// -- the screen is a fact about the submitted text, not about this node.
    fn verify_lean(&self, spec: &Value, artifact: &Value) -> Verdict {
        let statement = match spec.get("statement").and_then(Value::as_str) {
            Some(statement) if !statement.trim().is_empty() => statement,
            _ => return Verdict::invalid_spec("lean spec needs a 'statement'"),
        };
        let proof = match artifact.get("proof").and_then(Value::as_str) {
            Some(proof) if !proof.trim().is_empty() => proof,
            _ => return Verdict::reject("artifact has no 'proof' text"),
        };

        // Fails closed: only an explicit boolean `true` opts in. The reference
        // implementation uses Python truthiness, which would let a stray `1`
        // enable `native_decide`; requiring the boolean means a malformed spec
        // gets the *stricter* treatment.
        let allow_native_decide = spec
            .get("allow_native_decide")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut screens: Vec<&Screen> = FORBIDDEN.iter().collect();
        if !allow_native_decide {
            screens.push(&NATIVE_DECIDE);
        }
        for screen in screens {
            if screen.matches(proof) {
                return Verdict::new(
                    Status::Reject,
                    screen.why,
                    Value::object([("pattern", Value::string(screen.pattern))]),
                );
            }
        }
        // The statement comes from the objective, never the submitter -- and
        // the proof is appended to it as text, so anything before the
        // proof's `:=` would continue the pinned header. ` ∨ True :=
        // Or.inr trivial` after `theorem t : 2 + 2 = 5` proves a different,
        // easier theorem, with no hole, no axiom and a clean exit. `:=` cannot
        // continue a term, so a proof that opens with it leaves the header
        // exactly as the objective wrote it.
        if !proof.trim_start().starts_with(":=") {
            return Verdict::new(
                Status::Reject,
                LEAN_PROOF_MUST_OPEN_WITH_ASSIGN,
                Value::object([("pattern", Value::string(r"^\s*:="))]),
            );
        }
        // What the compiled theorem may rest on, read from the spec before the
        // toolchain lookup like every other spec check.
        let allowed_axioms = match lean_allowed_axioms(spec, allow_native_decide) {
            Ok(allowed) => allowed,
            Err(verdict) => return verdict,
        };
        let theorem = lean_theorem_name(statement);
        // What the replay is told the statement declares. `-` for an
        // `example`, which declares nothing to hold the claim to by name.
        let theorem_arg = theorem.as_deref().unwrap_or("-");

        // `project_root` comes from the objective record -- attacker-authored,
        // like every other spec field -- and is made readable inside the jail.
        // It resolves against the bundle root and must stay inside it, exactly
        // as pinned code paths must. Screened before the toolchain lookup: a
        // malformed spec is malformed whether or not this node has Lean, and
        // the reference implementation refuses it in the same place. The
        // project itself is read-only; generated files belong in scratch.
        let project_cwd = match spec.get("project_root").and_then(Value::as_str) {
            Some(root) if !root.is_empty() => match contained_dir(&self.root, root) {
                Some(cwd) => Some(cwd),
                None => {
                    return Verdict::invalid_spec(format!(
                        "project_root escapes the objective root: {root}"
                    ))
                }
            },
            _ => None,
        };

        let binary = match which(&self.lean_binary) {
            Some(binary) => binary,
            // No toolchain is an infrastructure fact about this node. It says
            // nothing about the proof and must never settle the objective.
            None => {
                return Verdict::unavailable(format!(
                    "'{}' not on PATH; install a Lean toolchain to verify",
                    self.lean_binary
                ))
            }
        };
        let timeout = match spec_timeout(spec, DEFAULT_LEAN_TIMEOUT_SECONDS) {
            Ok(timeout) => self.bounded(timeout),
            Err(verdict) => return verdict,
        };

        let preamble = spec.get("preamble").and_then(Value::as_str).unwrap_or("");
        let workdir = match TempDir::new("proofwork-lean") {
            Ok(workdir) => workdir,
            Err(error) => {
                return Verdict::unavailable(format!("cannot create a working directory: {error}"))
            }
        };

        let cwd = project_cwd.unwrap_or_else(|| workdir.path().to_path_buf());

        // Lean elaboration runs arbitrary code (macros, tactics, elaborators),
        // and half the input is submitter-controlled, so every spawn below is
        // jailed like any other. A declared project is read-only: verifier
        // execution must not persist generated files or modify code seen by
        // later claims. The scratch directory remains the only writable
        // location, and the compiled modules and the replay live there.
        let mut plan = Confinement::new(workdir.path(), &cwd, timeout.as_secs())
            .reading(&binary)
            .scrubbed();
        if let Some(root) = &self.lean_root {
            plan = plan.reading(root);
        }
        let claim_dir = workdir.path().join("claim");
        let statement_dir = workdir.path().join("statement");
        let driver = workdir.path().join("KernelReplay.lean");
        let setup = fs::create_dir_all(&claim_dir)
            .and_then(|()| fs::create_dir_all(&statement_dir))
            .and_then(|()| fs::write(&driver, KERNEL_REPLAY.as_bytes()));
        if let Err(error) = setup {
            return Verdict::unavailable(format!("cannot prepare the Lean scratch: {error}"));
        }
        let source_name = format!("{LEAN_MODULE}.lean");
        let olean_name = format!("{LEAN_MODULE}.olean");
        let statement_olean = statement_dir.join(&olean_name);
        let compile = |dir: &Path| {
            sandbox::argv([
                OsStr::new("-R"),
                dir.as_os_str(),
                OsStr::new("-o"),
                dir.join(&olean_name).as_os_str(),
                dir.join(&source_name).as_os_str(),
            ])
        };
        let replay = |claim: &Path, marker: &str| {
            sandbox::argv([
                OsStr::new("--run"),
                driver.as_os_str(),
                claim.as_os_str(),
                statement_olean.as_os_str(),
                OsStr::new(theorem_arg),
                OsStr::new(marker),
            ])
        };
        let run = |args: Vec<OsString>| -> Result<Completed, LeanRun> {
            let jailed = sandbox::confine(&binary, &args, &plan)
                .map_err(|sandbox::Unavailable(why)| LeanRun::Jail(why))?;
            let mut command = jailed.command;
            run_bounded(&mut command, workdir.path(), None, timeout, plan.limits()).map_err(
                |failure| match failure {
                    RunFailure::TimedOut(throttled) => {
                        LeanRun::TimedOut(timeout.as_secs(), RunFailure::throttle_note(throttled))
                    }
                    RunFailure::Spawn(error) | RunFailure::Io(error) => {
                        LeanRun::Failed(error.to_string())
                    }
                },
            )
        };

        // Control before belief. Below, a non-zero exit is read as the
        // kernel's answer about the proof -- which is only true if Lean can
        // run here at all. A toolchain the jail denies (elan's under `$HOME`,
        // a `lean` whose libraries it cannot read) also exits non-zero, and
        // read as a verdict that turns "this node's Lean is broken" into
        // "your proof is wrong": the exact attack this module exists to
        // prevent. So the objective's own statement is compiled first with a
        // hole, text no submitter wrote. If that does not exit 0, nothing
        // about the proof can be learned here, and the verdict is
        // Unavailable -- whether the cause is this node's jail or a statement
        // that does not elaborate, neither of which is the proof's doing.
        //
        // That compile is also what the claim is held to: the kernel replay
        // compares the claim's declarations with it. So the control runs the
        // replay on the statement itself, which must pass and report
        // `sorryAx`: a Lean on which the replay does not run, or does not
        // read axioms, is found here as Unavailable rather than by misjudging
        // a proof. The compiled statement is remembered per process once this
        // passes, so the cost is one extra elaboration per objective rather
        // than per claim.
        let control_key = blobs::address(
            format!(
                "{}\n{}\n{}\n{}\nkernel-replay {}",
                binary.display(),
                cwd.display(),
                preamble,
                statement,
                blobs::address(KERNEL_REPLAY.as_bytes()),
            )
            .as_bytes(),
        );
        if let Some(compiled) = lean_statement_olean(&control_key) {
            if let Err(error) = fs::write(&statement_olean, compiled) {
                return Verdict::unavailable(format!(
                    "cannot write the compiled statement: {error}"
                ));
            }
        } else {
            if let Err(error) = fs::write(
                statement_dir.join(&source_name),
                format!("{preamble}\n{statement} := by sorry\n").as_bytes(),
            ) {
                return Verdict::unavailable(format!("cannot write the Lean source: {error}"));
            }
            let completed = match run(compile(&statement_dir)) {
                Ok(completed) => completed,
                Err(failure) => {
                    return failure.unavailable("compiling the objective's statement alone")
                }
            };
            match completed.code {
                Some(0) => {}
                Some(code) => {
                    let output = format!("{}{}", completed.stdout, completed.stderr);
                    return Verdict::new(
                        Status::Unavailable,
                        format!(
                            "lean could not compile the objective's statement on its own \
                             (exit {code}), so no proof can be judged here: this node's Lean \
                             does not run under its jail, or the statement does not elaborate. \
                             That is a fact about this node or the objective, not the proof"
                        ),
                        Value::object([
                            ("control_returncode", Value::Int(i128::from(code))),
                            (
                                "control_output_sha256",
                                Value::string(blobs::address(output.trim().as_bytes())),
                            ),
                            ("lean_binary", Value::string(binary.to_string_lossy())),
                        ]),
                    );
                }
                None => {
                    return Verdict::unavailable(
                        "lean was killed by a signal while compiling the objective's statement \
                         alone; that is a fact about this node, not the proof",
                    )
                }
            }
            let control_marker = audit_marker();
            let completed = match run(replay(&statement_olean, &control_marker)) {
                Ok(completed) => completed,
                Err(failure) => {
                    return failure.unavailable("replaying the objective's statement alone")
                }
            };
            let output = format!("{}{}", completed.stdout, completed.stderr);
            match read_kernel_replay(&output, &control_marker) {
                KernelReplay::Passed { axioms, .. }
                    if theorem.is_none() || axioms.iter().any(|a| a == "sorryAx") => {}
                reading => {
                    return Verdict::new(
                        Status::Unavailable,
                        "this node's Lean did not run the kernel replay on the objective's \
                         statement proved by `sorry`, or did not report it as resting on \
                         `sorryAx`, so no replay can be trusted here. That is a fact about this \
                         node's Lean, not the proof",
                        Value::object([
                            ("control_replay", Value::string(format!("{reading:?}"))),
                            (
                                "control_output_sha256",
                                Value::string(blobs::address(output.trim().as_bytes())),
                            ),
                            ("lean_binary", Value::string(binary.to_string_lossy())),
                        ]),
                    );
                }
            }
            match fs::read(&statement_olean) {
                Ok(compiled) => remember_lean_statement(&control_key, compiled),
                Err(error) => {
                    return Verdict::unavailable(format!(
                        "lean compiled the statement but left no module to replay against: {error}"
                    ))
                }
            }
        }

        if let Err(error) = fs::write(
            claim_dir.join(&source_name),
            format!("{preamble}\n{statement} {proof}\n").as_bytes(),
        ) {
            return Verdict::unavailable(format!("cannot write the Lean source: {error}"));
        }
        let completed = match run(compile(&claim_dir)) {
            Ok(completed) => completed,
            // A timeout is not a refutation. The proof may be fine and slow.
            Err(failure) => return failure.unavailable("compiling the claim"),
        };

        let output = format!("{}{}", completed.stdout, completed.stderr)
            .trim()
            .to_string();
        let evidence = Value::object([
            (
                "returncode",
                match completed.code {
                    Some(code) => Value::Int(i128::from(code)),
                    None => Value::Null,
                },
            ),
            (
                "output_sha256",
                Value::string(blobs::address(output.as_bytes())),
            ),
            ("lean_binary", Value::string(binary.to_string_lossy())),
        ]);

        match completed.code {
            // The kernel ran and said no. This is the one place a non-zero exit
            // is a real verdict rather than an infrastructure fact: the exit
            // code *is* the kernel's answer about this proof.
            Some(code) if code != 0 => {
                Verdict::new(Status::Reject, "lean rejected the proof", evidence)
            }
            // Killed by a signal: OOM, or an operator's `kill`. The reference
            // implementation reports Python's negative return code and rejects;
            // that misfiles an infrastructure failure as a statement about the
            // proof, so this port reports it as unavailable instead.
            None => Verdict::new(
                Status::Unavailable,
                "lean was killed by a signal; that is a fact about this node, not the proof",
                evidence,
            ),
            Some(_) => {
                // Lean *warns* rather than errors on a declaration that depends
                // on `sorryAx`, so a clean exit code is not sufficient. Older
                // toolchains quote the word one way and newer ones the other.
                if output.contains("declaration uses 'sorry'")
                    || output.contains("declaration uses `sorry`")
                {
                    return Verdict::new(Status::Reject, "proof depends on sorryAx", evidence);
                }
                // A clean compile is what the submitter's own code reported:
                // elaboration ran it, and it can leave a declaration in the
                // environment the kernel never saw. The replay is a process
                // that code never ran in, and its answer decides.
                let marker = audit_marker();
                let completed = match run(replay(&claim_dir.join(&olean_name), &marker)) {
                    Ok(completed) => completed,
                    Err(failure) => return failure.unavailable("replaying the claim"),
                };
                let replayed = format!("{}{}", completed.stdout, completed.stderr);
                let evidence = {
                    let mut map = evidence.as_object().cloned().unwrap_or_default();
                    map.insert(
                        "replay_output_sha256".to_string(),
                        Value::string(blobs::address(replayed.trim().as_bytes())),
                    );
                    Value::Object(map)
                };
                if completed.code.is_none() {
                    return Verdict::new(
                        Status::Unavailable,
                        "the kernel replay was killed by a signal; that is a fact about this \
                         node, not the proof",
                        evidence,
                    );
                }
                lean_replay_verdict(
                    read_kernel_replay(&replayed, &marker),
                    &allowed_axioms,
                    allow_native_decide,
                    evidence,
                )
            }
        }
    }

    /// Compile one Lean source under the jail the `lean` verifier uses, and
    /// hand back what Lean said.
    ///
    /// For an author testing a theorem before posting it -- Cairn.app's
    /// drafting sheet, whose source a language model wrote. Elaboration runs
    /// code (`#eval`, `run_cmd`, `initialize`, macros), so text nobody has
    /// read yet is compiled exactly where a submitter's would be: no
    /// network, scratch-only writes, a scrubbed environment, the operator's
    /// Lean and nothing else of theirs. Nothing here is a verdict.
    pub fn compile_lean(&self, source: &str, timeout: Duration) -> LeanCompile {
        let Some(binary) = which(&self.lean_binary) else {
            return LeanCompile::Unavailable(format!(
                "'{}' not on PATH; install a Lean toolchain",
                self.lean_binary
            ));
        };
        let timeout = self.bounded(timeout);
        let workdir = match TempDir::new("leancompile") {
            Ok(workdir) => workdir,
            Err(error) => {
                return LeanCompile::Unavailable(format!(
                    "cannot create a working directory: {error}"
                ))
            }
        };
        let file = workdir.path().join("Challenge.lean");
        if let Err(error) = fs::write(&file, source.as_bytes()) {
            return LeanCompile::Unavailable(format!("cannot write the Lean source: {error}"));
        }
        let mut plan = Confinement::new(workdir.path(), workdir.path(), timeout.as_secs())
            .reading(&binary)
            .scrubbed();
        if let Some(root) = &self.lean_root {
            plan = plan.reading(root);
        }
        let jailed = match sandbox::confine(&binary, &sandbox::argv([file.as_os_str()]), &plan) {
            Ok(jailed) => jailed,
            Err(sandbox::Unavailable(why)) => {
                return LeanCompile::Unavailable(format!("cannot jail lean: {why}"))
            }
        };
        let mut command = jailed.command;
        match run_bounded(&mut command, workdir.path(), None, timeout, plan.limits()) {
            Ok(Completed {
                code: Some(code),
                stdout,
                stderr,
            }) => LeanCompile::Ran {
                code,
                output: format!("{stdout}{stderr}")
                    .replace(&file.display().to_string(), "Challenge.lean"),
            },
            Ok(Completed { code: None, .. }) => {
                LeanCompile::Unavailable("lean was killed by a signal".to_string())
            }
            Err(RunFailure::TimedOut(throttled)) => LeanCompile::Unavailable(format!(
                "lean exceeded {}s{}",
                timeout.as_secs(),
                RunFailure::throttle_note(throttled)
            )),
            Err(RunFailure::Spawn(error)) | Err(RunFailure::Io(error)) => {
                LeanCompile::Unavailable(format!("cannot run lean: {error}"))
            }
        }
    }

    // -- replay -------------------------------------------------------------

    /// Replay verification: re-run a pinned computation and compare declared
    /// fields.
    ///
    /// For deterministic simulation and search whose output is not
    /// self-certifying. It costs a full re-run, so it is the expensive end of
    /// what this network should be doing -- but it is honest and needs no
    /// hardware attestation.
    ///
    /// Spec: `{kind, command, cwd, reproducible_fields, timeout_seconds}`. The
    /// command must print a single JSON object to stdout, and the artifact's
    /// claimed value for every declared field must match the re-run exactly.
    ///
    /// Note the asymmetry with `lean`: here a non-zero exit is `Unavailable`,
    /// not `Reject`. Lean's exit code is a verdict about the submitted proof;
    /// the replay command belongs to the *objective*, so its failure says the
    /// re-run did not happen, not that the claim is false.
    fn verify_replay(&self, spec: &Value, artifact: &Value) -> Verdict {
        let command_parts: Vec<&str> = match spec.get("command").and_then(Value::as_array) {
            Some(parts) => {
                let mut out = Vec::with_capacity(parts.len());
                for part in parts {
                    match part.as_str() {
                        Some(text) => out.push(text),
                        None => {
                            return Verdict::invalid_spec("command must be a list of strings");
                        }
                    }
                }
                out
            }
            None => return Verdict::invalid_spec("command must be a list of strings"),
        };
        // The reference implementation reaches a non-settling verdict here too,
        // by a longer route: `subprocess.run([])` raises and the dispatcher
        // catches it as UNAVAILABLE. Naming it a spec defect is more accurate --
        // an empty command is a malformed objective, not a broken node -- and
        // both statuses settle nothing, so no value moves either way.
        let program = match command_parts.first() {
            Some(program) => *program,
            None => return Verdict::invalid_spec("command must be a non-empty list of strings"),
        };

        let fields: &[Value] = match spec.get("reproducible_fields").and_then(Value::as_array) {
            Some(fields) if !fields.is_empty() => fields,
            _ => return Verdict::invalid_spec("reproducible_fields must be non-empty"),
        };
        let mut bad: Vec<String> = Vec::new();
        let mut declared_fields: Vec<&str> = Vec::with_capacity(fields.len());
        for field in fields {
            match field.as_str() {
                Some(name) if !machine_dependent(name) => declared_fields.push(name),
                Some(name) => bad.push(format!("'{name}'")),
                None => bad.push(field.canonical_string()),
            }
        }
        if !bad.is_empty() {
            return Verdict::invalid_spec(format!(
                "machine-dependent fields cannot be reproducible: [{}]. \
                 Timings and memory measure the host, not the computation.",
                bad.join(", ")
            ));
        }

        let timeout = match spec_timeout(spec, DEFAULT_REPLAY_TIMEOUT_SECONDS) {
            Ok(timeout) => self.bounded(timeout),
            Err(verdict) => return verdict,
        };

        // `cwd` comes from the objective record, and the jail ro-binds it.
        // Unconfined it reads any host directory the record names -- and any
        // declared field the command prints lands in public verdict evidence,
        // which is exfiltration with no network needed. So it resolves against
        // the bundle root and must stay inside it, the same containment pinned
        // code paths get. The reference implementation applies the identical
        // check.
        let relative = spec.get("cwd").and_then(Value::as_str).unwrap_or(".");
        let cwd = match contained_dir(&self.root, relative) {
            Some(cwd) => cwd,
            None => {
                return Verdict::invalid_spec(format!("cwd escapes the objective root: {relative}"))
            }
        };

        let workdir = match TempDir::new("proofwork-replay") {
            Ok(workdir) => workdir,
            Err(error) => {
                return Verdict::unavailable(format!("cannot create a working directory: {error}"))
            }
        };
        // Resolved here rather than left to the jail's `PATH`: bubblewrap hands
        // the child a filesystem where the operator's `PATH` mostly does not
        // exist, so a bare program name would resolve to a different binary or
        // to none at all. The lookup failure is `Unavailable` for the same
        // reason a missing interpreter is.
        let resolved = match which(program) {
            Some(resolved) => resolved,
            None => {
                return Verdict::unavailable(format!(
                    "replay command '{program}' is not on PATH; this node cannot re-run it"
                ))
            }
        };
        let rest: Vec<OsString> = sandbox::argv(command_parts.get(1..).unwrap_or(&[]));
        // The replay command is objective-authored by definition. Its `cwd` is
        // read-only: a re-run that needs to mutate the bundle it is checking
        // is not reproducible anyway. Its environment is minimal because the
        // command is objective-controlled and verdict evidence is public.
        let plan = Confinement::new(workdir.path(), &cwd, timeout.as_secs())
            .reading(&resolved)
            .reading(&self.root)
            .scrubbed();
        let jailed = match sandbox::confine(&resolved, &rest, &plan) {
            Ok(jailed) => jailed,
            Err(sandbox::Unavailable(why)) => {
                return Verdict::unavailable(format!("cannot jail the replay command: {why}"))
            }
        };
        let mut command = jailed.command;

        let completed =
            match run_bounded(&mut command, workdir.path(), None, timeout, plan.limits()) {
                Ok(completed) => completed,
                Err(RunFailure::TimedOut(throttled)) => {
                    return Verdict::unavailable(format!(
                        "replay exceeded {}s{}; a timeout is not a refutation",
                        timeout.as_secs(),
                        RunFailure::throttle_note(throttled)
                    ))
                }
                Err(RunFailure::Spawn(error)) | Err(RunFailure::Io(error)) => {
                    return Verdict::unavailable(format!("cannot run replay command: {error}"))
                }
            };

        if completed.code != Some(0) {
            let code = match completed.code {
                Some(code) => code.to_string(),
                None => "on a signal".to_string(),
            };
            return Verdict::new(
                Status::Unavailable,
                format!(
                    "replay command exited {code}; infrastructure failure is not \
                     evidence about the artifact"
                ),
                Value::object([(
                    "stderr_sha256",
                    Value::string(blobs::address(completed.stderr.as_bytes())),
                )]),
            );
        }

        // Parsed with the permissive JSON reader, not the canonical one: an
        // *undeclared* float somewhere in the output is none of our business.
        // Declared fields are converted individually below, where a float is a
        // spec defect because it cannot be compared reproducibly.
        let parsed: serde_json::Value = match serde_json::from_str(completed.stdout.trim()) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Verdict::unavailable(format!("replay output is not JSON: {error}"))
            }
        };
        let observed = match parsed.as_object() {
            Some(observed) => observed,
            None => return Verdict::unavailable("replay output is not a JSON object"),
        };

        let claimed = match artifact.get("results") {
            Some(Value::Object(claimed)) => claimed.clone(),
            _ => return Verdict::reject("artifact has no 'results' object"),
        };

        let mut mismatches: BTreeMap<String, Value> = BTreeMap::new();
        let mut reproduced: Vec<String> = Vec::new();
        for name in declared_fields.iter().copied() {
            let raw = match observed.get(name) {
                Some(raw) => raw,
                // The objective declared a field its own command does not
                // print. Nothing was compared, so nothing is settled.
                None => {
                    return Verdict::unavailable(format!(
                        "replay output is missing declared field '{name}'"
                    ))
                }
            };
            let seen = match canonicalize(raw) {
                Ok(seen) => seen,
                Err(why) => {
                    return Verdict::invalid_spec(format!(
                        "declared field '{name}' is not canonically comparable ({why}); \
                         a value two honest nodes could render differently cannot be \
                         a reproducible field"
                    ))
                }
            };
            let claim = claimed.get(name).cloned().unwrap_or(Value::Null);
            if claim == seen {
                reproduced.push(name.to_string());
            } else {
                mismatches.insert(
                    name.to_string(),
                    Value::object([
                        ("claimed_sha256", Value::string(claim.digest())),
                        ("observed_sha256", Value::string(seen.digest())),
                    ]),
                );
            }
        }

        if !mismatches.is_empty() {
            return Verdict::new(
                Status::Reject,
                "replay disagrees with the claim",
                Value::object([("mismatches", Value::Object(mismatches))]),
            );
        }
        Verdict::new(
            Status::Accept,
            format!(
                "replay reproduced {} declared field(s)",
                declared_fields.len()
            ),
            Value::object([(
                "reproduced_fields",
                Value::array(reproduced.into_iter().map(Value::string)),
            )]),
        )
    }

    // -- pinned code --------------------------------------------------------

    /// Resolve a pinned source file and verify its hash **before** it runs.
    ///
    /// Checkers and evaluators are ordinary source files pinned by SHA-256. The
    /// hash is part of the objective's identity, so editing an evaluator does
    /// not silently rescore an objective -- it forks it into a different
    /// objective, and the old one now fails this check.
    ///
    /// Three failure modes, two statuses:
    ///
    /// - a path that escapes the root, or a hash that does not match with no
    ///   correct copy available anywhere, means the objective is broken:
    ///   `InvalidSpec`. A tampered checker is never run.
    /// - code this node cannot obtain — no bundle file *and* no blob — means
    ///   this node cannot verify: `Unavailable`. It says nothing about the
    ///   artifact, and a peer can fix it by sending the blob.
    ///
    /// Both sides of the lexical containment check are made absolute first. An
    /// existing bundle file is then resolved through the filesystem before it is
    /// read or executed. The second step is what makes an in-root symlink unable
    /// to select a host file.
    fn pinned(
        &self,
        role: &str,
        relative: &str,
        declared_sha256: &str,
    ) -> Result<PathBuf, Verdict> {
        self.resolve_pinned(relative, declared_sha256)
            .map_err(|failure| match failure {
                PinFailure::Escape => Verdict::invalid_spec(format!(
                    "pinned path escapes the objective root: {relative}"
                )),
                // Wording unchanged from before the blob store: an operator who
                // edited a checker in place needs this diagnostic, and a cached
                // blob must not rescue (or rephrase) the mismatch.
                PinFailure::Mismatch { actual } => Verdict::invalid_spec(format!(
                    "pinned code {relative} has sha256 {actual}, objective declares \
                     {declared_sha256}"
                )),
                PinFailure::Absent { detail } => {
                    Verdict::unavailable(format!("cannot load {role}: {detail}"))
                }
            })
    }

    /// Whether this node can obtain the bytes behind a pin, and if not, why.
    ///
    /// Split out from `VerifierRegistry::pinned` so the wire protocol can ask
    /// "which blobs am I missing" using the *same* resolution the verifier will
    /// use. Two implementations of that question would eventually disagree, and
    /// the failure would be a node that fetches nothing while reporting
    /// `Unavailable` forever.
    fn resolve_pinned(&self, relative: &str, declared: &str) -> Result<PathBuf, PinFailure> {
        let root = absolutize(&self.root).map_err(|error| PinFailure::Absent {
            detail: format!("cannot resolve the objective root: {error}"),
        })?;
        let full = absolutize(&root.join(relative)).map_err(|error| PinFailure::Absent {
            detail: format!("cannot resolve the pinned path: {error}"),
        })?;
        // Component-wise, so `/objective-root-evil` does not count as being
        // inside `/objective-root` the way a string prefix test would.
        //
        // Checked before the store is consulted, and that order is deliberate:
        // a pin whose path leaves the bundle is a malformed objective, and
        // content-addressing must not rescue it. Otherwise an objective could
        // name `../../.ssh/id_rsa` with a matching hash, get refused today, and
        // start resolving tomorrow the moment somebody's node happened to hold a
        // blob under that address.
        if !full.starts_with(&root) {
            return Err(PinFailure::Escape);
        }

        // The content-addressed fallback, and the reason this module exists: a
        // peer that learned the objective over the wire has no bundle file at
        // all. Keep it available for any failure to resolve or read the bundle
        // origin, while never allowing it to rescue an escaped path.
        let blob_fallback =
            |origin_error: io::Error| match self.blobs.read(declared) {
                Ok(_) => absolutize(&self.blobs.path_of(declared).map_err(|error| {
                    PinFailure::Absent {
                        detail: error.to_string(),
                    }
                })?)
                .map_err(|error| PinFailure::Absent {
                    detail: format!("cannot resolve the blob store path: {error}"),
                }),
                Err(store) => Err(PinFailure::Absent {
                    detail: format!("{origin_error} ({}); {store}", full.display()),
                }),
            };

        // Resolve containment before reading. Reading first and rejecting the
        // canonical path afterwards would still touch an attacker-selected host
        // file (or device), even if its bytes never reached the verifier.
        let canonical_full = match fs::canonicalize(&full) {
            Ok(path) => path,
            Err(error) => return blob_fallback(error),
        };
        let canonical_root = fs::canonicalize(&root).map_err(|error| PinFailure::Absent {
            detail: format!("cannot canonicalize the objective root: {error}"),
        })?;
        if !canonical_full.starts_with(&canonical_root) {
            return Err(PinFailure::Escape);
        }

        // The bundle is the origin. Consulted first so that an operator who
        // edits a checker in place is told their edit no longer matches the pin,
        // rather than having a cached blob silently stand in for the file they
        // are looking at. Mismatch returns immediately; the store is only for
        // peers that have no readable bundle file at all.
        let source = match fs::read(&canonical_full) {
            Ok(source) => source,
            Err(error) => return blob_fallback(error),
        };
        let actual = blobs::address(&source);
        if actual == declared {
            // Preserve the canonical bundle location: Python checkers may
            // deliberately read adjacent state, and audits rely on `__file__`
            // naming that directory.
            Ok(canonical_full)
        } else {
            Err(PinFailure::Mismatch { actual })
        }
    }

    /// The content addresses of pinned code this node cannot currently obtain.
    ///
    /// Empty for a spec whose code resolves, for a kind with no pinned code, and
    /// for a pin whose path escapes the root — the last because such an
    /// objective is broken and fetching its blob would not make it runnable, so
    /// asking peers for it is pure noise.
    pub fn missing_code(&self, spec: &Value) -> Vec<String> {
        let mut out = Vec::new();
        for pin in pinned_code(spec) {
            if !blobs::is_address(&pin.sha256) {
                continue;
            }
            match self.resolve_pinned(&pin.path, &pin.sha256) {
                Ok(_) | Err(PinFailure::Escape) => {}
                Err(_) => out.push(pin.sha256),
            }
        }
        out
    }

    /// Copy every pinned file this bundle actually has into the blob store, so
    /// this node can serve it.
    ///
    /// Best effort by construction, and it must stay that way: this runs when an
    /// objective is admitted, and objectives are admitted during record sync by
    /// nodes that have never seen the bundle. Returning an error there would
    /// make a node refuse to import a peer's objective because it could not
    /// cache code it was never given — sync would stop, silently, exactly the
    /// class of bug this repository warns about.
    ///
    /// Returns the addresses now servable from this node.
    pub fn publish_code(&self, spec: &Value) -> Vec<String> {
        let mut published = Vec::new();
        for pin in pinned_code(spec) {
            if !blobs::is_address(&pin.sha256) {
                continue;
            }
            // Use the same symlink-aware containment and hash check execution
            // uses. A publisher must not turn an in-bundle symlink into a way
            // to read and distribute an arbitrary host file. The resolved path
            // can be either the bundle origin or an existing store entry;
            // `put` validates either before it is advertised.
            let Ok(path) = self.resolve_pinned(&pin.path, &pin.sha256) else {
                continue;
            };
            let Ok(source) = fs::read(path) else {
                continue;
            };
            if self.blobs.put(&pin.sha256, &source).is_ok() {
                published.push(pin.sha256);
            }
        }
        published
    }

    /// Admit a blob offered by a peer, or say why not.
    ///
    /// The verification is [`BlobStore::put`]'s: bytes that do not hash to the
    /// address never reach a filename under which they could be run. Whether the
    /// address was one this node *asked for* is a separate check, made by
    /// [`crate::p2p::code::admit`] against the want set, because that is where
    /// the want set lives and a disk filled with unrequested blobs is a
    /// different problem from a blob that lies about its hash.
    pub fn admit_code(&self, declared: &str, bytes: &[u8]) -> Result<(), blobs::BlobError> {
        self.blobs.put(declared, bytes).map(|_| ())
    }

    /// The interpreter a pinned `role` runs under, or the `Unavailable`
    /// verdict that says why there is none here.
    ///
    /// A shim on `PATH` used to be found, jailed, and run, and to exit 126
    /// (127 under bubblewrap) on every pinned check, with nothing in the
    /// verdict to say the interpreter was the problem. It is refused here instead, before
    /// anything is spawned, with the fix in the detail. Still `Unavailable`:
    /// which `python3` this node has is a fact about the node.
    fn pinned_interpreter(
        &self,
        role: &str,
        mechanism: sandbox::Mechanism,
    ) -> Result<PathBuf, Verdict> {
        let Some(interpreter) = which(&self.python_binary) else {
            return Err(Verdict::unavailable(format!(
                "'{}' not on PATH; the pinned {role} cannot be run here",
                self.python_binary
            )));
        };
        match self.python_refusal(&interpreter, mechanism.is_jail()) {
            None => Ok(interpreter),
            Some(why) => Err(Verdict::new(
                Status::Unavailable,
                format!("cannot jail the pinned {role}: {why}"),
                Value::object([("sandbox", Value::string(mechanism.as_str()))]),
            )),
        }
    }

    /// Run pinned code in a jailed child process and collect its single JSON
    /// result.
    ///
    /// Every failure here is `Unavailable`: a missing interpreter, a jail that
    /// will not start, a crashed checker, a checker that ran past its deadline,
    /// output that is not a JSON object. None of those are facts about the
    /// artifact. The one thing this function does *not* decide is whether the
    /// returned value has the right shape -- that is the caller's job, and it
    /// is `InvalidSpec`, because a checker returning the wrong type is a broken
    /// objective.
    ///
    /// `seed` is passed to the entrypoint as a second argument when present.
    /// Only the `statistical` kind supplies one.
    fn run_pinned(
        &self,
        role: &str,
        path: &Path,
        entrypoint: &str,
        artifact: &Value,
        timeout: Duration,
        seed: Option<i64>,
    ) -> Result<Harvest, Verdict> {
        let interpreter = self.pinned_interpreter(role, sandbox::mechanism())?;
        let workdir = match TempDir::new("proofwork-pinned") {
            Ok(workdir) => workdir,
            Err(error) => {
                return Err(Verdict::unavailable(format!(
                    "cannot create a working directory: {error}"
                )))
            }
        };

        let mut args: Vec<OsString> = sandbox::argv(["-c", HARNESS]);
        args.push(path.as_os_str().to_os_string());
        args.push(OsString::from(entrypoint));
        if let Some(seed) = seed {
            args.push(OsString::from(seed.to_string()));
        }

        // A pinned checker is a pure function of the artifact: it needs the
        // interpreter, its own source, and nothing else. This is the one spawn
        // path where the full jail costs nothing, so it gets all of it --
        // scrubbed environment and an address-space cap included.
        let mut plan = Confinement::new(workdir.path(), workdir.path(), timeout.as_secs())
            .reading(&interpreter)
            .reading(path)
            .scrubbed()
            .capped_memory();
        if let Some(root) = &self.python_root {
            plan = plan.reading(root);
        }
        let jailed = match sandbox::confine(&interpreter, &args, &plan) {
            Ok(jailed) => jailed,
            Err(sandbox::Unavailable(why)) => {
                return Err(Verdict::unavailable(format!(
                    "cannot jail the pinned {role}: {why}"
                )))
            }
        };
        let mechanism = jailed.mechanism;
        let mut command = jailed.command;

        let stdin = artifact.canonical_bytes();
        let completed = match run_bounded(
            &mut command,
            workdir.path(),
            Some(stdin.as_slice()),
            timeout,
            plan.limits(),
        ) {
            Ok(completed) => completed,
            Err(RunFailure::TimedOut(throttled)) => {
                return Err(Verdict::unavailable(format!(
                    "pinned {role} exceeded {}s{}; a timeout is not a refutation",
                    timeout.as_secs(),
                    RunFailure::throttle_note(throttled)
                )))
            }
            Err(RunFailure::Spawn(error)) | Err(RunFailure::Io(error)) => {
                return Err(Verdict::unavailable(format!(
                    "cannot run {role} under the {mechanism} jail: {error}"
                )))
            }
        };

        if completed.code != Some(0) {
            let code = match completed.code {
                Some(code) => code.to_string(),
                None => "on a signal".to_string(),
            };
            return Err(Verdict::new(
                Status::Unavailable,
                format!(
                    "pinned {role} exited {code}; a crashed verifier is unavailable, \
                     not a rejection"
                ),
                Value::object([
                    (
                        "stderr_sha256",
                        Value::string(blobs::address(completed.stderr.as_bytes())),
                    ),
                    ("sandbox", Value::string(mechanism)),
                ]),
            ));
        }

        match parse_harvest(&completed.stdout) {
            Some(harvest) => Ok(harvest),
            None => Err(Verdict::new(
                Status::Unavailable,
                format!("pinned {role} did not print a result object this node can read"),
                Value::object([
                    (
                        "stdout_sha256",
                        Value::string(blobs::address(completed.stdout.as_bytes())),
                    ),
                    (
                        "stderr_sha256",
                        Value::string(blobs::address(completed.stderr.as_bytes())),
                    ),
                    ("sandbox", Value::string(mechanism)),
                ]),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Harness result handling
// ---------------------------------------------------------------------------

/// What the harness printed, before it is interpreted per verifier kind.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Harvest {
    /// `check` returned a bool, or a tuple whose first element is a bool.
    Boolean { ok: bool, detail: String },
    /// `score` returned an integer.
    Score(i128),
    /// `score` returned an integer too large to represent. Python has bignums;
    /// the canonical record format stops at signed 128 bits.
    ScoreOutOfRange(String),
    /// The entrypoint returned something of the wrong type; carries the Python
    /// type name so the verdict can say which.
    BadReturn(String),
    /// The entrypoint returned a dict or a list.
    ///
    /// Still an error for all five verifier kinds, and `type_name` exists so
    /// the diagnostic reads exactly as [`Harvest::BadReturn`]'s used to. It has
    /// a variant of its own because a *stepper* returns one on purpose, and
    /// re-parsing a discarded type name out of an error string would be the
    /// worse of the two designs. `raw` is the JSON text, unparsed: a state
    /// containing a float is refusable rather than silently rounded, and the
    /// refusal belongs at the call site that knows what it asked for.
    Json { raw: String, type_name: String },
}

fn parse_harvest(stdout: &str) -> Option<Harvest> {
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    let map = parsed.as_object()?;
    if let Some(name) = map.get("bad_return").and_then(|value| value.as_str()) {
        return Some(Harvest::BadReturn(name.to_string()));
    }
    if let Some(value) = map.get("value") {
        let type_name = map
            .get("value_type")
            .and_then(|value| value.as_str())
            .unwrap_or("object")
            .to_string();
        return Some(Harvest::Json {
            raw: value.to_string(),
            type_name,
        });
    }
    if let Some(ok) = map.get("ok").and_then(|value| value.as_bool()) {
        let detail = map
            .get("detail")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        return Some(Harvest::Boolean { ok, detail });
    }
    if let Some(serde_json::Value::Number(number)) = map.get("score") {
        // `arbitrary_precision` keeps the number as its original text, so a
        // bignum is distinguishable from a float instead of silently becoming
        // one. Both are refused; see the evaluator docs for why.
        let raw = number.to_string();
        if raw.contains('.') || raw.contains('e') || raw.contains('E') {
            return Some(Harvest::BadReturn("float".to_string()));
        }
        return Some(match raw.parse::<i128>() {
            Ok(score) => Harvest::Score(score),
            Err(_) => Harvest::ScoreOutOfRange(raw),
        });
    }
    None
}

/// Turn a scoring verifier's result into a verdict.
///
/// Shared by `evaluator` and `statistical`, which differ only in what they call
/// the pinned file and what they add to the evidence. Split out from the
/// verifiers so the arithmetic edge cases are testable without spawning an
/// interpreter.
///
/// `role` names the pinned file in diagnostics; `extra` is folded into the
/// evidence alongside the score. The `score` key stays where it is regardless:
/// [`crate::frontier`] reads it from there.
fn score_verdict(
    outcome: Harvest,
    threshold: i64,
    direction: Direction,
    role: &str,
    extra: Value,
) -> Verdict {
    let score = match outcome {
        Harvest::Score(score) => match i64::try_from(score) {
            Ok(score) => score,
            // The frontier records scores as i64. An evaluator producing
            // something that cannot be recorded is an evaluator no node can use.
            Err(_) => {
                return Verdict::invalid_spec(format!(
                    "{role} returned {score}, outside the signed 64-bit range the \
                     frontier records scores in"
                ))
            }
        },
        Harvest::ScoreOutOfRange(raw) => {
            return Verdict::invalid_spec(format!(
                "{role} returned {raw}, outside the range any node can record"
            ))
        }
        // `True` in Python is an `int`, so this is a real failure mode rather
        // than a hypothetical one, and it must not score as 1.
        Harvest::Boolean { .. } => {
            return Verdict::invalid_spec(format!(
                "{role} returned bool; scores must be int so every node agrees on \
                 the comparison"
            ))
        }
        Harvest::BadReturn(kind)
        | Harvest::Json {
            type_name: kind, ..
        } => {
            return Verdict::invalid_spec(format!(
                "{role} returned {kind}; scores must be int so every node agrees on \
                 the comparison"
            ))
        }
    };

    let met = direction.clears(score, threshold);
    let mut evidence = BTreeMap::from([
        // The ratchet reads the score from here. Keep the key stable.
        ("score".to_string(), Value::Int(i128::from(score))),
        ("threshold".to_string(), Value::Int(i128::from(threshold))),
        ("direction".to_string(), Value::string(direction.as_str())),
    ]);
    if let Value::Object(more) = extra {
        evidence.extend(more);
    }
    Verdict::new(
        if met { Status::Accept } else { Status::Reject },
        format!("score {score} vs threshold {threshold} ({direction})"),
        Value::Object(evidence),
    )
}

// ---------------------------------------------------------------------------
// Spec helpers
// ---------------------------------------------------------------------------

fn required_str<'a>(spec: &'a Value, key: &str) -> Result<&'a str, Verdict> {
    match spec.get(key).and_then(Value::as_str) {
        Some(value) => Ok(value),
        None => Err(Verdict::invalid_spec(format!("missing spec field '{key}'"))),
    }
}

/// The integer rejection threshold shared by `evaluator` and `statistical`.
///
/// `Value::Bool` is not `Value::Int`, so the reference implementation's
/// explicit `isinstance(threshold, bool)` guard is structural here.
fn spec_threshold(spec: &Value) -> Result<i64, Verdict> {
    match spec.get("threshold") {
        Some(Value::Int(raw)) => i64::try_from(*raw).map_err(|_| {
            Verdict::invalid_spec(format!(
                "threshold {raw} is outside the signed 64-bit range scores are recorded in"
            ))
        }),
        _ => Err(Verdict::invalid_spec(
            "threshold must be an integer (scale fractional scores)",
        )),
    }
}

fn spec_direction(spec: &Value) -> Result<Direction, Verdict> {
    match spec.get("direction") {
        None => Ok(Direction::Maximize),
        Some(Value::String(text)) => Direction::parse(text).ok_or_else(|| {
            Verdict::invalid_spec("direction must be one of (\"maximize\", \"minimize\")")
        }),
        Some(_) => Err(Verdict::invalid_spec(
            "direction must be one of (\"maximize\", \"minimize\")",
        )),
    }
}

/// Read `timeout_seconds`, falling back to `default`.
///
/// A malformed timeout is `InvalidSpec` rather than a silent default: the
/// deadline is part of what an objective promises its verifiers, and quietly
/// substituting our own would make two nodes disagree about whether a slow
/// artifact times out.
fn spec_timeout(spec: &Value, default: u64) -> Result<Duration, Verdict> {
    let seconds = match spec.get("timeout_seconds") {
        None | Some(Value::Null) => default,
        Some(Value::Int(raw)) => match u64::try_from(*raw) {
            Ok(seconds) if seconds > 0 && seconds <= MAX_TIMEOUT_SECONDS => seconds,
            _ => {
                return Err(Verdict::invalid_spec(format!(
                    "timeout_seconds must be a positive integer no greater than \
                     {MAX_TIMEOUT_SECONDS}"
                )))
            }
        },
        Some(_) => {
            return Err(Verdict::invalid_spec(
                "timeout_seconds must be a positive integer",
            ))
        }
    };
    Ok(Duration::from_secs(seconds))
}

fn machine_dependent(field: &str) -> bool {
    let lowered = field.to_ascii_lowercase();
    TIME_LIKE.iter().any(|token| lowered.contains(*token))
}

/// Convert one permissively-parsed JSON value into a canonical one.
///
/// Goes through text rather than reaching into the canonical module's internals,
/// which keeps the float and integer-range rules in exactly one place.
fn canonicalize(value: &serde_json::Value) -> Result<Value, String> {
    let text = serde_json::to_string(value).map_err(|error| error.to_string())?;
    Value::from_json(&text).map_err(|error| error.to_string())
}

impl Screen {
    /// Word-boundary matching, implemented by hand because no regex crate is
    /// available (and because a regex engine on submitter-controlled text is
    /// itself an attack surface).
    ///
    /// A match is the token with non-word neighbours, where a word byte is
    /// ASCII alphanumeric or `_`. Bytes above 0x7f count as *non*-word, which
    /// differs from Python's Unicode-aware `\b`: the difference can only make
    /// the screen fire more often, never less. That direction is the safe one --
    /// an over-eager screen rejects a proof that could be rewritten, while an
    /// under-eager one accepts a `sorry` and mints money for nothing.
    fn matches(&self, text: &str) -> bool {
        if self.whole_word {
            contains_word(text, self.token)
        } else {
            text.contains(self.token)
        }
    }
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    let hay = haystack.as_bytes();
    let ndl = needle.as_bytes();
    if ndl.is_empty() || ndl.len() > hay.len() {
        return false;
    }
    let last_start = hay.len() - ndl.len();
    let mut start = 0usize;
    while start <= last_start {
        let end = start + ndl.len();
        if &hay[start..end] == ndl {
            let left_clear = start == 0 || !is_word_byte(hay[start - 1]);
            let right_clear = end == hay.len() || !is_word_byte(hay[end]);
            if left_clear && right_clear {
                return true;
            }
        }
        start += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Lexical normalization: drop `.`, resolve `..` textually, never touch the
/// filesystem.
///
/// Deliberately not [`fs::canonicalize`] at this first stage: missing checker
/// paths must remain eligible for the content-addressed fallback. Existing
/// files and directories receive a second, symlink-resolving containment check
/// before they are read, mounted, or executed.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(std::path::MAIN_SEPARATOR_STR),
            Component::CurDir => {}
            Component::ParentDir => {
                // Both tests finish borrowing `out` before it is mutated.
                let tail_is_normal =
                    matches!(out.components().next_back(), Some(Component::Normal(_)));
                let at_root = matches!(
                    out.components().next_back(),
                    Some(Component::RootDir) | Some(Component::Prefix(_))
                );
                if tail_is_normal {
                    out.pop();
                } else if !at_root {
                    // `..` at the root is the root, as in every OS and in
                    // Python's `os.path.normpath`; anywhere else a leading `..`
                    // has to survive, since there is nothing to cancel it with.
                    out.push("..");
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Absolute, normalized, and symlink-preserving -- Python's `os.path.abspath`.
fn absolutize(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(normalize(path))
    } else {
        Ok(normalize(&std::env::current_dir()?.join(path)))
    }
}

/// Resolve an objective-authored directory against the bundle root, refusing
/// escapes -- the same containment [`VerifierRegistry::resolve_pinned`]
/// applies to pinned code, for the same reason.
///
/// A spec field must never choose a host path: these directories are handed to
/// the jail as readable roots, so an uncontained one exposes whatever the
/// record names -- `"/"` included. `Path::join` replaces the root when the
/// field is absolute, and the `starts_with` below is component-wise, so both
/// the absolute and the `../` spellings land in `None`.
fn contained_dir(root: &Path, relative: &str) -> Option<PathBuf> {
    let lexical_root = absolutize(root).ok()?;
    let lexical_full = absolutize(&lexical_root.join(relative)).ok()?;
    if !lexical_full.starts_with(&lexical_root) {
        return None;
    }
    let canonical_root = fs::canonicalize(&lexical_root).ok()?;
    let canonical_full = fs::canonicalize(&lexical_full).ok()?;
    (canonical_full.is_dir() && canonical_full.starts_with(&canonical_root))
        .then_some(canonical_full)
}

/// `shutil.which`, minus the Windows extension handling.
///
/// A name containing a separator is taken as a path and checked directly;
/// anything else is searched for on `PATH`. Returning `None` is what turns a
/// missing toolchain into `Unavailable` instead of a rejection, so this is a
/// security-relevant function despite looking like plumbing.
/// Statements whose control passed in this process, compiled, by the key
/// `verify_lean` builds from the binary, cwd, preamble, statement and replay
/// driver. A failed control is never remembered: a toolchain installed, or a
/// jail fixed, after the first claim is found by the next one. Bounded: a
/// compiled statement is the module's own declarations, a few kilobytes, and
/// past the bound the oldest key is dropped and simply compiled again.
fn lean_statements() -> &'static std::sync::Mutex<BTreeMap<String, Vec<u8>>> {
    static STATEMENTS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, Vec<u8>>>> =
        std::sync::OnceLock::new();
    STATEMENTS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Most compiled statements [`lean_statements`] keeps.
const MAX_LEAN_STATEMENTS: usize = 256;

fn lean_statement_olean(key: &str) -> Option<Vec<u8>> {
    lean_statements()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(key)
        .cloned()
}

fn remember_lean_statement(key: &str, compiled: Vec<u8>) {
    let mut statements = lean_statements()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if statements.len() >= MAX_LEAN_STATEMENTS && !statements.contains_key(key) {
        if let Some(first) = statements.keys().next().cloned() {
            statements.remove(&first);
        }
    }
    statements.insert(key.to_string(), compiled);
}

/// Why one jailed Lean run produced no output to judge.
enum LeanRun {
    Jail(String),
    TimedOut(u64, String),
    Failed(String),
}

impl LeanRun {
    /// Unavailable, always: none of these is the proof's doing.
    fn unavailable(self, doing: &str) -> Verdict {
        match self {
            LeanRun::Jail(why) => Verdict::unavailable(format!("cannot jail lean: {why}")),
            LeanRun::TimedOut(seconds, note) => Verdict::unavailable(format!(
                "lean exceeded {seconds}s {doing}{note}; timeout is not a refutation"
            )),
            LeanRun::Failed(error) => {
                Verdict::unavailable(format!("cannot run lean ({doing}): {error}"))
            }
        }
    }
}

/// `<binary> --version`'s first line, asked once per resolved path for the
/// life of the process. `None` when the program would not run or printed
/// nothing. Both `lean` and `python3` answer this flag on stdout in one line.
fn version_of(binary: &Path) -> Option<String> {
    use std::sync::{Mutex, OnceLock};
    static VERSIONS: OnceLock<Mutex<BTreeMap<PathBuf, Option<String>>>> = OnceLock::new();
    let cache = VERSIONS.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(known) = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(binary)
    {
        return known.clone();
    }
    let probed = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let text = String::from_utf8_lossy(&output.stdout);
            let line = text.lines().next().unwrap_or("").trim().to_string();
            if line.is_empty() {
                None
            } else {
                Some(line)
            }
        });
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(binary.to_path_buf(), probed.clone());
    probed
}

fn which(binary: &str) -> Option<PathBuf> {
    if binary.is_empty() {
        return None;
    }
    if binary.contains('/') || binary.contains(std::path::MAIN_SEPARATOR) {
        let candidate = Path::new(binary);
        return if is_executable_file(candidate) {
            Some(candidate.to_path_buf())
        } else {
            None
        };
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(binary);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

// ---------------------------------------------------------------------------
// Subprocess execution with a wall-clock bound
// ---------------------------------------------------------------------------

/// A scratch directory removed on drop, including on an early return.
///
/// `std` has no `tempfile`, and the dependency list is closed. This is the
/// minimum that is correct: a unique name, private permissions on unix, and
/// cleanup in `Drop` so no error path leaks a directory.
#[derive(Debug)]
struct TempDir {
    path: PathBuf,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    fn new(prefix: &str) -> io::Result<TempDir> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        for attempt in 0..64u32 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = base.join(format!("{prefix}-{pid}-{nanos}-{counter}-{attempt}"));
            match create_private_dir(&candidate) {
                Ok(()) => return Ok(TempDir { path: candidate }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort: a failure to clean up must not panic in library code,
        // and it must not mask the verdict being returned.
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().create(path)
}

/// What [`VerifierRegistry::compile_lean`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanCompile {
    /// Lean ran to an exit code; `output` is what it printed.
    Ran { code: i32, output: String },
    /// Lean could not be run here, for the reason given.
    Unavailable(String),
}

/// What a finished child produced. `code` is `None` if it died on a signal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Completed {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
enum RunFailure {
    /// The child never started -- usually a missing binary.
    Spawn(io::Error),
    /// The plumbing around the child failed.
    Io(io::Error),
    /// The child outlived its deadline and was killed. Carries the CPU cap
    /// and how long it held the child, if it ever did.
    TimedOut(Option<(u32, Duration)>),
}

impl RunFailure {
    /// What to add to a timeout's message when this node's own CPU cap spent
    /// part of the deadline. Empty otherwise, so an uncapped node's messages
    /// read exactly as they always have.
    fn throttle_note(throttled: Option<(u32, Duration)>) -> String {
        match throttled {
            Some((cpus, paused)) => format!(
                " (this node's CPU cap of {cpus} core{}, {}, paused it for {}s of that)",
                if cpus == 1 { "" } else { "s" },
                limits::CPUS_ENV,
                paused.as_secs()
            ),
            None => String::new(),
        }
    }
}

/// Run a child under a wall-clock bound.
///
/// `std` has no subprocess timeout, so this spawns the child and polls
/// [`std::process::Child::try_wait`] until the deadline, then kills and reaps
/// it. Two details are not optional:
///
/// - **Streams go to files in `workdir`, not to pipes.** A child that fills a
///   pipe buffer nobody is draining blocks forever, which would turn a chatty
///   checker into a guaranteed timeout. Files never block, and this avoids
///   needing reader threads to be correct.
/// - **The killed child is waited on.** Skipping the reap leaves a zombie for
///   every timeout, and a node verifies continuously.
///
/// Elapsed time is measured with [`Instant::elapsed`] rather than by adding a
/// `Duration` to an `Instant`, because that addition panics on overflow and
/// library code here does not panic.
///
/// `limits` is what the same loop holds the child's process tree to while it
/// waits: a CPU cap and, on macOS, a memory cap. See [`limits`].
fn run_bounded(
    command: &mut Command,
    workdir: &Path,
    stdin: Option<&[u8]>,
    timeout: Duration,
    limits: limits::Limits,
) -> Result<Completed, RunFailure> {
    let out_path = workdir.join("stdout");
    let err_path = workdir.join("stderr");
    let capture = |path: &Path| {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    };
    let out_file = capture(&out_path).map_err(RunFailure::Io)?;
    let err_file = capture(&err_path).map_err(RunFailure::Io)?;
    // Keep parent-owned handles to the exact inodes we created. The child owns
    // `workdir` and can replace `stdout` or `stderr` with a symlink while it
    // runs; reopening either pathname afterwards would make the unsandboxed
    // parent follow that link and read a host file on the child's behalf.
    let out_child = out_file.try_clone().map_err(RunFailure::Io)?;
    let err_child = err_file.try_clone().map_err(RunFailure::Io)?;

    match stdin {
        Some(bytes) => {
            let in_path = workdir.join("stdin");
            fs::write(&in_path, bytes).map_err(RunFailure::Io)?;
            let in_file = fs::File::open(&in_path).map_err(RunFailure::Io)?;
            command.stdin(Stdio::from(in_file));
        }
        None => {
            // Never inherit this process's stdin: a child that reads from the
            // terminal would hang the node until its deadline.
            command.stdin(Stdio::null());
        }
    }
    command.stdout(Stdio::from(out_child));
    command.stderr(Stdio::from(err_child));

    // Its own process group, so the deadline can take out whatever the child
    // spawned rather than only the child. Under bubblewrap `--unshare-pid`
    // already does this; seatbelt and the no-jail fallback have no pid
    // namespace, so without it a checker that forks and exits leaves its
    // children running past the timeout with nothing watching them.
    #[cfg(unix)]
    let command = {
        use std::os::unix::process::CommandExt;
        // Safety: `setpgid(0, 0)` between fork and exec is async-signal-safe.
        // It touches no allocator and no lock, which is the whole constraint
        // on a pre_exec closure.
        unsafe { command.pre_exec(crate::verifiers::setpgid_self) }
    };

    let mut child = command.spawn().map_err(RunFailure::Spawn)?;
    let started = Instant::now();
    // Released (anything it stopped, continued) before every kill below, so a
    // descendant outside the group that the kill misses is not also left
    // frozen; and on drop, for every other way out of this function.
    let mut watch = limits::Watch::new(limits, child.id());
    let mut over_cap = false;
    let mut breach = None;
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let throttled = watch.throttled();
                    watch.release();
                    reap(&mut child);
                    return Err(RunFailure::TimedOut(throttled));
                }
                // A checker that prints for its whole CPU budget fills the
                // operator's disk. Checked while it runs rather than after,
                // because "after" is too late for the bytes already written.
                if captured_bytes(&out_file, &err_file) > MAX_CAPTURED_BYTES {
                    over_cap = true;
                    watch.release();
                    reap(&mut child);
                    break None;
                }
                if let Err(over) = watch.poll() {
                    breach = Some(over);
                    watch.release();
                    reap(&mut child);
                    break None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => {
                watch.release();
                reap(&mut child);
                return Err(RunFailure::Io(error));
            }
        }
    };
    watch.release();
    if over_cap {
        return Err(RunFailure::Io(io::Error::other(format!(
            "verifier wrote more than {MAX_CAPTURED_BYTES} bytes of output and was stopped; \
             that is a fact about this node's limits, not about the artifact"
        ))));
    }
    if let Some(breach) = breach {
        return Err(RunFailure::Io(io::Error::other(breach.to_string())));
    }

    Ok(Completed {
        code,
        stdout: read_lossy(out_file),
        stderr: read_lossy(err_file),
    })
}

/// Kill a child and everything it started, then reap it.
///
/// The process group first: `Child::kill` signals one pid, and a checker that
/// forked has already escaped that. Killing the group is best-effort — the
/// child may have changed its own group, and on a platform without process
/// groups there is nothing to kill — so the direct kill still follows.
fn reap(child: &mut std::process::Child) {
    #[cfg(unix)]
    kill_process_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn setpgid_self() -> io::Result<()> {
    // SAFETY: `setpgid` is a plain syscall wrapper with no preconditions
    // beyond valid arguments; `(0, 0)` means "this process, its own group".
    if unsafe { libc_setpgid(0, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn kill_process_group(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: `kill` with a negative pid signals the process group; an
        // invalid group is reported in the return value, which is ignored
        // because this is best-effort cleanup.
        unsafe {
            libc_kill(-pid, 9);
        }
    }
}

// This crate has no `libc` dependency and will not grow one for two calls.
// Both are stable syscall entry points in the platform's C library, which is
// already linked into every Rust binary on these targets.
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "setpgid"]
    fn libc_setpgid(pid: i32, pgid: i32) -> i32;
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// Bytes captured so far across both streams.
fn captured_bytes(out_file: &fs::File, err_file: &fs::File) -> u64 {
    let size = |file: &fs::File| file.metadata().map(|meta| meta.len()).unwrap_or(0);
    size(out_file).saturating_add(size(err_file))
}

/// Read captured output, tolerating both a missing file and invalid UTF-8.
/// Neither is worth failing a verification over; the reference implementation
/// decodes with the same tolerance.
///
/// Reads at most [`MAX_CAPTURED_BYTES`]: the caller only ever keeps a short
/// tail, and loading a multi-gigabyte capture into a `String` to throw nearly
/// all of it away is how a disk-filling checker becomes an OOM as well.
fn read_lossy(mut file: fs::File) -> String {
    use std::io::{Read as _, Seek as _};
    if file.rewind().is_err() {
        return String::new();
    }
    let mut buffer = Vec::new();
    if file
        .by_ref()
        .take(MAX_CAPTURED_BYTES)
        .read_to_end(&mut buffer)
        .is_err()
    {
        return String::new();
    }
    String::from_utf8_lossy(&buffer).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> TempDir {
        TempDir::new(name).expect("temp dir")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        blobs::address(bytes)
    }

    fn have(binary: &str) -> bool {
        which(binary).is_some()
    }

    const CHECKER: &str = "def check(artifact):\n    return artifact.get(\"n\") == 42\n";
    const EVALUATOR: &str = "def score(artifact):\n    return len(artifact.get(\"items\", []))\n";

    fn write_pinned(dir: &TempDir, name: &str, source: &str) -> String {
        fs::write(dir.path().join(name), source).expect("write pinned source");
        sha256_hex(source.as_bytes())
    }

    #[test]
    fn a_checker_resolved_from_the_blob_store_actually_runs() {
        // The content-addressed fallback is the entire reason `blobs` exists: a
        // node that learned an objective over the wire has no bundle, fetches
        // the pinned checker by its hash, and verifies against that.
        //
        // It could never load one. A blob's filename *is* its hash, so it never
        // ends in `.py`, and `spec_from_file_location` returns None for an
        // extension it does not recognise -- so the harness bailed and every
        // claim on such a node came back `unavailable`, which is exactly the
        // failure the blob store was built to remove.
        //
        // Nothing caught it because nothing fetched a blob: `swarm::tcp` had no
        // caller outside its own tests, and the tests that exercise
        // `resolve_pinned` check the path it returns rather than running Python
        // against it. Two subsystems each correct, and the seam between them
        // never traversed.
        if !have("python3") {
            return;
        }
        let bundle = tmpdir("blob-resolved-bundle");
        let store_dir = tmpdir("blob-resolved-store");
        let declared = sha256_hex(CHECKER.as_bytes());
        // The blob store holds it; the bundle deliberately does not.
        BlobStore::at(store_dir.path())
            .put(&declared, CHECKER.as_bytes())
            .expect("stores the blob");

        let registry =
            VerifierRegistry::new(bundle.path()).with_blob_dir(store_dir.path().to_path_buf());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("checkers/absent.py")),
            ("checker_sha256", Value::string(declared)),
            ("entrypoint", Value::string("check")),
        ]);

        let accepted = registry.run(&spec, &Value::object([("n", Value::Int(42))]));
        assert_eq!(
            accepted.status,
            Status::Accept,
            "a fetched checker did not run: {}",
            accepted.detail
        );
        // And it is a real verdict, not an accept-everything: the same checker
        // rejects the artifact it should.
        let rejected = registry.run(&spec, &Value::object([("n", Value::Int(41))]));
        assert_eq!(rejected.status, Status::Reject, "{}", rejected.detail);
    }

    // -- status ------------------------------------------------------------

    #[test]
    fn only_accept_and_reject_settle() {
        assert!(Status::Accept.settles());
        assert!(Status::Reject.settles());
        assert!(!Status::Unavailable.settles());
        assert!(!Status::InvalidSpec.settles());
    }

    #[test]
    fn status_round_trips_through_the_wire_spelling() {
        for status in [
            Status::Accept,
            Status::Reject,
            Status::Unavailable,
            Status::InvalidSpec,
        ] {
            assert_eq!(Status::from_wire(status.as_str()), Some(status));
        }
        assert_eq!(Status::from_wire("haruspicy"), None);
    }

    // -- verdict -----------------------------------------------------------

    #[test]
    fn verdict_serializes_the_shape_the_ledger_records() {
        let verdict = Verdict::accept("fine");
        let value = verdict.to_value();
        assert_eq!(value.get("status").and_then(Value::as_str), Some("accept"));
        assert_eq!(value.get("detail").and_then(Value::as_str), Some("fine"));
        assert!(value.get("evidence").and_then(Value::as_object).is_some());
        assert_eq!(Verdict::from_value(&value), Some(verdict));
    }

    #[test]
    fn score_reads_the_key_the_ratchet_reads() {
        let verdict =
            Verdict::accept("x").with_evidence(Value::object([("score", Value::Int(17))]));
        assert_eq!(verdict.score(), Some(17));
        // A boolean is not a score, even though Python's bool is an int.
        let boolean =
            Verdict::accept("x").with_evidence(Value::object([("score", Value::Bool(true))]));
        assert_eq!(boolean.score(), None);
        // Neither is something the frontier could not record.
        let huge = Verdict::accept("x").with_evidence(Value::object([(
            "score",
            Value::Int(i128::from(i64::MAX) + 1),
        )]));
        assert_eq!(huge.score(), None);
        assert_eq!(Verdict::accept("x").score(), None);
    }

    // -- score arithmetic --------------------------------------------------

    #[test]
    fn thresholds_compare_without_arithmetic_that_could_overflow() {
        // The pair that would overflow i64 if the implementation subtracted.
        assert!(Direction::Maximize.clears(i64::MAX, i64::MIN));
        assert!(!Direction::Maximize.clears(i64::MIN, i64::MAX));
        assert!(Direction::Minimize.clears(i64::MIN, i64::MAX));
        assert!(!Direction::Minimize.clears(i64::MAX, i64::MIN));
        assert!(Direction::Maximize.clears(3, 3));
        assert!(Direction::Minimize.clears(3, 3));
    }

    fn scored(outcome: Harvest, threshold: i64, direction: Direction) -> Verdict {
        score_verdict(
            outcome,
            threshold,
            direction,
            "evaluator",
            Value::object([("evaluator_sha256", Value::string("ab"))]),
        )
    }

    #[test]
    fn evaluator_threshold_decides_accept_or_reject() {
        let accepted = scored(Harvest::Score(3), 3, Direction::Maximize);
        assert_eq!(accepted.status, Status::Accept);
        assert_eq!(accepted.score(), Some(3));
        let rejected = scored(Harvest::Score(2), 3, Direction::Maximize);
        assert_eq!(rejected.status, Status::Reject);
        let minimized = scored(Harvest::Score(2), 3, Direction::Minimize);
        assert_eq!(minimized.status, Status::Accept);
    }

    #[test]
    fn the_score_evidence_shape_is_stable_across_both_scoring_kinds() {
        // The frontier reads `score` from evidence and the audit re-derives
        // payouts from it; a kind that spells the key differently would settle
        // and then be unrecheckable.
        let evaluator = scored(Harvest::Score(3), 3, Direction::Maximize);
        assert_eq!(evaluator.score(), Some(3));
        assert!(evaluator.evidence.get("evaluator_sha256").is_some());
        let statistical = score_verdict(
            Harvest::Score(3),
            3,
            Direction::Maximize,
            "statistic",
            Value::object([
                ("statistic_sha256", Value::string("ab")),
                ("seed", Value::Int(7)),
            ]),
        );
        assert_eq!(statistical.score(), Some(3));
        assert_eq!(
            statistical.evidence.get("seed").and_then(Value::as_i64),
            Some(7)
        );
    }

    #[test]
    fn a_score_too_large_to_record_is_a_spec_defect_not_a_rejection() {
        let over = scored(
            Harvest::Score(i128::from(i64::MAX) + 1),
            0,
            Direction::Maximize,
        );
        assert_eq!(over.status, Status::InvalidSpec);
        assert!(!over.status.settles());

        let bignum = scored(
            Harvest::ScoreOutOfRange(
                "1606938044258990275541962092341162602522202993782792835301376".into(),
            ),
            0,
            Direction::Maximize,
        );
        assert_eq!(bignum.status, Status::InvalidSpec);
    }

    #[test]
    fn a_non_integer_score_is_refused_because_nodes_would_disagree() {
        let float = scored(Harvest::BadReturn("float".into()), 3, Direction::Maximize);
        assert_eq!(float.status, Status::InvalidSpec);
        assert!(float.detail.contains("int"));

        let boolean = scored(
            Harvest::Boolean {
                ok: true,
                detail: String::new(),
            },
            3,
            Direction::Maximize,
        );
        assert_eq!(boolean.status, Status::InvalidSpec);
        assert!(boolean.detail.contains("int"));
    }

    // -- harness output ----------------------------------------------------

    #[test]
    fn harvest_parses_every_shape_the_harness_emits() {
        assert_eq!(
            parse_harvest("{\"ok\": true, \"detail\": \"hi\"}"),
            Some(Harvest::Boolean {
                ok: true,
                detail: "hi".to_string()
            })
        );
        assert_eq!(parse_harvest("{\"score\": 20}\n"), Some(Harvest::Score(20)));
        assert_eq!(
            parse_harvest("{\"bad_return\": \"float\"}"),
            Some(Harvest::BadReturn("float".to_string()))
        );
        assert_eq!(
            parse_harvest("{\"score\": 3.5}"),
            Some(Harvest::BadReturn("float".to_string()))
        );
        assert_eq!(
            parse_harvest(
                "{\"score\": 1606938044258990275541962092341162602522202993782792835301376}"
            ),
            Some(Harvest::ScoreOutOfRange(
                "1606938044258990275541962092341162602522202993782792835301376".to_string()
            ))
        );
        assert_eq!(parse_harvest("not json"), None);
        assert_eq!(parse_harvest("[1, 2]"), None);
        assert_eq!(parse_harvest("{\"unexpected\": 1}"), None);
    }

    // -- word-boundary screening -------------------------------------------

    #[test]
    fn word_boundaries_match_the_reference_regexes() {
        assert!(contains_word(":= by sorry", "sorry"));
        assert!(contains_word("sorry", "sorry"));
        assert!(contains_word("(sorry)", "sorry"));
        assert!(contains_word("by\nsorry\n", "sorry"));
        // Neighbouring word characters mean it is a different identifier.
        assert!(!contains_word("sorryAx", "sorry"));
        assert!(!contains_word("no_sorry_here", "sorry"));
        assert!(!contains_word("presorry", "sorry"));
        assert!(!contains_word("sorry9", "sorry"));
        assert!(!contains_word("", "sorry"));
        assert!(!contains_word("sorry", ""));
        assert!(!contains_word("sor", "sorry"));
        // The screen must survive a second occurrence after a non-matching one.
        assert!(contains_word("sorryAx then sorry", "sorry"));
    }

    #[test]
    fn every_escape_hatch_is_screened() {
        let spec = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : True")),
        ]);
        // `lean` is absent in CI; these must reject anyway, before any lookup.
        let registry = VerifierRegistry::new(".").with_lean_binary("lean-does-not-exist-xyz");
        for proof in [
            ":= by sorry",
            ":= by admit",
            ":= by native_decide",
            "axiom cheat : True",
            "@[implemented_by evil] := by trivial",
        ] {
            let artifact = Value::object([("proof", Value::string(proof))]);
            let verdict = registry.run(&spec, &artifact);
            assert_eq!(verdict.status, Status::Reject, "proof: {proof}");
            assert!(verdict.evidence.get("pattern").is_some());
        }
    }

    #[test]
    fn a_proof_that_extends_the_statement_is_rejected_before_lean_runs() {
        // Appended to `theorem t : 2 + 2 = 5`, each of these makes Lean check
        // an easier theorem than the pinned one: no hole, no axiom, exit 0.
        // The toolchain does not exist, so Unavailable would mean the check
        // had moved below the lookup.
        let spec = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : 2 + 2 = 5")),
        ]);
        let registry = VerifierRegistry::new(".").with_lean_binary("lean-does-not-exist-xyz");
        for widened in [
            " ∨ True := Or.inr trivial",
            "→ 2 + 2 = 5 := id",
            "\n  ∨ True\n:= Or.inr trivial",
            "|>.symm := rfl",
            "-- a comment first\n:= rfl",
        ] {
            let artifact = Value::object([("proof", Value::string(widened))]);
            let verdict = registry.run(&spec, &artifact);
            assert_eq!(
                verdict.status,
                Status::Reject,
                "{widened:?}: {}",
                verdict.detail
            );
            assert_eq!(verdict.detail, LEAN_PROOF_MUST_OPEN_WITH_ASSIGN);
        }
        // Leading whitespace is fine: the header is still the objective's.
        for honest in [":= by decide", "  := by decide", "\n:= by\n  decide"] {
            let artifact = Value::object([("proof", Value::string(honest))]);
            assert_eq!(
                registry.run(&spec, &artifact).status,
                Status::Unavailable,
                "{honest:?} should reach the toolchain lookup"
            );
        }
    }

    #[test]
    fn native_decide_passes_the_screen_when_the_objective_opts_in() {
        let spec = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : True")),
            ("allow_native_decide", Value::Bool(true)),
        ]);
        let registry = VerifierRegistry::new(".").with_lean_binary("lean-does-not-exist-xyz");
        let artifact = Value::object([("proof", Value::string(":= by native_decide"))]);
        // Past the screen; without a toolchain the verdict is Unavailable.
        let verdict = registry.run(&spec, &artifact);
        assert_ne!(verdict.status, Status::Reject);
        assert_eq!(verdict.status, Status::Unavailable);
    }

    #[test]
    fn a_missing_lean_toolchain_is_unavailable_not_a_rejection() {
        // The failure mode this prevents: take verifiers offline and every
        // honest submission "fails".
        let spec = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : True")),
        ]);
        let artifact = Value::object([("proof", Value::string(":= by trivial"))]);
        let registry = VerifierRegistry::new(".").with_lean_binary("lean-does-not-exist-xyz");
        let verdict = registry.run(&spec, &artifact);
        assert_eq!(verdict.status, Status::Unavailable);
        assert!(!verdict.status.settles());
    }

    #[test]
    fn lean_needs_a_statement_from_the_objective() {
        // The statement comes from the objective, never the submitter.
        let registry = VerifierRegistry::new(".");
        let artifact = Value::object([("proof", Value::string(":= by trivial"))]);
        let verdict = registry.run(&Value::object([("kind", Value::string("lean"))]), &artifact);
        assert_eq!(verdict.status, Status::InvalidSpec);
        let blank = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("   ")),
        ]);
        assert_eq!(registry.run(&blank, &artifact).status, Status::InvalidSpec);
    }

    #[test]
    fn a_proofless_artifact_is_rejected() {
        let registry = VerifierRegistry::new(".");
        let spec = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : True")),
        ]);
        assert_eq!(
            registry
                .run(&spec, &Value::object([("proof", Value::string(" "))]))
                .status,
            Status::Reject
        );
    }

    // -- dispatch ----------------------------------------------------------

    #[test]
    fn a_spec_without_a_kind_is_invalid() {
        let registry = VerifierRegistry::new(".");
        assert_eq!(
            registry.run(&empty_object(), &empty_object()).status,
            Status::InvalidSpec
        );
    }

    #[test]
    fn an_unknown_kind_is_unavailable_because_another_node_may_know_it() {
        let registry = VerifierRegistry::new(".");
        let spec = Value::object([("kind", Value::string("haruspicy"))]);
        let verdict = registry.run(&spec, &empty_object());
        assert_eq!(verdict.status, Status::Unavailable);
        assert!(!verdict.status.settles());
    }

    #[test]
    fn kinds_are_sorted_and_complete() {
        assert_eq!(
            VerifierRegistry::kinds(),
            &[
                "certificate",
                "evaluator",
                "lean",
                "replay",
                "statistical",
                "workspace"
            ]
        );
        for kind in VerifierRegistry::kinds() {
            assert!(VerifierRegistry::supports(kind));
            assert_eq!(Kind::parse(kind).map(|k| k.as_str()), Some(*kind));
        }
        // `kinds()` is what the CLI prints and what the schema enum mirrors;
        // `Kind::ALL` is what dispatch matches on. Two lists, one truth.
        let dispatchable: Vec<&str> = Kind::ALL.iter().map(Kind::as_str).collect();
        assert_eq!(dispatchable, VerifierRegistry::kinds());
        assert!(!VerifierRegistry::supports("haruspicy"));
    }

    // -- pinned code -------------------------------------------------------

    #[test]
    fn a_pinned_path_cannot_escape_a_relative_root() {
        // The reference implementation's actual bug: a relative root like "."
        // never prefixes a normalized relative join, so both sides must be made
        // absolute before comparing. Legitimate paths must still resolve.
        let registry = VerifierRegistry::new(".");
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("../outside.py")),
            ("checker_sha256", Value::string("0".repeat(64))),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &empty_object());
        assert_eq!(verdict.status, Status::InvalidSpec);
        assert!(verdict.detail.contains("escapes"));
        assert!(!verdict.status.settles());
    }

    #[test]
    fn a_sibling_directory_does_not_count_as_inside_the_root() {
        let root = tmpdir("proofwork-root-test");
        let sibling = root.path().with_extension("evil");
        let registry = VerifierRegistry::new(root.path());
        let escape = registry.pinned("checker", "../", "0".repeat(64).as_str());
        assert!(escape.is_err());
        // Component-wise containment, not a string prefix test.
        assert!(!normalize(&sibling).starts_with(normalize(root.path())));
    }

    #[test]
    fn a_missing_checker_is_unavailable_not_a_rejection() {
        let root = tmpdir("proofwork-missing");
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("nope.py")),
            ("checker_sha256", Value::string("0".repeat(64))),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &Value::object([("n", Value::Int(42))]));
        assert_eq!(verdict.status, Status::Unavailable);
        assert!(!verdict.status.settles());
    }

    #[test]
    fn an_edited_checker_invalidates_the_spec_rather_than_rescoring() {
        let root = tmpdir("proofwork-edited");
        let sha = write_pinned(&root, "c.py", CHECKER);
        // Same pin, different code: the objective's identity no longer matches.
        fs::write(
            root.path().join("c.py"),
            CHECKER.replace("42", "41").as_bytes(),
        )
        .expect("rewrite");
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &Value::object([("n", Value::Int(41))]));
        assert_eq!(verdict.status, Status::InvalidSpec);
        assert!(!verdict.status.settles());
    }

    #[test]
    fn missing_certificate_spec_fields_are_reported_together() {
        let registry = VerifierRegistry::new(".");
        let spec = Value::object([("kind", Value::string("certificate"))]);
        let verdict = registry.run(&spec, &empty_object());
        assert_eq!(verdict.status, Status::InvalidSpec);
        assert!(verdict.detail.contains("checker"));
        assert!(verdict.detail.contains("entrypoint"));
    }

    fn base(extra: Vec<(&str, Value)>) -> Value {
        let mut pairs: Vec<(&str, Value)> = vec![
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            ("evaluator_sha256", Value::string("0".repeat(64))),
            ("entrypoint", Value::string("score")),
        ];
        pairs.extend(extra);
        Value::object(pairs)
    }

    #[test]
    fn evaluator_specs_require_an_integer_threshold_and_a_known_direction() {
        let registry = VerifierRegistry::new(".");
        // No threshold at all.
        assert_eq!(
            registry.run(&base(vec![]), &empty_object()).status,
            Status::InvalidSpec
        );
        // A string threshold. (A float one cannot even be constructed: Value
        // has no float variant.)
        assert_eq!(
            registry
                .run(
                    &base(vec![("threshold", Value::string("3"))]),
                    &empty_object()
                )
                .status,
            Status::InvalidSpec
        );
        // A boolean threshold: Python needs an explicit isinstance guard here.
        assert_eq!(
            registry
                .run(
                    &base(vec![("threshold", Value::Bool(true))]),
                    &empty_object()
                )
                .status,
            Status::InvalidSpec
        );
        // Out of the range the frontier can record.
        assert_eq!(
            registry
                .run(
                    &base(vec![("threshold", Value::Int(i128::from(i64::MAX) + 1))]),
                    &empty_object()
                )
                .status,
            Status::InvalidSpec
        );
        // An unknown direction.
        assert_eq!(
            registry
                .run(
                    &base(vec![
                        ("threshold", Value::Int(3)),
                        ("direction", Value::string("sideways"))
                    ]),
                    &empty_object()
                )
                .status,
            Status::InvalidSpec
        );
    }

    // -- statistical -------------------------------------------------------

    const STATISTIC: &str = "def statistic(artifact, seed):\n    \
                             return seed * 10 + len(artifact.get(\"data\", []))\n";

    fn statistical_spec(sha: &str, extra: Vec<(&str, Value)>) -> Value {
        let mut pairs: Vec<(&str, Value)> = vec![
            ("kind", Value::string("statistical")),
            (
                "statistic",
                Value::object([
                    ("path", Value::string("s.py")),
                    ("sha256", Value::string(sha)),
                ]),
            ),
            ("entrypoint", Value::string("statistic")),
            ("direction", Value::string("minimize")),
        ];
        pairs.extend(extra);
        Value::object(pairs)
    }

    #[test]
    fn a_statistical_verifier_uses_the_objectives_seed_not_the_artifacts() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-statistical");
        let sha = write_pinned(&root, "s.py", STATISTIC);
        let registry = VerifierRegistry::new(root.path());
        // Two data points, so the statistic is `seed * 10 + 2`.
        let artifact = Value::object([
            ("data", Value::array([Value::Int(1), Value::Int(2)])),
            // A submitter-supplied seed must be ignored: if it were read, the
            // submitter would choose the randomisation they are tested under.
            ("seed", Value::Int(99)),
        ]);

        let default_seed = registry.run(
            &statistical_spec(&sha, vec![("threshold", Value::Int(2))]),
            &artifact,
        );
        assert_eq!(
            default_seed.status,
            Status::Accept,
            "{}",
            default_seed.detail
        );
        assert_eq!(
            default_seed.score(),
            Some(2),
            "seed defaulted to something other than 0"
        );

        let pinned = registry.run(
            &statistical_spec(
                &sha,
                vec![("threshold", Value::Int(2)), ("seed", Value::Int(3))],
            ),
            &artifact,
        );
        assert_eq!(pinned.score(), Some(32));
        // 32 > 2 under `minimize`, so the same artifact now fails: the seed is
        // part of the objective's identity precisely because it can flip this.
        assert_eq!(pinned.status, Status::Reject);
        assert_eq!(pinned.evidence.get("seed").and_then(Value::as_i64), Some(3));
    }

    #[test]
    fn a_statistical_verifier_is_bit_reproducible_across_runs() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-statistical-stable");
        let sha = write_pinned(&root, "s.py", STATISTIC);
        let registry = VerifierRegistry::new(root.path());
        let spec = statistical_spec(&sha, vec![("threshold", Value::Int(50))]);
        let artifact = Value::object([("data", Value::array([Value::Int(1)]))]);
        let first = registry.run(&spec, &artifact);
        let second = registry.run(&spec, &artifact);
        assert_eq!(first, second);
    }

    #[test]
    fn a_statistical_spec_must_pin_a_path_a_hash_and_an_integer_threshold() {
        let registry = VerifierRegistry::new(".");
        let sha = "0".repeat(64);
        for (why, spec) in [
            (
                "no statistic block",
                Value::object([
                    ("kind", Value::string("statistical")),
                    ("entrypoint", Value::string("statistic")),
                    ("threshold", Value::Int(1)),
                ]),
            ),
            (
                "statistic is not an object",
                Value::object([
                    ("kind", Value::string("statistical")),
                    ("statistic", Value::string("s.py")),
                    ("entrypoint", Value::string("statistic")),
                    ("threshold", Value::Int(1)),
                ]),
            ),
            (
                "no sha256",
                Value::object([
                    ("kind", Value::string("statistical")),
                    (
                        "statistic",
                        Value::object([("path", Value::string("s.py"))]),
                    ),
                    ("entrypoint", Value::string("statistic")),
                    ("threshold", Value::Int(1)),
                ]),
            ),
            ("no threshold", statistical_spec(&sha, vec![])),
            (
                "float threshold is unrepresentable, so a string stands in for it",
                statistical_spec(&sha, vec![("threshold", Value::string("0.05"))]),
            ),
            (
                "boolean threshold",
                statistical_spec(&sha, vec![("threshold", Value::Bool(true))]),
            ),
            (
                "non-integer seed",
                statistical_spec(
                    &sha,
                    vec![("threshold", Value::Int(1)), ("seed", Value::string("0"))],
                ),
            ),
            (
                "unknown direction",
                Value::object([
                    ("kind", Value::string("statistical")),
                    (
                        "statistic",
                        Value::object([
                            ("path", Value::string("s.py")),
                            ("sha256", Value::string(&sha)),
                        ]),
                    ),
                    ("entrypoint", Value::string("statistic")),
                    ("threshold", Value::Int(1)),
                    ("direction", Value::string("sideways")),
                ]),
            ),
        ] {
            let verdict = registry.run(&spec, &empty_object());
            assert_eq!(verdict.status, Status::InvalidSpec, "{why}");
            assert!(!verdict.status.settles(), "{why}");
        }
    }

    #[test]
    fn a_statistic_returning_a_float_is_a_spec_defect_not_a_rejection() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-statistical-float");
        let sha = write_pinned(
            &root,
            "s.py",
            "def statistic(artifact, seed):\n    return 0.05\n",
        );
        let registry = VerifierRegistry::new(root.path());
        let verdict = registry.run(
            &statistical_spec(&sha, vec![("threshold", Value::Int(1))]),
            &empty_object(),
        );
        assert_eq!(verdict.status, Status::InvalidSpec);
        assert!(verdict.detail.contains("int"), "{}", verdict.detail);
    }

    #[test]
    fn an_edited_statistic_invalidates_the_objective_rather_than_rescoring() {
        // The point of the whole kind: the rejection rule cannot be changed
        // after the data exists without changing the objective's id.
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-statistical-edited");
        let sha = write_pinned(&root, "s.py", STATISTIC);
        fs::write(
            root.path().join("s.py"),
            b"def statistic(artifact, seed):\n    return 0\n",
        )
        .expect("rewrite");
        let registry = VerifierRegistry::new(root.path());
        let verdict = registry.run(
            &statistical_spec(&sha, vec![("threshold", Value::Int(1))]),
            &empty_object(),
        );
        assert_eq!(verdict.status, Status::InvalidSpec);
    }

    // -- timeouts ----------------------------------------------------------

    #[test]
    fn timeouts_must_be_positive_and_bounded() {
        assert!(spec_timeout(&empty_object(), 120).is_ok());
        assert_eq!(
            spec_timeout(&empty_object(), 120).ok(),
            Some(Duration::from_secs(120))
        );
        for bad in [
            Value::Int(0),
            Value::Int(-1),
            Value::Int(i128::from(MAX_TIMEOUT_SECONDS) + 1),
            Value::string("120"),
            Value::Bool(true),
        ] {
            let spec = Value::object([("timeout_seconds", bad.clone())]);
            let outcome = spec_timeout(&spec, 120);
            assert!(outcome.is_err(), "{bad:?} should be refused");
            if let Err(verdict) = outcome {
                assert_eq!(verdict.status, Status::InvalidSpec);
            }
        }
    }

    #[test]
    fn a_child_that_overruns_its_deadline_is_killed_rather_than_waited_on() {
        if !have("sleep") {
            return;
        }
        let workdir = tmpdir("proofwork-timeout");
        let mut command = Command::new("sleep");
        command.arg("30");
        let started = Instant::now();
        let outcome = run_bounded(
            &mut command,
            workdir.path(),
            None,
            Duration::from_millis(200),
            limits::Limits::default(),
        );
        assert!(matches!(outcome, Err(RunFailure::TimedOut(None))));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the deadline must actually bound the wait"
        );
    }

    #[test]
    fn a_missing_binary_is_a_spawn_failure_not_a_hang() {
        let workdir = tmpdir("proofwork-spawn");
        let mut command = Command::new("proofwork-nonexistent-binary-xyz");
        let outcome = run_bounded(
            &mut command,
            workdir.path(),
            None,
            Duration::from_secs(5),
            limits::Limits::default(),
        );
        assert!(matches!(outcome, Err(RunFailure::Spawn(_))));
    }

    #[cfg(unix)]
    #[test]
    fn capture_collection_reads_the_original_descriptor_not_a_child_symlink() {
        let workdir = tmpdir("proofwork-capture-symlink");
        let outside = std::env::temp_dir().join(format!(
            "proofwork-capture-secret-{}",
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&outside, "host secret").expect("write sentinel");

        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("printf child-output && rm \"$1/stdout\" && ln -s \"$2\" \"$1/stdout\"")
            .arg("sh")
            .arg(workdir.path())
            .arg(&outside);
        let completed = run_bounded(
            &mut command,
            workdir.path(),
            None,
            Duration::from_secs(5),
            limits::Limits::default(),
        )
        .expect("child completes");

        assert_eq!(completed.code, Some(0));
        assert_eq!(completed.stdout, "child-output");
        assert!(!completed.stdout.contains("host secret"));
        let _ = fs::remove_file(outside);
    }

    /// `0m1.234s` (bash) or `0m1.23s` (dash), as `times` prints, in ms.
    #[cfg(unix)]
    fn millis(field: &str) -> Option<u64> {
        let (minutes, seconds) = field.strip_suffix('s')?.split_once('m')?;
        let (whole, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
        let fraction = format!("{:0<3}", &fraction[..fraction.len().min(3)]);
        Some(
            minutes.parse::<u64>().ok()? * 60_000
                + whole.parse::<u64>().ok()? * 1000
                + fraction.parse::<u64>().ok()?,
        )
    }

    /// Run `script` under `limits` and return its wall time and the CPU time
    /// its children spent, both in ms. The CPU time is the shell's own
    /// `times`, which counts every descendant it waited for -- the work
    /// itself, measured by the kernel rather than by the watch under test.
    #[cfg(unix)]
    fn busy(script: &str, limits: limits::Limits) -> (u64, u64) {
        let workdir = tmpdir("proofwork-spin");
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "spin() {{ i=0; while [ $i -lt $1 ]; do i=$((i+1)); done; }}\n{script}\nwait\ntimes"
        ));
        let started = Instant::now();
        let completed = run_bounded(
            &mut command,
            workdir.path(),
            None,
            Duration::from_secs(120),
            limits,
        )
        .expect("the loops finish");
        let wall = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        assert_eq!(completed.code, Some(0), "{}", completed.stderr);
        let children = completed
            .stdout
            .lines()
            .nth(1)
            .expect("times prints two lines");
        let cpu = children
            .split_whitespace()
            .map(|field| millis(field).expect("a time"))
            .sum();
        (wall, cpu)
    }

    /// Steps of `spin` that take about `target_ms` of CPU on this machine.
    /// Calibrated on CPU time, not wall time: contention stretches the wall
    /// time of a fixed amount of work and leaves its CPU time alone.
    #[cfg(unix)]
    fn steps_for(target_ms: u64) -> u64 {
        let mut count = 20_000u64;
        // Bounded: a machine too slow to reach the target by then is still
        // measured, just with less margin.
        loop {
            // In the background, so it is a child `times` counts: a plain
            // call to a shell function runs in the shell itself.
            let (_, cpu) = busy(&format!("spin {count} &"), limits::Limits::default());
            if cpu >= target_ms || count >= 20_000_000 {
                return count;
            }
            count *= 2;
        }
    }

    /// What one core may spend in `wall_ms`: the core itself, the burst the
    /// bucket starts with, one sample's overrun by each of `busy` busy
    /// processes, and a sample's worth of slack for the edges.
    #[cfg(unix)]
    fn one_core(wall_ms: u64, busy: u64) -> u64 {
        wall_ms + 200 + busy * 100 + 100
    }

    /// The cap is only real if a tree that wants more cores does not get
    /// them. Four busy loops held to one core may spend one core's worth of
    /// CPU over the run and no more.
    ///
    /// The bound is on CPU spent per unit of wall time, which load on the
    /// machine can only lower -- a starved tree spends less -- so a busy CI
    /// host cannot fail it. What fails it is a cap that does not hold: four
    /// uncapped loops on four idle cores spend about four times their wall
    /// time. An earlier version compared wall times against a one-loop
    /// baseline, and failed under a loaded test run because contention
    /// stretched the baseline too.
    #[cfg(unix)]
    #[test]
    fn a_cpu_cap_holds_a_busy_tree_to_its_cores() {
        let count = steps_for(400);
        let (wall, cpu) = busy(
            &format!("spin {count} & spin {count} & spin {count} & spin {count} &"),
            limits::Limits {
                cpus: 1,
                memory_mb: 0,
            },
        );
        assert!(
            cpu <= one_core(wall, 4),
            "four loops held to one core spent {cpu} ms of CPU in {wall} ms"
        );
    }

    /// A process that starts and ends between two samples is never seen
    /// alive. Four chains of short commands are nothing but such processes;
    /// the watch still has to count them, through the reaped-children time of
    /// the shells that ran them.
    #[cfg(unix)]
    #[test]
    fn a_cpu_cap_counts_processes_too_short_to_sample() {
        let short = steps_for(400) / 16;
        let chain = format!("(for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do sh -c 'i=0; while [ $i -lt {short} ]; do i=$((i+1)); done'; done) &");
        let (wall, cpu) = busy(
            &[chain.as_str(); 4].join(" "),
            limits::Limits {
                cpus: 1,
                memory_mb: 0,
            },
        );
        assert!(
            cpu <= one_core(wall, 4),
            "four chains of short commands held to one core spent {cpu} ms of CPU in {wall} ms"
        );
    }

    #[test]
    fn a_throttled_timeout_says_whose_cap_it_was() {
        let note = RunFailure::throttle_note(Some((2, Duration::from_secs(41))));
        assert!(note.contains("2 cores"), "{note}");
        assert!(note.contains(limits::CPUS_ENV), "{note}");
        assert!(note.contains("41s"), "{note}");
        assert_eq!(RunFailure::throttle_note(None), "");
    }

    /// macOS has no `RLIMIT_AS`, so before the watch this cap was a number in
    /// the docs and nothing on the machine.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_tree_over_its_memory_cap_is_stopped_on_macos() {
        let workdir = tmpdir("proofwork-memory");
        // Perl rather than Python: /usr/bin/python3 on a Mac without the
        // developer tools is a stub that opens an install dialog.
        let mut command = Command::new("/usr/bin/perl");
        command.args(["-e", "my $x = 'x' x (512 << 20); sleep 20;"]);
        let started = Instant::now();
        let outcome = run_bounded(
            &mut command,
            workdir.path(),
            None,
            Duration::from_secs(30),
            limits::Limits {
                cpus: 0,
                memory_mb: 128,
            },
        );
        match outcome {
            Err(RunFailure::Io(error)) => {
                let text = error.to_string();
                assert!(text.contains("CAIRN_SANDBOX_MEMORY_MB"), "{text}");
                assert!(text.contains("not about the artifact"), "{text}");
            }
            other => panic!("expected the memory cap to stop it, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(15));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_inside_its_limits_is_left_alone() {
        let workdir = tmpdir("proofwork-inside-limits");
        let mut command = Command::new("sh");
        command.arg("-c").arg("printf fine");
        let completed = run_bounded(
            &mut command,
            workdir.path(),
            None,
            Duration::from_secs(5),
            limits::Limits {
                cpus: 1,
                memory_mb: 1024,
            },
        )
        .expect("child completes");
        assert_eq!(completed.code, Some(0));
        assert_eq!(completed.stdout, "fine");
    }

    // -- replay ------------------------------------------------------------

    #[test]
    fn replay_refuses_machine_dependent_fields() {
        // A cost claim denominated in seconds is a claim about somebody's
        // hardware and cannot be settled by re-execution.
        let registry = VerifierRegistry::new(".");
        for field in [
            "wall_clock_seconds",
            "peak_memory",
            "elapsed",
            "flops",
            "RSS",
            "TimeStamp",
            "run_date",
            "throughput_ops",
            "latency_p99",
            "duration",
        ] {
            let spec = Value::object([
                ("kind", Value::string("replay")),
                ("command", Value::array([Value::string("true")])),
                ("reproducible_fields", Value::array([Value::string(field)])),
            ]);
            let verdict = registry.run(&spec, &Value::object([("results", empty_object())]));
            assert_eq!(verdict.status, Status::InvalidSpec, "field: {field}");
            assert!(!verdict.status.settles());
        }
        assert!(!machine_dependent("relations_found"));
        assert!(!machine_dependent("solving_degree"));
    }

    #[test]
    fn replay_specs_must_carry_a_command_and_fields() {
        let registry = VerifierRegistry::new(".");
        let cases = [
            Value::object([("kind", Value::string("replay"))]),
            Value::object([
                ("kind", Value::string("replay")),
                ("command", Value::string("true")),
                ("reproducible_fields", Value::array([Value::string("n")])),
            ]),
            Value::object([
                ("kind", Value::string("replay")),
                ("command", Value::array([Value::Int(1)])),
                ("reproducible_fields", Value::array([Value::string("n")])),
            ]),
            // Empty command: nothing to run, so nothing to settle.
            Value::object([
                ("kind", Value::string("replay")),
                ("command", Value::array([])),
                ("reproducible_fields", Value::array([Value::string("n")])),
            ]),
            // Empty field list: an objective that declares nothing reproducible
            // has not said what it would mean to reproduce it.
            Value::object([
                ("kind", Value::string("replay")),
                ("command", Value::array([Value::string("true")])),
                ("reproducible_fields", Value::array([])),
            ]),
        ];
        for spec in cases {
            let verdict = registry.run(&spec, &Value::object([("results", empty_object())]));
            assert_eq!(verdict.status, Status::InvalidSpec, "spec: {spec:?}");
        }
    }

    #[test]
    fn replay_cwd_cannot_escape_the_objective_root() {
        // Regression. `cwd` is objective-authored and is ro-bound into the
        // jail; before the containment check an objective could name any host
        // directory -- `/home/<op>/.ssh` included -- and have its own command
        // read it, with declared fields as the exfiltration channel.
        let root = tmpdir("proofwork-replay-escape");
        let registry = VerifierRegistry::new(root.path());
        for escape in ["/", "/etc", "..", "../..", "a/../../.."] {
            let spec = Value::object([
                ("kind", Value::string("replay")),
                ("command", Value::array([Value::string("true")])),
                ("reproducible_fields", Value::array([Value::string("n")])),
                ("cwd", Value::string(escape)),
            ]);
            let verdict = registry.run(&spec, &Value::object([("results", empty_object())]));
            assert_eq!(verdict.status, Status::InvalidSpec, "cwd {escape:?}");
            assert!(verdict.detail.contains("escapes"), "{}", verdict.detail);
        }
        // Staying inside the root is not refused by the containment check.
        let spec = Value::object([
            ("kind", Value::string("replay")),
            ("command", Value::array([Value::string("true")])),
            ("reproducible_fields", Value::array([Value::string("n")])),
            ("cwd", Value::string(".")),
        ]);
        let verdict = registry.run(&spec, &Value::object([("results", empty_object())]));
        assert_ne!(verdict.status, Status::InvalidSpec, "{}", verdict.detail);
    }

    #[test]
    fn lean_project_root_cannot_escape_the_objective_root() {
        // Regression. `project_root` is objective-authored and readable in the
        // jail; "/" used to expose the operator's whole filesystem. Screened before
        // the toolchain lookup, so the refusal is testable without Lean.
        let root = tmpdir("proofwork-lean-escape");
        let registry = VerifierRegistry::new(root.path());
        for escape in ["/", "/etc", "..", "../.."] {
            let spec = Value::object([
                ("kind", Value::string("lean")),
                ("statement", Value::string("theorem t : True")),
                ("project_root", Value::string(escape)),
            ]);
            let artifact = Value::object([("proof", Value::string(":= trivial"))]);
            let verdict = registry.run(&spec, &artifact);
            assert_eq!(
                verdict.status,
                Status::InvalidSpec,
                "project_root {escape:?}: {}",
                verdict.detail
            );
            assert!(verdict.detail.contains("escapes"), "{}", verdict.detail);
        }
    }

    #[test]
    fn replay_reproduces_declared_fields() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-replay-ok");
        fs::write(
            root.path().join("run.py"),
            b"import json\nprint(json.dumps({'count': 7, 'seconds': 1.5}))\n",
        )
        .expect("write script");
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("replay")),
            (
                "command",
                Value::array([Value::string("python3"), Value::string("run.py")]),
            ),
            (
                "reproducible_fields",
                Value::array([Value::string("count")]),
            ),
        ]);
        let accepted = registry.run(
            &spec,
            &Value::object([("results", Value::object([("count", Value::Int(7))]))]),
        );
        assert_eq!(accepted.status, Status::Accept, "{}", accepted.detail);
        let rejected = registry.run(
            &spec,
            &Value::object([("results", Value::object([("count", Value::Int(8))]))]),
        );
        assert_eq!(rejected.status, Status::Reject);
        assert!(rejected.evidence.get("mismatches").is_some());
        let evidence = rejected.evidence.canonical_string();
        assert!(evidence.contains("claimed_sha256"));
        assert!(evidence.contains("observed_sha256"));
        assert!(!evidence.contains("\"claimed\":"));
        assert!(!evidence.contains("\"observed\":"));
        // An artifact with no results object is a bad artifact, not a bad node.
        let no_results = registry.run(&spec, &empty_object());
        assert_eq!(no_results.status, Status::Reject);
    }

    #[test]
    fn a_failing_replay_command_is_unavailable_not_a_rejection() {
        if !have("python3") {
            return;
        }
        let registry = VerifierRegistry::new(".");
        let spec = Value::object([
            ("kind", Value::string("replay")),
            (
                "command",
                Value::array([
                    Value::string("python3"),
                    Value::string("-c"),
                    Value::string("raise SystemExit(3)"),
                ]),
            ),
            (
                "reproducible_fields",
                Value::array([Value::string("count")]),
            ),
        ]);
        let verdict = registry.run(
            &spec,
            &Value::object([("results", Value::object([("count", Value::Int(1))]))]),
        );
        assert_eq!(verdict.status, Status::Unavailable);
        assert!(!verdict.status.settles());
    }

    #[test]
    fn replay_output_that_is_not_a_json_object_is_unavailable() {
        if !have("python3") {
            return;
        }
        let registry = VerifierRegistry::new(".");
        for program in ["print('not json')", "print('[1, 2]')"] {
            let spec = Value::object([
                ("kind", Value::string("replay")),
                (
                    "command",
                    Value::array([
                        Value::string("python3"),
                        Value::string("-c"),
                        Value::string(program),
                    ]),
                ),
                (
                    "reproducible_fields",
                    Value::array([Value::string("count")]),
                ),
            ]);
            let verdict = registry.run(
                &spec,
                &Value::object([("results", Value::object([("count", Value::Int(1))]))]),
            );
            assert_eq!(verdict.status, Status::Unavailable, "program: {program}");
        }
    }

    // -- certificate and evaluator, end to end -----------------------------

    #[test]
    fn a_certificate_accepts_a_real_witness_and_rejects_a_bad_one() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-cert");
        let sha = write_pinned(&root, "c.py", CHECKER);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
        ]);
        assert_eq!(
            registry
                .run(&spec, &Value::object([("n", Value::Int(42))]))
                .status,
            Status::Accept
        );
        assert_eq!(
            registry
                .run(&spec, &Value::object([("n", Value::Int(41))]))
                .status,
            Status::Reject
        );
    }

    #[test]
    fn a_crashing_checker_is_unavailable() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-crash");
        let source = "def check(artifact):\n    raise RuntimeError('x')\n";
        let sha = write_pinned(&root, "boom.py", source);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("boom.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &empty_object());
        assert_eq!(verdict.status, Status::Unavailable);
        assert!(!verdict.status.settles());
    }

    #[test]
    fn a_chatty_checker_still_returns_a_verdict() {
        // Its stdout must not be mistaken for the result channel.
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-chatty");
        let source = "def check(artifact):\n    print('progress')\n    return True, 'fine'\n";
        let sha = write_pinned(&root, "chatty.py", source);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("chatty.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &empty_object());
        assert_eq!(verdict.status, Status::Accept);
        assert_eq!(verdict.detail, "fine");
    }

    #[test]
    fn a_missing_entrypoint_is_unavailable() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-entry");
        let sha = write_pinned(&root, "c.py", CHECKER);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("not_there")),
        ]);
        assert_eq!(
            registry.run(&spec, &empty_object()).status,
            Status::Unavailable
        );
    }

    #[test]
    fn an_evaluator_scores_and_compares() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-eval");
        let sha = write_pinned(&root, "e.py", EVALUATOR);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            ("evaluator_sha256", Value::string(sha)),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(3)),
            ("direction", Value::string("maximize")),
        ]);
        let items = |n: usize| {
            Value::object([("items", Value::array((0..n).map(|i| Value::Int(i as i128))))])
        };
        let accepted = registry.run(&spec, &items(3));
        assert_eq!(accepted.status, Status::Accept, "{}", accepted.detail);
        assert_eq!(accepted.score(), Some(3));
        assert_eq!(registry.run(&spec, &items(2)).status, Status::Reject);
    }

    #[test]
    fn an_evaluator_that_returns_a_float_invalidates_the_spec() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-float");
        let source = "def score(artifact):\n    return 3.5\n";
        let sha = write_pinned(&root, "f.py", source);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("f.py")),
            ("evaluator_sha256", Value::string(sha)),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(3)),
        ]);
        let verdict = registry.run(&spec, &empty_object());
        assert_eq!(verdict.status, Status::InvalidSpec);
        assert!(verdict.detail.contains("int"));
        assert!(!verdict.status.settles());
    }

    #[test]
    fn a_looping_checker_is_unavailable_rather_than_a_hung_node() {
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-loop");
        let source = "import time\n\n\ndef check(artifact):\n    time.sleep(30)\n    return True\n";
        let sha = write_pinned(&root, "slow.py", source);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("slow.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
            ("timeout_seconds", Value::Int(1)),
        ]);
        let started = Instant::now();
        let verdict = registry.run(&spec, &empty_object());
        assert_eq!(verdict.status, Status::Unavailable);
        assert!(!verdict.status.settles());
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    #[test]
    fn an_interactive_registry_clamps_a_hostile_timeout() {
        // An objective may declare up to MAX_TIMEOUT_SECONDS -- a day -- which
        // is fine for a batch audit and a liveness attack on the
        // single-threaded MCP server, where it would stop answering even
        // `ping`. The clamp is opt-in: settlement must honour the objective's
        // own bound, or a slow verifier would settle differently depending on
        // who ran it.
        let root = tmpdir("proofwork-clamp");
        // Settlement and audit honour whatever the objective declared, up to
        // the format's own day-long maximum.
        let batch = VerifierRegistry::new(root.path());
        let day = Duration::from_secs(MAX_TIMEOUT_SECONDS);
        assert_eq!(batch.bounded(day), day);

        // An interactive caller does not.
        let interactive = VerifierRegistry::new(root.path()).interactive();
        assert_eq!(
            interactive.bounded(day).as_secs(),
            INTERACTIVE_TIMEOUT_SECONDS
        );
        // A timeout already under the ceiling is left alone, so the clamp
        // never *extends* what an objective asked for.
        assert_eq!(interactive.bounded(Duration::from_secs(5)).as_secs(), 5);
    }

    #[test]
    fn a_checker_that_floods_its_output_is_stopped_and_reported_unavailable() {
        // Only a digest of the capture is retained, so an unbounded one buys
        // nothing and costs the operator's disk -- and then the
        // node's memory when the capture is read back.
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-flood");
        // Writes well past the cap, as fast as it can.
        let source = "import sys\n\n\ndef check(artifact):\n    \
                      block = 'x' * 65536\n    \
                      while True:\n        sys.stdout.write(block)\n";
        let sha = write_pinned(&root, "flood.py", source);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("flood.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
            ("timeout_seconds", Value::Int(60)),
        ]);
        let started = Instant::now();
        let verdict = registry.run(&spec, &empty_object());
        // A node that could not complete the check says nothing about the
        // artifact -- this is infrastructure, so Unavailable and never Reject.
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
        assert!(!verdict.status.settles());
        // Stopped on the cap, well before the 60s deadline.
        assert!(
            started.elapsed() < Duration::from_secs(45),
            "the cap did not stop it: {:?}",
            started.elapsed()
        );
        // And nothing enormous was left behind in the scratch directory.
        assert!(
            !root.path().join("stdout").exists()
                || fs::metadata(root.path().join("stdout"))
                    .map(|m| m.len() <= MAX_CAPTURED_BYTES * 2)
                    .unwrap_or(true)
        );
    }

    // -- shipped examples --------------------------------------------------

    #[test]
    fn the_shipped_examples_verify() {
        // A broken example is a broken claim.
        if !have("python3") {
            return;
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let registry = VerifierRegistry::new(&root);
        for (name, artifact_field) in [
            ("collatz", "n"),
            ("capset", "points"),
            ("permutation", "observations"),
        ] {
            let objective_text =
                match fs::read_to_string(root.join("examples").join(name).join("objective.json")) {
                    Ok(text) => text,
                    Err(_) => continue,
                };
            let artifact_text =
                match fs::read_to_string(root.join("examples").join(name).join("artifact.json")) {
                    Ok(text) => text,
                    Err(_) => continue,
                };
            let objective = Value::from_json(&objective_text).expect("objective json");
            let artifact = Value::from_json(&artifact_text).expect("artifact json");
            let spec = objective.get("verifier").expect("verifier").clone();
            assert!(artifact.get(artifact_field).is_some());
            let verdict = registry.run(&spec, &artifact);
            assert_eq!(verdict.status, Status::Accept, "{name}: {}", verdict.detail);
            // Whatever the artifact does, the spec itself must be well formed:
            // a stale pin would surface as InvalidSpec.
            assert_ne!(
                registry.run(&spec, &empty_object()).status,
                Status::InvalidSpec
            );
        }
    }

    // -- paths and plumbing ------------------------------------------------

    #[test]
    fn normalization_resolves_dots_without_touching_the_filesystem() {
        assert_eq!(normalize(Path::new("/a/b/../c")), PathBuf::from("/a/c"));
        assert_eq!(normalize(Path::new("/a/./b/")), PathBuf::from("/a/b"));
        assert_eq!(normalize(Path::new("/..")), PathBuf::from("/"));
        assert_eq!(normalize(Path::new("/../..")), PathBuf::from("/"));
        assert_eq!(normalize(Path::new("a/../b")), PathBuf::from("b"));
        assert_eq!(normalize(Path::new("../b")), PathBuf::from("../b"));
        assert_eq!(normalize(Path::new("")), PathBuf::from("."));
        assert_eq!(normalize(Path::new("./")), PathBuf::from("."));
    }

    #[test]
    fn absolutize_makes_a_relative_root_comparable() {
        let absolute = absolutize(Path::new(".")).expect("cwd");
        assert!(absolute.is_absolute());
        let joined = absolutize(&absolute.join("sub/../file.py")).expect("join");
        assert_eq!(joined, absolute.join("file.py"));
        assert!(joined.starts_with(&absolute));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_cannot_escape_pinned_or_mounted_bundle_paths() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let root = tmpdir("proofwork-symlink-root");
        let outside = tmpdir("proofwork-symlink-outside");
        fs::write(outside.path().join("checker.py"), CHECKER).expect("outside checker");
        symlink(outside.path(), root.path().join("escape")).expect("symlink");

        // Unix-domain socket paths are short (104 bytes on macOS), while the
        // ordinary scratch helper deliberately carries a long unique name.
        let socket_dir = TempDir {
            path: PathBuf::from("/tmp").join(format!(
                "pw-symlink-{}-{}",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            )),
        };
        create_private_dir(socket_dir.path()).expect("short socket dir");
        let _socket = UnixListener::bind(socket_dir.path().join("s")).expect("outside socket");
        symlink(socket_dir.path(), root.path().join("escape-socket")).expect("socket symlink");

        assert!(contained_dir(root.path(), "escape").is_none());

        let registry = VerifierRegistry::new(root.path());
        let declared = sha256_hex(CHECKER.as_bytes());
        assert!(matches!(
            registry.resolve_pinned("escape/checker.py", &declared),
            Err(PinFailure::Escape)
        ));
        // A regular outside file would still end in Escape if a buggy resolver
        // opened it first and canonicalized second. A socket cannot be read as a
        // file: Escape here proves containment is decided before any open/read.
        assert!(matches!(
            registry.resolve_pinned("escape-socket/s", &declared),
            Err(PinFailure::Escape)
        ));

        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("escape/checker.py")),
            ("checker_sha256", Value::string(declared.clone())),
            ("entrypoint", Value::string("check")),
        ]);
        assert!(registry.publish_code(&spec).is_empty());
        assert!(!registry.blobs().holds(&declared));
    }

    #[test]
    fn which_finds_a_real_binary_and_not_an_imaginary_one() {
        assert!(which("proofwork-nonexistent-binary-xyz").is_none());
        assert!(which("").is_none());
        assert!(which("/proofwork/does/not/exist").is_none());
        if have("sh") {
            let found = which("sh").expect("sh");
            assert!(is_executable_file(&found));
        }
    }

    #[test]
    fn a_temp_dir_is_removed_when_it_drops() {
        let path = {
            let dir = tmpdir("proofwork-drop");
            let path = dir.path().to_path_buf();
            fs::write(path.join("scratch"), b"x").expect("write");
            assert!(path.exists());
            path
        };
        assert!(!path.exists());
    }

    #[test]
    fn temp_dirs_do_not_collide() {
        let first = tmpdir("proofwork-unique");
        let second = tmpdir("proofwork-unique");
        assert_ne!(first.path(), second.path());
    }

    #[test]
    fn canonicalize_refuses_a_float_field() {
        let float: serde_json::Value = serde_json::from_str("1.5").expect("json");
        assert!(canonicalize(&float).is_err());
        let integer: serde_json::Value = serde_json::from_str("7").expect("json");
        assert_eq!(canonicalize(&integer).ok(), Some(Value::Int(7)));
    }

    /// The predecessor of this test asserted the note still said "NOT a
    /// sandbox". That was the right test while there was no jail. Now there is
    /// one, and the risk has inverted: the note could quietly grow into a claim
    /// that the boundary is stronger than it is. So the assertions moved to the
    /// remaining gaps, which are the part a reader acts on and the part a future
    /// edit is tempted to drop.
    #[test]
    fn the_sandboxing_note_names_both_the_boundary_and_its_gaps() {
        for enforced in ["bubblewrap", "seatbelt", "no network", "scrubbed"] {
            assert!(SANDBOXING.contains(enforced), "missing: {enforced}");
        }
        assert!(SANDBOXING.contains("NOT a VM boundary"));
        for gap in [
            // A kernel escape is still an escape.
            "kernel",
            // No jail at all on an unsupported host.
            sandbox::REQUIRE_ENV,
        ] {
            assert!(SANDBOXING.contains(gap), "gap not stated: {gap}");
        }
    }

    #[test]
    fn objective_code_runs_jailed_on_a_host_that_has_a_jail() {
        // A jail that is silently not applied is the failure this whole module
        // exists to prevent, and it looks identical to a working one from the
        // outside. Assert the mechanism is actually reached.
        if !have("python3") || !sandbox::mechanism().is_jail() {
            return;
        }
        let root = tmpdir("proofwork-jail-network");
        // Opening a socket is the single capability the jail must remove.
        let source = "import socket\n\
                      def check(artifact):\n\
                      \x20   s = socket.socket()\n\
                      \x20   s.settimeout(2)\n\
                      \x20   s.connect((\"1.1.1.1\", 80))\n\
                      \x20   return True\n";
        let sha = write_pinned(&root, "net.py", source);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("net.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
            ("timeout_seconds", Value::Int(30)),
        ]);
        let verdict = registry.run(&spec, &empty_object());
        // The checker crashes because the connect is refused, and a crashed
        // checker is Unavailable. What must never happen is Accept.
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
        assert_eq!(
            verdict.evidence.get("sandbox").and_then(Value::as_str),
            Some(sandbox::mechanism().as_str())
        );
    }

    #[test]
    fn objective_code_cannot_write_outside_its_scratch_directory() {
        if !have("python3") || !sandbox::mechanism().is_jail() {
            return;
        }
        let root = tmpdir("proofwork-jail-write");
        let target = root.path().join("escaped.txt");
        let source = format!(
            "def check(artifact):\n    open({:?}, \"w\").write(\"x\")\n    return True\n",
            target.to_string_lossy()
        );
        let sha = write_pinned(&root, "w.py", &source);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("w.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &empty_object());
        // The promise is the host's: nothing outside scratch is written there.
        // How the attempt ends is the mechanism's, and the two differ. Seatbelt
        // denies the write, the checker raises, and a crash is Unavailable.
        // Under bubblewrap the write succeeds -- into the jail. It shows `w.py`
        // and not the directory around it, so bwrap made that directory as a
        // mount point on its own tmpfs: writable, and gone with the namespace.
        // Refusing it would take more than `--remount-ro /`, because under
        // `/tmp` that directory is on `/tmp`'s tmpfs, a mount of its own; and a
        // read-only `/tmp` would fail honest code that writes there rather than
        // to `$TMPDIR`, to protect nothing the host can see. So it is allowed,
        // and this pins that it stays out of the host.
        assert!(!target.exists(), "the jail let a write through to the host");
        let expected = match sandbox::mechanism() {
            sandbox::Mechanism::Bubblewrap(_) => Status::Accept,
            _ => Status::Unavailable,
        };
        assert_eq!(verdict.status, expected, "{}", verdict.detail);
    }

    #[test]
    fn objective_code_can_write_its_scratch_directory() {
        // The other half of the test above: `$TMPDIR` is where objective code
        // may write, and it has to be writable. Under bubblewrap it was not. A
        // pinned run starts in its scratch directory, and the jail bound that
        // cwd read-only after binding it writable, so the later mount won and a
        // checker using `tempfile` was Unavailable on Linux alone.
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-jail-scratch");
        let source = "import os\n\
                      def check(artifact):\n\
                      \x20   path = os.path.join(os.environ[\"TMPDIR\"], \"scratch\")\n\
                      \x20   with open(path, \"w\") as out:\n\
                      \x20       out.write(\"x\")\n\
                      \x20   with open(path) as back:\n\
                      \x20       return back.read() == \"x\"\n";
        let sha = write_pinned(&root, "scratch.py", source);
        let registry = VerifierRegistry::new(root.path());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("scratch.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &empty_object());
        assert_eq!(verdict.status, Status::Accept, "{}", verdict.detail);
    }

    /// `name`, reached as `which` reaches `python3` on many hosts: through an
    /// absolute symlink whose target is another absolute symlink, in a
    /// directory the jail has no reason to show. Debian's `/usr/bin/python3 ->
    /// /etc/alternatives/python3` is the shape. Returns the path to hand over.
    #[cfg(unix)]
    fn through_alternatives(dir: &Path, elsewhere: &TempDir, name: &str, file: &Path) -> PathBuf {
        let hop = elsewhere.path().join(name);
        std::os::unix::fs::symlink(file, &hop).expect("symlink");
        fs::create_dir_all(dir).expect("dir");
        std::os::unix::fs::symlink(&hop, dir.join(name)).expect("symlink");
        dir.join(name)
    }

    #[cfg(unix)]
    #[test]
    fn an_interpreter_named_through_absolute_symlinks_still_verifies() {
        // `which` hands over a name, and on many hosts it is an absolute
        // symlink. Under bubblewrap, `/usr/local/bin/python3 ->
        // /usr/bin/python3.11` made every pinned verdict on its host
        // Unavailable: the jail mounted the interpreter at that name, inside
        // its `/usr` bind, and a mount cannot land on a symlink. A test cannot
        // put a link under `/usr`; the sandbox's own tests rebuild that failure
        // in a directory the jail shows. This is the pinned path end to end,
        // with an interpreter that only runs if the jail recreates both links.
        let Some(python) = which("python3") else {
            return;
        };
        let root = tmpdir("proofwork-symlinked-python");
        let elsewhere = tmpdir("proofwork-alternatives");
        let interpreter =
            through_alternatives(&root.path().join("bin"), &elsewhere, "python3", &python);
        let sha = write_pinned(&root, "checker.py", CHECKER);
        let registry = VerifierRegistry::new(root.path())
            .with_python_binary(interpreter.to_string_lossy().into_owned());
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("checker.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &Value::object([("n", Value::Int(42))]));
        assert_eq!(verdict.status, Status::Accept, "{}", verdict.detail);
    }

    #[cfg(unix)]
    #[test]
    fn a_lean_named_through_absolute_symlinks_is_run_not_rejected() {
        // Lean is the verifier whose non-zero exit is a verdict, and a jail
        // that cannot execute the binary exits non-zero too. A `lean` reached
        // through a link the jail showed but could not follow -- here inside
        // the declared project, its target outside it -- came back Reject: the
        // shell's "not found" read as the kernel refusing the proof. The
        // replaying stand-in accepts an honest proof, so anything other than
        // Accept is the jail's doing.
        if !have("sh") || !have("cat") {
            return;
        }
        let root = tmpdir("proofwork-symlinked-lean");
        let elsewhere = tmpdir("proofwork-lean-elsewhere");
        let stand_in = replaying_lean(elsewhere.path());
        let binary = through_alternatives(
            &root.path().join("project/bin"),
            &elsewhere,
            "lean",
            &stand_in,
        );
        let registry =
            VerifierRegistry::new(root.path()).with_lean_binary(binary.to_string_lossy());
        let spec = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("example : True")),
            ("project_root", Value::string("project")),
        ]);
        let artifact = Value::object([("proof", Value::string(":= trivial"))]);
        let verdict = registry.run(&spec, &artifact);
        assert_eq!(verdict.status, Status::Accept, "{}", verdict.detail);
    }

    /// A stand-in Lean that speaks the replay protocol. Compiling (`-R DIR -o
    /// OLEAN FILE`) copies the source to the "olean", warning on `sorry` the
    /// way Lean does; replaying (`--run DRIVER CLAIM STATEMENT THEOREM
    /// MARKER`) reports from words in the claim's text, so each branch of the
    /// verdict can be reached without a real toolchain. A real one is
    /// exercised by `a_real_lean_replays_what_it_compiled`.
    #[cfg(unix)]
    fn replaying_lean(dir: &Path) -> PathBuf {
        replaying_lean_after(dir, "replaying-lean", "")
    }

    /// The replaying stand-in with `prelude` run first, so a test can make
    /// some calls answer differently. It stays one file: a jail shows the
    /// verifier the Lean binary it was given, not that binary's directory,
    /// so a wrapper that execs a second stand-in beside it exits 127 there.
    #[cfg(unix)]
    fn replaying_lean_after(dir: &Path, name: &str, prelude: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let lean = dir.join(name);
        fs::write(
            &lean,
            String::from("#!/bin/sh\n")
                + prelude
                + "case \"$1\" in\n\
             -R)\n\
               cat \"$5\" > \"$4\" || exit 1\n\
               case \"$(cat \"$5\")\" in *sorry*) echo \"$5:2:0: warning: declaration uses 'sorry'\";; esac\n\
               exit 0;;\n\
             --run)\n\
               text=$(cat \"$3\"); m=\"$6\"\n\
               echo \"$m replayed 1\"\n\
               case \"$text\" in\n\
               *REPLAY_REFUSES*) echo \"$m fail kernel replay: (kernel) declaration type mismatch\"; exit 1;;\n\
               *REPLAY_EXHAUSTED*) echo \"$m unavailable kernel replay: (kernel) deep recursion detected\"; exit 1;;\n\
               esac\n\
               case \"$text\" in *ADDS_AXIOM*) echo \"$m added-axiom t.added\"; echo \"$m axiom t.added\";; esac\n\
               case \"$text\" in *NATIVE_AXIOM*) echo \"$m added-axiom t._native.native_decide.ax_1_1\"; echo \"$m axiom t._native.native_decide.ax_1_1\";; esac\n\
               case \"$text\" in *PINNED_AXIOM*) echo \"$m pinned Assume.choice_free\"; echo \"$m axiom Assume.choice_free\";; esac\n\
               case \"$text\" in *sorry*) echo \"$m axiom sorryAx\";; esac\n\
               case \"$text\" in *ofReduceBool*) echo \"$m axiom Lean.ofReduceBool\";; esac\n\
               [ \"$5\" = \"-\" ] || echo \"$m axiom propext\"\n\
               echo \"$m ok\"; exit 0;;\n\
             esac\n\
             echo \"unexpected arguments: $*\" >&2; exit 2\n",
        )
        .expect("write stand-in");
        fs::set_permissions(&lean, fs::Permissions::from_mode(0o755)).expect("chmod");
        lean
    }

    /// What the replay reports decides the verdict: the standard axioms pass,
    /// an axiom the objective did not allow is refused, the objective can
    /// allow one by name or with `allow_native_decide`, a proof may not add
    /// an axiom of its own, and a replay the kernel refused is a rejection
    /// while one it could not finish is not.
    #[cfg(unix)]
    #[test]
    fn the_kernel_replay_decides_what_a_clean_compile_rests_on() {
        if !have("sh") || !have("cat") {
            return;
        }
        let root = tmpdir("proofwork-lean-replay");
        let lean = replaying_lean(root.path());
        let registry = VerifierRegistry::new(root.path()).with_lean_binary(lean.to_string_lossy());
        let spec = |extra: Vec<(&str, Value)>| {
            let mut fields = vec![
                ("kind", Value::string("lean")),
                ("statement", Value::string("theorem audited : 2 + 2 = 4")),
            ];
            fields.extend(extra);
            Value::object(fields)
        };
        let proof = |text: &str| Value::object([("proof", Value::string(text))]);

        let verdict = registry.run(&spec(vec![]), &proof(":= rfl"));
        assert_eq!(verdict.status, Status::Accept, "{}", verdict.detail);
        assert_eq!(
            verdict.evidence.get("axioms"),
            Some(&Value::Array(vec![Value::string("propext")]))
        );
        assert!(verdict.evidence.get("replay_output_sha256").is_some());

        // `Lean.ofReduceBool` named directly, not through `native_decide`, so
        // the token screen never saw it. The replay does.
        let compiler = proof(":= Lean.ofReduceBool _ _ rfl");
        let verdict = registry.run(&spec(vec![]), &compiler);
        assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
        assert!(
            verdict.detail.contains("Lean.ofReduceBool"),
            "{}",
            verdict.detail
        );
        let opted = registry.run(
            &spec(vec![("allow_native_decide", Value::Bool(true))]),
            &compiler,
        );
        assert_eq!(opted.status, Status::Accept, "{}", opted.detail);
        let listed = registry.run(
            &spec(vec![(
                "allowed_axioms",
                Value::Array(vec![Value::string("Lean.ofReduceBool")]),
            )]),
            &compiler,
        );
        assert_eq!(listed.status, Status::Accept, "{}", listed.detail);

        // What `native_decide` adds on a recent Lean: an axiom per use. Only
        // an objective that opted in takes it.
        let native = proof(":= rfl -- NATIVE_AXIOM");
        let verdict = registry.run(&spec(vec![]), &native);
        assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
        let opted = registry.run(
            &spec(vec![("allow_native_decide", Value::Bool(true))]),
            &native,
        );
        assert_eq!(opted.status, Status::Accept, "{}", opted.detail);

        // An axiom the claim's module declared and the statement's did not:
        // a metaprogram's. Refused even when the objective lists the name,
        // because a proof may not add axioms at all.
        let added = proof(":= rfl -- ADDS_AXIOM");
        for extra in [
            vec![],
            vec![(
                "allowed_axioms",
                Value::Array(vec![Value::string("t.added")]),
            )],
        ] {
            let verdict = registry.run(&spec(extra), &added);
            assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
            assert!(
                verdict.detail.contains("may not add axioms"),
                "{}",
                verdict.detail
            );
        }

        // The statement's own axiom, reported by the replay as declared by
        // the statement's compile: the objective's assumption, allowed.
        let pinned = registry.run(&spec(vec![]), &proof(":= rfl -- PINNED_AXIOM"));
        assert_eq!(pinned.status, Status::Accept, "{}", pinned.detail);

        // The kernel refused a declaration on replay: the claim's doing.
        let refused = registry.run(&spec(vec![]), &proof(":= rfl -- REPLAY_REFUSES"));
        assert_eq!(refused.status, Status::Reject, "{}", refused.detail);
        assert!(
            refused.detail.contains("kernel replay refused"),
            "{}",
            refused.detail
        );
        // The kernel ran out of room on replay: this node's doing.
        let exhausted = registry.run(&spec(vec![]), &proof(":= rfl -- REPLAY_EXHAUSTED"));
        assert_eq!(
            exhausted.status,
            Status::Unavailable,
            "{}",
            exhausted.detail
        );
        assert!(!exhausted.status.settles());

        // A malformed allow-list is the objective's fault, found before Lean.
        let bad = VerifierRegistry::new(root.path()).with_lean_binary("lean-does-not-exist-xyz");
        let verdict = bad.run(
            &spec(vec![("allowed_axioms", Value::string("Lean.ofReduceBool"))]),
            &proof(":= rfl"),
        );
        assert_eq!(verdict.status, Status::InvalidSpec, "{}", verdict.detail);
    }

    /// The replay against a real toolchain, when `CAIRN_TEST_LEAN` names one
    /// (CI has none; the stand-in above covers every branch there). Honest
    /// proofs pass with the axioms they really use, the statement's own
    /// axiom is the objective's to allow, an `example` replays with nothing to
    /// audit, and `native_decide`'s per-use axiom is taken only with the
    /// objective's leave.
    #[test]
    fn a_real_lean_replays_what_it_compiled() {
        let Some(lean) = std::env::var_os("CAIRN_TEST_LEAN") else {
            return;
        };
        let root = tmpdir("proofwork-real-lean");
        let registry = VerifierRegistry::new(root.path()).with_lean_binary(lean.to_string_lossy());
        let run = |preamble: &str, statement: &str, proof: &str, native: bool| {
            let spec = Value::object([
                ("kind", Value::string("lean")),
                ("preamble", Value::string(preamble)),
                ("statement", Value::string(statement)),
                ("allow_native_decide", Value::Bool(native)),
            ]);
            registry.run(&spec, &Value::object([("proof", Value::string(proof))]))
        };
        let axioms = |verdict: &Verdict| -> Vec<String> {
            match verdict.evidence.get("axioms") {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect(),
                _ => Vec::new(),
            }
        };

        let honest = run(
            "",
            "theorem pw_add_comm (a b : Nat) : a + b = b + a",
            ":= Nat.add_comm a b",
            false,
        );
        assert_eq!(honest.status, Status::Accept, "{}", honest.detail);
        assert!(axioms(&honest).is_empty(), "{:?}", axioms(&honest));

        let classical = run(
            "",
            "theorem pw_em (p : Prop) : p ∨ ¬p",
            ":= Classical.em p",
            false,
        );
        assert_eq!(classical.status, Status::Accept, "{}", classical.detail);
        assert!(axioms(&classical).iter().any(|a| a == "Classical.choice"));

        let private = run(
            "private def double : Nat → Nat\n  | 0 => 0\n  | n + 1 => double n + 2",
            "theorem pw_double (n : Nat) : double n = 2 * n",
            ":= by induction n with | zero => rfl | succ k ih => simp [double, ih]; omega",
            false,
        );
        assert_eq!(private.status, Status::Accept, "{}", private.detail);

        let assumed = run(
            "axiom pw_assumption : 1 = 2",
            "theorem pw_uses : 1 = 2",
            ":= pw_assumption",
            false,
        );
        assert_eq!(assumed.status, Status::Accept, "{}", assumed.detail);

        let example = run("", "example (a : Nat) : a = a", ":= rfl", false);
        assert_eq!(example.status, Status::Accept, "{}", example.detail);

        let wrong = run("", "theorem pw_wrong : 2 + 2 = 5", ":= rfl", false);
        assert_eq!(wrong.status, Status::Reject, "{}", wrong.detail);

        let native = run(
            "",
            "theorem pw_native : 10 < 20",
            ":= by native_decide",
            true,
        );
        assert_eq!(native.status, Status::Accept, "{}", native.detail);
    }

    /// A Lean on which the replay does not run is found by the control and
    /// reported Unavailable -- never a verdict about the proof.
    #[cfg(unix)]
    #[test]
    fn a_lean_the_replay_cannot_run_on_is_unavailable() {
        let Some(silent) = which("true") else {
            return;
        };
        let root = tmpdir("proofwork-lean-silent");
        let registry =
            VerifierRegistry::new(root.path()).with_lean_binary(silent.to_string_lossy());
        let spec = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem silent_replay : True")),
        ]);
        let verdict = registry.run(
            &spec,
            &Value::object([("proof", Value::string(":= trivial"))]),
        );
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
        assert!(verdict.evidence.get("control_replay").is_some());
    }

    #[test]
    fn the_replay_report_is_read_only_from_lines_that_carry_its_marker() {
        let marker = "cairn-kernel-replay-00ff";
        // Unmarked lines, and a marker run into another word, are not the
        // replay: Lean's own warnings share the stream.
        let report = "warning: unused variable\nok\ncairn-kernel-replay-00ffx ok\n\
                      cairn-kernel-replay-00ff replayed 3\n\
                      cairn-kernel-replay-00ff axiom propext\n\
                      cairn-kernel-replay-00ff pinned Assume.p\n\
                      cairn-kernel-replay-00ff added-axiom t.native\n\
                      cairn-kernel-replay-00ff ok\n\
                      cairn-kernel-replay-00ff fail too late to matter\n";
        assert_eq!(
            read_kernel_replay(report, marker),
            KernelReplay::Passed {
                axioms: vec!["propext".into()],
                added: vec!["t.native".into()],
                pinned: vec!["Assume.p".into()],
            }
        );
        assert_eq!(
            read_kernel_replay(
                "cairn-kernel-replay-00ff fail t is a def, not a theorem",
                marker
            ),
            KernelReplay::Refused("t is a def, not a theorem".into())
        );
        assert_eq!(
            read_kernel_replay(
                "cairn-kernel-replay-00ff unavailable kernel replay: x",
                marker
            ),
            KernelReplay::Unavailable("kernel replay: x".into())
        );
        assert_eq!(
            read_kernel_replay("cairn-kernel-replay-00ff axiom propext\n", marker),
            KernelReplay::NoReport
        );
        assert_eq!(read_kernel_replay("", marker), KernelReplay::NoReport);
    }

    #[test]
    fn the_replay_names_the_statements_theorem_and_holds_axiom_names_exactly() {
        assert_eq!(lean_theorem_name("theorem t : True").as_deref(), Some("t"));
        assert_eq!(
            lean_theorem_name("@[simp] theorem Foo.bar (n : Nat) : n = n").as_deref(),
            Some("Foo.bar")
        );
        assert_eq!(
            lean_theorem_name("lemma l{α : Type} : True").as_deref(),
            Some("l")
        );
        assert_eq!(lean_theorem_name("example : True"), None);
        // A word that merely contains the keyword is not one.
        assert_eq!(lean_theorem_name("def theorems : Nat"), None);

        assert!(is_native_decide_axiom("t._native.native_decide.ax_1_1"));
        assert!(!is_native_decide_axiom("native_decide"));
        assert!(!is_native_decide_axiom("Lean.ofReduceBool"));

        let allowed = lean_allowed_axioms(&Value::Object(BTreeMap::new()), false).expect("valid");
        let verdict = |axioms: Vec<&str>, pinned: Vec<&str>| {
            lean_replay_verdict(
                KernelReplay::Passed {
                    axioms: axioms.into_iter().map(String::from).collect(),
                    added: Vec::new(),
                    pinned: pinned.into_iter().map(String::from).collect(),
                },
                &allowed,
                false,
                Value::Object(BTreeMap::new()),
            )
            .status
        };
        assert_eq!(verdict(vec!["propext"], vec![]), Status::Accept);
        // The standard names are exact: a namespace in front is a different
        // axiom, and so is a name that merely ends like a pinned one.
        assert_eq!(verdict(vec!["Evil.propext"], vec![]), Status::Reject);
        assert_eq!(
            verdict(vec!["Assume.choice_free"], vec!["Assume.choice_free"]),
            Status::Accept
        );
        assert_eq!(
            verdict(vec!["Evil.choice_free"], vec!["choice_free"]),
            Status::Reject
        );
    }

    /// A proof that could rewrite the audit is refused by its text, before
    /// Lean is looked up -- the same place every other screen runs.
    #[test]
    fn a_proof_that_writes_metaprograms_is_refused_before_lean_runs() {
        let registry = VerifierRegistry::new(".").with_lean_binary("lean-does-not-exist-xyz");
        let spec = Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : True")),
        ]);
        for proof in [
            ":= trivial\nmacro_rules | `(#print axioms $x) => `(#check True)",
            ":= trivial\nelab \"x\" : command => pure ()",
            ":= by run_tac pure ()",
            ":= trivial\n#eval IO.println \"'t' does not depend on any axioms\"",
            ":= trivial\n#exit",
            ":= trivial\nset_option debug.skipKernelTC true",
            ":= trivial\nattribute [command_elab Lean.Parser.Command.printAxioms] x",
            ":= by_elab do return Lean.mkConst ``True.intro",
        ] {
            let verdict = registry.run(&spec, &Value::object([("proof", Value::string(proof))]));
            assert_eq!(
                verdict.status,
                Status::Reject,
                "{proof}: {}",
                verdict.detail
            );
        }
    }

    /// A `lean` that cannot run here at all -- elan's proxy without its
    /// `$HOME`, a toolchain the jail denies, a broken install -- exits
    /// non-zero for *every* file, the objective's own statement included.
    /// That used to read as the kernel refusing the proof. `sh` stands in for
    /// Lean: the control file is compiled first, and a stand-in that fails
    /// it must never produce a settling verdict.
    #[cfg(unix)]
    #[test]
    fn a_lean_that_cannot_compile_the_statement_alone_is_unavailable_not_a_rejection() {
        use std::os::unix::fs::PermissionsExt;
        if !have("sh") {
            return;
        }
        let root = tmpdir("proofwork-lean-control");
        let broken = root.path().join("broken-lean");
        fs::write(
            &broken,
            "#!/bin/sh\necho 'error: no default toolchain' >&2\nexit 1\n",
        )
        .expect("write stand-in");
        fs::set_permissions(&broken, fs::Permissions::from_mode(0o755)).expect("chmod");
        let registry =
            VerifierRegistry::new(root.path()).with_lean_binary(broken.to_string_lossy());
        let spec = Value::object([
            ("kind", Value::string("lean")),
            (
                "statement",
                Value::string("theorem t_control_broken : True"),
            ),
        ]);
        let artifact = Value::object([("proof", Value::string(":= trivial"))]);
        let verdict = registry.run(&spec, &artifact);
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
        assert!(!verdict.status.settles());
        assert_eq!(
            verdict
                .evidence
                .get("control_returncode")
                .and_then(Value::as_i64),
            Some(1)
        );

        // The converse: a stand-in that compiles and replays the statement
        // alone and then refuses the proof is the kernel saying no, and that
        // is a verdict.
        if !have("cat") {
            return;
        }
        let judging = replaying_lean_after(
            root.path(),
            "judging-lean",
            "case \"$1 $5\" in --run*|*/statement/*) ;; *) echo 'error: type mismatch' >&2; exit 1;; esac\n",
        );
        let registry =
            VerifierRegistry::new(root.path()).with_lean_binary(judging.to_string_lossy());
        let spec = Value::object([
            ("kind", Value::string("lean")),
            (
                "statement",
                Value::string("theorem t_control_judged : True"),
            ),
        ]);
        let verdict = registry.run(&spec, &artifact);
        assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
        // Once the control has passed for this statement it is not run
        // again: the second claim's verdict is the same and the evidence
        // carries no control fields.
        let again = registry.run(&spec, &artifact);
        assert_eq!(again.status, Status::Reject);
        assert!(again.evidence.get("control_returncode").is_none());
    }

    /// The author's pre-post compile: Lean's own words come back, and a
    /// Lean that cannot run is said to be that rather than a broken theorem.
    #[cfg(unix)]
    #[test]
    fn compile_lean_returns_what_lean_said_or_why_it_could_not_run() {
        use std::os::unix::fs::PermissionsExt;
        if !have("sh") {
            return;
        }
        let missing = VerifierRegistry::new(".").with_lean_binary("lean-does-not-exist-xyz");
        assert!(matches!(
            missing.compile_lean("theorem t : True := trivial", Duration::from_secs(5)),
            LeanCompile::Unavailable(_)
        ));

        let root = tmpdir("proofwork-lean-compile");
        let lean = root.path().join("lean");
        fs::write(
            &lean,
            "#!/bin/sh\ncase \"$(cat \"$1\")\" in *broken*) echo \"$1:1:0: error: unknown identifier\"; exit 1;; *) exit 0;; esac\n",
        )
        .expect("write stand-in");
        fs::set_permissions(&lean, fs::Permissions::from_mode(0o755)).expect("chmod");
        let registry = VerifierRegistry::new(root.path()).with_lean_binary(lean.to_string_lossy());
        assert_eq!(
            registry.compile_lean("theorem t : True := trivial", Duration::from_secs(30)),
            LeanCompile::Ran {
                code: 0,
                output: String::new()
            }
        );
        match registry.compile_lean("theorem broken : True := nope", Duration::from_secs(30)) {
            LeanCompile::Ran { code, output } => {
                assert_eq!(code, 1);
                // The jail's scratch path is not shown to the author.
                assert_eq!(
                    output.trim(),
                    "Challenge.lean:1:0: error: unknown identifier"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_lean_binary_and_a_granted_root_show_in_the_readiness_report() {
        let registry = VerifierRegistry::new(".")
            .with_lean_binary("lean-does-not-exist-xyz")
            .with_lean_root(Some(PathBuf::from("/opt/lean-toolchain")));
        let report = registry.readiness();
        let lean = report
            .get("toolchains")
            .and_then(|t| t.get("lean"))
            .expect("lean row");
        assert_eq!(
            lean.get("binary").and_then(Value::as_str),
            Some("lean-does-not-exist-xyz")
        );
        assert_eq!(lean.get("available"), Some(&Value::Bool(false)));
        assert_eq!(lean.get("path"), Some(&Value::Null));
        assert_eq!(
            lean.get("granted_root").and_then(Value::as_str),
            Some("/opt/lean-toolchain")
        );
        // An absent toolchain is an unservable kind with a reason, never a
        // kind that silently vanished from the list.
        let unservable = report.get("unservable").expect("unservable");
        assert!(unservable
            .get("lean")
            .and_then(Value::as_str)
            .is_some_and(|why| why.contains("Lean toolchain")));
        let kinds: Vec<&str> = match report.get("kinds") {
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        assert!(kinds.contains(&"lean"));
    }

    /// pyenv's `~/.pyenv/shims/python3`, as far as the jail is concerned: a
    /// script that execs something the jail does not show, and exits 126.
    #[cfg(unix)]
    fn pyenv_shim(dir: &TempDir) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let shims = dir.path().join("shims");
        fs::create_dir_all(&shims).expect("shims dir");
        let shim = shims.join("python3");
        fs::write(
            &shim,
            "#!/bin/sh\nexec /nonexistent/.pyenv/libexec/pyenv exec python3 \"$@\"\n",
        )
        .expect("write shim");
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("chmod shim");
        shim
    }

    #[cfg(unix)]
    #[test]
    fn a_shim_python_is_refused_up_front_as_unavailable_with_the_fix() {
        let root = tmpdir("proofwork-shim-python");
        let shim = pyenv_shim(&root);
        let registry =
            VerifierRegistry::new(root.path()).with_python_binary(shim.to_string_lossy());

        // Under a jail: refused before anything spawns, as Unavailable, with
        // the variables that fix it named and the mechanism in evidence.
        let seatbelt = sandbox::Mechanism::Seatbelt(PathBuf::from("/usr/bin/sandbox-exec"));
        let verdict = registry
            .pinned_interpreter("checker", seatbelt)
            .expect_err("a shim under a jail must be refused");
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
        assert!(
            verdict.detail.contains("version-manager shim"),
            "{}",
            verdict.detail
        );
        assert!(verdict.detail.contains(PYTHON_ENV), "{}", verdict.detail);
        assert!(
            verdict.detail.contains(PYTHON_ROOT_ENV),
            "{}",
            verdict.detail
        );
        assert_eq!(
            verdict.evidence.get("sandbox").and_then(Value::as_str),
            Some("sandbox-exec")
        );

        // Unconfined a shim finds its manager, so it is not refused there.
        assert_eq!(
            registry.pinned_interpreter("checker", sandbox::Mechanism::None("test")),
            Ok(shim.clone())
        );

        // End to end on this host, whatever its jail: never a rejection.
        let sha = write_pinned(&root, "checker.py", CHECKER);
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("checker.py")),
            ("checker_sha256", Value::string(sha)),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &Value::object([("n", Value::Int(42))]));
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
        if sandbox::mechanism().is_jail() {
            assert!(verdict.detail.contains(PYTHON_ENV), "{}", verdict.detail);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_shim_python_is_reported_unservable_by_the_readiness_report() {
        let root = tmpdir("proofwork-shim-readiness");
        let shim = pyenv_shim(&root);
        let registry = VerifierRegistry::new(root.path())
            .with_python_binary(shim.to_string_lossy())
            .with_python_root(Some(PathBuf::from("/opt/python-prefix")));
        let seatbelt = sandbox::Mechanism::Seatbelt(PathBuf::from("/usr/bin/sandbox-exec"));
        let report = registry.readiness_under(seatbelt, false);

        let python = report
            .get("toolchains")
            .and_then(|t| t.get("python3"))
            .expect("python3 row");
        // Found, and still not runnable: both are said.
        assert_eq!(python.get("available"), Some(&Value::Bool(true)));
        assert!(python
            .get("problem")
            .and_then(Value::as_str)
            .is_some_and(|why| why.contains(PYTHON_ENV)));
        assert_eq!(
            python.get("granted_root").and_then(Value::as_str),
            Some("/opt/python-prefix")
        );
        let unservable = report.get("unservable").expect("unservable");
        let servable: Vec<&str> = match report.get("servable") {
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        for kind in ["certificate", "evaluator", "statistical"] {
            assert!(
                unservable
                    .get(kind)
                    .and_then(Value::as_str)
                    .is_some_and(|why| why.contains("version-manager shim")),
                "{kind} should be unservable behind a shim"
            );
            assert!(!servable.contains(&kind));
        }

        // Without a jail there is nothing to refuse.
        let unjailed = registry.readiness_under(sandbox::Mechanism::None("test"), false);
        let python = unjailed
            .get("toolchains")
            .and_then(|t| t.get("python3"))
            .expect("python3 row");
        assert_eq!(python.get("problem"), Some(&Value::Null));
    }

    #[test]
    fn requiring_a_sandbox_that_is_absent_is_unavailable_never_a_rejection() {
        // Cannot be exercised by setting the env var here -- the probe is
        // cached process-wide and tests share a process -- so the decision
        // function is checked directly. The invariant is the one that matters:
        // no configuration of this module produces a settling verdict.
        let dir = tmpdir("proofwork-require");
        let plan = sandbox::Confinement::new(dir.path(), dir.path(), 1);
        if let sandbox::Mechanism::None(_) = sandbox::mechanism() {
            // Only reachable on a host with no jail; the error type carries no
            // status, which is what makes a rejection unconstructible here.
            let outcome = sandbox::confine(Path::new("/bin/true"), &[], &plan);
            assert!(outcome.is_ok() || matches!(outcome, Err(sandbox::Unavailable(_))));
        }
    }
}
