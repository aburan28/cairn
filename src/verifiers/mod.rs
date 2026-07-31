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
//! # Four verifiers
//!
//! | kind | what it proves | cost |
//! |---|---|---|
//! | `certificate` | an NP witness recomputes | milliseconds |
//! | `evaluator` | a pinned deterministic score clears a threshold | one evaluation |
//! | `lean` | a proof-assistant kernel accepted the proof | seconds to minutes |
//! | `replay` | a pinned computation reproduces its declared fields | a full re-run |
//!
//! # Architectural change from the Python reference: subprocess, not `exec`
//!
//! The reference implementation `exec`s pinned checker and evaluator source
//! **in-process**. This port runs it as a **subprocess** instead. Two reasons,
//! both real:
//!
//! 1. *Security.* In-process execution gives a malicious objective author the
//!    address space of every contributor who touches the objective -- their
//!    keys, their ledger, their filesystem handles. A subprocess is a genuine
//!    (if partial) improvement and the first step toward the jail described in
//!    [`SANDBOXING`], which the roadmap flags as a launch blocker.
//! 2. *Practicality.* The pinned checkers in `examples/` are Python. Rust cannot
//!    `exec` them; it can spawn an interpreter that can.
//!
//! The hash is verified **before** the subprocess is spawned, so tampered code
//! is never executed at all. A hash mismatch is [`Status::InvalidSpec`] rather
//! than `Reject`: the checker's hash is part of the objective's identity, so a
//! file that no longer matches its pin means the *objective* is broken, not that
//! the submitted artifact is bad.
//!
//! The other consequence of the subprocess design is a liveness one: an
//! in-process `exec` of a looping checker hangs the node forever, while every
//! child spawned here runs under a wall-clock bound and is killed on expiry.
//! Expiry yields `Unavailable`, so a slow checker can never become a rejection.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

use crate::canonical::Value;
use crate::store::blobs::BlobStore;

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
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Certificate => "certificate",
            Kind::Evaluator => "evaluator",
            Kind::Lean => "lean",
            Kind::Replay => "replay",
        }
    }

    pub fn parse(text: &str) -> Option<Kind> {
        match text {
            "certificate" => Some(Kind::Certificate),
            "evaluator" => Some(Kind::Evaluator),
            "lean" => Some(Kind::Lean),
            "replay" => Some(Kind::Replay),
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

/// Note carried across from the reference implementation, updated for the
/// subprocess design. Still a launch blocker, not a nice-to-have.
pub const SANDBOXING: &str = "\
Pinned verifier code runs in a child process rather than in this process, which \
is strictly better than the reference implementation's in-process exec: a \
crashing or looping checker cannot take the node down, it cannot read this \
process's memory, and it dies on a wall-clock deadline. It is NOT a sandbox. \
The child inherits the node's user, filesystem, and network, so a malicious \
objective author still gets code execution on every contributor who touches the \
objective. Before permissionless objective authorship, verifier execution must \
move into a real jail -- container, gVisor/Firecracker, or WASM -- with no \
network, a read-only filesystem view of the objective bundle, a memory cap, and \
an output cap. Tracked as a launch blocker.";

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

/// Characters of subprocess output retained as evidence.
const OUTPUT_TAIL_CHARS: usize = 2000;

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
];

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
const HARNESS: &str = r##"import importlib.util
import json
import sys


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: <pinned file> <entrypoint>\n")
        return 2
    path = sys.argv[1]
    entrypoint = sys.argv[2]
    artifact = json.load(sys.stdin)
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        spec = importlib.util.spec_from_file_location("pinned_verifier", path)
        if spec is None or spec.loader is None:
            sys.stderr.write("cannot load pinned module from %s\n" % (path,))
            return 3
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        func = getattr(module, entrypoint, None)
        if not callable(func):
            sys.stderr.write("no callable entrypoint %r\n" % (entrypoint,))
            return 4
        result = func(artifact)
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

/// Dispatches a verifier spec to the verifier it names.
///
/// `root` is the objective bundle root. Pinned checker and evaluator paths are
/// resolved against it and may not escape it; see [`VerifierRegistry::pinned`].
///
/// `blobs`, if set, is consulted *first* and by content
/// ([`VerifierRegistry::with_blobs`]). A registry without one behaves exactly as
/// this type always has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierRegistry {
    root: PathBuf,
    lean_binary: String,
    python_binary: String,
    blobs: Option<BlobStore>,
}

impl Default for VerifierRegistry {
    fn default() -> VerifierRegistry {
        VerifierRegistry::new(".")
    }
}

impl VerifierRegistry {
    pub fn new(root: impl Into<PathBuf>) -> VerifierRegistry {
        VerifierRegistry {
            root: root.into(),
            lean_binary: "lean".to_string(),
            python_binary: "python3".to_string(),
            blobs: None,
        }
    }

    /// Resolve pinned code by content before falling back to the filesystem.
    ///
    /// An objective already commits to its checker by digest, so the digest is
    /// the name and the relative path is only ever a hint about where a human
    /// keeps a copy. A registry with a blob store looks up the digest first,
    /// which makes an objective portable: it verifies on any node holding the
    /// bytes, regardless of that node's directory layout.
    ///
    /// This changes no id, no verdict that was previously reachable, and no
    /// conformance vector. A node with no blob store, or with one that does not
    /// hold the digest, resolves exactly as before.
    pub fn with_blobs(mut self, blobs: BlobStore) -> VerifierRegistry {
        self.blobs = Some(blobs);
        self
    }

    /// The blob store backing this registry, if any.
    pub fn blobs(&self) -> Option<&BlobStore> {
        self.blobs.as_ref()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Override the Lean binary. Useful for a node with a pinned toolchain, and
    /// for tests that need a binary that is guaranteed absent.
    pub fn with_lean_binary(mut self, binary: impl Into<String>) -> VerifierRegistry {
        self.lean_binary = binary.into();
        self
    }

    /// Override the interpreter that runs pinned checkers and evaluators.
    pub fn with_python_binary(mut self, binary: impl Into<String>) -> VerifierRegistry {
        self.python_binary = binary.into();
        self
    }

    /// Every kind this build can answer to, in sorted order.
    pub fn kinds() -> &'static [&'static str] {
        &["certificate", "evaluator", "lean", "replay"]
    }

    /// The content digests a verifier spec pins, if any.
    ///
    /// The spec format is this module's business -- it is the only place that
    /// knows `certificate` pins `checker_sha256` and `evaluator` pins
    /// `evaluator_sha256` -- so the question "which blobs does this objective
    /// need" is answered here rather than by a caller pattern-matching on field
    /// names it would have to keep in sync.
    ///
    /// `lean` and `replay` pin nothing by hash: the former's trusted input is
    /// the objective's own statement, and the latter pins a command, a seed and
    /// an environment rather than a file. An empty result is therefore a normal
    /// answer and not a sign of a malformed spec.
    ///
    /// Malformed specs yield whatever digests are legible and no error. A
    /// verifier block missing its digest fails at verification with a verdict,
    /// which is where a caller can do something about it; failing here would
    /// turn "what should I keep on disk" into a question that can refuse to be
    /// answered.
    pub fn pinned_digests(spec: &Value) -> Vec<String> {
        ["checker_sha256", "evaluator_sha256"]
            .iter()
            .filter_map(|field| spec.get(field).and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    }

    /// Whether an objective naming this kind can be posted at all. The node
    /// refuses an objective whose verifier nothing here can run, because an
    /// objective whose payout has no machine behind it is an opinion.
    pub fn supports(kind: &str) -> bool {
        Kind::parse(kind).is_some()
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
            Ok(timeout) => timeout,
            Err(verdict) => return verdict,
        };

        let path = match self.pinned("checker", checker, declared) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        let outcome = match self.run_pinned("checker", path.path(), entrypoint, artifact, timeout) {
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
            Harvest::BadReturn(kind) => {
                Verdict::invalid_spec(format!("checker returned {kind}, expected bool"))
            }
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

        // `Value::Bool` is not `Value::Int`, so the reference implementation's
        // explicit `isinstance(threshold, bool)` guard is structural here.
        let threshold = match spec.get("threshold") {
            Some(Value::Int(raw)) => match i64::try_from(*raw) {
                Ok(threshold) => threshold,
                Err(_) => {
                    return Verdict::invalid_spec(format!(
                        "threshold {raw} is outside the signed 64-bit range scores are recorded in"
                    ))
                }
            },
            _ => {
                return Verdict::invalid_spec(
                    "threshold must be an integer (scale fractional scores)",
                )
            }
        };
        let direction = match spec.get("direction") {
            None => Direction::Maximize,
            Some(Value::String(text)) => match Direction::parse(text) {
                Some(direction) => direction,
                None => {
                    return Verdict::invalid_spec(
                        "direction must be one of (\"maximize\", \"minimize\")",
                    )
                }
            },
            Some(_) => {
                return Verdict::invalid_spec(
                    "direction must be one of (\"maximize\", \"minimize\")",
                )
            }
        };
        let timeout = match spec_timeout(spec, DEFAULT_PINNED_TIMEOUT_SECONDS) {
            Ok(timeout) => timeout,
            Err(verdict) => return verdict,
        };

        let path = match self.pinned("evaluator", evaluator, declared) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        let outcome = match self.run_pinned("evaluator", path.path(), entrypoint, artifact, timeout)
        {
            Ok(outcome) => outcome,
            Err(verdict) => return verdict,
        };
        score_verdict(outcome, threshold, direction, declared)
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
            Ok(timeout) => timeout,
            Err(verdict) => return verdict,
        };

        let preamble = spec.get("preamble").and_then(Value::as_str).unwrap_or("");
        let source = format!("{preamble}\n{statement} {proof}\n");

        let workdir = match TempDir::new("proofwork-lean") {
            Ok(workdir) => workdir,
            Err(error) => {
                return Verdict::unavailable(format!("cannot create a working directory: {error}"))
            }
        };
        let claim = workdir.path().join("Claim.lean");
        if let Err(error) = fs::write(&claim, source.as_bytes()) {
            return Verdict::unavailable(format!("cannot write the Lean source: {error}"));
        }

        let cwd = match spec.get("project_root").and_then(Value::as_str) {
            Some(root) if !root.is_empty() => PathBuf::from(root),
            _ => workdir.path().to_path_buf(),
        };
        let mut command = Command::new(&binary);
        command.arg(&claim).current_dir(&cwd);

        let completed = match run_bounded(&mut command, workdir.path(), None, timeout) {
            Ok(completed) => completed,
            // A timeout is not a refutation. The proof may be fine and slow.
            Err(RunFailure::TimedOut) => {
                return Verdict::unavailable(format!(
                    "lean exceeded {}s; timeout is not a refutation",
                    timeout.as_secs()
                ))
            }
            Err(RunFailure::Spawn(error)) | Err(RunFailure::Io(error)) => {
                return Verdict::unavailable(format!("cannot run lean: {error}"))
            }
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
                "output_tail",
                Value::string(tail(&output, OUTPUT_TAIL_CHARS)),
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
                // on `sorryAx`, so a clean exit code is not sufficient.
                if output.contains("declaration uses 'sorry'") {
                    Verdict::new(Status::Reject, "proof depends on sorryAx", evidence)
                } else {
                    Verdict::new(Status::Accept, "kernel accepted the proof", evidence)
                }
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
            Ok(timeout) => timeout,
            Err(verdict) => return verdict,
        };

        // Lexical join, as in the reference implementation: an absolute `cwd`
        // replaces the root, and no containment check is applied. The command
        // itself is arbitrary anyway -- see SANDBOXING for what that costs.
        let relative = spec.get("cwd").and_then(Value::as_str).unwrap_or(".");
        let cwd = normalize(&self.root.join(relative));

        let workdir = match TempDir::new("proofwork-replay") {
            Ok(workdir) => workdir,
            Err(error) => {
                return Verdict::unavailable(format!("cannot create a working directory: {error}"))
            }
        };
        let mut command = Command::new(program);
        if let Some(rest) = command_parts.get(1..) {
            command.args(rest);
        }
        command.current_dir(&cwd);

        let completed = match run_bounded(&mut command, workdir.path(), None, timeout) {
            Ok(completed) => completed,
            Err(RunFailure::TimedOut) => {
                return Verdict::unavailable(format!(
                    "replay exceeded {}s; a timeout is not a refutation",
                    timeout.as_secs()
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
                    "stderr_tail",
                    Value::string(tail(&completed.stderr, OUTPUT_TAIL_CHARS)),
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
        let mut reproduced: BTreeMap<String, Value> = BTreeMap::new();
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
                reproduced.insert(name.to_string(), seen);
            } else {
                mismatches.insert(
                    name.to_string(),
                    Value::object([("claimed", claim), ("observed", seen)]),
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
            Value::object([("reproduced", Value::Object(reproduced))]),
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
    /// Two failure modes, two statuses:
    ///
    /// - a path that escapes the root, or a hash that does not match, means the
    ///   objective is broken: `InvalidSpec`. A tampered checker is never run.
    /// - a file this node cannot read means this node cannot verify:
    ///   `Unavailable`. It says nothing about the artifact.
    ///
    /// Both sides of the containment check are made absolute first. A relative
    /// root like `"."` never prefixes a normalized relative join, so the naive
    /// check rejects every legitimate objective -- an actual bug the reference
    /// implementation carries a comment about.
    /// Locate the pinned code an objective declares, by content then by path.
    ///
    /// The digest is the identity and the relative path is a hint, so the blob
    /// store is asked first. Two failure modes are kept apart on purpose, and it
    /// is the same distinction the whole verification ladder rests on:
    ///
    /// - **The bytes are not here** -- no blob, no file -- is `Unavailable`. An
    ///   infrastructure fact about this node. The objective is fine and another
    ///   node may well settle it.
    /// - **The bytes at the declared path are the wrong bytes** is
    ///   `INVALID_SPEC`. A fact about the objective, reported the same way it
    ///   always was.
    ///
    /// A blob that is present but corrupt is the first kind, not the second: the
    /// name promised one thing and the disk holds another, which says nothing
    /// whatever about the objective that asked for it.
    fn pinned(
        &self,
        role: &str,
        relative: &str,
        declared_sha256: &str,
    ) -> Result<PinnedCode, Verdict> {
        if let Some(blobs) = &self.blobs {
            match blobs.get(declared_sha256) {
                // Present, and it hashes to its own name, which is the declared
                // digest -- so there is nothing left to check.
                Ok(Some(bytes)) => return PinnedCode::materialize(role, &bytes),
                // Not held locally: fall through to the path, which is what a
                // node that has never seen a blob store does anyway.
                Ok(None) => {}
                Err(error) => {
                    return Err(Verdict::unavailable(format!(
                        "cannot load {role} from the blob store: {error}"
                    )))
                }
            }
        }

        let root = match absolutize(&self.root) {
            Ok(root) => root,
            Err(error) => {
                return Err(Verdict::unavailable(format!(
                    "cannot resolve the objective root: {error}"
                )))
            }
        };
        let full = match absolutize(&root.join(relative)) {
            Ok(full) => full,
            Err(error) => {
                return Err(Verdict::unavailable(format!(
                    "cannot resolve the pinned {role} path: {error}"
                )))
            }
        };
        // Component-wise, so `/objective-root-evil` does not count as being
        // inside `/objective-root` the way a string prefix test would.
        if !full.starts_with(&root) {
            return Err(Verdict::invalid_spec(format!(
                "pinned path escapes the objective root: {relative}"
            )));
        }

        let source = match fs::read(&full) {
            Ok(source) => source,
            Err(error) => {
                return Err(Verdict::unavailable(format!(
                    "cannot load {role}: {error} ({})",
                    full.display()
                )))
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(&source);
        let actual = format!("{:x}", hasher.finalize());
        if actual != declared_sha256 {
            return Err(Verdict::invalid_spec(format!(
                "pinned code {relative} has sha256 {actual}, objective declares {declared_sha256}"
            )));
        }
        Ok(PinnedCode::at(full))
    }

    /// Run pinned code in a child process and collect its single JSON result.
    ///
    /// Every failure here is `Unavailable`: a missing interpreter, a crashed
    /// checker, a checker that ran past its deadline, output that is not a JSON
    /// object. None of those are facts about the artifact. The one thing this
    /// function does *not* decide is whether the returned value has the right
    /// shape -- that is the caller's job, and it is `InvalidSpec`, because a
    /// checker returning the wrong type is a broken objective.
    fn run_pinned(
        &self,
        role: &str,
        path: &Path,
        entrypoint: &str,
        artifact: &Value,
        timeout: Duration,
    ) -> Result<Harvest, Verdict> {
        let interpreter = match which(&self.python_binary) {
            Some(interpreter) => interpreter,
            None => {
                return Err(Verdict::unavailable(format!(
                    "'{}' not on PATH; the pinned {role} cannot be run here",
                    self.python_binary
                )))
            }
        };
        let workdir = match TempDir::new("proofwork-pinned") {
            Ok(workdir) => workdir,
            Err(error) => {
                return Err(Verdict::unavailable(format!(
                    "cannot create a working directory: {error}"
                )))
            }
        };

        let mut command = Command::new(&interpreter);
        command
            .arg("-c")
            .arg(HARNESS)
            .arg(path)
            .arg(entrypoint)
            .current_dir(workdir.path());

        let stdin = artifact.canonical_bytes();
        let completed = match run_bounded(
            &mut command,
            workdir.path(),
            Some(stdin.as_slice()),
            timeout,
        ) {
            Ok(completed) => completed,
            Err(RunFailure::TimedOut) => {
                return Err(Verdict::unavailable(format!(
                    "pinned {role} exceeded {}s; a timeout is not a refutation",
                    timeout.as_secs()
                )))
            }
            Err(RunFailure::Spawn(error)) | Err(RunFailure::Io(error)) => {
                return Err(Verdict::unavailable(format!("cannot run {role}: {error}")))
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
                Value::object([(
                    "stderr_tail",
                    Value::string(tail(&completed.stderr, OUTPUT_TAIL_CHARS)),
                )]),
            ));
        }

        match parse_harvest(&completed.stdout) {
            Some(harvest) => Ok(harvest),
            None => Err(Verdict::new(
                Status::Unavailable,
                format!("pinned {role} did not print a result object this node can read"),
                Value::object([
                    (
                        "stdout_tail",
                        Value::string(tail(&completed.stdout, OUTPUT_TAIL_CHARS)),
                    ),
                    (
                        "stderr_tail",
                        Value::string(tail(&completed.stderr, OUTPUT_TAIL_CHARS)),
                    ),
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
}

fn parse_harvest(stdout: &str) -> Option<Harvest> {
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    let map = parsed.as_object()?;
    if let Some(name) = map.get("bad_return").and_then(|value| value.as_str()) {
        return Some(Harvest::BadReturn(name.to_string()));
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

/// Turn an evaluator's result into a verdict.
///
/// Split out from [`VerifierRegistry::verify_evaluator`] so the arithmetic edge
/// cases are testable without spawning an interpreter.
fn score_verdict(
    outcome: Harvest,
    threshold: i64,
    direction: Direction,
    evaluator_sha256: &str,
) -> Verdict {
    let score = match outcome {
        Harvest::Score(score) => match i64::try_from(score) {
            Ok(score) => score,
            // The frontier records scores as i64. An evaluator producing
            // something that cannot be recorded is an evaluator no node can use.
            Err(_) => {
                return Verdict::invalid_spec(format!(
                    "evaluator returned {score}, outside the signed 64-bit range the \
                     frontier records scores in"
                ))
            }
        },
        Harvest::ScoreOutOfRange(raw) => {
            return Verdict::invalid_spec(format!(
                "evaluator returned {raw}, outside the range any node can record"
            ))
        }
        // `True` in Python is an `int`, so this is a real failure mode rather
        // than a hypothetical one, and it must not score as 1.
        Harvest::Boolean { .. } => {
            return Verdict::invalid_spec(
                "evaluator returned bool; scores must be int so every node agrees on \
                 the comparison",
            )
        }
        Harvest::BadReturn(kind) => {
            return Verdict::invalid_spec(format!(
                "evaluator returned {kind}; scores must be int so every node agrees on \
                 the comparison"
            ))
        }
    };

    let met = direction.clears(score, threshold);
    Verdict::new(
        if met { Status::Accept } else { Status::Reject },
        format!("score {score} vs threshold {threshold} ({direction})"),
        Value::object([
            // The ratchet reads the score from here. Keep the key stable.
            ("score", Value::Int(i128::from(score))),
            ("threshold", Value::Int(i128::from(threshold))),
            ("direction", Value::string(direction.as_str())),
            ("evaluator_sha256", Value::string(evaluator_sha256)),
        ]),
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

/// Last `max_chars` characters, on a character boundary so the result is always
/// valid UTF-8 (byte slicing here would panic on multi-byte output).
fn tail(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text.to_string();
    }
    text.chars().skip(total - max_chars).collect()
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Lexical normalization: drop `.`, resolve `..` textually, never touch the
/// filesystem.
///
/// Deliberately *not* [`fs::canonicalize`]: that requires the path to exist (so
/// a missing checker would report "escapes the root" instead of "not found")
/// and it resolves symlinks, which would let a symlink inside the bundle change
/// what the containment check means.
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

/// `shutil.which`, minus the Windows extension handling.
///
/// A name containing a separator is taken as a path and checked directly;
/// anything else is searched for on `PATH`. Returning `None` is what turns a
/// missing toolchain into `Unavailable` instead of a rejection, so this is a
/// security-relevant function despite looking like plumbing.
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

/// Pinned code, located and ready to run.
///
/// Two provenances, one type. Code found at the objective's declared path is
/// used where it lies; code resolved from the blob store is written into a
/// scratch directory this value owns, and removed when it drops.
///
/// The copy is not incidental. A blob is filed under its digest, which is 62 hex
/// characters and no extension, and Python's
/// `importlib.util.spec_from_file_location` picks a loader from the suffix -- so
/// a blob handed to it directly loads as nothing at all. Materializing it as
/// `pinned.py` is the smaller fix than teaching the harness about loaders, and
/// the harness is shared with the reference implementation, where a divergence
/// would be a real one.
///
/// It buys a second thing worth having: the pinned code never learns where the
/// blob store is, so a checker that goes looking cannot read or scribble on
/// blobs belonging to other objectives.
#[derive(Debug)]
struct PinnedCode {
    path: PathBuf,
    /// Dropped -- and deleted -- when the verification that owns this finishes.
    /// Present only for code that came from a blob.
    _scratch: Option<TempDir>,
}

impl PinnedCode {
    /// Code already on disk at a path of its own.
    fn at(path: PathBuf) -> PinnedCode {
        PinnedCode {
            path,
            _scratch: None,
        }
    }

    /// Write `bytes` somewhere runnable.
    fn materialize(role: &str, bytes: &[u8]) -> Result<PinnedCode, Verdict> {
        let scratch = TempDir::new("proofwork-pinned-blob").map_err(|error| {
            Verdict::unavailable(format!("cannot place the pinned {role}: {error}"))
        })?;
        let path = scratch.path().join("pinned.py");
        fs::write(&path, bytes).map_err(|error| {
            Verdict::unavailable(format!("cannot place the pinned {role}: {error}"))
        })?;
        Ok(PinnedCode {
            path,
            _scratch: Some(scratch),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

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
    /// The child outlived its deadline and was killed.
    TimedOut,
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
fn run_bounded(
    command: &mut Command,
    workdir: &Path,
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<Completed, RunFailure> {
    let out_path = workdir.join("stdout");
    let err_path = workdir.join("stderr");
    let out_file = fs::File::create(&out_path).map_err(RunFailure::Io)?;
    let err_file = fs::File::create(&err_path).map_err(RunFailure::Io)?;

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
    command.stdout(Stdio::from(out_file));
    command.stderr(Stdio::from(err_file));

    let mut child = command.spawn().map_err(RunFailure::Spawn)?;
    let started = Instant::now();
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunFailure::TimedOut);
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunFailure::Io(error));
            }
        }
    };

    Ok(Completed {
        code,
        stdout: read_lossy(&out_path),
        stderr: read_lossy(&err_path),
    })
}

/// Read captured output, tolerating both a missing file and invalid UTF-8.
/// Neither is worth failing a verification over; the reference implementation
/// decodes with the same tolerance.
fn read_lossy(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    }
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
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
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

    #[test]
    fn evaluator_threshold_decides_accept_or_reject() {
        let accepted = score_verdict(Harvest::Score(3), 3, Direction::Maximize, "ab");
        assert_eq!(accepted.status, Status::Accept);
        assert_eq!(accepted.score(), Some(3));
        let rejected = score_verdict(Harvest::Score(2), 3, Direction::Maximize, "ab");
        assert_eq!(rejected.status, Status::Reject);
        let minimized = score_verdict(Harvest::Score(2), 3, Direction::Minimize, "ab");
        assert_eq!(minimized.status, Status::Accept);
    }

    #[test]
    fn a_score_too_large_to_record_is_a_spec_defect_not_a_rejection() {
        let over = score_verdict(
            Harvest::Score(i128::from(i64::MAX) + 1),
            0,
            Direction::Maximize,
            "ab",
        );
        assert_eq!(over.status, Status::InvalidSpec);
        assert!(!over.status.settles());

        let bignum = score_verdict(
            Harvest::ScoreOutOfRange(
                "1606938044258990275541962092341162602522202993782792835301376".into(),
            ),
            0,
            Direction::Maximize,
            "ab",
        );
        assert_eq!(bignum.status, Status::InvalidSpec);
    }

    #[test]
    fn a_non_integer_score_is_refused_because_nodes_would_disagree() {
        let float = score_verdict(
            Harvest::BadReturn("float".into()),
            3,
            Direction::Maximize,
            "ab",
        );
        assert_eq!(float.status, Status::InvalidSpec);
        assert!(float.detail.contains("int"));

        let boolean = score_verdict(
            Harvest::Boolean {
                ok: true,
                detail: String::new(),
            },
            3,
            Direction::Maximize,
            "ab",
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
            &["certificate", "evaluator", "lean", "replay"]
        );
        for kind in VerifierRegistry::kinds() {
            assert!(VerifierRegistry::supports(kind));
            assert_eq!(Kind::parse(kind).map(|k| k.as_str()), Some(*kind));
        }
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
        );
        assert!(matches!(outcome, Err(RunFailure::TimedOut)));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the deadline must actually bound the wait"
        );
    }

    #[test]
    fn a_missing_binary_is_a_spawn_failure_not_a_hang() {
        let workdir = tmpdir("proofwork-spawn");
        let mut command = Command::new("proofwork-nonexistent-binary-xyz");
        let outcome = run_bounded(&mut command, workdir.path(), None, Duration::from_secs(5));
        assert!(matches!(outcome, Err(RunFailure::Spawn(_))));
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

    // -- blob resolution ---------------------------------------------------

    #[test]
    fn a_checker_held_only_as_a_blob_still_verifies() {
        // The point of the whole blob store: the objective names its checker by
        // digest, so a node that has the *bytes* can verify it without having
        // the file the author happened to write it to. `root` here is an empty
        // directory -- there is no `c.py` anywhere.
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-blob-verify");
        let blobs = BlobStore::new(root.path().join("blobs"));
        blobs.prepare().expect("prepares");
        let digest = blobs.put(CHECKER.as_bytes()).expect("puts");
        let bare = digest.strip_prefix("sha256:").expect("prefixed");

        let spec = Value::object([
            ("kind", Value::string("certificate")),
            // A path that does not exist and never did.
            ("checker", Value::string("nowhere/c.py")),
            ("checker_sha256", Value::string(bare)),
            ("entrypoint", Value::string("check")),
        ]);
        let artifact = Value::object([("n", Value::Int(42))]);

        let without = VerifierRegistry::new(root.path());
        assert_eq!(
            without.run(&spec, &artifact).status,
            Status::Unavailable,
            "no blob store and no file: an infrastructure fact, never a rejection"
        );

        let with = VerifierRegistry::new(root.path()).with_blobs(blobs);
        assert_eq!(with.run(&spec, &artifact).status, Status::Accept);
        assert_eq!(
            with.run(&spec, &Value::object([("n", Value::Int(41))]))
                .status,
            Status::Reject,
            "resolving by content changes where the bytes came from, not the verdict"
        );
    }

    #[test]
    fn the_path_still_works_when_the_blob_store_does_not_have_it() {
        // Backward compatibility, stated as a test. A store that has never seen
        // this digest must fall through to the old behaviour rather than
        // shadowing it.
        if !have("python3") {
            return;
        }
        let root = tmpdir("proofwork-blob-fallback");
        let sha = write_pinned(&root, "c.py", CHECKER);
        let blobs = BlobStore::new(root.path().join("blobs"));
        blobs.prepare().expect("prepares");
        blobs.put(b"something else entirely").expect("puts");

        let registry = VerifierRegistry::new(root.path()).with_blobs(blobs);
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
    }

    #[test]
    fn a_corrupt_blob_is_unavailable_and_never_a_verdict_about_the_artifact() {
        // The distinction the whole ladder rests on. Bytes on this disk that do
        // not match the name they are filed under say something about this disk.
        // Reporting `Reject` would let a node with a damaged cache refute honest
        // work, and reporting `INVALID_SPEC` would blame an objective that is
        // perfectly well formed.
        let root = tmpdir("proofwork-blob-corrupt");
        let blobs = BlobStore::new(root.path().join("blobs"));
        blobs.prepare().expect("prepares");
        let digest = blobs.put(CHECKER.as_bytes()).expect("puts");
        fs::write(
            blobs.path_of(&digest).expect("a digest"),
            b"def check(artifact):\n    return True\n",
        )
        .expect("tamper");

        let registry = VerifierRegistry::new(root.path()).with_blobs(blobs);
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            (
                "checker_sha256",
                Value::string(digest.strip_prefix("sha256:").expect("prefixed")),
            ),
            ("entrypoint", Value::string("check")),
        ]);
        let verdict = registry.run(&spec, &Value::object([("n", Value::Int(42))]));
        assert_eq!(verdict.status, Status::Unavailable);
        assert!(!verdict.status.settles());
    }

    #[test]
    fn pinned_digests_names_what_a_spec_needs_on_disk() {
        assert_eq!(
            VerifierRegistry::pinned_digests(&Value::object([
                ("kind", Value::string("evaluator")),
                ("evaluator_sha256", Value::string("ab")),
            ])),
            vec!["ab".to_string()]
        );
        assert_eq!(
            VerifierRegistry::pinned_digests(&Value::object([
                ("kind", Value::string("certificate")),
                ("checker_sha256", Value::string("cd")),
            ])),
            vec!["cd".to_string()]
        );
        // `lean` trusts the objective's own statement and `replay` pins a
        // command rather than a file, so neither needs anything kept on disk.
        // An empty answer is a real answer here, not a parse failure.
        for kind in ["lean", "replay"] {
            assert!(VerifierRegistry::pinned_digests(&Value::object([(
                "kind",
                Value::string(kind)
            )]))
            .is_empty());
        }
        // A malformed spec yields what is legible and no error: this question is
        // "what should I keep", and it must always have an answer.
        assert!(VerifierRegistry::pinned_digests(&Value::object([(
            "evaluator_sha256",
            Value::Int(7)
        )]))
        .is_empty());
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

    // -- shipped examples --------------------------------------------------

    #[test]
    fn the_shipped_examples_verify() {
        // A broken example is a broken claim.
        if !have("python3") {
            return;
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let registry = VerifierRegistry::new(&root);
        for (name, artifact_field) in [("collatz", "n"), ("capset", "points")] {
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
    fn tails_are_bounded_and_stay_valid_utf8() {
        assert_eq!(tail("abc", 10), "abc");
        assert_eq!(tail("abcdef", 3), "def");
        assert_eq!(tail("", 3), "");
        // Multi-byte characters: byte slicing here would panic.
        let text = "αβγδε";
        assert_eq!(tail(text, 2), "δε");
        assert_eq!(tail(text, 0), "");
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

    #[test]
    fn the_sandboxing_note_still_says_this_is_not_a_sandbox() {
        assert!(SANDBOXING.contains("NOT a sandbox"));
        assert!(SANDBOXING.contains("launch blocker"));
    }
}
