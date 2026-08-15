//! The one thing that makes a computation bisectable: a pinned function from a
//! state to the next state.
//!
//! Everything else in [`crate::challenge`] is pure. This is the module's only
//! contact with execution, and it is deliberately the narrowest possible
//! contact: one call, on one state, at the end of a search that has already
//! decided which state.
//!
//! # Why the stepper is part of the objective
//!
//! A `replay` spec names a *command*. A command has an input and an output and
//! nothing in between that two parties could point at, so a disagreement about
//! a command can only be settled by running the whole thing — which is where we
//! started. Bisection needs the computation broken into steps that both parties
//! can name, and only the objective's author can say what a step is.
//!
//! So a `stepper` block in the verifier spec is what declares an objective
//! bisectable:
//!
//! ```json
//! "stepper": {
//!   "code": "examples/collatz/steppers/trajectory.py",
//!   "code_sha256": "…",
//!   "entrypoint": "step"
//! }
//! ```
//!
//! Pinned by hash like every other piece of objective-authored code, run in the
//! same jail, and — the part that matters for adjudication — **deterministic by
//! obligation**. A stepper that consults a clock, a random source, or the
//! machine it runs on produces a trace nobody else can reproduce, so no dispute
//! over it is settleable. That obligation cannot be enforced by inspection, and
//! this module does not pretend otherwise; what it does is remove the excuses,
//! since the jail hands the step no network, no environment and no writable
//! filesystem.

use std::time::Duration;

use crate::canonical::Value;
use crate::verifiers::{Verdict, VerifierRegistry};

/// Wall-clock bound on a single step.
///
/// A *step*, not a computation: if one step of a trace takes longer than this,
/// the objective's steps are too coarse to bisect and the fix is a finer step
/// function, not a longer timeout. Kept short deliberately, because the cost of
/// adjudication is the whole argument for the mechanism.
pub const DEFAULT_STEP_TIMEOUT_SECONDS: u64 = 10;

/// A pinned step function, resolved against a verifier registry.
///
/// `Debug` prints the pin and not the registry: the hash is what identifies
/// which stepper adjudicated a dispute, and the registry behind it is a
/// filesystem handle nobody reading a test failure wants to see.
pub struct Stepper<'a> {
    registry: &'a VerifierRegistry,
    code: String,
    sha256: String,
    entrypoint: String,
    timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepError {
    /// The spec has no `stepper` block, or it is incomplete. The objective is
    /// simply not bisectable, which is a legitimate thing for an objective to
    /// be — most are.
    NotBisectable(String),
    /// The step could not be run, or the code is broken. Carries the verdict so
    /// the caller can tell "this node cannot" from "this objective cannot",
    /// which is the same split every verifier path makes.
    Failed(Verdict),
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepError::NotBisectable(why) => write!(f, "objective is not bisectable: {why}"),
            StepError::Failed(verdict) => {
                write!(f, "{}: {}", verdict.status.as_str(), verdict.detail)
            }
        }
    }
}

impl std::error::Error for StepError {}

impl std::fmt::Debug for Stepper<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stepper")
            .field("code", &self.code)
            .field("code_sha256", &self.sha256)
            .field("entrypoint", &self.entrypoint)
            .finish_non_exhaustive()
    }
}

impl<'a> Stepper<'a> {
    /// Read a `stepper` block out of a verifier spec.
    ///
    /// Returns `NotBisectable` rather than an error-shaped failure when the
    /// block is absent: an objective without a stepper is the normal case, and
    /// a caller asking "can this be bisected" should not have to distinguish
    /// "no" from "broken" by parsing a message.
    pub fn from_spec(
        registry: &'a VerifierRegistry,
        spec: &Value,
    ) -> Result<Stepper<'a>, StepError> {
        let block = spec
            .get("stepper")
            .ok_or_else(|| StepError::NotBisectable("the spec declares no stepper".to_string()))?;
        let field = |name: &str| -> Result<String, StepError> {
            block
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| StepError::NotBisectable(format!("stepper has no '{name}'")))
        };
        let timeout = match block.get("timeout_seconds") {
            None => DEFAULT_STEP_TIMEOUT_SECONDS,
            Some(value) => match value.as_u64() {
                Some(seconds) if seconds > 0 => seconds,
                _ => {
                    return Err(StepError::NotBisectable(
                        "stepper timeout_seconds must be a positive integer".to_string(),
                    ))
                }
            },
        };
        Ok(Stepper {
            registry,
            code: field("code")?,
            sha256: field("code_sha256")?,
            entrypoint: field("entrypoint")?,
            timeout: Duration::from_secs(timeout),
        })
    }

    /// Whether a spec declares a stepper at all.
    pub fn declared(spec: &Value) -> bool {
        spec.get("stepper").is_some()
    }

    /// The pinned code's hash, which is what a dispute is adjudicated under.
    ///
    /// Worth recording alongside an outcome: two adjudicators running different
    /// steppers would reach different verdicts on the same dispute, and the pin
    /// is what makes that a detectable disagreement rather than a silent one.
    pub fn code_sha256(&self) -> &str {
        &self.sha256
    }

    /// One step. The whole point of the module in one call.
    pub fn step(&self, state: &Value) -> Result<Value, StepError> {
        self.registry
            .transform(
                "stepper",
                &self.code,
                &self.sha256,
                &self.entrypoint,
                state,
                self.timeout,
            )
            .map_err(StepError::Failed)
    }
}
