//! Objective capability metadata and node-local resource matching.
//!
//! These values describe routing and availability, not settled work. An
//! objective may declare what kind of worker can make progress and the
//! minimum resources it expects; a host may offer what it is willing to make
//! available. A match is only a useful answer to "which challenges can this
//! machine try?". It is never evidence that a worker ran or that a result is
//! correct.
//!
//! Capability metadata lives inside the objective's verifier object under the
//! `capabilities` key. That keeps it content-addressed with the challenge and
//! lets older objectives remain valid by omission. Verifier implementations
//! ignore this routing hint; the pinned verifier remains the only authority on
//! an accepted artifact.

use std::fmt;

use crate::canonical::Value;
use crate::hardware::{CpuProfile, CpuRequirements};
use crate::pricing::RateCard;
use crate::records::Objective;

const CAPABILITIES_KEY: &str = "capabilities";

/// Whether an application can supply the worker for an objective.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerRequirement {
    /// A worker integration identified by a stable app-local name.
    BuiltIn { id: String },
    /// A solver package the objective pins by id (`sha256:` of its canonical
    /// manifest; see [`crate::solver`]). `cairn work --package auto` fetches
    /// it, checks every file against the pin, runs its tests and then runs it
    /// in the sandbox, so nobody has to choose a program to contribute.
    Package { id: String },
    /// The operator must provide a compatible worker or solver.
    External,
}

impl WorkerRequirement {
    pub fn mode(&self) -> &'static str {
        match self {
            Self::BuiltIn { .. } => "built_in",
            Self::Package { .. } => "package",
            Self::External => "external",
        }
    }

    pub fn to_value(&self) -> Value {
        let mut fields = vec![("mode", Value::string(self.mode()))];
        match self {
            Self::BuiltIn { id } => fields.push(("id", Value::string(id.clone()))),
            Self::Package { id } => fields.push(("package", Value::string(id.clone()))),
            Self::External => {}
        }
        Value::object(fields)
    }
}

/// How a compatible worker receives work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentMode {
    /// The worker computes a deterministic slice of the objective's search.
    Partitioned,
    /// A host-side executor receives a queued job selected by the node.
    Queued,
}

impl AssignmentMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Partitioned => "partitioned",
            Self::Queued => "queued",
        }
    }
}

/// Minimum resources an objective asks a host to provide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceRequirements {
    pub cpus: Option<u64>,
    pub memory_mb: Option<u64>,
    pub gpus: Option<u64>,
    pub storage_mb: Option<u64>,
    pub concurrency: Option<u64>,
    pub cpu: CpuRequirements,
    /// A malformed hint must never silently become an unconstrained match.
    pub invalid: bool,
}

impl ResourceRequirements {
    fn to_value(&self) -> Value {
        Value::object([
            ("cpus", optional_int(self.cpus)),
            ("memory_mb", optional_int(self.memory_mb)),
            ("gpus", optional_int(self.gpus)),
            ("storage_mb", optional_int(self.storage_mb)),
            ("concurrency", optional_int(self.concurrency)),
            ("cpu", self.cpu.to_value()),
            ("invalid", Value::Bool(self.invalid)),
        ])
    }
}

/// A host's current, voluntary offer to run compatible work.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceOffer {
    pub cpus: Option<u64>,
    pub memory_mb: Option<u64>,
    pub gpus: Option<u64>,
    pub storage_mb: Option<u64>,
    pub concurrency: Option<u64>,
    pub cpu: Option<CpuProfile>,
    pub pricing: Option<RateCard>,
    /// CPU time quota in thousandths of one core, independent of thread count.
    pub cpu_millis: Option<u64>,
}

impl ResourceOffer {
    pub fn from_value(value: &Value) -> Result<Self, ScheduleError> {
        let object = value.as_object().ok_or(ScheduleError::NotAnObject)?;
        let field = |name| optional_u64(object.get(name), name);
        Ok(Self {
            cpus: field("cpus")?,
            memory_mb: field("memory_mb")?,
            gpus: field("gpus")?,
            storage_mb: field("storage_mb")?,
            concurrency: field("concurrency")?,
            cpu_millis: field("cpu_millis")?,
            cpu: match object.get("cpu") {
                None | Some(Value::Null) => None,
                Some(value) => Some(CpuProfile::from_value(value).map_err(|_| {
                    ScheduleError::InvalidField {
                        field: "cpu",
                        expected: "a CPU profile with an architecture and exact feature names",
                    }
                })?),
            },
            pricing: match object.get("pricing") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    Some(
                        RateCard::from_value(value).map_err(|_| ScheduleError::InvalidField {
                            field: "pricing",
                            expected: "a valid compute rate card",
                        })?,
                    )
                }
            },
        })
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("cpus", optional_int(self.cpus)),
            ("memory_mb", optional_int(self.memory_mb)),
            ("gpus", optional_int(self.gpus)),
            ("storage_mb", optional_int(self.storage_mb)),
            ("concurrency", optional_int(self.concurrency)),
            (
                "cpu",
                self.cpu.as_ref().map_or(Value::Null, CpuProfile::to_value),
            ),
            (
                "pricing",
                self.pricing
                    .as_ref()
                    .map_or(Value::Null, RateCard::to_value),
            ),
            ("cpu_millis", optional_int(self.cpu_millis)),
        ])
    }

    /// The offer derived from the existing host registration fields. An agent
    /// may override any value by posting `resources`; absent dimensions stay
    /// absent rather than becoming optimistic guesses.
    pub fn from_host_facts(hardware: &Value, jobs: &Value) -> Self {
        let number = |object: &Value, name| object.get(name).and_then(Value::as_u64);
        Self {
            cpus: limited(
                number(hardware, "cpus"),
                hardware.get("cgroup").and_then(|v| number(v, "cpus")),
            ),
            memory_mb: limited(
                number(hardware, "memory_mb"),
                hardware.get("cgroup").and_then(|v| number(v, "memory_mb")),
            ),
            gpus: hardware
                .get("gpus")
                .and_then(Value::as_array)
                .map(|items| items.len() as u64),
            storage_mb: None,
            concurrency: number(jobs, "capacity"),
            cpu: hardware
                .get("cpu")
                .and_then(|v| CpuProfile::from_value(v).ok()),
            pricing: None,
            cpu_millis: limited(
                number(hardware, "cpus").and_then(|cpus| cpus.checked_mul(1000)),
                hardware.get("cgroup").and_then(|v| number(v, "cpu_millis")),
            ),
        }
    }
}

/// The routing contract published beside an objective in reader APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectiveCapabilities {
    pub worker: WorkerRequirement,
    pub assignment: AssignmentMode,
    pub resources: ResourceRequirements,
}

impl Default for ObjectiveCapabilities {
    fn default() -> Self {
        Self {
            worker: WorkerRequirement::External,
            assignment: AssignmentMode::Partitioned,
            resources: ResourceRequirements::default(),
        }
    }
}

impl ObjectiveCapabilities {
    /// Read the optional routing hint. Malformed hints degrade to the safe
    /// external-worker default: a bad hint must make a challenge less easy to
    /// route, never make an operator run an unexpected program.
    pub fn for_objective(objective: &Objective) -> Self {
        let Some(capabilities) = objective.verifier.get(CAPABILITIES_KEY) else {
            return Self::default();
        };
        let Some(object) = capabilities.as_object() else {
            return Self {
                resources: ResourceRequirements {
                    invalid: true,
                    ..ResourceRequirements::default()
                },
                ..Self::default()
            };
        };
        let worker = match object.get("worker") {
            Some(Value::String(mode)) if mode == "built_in" || mode == "builtin" => {
                WorkerRequirement::BuiltIn {
                    id: "default".to_string(),
                }
            }
            Some(Value::Object(worker))
                if worker.get("mode").and_then(Value::as_str) == Some("built_in")
                    || worker.get("mode").and_then(Value::as_str) == Some("builtin") =>
            {
                match worker.get("id").and_then(Value::as_str) {
                    Some(id) if !id.is_empty() => WorkerRequirement::BuiltIn { id: id.into() },
                    _ => WorkerRequirement::External,
                }
            }
            // A pin that is not a package id is a typo, and a typo must not
            // become "run something": it falls back to external, like every
            // other malformed hint here.
            Some(Value::Object(worker))
                if worker.get("mode").and_then(Value::as_str) == Some("package") =>
            {
                match worker.get("package").and_then(Value::as_str) {
                    Some(id) if crate::solver::manifest::is_record_id(id) => {
                        WorkerRequirement::Package { id: id.into() }
                    }
                    _ => WorkerRequirement::External,
                }
            }
            _ => WorkerRequirement::External,
        };
        let assignment = match object.get("assignment").and_then(Value::as_str) {
            Some("queued") => AssignmentMode::Queued,
            _ => AssignmentMode::Partitioned,
        };
        let resources = match object.get("resources") {
            None => ResourceRequirements::default(),
            Some(value) => {
                requirements_from_value(value).unwrap_or_else(|_| ResourceRequirements {
                    invalid: true,
                    ..ResourceRequirements::default()
                })
            }
        };
        Self {
            worker,
            assignment,
            resources,
        }
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("worker", self.worker.to_value()),
            ("assignment", Value::string(self.assignment.as_str())),
            ("resources", self.resources.to_value()),
        ])
    }
}

/// Whether one host can satisfy all declared minimums.
pub fn matches(requirements: &ResourceRequirements, offer: &ResourceOffer) -> bool {
    fn enough(required: Option<u64>, offered: Option<u64>) -> bool {
        match required {
            Some(required) => offered.is_some_and(|offered| offered >= required),
            None => true,
        }
    }
    !requirements.invalid
        && requirements.cpu.matches(offer.cpu.as_ref())
        && requirements.cpus.is_none_or(|cpus| {
            offer
                .cpu_millis
                .is_none_or(|millis| u128::from(millis) >= u128::from(cpus) * 1000)
        })
        && enough(requirements.cpus, offer.cpus)
        && enough(requirements.memory_mb, offer.memory_mb)
        && enough(requirements.gpus, offer.gpus)
        && enough(requirements.storage_mb, offer.storage_mb)
        && enough(requirements.concurrency, offer.concurrency)
}

/// Keep capacity parsing distinct from offer parsing: requirements describe a
/// predicate, while a profile describes an observation.
fn requirements_from_value(value: &Value) -> Result<ResourceRequirements, ScheduleError> {
    let object = value.as_object().ok_or(ScheduleError::NotAnObject)?;
    if object.keys().any(|key| {
        ![
            "cpus",
            "memory_mb",
            "gpus",
            "storage_mb",
            "concurrency",
            "cpu",
        ]
        .contains(&key.as_str())
    }) {
        return Err(ScheduleError::InvalidField {
            field: "resources",
            expected: "known resource dimensions",
        });
    }
    Ok(ResourceRequirements {
        cpus: optional_u64(object.get("cpus"), "cpus")?,
        memory_mb: optional_u64(object.get("memory_mb"), "memory_mb")?,
        gpus: optional_u64(object.get("gpus"), "gpus")?,
        storage_mb: optional_u64(object.get("storage_mb"), "storage_mb")?,
        concurrency: optional_u64(object.get("concurrency"), "concurrency")?,
        cpu: object
            .get("cpu")
            .map(CpuRequirements::from_value)
            .transpose()
            .map_err(|_| ScheduleError::InvalidField {
                field: "cpu",
                expected: "valid CPU requirements",
            })?
            .unwrap_or_default(),
        invalid: false,
    })
}

fn limited(physical: Option<u64>, limit: Option<u64>) -> Option<u64> {
    match (physical, limit) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    NotAnObject,
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject => f.write_str("resource offer must be an object"),
            Self::InvalidField { field, expected } => {
                write!(f, "resource field `{field}` must be {expected}")
            }
        }
    }
}

impl std::error::Error for ScheduleError {}

fn optional_u64(value: Option<&Value>, field: &'static str) -> Result<Option<u64>, ScheduleError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or(ScheduleError::InvalidField {
            field,
            expected: "a non-negative integer",
        }),
    }
}

fn optional_int(value: Option<u64>) -> Value {
    value.map_or(Value::Null, |value| Value::Int(i128::from(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> ResourceOffer {
        ResourceOffer {
            cpus: Some(8),
            memory_mb: Some(16_384),
            gpus: Some(1),
            storage_mb: Some(100_000),
            concurrency: Some(2),
            ..ResourceOffer::default()
        }
    }

    #[test]
    fn instruction_requirements_and_malformed_metadata_fail_closed() {
        let mut host = offer();
        let required = requirements_from_value(
            &Value::from_json(
                r#"{"cpus":1,"cpu":{"arch":"x86_64","features":["avx512f","avx512bw"]}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!matches(&required, &host));
        host.cpu = Some(CpuProfile {
            arch: "x86_64".into(),
            features: vec!["avx512f".into()],
            ..CpuProfile::default()
        });
        assert!(!matches(&required, &host));
        host.cpu.as_mut().unwrap().features.push("avx512bw".into());
        assert!(matches(&required, &host));
        host.cpu_millis = Some(500);
        assert!(!matches(&required, &host));
        let mut objective = Objective::from_value(&Value::from_json(r#"{"goal":"g","statement":"s","verifier":{"kind":"certificate"},"reward":1,"funder":"f","created_at":"2026-01-01T00:00:00Z"}"#).unwrap()).unwrap();
        for bad in [
            r#"{"resources":{"cpus":-1}}"#,
            r#"{"resources":{"cpu":{"feautres":["avx2"]}}}"#,
            r#"{"resources":null}"#,
            "42",
        ] {
            objective.verifier = Value::object([("capabilities", Value::from_json(bad).unwrap())]);
            let capabilities = ObjectiveCapabilities::for_objective(&objective);
            assert!(capabilities.resources.invalid, "{bad}");
            assert!(!matches(&capabilities.resources, &offer()));
        }
    }

    #[test]
    fn host_caps_never_replace_a_smaller_affinity_with_a_larger_quota() {
        let hardware = Value::from_json(
            r#"{"cpus":2,"memory_mb":1024,"cgroup":{"cpus":8,"memory_mb":8192,"cpu_millis":500}}"#,
        )
        .unwrap();
        let offer = ResourceOffer::from_host_facts(&hardware, &Value::Null);
        assert_eq!(offer.cpus, Some(2));
        assert_eq!(offer.memory_mb, Some(1024));
        assert_eq!(offer.cpu_millis, Some(500));
        assert_eq!(ResourceOffer::from_value(&offer.to_value()).unwrap(), offer);
    }

    #[test]
    fn a_host_offer_matches_minimums_without_guessing_missing_capacity() {
        let requirements = ResourceRequirements {
            cpus: Some(4),
            memory_mb: Some(8_192),
            gpus: Some(1),
            storage_mb: None,
            concurrency: Some(1),
            ..ResourceRequirements::default()
        };
        assert!(matches(&requirements, &offer()));
        assert!(!matches(
            &ResourceRequirements {
                memory_mb: Some(20_000),
                ..requirements.clone()
            },
            &offer()
        ));
        assert!(!matches(
            &ResourceRequirements {
                storage_mb: Some(1),
                ..requirements
            },
            &ResourceOffer {
                storage_mb: None,
                ..offer()
            }
        ));
    }

    #[test]
    fn capability_metadata_is_optional_and_defaults_to_external_partitioned_work() {
        let objective = Objective::from_value(&Value::from_json(
            r#"{"goal":"g","statement":"s","verifier":{"kind":"certificate"},"reward":1,"funder":"f","created_at":"2026-01-01T00:00:00Z"}"#,
        ).unwrap()).unwrap();
        assert_eq!(
            ObjectiveCapabilities::for_objective(&objective),
            ObjectiveCapabilities::default()
        );
    }

    #[test]
    fn built_in_worker_and_resources_are_read_from_the_verifier_capability_hint() {
        let objective = Objective::from_value(&Value::from_json(
            r#"{"goal":"g","statement":"s","verifier":{"kind":"certificate","capabilities":{"worker":{"mode":"built_in","id":"rho"},"assignment":"queued","resources":{"cpus":4,"memory_mb":1024}}},"reward":1,"funder":"f","created_at":"2026-01-01T00:00:00Z"}"#,
        ).unwrap()).unwrap();
        let capabilities = ObjectiveCapabilities::for_objective(&objective);
        assert_eq!(
            capabilities.worker,
            WorkerRequirement::BuiltIn { id: "rho".into() }
        );
        assert_eq!(capabilities.assignment, AssignmentMode::Queued);
        assert_eq!(capabilities.resources.cpus, Some(4));
        assert_eq!(capabilities.resources.memory_mb, Some(1024));
    }

    #[test]
    fn a_pinned_solver_package_is_read_and_a_malformed_pin_runs_nothing() {
        let with = |worker: &str| {
            let objective = Objective::from_value(&Value::from_json(&format!(
                r#"{{"goal":"g","statement":"s","verifier":{{"kind":"certificate","capabilities":{{"worker":{worker}}}}},"reward":1,"funder":"f","created_at":"2026-01-01T00:00:00Z"}}"#
            )).unwrap()).unwrap();
            ObjectiveCapabilities::for_objective(&objective).worker
        };
        let id = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            with(&format!(r#"{{"mode":"package","package":"{id}"}}"#)),
            WorkerRequirement::Package { id: id.clone() }
        );
        assert_eq!(
            WorkerRequirement::Package { id: id.clone() }.to_value(),
            Value::object([
                ("mode", Value::string("package")),
                ("package", Value::string(id))
            ])
        );
        for bad in [
            r#"{"mode":"package"}"#,
            r#"{"mode":"package","package":"../../bin/sh"}"#,
            r#"{"mode":"package","package":"sha256:ABCD"}"#,
        ] {
            assert_eq!(with(bad), WorkerRequirement::External, "{bad}");
        }
    }
}
