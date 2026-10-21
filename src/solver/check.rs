//! "It has to pass": run a package's known-answer tests in the jail and say
//! what happened.
//!
//! The report is advice about one host, not a record. It is what a node shows
//! beside a package it offers and what a worker prints before it starts, and
//! it never reaches the log: whether a candidate is worth anything is still
//! the objective's pinned verifier's question alone.

use std::time::Duration;

use super::manifest::{Platform, TestVector};
use super::package::{runnable_here, Package};
use super::run::{self, Failure, Round};
use crate::canonical::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    /// Could not be decided on this host. Never a failure of the package.
    Unavailable,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Fail => "fail",
            Outcome::Unavailable => "unavailable",
        }
    }

    pub fn parse(text: &str) -> Option<Outcome> {
        match text {
            "pass" => Some(Outcome::Pass),
            "fail" => Some(Outcome::Fail),
            "unavailable" => Some(Outcome::Unavailable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    pub name: String,
    pub platform: Option<Platform>,
    pub outcome: Outcome,
    pub detail: String,
    pub candidates: usize,
    pub millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub package: String,
    pub sandbox: String,
    pub checked_at: String,
    /// The objective whose pinned verifier judged `verify: "accept"` tests.
    pub objective: Option<String>,
    pub tests: Vec<TestResult>,
    /// Targets whose format and hashes were checked but which this host
    /// cannot run, so whose tests it could not.
    pub not_run: Vec<String>,
}

impl Report {
    /// Pass only when something ran and everything that ran passed.
    pub fn verdict(&self) -> Outcome {
        if self.tests.iter().any(|t| t.outcome == Outcome::Fail) {
            Outcome::Fail
        } else if self.tests.is_empty()
            || self.tests.iter().any(|t| t.outcome == Outcome::Unavailable)
        {
            Outcome::Unavailable
        } else {
            Outcome::Pass
        }
    }

    pub fn to_value(&self) -> Value {
        let mut fields = vec![
            ("package", Value::string(&self.package)),
            ("verdict", Value::string(self.verdict().as_str())),
            ("sandbox", Value::string(&self.sandbox)),
            ("checked_at", Value::string(&self.checked_at)),
            (
                "tests",
                Value::array(self.tests.iter().map(|t| {
                    Value::object([
                        ("name", Value::string(&t.name)),
                        (
                            "platform",
                            t.platform
                                .map(|p| Value::string(p.as_str()))
                                .unwrap_or(Value::Null),
                        ),
                        ("outcome", Value::string(t.outcome.as_str())),
                        ("detail", Value::string(&t.detail)),
                        ("candidates", Value::Int(t.candidates as i128)),
                        ("millis", Value::Int(i128::from(t.millis))),
                    ])
                })),
            ),
            (
                "not_run",
                Value::array(self.not_run.iter().map(Value::string)),
            ),
        ];
        if let Some(objective) = &self.objective {
            fields.push(("objective", Value::string(objective)));
        }
        Value::object(fields)
    }

    pub fn from_value(value: &Value) -> Option<Report> {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
        let tests = value
            .get("tests")?
            .as_array()?
            .iter()
            .map(|t| {
                Some(TestResult {
                    name: t.get("name")?.as_str()?.to_string(),
                    platform: t
                        .get("platform")
                        .and_then(Value::as_str)
                        .and_then(Platform::parse),
                    outcome: Outcome::parse(t.get("outcome")?.as_str()?)?,
                    detail: t.get("detail")?.as_str()?.to_string(),
                    candidates: t.get("candidates")?.as_u64()? as usize,
                    millis: t.get("millis")?.as_u64()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Report {
            package: text("package")?,
            sandbox: text("sandbox")?,
            checked_at: text("checked_at")?,
            objective: text("objective"),
            tests,
            not_run: value
                .get("not_run")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// One line per test, for a terminal.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for t in &self.tests {
            let on = t.platform.map(|p| format!(" [{p}]")).unwrap_or_default();
            lines.push(format!(
                "  {:<11} {}{on} -- {}",
                t.outcome.as_str(),
                t.name,
                t.detail
            ));
        }
        if !self.not_run.is_empty() {
            lines.push(format!(
                "  not run here (format and hashes checked only): {}",
                self.not_run.join(", ")
            ));
        }
        lines
    }
}

/// What the objective's pinned verifier said about one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verify {
    Accept,
    Reject(String),
    Unavailable(String),
}

/// How to check: against which objective, and whether a host with no jail
/// may run the tests anyway.
pub struct Checker<'a> {
    pub objective: Option<&'a str>,
    pub verify: Option<&'a dyn Fn(&Value) -> Verify>,
    pub allow_unjailed: bool,
    /// Every runnable target, or only the one a worker here would use.
    pub all_targets: bool,
    /// With no `verify` here, whether the node that offered the package
    /// already scored its `verify: "accept"` tests with the objective's pinned
    /// verifier (its report passed). A worker has no verifier of its own to
    /// ask; what it can still check -- the solver runs, exits 0 and prints
    /// candidates -- it checks.
    pub node_vouched: bool,
}

/// Run every test on every target this host can run.
pub fn check(package: &Package, checker: &Checker<'_>) -> Report {
    let manifest = &package.manifest;
    let mut platforms = runnable_here(manifest);
    if !checker.all_targets {
        platforms.truncate(1);
    }
    let not_run: Vec<String> = manifest
        .targets
        .keys()
        .filter(|p| !platforms.contains(p))
        .map(|p| p.as_str().to_string())
        .chain(manifest.other_targets.iter().cloned())
        .collect();
    let mut sandbox = super::executor::name();
    let mut tests = Vec::new();
    if platforms.is_empty() {
        for test in &manifest.tests {
            tests.push(TestResult {
                name: test.name.clone(),
                platform: None,
                outcome: Outcome::Unavailable,
                detail: "no target in this package runs on this host".into(),
                candidates: 0,
                millis: 0,
            });
        }
    }
    for platform in platforms {
        let target = &manifest.targets[&platform];
        for test in &manifest.tests {
            let round = Round {
                dir: &package.dir,
                platform,
                target,
                resources: manifest.resources,
                assignment: &test.assignment,
                objective: checker
                    .objective
                    .or(manifest.objective.as_deref())
                    .unwrap_or(""),
                worker: "cairn-solver-check",
                round: test.round,
                threads: 1,
                allow_unjailed: checker.allow_unjailed,
            };
            let ran = run::run(&round);
            if let Ok(output) = &ran {
                sandbox = output.sandbox.to_string();
            }
            let mut result = judge(test, ran, checker);
            result.platform = Some(platform);
            tests.push(result);
        }
    }
    Report {
        package: package.id(),
        sandbox,
        checked_at: crate::time::timestamp(),
        objective: checker
            .objective
            .map(str::to_string)
            .or_else(|| manifest.objective.clone()),
        tests,
        not_run,
    }
}

fn judge(
    test: &TestVector,
    ran: Result<run::Output, Failure>,
    checker: &Checker<'_>,
) -> TestResult {
    let mut result = TestResult {
        name: test.name.clone(),
        platform: None,
        outcome: Outcome::Pass,
        detail: String::new(),
        candidates: 0,
        millis: 0,
    };
    let output = match ran {
        Ok(output) => output,
        Err(Failure::Unavailable(why)) => {
            result.outcome = Outcome::Unavailable;
            result.detail = why;
            return result;
        }
        Err(broke @ Failure::Broke { .. }) => {
            result.outcome = Outcome::Fail;
            result.detail = broke.to_string();
            return result;
        }
    };
    result.candidates = output.candidates.len();
    result.millis = u64::try_from(output.elapsed.as_millis()).unwrap_or(u64::MAX);
    let fail = |mut result: TestResult, detail: String| {
        result.outcome = Outcome::Fail;
        result.detail = detail;
        result
    };
    if let Some(first) = output.skipped.first() {
        return fail(
            result,
            format!(
                "printed {} line(s) that are not candidate objects ({first}); every stdout line \
                 must be one JSON object",
                output.skipped.len()
            ),
        );
    }
    if let Some(expected) = &test.expect {
        let mut want: Vec<String> = expected.iter().map(Value::canonical_string).collect();
        let mut got: Vec<String> = output
            .candidates
            .iter()
            .map(Value::canonical_string)
            .collect();
        want.sort();
        got.sort();
        if want != got {
            let missing = want.iter().find(|w| !got.contains(w));
            let extra = got.iter().find(|g| !want.contains(g));
            let mut detail = format!(
                "printed {} candidate(s), expected {}",
                got.len(),
                want.len()
            );
            if let Some(missing) = missing {
                detail.push_str(&format!("; missing {}", clip(missing)));
            }
            if let Some(extra) = extra {
                detail.push_str(&format!("; unexpected {}", clip(extra)));
            }
            return fail(result, detail);
        }
    }
    if test.verify_accept {
        if output.candidates.is_empty() {
            return fail(
                result,
                "printed nothing; verify: \"accept\" needs at least one candidate".into(),
            );
        }
        let Some(verify) = checker.verify else {
            if checker.node_vouched {
                result.detail = format!(
                    "{} candidate(s) under {}; the node scored this test with the objective's \
                     verifier when the package was added",
                    output.candidates.len(),
                    output.sandbox
                );
                return result;
            }
            result.outcome = Outcome::Unavailable;
            result.detail = "no objective to verify against here (give --objective)".into();
            return result;
        };
        for (n, candidate) in output.candidates.iter().enumerate() {
            match verify(candidate) {
                Verify::Accept => {}
                Verify::Reject(why) => {
                    return fail(
                        result,
                        format!("the pinned verifier rejected candidate {}: {why}", n + 1),
                    )
                }
                Verify::Unavailable(why) => {
                    result.outcome = Outcome::Unavailable;
                    result.detail = format!("the pinned verifier could not run here: {why}");
                    return result;
                }
            }
        }
    }
    result.detail = format!(
        "{} candidate(s) in {:.1} s under {}",
        output.candidates.len(),
        Duration::from_millis(result.millis).as_secs_f64(),
        output.sandbox
    );
    result
}

fn clip(text: &str) -> String {
    if text.len() <= 120 {
        return text.to_string();
    }
    let mut cut = 120;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &text[..cut])
}
