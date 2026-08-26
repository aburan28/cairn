//! What the `cairn` binary does with the log-related environment variables,
//! checked on the real process.
//!
//! `CAIRN_LOG` used to be the ledger path here and the stderr log level in
//! every daemon. `Ledger::open_with` treats a missing file as an empty log, so
//! `CAIRN_LOG=debug cairn audit` audited a nonexistent file named `debug` and
//! printed "log verified". The unit tests in `src/main.rs` pin the parser; this
//! file pins the exit code and both streams, because the thing that went wrong
//! was a clean exit that a script would have believed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "cairn-cli-env-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Run the binary in `dir` with a scrubbed environment, so a developer's own
/// shell (which may well export one of these) cannot decide the outcome.
fn cairn(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cairn"));
    command
        .current_dir(dir)
        .env_remove("CAIRN_LOG")
        .env_remove("CAIRN_LOG_PATH")
        .env_remove("CAIRN_LOG_LEVEL")
        .env_remove("CAIRN_DATA")
        .args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("spawn cairn")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn a_level_in_cairn_log_makes_audit_fail_instead_of_verifying_nothing() {
    let dir = scratch("level");
    let output = cairn(&dir, &[("CAIRN_LOG", "debug")], &["audit"]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected a usage error; stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("log verified"),
        "audited a file that does not exist and called it clean: {stdout}"
    );
    assert!(
        stderr.contains("CAIRN_LOG_PATH") && stderr.contains("CAIRN_LOG_LEVEL"),
        "the refusal must name both replacements; got: {stderr}"
    );
    assert!(
        !dir.join("debug").exists(),
        "a file named after the level was created"
    );
}

#[test]
fn a_level_in_cairn_log_is_ignored_once_the_log_is_named_on_the_command_line() {
    // An operator with `export CAIRN_LOG=debug` in their profile, for the
    // daemons, and scripts that always pass `--log`: those scripts must keep
    // working, because for them the variable was never ambiguous.
    let dir = scratch("named");
    let log = dir.join("ledger.jsonl");
    let output = cairn(
        &dir,
        &[("CAIRN_LOG", "debug")],
        &["--log", log.to_str().expect("utf-8"), "audit"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        text(&output.stderr)
    );
    assert!(text(&output.stdout).contains("log verified"));
}

#[test]
fn a_level_in_cairn_log_does_not_stop_help() {
    let dir = scratch("help");
    let output = cairn(&dir, &[("CAIRN_LOG", "debug")], &["help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).contains("CAIRN_LOG_PATH"));
}

#[test]
fn cairn_log_path_names_the_ledger() {
    // A file that is not a ledger, so that opening it is visible: an absent
    // path opens as an empty log, and would prove nothing about which path
    // was read.
    let dir = scratch("path");
    let log = dir.join("ledger.jsonl");
    std::fs::write(&log, "this is not a record\n").expect("writes");
    let output = cairn(
        &dir,
        &[("CAIRN_LOG_PATH", log.to_str().expect("utf-8"))],
        &["audit"],
    );
    let stdout = text(&output.stdout);
    assert_ne!(
        output.status.code(),
        Some(0),
        "the ledger at CAIRN_LOG_PATH was not the one opened; stdout: {stdout}"
    );
    assert!(!stdout.contains("log verified"));
    assert!(
        !dir.join("cairn.jsonl").exists(),
        "fell back to the default path instead"
    );
}

#[test]
fn an_obvious_path_in_cairn_log_still_works_and_warns_once() {
    let dir = scratch("legacy-path");
    let log = dir.join("legacy.jsonl");
    std::fs::write(&log, "this is not a record\n").expect("writes");
    let output = cairn(
        &dir,
        &[("CAIRN_LOG", log.to_str().expect("utf-8"))],
        &["audit"],
    );
    let stderr = text(&output.stderr);
    // The file was opened (it is garbage, so the audit fails on it) ...
    assert_ne!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(!text(&output.stdout).contains("log verified"));
    // ... and the operator was told where the name went.
    assert!(
        stderr.contains("deprecated") && stderr.contains("CAIRN_LOG_PATH"),
        "no deprecation warning; got: {stderr}"
    );
    assert_eq!(
        stderr.matches("deprecated").count(),
        1,
        "warned more than once: {stderr}"
    );
}
