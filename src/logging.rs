//! Levelled diagnostics, on stderr, always.
//!
//! # Why this exists
//!
//! Before it, every diagnostic in the crate was an unconditional `eprintln!`:
//! seventy of them, twenty-four in the p2p daemon (then the separate
//! `cairn-p2p` binary) alone, none carrying a
//! timestamp. A daemon that runs for days on a five-second tick could not say
//! *when* anything happened, two nodes' output could not be lined up against
//! each other, and there was no way to ask for more detail without editing the
//! source and rebuilding. Diagnosing a stalled transfer genuinely meant
//! patching in `eprintln!`s by hand — which is the same thing as having no
//! logging.
//!
//! # Why the backend is ours
//!
//! The [`log`] facade is a dependency; what writes the bytes is here, and that
//! is deliberate. **`cairn mcp` and `cairn run` speak JSON-RPC on stdout.** A logger that
//! wrote a line there would not look untidy, it would corrupt the protocol
//! mid-session and the client would blame itself — the exact failure
//! `scripts/mcp-smoke.sh` exists to catch. Owning the writer is what turns
//! "stderr, always" from a convention somebody has to remember into a test —
//! `every_level_writes_to_stderr_and_never_stdout` below, which re-execs this
//! binary as a child so it checks what the *process* put on each stream.
//!
//! (Named rather than linked: it is `#[cfg(test)]`, so an intra-doc link to it
//! does not resolve in a doc build and `cargo doc -D warnings` rejects it.)
//!
//! # Filtering
//!
//! `CAIRN_LOG_LEVEL` picks the level: `error`, `warn`, `info`, `debug`,
//! `trace`, or `off`. Default `info`, which is the daemon's ordinary narration
//! and nothing per-message. `debug` adds every p2p protocol message with its
//! peer and direction; `trace` is the same plus payload detail.
//!
//! It was `CAIRN_LOG` until that name turned out to be doing two jobs: the
//! `cairn` CLI read it as the ledger *path*, so `CAIRN_LOG=debug` exported for
//! a daemon sent `cairn audit` to a nonexistent file called `debug`, which
//! opens as an empty log and audits clean. `CAIRN_LOG` is still honoured here
//! when it holds a level, so an operator's existing shell keeps working; the
//! CLI refuses that same value, which is the half that was dangerous.
//!
//! Deliberately one global level rather than per-module filtering. A directive
//! grammar (`p2p=debug,swarm=trace`) is a parser, a spec, and a thing to get
//! wrong, and the question an operator actually has here is "show me more",
//! not "show me more about exactly this module". `RUST_LOG` is not read: this
//! is not `env_logger` and pretending otherwise would promise a syntax that
//! does not work.

use crate::time::timestamp;
use log::{LevelFilter, Log, Metadata, Record};
use std::io::Write;

/// The environment variable that sets the level.
pub const LEVEL_VAR: &str = "CAIRN_LOG_LEVEL";

/// The name the level used to live under, shared with the ledger path.
///
/// Read only when [`LEVEL_VAR`] is unset *and* the value parses as a level:
/// a path here was aimed at the `cairn` CLI, not at this logger, and is not
/// this logger's business to complain about.
pub const LEGACY_LEVEL_VAR: &str = "CAIRN_LOG";

/// Writes every record to stderr, prefixed with a UTC timestamp and level.
struct StderrLogger {
    level: LevelFilter,
}

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // One `write!` of one preformatted string rather than several: two
        // threads logging concurrently interleave at write boundaries, and a
        // daemon logs from its accept thread and its dial loop at once. Not a
        // lock -- a single write is not atomic in general -- but it is the
        // difference between rare interleaving and routine interleaving.
        let line = format!(
            "{} {:<5} {} {}\n",
            timestamp(),
            record.level(),
            record.target(),
            record.args()
        );
        // Failure to log is never worth crashing over, and stderr being closed
        // or full is exactly when a panic would be least welcome.
        let _ = std::io::stderr().write_all(line.as_bytes());
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

/// Parse a level name. Unknown values are `None` rather than a default, so the
/// caller can say so instead of silently logging at a level nobody asked for.
pub fn parse_level(text: &str) -> Option<LevelFilter> {
    match text.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

/// Where a level came from, so [`init`] can say so once the logger is up.
#[derive(Debug, PartialEq, Eq)]
enum Resolution {
    /// Nothing asked; `info`.
    Default,
    /// [`LEVEL_VAR`] named it.
    Explicit,
    /// [`LEGACY_LEVEL_VAR`] named it, and the operator should move.
    Legacy,
    /// [`LEVEL_VAR`] held this, which is not a level; `info` is used.
    Unparseable(String),
}

/// Pick the level from the two variables' values, without touching the
/// environment, so the precedence can be tested as a function.
///
/// [`LEVEL_VAR`] wins whenever it is set, even when it is wrong: a typo in the
/// new name should be reported as one, not silently papered over by an old
/// setting that happens to be lying around. The legacy name is consulted only
/// in its absence, and only when its value is actually a level.
fn resolve(explicit: Option<&str>, legacy: Option<&str>) -> (LevelFilter, Resolution) {
    match explicit.filter(|text| !text.is_empty()) {
        Some(text) => match parse_level(text) {
            Some(level) => (level, Resolution::Explicit),
            None => (LevelFilter::Info, Resolution::Unparseable(text.to_string())),
        },
        None => match legacy.and_then(parse_level) {
            Some(level) => (level, Resolution::Legacy),
            None => (LevelFilter::Info, Resolution::Default),
        },
    }
}

/// Install the logger, reading [`LEVEL_VAR`] for the level, and
/// [`LEGACY_LEVEL_VAR`] when that is unset and the old one holds a level.
///
/// Idempotent and never fatal: a second call, or a binary whose library
/// already installed one, is a no-op rather than an error. Nothing here is
/// worth failing a node's startup over.
///
/// An unparseable `CAIRN_LOG_LEVEL` warns *through the logger it just
/// installed* and keeps the default, which is the honest order -- refusing to
/// start because a diagnostic setting was misspelled would be worse than the
/// typo. A level taken from the legacy name warns the same way, once, so the
/// operator learns the new name from the daemon they were tuning.
pub fn init() {
    let explicit = std::env::var(LEVEL_VAR).ok();
    let legacy = std::env::var(LEGACY_LEVEL_VAR).ok();
    let (level, resolution) = resolve(explicit.as_deref(), legacy.as_deref());

    let logger = Box::new(StderrLogger { level });
    if log::set_boxed_logger(logger).is_ok() {
        log::set_max_level(level);
    }

    match resolution {
        Resolution::Unparseable(text) => log::warn!(
            "{LEVEL_VAR}={text:?} is not a level (off, error, warn, info, debug, trace); \
             using info"
        ),
        Resolution::Legacy => log::warn!(
            "{LEGACY_LEVEL_VAR} is deprecated for the log level; set {LEVEL_VAR} instead \
             (the cairn CLI reads {LEGACY_LEVEL_VAR} as a ledger path and refuses a level)"
        ),
        Resolution::Default | Resolution::Explicit => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;

    #[test]
    fn levels_parse_by_name_and_case_insensitively() {
        assert_eq!(parse_level("debug"), Some(LevelFilter::Debug));
        assert_eq!(parse_level("  TRACE "), Some(LevelFilter::Trace));
        assert_eq!(parse_level("warning"), Some(LevelFilter::Warn));
        assert_eq!(parse_level("off"), Some(LevelFilter::Off));
        // Not a default. The caller reports it; guessing would log at a level
        // nobody chose.
        assert_eq!(parse_level("verbose"), None);
        assert_eq!(parse_level(""), None);
    }

    #[test]
    fn the_new_name_wins_and_the_old_one_counts_only_as_a_level() {
        assert_eq!(
            resolve(None, None),
            (LevelFilter::Info, Resolution::Default)
        );
        assert_eq!(
            resolve(Some("debug"), None),
            (LevelFilter::Debug, Resolution::Explicit)
        );
        // The old name still turns the level up, so a shell that exported it
        // for a daemon keeps working -- but it is flagged, not silent.
        assert_eq!(
            resolve(None, Some("trace")),
            (LevelFilter::Trace, Resolution::Legacy)
        );
        assert_eq!(
            resolve(None, Some("  ERROR ")),
            (LevelFilter::Error, Resolution::Legacy)
        );
        // A path in the old name was aimed at the CLI, not here. Ignored, not
        // reported: the CLI is the one that reads it and can say so.
        assert_eq!(
            resolve(None, Some("/srv/cairn/cairn.jsonl")),
            (LevelFilter::Info, Resolution::Default)
        );
        assert_eq!(
            resolve(None, Some("cairn.jsonl")),
            (LevelFilter::Info, Resolution::Default)
        );
        // The new name takes precedence over the old even when it is wrong,
        // and says so; an old setting must not quietly override a typo in the
        // one the operator is actually editing.
        assert_eq!(
            resolve(Some("verbose"), Some("trace")),
            (
                LevelFilter::Info,
                Resolution::Unparseable(String::from("verbose"))
            )
        );
        assert_eq!(
            resolve(Some("warn"), Some("trace")),
            (LevelFilter::Warn, Resolution::Explicit)
        );
        // Empty is unset. `CAIRN_LOG_LEVEL= cairn serve` should not report a
        // typo in nothing.
        assert_eq!(
            resolve(Some(""), Some("debug")),
            (LevelFilter::Debug, Resolution::Legacy)
        );
    }

    #[test]
    fn a_level_admits_itself_and_everything_louder() {
        let logger = StderrLogger {
            level: LevelFilter::Info,
        };
        for admitted in [Level::Error, Level::Warn, Level::Info] {
            assert!(
                logger.enabled(&Metadata::builder().level(admitted).build()),
                "{admitted} should pass an info filter"
            );
        }
        for filtered in [Level::Debug, Level::Trace] {
            assert!(
                !logger.enabled(&Metadata::builder().level(filtered).build()),
                "{filtered} should not pass an info filter"
            );
        }
    }

    /// The property the MCP protocol depends on.
    ///
    /// `cairn mcp` writes JSON-RPC to stdout. One log line there is a
    /// corrupt frame, and the client blames itself. Asserted on the real
    /// process rather than by reading the source, because the thing that would
    /// break this is a future edit reaching for `println!`.
    #[test]
    fn every_level_writes_to_stderr_and_never_stdout() {
        let exe = std::env::current_exe().expect("test binary path");
        // Re-exec this same test binary as a child, with a marker telling it to
        // run the logging body instead of the suite. Spawning a child is the
        // only way to capture what a *process* put on each stream.
        let output = std::process::Command::new(exe)
            .env("CAIRN_LOG_TEST_CHILD", "1")
            .env(LEVEL_VAR, "trace")
            .arg("--ignored")
            .arg("emit_one_line_at_every_level")
            .output()
            .expect("re-exec the test binary");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for level in ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"] {
            assert!(
                stderr.contains(level),
                "{level} never reached stderr; got: {stderr}"
            );
            assert!(
                !stdout.contains(level),
                "{level} reached STDOUT, which corrupts the MCP protocol; got: {stdout}"
            );
        }
    }

    /// The child half of the test above. `#[ignore]` so it never runs in the
    /// ordinary suite, where its output would just be noise.
    #[test]
    #[ignore = "child process of every_level_writes_to_stderr_and_never_stdout"]
    fn emit_one_line_at_every_level() {
        init();
        log::error!("ERROR marker");
        log::warn!("WARN marker");
        log::info!("INFO marker");
        log::debug!("DEBUG marker");
        log::trace!("TRACE marker");
    }
}
