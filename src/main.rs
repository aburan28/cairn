//! `proofwork` -- the command line.
//!
//! ```text
//! proofwork [--log PATH] [--root PATH] <command>
//!   post      examples/collatz/objective.json
//!   commit    <objective-id> --submitter alice --artifact a.json --nonce n1
//!   reveal    <objective-id> --submitter alice --artifact a.json --nonce n1
//!   settle
//!   audit
//!   verify    --from checkpoint.json [--root-key HEX|FILE] [--audit]
//!   attribute
//!   log
//! ```
//!
//! Everything this binary prints is re-derivable by anyone holding a copy of the
//! log. That is the whole Stage 0 proposition -- one operator, no consensus, no
//! trust required -- so the commands are deliberately thin: they read files,
//! hand records to [`proofwork::node`], and format what comes back.
//!
//! # Why the argument parser is hand-rolled
//!
//! The reference implementation uses `argparse`. There is no `clap` in this
//! crate's dependency set, and adding one to parse six subcommands would be a
//! poor trade: the grammar below reads top to bottom, and every failure in it is
//! a typed error rather than a process abort. `clap` and `argparse` both call
//! `exit()` from inside the parser; this one returns.
//!
//! # No panics, including the ones a CLI usually gets away with
//!
//! Three panics that ship in most Rust command-line tools are handled here
//! explicitly, because the no-panic rule in this crate is not decoration:
//!
//! 1. [`std::env::args`] panics on an argument that is not valid UTF-8. This
//!    binary reads [`std::env::args_os`] and reports the bad argument instead.
//! 2. `println!` panics when stdout is gone -- `proofwork log | head -1` is the
//!    everyday way to trigger it, and `scripts/demo.sh` does exactly that. Every
//!    line goes through [`say`], where a closed pipe simply ends the output.
//! 3. Slicing a string by byte offset panics on a multi-byte boundary. The log
//!    summaries truncate by *character*, matching Python's `str` slicing, which
//!    is the same reason they cannot panic.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | success |
//! | 1    | `audit` found problems, or `verify` found a checkpoint mismatch |
//! | 2    | the network refused the submission, or the input was bad |
//! | 3    | `reveal` produced a verdict that settles nothing |
//!
//! Code 3 is the one worth explaining. A *rejected* claim exits 0: rejection is
//! a real answer, reached by a verifier that ran. `unavailable` and
//! `invalid_spec` exit 3, because nothing was learned about the artifact and a
//! caller scripting against this binary must be able to tell "we checked and it
//! is wrong" from "we could not check". Collapsing those two is precisely the
//! confusion the verdict taxonomy exists to prevent.

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read as _, Write};
use std::path::{Path, PathBuf};
use std::process;

use proofwork::attribution::{payouts_over, FlowError, FlowParams};
use proofwork::canonical::{short, CanonicalError, Value};
use proofwork::checkpoint::SignedCheckpoint;
use proofwork::incentive::design::Report as IncentiveReport;
use proofwork::incentive::{NodeParams, ParamError, Rat};
use proofwork::ledger::{Codec, Ledger, LedgerError};
use proofwork::node::Node;
use proofwork::records::{commitment_hash, Claim, Commitment, Objective, RecordError};
use proofwork::schema::{validate_claim, validate_objective, SchemaError};
use proofwork::store::atrest::{AtRestError, Cipher};
use proofwork::store::{mirror, quota, Store, StoreError};
use proofwork::time::timestamp;

/// Where the log lives when `--log` and `$PROOFWORK_LOG` are both silent.
const DEFAULT_LOG: &str = "proofwork.jsonl";

/// Bytes of entropy in a generated nonce -- `secrets.token_hex(16)`.
const NONCE_BYTES: usize = 16;

/// Characters of an objective statement shown by `log`.
const STATEMENT_WIDTH: usize = 60;

/// Characters of a verdict detail shown by `log`.
const DETAIL_WIDTH: usize = 40;

// ---------------------------------------------------------------------------
// Adapter for `src/node.rs`
//
// Every call into the rules engine goes through this block, so nothing below
// names a `node` type and a change to that module's signatures lands in one
// place. The surface used is:
//
//     Node::new(ledger, root) -> Node
//     Node::ledger(&self) -> &Ledger
//     Node::post_objective(&mut self, &Objective, ts: &str) -> Result<String, RuleViolation>
//     Node::commit(&mut self, &Commitment, ts: &str)        -> Result<String, RuleViolation>
//     Node::reveal(&mut self, &Claim, ts: &str)             -> Result<Outcome, RuleViolation>
//     Node::audit(&self, rerun: bool) -> Vec<String>
//
// `ts` is required rather than defaulted, unlike the reference implementation's
// `ts: str | None = None`. That is the better contract -- the log's timestamps
// come from one clock reading per command instead of one per append -- and it
// is why [`timestamp`] lives here.
// ---------------------------------------------------------------------------

/// Open the log and wrap it in a node rooted at `--root`.
fn open_node(options: &Options) -> Result<Node, CliError> {
    let codec = resolve_codec(options)?;
    let ledger = Ledger::open_with(options.log.as_str(), codec).map_err(CliError::Ledger)?;
    Ok(Node::new(ledger, options.root.as_str()))
}

/// Read-only view of the node's log, for `log` and `attribute`.
fn ledger_of(node: &Node) -> &Ledger {
    node.ledger()
}

fn post_objective(node: &mut Node, objective: &Objective, ts: &str) -> Result<String, CliError> {
    node.post_objective(objective, ts)
        .map_err(|violation| CliError::Refused(violation.to_string()))
}

fn post_commitment(node: &mut Node, commitment: &Commitment, ts: &str) -> Result<(), CliError> {
    node.commit(commitment, ts)
        .map(|_id| ())
        .map_err(|violation| CliError::Refused(violation.to_string()))
}

/// Reveal a claim and flatten the outcome, so no `node` type escapes this block.
fn reveal_claim(node: &mut Node, claim: &Claim, ts: &str) -> Result<RevealReport, CliError> {
    let outcome = node
        .reveal(claim, ts)
        .map_err(|violation| CliError::Refused(violation.to_string()))?;
    Ok(RevealReport {
        claim_id: outcome.claim_id.clone(),
        status: outcome.verdict.status.as_str().to_string(),
        detail: outcome.verdict.detail.clone(),
        settles: outcome.verdict.settles(),
        settled: outcome.settled,
        pending_epoch: outcome.pending_epoch,
        reward: outcome.reward,
        note: outcome.note.clone(),
    })
}

/// Drain every settlement batch whose epoch has closed.
fn settle_now(node: &mut Node, ts: &str) -> Result<Vec<(String, bool, u64, String)>, CliError> {
    let outcomes = node
        .settle_at(ts)
        .map_err(|violation| CliError::Refused(violation.to_string()))?;
    Ok(outcomes
        .into_iter()
        .map(|outcome| {
            (
                outcome.claim_id,
                outcome.settled,
                outcome.reward,
                outcome.note,
            )
        })
        .collect())
}

fn audit_log(node: &Node, rerun: bool) -> Vec<String> {
    node.audit(rerun)
}

/// What `reveal` tells the user, decoupled from `node::Outcome`.
///
/// `settled` and `settles` are separate on purpose and are not redundant: a
/// verdict can settle -- a genuine `reject`, or an `accept` of an artifact
/// already in the log -- while moving no value at all. Printing only one of them
/// would hide either "we reached a real answer" or "you were paid".
#[derive(Debug, Clone, PartialEq, Eq)]
struct RevealReport {
    claim_id: String,
    status: String,
    detail: String,
    /// The verdict is a real answer about the artifact (`accept` or `reject`).
    settles: bool,
    /// Value actually moved.
    settled: bool,
    /// Accepted, but its reveal epoch has not closed, so nothing has been paid
    /// yet and `settled == false` does not mean "earned nothing".
    pending_epoch: Option<u64>,
    reward: u64,
    note: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything this binary can fail with, and nothing it can panic with.
#[derive(Debug)]
enum CliError {
    /// The command line does not parse.
    Usage(String),
    /// The network refused the submission. Carries the rule violation's message
    /// rather than the violation itself, so this type stays independent of
    /// `node`.
    Refused(String),
    Io {
        context: String,
        source: io::Error,
    },
    /// A file the user pointed at is not canonically representable JSON -- a
    /// float, most likely. Worth its own variant because the fix is specific:
    /// carry a scaled integer or a decimal string instead.
    Json {
        path: String,
        source: CanonicalError,
    },
    /// A checkpoint file could not be read as one. Carries the message rather
    /// than the error, so this type stays independent of `checkpoint`.
    Checkpoint(String),
    Record(RecordError),
    /// The body does not match the published schema in `spec/`.
    ///
    /// Separate from [`CliError::Record`] because it fires earlier and says
    /// something different: the record is not the shape third parties implement
    /// against, so it is refused before any constructor gets to interpret it.
    Schema(SchemaError),
    Ledger(LedgerError),
    Flow(FlowError),
    /// A payload already in the log cannot be read back. Distinct from
    /// [`CliError::Record`], which is about a file the user just supplied: this
    /// one means the log itself is malformed, and the entry number is the only
    /// way to find it.
    LogPayload {
        seq: u64,
        reason: String,
    },
    /// A total exceeded the range this build can represent. Python's integers
    /// are unbounded and the reference implementation therefore has no such
    /// failure; here it is reported, never wrapped.
    Overflow(String),
    /// No operating-system entropy for a nonce.
    Entropy(String),
    /// A set of incentive parameters that is not a network.
    Params(ParamError),
    /// The local store could not be read, sized, or copied.
    Store(StoreError),
    /// The at-rest key could not be created, found, or used.
    AtRest(AtRestError),
    /// An argument is not valid UTF-8. `std::env::args` would panic on this.
    NotUnicode(usize),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(message) => f.write_str(message),
            CliError::Params(error) => write!(f, "{error}"),
            CliError::Store(error) => write!(f, "{error}"),
            CliError::AtRest(error) => write!(f, "{error}"),
            CliError::Refused(message) => f.write_str(message),
            CliError::Io { context, source } => write!(f, "{context}: {source}"),
            CliError::Json { path, source } => write!(f, "{path}: {source}"),
            CliError::Checkpoint(message) => f.write_str(message),
            CliError::Record(source) => write!(f, "{source}"),
            CliError::Schema(source) => write!(f, "{source}"),
            CliError::Ledger(source) => write!(f, "{source}"),
            CliError::Flow(source) => write!(f, "{source}"),
            CliError::LogPayload { seq, reason } => write!(f, "log entry {seq}: {reason}"),
            CliError::Overflow(what) => {
                write!(f, "{what} exceeds the range this build can represent")
            }
            CliError::Entropy(why) => f.write_str(why),
            CliError::NotUnicode(position) => write!(f, "argument {position} is not valid UTF-8"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Io { source, .. } => Some(source),
            CliError::Json { source, .. } => Some(source),
            CliError::Record(source) => Some(source),
            CliError::Schema(source) => Some(source),
            CliError::Ledger(source) => Some(source),
            CliError::Flow(source) => Some(source),
            _ => None,
        }
    }
}

impl CliError {
    /// The stderr line. `refused:` is reserved for rule violations, matching the
    /// reference implementation, so a script can tell a rejected submission from
    /// a mistyped path without parsing prose.
    fn report(&self) -> String {
        match self {
            CliError::Usage(message) => format!("usage: {message}\ntry `proofwork help`"),
            // A schema violation *is* a refusal: the network declined to record
            // the body, and a script watching for `refused:` needs to see it as
            // one rather than as a local file-handling error.
            CliError::Refused(message) => format!("refused: {message}"),
            CliError::Schema(source) => format!("refused: {source}"),
            other => format!("error: {other}"),
        }
    }

    /// Every error here exits 2. Codes 1 and 3 are outcomes, not errors -- the
    /// log audited and found problems, or a verifier reached no real verdict --
    /// and both are returned from their commands as ordinary success values.
    fn code(&self) -> i32 {
        2
    }
}

// ---------------------------------------------------------------------------
// Command line grammar
// ---------------------------------------------------------------------------

/// Options that apply to every command. Accepted before the command name, where
/// `argparse` puts them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    log: String,
    root: String,
    /// The data directory, when one was chosen. `None` keeps the pre-existing
    /// behaviour exactly: a bare `proofwork.jsonl` wherever you are standing.
    data: Option<String>,
    /// Explicit key file, overriding `$PROOFWORK_KEY` and the default.
    key_file: Option<String>,
    /// File holding the passphrase for a wrapped key.
    passphrase_file: Option<String>,
    /// Size cap on the data directory, in bytes.
    max_size: Option<u64>,
}

impl Options {
    fn from_env() -> Options {
        let data = env::var(proofwork::store::DATA_ENV)
            .ok()
            .filter(|value| !value.is_empty());
        // `--log` and `$PROOFWORK_LOG` still win, and the default when neither
        // is set still depends on whether a data directory was chosen. An
        // operator upgrading into this release must find their log exactly
        // where they left it.
        let log = env::var("PROOFWORK_LOG").ok().filter(|v| !v.is_empty());
        Options {
            log: match (log, &data) {
                (Some(explicit), _) => explicit,
                (None, Some(data)) => Store::new(data).log_path().display().to_string(),
                (None, None) => DEFAULT_LOG.to_string(),
            },
            root: String::from("."),
            data,
            key_file: None,
            passphrase_file: None,
            max_size: None,
        }
    }

    /// The store this invocation is working in.
    ///
    /// Falls back to the log file's own directory when no data directory was
    /// chosen, so `store status` and `sync` mean something even for an operator
    /// who never adopted the layout.
    fn store(&self) -> Store {
        let root = match &self.data {
            Some(data) => PathBuf::from(data),
            None => PathBuf::from(&self.log)
                .parent()
                .map(Path::to_path_buf)
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| PathBuf::from(".")),
        };
        Store::new(root).with_limit(self.max_size)
    }

    /// Where the at-rest key lives.
    fn key_path(&self) -> PathBuf {
        match &self.key_file {
            Some(path) => PathBuf::from(path),
            None => self.store().default_key_path(),
        }
    }

    /// The passphrase, if one was supplied.
    ///
    /// From a file or `$PROOFWORK_PASSPHRASE`, never from a prompt. Reading a
    /// passphrase without echoing it needs terminal control this crate has no
    /// dependency for, and echoing one into a shell's scrollback and history is
    /// worse than not offering the option.
    fn passphrase(&self) -> Result<Option<String>, CliError> {
        if let Some(path) = &self.passphrase_file {
            let text = fs::read_to_string(path).map_err(|source| CliError::Io {
                context: format!("reading {path}"),
                source,
            })?;
            return Ok(Some(text.trim_end_matches(['\n', '\r']).to_string()));
        }
        Ok(env::var("PROOFWORK_PASSPHRASE")
            .ok()
            .filter(|value| !value.is_empty()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Post {
        objective: String,
    },
    Commit {
        objective_id: String,
        submitter: String,
        artifact: String,
        /// `None` means "generate one", matching `args.nonce or token_hex(16)`.
        nonce: Option<String>,
    },
    Reveal {
        objective_id: String,
        submitter: String,
        artifact: String,
        nonce: String,
        cites: Vec<String>,
    },
    Settle,
    Audit {
        rerun: bool,
    },
    Verify {
        checkpoint: String,
        /// Hex, or a path to a file holding hex. `None` trusts the key inside
        /// the checkpoint, which authenticates nothing -- see [`cmd_verify`].
        root_key: Option<String>,
        /// Also re-derive the rules over the signed prefix.
        audit: bool,
        rerun: bool,
    },
    Attribute {
        params: FlowParams,
    },
    Blob {
        action: BlobAction,
    },
    /// Evaluate the node-operator incentives at a parameter set.
    ///
    /// The only command that reads no log. It answers a question about the
    /// *rules* rather than about anything that has happened, so it takes its
    /// whole input from flags and is safe to run anywhere.
    Incentives {
        params: Box<NodeParams>,
        /// Also report how far each parameter can move before the mechanism
        /// breaks. Opt-in because it is hundreds of full solver runs.
        robustness: bool,
    },
    /// Create an at-rest key.
    Keygen {
        wrap: bool,
    },
    /// Report or reclaim local storage.
    Store {
        action: StoreAction,
    },
    /// Copy the store to a directory of the operator's choosing.
    Sync {
        destination: String,
        options: mirror::Options,
    },
    Log,
    Help,
}

/// What `proofwork blob` was asked to do.
///
/// Collection is a command rather than something a sync round does on its way
/// past, and that is deliberate: a node cannot distinguish a blob nobody wants
/// from a blob pinned by an objective it has not synced yet, so a timer-driven
/// collector would delete exactly the code its peers are about to ask it for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlobAction {
    /// Every content address held.
    List,
    /// Pins the log names that this node cannot obtain — why a verdict came
    /// back `unavailable`.
    Need,
    /// Copy every pinned file the bundle has into the store, so peers can fetch
    /// it. Idempotent, and what a log written before blobs existed needs.
    Publish,
    /// Drop blobs no objective in the log pins.
    Collect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreAction {
    /// How much is used, split into what can and cannot be evicted.
    Status,
    /// Evict reclaimable content until the cap is met.
    Gc,
    /// Convert a plaintext log to a sealed one, in place.
    Encrypt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Invocation {
    options: Options,
    command: Command,
}

/// A position in the argument list.
///
/// Deliberately not an iterator: several of the parsers below need to look at
/// the next token *without* consuming it -- `--cites` stops at the first token
/// that looks like a flag -- and a cursor says that more plainly than a
/// `Peekable` threaded through six functions.
struct Cursor {
    tokens: Vec<String>,
    at: usize,
}

impl Cursor {
    fn new(tokens: Vec<String>) -> Cursor {
        Cursor { tokens, at: 0 }
    }

    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.at).map(String::as_str)
    }

    /// Peek, but owned. Callers match on this and then consume, which a borrowed
    /// peek would not allow while the match is still live.
    fn peek_owned(&self) -> Option<String> {
        self.peek().map(str::to_string)
    }

    fn take(&mut self) -> Option<String> {
        let token = self.tokens.get(self.at).cloned();
        if token.is_some() {
            // Saturating rather than `+= 1`: `at` never passes `tokens.len()`,
            // but a counter that cannot wrap needs no argument about why.
            self.at = self.at.saturating_add(1);
        }
        token
    }

    /// The value belonging to `flag`.
    ///
    /// A following flag is refused rather than swallowed, so `--submitter
    /// --artifact a.json` is an error instead of a submitter literally named
    /// `--artifact`. That mirrors `argparse` and, more to the point, stops a
    /// typo from being recorded in an append-only log.
    fn value(&mut self, flag: &str) -> Result<String, CliError> {
        let missing = || CliError::Usage(format!("{flag} needs a value"));
        match self.peek() {
            None => Err(missing()),
            Some(next) if is_flag(next) => Err(missing()),
            Some(_) => self.take().ok_or_else(missing),
        }
    }
}

/// Does this token look like an option rather than a value?
///
/// A bare `-` is not a flag: it is the conventional spelling of "standard
/// input", and refusing it here would be a surprise with no upside.
fn is_flag(token: &str) -> bool {
    token.starts_with('-') && token.chars().count() > 1
}

/// Rewrite `--flag=value` into `--flag` `value`.
///
/// `argparse` accepts both spellings and shell users expect both. Doing it as a
/// pre-pass keeps every parser below dealing with exactly one form. Only tokens
/// that already look like long options are touched, so a positional path
/// containing `=` survives intact.
fn expand_inline_values(tokens: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    for token in tokens {
        if token.starts_with("--") {
            if let Some(split) = token.find('=') {
                let (flag, rest) = token.split_at(split);
                out.push(flag.to_string());
                // `rest` starts with the single ASCII byte `=`, so skipping one
                // byte lands on a character boundary. `get` rather than a slice
                // expression, so that even a wrong assumption cannot panic.
                out.push(rest.get(1..).unwrap_or("").to_string());
                continue;
            }
        }
        out.push(token);
    }
    out
}

fn parse(argv: Vec<String>) -> Result<Invocation, CliError> {
    let mut cursor = Cursor::new(expand_inline_values(argv));
    let mut options = Options::from_env();

    while let Some(token) = cursor.peek_owned() {
        if token == "--log" {
            cursor.take();
            options.log = cursor.value("--log")?;
        } else if token == "--root" {
            cursor.take();
            options.root = cursor.value("--root")?;
        } else if token == "--data-dir" {
            cursor.take();
            let data = cursor.value("--data-dir")?;
            // Only redirect the log if nothing more specific already did.
            if env::var("PROOFWORK_LOG")
                .ok()
                .filter(|v| !v.is_empty())
                .is_none()
                && options.log == DEFAULT_LOG
            {
                options.log = Store::new(&data).log_path().display().to_string();
            }
            options.data = Some(data);
        } else if token == "--key-file" {
            cursor.take();
            options.key_file = Some(cursor.value("--key-file")?);
        } else if token == "--passphrase-file" {
            cursor.take();
            options.passphrase_file = Some(cursor.value("--passphrase-file")?);
        } else if token == "--max-size" {
            cursor.take();
            let text = cursor.value("--max-size")?;
            options.max_size = Some(proofwork::store::parse_size(&text).map_err(CliError::Store)?);
        } else if token == "-h" || token == "--help" {
            cursor.take();
            return Ok(Invocation {
                options,
                command: Command::Help,
            });
        } else {
            break;
        }
    }

    let name = match cursor.take() {
        Some(name) => name,
        None => return Err(CliError::Usage(String::from("no command given"))),
    };

    let command = match name.as_str() {
        "post" => parse_post(&mut cursor)?,
        "commit" => parse_commit(&mut cursor)?,
        "reveal" => parse_reveal(&mut cursor)?,
        "settle" => {
            expect_end(&mut cursor, "settle")?;
            Command::Settle
        }
        "audit" => parse_audit(&mut cursor)?,
        "verify" => parse_verify(&mut cursor)?,
        "attribute" => parse_attribute(&mut cursor)?,
        "blob" => parse_blob(&mut cursor)?,
        "incentives" => parse_incentives(&mut cursor)?,
        "keygen" => parse_keygen(&mut cursor)?,
        "store" => parse_store(&mut cursor)?,
        "sync" => parse_sync(&mut cursor)?,
        "log" => {
            expect_end(&mut cursor, "log")?;
            Command::Log
        }
        "help" => Command::Help,
        other => return Err(CliError::Usage(format!("unknown command {other:?}"))),
    };

    Ok(Invocation { options, command })
}

fn parse_post(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut objective: Option<String> = None;
    while let Some(token) = cursor.take() {
        if is_flag(&token) {
            return Err(CliError::Usage(format!("post: unknown option {token:?}")));
        }
        if objective.is_some() {
            return Err(CliError::Usage(format!(
                "post: unexpected argument {token:?}"
            )));
        }
        objective = Some(token);
    }
    Ok(Command::Post {
        objective: require(objective, "post", "an objective JSON file")?,
    })
}

fn parse_commit(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut objective_id: Option<String> = None;
    let mut submitter: Option<String> = None;
    let mut artifact: Option<String> = None;
    let mut nonce: Option<String> = None;

    while let Some(token) = cursor.take() {
        if token == "--submitter" {
            submitter = Some(cursor.value("--submitter")?);
        } else if token == "--artifact" {
            artifact = Some(cursor.value("--artifact")?);
        } else if token == "--nonce" {
            nonce = Some(cursor.value("--nonce")?);
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("commit: unknown option {token:?}")));
        } else if objective_id.is_some() {
            return Err(CliError::Usage(format!(
                "commit: unexpected argument {token:?}"
            )));
        } else {
            objective_id = Some(token);
        }
    }

    Ok(Command::Commit {
        objective_id: require(objective_id, "commit", "an objective id")?,
        submitter: require(submitter, "commit", "--submitter")?,
        artifact: require(artifact, "commit", "--artifact")?,
        // An explicitly empty `--nonce ""` generates one, exactly as Python's
        // `args.nonce or token_hex(16)` does. An empty nonce is not a nonce.
        nonce: nonce.filter(|value| !value.is_empty()),
    })
}

fn parse_reveal(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut objective_id: Option<String> = None;
    let mut submitter: Option<String> = None;
    let mut artifact: Option<String> = None;
    let mut nonce: Option<String> = None;
    let mut cites: Vec<String> = Vec::new();

    while let Some(token) = cursor.take() {
        if token == "--submitter" {
            submitter = Some(cursor.value("--submitter")?);
        } else if token == "--artifact" {
            artifact = Some(cursor.value("--artifact")?);
        } else if token == "--nonce" {
            nonce = Some(cursor.value("--nonce")?);
        } else if token == "--cites" {
            // `nargs="*"`: consume until the next flag or the end. Claim ids are
            // `sha256:` digests, so none of them can be mistaken for a flag.
            while let Some(next) = cursor.peek_owned() {
                if is_flag(&next) {
                    break;
                }
                cursor.take();
                cites.push(next);
            }
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("reveal: unknown option {token:?}")));
        } else if objective_id.is_some() {
            return Err(CliError::Usage(format!(
                "reveal: unexpected argument {token:?}"
            )));
        } else {
            objective_id = Some(token);
        }
    }

    Ok(Command::Reveal {
        objective_id: require(objective_id, "reveal", "an objective id")?,
        submitter: require(submitter, "reveal", "--submitter")?,
        artifact: require(artifact, "reveal", "--artifact")?,
        // Required, unlike on `commit`: revealing is opening a commitment, and
        // the nonce is part of what that commitment hashed. There is nothing to
        // generate.
        nonce: require(nonce, "reveal", "--nonce")?,
        cites,
    })
}

fn parse_audit(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut rerun = true;
    while let Some(token) = cursor.take() {
        if token == "--no-rerun" {
            rerun = false;
        } else {
            return Err(CliError::Usage(format!("audit: unknown option {token:?}")));
        }
    }
    Ok(Command::Audit { rerun })
}

fn parse_verify(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut checkpoint: Option<String> = None;
    let mut root_key: Option<String> = None;
    let mut audit = false;
    // Mirrors `audit`: re-running the verifiers is the default, and
    // `--no-rerun` is the way to ask for the cheap structural check.
    let mut rerun = true;

    while let Some(token) = cursor.take() {
        if token == "--from" {
            checkpoint = Some(cursor.value("--from")?);
        } else if token == "--root-key" {
            root_key = Some(cursor.value("--root-key")?);
        } else if token == "--audit" {
            audit = true;
        } else if token == "--no-rerun" {
            rerun = false;
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("verify: unknown option {token:?}")));
        } else if checkpoint.is_some() {
            return Err(CliError::Usage(format!(
                "verify: unexpected argument {token:?}"
            )));
        } else {
            checkpoint = Some(token);
        }
    }

    Ok(Command::Verify {
        checkpoint: require(checkpoint, "verify", "--from <checkpoint.json>")?,
        root_key,
        audit,
        rerun,
    })
}

/// `incentives [--nodes N] [--settled N] [--stake N] [--fee N/D] ...`
///
/// Every flag overrides one field of [`NodeParams::reference`], so an analyst
/// changes the number they care about and inherits a coherent set for the rest.
/// The alternative -- requiring all twenty-odd -- would make the command
/// unusable, and defaulting the ones the user forgot to zero would silently
/// produce an answer about a different network.
///
/// Rates are written as exact fractions (`1/100`), never as decimals. That is
/// not fussiness: the whole harness exists to make equilibrium comparisons
/// decidable, and accepting `0.01` here would mean parsing it into a float and
/// throwing that away at the first threshold comparison.
fn parse_incentives(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut params = NodeParams::reference();
    let mut robustness = false;

    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--robustness" => robustness = true,
            "--nodes" => params.nodes = parse_u32(&cursor.value("--nodes")?, "--nodes")?,
            "--settled" => {
                params.settled_value = parse_u64(&cursor.value("--settled")?, "--settled")?
            }
            "--fee" => params.fee = parse_rate(&cursor.value("--fee")?, "--fee")?,
            "--stake" => params.stake = parse_u64(&cursor.value("--stake")?, "--stake")?,
            "--slash-rate" => {
                params.slash_rate = parse_rate(&cursor.value("--slash-rate")?, "--slash-rate")?
            }
            "--verify-cost" => {
                params.verify_cost = parse_u64(&cursor.value("--verify-cost")?, "--verify-cost")?
            }
            "--storage-cost" => {
                params.storage_cost = parse_u64(&cursor.value("--storage-cost")?, "--storage-cost")?
            }
            "--operating-cost" => {
                params.operating_cost =
                    parse_u64(&cursor.value("--operating-cost")?, "--operating-cost")?
            }
            "--canary-rate" => {
                params.canary_rate = parse_rate(&cursor.value("--canary-rate")?, "--canary-rate")?
            }
            "--canary-leak" => {
                params.canary_leak = parse_rate(&cursor.value("--canary-leak")?, "--canary-leak")?
            }
            "--fraud-rate" => {
                params.fraud_rate = parse_rate(&cursor.value("--fraud-rate")?, "--fraud-rate")?
            }
            "--catch-bounty" => {
                params.catch_bounty = parse_u64(&cursor.value("--catch-bounty")?, "--catch-bounty")?
            }
            "--audit-rate" => {
                params.audit_rate = parse_rate(&cursor.value("--audit-rate")?, "--audit-rate")?
            }
            "--committee" => {
                params.committee = parse_u32(&cursor.value("--committee")?, "--committee")?
            }
            "--threshold" => {
                params.threshold = parse_u32(&cursor.value("--threshold")?, "--threshold")?
            }
            "--sealed-value" => {
                params.sealed_value = parse_u64(&cursor.value("--sealed-value")?, "--sealed-value")?
            }
            "--detection-rate" => {
                params.detection_rate =
                    parse_rate(&cursor.value("--detection-rate")?, "--detection-rate")?
            }
            "--per-node-rewards" => params.reward_rule = proofwork::incentive::RewardRule::PerNode,
            other => {
                return Err(CliError::Usage(format!(
                    "incentives: unknown option {other:?}"
                )))
            }
        }
    }

    // Validated here so a nonsense network is a command line error rather than
    // a surprise partway through a report.
    params.validate().map_err(CliError::Params)?;
    Ok(Command::Incentives {
        params: Box::new(params),
        robustness,
    })
}

/// A rate as an exact fraction: `1/100`, or a bare `0` or `1`.
fn parse_rate(text: &str, flag: &str) -> Result<Rat, CliError> {
    let bad = || {
        CliError::Usage(format!(
            "{flag}: expected an exact fraction in [0, 1] such as 1/100, got {text:?}"
        ))
    };
    let (num, den) = match text.split_once('/') {
        Some((num, den)) => (num, den),
        None => (text, "1"),
    };
    let num: u32 = num.trim().parse().map_err(|_| bad())?;
    let den: u32 = den.trim().parse().map_err(|_| bad())?;
    Rat::rate(num, den).ok_or_else(bad)
}

fn parse_keygen(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut wrap = false;
    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--passphrase" => wrap = true,
            other => return Err(CliError::Usage(format!("keygen: unknown option {other:?}"))),
        }
    }
    Ok(Command::Keygen { wrap })
}

fn parse_store(cursor: &mut Cursor) -> Result<Command, CliError> {
    let action = match cursor.take().as_deref() {
        Some("status") | None => StoreAction::Status,
        Some("gc") => StoreAction::Gc,
        Some("encrypt") => StoreAction::Encrypt,
        Some(other) => {
            return Err(CliError::Usage(format!(
                "store: unknown action {other:?}; try status, gc, or encrypt"
            )))
        }
    };
    expect_end(cursor, "store")?;
    Ok(Command::Store { action })
}

fn parse_sync(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut destination: Option<String> = None;
    let mut options = mirror::Options::default();
    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--prune" => options.prune = true,
            "--dry-run" => options.dry_run = true,
            other if is_flag(other) => {
                return Err(CliError::Usage(format!("sync: unknown option {other:?}")))
            }
            other => {
                if destination.is_some() {
                    return Err(CliError::Usage(format!(
                        "sync: unexpected argument {other:?}"
                    )));
                }
                destination = Some(other.to_string());
            }
        }
    }
    Ok(Command::Sync {
        destination: require(destination, "sync", "a destination directory")?,
        options,
    })
}

fn parse_attribute(cursor: &mut Cursor) -> Result<Command, CliError> {
    // Seeded from `FlowParams::default()` so the defaults live in one place --
    // the module that has to honour them -- rather than being restated here.
    let defaults = FlowParams::default();
    let mut delta_num = defaults.delta_num();
    let mut delta_den = defaults.delta_den();
    let mut max_depth = defaults.max_depth();

    while let Some(token) = cursor.take() {
        if token == "--delta-num" {
            delta_num = parse_u64(&cursor.value("--delta-num")?, "--delta-num")?;
        } else if token == "--delta-den" {
            delta_den = parse_u64(&cursor.value("--delta-den")?, "--delta-den")?;
        } else if token == "--max-depth" {
            max_depth = parse_u32(&cursor.value("--max-depth")?, "--max-depth")?;
        } else {
            return Err(CliError::Usage(format!(
                "attribute: unknown option {token:?}"
            )));
        }
    }

    // Validated here rather than at use, so an impossible delta is a command
    // line error and not a surprise partway through a payout table.
    let params = FlowParams::new(delta_num, delta_den, max_depth).map_err(CliError::Flow)?;
    Ok(Command::Attribute { params })
}

fn expect_end(cursor: &mut Cursor, command: &str) -> Result<(), CliError> {
    match cursor.take() {
        None => Ok(()),
        Some(token) => Err(CliError::Usage(format!(
            "{command}: unexpected argument {token:?}"
        ))),
    }
}

fn require(value: Option<String>, command: &str, what: &str) -> Result<String, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("{command}: {what} is required")))
}

fn parse_blob(cursor: &mut Cursor) -> Result<Command, CliError> {
    let action = match cursor.take() {
        // Bare `blob` lists, because "what do I have" is the question an
        // operator diagnosing an `unavailable` verdict asks first.
        None => BlobAction::List,
        Some(word) => match word.as_str() {
            "ls" | "list" => BlobAction::List,
            "need" => BlobAction::Need,
            "publish" => BlobAction::Publish,
            "gc" => BlobAction::Collect,
            other => {
                return Err(CliError::Usage(format!(
                    "blob: unknown action {other:?}; expected ls, need, publish, or gc"
                )))
            }
        },
    };
    expect_end(cursor, "blob")?;
    Ok(Command::Blob { action })
}

/// Negative numbers are rejected by the type, not by a range check: `-1` does
/// not parse as `u64` and never reaches [`FlowParams`].
fn parse_u64(text: &str, flag: &str) -> Result<u64, CliError> {
    text.parse::<u64>().map_err(|_| {
        CliError::Usage(format!(
            "{flag} expects a non-negative integer, got {text:?}"
        ))
    })
}

fn parse_u32(text: &str, flag: &str) -> Result<u32, CliError> {
    text.parse::<u32>().map_err(|_| {
        CliError::Usage(format!(
            "{flag} expects a non-negative integer, got {text:?}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Write one line, treating a closed pipe as the end of output.
///
/// `println!` panics if the write fails, and `proofwork post ... | head -1` --
/// which `scripts/demo.sh` runs to pick the objective id out of field 2 -- is
/// the ordinary way to make it fail. A CLI dying with a Rust panic because the
/// reader stopped reading is both ugly and a violation of this crate's no-panic
/// rule.
fn say(out: &mut dyn Write, text: impl AsRef<str>) {
    let _ = writeln!(out, "{}", text.as_ref());
}

fn print_help(out: &mut dyn Write) {
    say(out, "proofwork -- verified results as the unit of account");
    say(out, "");
    say(out, "usage: proofwork [--log PATH] [--root PATH] <command>");
    say(out, "");
    say(out, "commands:");
    say(out, "  post <objective.json>");
    say(out, "      fund a checkable question");
    say(
        out,
        "  commit <objective-id> --submitter S --artifact FILE [--nonce N]",
    );
    say(out, "      bind to an artifact without revealing it");
    say(
        out,
        "  reveal <objective-id> --submitter S --artifact FILE --nonce N [--cites ID ...]",
    );
    say(
        out,
        "      reveal a committed artifact and verify it (settles when the epoch closes)",
    );
    say(out, "  settle");
    say(out, "      pay out every reveal epoch that has closed");
    say(out, "  audit [--no-rerun]");
    say(out, "      re-derive the entire log independently");
    say(
        out,
        "  verify --from CHECKPOINT [--root-key HEX|FILE] [--audit] [--no-rerun]",
    );
    say(
        out,
        "      check a signed checkpoint against this log's prefix",
    );
    say(
        out,
        "  attribute [--delta-num N] [--delta-den N] [--max-depth N]",
    );
    say(out, "      compute citation-flow payouts");
    say(out, "  blob [ls|need|publish|gc]");
    say(
        out,
        "      inspect the content-addressed store of pinned verifier code",
    );
    say(
        out,
        "  incentives [--nodes N] [--settled N] [--canary-rate N/D] ...",
    );
    say(
        out,
        "      evaluate the node-operator game at a parameter set",
    );
    say(out, "  log");
    say(out, "      print the log");
    say(out, "  keygen [--passphrase]");
    say(
        out,
        "      create the at-rest key that seals the local store",
    );
    say(out, "  store [status|gc|encrypt]");
    say(
        out,
        "      report local usage, reclaim space, or seal an existing log",
    );
    say(out, "  sync <dir> [--prune] [--dry-run]");
    say(
        out,
        "      copy the store to a directory of your choosing, still encrypted",
    );
    say(out, "  help");
    say(out, "      this message");
    say(out, "");
    say(out, "options:");
    say(
        out,
        "  --log PATH    JSONL log (default: $PROOFWORK_LOG, else proofwork.jsonl)",
    );
    say(
        out,
        "  --root PATH   root for pinned verifier code (default: .)",
    );
    say(
        out,
        "  --data-dir PATH        where node data lives (default: $PROOFWORK_DATA)",
    );
    say(
        out,
        "  --key-file PATH        at-rest key (default: $PROOFWORK_KEY, else ~/.proofwork/key)",
    );
    say(
        out,
        "  --passphrase-file PATH passphrase for a wrapped key (else $PROOFWORK_PASSPHRASE)",
    );
    say(
        out,
        "  --max-size SIZE        cap on the data directory, e.g. 20GB or 20GiB",
    );
    say(out, "");
    say(out, "exit codes:");
    say(out, "  0  success");
    say(
        out,
        "  1  audit found problems, a checkpoint did not match, or incentives do not hold",
    );
    say(out, "  2  refused, or bad input");
    say(out, "  3  reveal produced a verdict that settles nothing");
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Read a JSON file as a canonical value.
///
/// Floats are refused here, at the boundary, rather than deeper in: a float
/// cannot be canonically serialized, so an artifact carrying one has no stable
/// identity and no two nodes would agree on its hash.
fn read_json(path: &str) -> Result<Value, CliError> {
    let text = fs::read_to_string(path).map_err(|source| CliError::Io {
        context: format!("reading {path}"),
        source,
    })?;
    Value::from_json(&text).map_err(|source| CliError::Json {
        path: path.to_string(),
        source,
    })
}

fn cmd_post(out: &mut dyn Write, options: &Options, path: &str) -> Result<i32, CliError> {
    let mut node = open_node(options)?;
    let data = read_json(path)?;
    // The published schema runs *before* the constructor. `Objective::from_value`
    // is permissive by necessity -- it has to read back records written by older
    // versions of this code -- so it is the wrong place to enforce the contract
    // third parties implement against. Gating here means nothing enters the log
    // that `spec/objective.schema.json` would reject.
    validate_objective(&data).map_err(CliError::Schema)?;
    let objective = Objective::from_value(&data).map_err(CliError::Record)?;
    let id = post_objective(&mut node, &objective, &timestamp())?;

    // Field 2 of this line is the objective id, and `scripts/demo.sh` reads it
    // with `awk '{print $2}'`. Keep it first, and keep the id second.
    say(out, format!("objective {id}"));
    say(
        out,
        format!(
            "  reward {}  verifier {}",
            objective.reward,
            objective.verifier_kind().unwrap_or("?")
        ),
    );
    Ok(0)
}

fn cmd_commit(
    out: &mut dyn Write,
    options: &Options,
    objective_id: &str,
    submitter: &str,
    artifact_path: &str,
    nonce: Option<&str>,
) -> Result<i32, CliError> {
    let mut node = open_node(options)?;
    let artifact = read_json(artifact_path)?;
    let nonce = match nonce {
        Some(nonce) => nonce.to_string(),
        None => random_nonce()?,
    };

    // One clock reading for the record and the log entry alike, so a commitment
    // cannot appear to have been created after it was appended.
    let stamp = timestamp();
    let hash = commitment_hash(objective_id, submitter, &artifact, &nonce);
    let commitment = Commitment::new(objective_id, submitter, hash.as_str(), stamp.as_str());
    post_commitment(&mut node, &commitment, &stamp)?;

    say(out, format!("committed {}", short(&hash)));
    say(
        out,
        format!("  nonce {nonce}   <- keep this; you need it to reveal"),
    );
    Ok(0)
}

fn cmd_reveal(
    out: &mut dyn Write,
    options: &Options,
    objective_id: &str,
    submitter: &str,
    artifact_path: &str,
    nonce: &str,
    cites: &[String],
) -> Result<i32, CliError> {
    let mut node = open_node(options)?;
    let artifact = read_json(artifact_path)?;
    let stamp = timestamp();
    let claim = Claim::new(
        objective_id,
        submitter,
        artifact,
        nonce,
        stamp.as_str(),
        cites.to_vec(),
    )
    .map_err(CliError::Record)?;
    validate_claim(&claim.to_value()).map_err(CliError::Schema)?;

    let report = reveal_claim(&mut node, &claim, &stamp)?;
    // Print the FULL claim id, not the display-shortened form. Citing this claim
    // is the next thing anyone does with it -- an improvement on a progressive
    // objective is *required* to cite the frontier it beat -- and a truncated id
    // cannot be passed to `--cites`. A convenience abbreviation that makes the
    // output unusable for the workflow that follows is not a convenience.
    say(out, format!("claim {}", report.claim_id));
    say(
        out,
        format!("  verdict  {}: {}", report.status, report.detail),
    );
    match report.pending_epoch {
        Some(epoch) => say(
            out,
            format!("  pending  settles when epoch {epoch} closes  (`proofwork settle`)"),
        ),
        None => say(
            out,
            format!(
                "  settled  {}  reward {}  ({})",
                report.settled, report.reward, report.note
            ),
        ),
    }

    // See the module docs: a rejection is a real answer and exits 0. Only a
    // verdict that settles nothing -- `unavailable`, `invalid_spec` -- exits 3,
    // because in that case nothing was learned and the objective is still open.
    Ok(if report.settles { 0 } else { 3 })
}

/// Close every reveal epoch that is over and pay out its batch.
///
/// Exists because settlement is deferred: a claim accepted in epoch N is paid
/// when N closes, in an order derived from a beacon rather than from arrival.
/// Every other command drains due batches on its way in, so this is only needed
/// when nothing else is happening -- which is exactly the case a demo, a cron
/// job, or an operator winding a quiet objective down finds itself in.
fn cmd_settle(out: &mut dyn Write, options: &Options) -> Result<i32, CliError> {
    let mut node = open_node(options)?;
    let settled = settle_now(&mut node, &timestamp())?;
    if settled.is_empty() {
        say(out, "no batch was due");
        return Ok(0);
    }
    for (claim_id, moved, reward, note) in &settled {
        say(out, format!("claim {claim_id}"));
        say(
            out,
            format!("  settled  {moved}  reward {reward}  ({note})"),
        );
    }
    Ok(0)
}

fn cmd_audit(out: &mut dyn Write, options: &Options, rerun: bool) -> Result<i32, CliError> {
    let node = open_node(options)?;
    let problems = audit_log(&node, rerun);
    let ledger = ledger_of(&node);

    say(
        out,
        format!(
            "entries {}   head {}",
            ledger.len(),
            short(ledger.head().unwrap_or("-"))
        ),
    );
    say(
        out,
        format!(
            "merkle  {}",
            ledger.root().unwrap_or_else(|| String::from("-"))
        ),
    );

    if !problems.is_empty() {
        say(out, "");
        say(out, format!("{} problem(s):", problems.len()));
        for problem in &problems {
            say(out, format!("  ! {problem}"));
        }
        return Ok(1);
    }

    say(out, "");
    say(
        out,
        "log verified: chain intact, every settled claim re-verified",
    );
    Ok(0)
}

/// Check a signed checkpoint against the local log.
///
/// The question this answers is the one a hash chain cannot answer alone: *is
/// my copy of the log a prefix-consistent view of what the operator published?*
/// A truncated log is internally consistent -- every link checks out -- so
/// rollback is invisible without an external anchor, and this is the anchor.
///
/// Three exit codes, and the split between them is deliberate. A signature that
/// does not verify and a root that does not match are the *same* answer to the
/// reader: the log in front of them is not the one that was signed. Both are 1.
/// A missing file or an unparsable checkpoint is 2, because nothing was
/// checked either way and reporting "mismatch" would be a false accusation.
fn cmd_verify(
    out: &mut dyn Write,
    options: &Options,
    checkpoint_path: &str,
    root_key: Option<&str>,
    audit: bool,
    rerun: bool,
) -> Result<i32, CliError> {
    let signed = SignedCheckpoint::from_value(&read_json(checkpoint_path)?)
        .map_err(|source| CliError::Checkpoint(source.to_string()))?;

    // Without an out-of-band key this verifies only that the file is
    // self-consistent: an operator rewriting history signs the rewrite with a
    // fresh key and the check passes. Said plainly rather than left to the
    // reader to work out, because a verification that proves nothing is worse
    // than none -- it is the one that gets quoted.
    let expected = match root_key {
        Some(source) => read_root_key(source)?,
        None => signed.public_key.clone(),
    };

    let node = open_node(options)?;
    let ledger = ledger_of(&node);
    if let Err(error) = signed.verify_prefix(ledger, &expected) {
        say(out, format!("checkpoint FAILED: {error}"));
        return Ok(1);
    }

    say(
        out,
        format!(
            "checkpoint ok: height {}  head {}  issued {}",
            signed.checkpoint.height,
            short(signed.checkpoint.head.as_deref().unwrap_or("-")),
            signed.checkpoint.issued_at
        ),
    );
    if root_key.is_none() {
        say(
            out,
            "  warning: no --root-key given, so this checks the file against itself; \
             pin the operator's published key to make it mean anything",
        );
    }
    let local = ledger.len();
    let height = signed.checkpoint.height;
    if local as u64 > height {
        say(
            out,
            format!("  local log continues past the checkpoint ({local} entries)"),
        );
    }

    if !audit {
        return Ok(0);
    }

    // Audit the signed prefix, not the whole log: entries appended after the
    // checkpoint have not been vouched for by anyone, and folding their
    // problems into this result would make a valid checkpoint look broken.
    let height = usize::try_from(height)
        .map_err(|_| CliError::Overflow(String::from("checkpoint height")))?;
    let prefix = match ledger.prefix(height) {
        Some(prefix) => prefix,
        // Unreachable: `verify_prefix` already refused a short log above. An
        // error rather than an unwrap all the same -- this is the money path.
        None => {
            return Err(CliError::Checkpoint(format!(
                "log is shorter than {height}"
            )))
        }
    };
    let problems = Node::new(prefix, options.root.as_str()).audit(rerun);
    if !problems.is_empty() {
        say(out, "");
        say(
            out,
            format!("{} problem(s) inside the signed prefix:", problems.len()),
        );
        for problem in &problems {
            say(out, format!("  ! {problem}"));
        }
        return Ok(1);
    }
    say(out, "  signed prefix re-derives cleanly");
    Ok(0)
}

/// A root key given as hex on the command line, or as a file holding hex.
///
/// Both spellings, because a 1952-byte ML-DSA-65 key is 3904 hex characters and
/// no one is pasting that into a shell. Which one was meant is decided by
/// whether the argument names an existing file, not by a flag: a path and a
/// hex blob are not confusable.
fn read_root_key(source: &str) -> Result<Vec<u8>, CliError> {
    let text = if Path::new(source).is_file() {
        fs::read_to_string(source).map_err(|error| CliError::Io {
            context: format!("reading {source}"),
            source: error,
        })?
    } else {
        source.to_string()
    };
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if text.len() % 2 != 0 {
        return Err(CliError::Usage(String::from(
            "--root-key: hex has an odd number of digits",
        )));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let digits: Vec<char> = text.chars().collect();
    for pair in digits.chunks(2) {
        let hex: String = pair.iter().collect();
        let byte = u8::from_str_radix(&hex, 16)
            .map_err(|_| CliError::Usage(format!("--root-key: {hex:?} is not hex")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn cmd_attribute(
    out: &mut dyn Write,
    options: &Options,
    params: &FlowParams,
) -> Result<i32, CliError> {
    let node = open_node(options)?;
    let ledger = ledger_of(&node);
    let claims = claim_index(ledger)?;
    let settlements = settlements_of(ledger)?;
    let payouts = payouts_over(&settlements, &claims, params).map_err(CliError::Flow)?;

    for line in render_attribution(params, &payouts)? {
        say(out, line);
    }
    Ok(0)
}

/// Print the incentive report and say whether the mechanism holds.
///
/// Exit code 1 when it does not, matching `audit`: both are "the tool ran fine
/// and the answer is bad news", which a script has to be able to tell from "the
/// tool could not run". A failing report is still printed in full -- the useful
/// part is *which* line failed.
fn cmd_incentives(
    out: &mut dyn Write,
    params: &NodeParams,
    robustness: bool,
) -> Result<i32, CliError> {
    let report = IncentiveReport::of(params).map_err(|error| CliError::Usage(error.to_string()))?;
    for line in report.to_string().lines() {
        say(out, line);
    }
    if robustness {
        say(out, "");
        say(
            out,
            "robustness -- how far each parameter moves before honesty stops holding",
        );
        let margins = proofwork::incentive::robustness::margins(params)
            .map_err(|error| CliError::Usage(error.to_string()))?;
        for margin in &margins {
            say(out, format!("  {margin}"));
        }
        // The line that changes what somebody does next. A verdict says the
        // mechanism works; this says which measurement it is betting on.
        match margins.iter().find(|m| m.factor.is_some()) {
            Some(binding) => say(
                out,
                format!(
                    "  binding constraint    {} -- measure this one first",
                    binding.parameter
                ),
            ),
            None => say(
                out,
                "  no parameter breaks within the ladder, or the point already fails",
            ),
        }
    }
    Ok(if report.passes() { 0 } else { 1 })
}

// ---------------------------------------------------------------------------
// The local store
// ---------------------------------------------------------------------------

/// Decide how to read and write this invocation's log.
///
/// The ledger deliberately refuses to guess ([`Ledger::open_with`]); this is
/// where the guessing is allowed to happen, because it is a user-experience
/// decision rather than an integrity one. The rule:
///
/// * a log whose first line is sealed needs the key, and says so if it is
///   missing rather than reporting the file as corrupt;
/// * a log that is already plaintext stays plaintext, even if a key exists --
///   converting somebody's log as a side effect of an unrelated command would
///   be indefensible, and `store encrypt` is the command that does it on
///   purpose;
/// * a log that does not exist yet is created sealed **if a key is there**, so
///   `keygen` followed by ordinary use encrypts without further ceremony.
fn resolve_codec(options: &Options) -> Result<Codec, CliError> {
    let sealed_on_disk = first_line_is_sealed(&options.log)?;
    let key_path = options.key_path();
    let exists = key_path.exists();

    match (sealed_on_disk, exists) {
        (Some(true), false) => Err(CliError::AtRest(AtRestError::NoKeyFile { path: key_path })),
        (Some(true), true) | (None, true) => {
            let passphrase = options.passphrase()?;
            let cipher = Cipher::read_key_file(&key_path, passphrase.as_deref())
                .map_err(CliError::AtRest)?;
            Ok(Codec::Sealed(Box::new(cipher)))
        }
        // Plaintext log, or no log and no key: unchanged behaviour.
        (Some(false), _) | (None, false) => Ok(Codec::Plain),
    }
}

/// `Some(true)` sealed, `Some(false)` plaintext, `None` for an absent or empty log.
fn first_line_is_sealed(path: &str) -> Result<Option<bool>, CliError> {
    if !Path::new(path).exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|source| CliError::Io {
        context: format!("reading {path}"),
        source,
    })?;
    Ok(text
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(proofwork::store::atrest::is_sealed_line))
}

fn cmd_keygen(out: &mut dyn Write, options: &Options, wrap: bool) -> Result<i32, CliError> {
    let path = options.key_path();
    let passphrase = options.passphrase()?;
    if wrap && passphrase.is_none() {
        return Err(CliError::Usage(String::from(
            "keygen --passphrase needs a passphrase: set $PROOFWORK_PASSPHRASE or \
             pass --passphrase-file PATH. There is no prompt, because reading one \
             without echoing it needs terminal control this binary does not link",
        )));
    }
    let cipher = Cipher::generate(&mut rand_core::OsRng);
    cipher
        .write_key_file(
            &path,
            if wrap { passphrase.as_deref() } else { None },
            &mut rand_core::OsRng,
        )
        .map_err(CliError::AtRest)?;

    say(out, format!("key written to {}", path.display()));
    if wrap {
        say(out, "  wrapped with a passphrase (argon2id)");
    }
    if !proofwork::store::atrest::private_permissions_supported() {
        say(
            out,
            "  warning: this platform cannot restrict the key to its owner",
        );
    }
    // The one thing an operator has to be told, once, loudly.
    let store = options.store();
    if path.starts_with(store.root()) {
        say(out, "");
        say(
            out,
            "  WARNING: this key is INSIDE the data directory. Anything that copies",
        );
        say(
            out,
            "  that directory copies the key with it, which is not encryption at all.",
        );
        say(
            out,
            "  `proofwork sync` refuses to copy it; other tools will not.",
        );
    }
    say(out, "");
    say(
        out,
        "Back this file up somewhere the data is not. Lose it and the log is",
    );
    say(
        out,
        "unreadable -- there is no recovery path and that is the design.",
    );
    Ok(0)
}

fn cmd_store(out: &mut dyn Write, options: &Options, action: StoreAction) -> Result<i32, CliError> {
    let store = options.store();
    match action {
        StoreAction::Status => {
            let usage = quota::usage(&store).map_err(CliError::Store)?;
            say(out, format!("store   {}", store.root().display()));
            say(out, format!("log     {}", options.log));
            say(
                out,
                format!(
                    "sealed  {}",
                    match first_line_is_sealed(&options.log)? {
                        Some(true) => "yes",
                        Some(false) => "no -- run `proofwork store encrypt`",
                        None => "n/a (log is empty)",
                    }
                ),
            );
            let key = options.key_path();
            say(
                out,
                format!(
                    "key     {} ({})",
                    key.display(),
                    if key.exists() { "present" } else { "absent" }
                ),
            );
            say(
                out,
                format!("usage   {}", quota::describe(&usage, store.limit())),
            );
            if let Some(limit) = store.limit() {
                if usage.over(limit) {
                    say(out, "        OVER LIMIT -- run `proofwork store gc`");
                    return Ok(1);
                }
            }
            Ok(0)
        }
        StoreAction::Gc => {
            if store.limit().is_none() {
                return Err(CliError::Usage(String::from(
                    "store gc needs a limit: pass --max-size, for example --max-size 20GB",
                )));
            }
            let eviction = quota::reclaim(&store, 0).map_err(CliError::Store)?;
            if eviction.is_empty() {
                say(out, "nothing to reclaim");
            } else {
                for (path, bytes) in &eviction.removed {
                    say(
                        out,
                        format!(
                            "evicted {} ({})",
                            path.display(),
                            proofwork::store::format_size(*bytes)
                        ),
                    );
                }
                say(
                    out,
                    format!(
                        "freed {} -- {}",
                        proofwork::store::format_size(eviction.freed),
                        quota::describe(&eviction.after, store.limit())
                    ),
                );
                say(
                    out,
                    "note: evicted content can no longer answer an availability challenge.",
                );
            }
            Ok(0)
        }
        StoreAction::Encrypt => cmd_encrypt(out, options),
    }
}

/// Convert a plaintext log to a sealed one.
///
/// Written to a new file, verified by reading it back, and only then swapped in.
/// The plaintext original is renamed aside rather than deleted: this command
/// must not be able to destroy somebody's only copy, so the last step is left to
/// the operator and is stated loudly rather than done quietly.
fn cmd_encrypt(out: &mut dyn Write, options: &Options) -> Result<i32, CliError> {
    match first_line_is_sealed(&options.log)? {
        Some(true) => {
            say(out, "already sealed; nothing to do");
            return Ok(0);
        }
        None => {
            say(out, "log is empty or absent; nothing to convert");
            say(out, "new entries will be sealed if a key is present");
            return Ok(0);
        }
        Some(false) => {}
    }
    let key_path = options.key_path();
    if !key_path.exists() {
        return Err(CliError::AtRest(AtRestError::NoKeyFile { path: key_path }));
    }
    let passphrase = options.passphrase()?;
    let cipher =
        Cipher::read_key_file(&key_path, passphrase.as_deref()).map_err(CliError::AtRest)?;

    let plain = Ledger::open(&options.log).map_err(CliError::Ledger)?;
    let problems = plain.verify_chain();
    if !problems.is_empty() {
        // Converting a broken log would bake the breakage into ciphertext and
        // make it far harder to diagnose afterwards.
        for problem in &problems {
            say(out, format!("  {problem}"));
        }
        return Err(CliError::Refused(String::from(
            "the log does not verify; fix it before sealing it",
        )));
    }

    let sealed_path = format!("{}.sealing", options.log);
    let _ = fs::remove_file(&sealed_path);
    {
        let mut sealed = Ledger::open_with(
            &sealed_path,
            Codec::Sealed(Box::new(
                Cipher::read_key_file(&key_path, passphrase.as_deref())
                    .map_err(CliError::AtRest)?,
            )),
        )
        .map_err(CliError::Ledger)?;
        for entry in plain.entries() {
            sealed
                .append(&entry.kind, entry.payload.clone(), &entry.ts)
                .map_err(CliError::Ledger)?;
        }
    }

    // Read it back before anything is moved. An encryption step that cannot be
    // reversed is one that has to be proved right before it is trusted.
    let check = Ledger::open_with(&sealed_path, Codec::Sealed(Box::new(cipher)))
        .map_err(CliError::Ledger)?;
    if check.entries() != plain.entries() || check.root() != plain.root() {
        let _ = fs::remove_file(&sealed_path);
        return Err(CliError::Refused(String::from(
            "the sealed copy does not re-derive the original; nothing was changed",
        )));
    }

    let backup = format!("{}.plaintext.bak", options.log);
    fs::rename(&options.log, &backup).map_err(|source| CliError::Io {
        context: format!("moving {} aside", options.log),
        source,
    })?;
    fs::rename(&sealed_path, &options.log).map_err(|source| CliError::Io {
        context: format!("installing {}", options.log),
        source,
    })?;

    say(
        out,
        format!(
            "sealed {} entries; root unchanged at {}",
            check.len(),
            check.root().unwrap_or_default()
        ),
    );
    say(out, "");
    say(
        out,
        format!("The PLAINTEXT original is still on disk at {backup}"),
    );
    say(
        out,
        "Delete it yourself once you have confirmed the sealed log reads back.",
    );
    say(
        out,
        "It is left in place because this command must not be able to",
    );
    say(out, "destroy your only copy.");
    Ok(0)
}

fn cmd_sync(
    out: &mut dyn Write,
    options: &Options,
    destination: &str,
    mirror_options: mirror::Options,
) -> Result<i32, CliError> {
    let store = options.store();
    let report =
        mirror::mirror(&store, Path::new(destination), mirror_options).map_err(CliError::Store)?;
    if mirror_options.dry_run {
        say(out, "dry run -- nothing was written");
    }
    for path in &report.copied {
        say(out, format!("copied {}", path.display()));
    }
    for path in &report.pruned {
        say(out, format!("pruned {}", path.display()));
    }
    for line in report.summary().lines() {
        say(out, line);
    }
    Ok(0)
}

fn cmd_log(out: &mut dyn Write, options: &Options) -> Result<i32, CliError> {
    let node = open_node(options)?;
    for entry in ledger_of(&node).entries() {
        say(
            out,
            format!(
                "{:>4}  {:<11} {}  {}",
                entry.seq,
                entry.kind,
                short(&entry.hash),
                summarize(&entry.kind, &entry.payload)
            ),
        );
    }
    Ok(0)
}

/// Inspect and maintain the content-addressed store of pinned verifier code.
///
/// Exit code 0 throughout, including for `need` with unmet pins. Missing code is
/// `Unavailable` — this node cannot check something — and reporting it as a
/// failure would make a script treat "I have not fetched the checker yet" as "the
/// log is wrong". `audit` is where a log that does not re-derive is an error.
fn cmd_blob(out: &mut dyn Write, options: &Options, action: BlobAction) -> Result<i32, CliError> {
    let node = open_node(options)?;
    let store = node.registry().blobs();
    match action {
        BlobAction::List => {
            let held = store.addresses();
            say(
                out,
                format!("{} blob(s) in {}", held.len(), store.dir().display()),
            );
            let pinned = node.pinned_code();
            for address in held {
                // Whether anything in *this* log still wants it, which is what
                // `gc` would act on.
                let mark = if pinned.contains(&address) {
                    "pinned"
                } else {
                    "unreferenced"
                };
                say(out, format!("  {} {mark}", short_address(&address)));
            }
        }
        BlobAction::Need => {
            let needs = node.missing_code();
            if needs.is_empty() {
                say(
                    out,
                    "every pinned verifier in this log is available locally",
                );
            } else {
                say(
                    out,
                    format!(
                        "{} pin(s) unavailable; verdicts against them will be \
                             'unavailable' until a peer serves them",
                        needs.len()
                    ),
                );
                for address in &needs {
                    say(out, format!("  {}", short_address(address)));
                }
            }
        }
        BlobAction::Publish => {
            let published = node.publish_local_code();
            say(
                out,
                format!(
                    "{published} pinned blob(s) servable from {}",
                    store.dir().display()
                ),
            );
        }
        BlobAction::Collect => {
            let dropped = store.retain(&node.pinned_code());
            say(out, format!("dropped {dropped} unreferenced blob(s)"));
        }
    }
    Ok(0)
}

/// A content address abbreviated the way [`short`] abbreviates a record hash, so
/// the two read alike in a terminal. Full addresses are 64 characters and the
/// prefix identifies a blob among the handful a node holds.
fn short_address(address: &str) -> String {
    match address.get(..12) {
        Some(head) => format!("{head}…"),
        None => address.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Reading the log
// ---------------------------------------------------------------------------

/// Every claim in the log, keyed by claim id -- the map attribution walks.
///
/// A payload that will not decode is an error rather than a skipped row.
/// Dropping a claim silently would change who gets paid, and a payout table that
/// is quietly wrong is worse than one that refuses to print.
fn claim_index(ledger: &Ledger) -> Result<BTreeMap<String, Claim>, CliError> {
    let mut claims: BTreeMap<String, Claim> = BTreeMap::new();
    for entry in ledger.entries_of_kind("claim") {
        let claim = Claim::from_value(&entry.payload).map_err(|error| CliError::LogPayload {
            seq: entry.seq,
            reason: error.to_string(),
        })?;
        claims.insert(claim.id(), claim);
    }
    Ok(claims)
}

/// `(claim_id, reward)` for every settlement, in log order.
///
/// A reward that is negative or larger than `u64` is refused rather than
/// truncated: Python wrote this log with unbounded integers, and a settlement
/// this build cannot represent must be reported, not rounded into one it can.
fn settlements_of(ledger: &Ledger) -> Result<Vec<(String, u64)>, CliError> {
    let mut out: Vec<(String, u64)> = Vec::new();
    for entry in ledger.entries_of_kind("settlement") {
        let bad = |reason: &str| CliError::LogPayload {
            seq: entry.seq,
            reason: reason.to_string(),
        };
        let claim_id = entry
            .payload
            .get("claim_id")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("settlement has no claim_id"))?;
        let reward = entry
            .payload
            .get("reward")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("settlement reward is not a representable unit count"))?;
        out.push((claim_id.to_string(), reward));
    }
    Ok(out)
}

/// One-line summary of a log entry, by kind.
///
/// Total on purpose: an unreadable payload yields a blank summary rather than an
/// error. `log` is the command you reach for *because* something is wrong with
/// the log, so it must never be the command that refuses to run.
fn summarize(kind: &str, payload: &Value) -> String {
    let text = |key: &str| payload.get(key).and_then(Value::as_str).unwrap_or("");
    match kind {
        "objective" => truncate_chars(text("statement"), STATEMENT_WIDTH),
        "claim" | "commitment" => format!("by {}", text("submitter")),
        "verdict" => {
            let verdict = payload.get("verdict");
            let status = verdict
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("?");
            let detail = verdict
                .and_then(|value| value.get("detail"))
                .and_then(Value::as_str)
                .unwrap_or("");
            format!("{status}: {}", truncate_chars(detail, DETAIL_WIDTH))
        }
        "settlement" => {
            let reward = payload
                .get("reward")
                .and_then(Value::as_i128)
                .map(|units| units.to_string())
                .unwrap_or_else(|| String::from("?"));
            format!("{} <- {reward}", text("submitter"))
        }
        "batch" => {
            let epoch = payload
                .get("epoch")
                .and_then(Value::as_i128)
                .map(|epoch| epoch.to_string())
                .unwrap_or_else(|| String::from("?"));
            let claims = match payload.get("claims") {
                Some(Value::Array(items)) => items.len(),
                _ => 0,
            };
            format!("epoch {epoch}: {claims} claim(s)")
        }
        _ => String::new(),
    }
}

/// First `limit` **characters**, mirroring Python's `str` slicing.
///
/// Byte slicing would panic on a multi-byte boundary, which a statement in any
/// language but English can supply.
fn truncate_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

// ---------------------------------------------------------------------------
// Attribution table
// ---------------------------------------------------------------------------

/// Render the payout table as lines.
///
/// Split out from the command so the arithmetic and the column widths can be
/// tested without a log on disk.
fn render_attribution(
    params: &FlowParams,
    payouts: &BTreeMap<String, u64>,
) -> Result<Vec<String>, CliError> {
    let mut lines: Vec<String> = Vec::new();
    if payouts.is_empty() {
        lines.push(String::from("no settlements yet"));
        return Ok(lines);
    }

    let total = total_units(payouts)?;
    // Character count, not byte length: a submitter name with an accent in it
    // must not shift the column. Rust pads `{:<width$}` by characters too, so
    // the two agree.
    let width = payouts
        .keys()
        .map(|who| who.chars().count())
        .max()
        .unwrap_or(0);

    lines.push(format!(
        "delta {}/{}  max_depth {}",
        params.delta_num(),
        params.delta_den(),
        params.max_depth()
    ));
    lines.push(String::new());

    // Largest payout first. Ties break on name, which the reference
    // implementation leaves to dict insertion order -- a detail no second
    // implementation could reproduce. Sorting the tie makes the table
    // deterministic across implementations, which is the property that matters
    // for output anyone is meant to re-derive.
    let mut rows: Vec<(&String, u64)> = payouts.iter().map(|(who, units)| (who, *units)).collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));

    for (who, units) in rows {
        lines.push(format!(
            "  {:<width$}  {:>10}  {:>5.1}%",
            who,
            units,
            percent(units, total),
            width = width
        ));
    }
    lines.push(format!(
        "  {:<width$}  {}",
        "",
        "-".repeat(10),
        width = width
    ));
    lines.push(format!(
        "  {:<width$}  {:>10}",
        "total",
        total,
        width = width
    ));
    Ok(lines)
}

/// Sum the payouts in `u128`.
///
/// This is the overflow the Python port never had to think about. Each payout
/// fits in `u64` because the ledger's unit of account does, but their *sum* is
/// bounded by nothing: a long-lived log with large pools reaches `u64::MAX`
/// honestly. Widening to `u128` makes the total exact, and the addition is still
/// checked, because a wrapped total would understate what the network paid --
/// which is the one number an auditor is here to read.
fn total_units(payouts: &BTreeMap<String, u64>) -> Result<u128, CliError> {
    let mut total: u128 = 0;
    for units in payouts.values() {
        total = total
            .checked_add(u128::from(*units))
            .ok_or_else(|| CliError::Overflow(String::from("attribution total")))?;
    }
    Ok(total)
}

/// Share of the total, as a percentage for display only.
///
/// The float appears exactly here, on the way to a terminal, and never enters a
/// record: [`Value`] has no float variant, so it could not if it tried. A zero
/// total pays nobody, and reporting `0.0` beats the `NaN` that dividing by it
/// would otherwise print.
fn percent(units: u64, total: u128) -> f64 {
    if total == 0 {
        return 0.0;
    }
    100.0 * (units as f64) / (total as f64)
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

/// 16 bytes of operating-system entropy, hex encoded.
///
/// The equivalent of `secrets.token_hex(16)`. The nonce is what stops a
/// guessable artifact -- `{"n": 27}` -- from being brute-forced out of a
/// published commitment before it is revealed, so a *predictable* nonce silently
/// removes the hiding property while leaving every command it appears in looking
/// like it worked.
///
/// That is why there is no fallback. If the kernel entropy source cannot be
/// read, this refuses and tells the user to pass `--nonce`, rather than deriving
/// something clock-shaped that would be guessable by anyone who knows roughly
/// when the commitment was made.
fn random_nonce() -> Result<String, CliError> {
    const SOURCE: &str = "/dev/urandom";
    let complain = |error: io::Error| {
        CliError::Entropy(format!(
            "no entropy for a nonce ({SOURCE}: {error}); pass --nonce explicitly"
        ))
    };
    let mut source = File::open(SOURCE).map_err(complain)?;
    let mut bytes = [0u8; NONCE_BYTES];
    source.read_exact(&mut bytes).map_err(complain)?;
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn run(argv: Vec<String>, out: &mut dyn Write) -> Result<i32, CliError> {
    let invocation = parse(argv)?;
    let options = &invocation.options;
    match &invocation.command {
        Command::Help => {
            print_help(out);
            Ok(0)
        }
        Command::Post { objective } => cmd_post(out, options, objective),
        Command::Commit {
            objective_id,
            submitter,
            artifact,
            nonce,
        } => cmd_commit(
            out,
            options,
            objective_id,
            submitter,
            artifact,
            nonce.as_deref(),
        ),
        Command::Reveal {
            objective_id,
            submitter,
            artifact,
            nonce,
            cites,
        } => cmd_reveal(
            out,
            options,
            objective_id,
            submitter,
            artifact,
            nonce,
            cites,
        ),
        Command::Settle => cmd_settle(out, options),
        Command::Audit { rerun } => cmd_audit(out, options, *rerun),
        Command::Verify {
            checkpoint,
            root_key,
            audit,
            rerun,
        } => cmd_verify(
            out,
            options,
            checkpoint,
            root_key.as_deref(),
            *audit,
            *rerun,
        ),
        Command::Attribute { params } => cmd_attribute(out, options, params),
        Command::Blob { action } => cmd_blob(out, options, *action),
        Command::Incentives { params, robustness } => cmd_incentives(out, params, *robustness),
        Command::Keygen { wrap } => cmd_keygen(out, options, *wrap),
        Command::Store { action } => cmd_store(out, options, *action),
        Command::Sync {
            destination,
            options: mirror_options,
        } => cmd_sync(out, options, destination, *mirror_options),
        Command::Log => cmd_log(out, options),
    }
}

/// Collect arguments without the panic [`std::env::args`] raises on an argument
/// that is not valid UTF-8.
fn arguments() -> Result<Vec<String>, CliError> {
    let mut argv: Vec<String> = Vec::new();
    for (position, raw) in env::args_os().enumerate() {
        if position == 0 {
            continue;
        }
        match raw.into_string() {
            Ok(argument) => argv.push(argument),
            Err(_) => return Err(CliError::NotUnicode(position)),
        }
    }
    Ok(argv)
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let code = match arguments().and_then(|argv| run(argv, &mut out)) {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(io::stderr(), "{}", error.report());
            error.code()
        }
    };

    // `process::exit` runs no destructors, so the buffered output is flushed
    // here rather than left to one.
    let _ = out.flush();
    process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn payouts(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(who, units)| ((*who).to_string(), *units))
            .collect()
    }

    // -- argument parsing --------------------------------------------------

    #[test]
    fn global_options_precede_the_command() {
        let parsed =
            parse(argv(&["--log", "/tmp/x.jsonl", "--root", "/srv", "log"])).expect("this parses");
        assert_eq!(parsed.options.log, "/tmp/x.jsonl");
        assert_eq!(parsed.options.root, "/srv");
        assert_eq!(parsed.command, Command::Log);
    }

    #[test]
    fn inline_values_are_accepted() {
        let parsed = parse(argv(&["--log=/tmp/y.jsonl", "log"])).expect("this parses");
        assert_eq!(parsed.options.log, "/tmp/y.jsonl");
    }

    #[test]
    fn a_positional_containing_an_equals_sign_is_untouched() {
        let expanded = expand_inline_values(argv(&["post", "a=b.json"]));
        assert_eq!(expanded, argv(&["post", "a=b.json"]));
    }

    #[test]
    fn a_flag_may_not_swallow_the_next_flag_as_its_value() {
        let error = parse(argv(&[
            "commit",
            "OID",
            "--submitter",
            "--artifact",
            "a.json",
        ]))
        .expect_err("a missing value is a usage error");
        assert!(matches!(error, CliError::Usage(_)), "got {error:?}");
    }

    #[test]
    fn an_empty_nonce_asks_for_a_generated_one() {
        let parsed = parse(argv(&[
            "commit",
            "OID",
            "--submitter",
            "alice",
            "--artifact",
            "a.json",
            "--nonce",
            "",
        ]))
        .expect("this parses");
        match parsed.command {
            Command::Commit { nonce, .. } => assert_eq!(nonce, None),
            other => panic!("expected commit, got {other:?}"),
        }
    }

    #[test]
    fn cites_consumes_until_the_next_flag() {
        let parsed = parse(argv(&[
            "reveal",
            "OID",
            "--cites",
            "a",
            "b",
            "c",
            "--submitter",
            "alice",
            "--artifact",
            "a.json",
            "--nonce",
            "n1",
        ]))
        .expect("this parses");
        match parsed.command {
            Command::Reveal {
                cites,
                objective_id,
                ..
            } => {
                assert_eq!(cites, argv(&["a", "b", "c"]));
                assert_eq!(objective_id, "OID");
            }
            other => panic!("expected reveal, got {other:?}"),
        }
    }

    #[test]
    fn cites_may_be_empty() {
        let parsed = parse(argv(&[
            "reveal",
            "OID",
            "--submitter",
            "a",
            "--artifact",
            "f",
            "--nonce",
            "n",
            "--cites",
        ]))
        .expect("this parses");
        match parsed.command {
            Command::Reveal { cites, .. } => assert!(cites.is_empty()),
            other => panic!("expected reveal, got {other:?}"),
        }
    }

    #[test]
    fn a_reveal_without_a_nonce_is_refused() {
        let error = parse(argv(&[
            "reveal",
            "OID",
            "--submitter",
            "a",
            "--artifact",
            "f",
        ]))
        .expect_err("there is nothing to generate on reveal");
        assert!(matches!(error, CliError::Usage(_)), "got {error:?}");
    }

    #[test]
    fn audit_defaults_to_rerunning_verifiers() {
        assert_eq!(
            parse(argv(&["audit"])).expect("parses").command,
            Command::Audit { rerun: true }
        );
        assert_eq!(
            parse(argv(&["audit", "--no-rerun"]))
                .expect("parses")
                .command,
            Command::Audit { rerun: false }
        );
    }

    #[test]
    fn attribute_defaults_match_flow_params() {
        let parsed = parse(argv(&["attribute"])).expect("parses");
        assert_eq!(
            parsed.command,
            Command::Attribute {
                params: FlowParams::default()
            }
        );
    }

    #[test]
    fn incentives_defaults_to_the_reference_network() {
        let parsed = parse(argv(&["incentives"])).expect("parses");
        assert_eq!(
            parsed.command,
            Command::Incentives {
                params: Box::new(NodeParams::reference()),
                robustness: false,
            }
        );
        // Opt-in, because a margin table is hundreds of full solver runs.
        assert_eq!(
            parse(argv(&["incentives", "--robustness"]))
                .expect("parses")
                .command,
            Command::Incentives {
                params: Box::new(NodeParams::reference()),
                robustness: true,
            }
        );
    }

    #[test]
    fn incentives_overrides_one_field_and_inherits_the_rest() {
        // The property that makes the command usable: an analyst changes the
        // number they care about without restating twenty others, and does not
        // silently get a different network for the ones they left out.
        let parsed =
            parse(argv(&["incentives", "--canary-rate", "0", "--nodes", "40"])).expect("parses");
        match parsed.command {
            Command::Incentives { params, .. } => {
                assert_eq!(params.canary_rate, Rat::ZERO);
                assert_eq!(params.nodes, 40);
                assert_eq!(params.stake, NodeParams::reference().stake);
                assert_eq!(params.fee, NodeParams::reference().fee);
            }
            other => panic!("expected an incentives command, got {other:?}"),
        }
    }

    #[test]
    fn rates_are_exact_fractions_and_decimals_are_refused() {
        // Accepting "0.01" would mean parsing a float and throwing it away at
        // the first threshold comparison, which is the one thing the harness
        // exists to avoid.
        assert_eq!(
            parse_rate("1/100", "--canary-rate").expect("parses"),
            Rat::rate(1, 100).expect("a valid rate")
        );
        assert_eq!(parse_rate("0", "--fee").expect("parses"), Rat::ZERO);
        assert_eq!(parse_rate("1", "--fee").expect("parses"), Rat::ONE);
        assert!(parse_rate("0.01", "--fee").is_err());
        assert!(parse_rate("3/2", "--fee").is_err(), "above one");
        assert!(parse_rate("1/0", "--fee").is_err(), "no answer");
        assert!(parse_rate("-1/2", "--fee").is_err());
        assert!(parse_rate("", "--fee").is_err());
    }

    #[test]
    fn an_impossible_committee_is_refused_before_any_report_is_printed() {
        let error = parse(argv(&["incentives", "--threshold", "99"]))
            .expect_err("a threshold above the committee is not a t-of-n");
        assert!(matches!(error, CliError::Params(_)), "got {error:?}");
        // Cross-field, too: shrinking the network below the committee it
        // inherited is caught here rather than deep inside a payoff function.
        let error = parse(argv(&["incentives", "--nodes", "7"]))
            .expect_err("a committee cannot be larger than the network");
        assert!(matches!(error, CliError::Params(_)), "got {error:?}");
    }

    #[test]
    fn parse_u64_rejects_negatives_and_junk() {
        assert!(parse_u64("-1", "--delta-num").is_err());
        assert!(parse_u64("1.5", "--delta-num").is_err());
        assert!(parse_u64("", "--delta-num").is_err());
        assert_eq!(parse_u64("4", "--delta-den").expect("4 parses"), 4);
        assert!(parse_u32("-1", "--max-depth").is_err());
        assert_eq!(parse_u32("6", "--max-depth").expect("6 parses"), 6);
    }

    #[test]
    fn a_delta_above_one_is_refused_before_any_payout_is_printed() {
        let error = parse(argv(&["attribute", "--delta-num", "5", "--delta-den", "4"]))
            .expect_err("delta must lie in [0, 1]");
        assert!(matches!(error, CliError::Flow(_)), "got {error:?}");
    }

    #[test]
    fn a_zero_denominator_is_refused() {
        let error = parse(argv(&["attribute", "--delta-den", "0"]))
            .expect_err("a zero denominator has no answer");
        assert!(matches!(error, CliError::Flow(_)), "got {error:?}");
    }

    #[test]
    fn unknown_commands_and_empty_lines_are_usage_errors() {
        assert!(matches!(
            parse(argv(&[])).expect_err("no command"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["conjure"])).expect_err("no such command"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["settle", "extra"])).expect_err("settle takes no arguments"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["log", "extra"])).expect_err("log takes no arguments"),
            CliError::Usage(_)
        ));
    }

    #[test]
    fn help_is_reachable_three_ways() {
        for spelling in [vec!["help"], vec!["--help"], vec!["-h"]] {
            let parsed = parse(argv(&spelling)).expect("parses");
            assert_eq!(parsed.command, Command::Help, "for {spelling:?}");
        }
    }

    #[test]
    fn a_bare_dash_is_a_value_not_a_flag() {
        assert!(!is_flag("-"));
        assert!(is_flag("-h"));
        assert!(is_flag("--log"));
        assert!(!is_flag("sha256:abc"));
        assert!(!is_flag(""));
    }

    // -- arithmetic --------------------------------------------------------

    #[test]
    fn totals_are_summed_in_u128_and_do_not_wrap() {
        let table = payouts(&[("alice", u64::MAX), ("bob", u64::MAX)]);
        let total = total_units(&table).expect("u128 holds two u64 maxima");
        assert_eq!(total, u128::from(u64::MAX) * 2);
        // The point of the widening: this is the number a u64 sum would have
        // reported instead.
        assert_ne!(total, u128::from(u64::MAX.wrapping_add(u64::MAX)));
    }

    #[test]
    fn a_zero_total_prints_zero_rather_than_nan() {
        let value = percent(0, 0);
        assert!(value.is_finite());
        assert_eq!(value, 0.0);
    }

    #[test]
    fn percentages_are_shares_of_the_total() {
        assert_eq!(percent(1, 4), 25.0);
        assert_eq!(percent(3, 4), 75.0);
    }

    #[test]
    fn an_all_zero_payout_table_still_renders() {
        // Reachable: `flow` credits a submitter zero units when the claim passes
        // everything upstream, and a settlement of zero pays nobody anything.
        let table = payouts(&[("alice", 0), ("bob", 0)]);
        let lines = render_attribution(&FlowParams::default(), &table).expect("renders");
        assert!(lines.iter().any(|line| line.contains("0.0%")));
        assert!(lines.iter().any(|line| line.contains("total")));
    }

    // -- table rendering ---------------------------------------------------

    #[test]
    fn an_empty_table_says_so() {
        let lines = render_attribution(&FlowParams::default(), &BTreeMap::new()).expect("renders");
        assert_eq!(lines, vec![String::from("no settlements yet")]);
    }

    #[test]
    fn rows_are_ordered_by_units_then_name() {
        let table = payouts(&[("carol", 10), ("alice", 30), ("bob", 10)]);
        let lines = render_attribution(&FlowParams::default(), &table).expect("renders");
        let names: Vec<&str> = lines
            .iter()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|word| ["alice", "bob", "carol"].contains(word))
            .collect();
        assert_eq!(names, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn the_total_row_agrees_with_the_rows_above_it() {
        let table = payouts(&[("alice", 750), ("bob", 250)]);
        let lines = render_attribution(&FlowParams::default(), &table).expect("renders");
        let last = lines.last().expect("a total row");
        assert!(last.contains("total"), "got {last:?}");
        assert!(last.contains("1000"), "got {last:?}");
        assert!(lines.iter().any(|line| line.contains("75.0%")));
        assert!(lines.iter().any(|line| line.contains("25.0%")));
    }

    #[test]
    fn the_header_reports_the_parameters_in_force() {
        let params = FlowParams::new(1, 3, 2).expect("1/3 is a valid delta");
        let lines = render_attribution(&params, &payouts(&[("alice", 1)])).expect("renders");
        assert_eq!(
            lines.first().map(String::as_str),
            Some("delta 1/3  max_depth 2")
        );
    }

    #[test]
    fn columns_are_padded_by_characters_not_bytes() {
        let table = payouts(&[("zoé", 1), ("al", 1)]);
        let lines = render_attribution(&FlowParams::default(), &table).expect("renders");
        let rows: Vec<&String> = lines.iter().filter(|line| line.contains('%')).collect();
        assert_eq!(rows.len(), 2);
        // Same character count on both rows, even though "zoé" is four bytes.
        let widths: Vec<usize> = rows.iter().map(|line| line.chars().count()).collect();
        assert_eq!(widths.first(), widths.last(), "rows: {rows:?}");
    }

    // -- log summaries -----------------------------------------------------

    #[test]
    fn summaries_never_panic_on_a_malformed_payload() {
        let empty = Value::Object(BTreeMap::new());
        for kind in [
            "objective",
            "claim",
            "commitment",
            "verdict",
            "settlement",
            "frontier",
            "nonsense",
        ] {
            let _ = summarize(kind, &empty);
        }
        // Not even an object.
        assert_eq!(summarize("objective", &Value::Null), "");
        assert_eq!(summarize("settlement", &Value::Int(7)), " <- ?");
    }

    #[test]
    fn summaries_read_the_fields_the_reference_implementation_reads() {
        let objective = proofwork::obj! { "statement" => Value::string("Exhibit a cap set") };
        assert_eq!(summarize("objective", &objective), "Exhibit a cap set");

        let claim = proofwork::obj! { "submitter" => Value::string("alice") };
        assert_eq!(summarize("claim", &claim), "by alice");
        assert_eq!(summarize("commitment", &claim), "by alice");

        let verdict = proofwork::obj! {
            "verdict" => proofwork::obj! {
                "status" => Value::string("accept"),
                "detail" => Value::string("certificate checks out"),
            },
        };
        assert_eq!(
            summarize("verdict", &verdict),
            "accept: certificate checks out"
        );

        let settlement = proofwork::obj! {
            "submitter" => Value::string("bob"),
            "reward" => Value::Int(250_000),
        };
        assert_eq!(summarize("settlement", &settlement), "bob <- 250000");
    }

    #[test]
    fn truncation_counts_characters_and_cannot_split_one() {
        let statement = "é".repeat(80);
        let cut = truncate_chars(&statement, STATEMENT_WIDTH);
        assert_eq!(cut.chars().count(), STATEMENT_WIDTH);
        // Byte slicing at 60 would have landed mid-character and panicked.
        assert_eq!(cut.len(), STATEMENT_WIDTH * 2);
        assert_eq!(truncate_chars("short", STATEMENT_WIDTH), "short");
    }

    #[test]
    fn a_long_verdict_detail_is_cut_to_forty_characters() {
        let verdict = proofwork::obj! {
            "verdict" => proofwork::obj! {
                "status" => Value::string("reject"),
                "detail" => Value::string("x".repeat(100)),
            },
        };
        assert_eq!(
            summarize("verdict", &verdict),
            format!("reject: {}", "x".repeat(DETAIL_WIDTH))
        );
    }

    // -- nonces ------------------------------------------------------------

    #[test]
    fn hex_encoding_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn a_generated_nonce_is_thirty_two_hex_characters() {
        // `secrets.token_hex(16)` produces exactly this shape.
        match random_nonce() {
            Ok(nonce) => {
                assert_eq!(nonce.chars().count(), NONCE_BYTES * 2);
                assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
            }
            // A machine with no /dev/urandom must say so rather than invent
            // entropy; that refusal is the tested behaviour too.
            Err(error) => assert!(matches!(error, CliError::Entropy(_)), "got {error:?}"),
        }
    }

    #[test]
    fn two_generated_nonces_differ() {
        if let (Ok(first), Ok(second)) = (random_nonce(), random_nonce()) {
            assert_ne!(first, second, "a nonce that repeats is not a nonce");
        }
    }

    // -- error reporting ---------------------------------------------------

    #[test]
    fn rule_violations_are_reported_as_refusals() {
        let error = CliError::Refused(String::from("objective is already settled"));
        assert_eq!(error.report(), "refused: objective is already settled");
        assert_eq!(error.code(), 2);
    }

    #[test]
    fn other_failures_are_reported_as_errors() {
        let error = CliError::LogPayload {
            seq: 4,
            reason: String::from("settlement has no claim_id"),
        };
        assert_eq!(
            error.report(),
            "error: log entry 4: settlement has no claim_id"
        );
    }
}
