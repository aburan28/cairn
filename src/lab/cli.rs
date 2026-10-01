//! `cairn lab …`: the lab from a shell.
//!
//! Hand-parsed for the reason the rest of the binary is (see `src/main.rs`):
//! no `clap`, typed errors instead of a parser that calls `exit()`. Every
//! command reads `--lab DIR` (or `$CAIRN_LAB`, or `./.cairn-lab`), and every
//! command that writes needs `--identity FILE` (or `$CAIRN_LAB_IDENTITY`) —
//! the ed25519 key ops are signed with, in the same file shape `cairn identity
//! --out` writes.
//!
//! Exit codes follow the verifier taxonomy: `0` done, `1` a check found
//! problems or a command it ran failed, `2` bad usage or the rules refused,
//! `3` nothing was learned — the sandbox could not run the command, which is a
//! fact about this host and not about the command.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::api::{self, ExecRequest, Expect, Input};
use super::env::{self, ImportOptions, Source};
use super::exec::{self, Preference};
use super::op::{self, Body, EntryRef, Member, Outcome, Policy, Role};
use super::state::{Conflict, State};
use super::store::Lab;
use super::sync::{self, Access, RemotePeer};
use super::tree::{self, Filter};
use super::{LabError, DEFAULT_DIR, LAB_ENV};
use crate::canonical::Value;
use crate::crypto::identity::Identity;
use crate::p2p::handshake::{peer_id_hex, PeerIdentity};

/// Environment variable naming the signing identity file.
pub const IDENTITY_ENV: &str = "CAIRN_LAB_IDENTITY";

const USAGE: &str = "\
cairn lab — a replicated research workspace (signed ops, CRDT merge, sandboxed runs)

USAGE
    cairn lab [--lab DIR] <command> [options]

SPACE
    init --name NAME --identity FILE [--policy FILE] [--member KEY:ROLES[:PEER,...]]...
    clone --space ID (--dir PATH | --peer ID@HOST:PORT --peer-identity FILE | --bundle FILE)
    status [--json]                 space, ops, heads, members, conflicts, exclusions
    log [--limit N]                 ops in (lamport, id) order
    verify                          re-check every signature and blob hash
    members                         who may do what
    admit KEY --roles writer[,admin,reader] [--peer PEERID]... --identity FILE
    revoke KEY --identity FILE
    policy [--json] | policy set FILE --identity FILE
    identity --out FILE             a new ed25519 signing identity

FILES
    ls [PREFIX] [--json]            live files under PREFIX
    cat PATH                        the bytes a checkout writes for PATH
    put PATH (--file F | --text T) --identity FILE [--create] [--exec]
    rm PATH --identity FILE
    conflicts [--json]              registers with more than one value
    resolve PATH (--file F | --pick OP#N) --identity FILE
    checkout DIR [--include GLOB]... [--exclude GLOB]... [--force]
    commit DIR --identity FILE [--include GLOB]... [--exclude GLOB]...
    changes DIR [--include GLOB]... [--exclude GLOB]...

DOCS, LEASES, MESSAGES
    doc DOC [--json]                fields of a doc
    doc set DOC KEY JSON --identity FILE
    claim TASK --holder ADDR --ttl SECONDS --identity FILE [--note TEXT]
    release CLAIM-ID --outcome completed|failed|abandoned --identity FILE [--note TEXT]
    tasks [--json]                  every task's leases, evaluated now
    send --to ADDR[,ADDR] --subject S --body B --identity FILE [--from ADDR] [--ref X]...
    inbox ADDR [--json]
    ack MSG-ID --as ADDR --identity FILE

ENVIRONMENTS AND RUNS
    env import NAME (--docker IMAGE | --podman IMAGE | --tar FILE | --dir DIR [--move])
               --identity FILE [--env KEY=VALUE]... [--workdir DIR] [--note TEXT]
    env ls [--json] | env show NAME | env verify NAME
    exec --env NAME --identity FILE [--input LABPATH[:TARGET]]... [--mount HOSTDIR:TARGET]...
         [--publish PREFIX] [--cwd DIR] [--setenv KEY=VALUE]... [--timeout SECONDS]
         [--memory MB] [--cpus N] [--pids N] [--network] [--sandbox auto|runsc|bwrap|none]
         [--task TASK] [--note TEXT] [--keep] [--json] -- COMMAND [ARGS]...
                                    inputs are read-only: a prefix becomes a directory at
                                    TARGET (default /in/LABPATH), a single file that file;
                                    whatever the command writes to /out is published
    runs [--limit N] [--json]       run receipts, newest first
    sandbox                         which sandbox this host can use

SYNC
    sync --dir PATH                 reconcile with another lab directory
    sync --peer ID@HOST:PORT --peer-identity FILE
    serve --listen ADDR --peer-identity FILE [--allow PEERID]... [--open]
    peer-id --peer-identity FILE    this machine's transport id (created if absent)
    bundle --out FILE [--have FILE] write ops (and their blobs) to one file
    unbundle FILE                   read a bundle

AGENTS
    mcp --identity FILE [--as ADDR] the lab as MCP tools over stdio

EXIT CODES
    0 done   1 a check failed, or the command run under `exec` failed
    2 bad usage, or the rules refused   3 the sandbox could not run the command
";

/// Entry point: `cairn lab ARGS…`. Returns the process exit code.
pub fn main(args: Vec<String>) -> i32 {
    let mut out = io::stdout().lock();
    match run(args, &mut out) {
        Ok(code) => code,
        Err(CliError::Usage(message)) => {
            eprintln!("cairn lab: {message}\n\nrun `cairn lab help` for usage");
            2
        }
        Err(CliError::Lab(error)) => {
            eprintln!("cairn lab: {error}");
            match error {
                LabError::Refused(_) | LabError::Invalid(_) | LabError::NotFound(_) => 2,
                _ => 1,
            }
        }
    }
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Lab(LabError),
}

impl From<LabError> for CliError {
    fn from(error: LabError) -> CliError {
        CliError::Lab(error)
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> CliError {
        CliError::Lab(LabError::Io(error.to_string()))
    }
}

fn usage<T>(message: impl Into<String>) -> Result<T, CliError> {
    Err(CliError::Usage(message.into()))
}

/// A cursor over arguments, with the flag helpers every command needs.
struct Args {
    items: Vec<String>,
    position: usize,
}

impl Args {
    fn next(&mut self) -> Option<String> {
        let item = self.items.get(self.position).cloned();
        if item.is_some() {
            self.position += 1;
        }
        item
    }

    fn value(&mut self, flag: &str) -> Result<String, CliError> {
        self.next()
            .ok_or_else(|| CliError::Usage(format!("{flag} needs a value")))
    }

    /// Parse the remaining arguments into flags and positionals. `--` ends
    /// flag parsing; everything after it is positional (the `exec` command).
    fn rest(&mut self, flags_with_values: &[&str]) -> Result<Parsed, CliError> {
        let mut parsed = Parsed::default();
        while let Some(item) = self.next() {
            if item == "--" {
                while let Some(rest) = self.next() {
                    parsed.trailing.push(rest);
                }
                break;
            }
            if let Some(flag) = item.strip_prefix("--") {
                if flags_with_values.contains(&flag) {
                    let value = self.value(&item)?;
                    parsed
                        .values
                        .entry(flag.to_string())
                        .or_default()
                        .push(value);
                } else {
                    parsed.switches.insert(flag.to_string());
                }
            } else {
                parsed.positional.push(item);
            }
        }
        Ok(parsed)
    }
}

#[derive(Debug, Default)]
struct Parsed {
    values: BTreeMap<String, Vec<String>>,
    switches: BTreeSet<String>,
    positional: Vec<String>,
    trailing: Vec<String>,
}

impl Parsed {
    fn one(&self, flag: &str) -> Option<&str> {
        self.values
            .get(flag)
            .and_then(|values| values.last())
            .map(String::as_str)
    }

    fn all(&self, flag: &str) -> Vec<String> {
        self.values.get(flag).cloned().unwrap_or_default()
    }

    fn need(&self, flag: &str) -> Result<&str, CliError> {
        self.one(flag)
            .ok_or_else(|| CliError::Usage(format!("--{flag} is required")))
    }

    fn has(&self, switch: &str) -> bool {
        self.switches.contains(switch)
    }

    fn reject_unknown(&self, allowed_switches: &[&str]) -> Result<(), CliError> {
        for switch in &self.switches {
            if !allowed_switches.contains(&switch.as_str()) {
                return usage(format!("unknown option --{switch}"));
            }
        }
        Ok(())
    }

    fn positional(&self, n: usize, what: &str) -> Result<&str, CliError> {
        self.positional
            .get(n)
            .map(String::as_str)
            .ok_or_else(|| CliError::Usage(format!("missing {what}")))
    }

    fn u64_flag(&self, flag: &str, default: u64) -> Result<u64, CliError> {
        match self.one(flag) {
            None => Ok(default),
            Some(text) => text
                .parse()
                .map_err(|_| CliError::Usage(format!("--{flag} must be a whole number"))),
        }
    }

    fn filter(&self) -> Filter {
        Filter {
            include: self.all("include"),
            exclude: self.all("exclude"),
        }
    }
}

fn say(out: &mut dyn io::Write, text: impl AsRef<str>) {
    // A closed pipe ends the output; it is not an error worth a panic.
    let _ = writeln!(out, "{}", text.as_ref());
}

fn lab_dir(explicit: Option<String>) -> PathBuf {
    explicit
        .map(PathBuf::from)
        .or_else(|| std::env::var_os(LAB_ENV).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}

fn run(args: Vec<String>, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let mut args = Args {
        items: args,
        position: 0,
    };
    let mut explicit_lab = None;
    let command = loop {
        match args.next() {
            None => {
                say(out, USAGE);
                return Ok(0);
            }
            Some(flag) if flag == "--lab" => explicit_lab = Some(args.value("--lab")?),
            Some(command) => break command,
        }
    };
    let dir = lab_dir(explicit_lab);
    match command.as_str() {
        "help" | "--help" | "-h" => {
            say(out, USAGE);
            Ok(0)
        }
        "init" => cmd_init(&dir, &mut args, out),
        "clone" => cmd_clone(&dir, &mut args, out),
        "status" => cmd_status(&dir, &mut args, out),
        "log" => cmd_log(&dir, &mut args, out),
        "verify" => cmd_verify(&dir, out),
        "members" => cmd_members(&dir, out),
        "admit" => cmd_admit(&dir, &mut args, out),
        "revoke" => cmd_revoke(&dir, &mut args, out),
        "policy" => cmd_policy(&dir, &mut args, out),
        "identity" => cmd_identity(&mut args, out),
        "ls" => cmd_ls(&dir, &mut args, out),
        "cat" => cmd_cat(&dir, &mut args, out),
        "put" => cmd_put(&dir, &mut args, out),
        "rm" => cmd_rm(&dir, &mut args, out),
        "conflicts" => cmd_conflicts(&dir, &mut args, out),
        "resolve" => cmd_resolve(&dir, &mut args, out),
        "checkout" => cmd_checkout(&dir, &mut args, out),
        "commit" => cmd_commit(&dir, &mut args, out),
        "changes" => cmd_changes(&dir, &mut args, out),
        "doc" => cmd_doc(&dir, &mut args, out),
        "claim" => cmd_claim(&dir, &mut args, out),
        "release" => cmd_release(&dir, &mut args, out),
        "tasks" => cmd_tasks(&dir, &mut args, out),
        "send" => cmd_send(&dir, &mut args, out),
        "inbox" => cmd_inbox(&dir, &mut args, out),
        "ack" => cmd_ack(&dir, &mut args, out),
        "env" => cmd_env(&dir, &mut args, out),
        "exec" => cmd_exec(&dir, &mut args, out),
        "runs" => cmd_runs(&dir, &mut args, out),
        "sandbox" => cmd_sandbox(out),
        "sync" => cmd_sync(&dir, &mut args, out),
        "serve" => cmd_serve(&dir, &mut args),
        "peer-id" => cmd_peer_id(&mut args, out),
        "bundle" => cmd_bundle(&dir, &mut args, out),
        "unbundle" => cmd_unbundle(&dir, &mut args, out),
        "mcp" => {
            let parsed = args.rest(&["identity", "as"])?;
            let identity = load_identity(parsed.one("identity"))?;
            let address = parsed.one("as").unwrap_or("agent").to_string();
            Ok(super::mcp::serve(&dir, identity, address))
        }
        other => usage(format!("unknown command {other:?}")),
    }
}

// -- identities ------------------------------------------------------------------

/// Load the ed25519 signing identity: `--identity`, else `$CAIRN_LAB_IDENTITY`.
fn load_identity(explicit: Option<&str>) -> Result<Identity, CliError> {
    let path = explicit
        .map(PathBuf::from)
        .or_else(|| std::env::var_os(IDENTITY_ENV).map(PathBuf::from))
        .ok_or_else(|| {
            CliError::Usage(format!(
                "a write needs --identity FILE (or ${IDENTITY_ENV}); \
                 `cairn lab identity --out FILE` makes one"
            ))
        })?;
    read_identity(&path).map_err(CliError::Lab)
}

/// Read a signing identity in the `{"secret": hex, "public": hex}` shape.
pub fn read_identity(path: &Path) -> Result<Identity, LabError> {
    let text = crate::secret_file::read_to_string(path)
        .map_err(|e| LabError::Io(format!("{}: {e}", path.display())))?;
    let value = Value::from_json(&text)
        .map_err(|e| LabError::Invalid(format!("{}: {e}", path.display())))?;
    let secret = value
        .get("secret")
        .and_then(Value::as_str)
        .and_then(crate::hex::decode)
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| {
            LabError::Invalid(format!(
                "{}: needs a 32-byte hex \"secret\"",
                path.display()
            ))
        })?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&secret);
    let identity = Identity::from_secret_bytes(bytes);
    if let Some(public) = value.get("public").and_then(Value::as_str) {
        if public != identity.submitter_id() {
            return Err(LabError::Invalid(format!(
                "{}: \"public\" does not match \"secret\"",
                path.display()
            )));
        }
    }
    Ok(identity)
}

fn cmd_identity(args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["out"])?;
    let path = PathBuf::from(parsed.need("out")?);
    let identity = Identity::generate(&mut rand_core::OsRng);
    let value = Value::object([
        (
            "secret",
            Value::string(crate::hex::encode(&*identity.to_secret_bytes())),
        ),
        ("public", Value::string(identity.submitter_id())),
    ]);
    crate::secret_file::write_new(&path, value.canonical_string().as_bytes())
        .map_err(|e| LabError::Io(format!("{}: {e}", path.display())))?;
    say(out, format!("identity written to {}", path.display()));
    say(out, format!("  key {}", identity.submitter_id()));
    Ok(0)
}

/// Load or create the transport identity (Classic McEliece), in the shape
/// `cairn p2p --identity` uses.
fn load_peer_identity(path: &Path) -> Result<PeerIdentity, LabError> {
    if !path.exists() {
        let identity = PeerIdentity::generate();
        let value = Value::object([
            (
                "public",
                Value::string(crate::hex::encode(identity.public_key())),
            ),
            (
                "secret",
                Value::string(crate::hex::encode(identity.secret_key())),
            ),
        ]);
        crate::secret_file::write_new(path, value.canonical_string().as_bytes())
            .map_err(|e| LabError::Io(format!("{}: {e}", path.display())))?;
        return Ok(identity);
    }
    let text = crate::secret_file::read_to_string(path)
        .map_err(|e| LabError::Io(format!("{}: {e}", path.display())))?;
    let value = Value::from_json(&text)
        .map_err(|e| LabError::Invalid(format!("{}: {e}", path.display())))?;
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .and_then(crate::hex::decode)
            .ok_or_else(|| LabError::Invalid(format!("{}: needs hex {name}", path.display())))
    };
    PeerIdentity::from_bytes(&field("public")?, &field("secret")?)
        .map_err(|e| LabError::Invalid(format!("{}: {e}", path.display())))
}

fn cmd_peer_id(args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["peer-identity"])?;
    let identity = load_peer_identity(Path::new(parsed.need("peer-identity")?))?;
    say(out, peer_id_hex(&identity.id()));
    Ok(0)
}

// -- space ------------------------------------------------------------------------

fn parse_member(spec: &str) -> Result<Member, CliError> {
    let mut parts = spec.splitn(3, ':');
    let key = op::key_hex(parts.next().unwrap_or("")).map_err(|e| CliError::Usage(e.0))?;
    let roles = parse_roles(parts.next().unwrap_or("writer"))?;
    let peers = match parts.next() {
        Some(list) if !list.is_empty() => list
            .split(',')
            .map(|p| op::key_hex(p).map_err(|e| CliError::Usage(e.0)))
            .collect::<Result<BTreeSet<_>, _>>()?,
        _ => BTreeSet::new(),
    };
    Ok(Member { key, roles, peers })
}

fn parse_roles(text: &str) -> Result<BTreeSet<Role>, CliError> {
    text.split(',')
        .map(|role| Role::parse(role.trim()).map_err(|e| CliError::Usage(e.0)))
        .collect()
}

fn read_policy(path: &str) -> Result<Policy, CliError> {
    let text = fs::read_to_string(path).map_err(|e| LabError::Io(format!("{path}: {e}")))?;
    let value = Value::from_json(&text).map_err(|e| LabError::Invalid(format!("{path}: {e}")))?;
    Ok(Policy::from_value(&value).map_err(LabError::from)?)
}

fn cmd_init(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["name", "identity", "policy", "member"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let name = parsed.need("name")?;
    let policy = match parsed.one("policy") {
        Some(path) => read_policy(path)?,
        None => Policy::default(),
    };
    let members = parsed
        .all("member")
        .iter()
        .map(|spec| parse_member(spec))
        .collect::<Result<Vec<_>, _>>()?;
    let lab = Lab::init(dir, &identity, name, members, policy)?;
    say(
        out,
        format!("space {} created at {}", lab.space(), dir.display()),
    );
    say(out, format!("  name {name}"));
    say(out, format!("  admin {}", identity.submitter_id()));
    Ok(0)
}

fn cmd_clone(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["space", "dir", "peer", "peer-identity", "bundle"])?;
    let space = parsed.need("space")?;
    Lab::create_empty(dir, space)?;
    let mut lab = Lab::open(dir)?;
    let report = if let Some(path) = parsed.one("bundle") {
        let mut file = fs::File::open(path).map_err(|e| LabError::Io(format!("{path}: {e}")))?;
        sync::read_bundle(&mut lab, &mut file)?
    } else {
        sync_with(&mut lab, &parsed)?
    };
    print_sync(out, &report);
    say(
        out,
        format!("cloned {} ops into {}", lab.len(), dir.display()),
    );
    Ok(0)
}

fn cmd_status(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&[])?;
    parsed.reject_unknown(&["json"])?;
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let conflicts = state.conflicts();
    let live_files = state.list("").len();
    let wanted = sync::wanted_blobs(&lab);
    let now = api::now();
    let tasks = state.tasks(now);
    let held = tasks.values().filter(|t| t.holder.is_some()).count();
    if parsed.has("json") {
        let value = Value::object([
            ("space", Value::string(lab.space())),
            ("name", Value::string(&state.name)),
            ("ops", Value::Int(lab.len() as i128)),
            ("heads", Value::Int(lab.heads().len() as i128)),
            ("members", Value::Int(state.roster.members.len() as i128)),
            ("files", Value::Int(live_files as i128)),
            ("conflicts", Value::Int(conflicts.len() as i128)),
            ("excluded", Value::Int(state.excluded.len() as i128)),
            ("tasks_held", Value::Int(held as i128)),
            ("messages", Value::Int(state.messages.len() as i128)),
            ("runs", Value::Int(state.runs.len() as i128)),
            ("environments", Value::Int(state.envs.len() as i128)),
            ("blobs_missing", Value::Int(wanted.len() as i128)),
        ]);
        say(out, value.canonical_string());
        return Ok(0);
    }
    say(out, format!("space     {}", lab.space()));
    say(out, format!("name      {}", state.name));
    say(
        out,
        format!("ops       {} ({} head(s))", lab.len(), lab.heads().len()),
    );
    say(out, format!("members   {}", state.roster.members.len()));
    say(out, format!("files     {live_files}"));
    say(out, format!("conflicts {}", conflicts.len()));
    say(out, format!("excluded  {}", state.excluded.len()));
    say(
        out,
        format!("tasks     {} held, {} known", held, tasks.len()),
    );
    say(out, format!("messages  {}", state.messages.len()));
    say(out, format!("envs      {}", state.envs.len()));
    say(out, format!("runs      {}", state.runs.len()));
    if !wanted.is_empty() {
        say(
            out,
            format!(
                "missing   {} blob(s) referenced but not held — sync to fetch",
                wanted.len()
            ),
        );
    }
    Ok(0)
}

fn cmd_log(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["limit"])?;
    let limit = parsed.u64_flag("limit", 50)? as usize;
    let lab = Lab::open(dir)?;
    let mut ops: Vec<&op::Op> = lab.ops().iter().collect();
    ops.sort_by(|a, b| super::store::order_key(b).cmp(&super::store::order_key(a)));
    for op in ops.into_iter().take(limit) {
        say(
            out,
            format!(
                "{} {:>6} {} {:<8} {}",
                crate::canonical::short(&op.id),
                op.lamport,
                op.time,
                op.body.kind(),
                describe(&op.body)
            ),
        );
    }
    Ok(0)
}

fn describe(body: &Body) -> String {
    match body {
        Body::Genesis { name, members, .. } => format!("{name} ({} member(s))", members.len()),
        Body::Members { admit, revoke } => format!("+{} -{}", admit.len(), revoke.len()),
        Body::Policy(_) => "policy".into(),
        Body::Files { entries } => match entries.len() {
            1 => entries[0].path.clone(),
            n => format!("{n} files, e.g. {}", entries[0].path),
        },
        Body::Doc { doc, fields } => format!("{doc} ({} field(s))", fields.len()),
        Body::Claim {
            task, holder, ttl, ..
        } => format!("{task} by {holder} for {ttl}s"),
        Body::Release { claim, outcome, .. } => {
            format!("{} {}", crate::canonical::short(claim), outcome.as_str())
        }
        Body::Msg { to, subject, .. } => format!("to {}: {subject}", to.join(",")),
        Body::Ack { msg, address } => format!("{} by {address}", crate::canonical::short(msg)),
        Body::Env { name, tree, .. } => format!("{name} = {}", crate::canonical::short(tree)),
        Body::Run { receipt, files } => format!(
            "{} in {} → {} file(s)",
            receipt
                .get("argv")
                .and_then(Value::as_array)
                .and_then(|argv| argv.first())
                .and_then(Value::as_str)
                .unwrap_or("?"),
            receipt
                .get("env")
                .and_then(|e| e.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("?"),
            files.len()
        ),
        Body::Unknown { kind } => format!("(unknown kind {kind})"),
    }
}

fn cmd_verify(dir: &Path, out: &mut dyn io::Write) -> Result<i32, CliError> {
    // Opening re-verifies every op line's signature and admissibility.
    let lab = Lab::open(dir)?;
    let mut bad = 0usize;
    for address in lab.blobs().addresses() {
        if !lab.blobs().verify(&address)? {
            say(out, format!("blob {address} does not hash to its address"));
            bad += 1;
        }
    }
    let state = State::of(&lab);
    say(
        out,
        format!(
            "{} ops verified; {} blob(s) checked, {bad} bad; {} op/entry exclusion(s)",
            lab.len(),
            lab.blobs().addresses().len(),
            state.excluded.len()
        ),
    );
    for excluded in &state.excluded {
        say(
            out,
            format!(
                "  excluded {}{}: {}",
                crate::canonical::short(&excluded.op),
                excluded.entry.map(|n| format!("#{n}")).unwrap_or_default(),
                excluded.reason
            ),
        );
    }
    Ok(if bad == 0 { 0 } else { 1 })
}

fn cmd_members(dir: &Path, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    for (key, standing) in &state.roster.members {
        let roles: Vec<&str> = standing.roles.iter().map(Role::as_str).collect();
        say(out, format!("{key} {}", roles.join(",")));
        for peer in &standing.peers {
            say(out, format!("    peer {peer}"));
        }
    }
    Ok(0)
}

fn cmd_admit(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["roles", "peer", "identity"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let key = op::key_hex(parsed.positional(0, "KEY")?).map_err(|e| CliError::Usage(e.0))?;
    let roles = parse_roles(parsed.one("roles").unwrap_or("writer"))?;
    let peers = parsed
        .all("peer")
        .iter()
        .map(|p| op::key_hex(p).map_err(|e| CliError::Usage(e.0)))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut lab = Lab::open(dir)?;
    let op = lab.append(
        &identity,
        Body::Members {
            admit: vec![Member { key, roles, peers }],
            revoke: Vec::new(),
        },
    )?;
    say(out, format!("admitted in {}", op.id));
    Ok(0)
}

fn cmd_revoke(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["identity"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let key = op::key_hex(parsed.positional(0, "KEY")?).map_err(|e| CliError::Usage(e.0))?;
    let mut lab = Lab::open(dir)?;
    let op = lab.append(
        &identity,
        Body::Members {
            admit: Vec::new(),
            revoke: vec![key],
        },
    )?;
    say(out, format!("revoked in {}", op.id));
    Ok(0)
}

fn cmd_policy(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["identity"])?;
    if parsed.positional.first().map(String::as_str) == Some("set") {
        let identity = load_identity(parsed.one("identity"))?;
        let policy = read_policy(parsed.positional(1, "policy FILE")?)?;
        let mut lab = Lab::open(dir)?;
        let op = lab.append(&identity, Body::Policy(policy))?;
        say(out, format!("policy set in {}", op.id));
        return Ok(0);
    }
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    say(out, state.policy.to_value().canonical_string());
    Ok(0)
}

// -- files ------------------------------------------------------------------------

fn cmd_ls(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&[])?;
    parsed.reject_unknown(&["json"])?;
    let prefix = parsed.positional.first().map(String::as_str).unwrap_or("");
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let listing = state.list(prefix);
    if parsed.has("json") {
        let value = Value::array(listing.iter().map(|(path, value)| {
            Value::object([
                ("path", Value::string(*path)),
                ("blob", Value::string(value.blob.as_deref().unwrap_or(""))),
                ("size", Value::Int(i128::from(value.size))),
                (
                    "values",
                    Value::Int(state.files.get(*path).map(Vec::len).unwrap_or(0) as i128),
                ),
            ])
        }));
        say(out, value.canonical_string());
        return Ok(0);
    }
    for (path, value) in listing {
        let siblings = state.files.get(path).map(Vec::len).unwrap_or(1);
        let mark = if siblings > 1 { " (conflict)" } else { "" };
        say(out, format!("{:>10}  {path}{mark}", value.size));
    }
    Ok(0)
}

fn cmd_cat(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&[])?;
    let path = parsed.positional(0, "PATH")?;
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let bytes = api::read_file(&lab, &state, path)?;
    let _ = out.write_all(&bytes);
    Ok(0)
}

fn content_of(parsed: &Parsed) -> Result<Vec<u8>, CliError> {
    match (parsed.one("file"), parsed.one("text")) {
        (Some("-"), None) => {
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes)?;
            Ok(bytes)
        }
        (Some(file), None) => Ok(fs::read(file).map_err(|e| LabError::Io(format!("{file}: {e}")))?),
        (None, Some(text)) => Ok(text.as_bytes().to_vec()),
        _ => usage("give exactly one of --file FILE and --text TEXT"),
    }
}

fn cmd_put(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["file", "text", "identity"])?;
    parsed.reject_unknown(&["create", "exec"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let path = parsed.positional(0, "PATH")?;
    let bytes = content_of(&parsed)?;
    let mut lab = Lab::open(dir)?;
    let expect = if parsed.has("create") {
        Expect::Absent
    } else {
        Expect::Current
    };
    let op = api::write_file(
        &mut lab,
        &identity,
        path,
        &bytes,
        parsed.has("exec"),
        expect,
    )?;
    say(out, format!("{path} written in {}", op.id));
    Ok(0)
}

fn cmd_rm(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["identity"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let path = parsed.positional(0, "PATH")?;
    let mut lab = Lab::open(dir)?;
    let op = api::delete_file(&mut lab, &identity, path)?;
    say(out, format!("{path} deleted in {}", op.id));
    Ok(0)
}

fn cmd_conflicts(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&[])?;
    parsed.reject_unknown(&["json"])?;
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let conflicts = state.conflicts();
    if parsed.has("json") {
        let value = Value::array(conflicts.iter().map(conflict_value));
        say(out, value.canonical_string());
        return Ok(0);
    }
    if conflicts.is_empty() {
        say(out, "no conflicts");
    }
    for conflict in &conflicts {
        match conflict {
            Conflict::File {
                path,
                values,
                write_once,
            } => {
                say(
                    out,
                    format!(
                        "file {path}{}",
                        if *write_once {
                            " (write-once: two different first writes; needs a human decision)"
                        } else {
                            ""
                        }
                    ),
                );
                for value in values {
                    say(
                        out,
                        format!(
                            "    {}  {}  by {}  {}",
                            value.version.entry,
                            value
                                .blob
                                .as_deref()
                                .map(crate::canonical::short)
                                .unwrap_or_else(|| "deleted".into()),
                            crate::canonical::short(&value.version.author),
                            value.version.time
                        ),
                    );
                }
            }
            Conflict::Field { doc, key, values } => {
                say(out, format!("doc {doc} field {key}"));
                for value in values {
                    say(
                        out,
                        format!(
                            "    {}  {}",
                            value.version.entry,
                            value.value.canonical_string()
                        ),
                    );
                }
            }
            Conflict::Env { name, values } => {
                say(out, format!("env {name}"));
                for value in values {
                    say(out, format!("    {}  {}", value.version.entry, value.tree));
                }
            }
        }
    }
    Ok(0)
}

fn conflict_value(conflict: &Conflict) -> Value {
    match conflict {
        Conflict::File {
            path,
            values,
            write_once,
        } => Value::object([
            ("kind", Value::string("file")),
            ("path", Value::string(path)),
            ("write_once", Value::Bool(*write_once)),
            (
                "values",
                Value::array(values.iter().map(|v| {
                    Value::object([
                        ("entry", Value::string(v.version.entry.to_string())),
                        ("author", Value::string(&v.version.author)),
                        (
                            "blob",
                            v.blob.as_deref().map(Value::string).unwrap_or(Value::Null),
                        ),
                    ])
                })),
            ),
        ]),
        Conflict::Field { doc, key, values } => Value::object([
            ("kind", Value::string("field")),
            ("doc", Value::string(doc)),
            ("key", Value::string(key)),
            (
                "values",
                Value::array(values.iter().map(|v| {
                    Value::object([
                        ("entry", Value::string(v.version.entry.to_string())),
                        ("value", v.value.clone()),
                    ])
                })),
            ),
        ]),
        Conflict::Env { name, values } => Value::object([
            ("kind", Value::string("env")),
            ("name", Value::string(name)),
            (
                "values",
                Value::array(values.iter().map(|v| {
                    Value::object([
                        ("entry", Value::string(v.version.entry.to_string())),
                        ("tree", Value::string(&v.tree)),
                    ])
                })),
            ),
        ]),
    }
}

fn cmd_resolve(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["file", "text", "pick", "identity"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let path = parsed.positional(0, "PATH")?;
    let mut lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let values = state
        .files
        .get(path)
        .ok_or_else(|| LabError::NotFound(path.to_string()))?;
    let seen: Vec<EntryRef> = values.iter().map(|v| v.version.entry.clone()).collect();
    let bytes = match parsed.one("pick") {
        Some(pick) => {
            let wanted = EntryRef::parse(pick).map_err(|e| CliError::Usage(e.0))?;
            let chosen = values
                .iter()
                .find(|v| v.version.entry == wanted)
                .ok_or_else(|| {
                    LabError::NotFound(format!("{pick} is not a current value of {path}"))
                })?;
            match &chosen.blob {
                Some(blob) => lab.blobs().read(blob)?,
                None => {
                    let op = api::delete_file(&mut lab, &identity, path)?;
                    say(out, format!("{path} resolved as deleted in {}", op.id));
                    return Ok(0);
                }
            }
        }
        None => content_of(&parsed)?,
    };
    let op = api::write_file(&mut lab, &identity, path, &bytes, false, Expect::Seen(seen))?;
    say(out, format!("{path} resolved in {}", op.id));
    Ok(0)
}

fn cmd_checkout(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["include", "exclude"])?;
    parsed.reject_unknown(&["force"])?;
    let target = PathBuf::from(parsed.positional(0, "DIR")?);
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let report = tree::checkout(&lab, &state, &target, &parsed.filter(), parsed.has("force"))?;
    say(
        out,
        format!(
            "{} written, {} unchanged, {} removed, {} kept with local changes, {} conflict sidecar(s)",
            report.written,
            report.unchanged,
            report.removed,
            report.kept.len(),
            report.conflicts.len()
        ),
    );
    for path in &report.kept {
        say(
            out,
            format!("  kept {path} (local changes; commit or --force)"),
        );
    }
    for sidecar in &report.conflicts {
        say(out, format!("  conflict {}", sidecar.display()));
    }
    if !report.missing.is_empty() {
        say(
            out,
            format!(
                "  {} file(s) not written: their blobs are not here yet (sync)",
                report.missing.len()
            ),
        );
    }
    Ok(0)
}

fn cmd_commit(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["include", "exclude", "identity"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let target = PathBuf::from(parsed.positional(0, "DIR")?);
    let mut lab = Lab::open(dir)?;
    let report = tree::commit(&mut lab, &identity, &target, &parsed.filter())?;
    say(
        out,
        format!(
            "{} written, {} deleted, {} adopted unchanged, in {} op(s)",
            report.written,
            report.deleted,
            report.adopted,
            report.ops.len()
        ),
    );
    for (path, why) in &report.refused {
        say(out, format!("  refused {path}: {why}"));
    }
    Ok(if report.refused.is_empty() { 0 } else { 2 })
}

fn cmd_changes(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["include", "exclude"])?;
    let target = PathBuf::from(parsed.positional(0, "DIR")?);
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let changes = tree::status(&lab, &state, &target, &parsed.filter())?;
    for (path, ..) in &changes.added {
        say(out, format!("A {path}"));
    }
    for (path, ..) in &changes.modified {
        say(out, format!("M {path}"));
    }
    for path in &changes.deleted {
        say(out, format!("D {path}"));
    }
    for (path, why) in &changes.skipped {
        say(out, format!("? {path} ({why})"));
    }
    say(
        out,
        format!(
            "{} added, {} modified, {} deleted, {} unchanged, {} already in the space",
            changes.added.len(),
            changes.modified.len(),
            changes.deleted.len(),
            changes.unchanged,
            changes.adopted.len()
        ),
    );
    Ok(0)
}

// -- docs, leases, messages ---------------------------------------------------------

fn cmd_doc(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["identity"])?;
    if parsed.positional.first().map(String::as_str) == Some("set") {
        let identity = load_identity(parsed.one("identity"))?;
        let doc = parsed.positional(1, "DOC")?;
        let key = parsed.positional(2, "KEY")?;
        let json = parsed.positional(3, "JSON value")?;
        let value = Value::from_json(json)
            .map_err(|e| CliError::Usage(format!("value is not JSON: {e}")))?;
        let mut lab = Lab::open(dir)?;
        let state = State::of(&lab);
        let pred = state
            .docs
            .get(doc)
            .and_then(|keys| keys.get(key))
            .map(|values| values.iter().map(|v| v.version.entry.clone()).collect())
            .unwrap_or_default();
        let op = lab.append(
            &identity,
            Body::Doc {
                doc: doc.to_string(),
                fields: vec![op::Field {
                    key: key.to_string(),
                    value,
                    pred,
                }],
            },
        )?;
        say(out, format!("{doc}.{key} set in {}", op.id));
        return Ok(0);
    }
    let doc = parsed.positional(0, "DOC")?;
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let value = state
        .doc(doc)
        .ok_or_else(|| LabError::NotFound(format!("doc {doc}")))?;
    say(out, value.canonical_string());
    Ok(0)
}

fn cmd_claim(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["holder", "ttl", "identity", "note"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let task = parsed.positional(0, "TASK")?;
    let holder = parsed.need("holder")?;
    let ttl = parsed.u64_flag("ttl", 3600)?;
    let mut lab = Lab::open(dir)?;
    let (op, view) = api::claim(
        &mut lab,
        &identity,
        task,
        holder,
        ttl,
        parsed.one("note").map(str::to_string),
    )?;
    let holds = view.holder.as_ref().is_some_and(|c| c.id == op.id);
    say(out, format!("lease {} on {task}", op.id));
    if holds {
        say(out, "  held");
        Ok(0)
    } else {
        let by = view
            .holder
            .as_ref()
            .map(|c| format!("{} ({})", c.holder, crate::canonical::short(&c.id)))
            .unwrap_or_else(|| "nobody".into());
        say(out, format!("  contended: the task is held by {by}"));
        Ok(1)
    }
}

fn cmd_release(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["outcome", "identity", "note"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let claim = parsed.positional(0, "CLAIM-ID")?;
    let outcome = Outcome::parse(parsed.need("outcome")?).map_err(|e| CliError::Usage(e.0))?;
    let mut lab = Lab::open(dir)?;
    let op = api::release(
        &mut lab,
        &identity,
        claim,
        outcome,
        parsed.one("note").map(str::to_string),
    )?;
    say(out, format!("released in {}", op.id));
    Ok(0)
}

fn cmd_tasks(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&[])?;
    parsed.reject_unknown(&["json"])?;
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let tasks = state.tasks(api::now());
    if parsed.has("json") {
        let value = Value::Object(
            tasks
                .iter()
                .map(|(task, view)| {
                    (
                        task.clone(),
                        Value::object([
                            (
                                "holder",
                                view.holder
                                    .as_ref()
                                    .map(|c| {
                                        Value::object([
                                            ("claim", Value::string(&c.id)),
                                            ("holder", Value::string(&c.holder)),
                                            (
                                                "expires_at",
                                                c.expires_at
                                                    .map(|t| Value::Int(i128::from(t)))
                                                    .unwrap_or(Value::Null),
                                            ),
                                        ])
                                    })
                                    .unwrap_or(Value::Null),
                            ),
                            ("contended", Value::Int(view.contended.len() as i128)),
                            ("expired", Value::Int(view.expired.len() as i128)),
                            ("released", Value::Int(view.released.len() as i128)),
                            ("completed", Value::Bool(view.completed)),
                        ]),
                    )
                })
                .collect(),
        );
        say(out, value.canonical_string());
        return Ok(0);
    }
    for (task, view) in &tasks {
        let status = if view.completed {
            "completed".to_string()
        } else if let Some(holder) = &view.holder {
            format!(
                "held by {} until {}",
                holder.holder,
                holder
                    .expires_at
                    .map(crate::time::format_iso8601_utc)
                    .unwrap_or_default()
            )
        } else {
            "free".to_string()
        };
        say(out, format!("{task}: {status}"));
        for claim in &view.contended {
            say(
                out,
                format!(
                    "    contended {} by {}",
                    crate::canonical::short(&claim.id),
                    claim.holder
                ),
            );
        }
    }
    Ok(0)
}

fn cmd_send(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["to", "subject", "body", "identity", "from", "ref"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let to: Vec<String> = parsed
        .need("to")?
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut lab = Lab::open(dir)?;
    let op = api::send(
        &mut lab,
        &identity,
        to,
        parsed.one("from").map(str::to_string),
        parsed.need("subject")?,
        parsed.one("body").unwrap_or(""),
        parsed.all("ref"),
    )?;
    say(out, format!("sent {}", op.id));
    Ok(0)
}

fn cmd_inbox(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&[])?;
    parsed.reject_unknown(&["json"])?;
    let address = parsed.positional(0, "ADDR")?;
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let inbox = state.inbox(address);
    if parsed.has("json") {
        let value = Value::array(inbox.iter().map(|m| {
            Value::object([
                ("id", Value::string(&m.id)),
                ("time", Value::string(&m.time)),
                (
                    "from",
                    Value::string(m.from.as_deref().unwrap_or(&m.author)),
                ),
                ("subject", Value::string(&m.subject)),
                ("body", Value::string(&m.body)),
            ])
        }));
        say(out, value.canonical_string());
        return Ok(0);
    }
    for message in inbox {
        say(
            out,
            format!(
                "{} {} from {}: {}",
                crate::canonical::short(&message.id),
                message.time,
                message.from.as_deref().unwrap_or(&message.author),
                message.subject
            ),
        );
        if !message.body.is_empty() {
            for line in message.body.lines() {
                say(out, format!("    {line}"));
            }
        }
    }
    Ok(0)
}

fn cmd_ack(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["as", "identity"])?;
    let identity = load_identity(parsed.one("identity"))?;
    let msg = parsed.positional(0, "MSG-ID")?;
    let mut lab = Lab::open(dir)?;
    let op = api::ack(&mut lab, &identity, msg, parsed.need("as")?)?;
    say(out, format!("acked in {}", op.id));
    Ok(0)
}

// -- environments and runs -----------------------------------------------------------

fn cmd_env(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let action = args.next().unwrap_or_else(|| "ls".into());
    match action.as_str() {
        "import" => {
            let parsed = args.rest(&[
                "docker", "podman", "tar", "dir", "identity", "env", "workdir", "note",
            ])?;
            let identity = load_identity(parsed.one("identity"))?;
            let name = parsed.positional(0, "NAME")?;
            let source = match (
                parsed.one("docker"),
                parsed.one("podman"),
                parsed.one("tar"),
                parsed.one("dir"),
            ) {
                (Some(image), None, None, None) => Source::Image {
                    engine: "docker".into(),
                    image: image.into(),
                },
                (None, Some(image), None, None) => Source::Image {
                    engine: "podman".into(),
                    image: image.into(),
                },
                (None, None, Some(tar), None) => Source::Tar(tar.into()),
                (None, None, None, Some(dir)) if parsed.has("move") => Source::Move(dir.into()),
                (None, None, None, Some(dir)) => Source::Dir(dir.into()),
                _ => return usage("give exactly one of --docker, --podman, --tar, --dir"),
            };
            let mut options = ImportOptions {
                workdir: parsed.one("workdir").map(str::to_string),
                note: parsed.one("note").map(str::to_string),
                ..ImportOptions::default()
            };
            for pair in parsed.all("env") {
                let (key, value) = pair
                    .split_once('=')
                    .ok_or_else(|| CliError::Usage(format!("--env {pair:?} is not KEY=VALUE")))?;
                options.env.insert(key.to_string(), value.to_string());
            }
            let mut lab = Lab::open(dir)?;
            let (resolved, op) = env::import(&mut lab, &identity, name, &source, &options)?;
            say(out, format!("environment {name} = {}", resolved.tree));
            say(out, format!("  root {}", resolved.rootfs.display()));
            say(out, format!("  named in {}", op.id));
            Ok(0)
        }
        "ls" => {
            let parsed = args.rest(&[])?;
            let lab = Lab::open(dir)?;
            let state = State::of(&lab);
            if parsed.has("json") {
                let value = Value::Object(
                    state
                        .envs
                        .iter()
                        .map(|(name, values)| {
                            (
                                name.clone(),
                                Value::object([
                                    ("tree", Value::string(&values[0].tree)),
                                    ("values", Value::Int(values.len() as i128)),
                                    (
                                        "here",
                                        Value::Bool(
                                            env::rootfs_path(&lab, &values[0].tree)
                                                .map(|p| p.is_dir())
                                                .unwrap_or(false),
                                        ),
                                    ),
                                ]),
                            )
                        })
                        .collect(),
                );
                say(out, value.canonical_string());
                return Ok(0);
            }
            for (name, values) in &state.envs {
                let here = env::rootfs_path(&lab, &values[0].tree)
                    .map(|p| p.is_dir())
                    .unwrap_or(false);
                say(
                    out,
                    format!(
                        "{name:<20} {}  {}{}",
                        values[0].tree,
                        if here { "here" } else { "not on this machine" },
                        if values.len() > 1 { "  (conflict)" } else { "" }
                    ),
                );
            }
            Ok(0)
        }
        "show" => {
            let parsed = args.rest(&[])?;
            let name = parsed.positional(0, "NAME")?;
            let lab = Lab::open(dir)?;
            let state = State::of(&lab);
            let resolved = env::resolve(&lab, &state, name)?;
            say(out, resolved.manifest.canonical_string());
            Ok(0)
        }
        "verify" => {
            let parsed = args.rest(&[])?;
            let name = parsed.positional(0, "NAME")?;
            let lab = Lab::open(dir)?;
            let state = State::of(&lab);
            let resolved = env::resolve(&lab, &state, name)?;
            if env::verify(&lab, &resolved.tree)? {
                say(out, format!("{name}: tree matches {}", resolved.tree));
                Ok(0)
            } else {
                say(
                    out,
                    format!("{name}: tree on disk no longer hashes to {}", resolved.tree),
                );
                Ok(1)
            }
        }
        other => usage(format!("unknown env action {other:?}")),
    }
}

fn cmd_exec(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&[
        "env", "identity", "input", "mount", "publish", "cwd", "setenv", "timeout", "memory",
        "cpus", "pids", "sandbox", "task", "note", "tmp",
    ])?;
    parsed.reject_unknown(&["network", "keep", "json"])?;
    let identity = load_identity(parsed.one("identity"))?;
    if parsed.trailing.is_empty() {
        return usage("exec needs a command after --");
    }
    let mut request = ExecRequest::new(parsed.need("env")?, parsed.trailing.clone());
    for spec in parsed.all("input") {
        let (prefix, target) = match spec.split_once(':') {
            Some((prefix, target)) => (prefix.to_string(), target.to_string()),
            None => (spec.clone(), format!("/in/{}", spec.trim_end_matches('/'))),
        };
        if !target.starts_with('/') {
            return usage(format!("input target {target:?} must be absolute"));
        }
        request.inputs.push(Input { prefix, target });
    }
    for spec in parsed.all("mount") {
        let (source, target) = spec
            .split_once(':')
            .ok_or_else(|| CliError::Usage(format!("--mount {spec:?} is not HOSTDIR:TARGET")))?;
        request
            .mounts
            .push((PathBuf::from(source), target.to_string()));
    }
    for pair in parsed.all("setenv") {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| CliError::Usage(format!("--setenv {pair:?} is not KEY=VALUE")))?;
        request.env_vars.insert(key.to_string(), value.to_string());
    }
    request.publish = parsed.one("publish").map(str::to_string);
    request.cwd = parsed.one("cwd").map(str::to_string);
    request.timeout = Duration::from_secs(parsed.u64_flag("timeout", 3600)?);
    request.memory_mb = parsed.u64_flag("memory", 0)?;
    request.cpus = u32::try_from(parsed.u64_flag("cpus", 0)?).unwrap_or(u32::MAX);
    request.pids = u32::try_from(parsed.u64_flag("pids", 0)?).unwrap_or(u32::MAX);
    request.tmp_mb = parsed.u64_flag("tmp", 1024)?;
    request.network = parsed.has("network");
    request.keep_work = parsed.has("keep");
    request.task = parsed.one("task").map(str::to_string);
    request.note = parsed.one("note").map(str::to_string);
    let sandbox = parsed
        .one("sandbox")
        .map(str::to_string)
        .or_else(|| std::env::var(exec::SANDBOX_ENV).ok())
        .unwrap_or_else(|| "auto".into());
    request.sandbox = Preference::parse(&sandbox)?;

    let mut lab = Lab::open(dir)?;
    let result = api::exec(&mut lab, &identity, &request)?;
    let outcome = &result.outcome;
    if parsed.has("json") {
        let mut pairs = vec![
            ("run", Value::string(&result.op.id)),
            ("publish", Value::string(&result.publish)),
            (
                "files",
                Value::array(result.published.iter().map(|(p, _, _)| Value::string(p))),
            ),
            ("stdout", Value::string(&result.stdout)),
            ("stderr", Value::string(&result.stderr)),
        ];
        pairs.extend(outcome.to_value());
        say(out, Value::object(pairs).canonical_string());
    } else {
        let _ = out.write_all(result.stdout.as_bytes());
        if !result.stderr.is_empty() {
            eprint!("{}", result.stderr);
        }
        say(out, format!("run {}", result.op.id));
        say(
            out,
            format!(
                "  backend {} {}  wall {} ms  exit {}{}{}",
                outcome.backend,
                outcome.backend_version,
                outcome.wall_ms,
                outcome
                    .exit_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "none".into()),
                if outcome.timed_out { "  TIMED OUT" } else { "" },
                if outcome.limit_exceeded {
                    "  LIMIT EXCEEDED"
                } else {
                    ""
                }
            ),
        );
        if let Some(error) = &outcome.error {
            say(out, format!("  sandbox error: {error}"));
        }
        for warning in &outcome.unenforced {
            say(out, format!("  not enforced: {warning}"));
        }
        for note in &outcome.notes {
            say(out, format!("  note: {note}"));
        }
        say(
            out,
            format!(
                "  {} output file(s) under {}",
                result.published.len(),
                result.publish
            ),
        );
        if let Some(work) = &result.work {
            say(out, format!("  work kept at {}", work.display()));
        }
    }
    Ok(if outcome.error.is_some() || outcome.limit_exceeded {
        3
    } else if outcome.succeeded() {
        0
    } else {
        1
    })
}

fn cmd_runs(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["limit"])?;
    let limit = parsed.u64_flag("limit", 20)? as usize;
    let lab = Lab::open(dir)?;
    let state = State::of(&lab);
    let runs: Vec<_> = state.runs.iter().rev().take(limit).collect();
    if parsed.has("json") {
        let value = Value::array(runs.iter().map(|run| {
            Value::object([
                ("id", Value::string(&run.id)),
                ("time", Value::string(&run.time)),
                ("author", Value::string(&run.author)),
                ("receipt", run.receipt.clone()),
                ("files", Value::Int(run.files.len() as i128)),
            ])
        }));
        say(out, value.canonical_string());
        return Ok(0);
    }
    for run in runs {
        let receipt = &run.receipt;
        let text = |key: &str| receipt.get(key).and_then(Value::as_str).unwrap_or("");
        let exit = receipt
            .get("exit_status")
            .and_then(Value::as_i64)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".into());
        say(
            out,
            format!(
                "{} {} env={} backend={} exit={} files={} publish={}{}",
                crate::canonical::short(&run.id),
                run.time,
                receipt
                    .get("env")
                    .and_then(|e| e.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                text("backend"),
                exit,
                run.files.len(),
                text("publish"),
                receipt
                    .get("error")
                    .and_then(Value::as_str)
                    .map(|e| format!(" error={e}"))
                    .unwrap_or_default()
            ),
        );
    }
    Ok(0)
}

fn cmd_sandbox(out: &mut dyn io::Write) -> Result<i32, CliError> {
    for (name, preference) in [
        ("runsc", Preference::Gvisor),
        ("bwrap", Preference::Bubblewrap),
    ] {
        match exec::backend(preference) {
            Ok(backend) => say(out, format!("{name}: usable ({})", backend.version())),
            Err(e) => say(out, format!("{name}: {e}")),
        }
    }
    match exec::backend(Preference::Auto) {
        Ok(backend) => say(out, format!("auto picks {}", backend.name())),
        Err(_) => say(out, "auto picks nothing: no sandbox works here"),
    }
    Ok(0)
}

// -- sync -------------------------------------------------------------------------------

fn sync_with(lab: &mut Lab, parsed: &Parsed) -> Result<sync::SyncReport, CliError> {
    match (parsed.one("dir"), parsed.one("peer")) {
        (Some(other), None) => {
            let mut other = Lab::open(Path::new(other))?;
            Ok(sync::sync(lab, &mut other)?)
        }
        (None, Some(peer)) => {
            let (id, addr) = peer
                .split_once('@')
                .ok_or_else(|| CliError::Usage(format!("--peer {peer:?} is not ID@HOST:PORT")))?;
            let addr: SocketAddr = resolve_addr(addr)?;
            let identity = load_peer_identity(Path::new(parsed.need("peer-identity")?))?;
            let mut remote = RemotePeer::connect(addr, id, &identity)?;
            Ok(sync::sync(lab, &mut remote)?)
        }
        _ => usage("give exactly one of --dir PATH and --peer ID@HOST:PORT"),
    }
}

fn resolve_addr(text: &str) -> Result<SocketAddr, CliError> {
    use std::net::ToSocketAddrs as _;
    text.to_socket_addrs()
        .map_err(|e| CliError::Usage(format!("{text:?}: {e}")))?
        .next()
        .ok_or_else(|| CliError::Usage(format!("{text:?} resolves to no address")))
}

fn print_sync(out: &mut dyn io::Write, report: &sync::SyncReport) {
    say(
        out,
        format!(
            "ops: {} received, {} sent, {} refused; blobs: {} received, {} sent, {} missing",
            report.ops_received,
            report.ops_sent,
            report.ops_refused.len(),
            report.blobs_received,
            report.blobs_sent,
            report.blobs_missing.len()
        ),
    );
    for (id, why) in report.ops_refused.iter().take(10) {
        say(
            out,
            format!("  refused {}: {why}", crate::canonical::short(id)),
        );
    }
}

fn cmd_sync(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["dir", "peer", "peer-identity"])?;
    let mut lab = Lab::open(dir)?;
    let report = sync_with(&mut lab, &parsed)?;
    print_sync(out, &report);
    Ok(if report.ops_refused.is_empty() { 0 } else { 1 })
}

fn cmd_serve(dir: &Path, args: &mut Args) -> Result<i32, CliError> {
    let parsed = args.rest(&["listen", "peer-identity", "allow"])?;
    parsed.reject_unknown(&["open"])?;
    let listen = resolve_addr(parsed.need("listen")?)?;
    let identity = load_peer_identity(Path::new(parsed.need("peer-identity")?))?;
    let access = Access {
        allow: parsed
            .all("allow")
            .iter()
            .map(|p| op::key_hex(p).map_err(|e| CliError::Usage(e.0)))
            .collect::<Result<BTreeSet<_>, _>>()?,
        open: parsed.has("open"),
    };
    sync::serve(dir, identity, listen, access)?;
    Ok(0)
}

fn cmd_bundle(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&["out", "have"])?;
    let lab = Lab::open(dir)?;
    let have = match parsed.one("have") {
        Some(path) => Some(
            fs::read_to_string(path)
                .map_err(|e| LabError::Io(format!("{path}: {e}")))?
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect::<BTreeSet<_>>(),
        ),
        None => None,
    };
    let path = parsed.need("out")?;
    let mut file = io::BufWriter::new(
        fs::File::create(path).map_err(|e| LabError::Io(format!("{path}: {e}")))?,
    );
    let (ops, blobs) = sync::write_bundle(&lab, &mut file, have.as_ref())?;
    say(
        out,
        format!("bundled {ops} op(s) and {blobs} blob(s) into {path}"),
    );
    Ok(0)
}

fn cmd_unbundle(dir: &Path, args: &mut Args, out: &mut dyn io::Write) -> Result<i32, CliError> {
    let parsed = args.rest(&[])?;
    let path = parsed.positional(0, "FILE")?;
    let mut lab = Lab::open(dir)?;
    let mut file = fs::File::open(path).map_err(|e| LabError::Io(format!("{path}: {e}")))?;
    let report = sync::read_bundle(&mut lab, &mut file)?;
    print_sync(out, &report);
    Ok(if report.ops_refused.is_empty() { 0 } else { 1 })
}
