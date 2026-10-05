//! `cairn fleet …`: enroll the machines that work for a leader.
//!
//! Two sides in one command, as `docs/design/fleet-enrollment.md` §11 lays
//! them out. On the **leader** it writes the registry beside the log --
//! invites, admissions, revocations -- and never touches the network:
//! membership changes only through files on the leader's own disk and the one
//! join route, which needs a token minted here. On a **worker** it joins with
//! a token and writes the member file, and signs single requests for clients
//! that cannot sign for themselves.
//!
//! Exit codes follow `cairn agent`'s: `0` done, `1` refused, `2` bad usage,
//! `3` the node could not be reached.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand_core::OsRng;

use super::auth::{self, key_hex, parse_key, JoinRequest, Key, MemberFile, Token};
use super::members::{Registry, Terms};
use crate::agent::cli::{parse, Parsed};
use crate::agent::http::{self, NodeUrl, Response};
use crate::canonical::Value;
use crate::crypto::identity::Identity;

/// Where a worker's member file is, for `cairn work`, `cairn agent`, the
/// units and `cairn fleet sign` alike.
pub const FILE_ENV: &str = "CAIRN_FLEET_FILE";
/// An invite token, read when `cairn fleet join` is given none, so a secret
/// store can hand it over without it appearing on a command line.
pub const INVITE_ENV: &str = "CAIRN_INVITE";

/// A join is one request; a leader slower than this is one to report.
const NODE_TIMEOUT: Duration = Duration::from_secs(20);
/// The longest body `cairn fleet sign` reads from stdin: the node's own cap.
const MAX_SIGNED_BODY: u64 = crate::serve::MAX_BODY_BYTES;
/// `prefix-<12 hex>` must still be a member name.
const MAX_PREFIX_CHARS: usize = auth::MAX_NAME_CHARS - 13;

const USAGE: &str = "\
cairn fleet — enroll the machines that work for this node, from anywhere

On the leader (writes <log dir>/fleet/; never the network):
    invite [--name NAME | --prefix P] [--uses N] [--expires 24h] [--member-ttl 12h]
           [--note TEXT] [--node URL] [--json] [--identity FILE | --leader KEY]
                                    mint an invitation and print its token, once
    admit --key KEY --name NAME [--ttl 12h]
                                    enroll a key by hand: no token on any wire
    list [--json]                   members, with expiry and revocation
    invites [--json]                invitations, with how many each admitted
    revoke NAME|KEY [--reason TEXT] revoke one member, at its next request, forever
    revoke --invite KEY [--reason TEXT]
                                    revoke every member one invite admitted, and the invite
    revoke-invite KEY               withdraw an invitation; its members stay

On a worker:
    join --node URL [--name NAME] [--out FILE] [TOKEN | -]
                                    join with a token (or $CAIRN_INVITE, or stdin with -)
                                    and write the member file, mode 0600
    join --manual --node URL --leader KEY --name NAME [--out FILE]
                                    write the member file and print the `admit` line
                                    for the operator to run on the leader
    sign [--member FILE] [--method POST] --target PATH
                                    sign one request whose body is on stdin and print
                                    the Authorization value, for clients that cannot

The leader's key comes from --leader, the identity file named by --identity or
$CAIRN_FLEET_IDENTITY, which is the file the node signs with. The member file
defaults to $CAIRN_FLEET_FILE, then ~/.cairn/fleet.json. Durations are seconds
or a number with s, m, h or d.

The node signs for members only when its CAIRN_FLEET lists `enrolled`:
    CAIRN_FLEET=enrolled cairn run …

EXIT CODES
    0 done   1 refused   2 bad usage   3 the node could not be reached
";

/// Why a command stopped.
#[derive(Debug)]
enum Failure {
    Usage(String),
    Refused(String),
    Unreachable(String),
}

fn usage(message: impl Into<String>) -> Failure {
    Failure::Usage(message.into())
}

fn refused(message: impl Into<String>) -> Failure {
    Failure::Refused(message.into())
}

/// Entry point: `cairn fleet ARGS…`, with the log the global flags resolved,
/// beside which the leader's registry lives. Returns the process exit code.
pub fn main(args: Vec<String>, log: &Path) -> i32 {
    let mut out = io::stdout().lock();
    let mut input = io::stdin().lock();
    match run(&args, log, &mut out, &mut input) {
        Ok(()) => 0,
        Err(Failure::Usage(message)) => {
            eprintln!("cairn fleet: {message}\n\nrun `cairn fleet help` for usage");
            2
        }
        Err(Failure::Refused(message)) => {
            eprintln!("cairn fleet: {message}");
            1
        }
        Err(Failure::Unreachable(message)) => {
            eprintln!("cairn fleet: {message}");
            3
        }
    }
}

fn run(
    args: &[String],
    log: &Path,
    out: &mut dyn Write,
    input: &mut dyn Read,
) -> Result<(), Failure> {
    let Some((command, rest)) = args.split_first() else {
        return write_out(out, USAGE);
    };
    let parsed = |values: &[&str], switches: &[&str]| {
        parse(rest, values, switches).map_err(|e| usage(e.to_string()))
    };
    match command.as_str() {
        "help" | "-h" | "--help" => write_out(out, USAGE),
        "invite" => invite(
            &parsed(
                &[
                    "name",
                    "prefix",
                    "uses",
                    "expires",
                    "member-ttl",
                    "note",
                    "node",
                    "identity",
                    "leader",
                ],
                &["json"],
            )?,
            log,
            out,
        ),
        "admit" => admit(
            &parsed(&["key", "name", "ttl", "identity", "leader"], &[])?,
            log,
            out,
        ),
        "list" => list(&parsed(&["identity", "leader"], &["json"])?, log, out),
        "invites" => invites(&parsed(&["identity", "leader"], &["json"])?, log, out),
        "revoke" => revoke(
            &parsed(&["invite", "reason", "identity", "leader"], &[])?,
            log,
            out,
        ),
        "revoke-invite" => revoke_invite(&parsed(&["identity", "leader"], &[])?, log, out),
        "join" => join(
            &parsed(&["node", "name", "out", "leader"], &["manual"])?,
            out,
            input,
        ),
        "sign" => sign(&parsed(&["member", "method", "target"], &[])?, out, input),
        other => Err(usage(format!("unknown command {other:?}"))),
    }
}

fn write_out(out: &mut dyn Write, text: &str) -> Result<(), Failure> {
    out.write_all(text.as_bytes())
        .map_err(|e| refused(format!("cannot write the output: {e}")))
}

fn now() -> u64 {
    crate::time::unix_seconds()
}

fn iso(unix: u64) -> String {
    crate::time::format_iso8601_utc(i64::try_from(unix).unwrap_or(i64::MAX))
}

/// `90`, `90s`, `15m`, `12h`, `7d`.
pub fn parse_duration(text: &str) -> Option<u64> {
    let text = text.trim();
    let (digits, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => text.split_at(at),
        None => (text, ""),
    };
    let scale = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return None,
    };
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(scale)
}

fn duration(parsed: &Parsed, flag: &str) -> Result<Option<u64>, Failure> {
    parsed
        .one(flag)
        .map(|text| {
            parse_duration(text).filter(|s| *s > 0).ok_or_else(|| {
                usage(format!(
                    "--{flag} needs a positive duration such as 3600, 90m, 12h or 7d, not {text:?}"
                ))
            })
        })
        .transpose()
}

/// The leader's public key: `--leader`, or the identity the node signs with.
fn leader_key(parsed: &Parsed) -> Result<Option<Key>, Failure> {
    if let Some(text) = parsed.one("leader") {
        return parse_key(text)
            .map(Some)
            .ok_or_else(|| usage("--leader needs a key of 64 lowercase hex characters"));
    }
    let path = parsed.one("identity").map(PathBuf::from).or_else(|| {
        std::env::var(super::IDENTITY_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(|v| PathBuf::from(v.trim()))
    });
    match path {
        Some(path) => crate::mcp::load_identity(&path)
            .map(|identity| Some(identity.public().to_bytes()))
            .map_err(refused),
        None => Ok(None),
    }
}

fn required_leader(parsed: &Parsed) -> Result<Key, Failure> {
    leader_key(parsed)?.ok_or_else(|| {
        usage(format!(
            "which leader? pass --identity FILE (the identity the node signs with), set {}, \
             or pass --leader KEY",
            super::IDENTITY_ENV
        ))
    })
}

/// The registry beside `log`. Commands that verify nothing (listing,
/// revoking) do not need the leader's key and work without one.
fn registry(log: &Path, leader: Option<Key>) -> Registry {
    Registry::for_log(log, leader.unwrap_or_default())
}

fn io_failure(what: &str) -> impl Fn(io::Error) -> Failure + '_ {
    move |e| refused(format!("{what}: {e}"))
}

// -- the leader's commands ---------------------------------------------------------

fn invite(parsed: &Parsed, log: &Path, out: &mut dyn Write) -> Result<(), Failure> {
    let leader = required_leader(parsed)?;
    let name = parsed.one("name").map(str::to_string);
    let prefix = parsed.one("prefix").map(str::to_string);
    if name.is_some() && prefix.is_some() {
        return Err(usage(
            "--name and --prefix are alternatives: one machine by name, or many by prefix",
        ));
    }
    if let Some(name) = &name {
        if !auth::valid_name(name) {
            return Err(usage(format!(
                "a member name is letters, digits, '.', '_' and '-', at most {} characters; \
                 {name:?} is not one",
                auth::MAX_NAME_CHARS
            )));
        }
    }
    if let Some(prefix) = &prefix {
        if !auth::valid_name(prefix) || prefix.len() > MAX_PREFIX_CHARS {
            return Err(usage(format!(
                "a prefix is letters, digits, '.', '_' and '-', at most {MAX_PREFIX_CHARS} \
                 characters, so that `{{prefix}}-{{12 hex}}` is still a name; {prefix:?} is not one"
            )));
        }
    }
    let uses = match parsed.one("uses") {
        None => 1,
        Some(text) => text
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| usage(format!("--uses needs a positive count, not {text:?}")))?,
    };
    if name.is_some() && uses > 1 {
        return Err(usage(
            "a named invite admits exactly one machine; use --prefix to invite several",
        ));
    }
    let expires_in = duration(parsed, "expires")?.unwrap_or(24 * 3_600);
    let terms = Terms {
        uses,
        expires_in,
        name,
        prefix,
        member_ttl: duration(parsed, "member-ttl")?,
        note: parsed.one("note").map(str::to_string),
    };
    let registry = registry(log, Some(leader));
    let at = now();
    let (token, invite) = registry
        .create_invite(&terms, at)
        .map_err(io_failure("cannot write the invite"))?;
    let node = parsed.one("node").unwrap_or("http://LEADER:8080");
    let join_line = format!("cairn fleet join --node {node} {}", token.render());
    if parsed.switch("json") {
        let opt = |v: &Option<String>| v.clone().map(Value::string).unwrap_or(Value::Null);
        let value = Value::object([
            ("token", Value::string(token.render())),
            ("invite", Value::string(key_hex(&invite.key))),
            ("leader", Value::string(key_hex(&leader))),
            ("uses", Value::Int(i128::from(invite.uses))),
            ("expires_at", Value::string(iso(invite.expires_at))),
            ("name", opt(&invite.name)),
            ("prefix", opt(&invite.prefix)),
            (
                "member_ttl_seconds",
                invite
                    .member_ttl
                    .map(|t| Value::Int(i128::from(t)))
                    .unwrap_or(Value::Null),
            ),
            ("note", opt(&invite.note)),
            ("join", Value::string(join_line)),
            (
                "directory",
                Value::string(registry.dir().display().to_string()),
            ),
        ]);
        return write_out(out, &format!("{}\n", value.canonical_string()));
    }
    let whom = match (&invite.name, &invite.prefix) {
        (Some(name), _) => format!("the machine named {name}"),
        (None, Some(prefix)) => format!(
            "{} machine{} named {prefix}-<first 12 hex of its key>",
            invite.uses,
            if invite.uses == 1 { "" } else { "s" }
        ),
        (None, None) => format!(
            "{} machine{}, each named as it asks (its hostname by default)",
            invite.uses,
            if invite.uses == 1 { "" } else { "s" }
        ),
    };
    let lasting = match invite.member_ttl {
        Some(ttl) => format!("; each membership ends {ttl} s after it joins"),
        None => String::new(),
    };
    let node_hint = if parsed.one("node").is_none() {
        "\nReplace http://LEADER:8080 with an address of this node's HTTP side that the \
         worker can reach (--node prints it in).\n"
    } else {
        ""
    };
    write_out(
        out,
        &format!(
            "invite {} admits {whom}, until {}{lasting}.\n\nOn the worker:\n\n  {join_line}\n\
             {node_hint}\nThe token is shown once and is a secret: whoever holds it can join, \
             until it is used up or expires. Hand it over out of band -- a paste, cloud-init, a \
             secret store -- and withdraw it with `cairn fleet revoke-invite {}`.\n",
            &key_hex(&invite.key)[..12],
            iso(invite.expires_at),
            key_hex(&invite.key),
        ),
    )
}

fn admit(parsed: &Parsed, log: &Path, out: &mut dyn Write) -> Result<(), Failure> {
    let key = parsed
        .one("key")
        .ok_or_else(|| {
            usage("admit needs --key, the member key `cairn fleet join --manual` printed")
        })
        .and_then(|text| {
            parse_key(text).ok_or_else(|| usage("--key needs 64 lowercase hex characters"))
        })?;
    let name = parsed
        .one("name")
        .ok_or_else(|| usage("admit needs --name"))?;
    let ttl = duration(parsed, "ttl")?;
    let registry = registry(log, leader_key(parsed)?);
    let member = registry
        .admit(key, name, ttl, now())
        .map_err(|r| refused(format!("{} ({})", r.message, r.reason)))?;
    write_out(
        out,
        &format!(
            "admitted {} as {}{}; it signs as this node from its next request\n",
            &key_hex(&member.key)[..12],
            member.name,
            member
                .expires_at
                .map(|at| format!(", until {}", iso(at)))
                .unwrap_or_default()
        ),
    )
}

fn list(parsed: &Parsed, log: &Path, out: &mut dyn Write) -> Result<(), Failure> {
    let registry = registry(log, leader_key(parsed)?);
    let at = now();
    let members = registry.members(at);
    let state = |member: &super::members::Member, revoked: &Option<super::members::Revocation>| {
        if revoked.is_some() {
            "revoked"
        } else if member.expired(at) {
            "expired"
        } else {
            "member"
        }
    };
    if parsed.switch("json") {
        let rows = members.iter().map(|(member, revoked, _)| {
            let mut row = member.to_value();
            if let Value::Object(fields) = &mut row {
                fields.insert("state".into(), Value::string(state(member, revoked)));
                fields.insert(
                    "revoked_at".into(),
                    revoked
                        .as_ref()
                        .map(|r| Value::string(iso(r.revoked_at)))
                        .unwrap_or(Value::Null),
                );
                fields.insert(
                    "revoked_reason".into(),
                    revoked
                        .as_ref()
                        .map(|r| Value::string(r.reason.clone()))
                        .unwrap_or(Value::Null),
                );
            }
            row
        });
        return write_out(out, &format!("{}\n", Value::array(rows).canonical_string()));
    }
    if members.is_empty() {
        return write_out(
            out,
            &format!(
                "no members in {}; `cairn fleet invite` makes a token to join with\n",
                registry.dir().display()
            ),
        );
    }
    let mut text = format!(
        "{:<28} {:<12} {:<25} {:<25} STATE\n",
        "NAME", "KEY", "JOINED", "EXPIRES"
    );
    for (member, revoked, _) in &members {
        let mut line = format!(
            "{:<28} {:<12} {:<25} {:<25} {}",
            member.name,
            &key_hex(&member.key)[..12],
            iso(member.joined_at),
            member.expires_at.map(iso).unwrap_or_else(|| "-".into()),
            state(member, revoked)
        );
        if let Some(revocation) = revoked {
            line.push_str(&format!(" {}", iso(revocation.revoked_at)));
            if !revocation.reason.is_empty() {
                line.push_str(&format!(" ({})", revocation.reason));
            }
        }
        text.push_str(line.trim_end());
        text.push('\n');
    }
    write_out(out, &text)
}

fn invites(parsed: &Parsed, log: &Path, out: &mut dyn Write) -> Result<(), Failure> {
    let registry = registry(log, leader_key(parsed)?);
    let at = now();
    let all = registry.invites();
    if parsed.switch("json") {
        let rows = all.iter().map(|(invite, used)| {
            let opt = |v: &Option<String>| v.clone().map(Value::string).unwrap_or(Value::Null);
            Value::object([
                ("invite", Value::string(key_hex(&invite.key))),
                ("created_at", Value::string(iso(invite.created_at))),
                ("expires_at", Value::string(iso(invite.expires_at))),
                ("uses", Value::Int(i128::from(invite.uses))),
                ("used", Value::Int(*used as i128)),
                ("name", opt(&invite.name)),
                ("prefix", opt(&invite.prefix)),
                (
                    "member_ttl_seconds",
                    invite
                        .member_ttl
                        .map(|t| Value::Int(i128::from(t)))
                        .unwrap_or(Value::Null),
                ),
                ("note", opt(&invite.note)),
                (
                    "open",
                    Value::Bool(at < invite.expires_at && *used < invite.uses as usize),
                ),
            ])
        });
        return write_out(out, &format!("{}\n", Value::array(rows).canonical_string()));
    }
    if all.is_empty() {
        return write_out(out, "no invitations outstanding\n");
    }
    let mut text = format!(
        "{:<12} {:<9} {:<25} {:<24} NOTE\n",
        "INVITE", "USED", "EXPIRES", "NAMES"
    );
    for (invite, used) in &all {
        let names = match (&invite.name, &invite.prefix) {
            (Some(name), _) => name.clone(),
            (None, Some(prefix)) => format!("{prefix}-…"),
            (None, None) => "as asked".to_string(),
        };
        let expires = if at >= invite.expires_at {
            "expired".to_string()
        } else {
            iso(invite.expires_at)
        };
        let line = format!(
            "{:<12} {:<9} {:<25} {:<24} {}",
            &key_hex(&invite.key)[..12],
            format!("{used}/{}", invite.uses),
            expires,
            names,
            invite.note.as_deref().unwrap_or("")
        );
        text.push_str(line.trim_end());
        text.push('\n');
    }
    write_out(out, &text)
}

fn revoke(parsed: &Parsed, log: &Path, out: &mut dyn Write) -> Result<(), Failure> {
    let registry = registry(log, leader_key(parsed)?);
    let reason = parsed.one("reason").unwrap_or("");
    let at = now();
    if let Some(text) = parsed.one("invite") {
        if !parsed.positional.is_empty() {
            return Err(usage("revoke takes a member or --invite KEY, not both"));
        }
        let invite = find_invite(&registry, text)?;
        let revoked = registry
            .revoke_invited(&invite, reason, at)
            .map_err(io_failure("cannot write a revocation"))?;
        let withdrawn = registry
            .revoke_invite(&invite)
            .map_err(io_failure("cannot withdraw the invite"))?;
        let mut text = String::new();
        for member in &revoked {
            text.push_str(&format!(
                "revoked {} ({})\n",
                member.name,
                &key_hex(&member.key)[..12]
            ));
        }
        text.push_str(&format!(
            "{} member{} of invite {} revoked; the invite {}\n",
            revoked.len(),
            if revoked.len() == 1 { "" } else { "s" },
            &key_hex(&invite)[..12],
            if withdrawn {
                "is withdrawn"
            } else {
                "was already gone"
            }
        ));
        return write_out(out, &text);
    }
    let [who] = parsed.positional.as_slice() else {
        return Err(usage(
            "revoke needs one member, by name or key, or --invite KEY",
        ));
    };
    let key = match registry.find(who, at) {
        Some(member) => member.key,
        // A key that never joined can be revoked too, so it never will.
        None => parse_key(who).ok_or_else(|| {
            refused(format!(
                "no member is called {who:?}; `cairn fleet list` shows who is"
            ))
        })?,
    };
    let revocation = registry
        .revoke(&key, reason, at)
        .map_err(io_failure("cannot write the revocation"))?;
    write_out(
        out,
        &format!(
            "revoked {} at {}: its next request is refused, and the key can never rejoin\n",
            &key_hex(&key)[..12],
            iso(revocation.revoked_at)
        ),
    )
}

fn revoke_invite(parsed: &Parsed, log: &Path, out: &mut dyn Write) -> Result<(), Failure> {
    let registry = registry(log, leader_key(parsed)?);
    let [text] = parsed.positional.as_slice() else {
        return Err(usage("revoke-invite needs the invite's key"));
    };
    let invite = find_invite(&registry, text)?;
    if registry
        .revoke_invite(&invite)
        .map_err(io_failure("cannot withdraw the invite"))?
    {
        write_out(
            out,
            &format!(
                "invite {} withdrawn: nobody joins with it now. Members it admitted stay; \
                 `cairn fleet revoke --invite {}` removes them\n",
                &key_hex(&invite)[..12],
                key_hex(&invite)
            ),
        )
    } else {
        Err(refused(format!(
            "no invite {} is outstanding",
            &key_hex(&invite)[..12]
        )))
    }
}

/// An invite by its full key, or by a prefix of it that names one.
fn find_invite(registry: &Registry, text: &str) -> Result<Key, Failure> {
    if let Some(key) = parse_key(text) {
        return Ok(key);
    }
    let matching: Vec<Key> = registry
        .invites()
        .into_iter()
        .map(|(invite, _)| invite.key)
        .filter(|key| !text.is_empty() && key_hex(key).starts_with(text))
        .collect();
    match matching.as_slice() {
        [one] => Ok(*one),
        [] => Err(refused(format!(
            "no invite starts {text:?}; `cairn fleet invites` lists them"
        ))),
        _ => Err(refused(format!(
            "{text:?} starts {} invites; give more of the key",
            matching.len()
        ))),
    }
}

// -- the worker's commands ---------------------------------------------------------

/// `$CAIRN_FLEET_FILE`, then `~/.cairn/fleet.json`.
pub fn default_member_file() -> PathBuf {
    if let Some(path) = std::env::var(FILE_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        return PathBuf::from(path.trim());
    }
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".cairn")
        .join("fleet.json")
}

/// This machine's name, as a member name: the first label of its hostname,
/// with anything outside the alphabet made a `-`.
fn host_name() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })?;
    let label = raw.trim().split('.').next().unwrap_or("");
    let name: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(auth::MAX_NAME_CHARS)
        .collect();
    Some(name).filter(|n| auth::valid_name(n))
}

fn join(parsed: &Parsed, out: &mut dyn Write, input: &mut dyn Read) -> Result<(), Failure> {
    let node_text = parsed
        .one("node")
        .ok_or_else(|| usage("join needs --node URL, the leader's HTTP side"))?;
    let node = NodeUrl::parse(node_text).map_err(|e| usage(e.to_string()))?;
    let path = parsed
        .one("out")
        .map(PathBuf::from)
        .unwrap_or_else(default_member_file);
    if path.exists() {
        return Err(refused(format!(
            "{} already holds a membership. Remove it to join again, or pass --out for a \
             second one",
            path.display()
        )));
    }
    if let Some(name) = parsed.one("name") {
        if !auth::valid_name(name) {
            return Err(usage(format!(
                "a member name is letters, digits, '.', '_' and '-', at most {} characters; \
                 {name:?} is not one",
                auth::MAX_NAME_CHARS
            )));
        }
    }
    if parsed.switch("manual") {
        return join_manually(parsed, &node, &path, out);
    }
    if parsed.one("leader").is_some() {
        return Err(usage(
            "--leader is for --manual; a token carries its leader's key already",
        ));
    }
    let token = read_token(parsed, input)?;

    // §5: the wrong node is caught before anything is made. Not a defence
    // against an attacker -- the join is bound to the token's leader, and the
    // member's records will name it whatever this answer says.
    let network = http::get(&node, "/network", NODE_TIMEOUT)
        .map_err(|e| Failure::Unreachable(e.to_string()))?;
    if !network.ok() {
        return Err(Failure::Unreachable(format!(
            "{}: GET /network answered {}",
            node.as_str(),
            network.error_text()
        )));
    }
    check_leader(&network.body, &token.leader, node.as_str())?;

    // A key made by an interrupted join is used again, so a join whose answer
    // was lost is retried with the same key and finds the same membership.
    let pending = pending_path(&path);
    let member = match MemberFile::load(&pending) {
        Ok(file) if file.leader == token.leader => file.member,
        _ => {
            let _ = std::fs::remove_file(&pending);
            let fresh = MemberFile {
                node: node.as_str().to_string(),
                leader: token.leader,
                name: "pending".to_string(),
                member: Identity::generate(&mut OsRng),
                expires_at: None,
            };
            fresh
                .save_new(&pending)
                .map_err(io_failure(&format!("cannot write {}", pending.display())))?;
            fresh.member
        }
    };

    let attempt = |name: &str| -> Result<Response, Failure> {
        let request = JoinRequest::sign(&token.leader, &token.invite(), &member, name, now());
        http::post_json(&node, "/fleet/join", &request.to_value(), NODE_TIMEOUT)
            .map_err(|e| Failure::Unreachable(e.to_string()))
    };
    let mut response = attempt(parsed.one("name").unwrap_or(""))?;
    // An invite that names nobody needs a name; this machine's is the default.
    if parsed.one("name").is_none() && reason(&response) == Some("name_required") {
        if let Some(host) = host_name() {
            response = attempt(&host)?;
        }
    }
    if !response.ok() {
        if response.status < 500 {
            // Refused, and nothing was recorded: the key goes with the attempt.
            let _ = std::fs::remove_file(&pending);
            return Err(refused(format!(
                "{}: {}",
                node.as_str(),
                response.error_text()
            )));
        }
        return Err(Failure::Unreachable(format!(
            "{}: {}; run the same command again to retry with the same key",
            node.as_str(),
            response.error_text()
        )));
    }
    let name = response
        .body
        .get("name")
        .and_then(Value::as_str)
        .filter(|n| auth::valid_name(n))
        .ok_or_else(|| refused(format!("{} answered a join without a name", node.as_str())))?
        .to_string();
    let expires_at = response
        .body
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(crate::time::parse_rfc3339)
        .and_then(|at| u64::try_from(at).ok());
    let file = MemberFile {
        node: node.as_str().to_string(),
        leader: token.leader,
        name,
        member,
        expires_at,
    };
    file.save_new(&path)
        .map_err(io_failure(&format!("cannot write {}", path.display())))?;
    let _ = std::fs::remove_file(&pending);
    write_out(
        out,
        &format!(
            "joined {} as {}{}.\nmember file: {} (mode 0600; it holds this machine's key)\n\n  \
             cairn work --fleet {} --objective <id> [--worker gpu0] -- <your walker>\n",
            node.as_str(),
            file.name,
            expires_at
                .map(|at| format!(", until {}", iso(at)))
                .unwrap_or_default(),
            path.display(),
            path.display()
        ),
    )
}

fn reason(response: &Response) -> Option<&str> {
    response.body.get("reason").and_then(Value::as_str)
}

/// The leader `GET /network` describes must be the token's, taking members.
fn check_leader(network: &Value, leader: &Key, node: &str) -> Result<(), Failure> {
    let fleet = network.get("node").and_then(|n| n.get("fleet"));
    let signs_as = fleet
        .and_then(|f| f.get("signs_as"))
        .and_then(Value::as_str);
    if signs_as != Some(key_hex(leader).as_str()) {
        return Err(refused(match signs_as {
            Some(other) => format!(
                "{node} signs as {other}, and this token is for {}: the wrong node, or a token \
                 for another leader",
                key_hex(leader)
            ),
            None => format!(
                "{node} leads no fleet (its CAIRN_FLEET is unset); this token is for {}",
                key_hex(leader)
            ),
        }));
    }
    let enrolled = fleet
        .and_then(|f| f.get("sources"))
        .and_then(Value::as_array)
        .is_some_and(|sources| sources.iter().any(|s| s.as_str() == Some("enrolled")));
    if !enrolled {
        return Err(refused(format!(
            "{node} leads a fleet by network only; its operator adds `enrolled` to CAIRN_FLEET \
             before a member can join"
        )));
    }
    Ok(())
}

fn pending_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".pending");
    path.with_file_name(name)
}

fn read_token(parsed: &Parsed, input: &mut dyn Read) -> Result<Token, Failure> {
    let text = match parsed.positional.as_slice() {
        [] => std::env::var(INVITE_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                usage(format!(
                    "join needs the token: as the last argument, `-` to read it from stdin, \
                     or in ${INVITE_ENV}"
                ))
            })?,
        [dash] if dash == "-" => {
            let mut text = String::new();
            input
                .take(4096)
                .read_to_string(&mut text)
                .map_err(|e| refused(format!("cannot read the token from stdin: {e}")))?;
            text
        }
        [token] => token.clone(),
        _ => return Err(usage("join takes one token")),
    };
    Token::parse(&text).map_err(|r| usage(r.message))
}

fn join_manually(
    parsed: &Parsed,
    node: &NodeUrl,
    path: &Path,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    if !parsed.positional.is_empty() {
        return Err(usage(
            "--manual takes no token: the operator admits the key by hand",
        ));
    }
    let leader = parsed
        .one("leader")
        .ok_or_else(|| usage("--manual needs --leader KEY, the leader's signs_as"))
        .and_then(|text| {
            parse_key(text).ok_or_else(|| usage("--leader needs 64 lowercase hex characters"))
        })?;
    let name = parsed
        .one("name")
        .ok_or_else(|| usage("--manual needs --name, the name the operator will admit"))?;
    let file = MemberFile {
        node: node.as_str().to_string(),
        leader,
        name: name.to_string(),
        member: Identity::generate(&mut OsRng),
        expires_at: None,
    };
    file.save_new(path)
        .map_err(io_failure(&format!("cannot write {}", path.display())))?;
    write_out(
        out,
        &format!(
            "member file: {} (mode 0600; it holds this machine's key)\n\nOn the leader, run:\n\n  \
             cairn fleet admit --key {} --name {name}\n",
            path.display(),
            file.member.submitter_id()
        ),
    )
}

fn sign(parsed: &Parsed, out: &mut dyn Write, input: &mut dyn Read) -> Result<(), Failure> {
    let path = parsed
        .one("member")
        .map(PathBuf::from)
        .unwrap_or_else(default_member_file);
    let file = MemberFile::load(&path).map_err(refused)?;
    let method = parsed.one("method").unwrap_or("POST");
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(usage(format!(
            "--method is an HTTP method such as POST, not {method:?}"
        )));
    }
    let target = parsed
        .one("target")
        .filter(|t| t.starts_with('/') && !t.bytes().any(|b| b.is_ascii_whitespace()))
        .ok_or_else(|| {
            usage(
                "--target needs the request-target exactly as the request line will carry it, \
                   such as /submit or /progress",
            )
        })?;
    let mut body = Vec::new();
    input
        .take(MAX_SIGNED_BODY + 1)
        .read_to_end(&mut body)
        .map_err(|e| refused(format!("cannot read the body from stdin: {e}")))?;
    if body.len() as u64 > MAX_SIGNED_BODY {
        return Err(refused(format!(
            "the body is past {MAX_SIGNED_BODY} bytes, more than a node accepts"
        )));
    }
    write_out(
        out,
        &format!("{}\n", file.authorize(now(), method, target, &body)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "cairn-fleet-cli-{tag}-{}-{}",
                std::process::id(),
                now()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn call(list: &[&str], log: &Path, stdin: &[u8]) -> (Result<(), Failure>, String) {
        let mut out = Vec::new();
        let mut input = stdin;
        let result = run(&args(list), log, &mut out, &mut input);
        (result, String::from_utf8(out).unwrap())
    }

    #[test]
    fn durations_read_seconds_and_four_units() {
        assert_eq!(parse_duration("90"), Some(90));
        assert_eq!(parse_duration("90s"), Some(90));
        assert_eq!(parse_duration("15m"), Some(900));
        assert_eq!(parse_duration("12h"), Some(43_200));
        assert_eq!(parse_duration("7d"), Some(604_800));
        for bad in ["", "h", "1.5h", "-3", "3w", "12 h"] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_operator_invites_admits_lists_and_revokes_without_a_network() {
        let scratch = Scratch::new("operator");
        let log = scratch.0.join("cairn.jsonl");
        let leader = Identity::from_secret_bytes([1; 32]).submitter_id();

        let (result, text) = call(
            &[
                "invite", "--leader", &leader, "--prefix", "rented", "--uses", "3", "--json",
            ],
            &log,
            b"",
        );
        result.unwrap();
        let invite = Value::from_json(text.trim()).unwrap();
        let token = Token::parse(invite.get("token").unwrap().as_str().unwrap()).unwrap();
        assert_eq!(key_hex(&token.leader), leader);
        assert_eq!(invite.get("uses").unwrap().as_u64(), Some(3));
        assert!(invite
            .get("join")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with("cairn fleet join --node http://LEADER:8080 cairn-invite1."));

        // Without a leader key there is nothing to put in a token.
        assert!(matches!(
            call(&["invite"], &log, b"").0,
            Err(Failure::Usage(_))
        ));
        assert!(matches!(
            call(
                &["invite", "--leader", &leader, "--name", "a", "--uses", "2"],
                &log,
                b""
            )
            .0,
            Err(Failure::Usage(_))
        ));
        assert!(matches!(
            call(
                &["invite", "--leader", &leader, "--prefix", &"p".repeat(28)],
                &log,
                b""
            )
            .0,
            Err(Failure::Usage(_))
        ));

        let member = Identity::from_secret_bytes([4; 32]).submitter_id();
        let (result, text) = call(
            &[
                "admit", "--key", &member, "--name", "desk-box", "--ttl", "1h",
            ],
            &log,
            b"",
        );
        result.unwrap();
        assert!(text.contains("desk-box"), "{text}");

        let (result, text) = call(&["list"], &log, b"");
        result.unwrap();
        assert!(
            text.contains("desk-box") && text.contains("member"),
            "{text}"
        );
        let (result, text) = call(&["invites"], &log, b"");
        result.unwrap();
        assert!(text.contains("0/3") && text.contains("rented-…"), "{text}");

        let (result, _) = call(&["revoke", "desk-box", "--reason", "returned"], &log, b"");
        result.unwrap();
        let (result, text) = call(&["list", "--json"], &log, b"");
        result.unwrap();
        let rows = Value::from_json(text.trim()).unwrap();
        let row = &rows.as_array().unwrap()[0];
        assert_eq!(row.get("state").unwrap().as_str(), Some("revoked"));
        assert_eq!(
            row.get("revoked_reason").unwrap().as_str(),
            Some("returned")
        );

        let prefix = &invite.get("invite").unwrap().as_str().unwrap()[..10];
        let (result, text) = call(&["revoke-invite", prefix], &log, b"");
        result.unwrap();
        assert!(text.contains("withdrawn"), "{text}");
        assert!(matches!(
            call(&["revoke-invite", prefix], &log, b"").0,
            Err(Failure::Refused(_))
        ));
        assert!(matches!(
            call(&["revoke", "nobody"], &log, b"").0,
            Err(Failure::Refused(_))
        ));
    }

    #[test]
    fn a_manual_join_writes_the_file_and_prints_the_admit_line() {
        let scratch = Scratch::new("manual");
        let path = scratch.0.join("member.json");
        let leader = Identity::from_secret_bytes([1; 32]).submitter_id();
        let path_text = path.display().to_string();
        let (result, text) = call(
            &[
                "join",
                "--manual",
                "--node",
                "http://203.0.113.7:8080",
                "--leader",
                &leader,
                "--name",
                "gpu-box-1",
                "--out",
                &path_text,
            ],
            Path::new("unused.jsonl"),
            b"",
        );
        result.unwrap();
        let file = MemberFile::load(&path).unwrap();
        assert_eq!(file.name, "gpu-box-1");
        assert_eq!(key_hex(&file.leader), leader);
        assert!(text.contains(&format!(
            "cairn fleet admit --key {} --name gpu-box-1",
            file.member.submitter_id()
        )));
        // A second join must not replace the key the operator is about to admit.
        assert!(matches!(
            call(
                &[
                    "join",
                    "--manual",
                    "--node",
                    "http://203.0.113.7:8080",
                    "--leader",
                    &leader,
                    "--name",
                    "gpu-box-1",
                    "--out",
                    &path_text,
                ],
                Path::new("unused.jsonl"),
                b"",
            )
            .0,
            Err(Failure::Refused(_))
        ));

        // `sign` builds the request string from its own flags and the body.
        let (result, header) = call(
            &["sign", "--member", &path_text, "--target", "/progress"],
            Path::new("unused.jsonl"),
            b"{}",
        );
        result.unwrap();
        let auth = auth::MemberAuth::parse(header.trim()).unwrap();
        auth.verify(&file.leader, "POST", "/progress", b"{}")
            .unwrap();
        assert!(matches!(
            call(
                &["sign", "--member", &path_text, "--target", "progress"],
                Path::new("unused.jsonl"),
                b"{}",
            )
            .0,
            Err(Failure::Usage(_))
        ));
    }

    #[test]
    fn the_leader_check_names_the_wrong_node_and_a_fleet_without_members() {
        let leader = [7u8; 32];
        let network = |signs_as: &str, sources: &[&str]| {
            Value::object([(
                "node",
                Value::object([(
                    "fleet",
                    Value::object([
                        ("signs_as", Value::string(signs_as)),
                        (
                            "sources",
                            Value::array(sources.iter().map(|s| Value::string(*s))),
                        ),
                    ]),
                )]),
            )])
        };
        check_leader(&network(&key_hex(&leader), &["enrolled"]), &leader, "n").unwrap();
        let wrong = check_leader(&network(&"ab".repeat(32), &["enrolled"]), &leader, "n");
        assert!(matches!(wrong, Err(Failure::Refused(m)) if m.contains("wrong node")));
        let by_network = check_leader(&network(&key_hex(&leader), &["10.0.0.0/8"]), &leader, "n");
        assert!(matches!(by_network, Err(Failure::Refused(m)) if m.contains("enrolled")));
        let none = check_leader(
            &Value::object([("node", Value::Object(Default::default()))]),
            &leader,
            "n",
        );
        assert!(matches!(none, Err(Failure::Refused(m)) if m.contains("leads no fleet")));
    }
}
