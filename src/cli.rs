//! The long-running and tool entry points, as `cairn` subcommands.
//!
//! These used to be separate binaries -- `cairn-p2p`, `cairn-serve`,
//! `cairn-gen-bootstrap`, `arena`, and `cairn-mcp` -- each with its own
//! `main`, its own argument loop, and its own idea of where the log lives.
//! They now live behind one binary for one reason: an operator, a script, an
//! MCP client stanza, and a release tarball all had to know five names and
//! keep them in step, and a release that shipped four of the five was not
//! detectably wrong until something dialled the missing one.
//!
//! Each function here takes the tokens that followed its subcommand name and
//! the [`Globals`] the `cairn` parser already resolved -- `--log`, `--root`,
//! `--data-dir`, `--key-file`, given *before* the command -- and uses them as
//! defaults. The same flags are still accepted *after* the subcommand too, so
//! a stanza written for `cairn-mcp --log X --root Y` becomes `cairn mcp --log
//! X --root Y` by changing the binary name and nothing else.
//!
//! Exit codes are the ones the binaries used: `--help` exits 0, a bad or
//! missing argument exits 2, and a startup failure the operator has to fix
//! exits 2 (daemons) or 1 (the publisher). `cmd --help >/dev/null || fail` is
//! how a packaging check asks whether a subcommand runs at all, and that
//! contract is kept.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::canonical::Value;
use crate::daemon::{self, Config};
use crate::p2p::handshake::PeerIdentity;
use crate::serve::{self, Serving};

/// What the `cairn` parser resolved before it reached the subcommand.
#[derive(Debug, Clone)]
pub struct Globals {
    /// The ledger, from `--log`, `$CAIRN_LOG_PATH`, `--data-dir`, or the
    /// default.
    pub log: PathBuf,
    /// The bundle root pinned verifier paths resolve against.
    pub root: PathBuf,
    /// An explicit at-rest key file, if one was named.
    pub key_file: Option<PathBuf>,
}

/// Print `text` to stderr and exit with `code`.
///
/// `-> !` so it composes as `unwrap_or_else(|| usage(...))` the way the old
/// binaries' `usage` did. Exiting from inside a subcommand rather than
/// returning a code keeps every one of those call sites one expression; the
/// standard library flushes stdout on the way out, so nothing already printed
/// is lost.
fn exit_with(code: i32, text: &str) -> ! {
    eprintln!("{text}");
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// mcp
// ---------------------------------------------------------------------------

/// `cairn mcp`: the standalone MCP server over stdio, owning its own ledger.
///
/// The combined node (`cairn run`) serves the same protocol from the daemon's
/// process; this one is for an agent that should work on a log that is
/// intentionally offline from the network.
pub fn mcp(args: Vec<String>, globals: Globals) -> i32 {
    crate::mcp::standalone(args, globals)
}

// ---------------------------------------------------------------------------
// p2p
// ---------------------------------------------------------------------------

fn p2p_usage(code: i32) -> ! {
    exit_with(
        code,
        "cairn p2p — a cairn node: p2p sync, and optionally HTTP\n\n\
         USAGE\n    \
         cairn [--log FILE] [--root DIR] p2p --identity FILE --root-key FILE\n              \
         --checkpoint FILE --listen ADDR\n              \
         [--bootstrap FILE ...] [--population FILE] [--queue DIR]\n              \
         [--fanout N] [--serve ADDR] [--max-queue N] [--key-file FILE]\n              \
         [--proxy URL]\n\n\
         --identity    peer identity; generated on first use if absent\n\
         --root-key    checkpoint signing key; generated on first use if absent\n\
         --checkpoint  where the signed checkpoint is written each round\n\
         --listen      p2p listen address, e.g. 0.0.0.0:9000\n\
         --log         the append-only log; opened exclusively, this is a writer\n\
         --root        bundle root pinned verifier paths resolve against\n\
         --bootstrap   a dial hint; repeatable\n\
         --population  gossip population file; omit to sync records only\n\
         --queue       submission spool, drained each round by this process\n\
         --fanout      peers dialled per round\n\
         --serve       ALSO publish the log over HTTP from this process\n\
         --max-queue   refuse submissions past this many undrained records\n\
         --key-file    at-rest key for a sealed log (default: the CLI's own)\n\
         --proxy       route every dial through a SOCKS5 proxy, e.g.\n              \
         socks5://127.0.0.1:9050 for a Tor client or obfs4 bridge\n\n\
         With --serve this is a whole node in one process: it holds the log's\n\
         write lock, so it is the only thing that *can* admit what it queues.\n\
         The complete node with MCP and the embedded reader is `cairn run`.",
    );
}

/// `cairn p2p`: the daemon alone, with no reader and no MCP.
pub fn p2p(args: Vec<String>, globals: Globals) -> i32 {
    // Before anything that could log. Stderr only -- see `logging`.
    crate::logging::init();

    let mut identity = None;
    let mut root_key = None;
    let mut checkpoint = None;
    let mut listen = None;
    let mut log = Some(globals.log.display().to_string());
    let mut root = Some(globals.root.display().to_string());
    let mut population = None;
    let mut queue = None;
    let mut fanout = None;
    let mut serve = None;
    let mut max_queue = None;
    let mut key_file = globals.key_file.map(|p| p.display().to_string());
    let mut proxy = None;
    let mut bootstrap = Vec::new();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--identity" => &mut identity,
            "--root-key" => &mut root_key,
            "--checkpoint" => &mut checkpoint,
            "--listen" => &mut listen,
            "--log" => &mut log,
            "--root" => &mut root,
            "--population" => &mut population,
            "--queue" => &mut queue,
            "--fanout" => &mut fanout,
            "--serve" => &mut serve,
            "--max-queue" => &mut max_queue,
            "--key-file" => &mut key_file,
            "--proxy" => &mut proxy,
            "--bootstrap" => {
                bootstrap.push(args.next().unwrap_or_else(|| p2p_usage(2)));
                continue;
            }
            "--help" | "-h" => p2p_usage(0),
            _ => p2p_usage(2),
        };
        *slot = Some(args.next().unwrap_or_else(|| p2p_usage(2)));
    }

    let listen: SocketAddr = listen
        .unwrap_or_else(|| p2p_usage(2))
        .parse()
        .unwrap_or_else(|_| p2p_usage(2));
    let mut config = Config::new(
        identity.unwrap_or_else(|| p2p_usage(2)),
        root_key.unwrap_or_else(|| p2p_usage(2)),
        checkpoint.unwrap_or_else(|| p2p_usage(2)),
        listen,
        log.unwrap_or_else(|| p2p_usage(2)),
        root.unwrap_or_else(|| p2p_usage(2)),
    );
    config.bootstrap = bootstrap.into_iter().map(PathBuf::from).collect();
    config.population = population.map(PathBuf::from);
    config.queue = queue.map(PathBuf::from);
    config.serve = serve;
    config.key_file = key_file.map(PathBuf::from);
    config.proxy = proxy;
    if let Some(text) = fanout {
        config.fanout = text.parse().unwrap_or_else(|_| p2p_usage(2));
    }
    if let Some(text) = max_queue {
        // Refused rather than clamped: an operator who typed a bound wants that
        // bound, and silently substituting one hides a full queue behind a
        // number they never chose.
        match text.parse::<usize>() {
            Ok(value) if value > 0 => config.max_queued = value,
            _ => exit_with(2, "cairn p2p: --max-queue needs a positive integer"),
        }
    }

    // `run` returns only on a startup failure the operator has to fix, so
    // there is no success path to fall through to.
    if let Err(error) = daemon::run(config) {
        log::error!("{error}");
        return 2;
    }
    0
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

fn serve_usage(code: i32) -> ! {
    exit_with(
        code,
        "cairn serve — publish a cairn log over HTTP\n\n\
         USAGE\n    \
         cairn [--log <path>] [--root <dir>] serve [--listen <addr>]\n                \
         [--queue <dir>] [--checkpoint <path>]\n\n\
         --log         the append-only log to publish (default cairn.jsonl)\n\
         --root        bundle root pinned verifier paths resolve against (default .)\n\
         --listen      address to bind (default 127.0.0.1:8080)\n\
         --queue       accept POST /submit into this spool directory; omit for read-only\n\
         --max-queue   refuse submissions past this many undrained records\n\
         --checkpoint  signed checkpoint to publish at GET /checkpoint\n\
         --key-file    at-rest key, if the log is sealed (default: the CLI's own)\n\n\
         ALSO BE A NODE\n    \
         Add --p2p-listen and this runs the p2p daemon in the same process,\n    \
         which is what lets it admit what it queues -- a log has one writer.\n\n\
         --p2p-listen  p2p listen address, e.g. 0.0.0.0:9000\n\
         --identity    peer identity; required with --p2p-listen\n\
         --root-key    checkpoint signing key; required with --p2p-listen\n\
         --bootstrap   a dial hint; repeatable\n\
         --population  gossip population file\n\
         --fanout      peers dialled per round\n\n\
         Everything served is public by design. Without --p2p-listen,\n\
         submissions are queued and never admitted: drain them into the log\n\
         with `cairn drain --queue <dir>`.",
    );
}

/// `cairn serve`: publish a log over HTTP, and optionally be the node too.
///
/// Without `--p2p-listen` this is a *publisher*: it takes no lock, holds no
/// `Node`, and re-reads the log per request, so it is safe to point at a log
/// another process is writing. With `--p2p-listen` it is the whole node,
/// running [`crate::daemon::run`] with the HTTP server on a thread.
pub fn serve(args: Vec<String>, globals: Globals) -> i32 {
    crate::logging::init();
    let mut log = globals.log;
    let mut root = globals.root;
    let mut listen = String::from("127.0.0.1:8080");
    let mut queue: Option<PathBuf> = None;
    let mut checkpoint: Option<PathBuf> = None;
    let mut max_queue = serve::DEFAULT_MAX_QUEUED;
    let mut key_file: Option<PathBuf> = globals.key_file;

    // The p2p half. All absent is the ordinary publisher.
    let mut p2p_listen: Option<String> = None;
    let mut identity: Option<PathBuf> = None;
    let mut root_key: Option<PathBuf> = None;
    let mut population: Option<PathBuf> = None;
    let mut fanout: Option<String> = None;
    let mut bootstrap: Vec<PathBuf> = Vec::new();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut next = |what: &str| match args.next() {
            Some(value) => value,
            None => exit_with(2, &format!("cairn serve: {what} needs a value")),
        };
        match arg.as_str() {
            "--log" => log = PathBuf::from(next("--log")),
            "--root" => root = PathBuf::from(next("--root")),
            "--listen" => listen = next("--listen"),
            "--queue" => queue = Some(PathBuf::from(next("--queue"))),
            "--max-queue" => {
                let raw = next("--max-queue");
                match raw.parse::<usize>() {
                    Ok(value) if value > 0 => max_queue = value,
                    // Refused rather than clamped: an operator who typed a
                    // bound wants that bound, and silently substituting one
                    // hides a full queue behind a number they never chose.
                    _ => exit_with(2, "cairn serve: --max-queue needs a positive integer"),
                }
            }
            "--checkpoint" => checkpoint = Some(PathBuf::from(next("--checkpoint"))),
            "--key-file" => key_file = Some(PathBuf::from(next("--key-file"))),
            "--p2p-listen" => p2p_listen = Some(next("--p2p-listen")),
            "--identity" => identity = Some(PathBuf::from(next("--identity"))),
            "--root-key" => root_key = Some(PathBuf::from(next("--root-key"))),
            "--population" => population = Some(PathBuf::from(next("--population"))),
            "--fanout" => fanout = Some(next("--fanout")),
            "--bootstrap" => bootstrap.push(PathBuf::from(next("--bootstrap"))),
            "--help" | "-h" => serve_usage(0),
            other => {
                eprintln!("cairn serve: unknown argument {other:?}");
                serve_usage(2);
            }
        }
    }

    // -- node mode ----------------------------------------------------------

    if let Some(addr) = p2p_listen {
        let addr: SocketAddr = addr
            .parse()
            .unwrap_or_else(|_| exit_with(2, "cairn serve: --p2p-listen needs host:port"));
        // Named individually rather than as one "missing options" error: an
        // operator who forgot the root key wants to be told which one.
        let identity = identity
            .unwrap_or_else(|| exit_with(2, "cairn serve: --p2p-listen also needs --identity"));
        let root_key = root_key
            .unwrap_or_else(|| exit_with(2, "cairn serve: --p2p-listen also needs --root-key"));
        // A daemon *writes* its checkpoint every round, so unlike the publisher
        // this is not optional -- there would be nowhere to put it.
        let checkpoint = checkpoint.unwrap_or_else(|| {
            exit_with(
                2,
                "cairn serve: --p2p-listen also needs --checkpoint to write",
            )
        });

        let mut config = Config::new(identity, root_key, checkpoint, addr, log, root);
        config.bootstrap = bootstrap;
        config.population = population;
        config.queue = queue;
        config.serve = Some(listen);
        config.max_queued = max_queue;
        config.key_file = key_file;
        if let Some(text) = fanout {
            config.fanout = text
                .parse()
                .unwrap_or_else(|_| exit_with(2, "cairn serve: --fanout needs a positive integer"));
        }
        if let Err(error) = daemon::run(config) {
            log::error!("{error}");
            return 2;
        }
        return 0;
    }

    // -- publisher ----------------------------------------------------------

    for (flag, given) in [
        ("--identity", identity.is_some()),
        ("--root-key", root_key.is_some()),
        ("--population", population.is_some()),
        ("--fanout", fanout.is_some()),
        ("--bootstrap", !bootstrap.is_empty()),
    ] {
        // Refused, not ignored. Every one of these is somebody trying to run a
        // node, and a publisher that silently dropped them would take no lock,
        // dial nobody and drain nothing while looking like it had started.
        if given {
            exit_with(
                2,
                &format!("cairn serve: {flag} has no effect without --p2p-listen"),
            );
        }
    }

    // The CLI's own default when no flag was given, so a publisher on a machine
    // that ran `cairn keygen` opens the same logs the CLI writes.
    // `resolve_codec` treats an absent key file as plaintext, so naming a path
    // that does not exist costs nothing.
    let key_path = key_file.unwrap_or_else(|| crate::store::Store::new(&root).default_key_path());
    let mut serving = Serving::new(&log, &root).with_key(key_path, None);
    if let Some(dir) = queue {
        serving = serving.accepting_into(dir).with_max_queued(max_queue);
    }
    if let Some(path) = checkpoint {
        serving = serving.with_checkpoint(path);
    }

    // Separately from `listen`, which also checks: this one owns the message.
    // Folded together, a missing key file was reported as "cannot listen on
    // 127.0.0.1:8080", which sends an operator to check the port.
    if let Err(error) = serving.check_startup() {
        eprintln!("cairn serve: {error}");
        return 1;
    }
    if let Err(error) = serve::listen(&listen, serving) {
        eprintln!("cairn serve: cannot listen on {listen}: {error}");
        return 1;
    }
    0
}

// ---------------------------------------------------------------------------
// gen-bootstrap
// ---------------------------------------------------------------------------

fn gen_bootstrap_usage(code: i32) -> ! {
    exit_with(
        code,
        "usage: cairn gen-bootstrap --addr HOST:PORT --out FILE [--identity-out FILE]",
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A host and a port, without deciding what the host means.
///
/// `[::1]:9000` splits at the last colon, which is why this uses `rsplit_once`
/// rather than counting them.
fn is_host_port(addr: &str) -> bool {
    match addr.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0),
        None => false,
    }
}

/// `cairn gen-bootstrap`: write a `--bootstrap` file for `cairn p2p`.
///
/// A bootstrap file is canonical JSON of the form
/// `{"addr":"host:port","public":"<hex McEliece public key>"}` (see
/// `docs/p2p.md`). The address is only ever a hint -- `p2p::handshake`
/// authenticates the *key*, not the socket it answered on -- so this cannot
/// make a real remote peer trustworthy. What it can do is produce a
/// structurally valid file for an address you intend to point at, with a
/// freshly generated keypair standing in until you have the peer's real
/// public key to swap in. The matching secret is written alongside on
/// request so the file pair is a usable identity for a second local node.
pub fn gen_bootstrap(args: Vec<String>) -> i32 {
    let mut addr = None;
    let mut out = None;
    let mut identity_out = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            gen_bootstrap_usage(0);
        }
        let slot = match arg.as_str() {
            "--addr" => &mut addr,
            "--out" => &mut out,
            "--identity-out" => &mut identity_out,
            _ => gen_bootstrap_usage(2),
        };
        *slot = Some(args.next().unwrap_or_else(|| gen_bootstrap_usage(2)));
    }
    let addr = addr.unwrap_or_else(|| gen_bootstrap_usage(2));
    let out = out.unwrap_or_else(|| gen_bootstrap_usage(2));
    // Shape only, and deliberately not `SocketAddr::parse`: this writes config
    // for a host that may be down, or not yet built, so resolving here would
    // refuse a perfectly good file for a peer that is merely offline. A
    // hostname is a legal address everywhere it is dialled -- see
    // `p2p::discovery::dialable` -- and the usage line says HOST:PORT.
    if !is_host_port(&addr) {
        eprintln!("--addr {addr:?} is not a host:port address");
        return 2;
    }

    let identity = PeerIdentity::generate();
    let public_hex = hex_encode(identity.public_key());

    // `placeholder_peer_id` is what lets the *daemon* say this file is not
    // finished yet, rather than only this command saying it once at generation
    // time and scrolling away in build output. A peer id is
    // `sha256(public key)`, so the daemon recomputes it from whatever `public`
    // currently holds and warns only while the two still match -- which means
    // the warning **clears itself** the moment somebody pastes the real key
    // in, with nothing to remember to delete. Extra fields are ignored by
    // every reader (`load_endpoint` takes `addr` and `public`), and a
    // bootstrap file is local configuration that never enters the log, so
    // this is not a record-format change.
    let bootstrap = Value::object([
        ("addr", Value::string(addr)),
        ("public", Value::string(public_hex.clone())),
        (
            "placeholder_peer_id",
            Value::string(crate::p2p::discovery::peer_id_string(
                &identity.to_public().id(),
            )),
        ),
    ]);
    if let Err(e) = std::fs::write(&out, bootstrap.canonical_string()) {
        eprintln!("{out}: {e}");
        return 2;
    }
    eprintln!("wrote bootstrap file: {out}");

    if let Some(identity_out) = identity_out {
        let identity_value = Value::object([
            ("public", Value::string(public_hex)),
            ("secret", Value::string(hex_encode(identity.secret_key()))),
        ]);
        if let Err(e) = crate::secret_file::write_new(
            Path::new(&identity_out),
            identity_value.canonical_string().as_bytes(),
        ) {
            eprintln!("{identity_out}: {e}");
            return 2;
        }
        eprintln!("wrote matching identity file: {identity_out}");
    }

    eprintln!(
        "note: this key is freshly generated, not the real seed peer's -- \
         replace \"public\" in {out} with the seed's actual public key once you have it, \
         or run the seed's own `cairn p2p --identity {out}` pointed here if you \
         control that host."
    );
    0
}

// ---------------------------------------------------------------------------
// seeds
// ---------------------------------------------------------------------------

// The published URL is deliberately *not* a constant here. This binary never
// fetches it -- `scripts/seeds-fetch.sh` does, and the Makefile has its own
// overridable copy -- so a third one in the crate would be a value that can
// drift from the two that are used, with nothing checking it against them.

/// Largest key file this will read, in bytes.
///
/// A transport key is 261,120 bytes and its hex is exactly 522,240 characters,
/// so anything past that is not a key file and there is no reason to hold it in
/// memory to find out. The fetch script is pointed at a URL a stranger controls
/// and this is the thing that reads what it downloaded.
const MAX_KEY_FILE: u64 = 600_000;

fn seeds_usage(code: i32) -> ! {
    exit_with(
        code,
        "usage: cairn seeds resolve --list FILE [--keys DIR] --out DIR\n       \
         cairn seeds publish --identity FILE --out DIR\n\n\
         resolve  check a downloaded seed list against its key files and write a\n         \
           --bootstrap file for every entry that verifies. Refuses the rest.\n\
         publish  write this node's own <transport>.key, to be added to the list\n         \
           by pull request.\n\n\
         The list is fetched by ./scripts/seeds-fetch.sh, not by this binary:\n\
         tests/cipher_policy.rs fails the build if a TLS crate enters the tree,\n\
         and an HTTP client is how one arrives. Same split as the drand beacon.",
    )
}

/// `cairn seeds`: turn a published seed list into bootstrap files, or publish
/// this node's key into one.
///
/// # Why the fetch is not here
///
/// `tests/cipher_policy.rs` fails the build if a TLS crate is in the resolved
/// dependency tree, and an HTTP client is the usual way one arrives -- that
/// test's own docs say so. `scripts/drand-beacon.sh` already settled the shape
/// this takes: the shell does the transport, the binary does the checking, and
/// the check is the part that had to be testable. So this reads local files
/// that something else downloaded, and cannot be talked into a network request.
///
/// # What verification means here, and what it does not
///
/// A key file is named for the peer id of the key inside it, and a peer id
/// **is** `sha256(public key)`. So `resolve` decodes the hex, hands it to
/// [`crate::p2p::handshake::PeerPublic::from_bytes`] -- which derives the id
/// itself rather than taking one on trust -- and refuses the file unless the
/// derived id is the name it arrived under. That check needs no trust in
/// whoever served it: a hostile mirror can withhold a key or serve a different
/// one, and cannot serve a *different key under the same name*.
///
/// What it does not do is make the address trustworthy, and nothing can. The
/// address is a dial hint; the handshake authenticates the key. An attacker who
/// controls the list can send every new node to a machine of their choosing --
/// and that machine cannot complete a handshake as the seed, so the cost is a
/// wasted dial and a node that is still looking. That is the same bound a
/// hostile DNS answer gets in `p2p::discovery::dialable`, and it is why this
/// file is safe to publish somewhere nobody has to trust.
pub fn seeds(args: Vec<String>) -> i32 {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some("resolve") => seeds_resolve(args.collect()),
        Some("publish") => seeds_publish(args.collect()),
        Some("-h") | Some("--help") => seeds_usage(0),
        Some(other) => {
            eprintln!("seeds: unknown verb {other:?}");
            seeds_usage(2)
        }
        None => seeds_usage(2),
    }
}

/// One entry's outcome, so the summary can say what was skipped and why rather
/// than printing a count.
enum Resolved {
    Wrote(String),
    Refused { name: String, why: String },
}

fn seeds_resolve(args: Vec<String>) -> i32 {
    let mut list: Option<String> = None;
    let mut keys: Option<String> = None;
    let mut out: Option<String> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            seeds_usage(0);
        }
        let slot = match arg.as_str() {
            "--list" => &mut list,
            "--keys" => &mut keys,
            "--out" => &mut out,
            _ => {
                eprintln!("seeds resolve: unknown option {arg:?}");
                seeds_usage(2)
            }
        };
        *slot = Some(args.next().unwrap_or_else(|| seeds_usage(2)));
    }
    let list = PathBuf::from(list.unwrap_or_else(|| seeds_usage(2)));
    let out = PathBuf::from(out.unwrap_or_else(|| seeds_usage(2)));
    // The key files sit beside the list unless told otherwise, because that is
    // how they are published and how the fetch script downloads them.
    let keys = keys.map(PathBuf::from).unwrap_or_else(|| {
        list.parent()
            .unwrap_or_else(|| Path::new("."))
            .join("seeds")
    });

    let text = match std::fs::read_to_string(&list) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("{}: {e}", list.display());
            return 2;
        }
    };
    let value = match Value::from_json(&text) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("{}: {e}", list.display());
            return 2;
        }
    };
    let entries = match value.get("seeds").and_then(Value::as_array) {
        Some(entries) => entries,
        None => {
            eprintln!("{}: no \"seeds\" array", list.display());
            return 2;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("{}: {e}", out.display());
        return 2;
    }

    let mut results = Vec::new();
    for entry in entries {
        results.push(resolve_one(entry, &keys, &out));
    }

    let mut wrote = 0usize;
    for result in &results {
        match result {
            Resolved::Wrote(path) => {
                wrote += 1;
                eprintln!("verified: {path}");
            }
            // Every refusal is printed. A seed list is edited by strangers via
            // pull request and downloaded over a network, so "three of four
            // entries were silently dropped" is the state an operator most
            // needs to be able to see -- and a count would not name which.
            Resolved::Refused { name, why } => eprintln!("refused {name}: {why}"),
        }
    }
    if wrote == 0 {
        eprintln!(
            "no seed in {} verified, so nothing was written to {}. \
             A list with no published transport keys is a list of addresses, and an \
             address authenticates nobody -- see docs/discovery.md.",
            list.display(),
            out.display()
        );
        return 1;
    }
    eprintln!(
        "wrote {wrote} bootstrap file(s) to {}; pass each with --bootstrap",
        out.display()
    );
    0
}

fn resolve_one(entry: &Value, keys: &Path, out: &Path) -> Resolved {
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>")
        .to_string();
    // A name becomes a filename, so it may not steer the write anywhere. The
    // list is fetched from a URL and edited by pull request; `../../.ssh` in a
    // `name` would otherwise be a file write chosen by whoever served it.
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Resolved::Refused {
            name,
            why: "name must be non-empty and only letters, digits, - and _".into(),
        };
    }
    let Some(addr) = entry.get("addr").and_then(Value::as_str) else {
        return Resolved::Refused {
            name,
            why: "no addr: an HTTP-only entry is for the site to read, not to dial".into(),
        };
    };
    let Some(transport) = entry.get("transport").and_then(Value::as_str) else {
        return Resolved::Refused {
            name,
            why: "no transport key published, so nothing here can authenticate it".into(),
        };
    };
    if transport.len() != 64 || !transport.chars().all(|c| c.is_ascii_hexdigit()) {
        return Resolved::Refused {
            name,
            why: format!("transport {transport:?} is not a 64-character peer id"),
        };
    }

    let path = keys.join(format!("{transport}.key"));
    let size = match std::fs::metadata(&path) {
        Ok(meta) => meta.len(),
        Err(e) => {
            return Resolved::Refused {
                name,
                why: format!("{}: {e}", path.display()),
            }
        }
    };
    if size > MAX_KEY_FILE {
        return Resolved::Refused {
            name,
            why: format!("{}: {size} bytes is not a transport key", path.display()),
        };
    }
    let hex = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => {
            return Resolved::Refused {
                name,
                why: format!("{}: {e}", path.display()),
            }
        }
    };
    let Some(bytes) = crate::hex::decode(hex.trim()) else {
        return Resolved::Refused {
            name,
            why: format!("{}: not hexadecimal", path.display()),
        };
    };
    // `from_bytes` derives the id from the key rather than accepting one, so
    // this comparison is the whole check: a file cannot be a key for a peer
    // other than the one its own bytes hash to.
    let public = match crate::p2p::handshake::PeerPublic::from_bytes(&bytes) {
        Ok(public) => public,
        Err(e) => {
            return Resolved::Refused {
                name,
                why: format!("{}: {e}", path.display()),
            }
        }
    };
    let derived = crate::p2p::discovery::peer_id_string(&public.id());
    if derived != transport {
        return Resolved::Refused {
            name,
            why: format!(
                "{} contains the key for {derived}, not {transport}. \
                 Whoever served this list served a key under the wrong name.",
                path.display()
            ),
        };
    }

    // The shape `load_endpoint` reads, and nothing else: extra fields are
    // ignored by every reader, and a bootstrap file is local configuration
    // that never enters the log.
    let bootstrap = Value::object([
        ("addr", Value::string(addr)),
        ("public", Value::string(hex.trim())),
    ]);
    let written = out.join(format!("{name}.json"));
    if let Err(e) = std::fs::write(&written, bootstrap.canonical_string()) {
        return Resolved::Refused {
            name,
            why: format!("{}: {e}", written.display()),
        };
    }
    Resolved::Wrote(written.display().to_string())
}

/// Write this node's transport key under the name the list will reference.
///
/// Run on the seed host, against the identity the daemon persists, and open a
/// pull request adding the file plus an entry. There is no upload path and
/// there should not be: publishing is a reviewed change to a repository, which
/// is the property that makes the anchor replaceable by someone other than
/// whoever holds the server.
fn seeds_publish(args: Vec<String>) -> i32 {
    let mut identity: Option<String> = None;
    let mut out: Option<String> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            seeds_usage(0);
        }
        let slot = match arg.as_str() {
            "--identity" => &mut identity,
            "--out" => &mut out,
            _ => {
                eprintln!("seeds publish: unknown option {arg:?}");
                seeds_usage(2)
            }
        };
        *slot = Some(args.next().unwrap_or_else(|| seeds_usage(2)));
    }
    let identity = PathBuf::from(identity.unwrap_or_else(|| seeds_usage(2)));
    let out = PathBuf::from(out.unwrap_or_else(|| seeds_usage(2)));

    // An identity file holds a secret beside the public half, so it is read
    // through `secret_file` like every other reader of one -- and only the
    // public half is ever written out below.
    let text = match crate::secret_file::read_to_string(&identity) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("{}: {e}", identity.display());
            return 2;
        }
    };
    let value = match Value::from_json(&text) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("{}: {e}", identity.display());
            return 2;
        }
    };
    let Some(public_hex) = value.get("public").and_then(Value::as_str) else {
        eprintln!("{}: public missing", identity.display());
        return 2;
    };
    let Some(bytes) = crate::hex::decode(public_hex) else {
        eprintln!("{}: public is not hexadecimal", identity.display());
        return 2;
    };
    let public = match crate::p2p::handshake::PeerPublic::from_bytes(&bytes) {
        Ok(public) => public,
        Err(e) => {
            eprintln!("{}: public: {e}", identity.display());
            return 2;
        }
    };
    let transport = crate::p2p::discovery::peer_id_string(&public.id());

    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("{}: {e}", out.display());
        return 2;
    }
    let path = out.join(format!("{transport}.key"));
    if let Err(e) = std::fs::write(&path, format!("{public_hex}\n")) {
        eprintln!("{}: {e}", path.display());
        return 2;
    }
    eprintln!("wrote {}", path.display());
    eprintln!(
        "add to launch/seeds.json:\n  \
         {{\"name\": \"...\", \"addr\": \"<public host:port>\", \
         \"transport\": \"{transport}\", \"http\": null, \
         \"operator\": \"...\", \"note\": \"...\"}}"
    );
    eprintln!(
        "the address is the one strangers can reach, not the one you --listen on: \
         a seed binds 0.0.0.0 and publishes its public address. See docs/p2p.md."
    );
    0
}

// ---------------------------------------------------------------------------
// arena
// ---------------------------------------------------------------------------

/// `cairn arena`: run the adversarial scenarios and print the payoffs.
///
/// This drives dozens of nodes through hundreds of epochs and takes seconds to
/// minutes, which is why it was once a separate binary; it is a subcommand now
/// because one name is easier to ship than two, and the cost of the run is in
/// the run and not in the dispatch. Every number it prints except the modelled
/// costs is read out of balances a real `Node` settled. Exits 1 while any
/// attack in the set is still profitable, so CI can gate on it.
pub fn arena(args: Vec<String>) -> i32 {
    use crate::arena::{scenarios, Costs, Verdict};

    let mut seed = 1u64;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                seed = args
                    .next()
                    .and_then(|text| text.parse().ok())
                    .unwrap_or(seed);
            }
            "-h" | "--help" => {
                println!("usage: cairn arena [--seed N]");
                return 0;
            }
            other => {
                eprintln!("unknown option {other:?}");
                return 2;
            }
        }
    }
    let trials = scenarios::all(seed);
    print!("{}", scenarios::report(&trials, Costs::default()));

    let open: Vec<&str> = trials
        .iter()
        .filter(|trial| matches!(trial.verdict(), Verdict::StillPays { .. }))
        .map(|trial| trial.attack.as_str())
        .collect();
    let inert: Vec<&str> = trials
        .iter()
        .filter(|trial| matches!(trial.verdict(), Verdict::NeverPaid { .. }))
        .map(|trial| trial.attack.as_str())
        .collect();
    if !inert.is_empty() {
        println!("inert (measured nothing): {}", inert.join(", "));
    }
    if open.is_empty() {
        println!("no attack in this set is profitable against its defence");
        0
    } else {
        println!("still profitable: {}", open.join(", "));
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_shape_accepts_names_and_ipv6_and_refuses_the_rest() {
        assert!(is_host_port("seed.example:5000"));
        assert!(is_host_port("[::1]:9000"));
        assert!(is_host_port("10.0.0.1:1"));
        assert!(!is_host_port("no-port"));
        assert!(!is_host_port(":5000"));
        assert!(!is_host_port("host:0"));
        assert!(!is_host_port("host:notaport"));
    }

    /// A scratch directory that removes itself, so a failing assertion does not
    /// leave half a megabyte of key file in `$TMPDIR` on every run.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("cairn-seeds-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).expect("scratch");
            Scratch(path)
        }
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// One generated identity, published and then resolved back, so the two
    /// halves of `cairn seeds` are checked against each other rather than
    /// against a fixture somebody would have to keep in step.
    ///
    /// Keygen is the expensive part, so the four cases below share one.
    fn published() -> (Scratch, String, String) {
        let scratch = Scratch::new("roundtrip");
        let identity = PeerIdentity::generate();
        let public_hex = hex_encode(identity.public_key());
        let transport = crate::p2p::discovery::peer_id_string(&identity.to_public().id());
        let keys = scratch.join("seeds");
        std::fs::create_dir_all(&keys).expect("keys dir");
        std::fs::write(
            keys.join(format!("{transport}.key")),
            format!("{public_hex}\n"),
        )
        .expect("key file");
        (scratch, transport, public_hex)
    }

    fn entry(json: &str) -> Value {
        Value::from_json(json).expect("entry")
    }

    /// The written file is the shape `--bootstrap` reads, and the key in it is
    /// the key the list named.
    ///
    /// The second half is the one worth a test: the address is copied through
    /// unchecked because an address is only ever a hint, so the key is the only
    /// thing here that can be wrong in a way that matters.
    #[test]
    fn a_published_key_resolves_into_a_usable_bootstrap_file() {
        let (scratch, transport, public_hex) = published();
        let out = scratch.join("out");
        std::fs::create_dir_all(&out).expect("out dir");

        let result = resolve_one(
            &entry(&format!(
                r#"{{"name":"us-west","addr":"203.0.113.10:5000","transport":"{transport}"}}"#
            )),
            &scratch.join("seeds"),
            &out,
        );
        assert!(matches!(result, Resolved::Wrote(_)), "refused a good entry");

        let written =
            Value::from_json(&std::fs::read_to_string(out.join("us-west.json")).expect("written"))
                .expect("canonical json");
        assert_eq!(
            written.get("addr").and_then(Value::as_str),
            Some("203.0.113.10:5000")
        );
        // Not a string comparison against `public_hex`: the property is that a
        // reader who parses this file arrives at the peer the list named.
        let bytes = crate::hex::decode(
            written
                .get("public")
                .and_then(Value::as_str)
                .expect("public"),
        )
        .expect("hex");
        let peer = crate::p2p::handshake::PeerPublic::from_bytes(&bytes).expect("key");
        assert_eq!(crate::p2p::discovery::peer_id_string(&peer.id()), transport);
        assert_eq!(bytes, crate::hex::decode(&public_hex).expect("hex"));
    }

    /// The whole security claim of publishing this list on a host nobody
    /// controls: a mirror can withhold a key or serve a different one, and
    /// cannot serve a different key *under the same name*.
    #[test]
    fn a_key_that_is_not_the_one_named_is_refused() {
        let (scratch, transport, _) = published();
        let out = scratch.join("out");
        std::fs::create_dir_all(&out).expect("out dir");
        let keys = scratch.join("seeds");

        // The same real key, filed under somebody else's id -- which is what a
        // substitution attack produces, and what a length or hex check misses.
        let impostor = "0".repeat(64);
        std::fs::copy(
            keys.join(format!("{transport}.key")),
            keys.join(format!("{impostor}.key")),
        )
        .expect("copy");

        let result = resolve_one(
            &entry(&format!(
                r#"{{"name":"impostor","addr":"203.0.113.10:5000","transport":"{impostor}"}}"#
            )),
            &keys,
            &out,
        );
        match result {
            Resolved::Refused { why, .. } => assert!(why.contains(&transport), "{why}"),
            Resolved::Wrote(_) => panic!("wrote a bootstrap file for a key under the wrong name"),
        }
        assert!(!out.join("impostor.json").exists());
    }

    /// An entry with no key is refused rather than written with a placeholder.
    ///
    /// Writing one would reproduce exactly the failure this whole path exists
    /// to end: a structurally valid bootstrap file that authenticates nobody,
    /// whose handshake failure is indistinguishable from a closed port.
    #[test]
    fn an_entry_with_no_published_key_writes_nothing() {
        let (scratch, _, _) = published();
        let out = scratch.join("out");
        std::fs::create_dir_all(&out).expect("out dir");

        for json in [
            r#"{"name":"nokey","addr":"203.0.113.11:5000"}"#,
            r#"{"name":"nokey","addr":"203.0.113.11:5000","transport":null}"#,
            r#"{"name":"httponly","transport":"00"}"#,
        ] {
            assert!(
                matches!(
                    resolve_one(&entry(json), &scratch.join("seeds"), &out),
                    Resolved::Refused { .. }
                ),
                "accepted {json}"
            );
        }
        assert_eq!(std::fs::read_dir(&out).expect("out").count(), 0);
    }

    /// `name` becomes a filename and the list arrives over the network, so it
    /// may not choose where the write lands.
    #[test]
    fn a_name_cannot_steer_the_write_out_of_the_output_directory() {
        let (scratch, transport, _) = published();
        let out = scratch.join("out");
        std::fs::create_dir_all(&out).expect("out dir");

        for name in ["../escape", "/etc/cairn", "a/b", "", "dot.dot"] {
            let json = format!(
                r#"{{"name":"{name}","addr":"203.0.113.10:5000","transport":"{transport}"}}"#
            );
            assert!(
                matches!(
                    resolve_one(&entry(&json), &scratch.join("seeds"), &out),
                    Resolved::Refused { .. }
                ),
                "accepted name {name:?}"
            );
        }
        assert_eq!(std::fs::read_dir(&out).expect("out").count(), 0);
    }
}
