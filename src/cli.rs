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
}
