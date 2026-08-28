//! `cairn-serve` — publish a node's log over HTTP, and queue submissions.
//!
//! The missing half of "anyone can independently re-derive every settled
//! result from the log alone": a way for somebody who is not the operator to
//! *obtain* the log. See the module docs in `serve.rs` for why writes go to a
//! spool rather than into the log.
//!
//! ```sh
//! cairn-serve --log cairn.jsonl --root . --listen 127.0.0.1:8080
//! cairn-serve --log cairn.jsonl --root . --listen 0.0.0.0:8080 \
//!     --queue ./queue --checkpoint checkpoint.json
//! ```
//!
//! Read-only unless `--queue` is given. That default is deliberate: publishing
//! is safe for anyone to do, accepting is a decision.
//!
//! # Publishing alone, and being a node
//!
//! Without `--p2p-listen` this is a *publisher*: it takes no lock, holds no
//! `Node`, and re-reads the log per request, so it is safe to point at a log
//! another process is writing. That is a real role — a read-only mirror, or a
//! public front for an operator whose daemon runs elsewhere.
//!
//! With `--p2p-listen` it is the whole node, running [`cairn::daemon::run`]
//! — the same function `cairn-p2p` calls, in one process, with the HTTP
//! server on a thread. Use it when the alternative would have been two units
//! sharing a directory.
//!
//! The queue is why the distinction matters. A `Ledger` is single-writer, so
//! whatever admits a queued submission must hold the write lock. A publisher
//! queues and something else drains; a node does both.

use std::net::SocketAddr;
use std::path::PathBuf;

use cairn::daemon::{self, Config};
use cairn::serve::{self, Serving};

/// Print the usage and exit with `code`.
///
/// `--help` exits 0 and a bad argument exits 2. They used to share one exit of
/// 2, which says "you used me wrong" to somebody who asked a question and
/// answered it correctly -- and `cmd --help >/dev/null || fail` is how a
/// packaging check or a smoke test asks whether a binary runs at all.
fn usage(code: i32) -> ! {
    eprintln!(
        "cairn-serve — publish a cairn log over HTTP\n\n\
         USAGE\n    \
         cairn-serve [--log <path>] [--root <dir>] [--listen <addr>]\n                    \
         [--queue <dir>] [--checkpoint <path>]\n\n\
         --log         the append-only log to publish (default cairn.jsonl)\n\
         --root        bundle root pinned verifier paths resolve against (default .)\n\
         --listen      address to bind (default 127.0.0.1:8080)\n\
         --queue       accept POST /submit into this spool directory; omit for read-only\n\
         --max-queue   refuse submissions past this many undrained records\n\
         --checkpoint  signed checkpoint to publish at GET /checkpoint\n\
         --key-file    at-rest key, if the log is sealed (default: the CLI's own)\n\
         --receipt-key sign a submission receipt into every POST /submit answer,\n              \
         with the checkpoint root key at this path -- the operator's\n              \
         word the record arrived, verifiable with `cairn receipt verify`\n\n\
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
         with `cairn drain --queue <dir>`.\n"
    );
    std::process::exit(code);
}

fn main() {
    // Before anything that could log. Stderr only -- see `logging` -- which
    // matters most here in the MCP server, where stdout is the protocol.
    cairn::logging::init();
    let mut log = PathBuf::from("cairn.jsonl");
    let mut root = PathBuf::from(".");
    let mut listen = String::from("127.0.0.1:8080");
    let mut queue: Option<PathBuf> = None;
    let mut checkpoint: Option<PathBuf> = None;
    let mut max_queue = serve::DEFAULT_MAX_QUEUED;
    let mut key_file: Option<PathBuf> = None;
    let mut receipt_key: Option<PathBuf> = None;

    // The p2p half. All absent is the ordinary publisher.
    let mut p2p_listen: Option<String> = None;
    let mut identity: Option<PathBuf> = None;
    let mut root_key: Option<PathBuf> = None;
    let mut population: Option<PathBuf> = None;
    let mut fanout: Option<String> = None;
    let mut bootstrap: Vec<PathBuf> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut next = |what: &str| match args.next() {
            Some(value) => value,
            None => {
                eprintln!("cairn-serve: {what} needs a value");
                std::process::exit(2);
            }
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
                    _ => {
                        eprintln!("cairn-serve: --max-queue needs a positive integer");
                        std::process::exit(2);
                    }
                }
            }
            "--checkpoint" => checkpoint = Some(PathBuf::from(next("--checkpoint"))),
            "--key-file" => key_file = Some(PathBuf::from(next("--key-file"))),
            "--receipt-key" => receipt_key = Some(PathBuf::from(next("--receipt-key"))),
            "--p2p-listen" => p2p_listen = Some(next("--p2p-listen")),
            "--identity" => identity = Some(PathBuf::from(next("--identity"))),
            "--root-key" => root_key = Some(PathBuf::from(next("--root-key"))),
            "--population" => population = Some(PathBuf::from(next("--population"))),
            "--fanout" => fanout = Some(next("--fanout")),
            "--bootstrap" => bootstrap.push(PathBuf::from(next("--bootstrap"))),
            "--help" | "-h" => usage(0),
            other => {
                eprintln!("cairn-serve: unknown argument {other:?}");
                usage(2);
            }
        }
    }

    // -- node mode ----------------------------------------------------------

    if let Some(addr) = p2p_listen {
        let addr: SocketAddr = addr.parse().unwrap_or_else(|_| {
            eprintln!("cairn-serve: --p2p-listen needs host:port");
            std::process::exit(2)
        });
        // Named individually rather than as one "missing options" error: an
        // operator who forgot the root key wants to be told which one.
        let identity = identity.unwrap_or_else(|| {
            eprintln!("cairn-serve: --p2p-listen also needs --identity");
            std::process::exit(2)
        });
        let root_key = root_key.unwrap_or_else(|| {
            eprintln!("cairn-serve: --p2p-listen also needs --root-key");
            std::process::exit(2)
        });
        // A daemon *writes* its checkpoint every round, so unlike the publisher
        // this is not optional -- there would be nowhere to put it.
        let checkpoint = checkpoint.unwrap_or_else(|| {
            eprintln!("cairn-serve: --p2p-listen also needs --checkpoint to write");
            std::process::exit(2)
        });

        if receipt_key.is_some() {
            // Refused, not ignored: the daemon signs receipts with its
            // --root-key already, and a second key here would either be the
            // same file said twice or a different authority than the
            // checkpoints readers pin -- both mistakes worth naming.
            eprintln!("cairn-serve: --receipt-key applies to the publisher; a node receipts with its --root-key");
            std::process::exit(2);
        }
        let mut config = Config::new(identity, root_key, checkpoint, addr, log, root);
        config.bootstrap = bootstrap;
        config.population = population;
        config.queue = queue;
        config.serve = Some(listen);
        config.max_queued = max_queue;
        config.key_file = key_file;
        if let Some(text) = fanout {
            config.fanout = text.parse().unwrap_or_else(|_| {
                eprintln!("cairn-serve: --fanout needs a positive integer");
                std::process::exit(2)
            });
        }
        if let Err(error) = daemon::run(config) {
            log::error!("{error}");
            std::process::exit(2);
        }
        return;
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
            eprintln!("cairn-serve: {flag} has no effect without --p2p-listen");
            std::process::exit(2);
        }
    }

    // The CLI's own default when no flag was given, so a publisher on a machine
    // that ran `cairn store keygen` opens the same logs the CLI writes.
    // `resolve_codec` treats an absent key file as plaintext, so naming a path
    // that does not exist costs nothing.
    let key_path = key_file.unwrap_or_else(|| cairn::store::Store::new(&root).default_key_path());
    let mut serving = Serving::new(&log, &root).with_key(key_path, None);
    if let Some(dir) = queue {
        serving = serving.accepting_into(dir).with_max_queued(max_queue);
    }
    if let Some(path) = checkpoint {
        serving = serving.with_checkpoint(path);
    }
    if let Some(path) = receipt_key {
        // Strict load: a receipt minted under a key nobody has pinned
        // authenticates nothing, so an absent file is an error here where the
        // daemon would generate one.
        match cairn::checkpoint::RootKey::load(&path) {
            Ok(key) => serving = serving.with_receipts(key),
            Err(error) => {
                eprintln!("cairn-serve: --receipt-key: {error}");
                std::process::exit(1);
            }
        }
    }

    // Separately from `listen`, which also checks: this one owns the message.
    // Folded together, a missing key file was reported as "cannot listen on
    // 127.0.0.1:8080", which sends an operator to check the port.
    if let Err(error) = serving.check_startup() {
        eprintln!("cairn-serve: {error}");
        std::process::exit(1);
    }
    if let Err(error) = serve::listen(&listen, serving) {
        eprintln!("cairn-serve: cannot listen on {listen}: {error}");
        std::process::exit(1);
    }
}
