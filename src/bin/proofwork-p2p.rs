//! `proofwork-p2p` — a long-running node: p2p sync, and optionally HTTP.
//!
//! The loop itself lives in [`proofwork::daemon`], which this and
//! `proofwork-serve` both call. Two entry points, one implementation of "be a
//! node": the alternative was two copies of a startup sequence that has to
//! agree about locking, checkpoint writing and queue draining.
//!
//! ```sh
//! # p2p only, as before
//! proofwork-p2p --identity id.json --root-key key.json --checkpoint cp.json \
//!     --listen 0.0.0.0:9000 --log proofwork.jsonl --root .
//!
//! # and publishing over HTTP from the same process
//! proofwork-p2p --identity id.json --root-key key.json --checkpoint cp.json \
//!     --listen 0.0.0.0:9000 --log proofwork.jsonl --root . \
//!     --serve 0.0.0.0:8080 --queue ./queue
//! ```
//!
//! Identity files and bootstrap files are local configuration. They are never
//! placed in the append-only ledger.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use proofwork::daemon::{self, Config};

/// Print the usage and exit with `code`.
///
/// `--help` exits 0 and a bad or missing argument exits 2. Sharing one exit of
/// 2 tells somebody who asked a question, and asked it correctly, that they
/// used the tool wrong -- and `cmd --help >/dev/null || fail` is how a
/// packaging check asks whether a binary runs at all.
fn usage(code: i32) -> ! {
    eprintln!(
        "proofwork-p2p — a proofwork node: p2p sync, and optionally HTTP\n\n\
         USAGE\n    \
         proofwork-p2p --identity FILE --root-key FILE --checkpoint FILE\n                  \
         --listen ADDR --log FILE --root DIR\n                  \
         [--bootstrap FILE ...] [--population FILE] [--queue DIR]\n                  \
         [--fanout N] [--serve ADDR] [--max-queue N] [--key-file FILE]\n\n\
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
         --key-file    at-rest key for a sealed log (default: the CLI's own)\n\n\
         With --serve this is a whole node in one process: it holds the log's\n\
         write lock, so it is the only thing that *can* admit what it queues.\n"
    );
    std::process::exit(code);
}

fn main() {
    // Before anything that could log. Stderr only -- see `logging` -- which
    // matters most here in the MCP server, where stdout is the protocol.
    proofwork::logging::init();

    let mut identity = None;
    let mut root_key = None;
    let mut checkpoint = None;
    let mut listen = None;
    let mut log = None;
    let mut root = None;
    let mut population = None;
    let mut queue = None;
    let mut fanout = None;
    let mut serve = None;
    let mut max_queue = None;
    let mut key_file = None;
    let mut bootstrap = Vec::new();

    let mut args = env::args().skip(1);
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
            "--bootstrap" => {
                bootstrap.push(args.next().unwrap_or_else(|| usage(2)));
                continue;
            }
            "--help" | "-h" => usage(0),
            _ => usage(2),
        };
        *slot = Some(args.next().unwrap_or_else(|| usage(2)));
    }

    let listen: SocketAddr = listen
        .unwrap_or_else(|| usage(2))
        .parse()
        .unwrap_or_else(|_| usage(2));
    let mut config = Config::new(
        identity.unwrap_or_else(|| usage(2)),
        root_key.unwrap_or_else(|| usage(2)),
        checkpoint.unwrap_or_else(|| usage(2)),
        listen,
        log.unwrap_or_else(|| usage(2)),
        root.unwrap_or_else(|| usage(2)),
    );
    config.bootstrap = bootstrap.into_iter().map(PathBuf::from).collect();
    config.population = population.map(PathBuf::from);
    config.queue = queue.map(PathBuf::from);
    config.serve = serve;
    config.key_file = key_file.map(PathBuf::from);
    if let Some(text) = fanout {
        config.fanout = text.parse().unwrap_or_else(|_| usage(2));
    }
    if let Some(text) = max_queue {
        // Refused rather than clamped: an operator who typed a bound wants that
        // bound, and silently substituting one hides a full queue behind a
        // number they never chose.
        match text.parse::<usize>() {
            Ok(value) if value > 0 => config.max_queued = value,
            _ => {
                eprintln!("proofwork-p2p: --max-queue needs a positive integer");
                std::process::exit(2);
            }
        }
    }

    // `run` returns only on a startup failure the operator has to fix, so
    // there is no success path to fall through to.
    if let Err(error) = daemon::run(config) {
        log::error!("{error}");
        std::process::exit(2);
    }
}
