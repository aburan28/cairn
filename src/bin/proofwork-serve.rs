//! `proofwork-serve` — publish a node's log over HTTP, and queue submissions.
//!
//! The missing half of "anyone can independently re-derive every settled
//! result from the log alone": a way for somebody who is not the operator to
//! *obtain* the log. See the module docs in `serve.rs` for why writes go to a
//! spool rather than into the log.
//!
//! ```sh
//! proofwork-serve --log proofwork.jsonl --root . --listen 127.0.0.1:8080
//! proofwork-serve --log proofwork.jsonl --root . --listen 0.0.0.0:8080 \
//!     --queue ./queue --checkpoint checkpoint.json
//! ```
//!
//! Read-only unless `--queue` is given. That default is deliberate: publishing
//! is safe for anyone to do, accepting is a decision.

use std::path::PathBuf;

use proofwork::serve::{self, Serving};

/// Print the usage and exit with `code`.
///
/// `--help` exits 0 and a bad argument exits 2. They used to share one exit of
/// 2, which says "you used me wrong" to somebody who asked a question and
/// answered it correctly -- and `cmd --help >/dev/null || fail` is how a
/// packaging check or a smoke test asks whether a binary runs at all.
fn usage(code: i32) -> ! {
    eprintln!(
        "proofwork-serve — publish a proofwork log over HTTP\n\n\
         USAGE\n    \
         proofwork-serve [--log <path>] [--root <dir>] [--listen <addr>]\n                    \
         [--queue <dir>] [--checkpoint <path>]\n\n\
         --log         the append-only log to publish (default proofwork.jsonl)\n\
         --root        bundle root pinned verifier paths resolve against (default .)\n\
         --listen      address to bind (default 127.0.0.1:8080)\n\
         --queue       accept POST /submit into this spool directory; omit for read-only\n\
         --max-queue   refuse submissions past this many undrained records\n\
         --checkpoint  signed checkpoint to publish at GET /checkpoint\n\n\
         Everything served is public by design. Submissions are queued, never\n\
         admitted: drain them into the log with `proofwork drain --queue <dir>`.\n"
    );
    std::process::exit(code);
}

fn main() {
    let mut log = PathBuf::from("proofwork.jsonl");
    let mut root = PathBuf::from(".");
    let mut listen = String::from("127.0.0.1:8080");
    let mut queue: Option<PathBuf> = None;
    let mut checkpoint: Option<PathBuf> = None;
    let mut max_queue = proofwork::serve::DEFAULT_MAX_QUEUED;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut next = |what: &str| match args.next() {
            Some(value) => value,
            None => {
                eprintln!("proofwork-serve: {what} needs a value");
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
                        eprintln!("proofwork-serve: --max-queue needs a positive integer");
                        std::process::exit(2);
                    }
                }
            }
            "--checkpoint" => checkpoint = Some(PathBuf::from(next("--checkpoint"))),
            "--help" | "-h" => usage(0),
            other => {
                eprintln!("proofwork-serve: unknown argument {other:?}");
                usage(2);
            }
        }
    }

    let mut serving = Serving::new(&log, &root);
    if let Some(dir) = queue {
        serving = serving.accepting_into(dir).with_max_queued(max_queue);
    }
    if let Some(path) = checkpoint {
        serving = serving.with_checkpoint(path);
    }

    if let Err(error) = serve::listen(&listen, serving) {
        eprintln!("proofwork-serve: cannot listen on {listen}: {error}");
        std::process::exit(1);
    }
}
