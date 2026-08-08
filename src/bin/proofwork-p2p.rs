//! Long-running p2p node.
//!
//! Identity files and bootstrap files are local configuration. They are never
//! placed in the append-only ledger.

use proofwork::canonical::Value;
use proofwork::checkpoint::RootKey;
use proofwork::gossip::{Candidate, Population};
use proofwork::ledger::Ledger;
use proofwork::node::Node;
use proofwork::p2p::discovery::{peer_id_string, Endpoint};
use proofwork::p2p::handshake::{PeerIdentity, PeerPublic};
use proofwork::p2p::multicast;
use proofwork::p2p::pop::PopLimits;
use proofwork::p2p::service::{Service, DEFAULT_FANOUT};
use proofwork::records::Objective;
use proofwork::serve;
use proofwork::time::timestamp;
use proofwork::verifiers::VerifierRegistry;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Beacons folded in per tick.
///
/// Bounded because the beacon socket is reachable by anyone on the segment: an
/// unbounded drain is a way for one host to hold the daemon's main loop. Any
/// backlog is picked up next tick, and a node re-announces every
/// `multicast::INTERVAL_SECONDS` regardless, so nothing is lost by deferring it.
const BEACONS_PER_TICK: usize = 64;

/// Print the usage and exit with `code`.
///
/// `--help` exits 0 and a bad or missing argument exits 2. Sharing one exit of
/// 2 tells somebody who asked a question, and asked it correctly, that they
/// used the tool wrong -- and `cmd --help >/dev/null || fail` is how a
/// packaging check asks whether a binary runs at all.
fn usage(code: i32) -> ! {
    eprintln!("usage: proofwork-p2p --identity FILE --root-key FILE --checkpoint FILE --listen ADDR --log FILE --root DIR [--bootstrap FILE ...] [--population FILE] [--queue DIR] [--fanout N]");
    std::process::exit(code);
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("hex has odd length".into());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for i in (0..text.len()).step_by(2) {
        out.push(u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "invalid hex")?);
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn load_identity(path: &Path) -> Result<PeerIdentity, String> {
    if !path.exists() {
        let identity = PeerIdentity::generate();
        let value = Value::object([
            ("public", Value::string(hex_encode(identity.public_key()))),
            ("secret", Value::string(hex_encode(identity.secret_key()))),
        ]);
        fs::write(path, value.canonical_string()).map_err(|e| e.to_string())?;
        return Ok(identity);
    }
    let value = Value::from_json(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let public = hex_decode(
        value
            .get("public")
            .and_then(Value::as_str)
            .ok_or("identity.public missing")?,
    )?;
    let secret = hex_decode(
        value
            .get("secret")
            .and_then(Value::as_str)
            .ok_or("identity.secret missing")?,
    )?;
    PeerIdentity::from_bytes(&public, &secret).map_err(|e| e.to_string())
}

/// A bootstrap file still carrying the placeholder key `gen-bootstrap` wrote.
///
/// Detected rather than remembered: the file records the peer id of the key it
/// generated, a peer id *is* `sha256(public key)`, so this recomputes it from
/// whatever `public` holds now and matches only while the two are the same
/// key. Pasting the real key in clears it with nothing to delete.
///
/// Worth its own path because the failure it explains is otherwise mute. A
/// placeholder key authenticates nobody, so the handshake fails and the daemon
/// prints a transport error identical to the one a firewall produces -- and an
/// operator with a correct address, an open port and a bogus key has no way to
/// tell those apart from the log.
fn is_placeholder(value: &Value, endpoint: &Endpoint) -> bool {
    value
        .get("placeholder_peer_id")
        .and_then(Value::as_str)
        .is_some_and(|recorded| {
            recorded == proofwork::p2p::discovery::peer_id_string(&endpoint.peer.id())
        })
}

fn load_endpoint(path: &Path) -> Result<(Endpoint, bool), String> {
    let value = Value::from_json(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let addr = value
        .get("addr")
        .and_then(Value::as_str)
        .ok_or("bootstrap.addr missing")?;
    // A bootstrap address may be a hostname. An EC2 instance reached by its
    // public DNS name keeps working across a restart that moves its IP, and a
    // name is safe to accept because the peer id decides -- see
    // `p2p::discovery::dialable`.
    let addr = proofwork::p2p::discovery::dialable(addr).ok_or_else(|| {
        format!("bootstrap.addr {addr:?} is neither an address nor a name that resolves")
    })?;
    let public = hex_decode(
        value
            .get("public")
            .and_then(Value::as_str)
            .ok_or("bootstrap.public missing")?,
    )?;
    let peer = PeerPublic::from_bytes(&public).map_err(|e| e.to_string())?;
    let endpoint = Endpoint::new(addr, peer);
    let placeholder = is_placeholder(&value, &endpoint);
    Ok((endpoint, placeholder))
}

fn load_root_key(path: &Path) -> Result<RootKey, String> {
    if !path.exists() {
        let key = RootKey::generate();
        let value = Value::object([
            ("public", Value::string(hex_encode(&key.public_key()))),
            (
                "secret",
                Value::string(hex_encode(&key.to_secret_bytes()[..])),
            ),
        ]);
        fs::write(path, value.canonical_string()).map_err(|e| e.to_string())?;
        return Ok(key);
    }
    let value = Value::from_json(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let secret = hex_decode(
        value
            .get("secret")
            .and_then(Value::as_str)
            .ok_or("root-key.secret missing")?,
    )?;
    let bytes: [u8; 32] = secret
        .try_into()
        .map_err(|_| "root-key.secret must be 32 bytes")?;
    let key = RootKey::from_secret_bytes(bytes);
    if let Some(public) = value.get("public").and_then(Value::as_str) {
        if hex_decode(public).map_err(|_| "invalid root-key.public")? != key.public_key() {
            return Err("root-key public does not match secret".into());
        }
    }
    Ok(key)
}

fn write_checkpoint(path: &Path, key: &RootKey, node: &Node) -> Result<(), String> {
    let signed = key.sign_ledger(node.ledger(), proofwork::time::timestamp());
    fs::write(path, signed.to_value().canonical_string()).map_err(|e| e.to_string())
}

/// Read the population file, or start empty if it is not there yet.
///
/// A missing file is a first run, not a fault. A *corrupt* one is a fault and
/// is reported: silently starting empty would throw away a node's search state
/// at the moment it most needs looking at.
fn load_population(path: &Path) -> Result<Population, String> {
    if !path.exists() {
        return Ok(Population::default());
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value = Value::from_json(&text).map_err(|e| e.to_string())?;
    Population::from_value(&value).map_err(|e| e.to_string())
}

fn save_population(path: &Path, population: &Population) -> Result<(), String> {
    fs::write(path, population.to_value().canonical_string()).map_err(|e| e.to_string())
}

/// A scorer for one sync round.
///
/// Decoding every objective out of the log costs a pass over it, and a round
/// may offer hundreds of candidates, so the map is built at most once per round
/// and only if a candidate actually arrives. It is deliberately *not* kept
/// between rounds: the record half of the round is what teaches this node about
/// new objectives, and a stale map would refuse candidates for the objective it
/// just learned.
struct RoundScorer {
    objectives: Option<BTreeMap<String, Objective>>,
    registry: VerifierRegistry,
}

impl RoundScorer {
    fn new(registry: VerifierRegistry) -> RoundScorer {
        RoundScorer {
            objectives: None,
            registry,
        }
    }

    /// Re-derive a gossiped candidate's score locally.
    ///
    /// Anything other than a score is `None`, which the ingest path treats as a
    /// refusal: an objective this node has not heard of, a verifier that
    /// produces no score, or a verifier that could not run at all. The last is
    /// the uncomfortable one and is still right here. `Unavailable` says
    /// nothing about the artifact, but a population entry is not a verdict --
    /// dropping the candidate costs a little search progress, whereas keeping a
    /// score this node never checked is precisely the import this path exists
    /// to refuse.
    fn score(&mut self, node: &Node, candidate: &Candidate) -> Option<i64> {
        let objectives = self.objectives.get_or_insert_with(|| node.objectives());
        let objective = objectives.get(&candidate.objective_id)?;
        self.registry
            .run(&objective.verifier, &candidate.artifact)
            .score()
    }
}

/// Node and population under one lock.
///
/// One mutex rather than one each: both halves of a round run on the same
/// connection, so the second lock would only ever be taken with the first
/// already held. Two locks always acquired in the same order is a deadlock
/// waiting for the first person who reverses them.
struct State {
    node: Node,
    population: Population,
}

/// Write out everything a round may have changed.
///
/// Failures are reported and the loop continues. A node that cannot write its
/// checkpoint is still a node that can serve records, and exiting here would
/// turn a full disk into a departure from the network.
fn persist(state: &State, checkpoint: &str, key: &RootKey, population: Option<&String>) {
    if let Err(error) = write_checkpoint(Path::new(checkpoint), key, &state.node) {
        eprintln!("checkpoint: {error}");
    }
    if let Some(path) = population {
        if let Err(error) = save_population(Path::new(path), &state.population) {
            eprintln!("population: {error}");
        }
    }
}

fn main() {
    let mut identity_path = None;
    let mut root_key_path = None;
    let mut checkpoint_path = None;
    let mut listen_addr = None;
    let mut log = None;
    let mut root = None;
    let mut population_path = None;
    let mut queue_path = None;
    let mut fanout = None;
    let mut bootstrap = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--identity" => &mut identity_path,
            "--root-key" => &mut root_key_path,
            "--checkpoint" => &mut checkpoint_path,
            "--listen" => &mut listen_addr,
            "--log" => &mut log,
            "--root" => &mut root,
            "--population" => &mut population_path,
            "--queue" => &mut queue_path,
            "--fanout" => &mut fanout,
            "--bootstrap" => {
                bootstrap.push(args.next().unwrap_or_else(|| usage(2)));
                continue;
            }
            "--help" | "-h" => usage(0),
            _ => usage(2),
        };
        *slot = Some(args.next().unwrap_or_else(|| usage(2)));
    }
    let identity_path = identity_path.unwrap_or_else(|| usage(2));
    let root_key_path = root_key_path.unwrap_or_else(|| usage(2));
    let checkpoint_path = checkpoint_path.unwrap_or_else(|| usage(2));
    let listen_addr = listen_addr
        .unwrap_or_else(|| usage(2))
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| usage(2));
    let log = log.unwrap_or_else(|| usage(2));
    let root = root.unwrap_or_else(|| usage(2));
    let fanout = match fanout {
        Some(text) => text.parse::<usize>().unwrap_or_else(|_| usage(2)),
        None => DEFAULT_FANOUT,
    };
    // The ledger first, and the ordering is deliberate.
    //
    // It is the cheapest check and the likeliest failure -- another daemon
    // already holds the log, which is what an operator hits when a restart
    // overlaps the old process. Doing it last meant ~243 ms of Classic McEliece
    // keygen, an identity file written for a node that cannot start, and a
    // bound listener, all before the refusal. The bound port is the part that
    // bites: during that window the address is taken and then released again,
    // so a restart flaps a port the operator is watching.
    //
    // The cost, stated rather than discovered later: opening creates the file,
    // so a start that fails *after* this — a missing bootstrap file, an
    // unbindable address — now leaves an empty log where it used to leave
    // nothing. That file is byte-for-byte the one a successful start would have
    // created, so the next run simply uses it. Worth an empty file.
    let ledger = Ledger::open_exclusive(log).unwrap_or_else(|e| {
        eprintln!("ledger: {e}");
        std::process::exit(2)
    });
    let identity = Arc::new(
        load_identity(Path::new(&identity_path)).unwrap_or_else(|e| {
            eprintln!("identity: {e}");
            std::process::exit(2)
        }),
    );
    let root_key = Arc::new(
        load_root_key(Path::new(&root_key_path)).unwrap_or_else(|e| {
            eprintln!("root key: {e}");
            std::process::exit(2)
        }),
    );
    let mut service = Service::new(Arc::clone(&identity));
    for path in bootstrap {
        match load_endpoint(Path::new(&path)) {
            Ok((endpoint, placeholder)) => {
                if placeholder {
                    // Loud, and at startup rather than at the first failed
                    // dial: a placeholder key fails the handshake with a
                    // transport error indistinguishable from a closed port, so
                    // an operator who has already checked the address and the
                    // firewall has nothing left to suspect. Said once here,
                    // the one remaining explanation is on screen before the
                    // first dial rather than absent from all of them.
                    eprintln!(
                        "bootstrap {path}: still carries the PLACEHOLDER key \
                         `proofwork-gen-bootstrap` generated, which authenticates nobody. \
                         Dials to {} will fail their handshake and report a plain transport \
                         error. Replace \"public\" in that file with the seed's real key -- \
                         the seed operator can print theirs from the \"public\" field of \
                         their --identity file.",
                        endpoint.addr
                    );
                }
                service.add_bootstrap(endpoint)
            }
            Err(error) => {
                eprintln!("bootstrap {path}: {error}");
                std::process::exit(2);
            }
        }
    }
    // Zero-configuration discovery on the local segment. Optional by design:
    // a host with no multicast route is a node without LAN discovery, not a
    // node that cannot start, so a failure here is reported and stepped over.
    let beacon =
        match multicast::Responder::bind(service.identity(), listen_addr.port(), multicast::PORT) {
            Ok(responder) => Some(responder),
            Err(error) => {
                eprintln!("multicast: {error} -- continuing without LAN discovery");
                None
            }
        };

    let listener = service.listen(listen_addr).unwrap_or_else(|e| {
        eprintln!("listen: {e}");
        // The one bind failure worth explaining, because the address that
        // causes it is the address an operator has every reason to think is
        // right. A cloud instance's public address is NAT'd to it and is on no
        // local interface, so `--listen <public ip>:9000` cannot bind at all --
        // and the fix is the counterintuitive one of binding the wildcard and
        // publishing the public address in the bootstrap file instead.
        if !listen_addr.ip().is_unspecified() {
            eprintln!(
                "listen: {} is not an address on this host. A cloud instance's public \
                 address is NAT'd to it and never appears on an interface -- bind \
                 0.0.0.0:{} and put the public address in the bootstrap file you hand \
                 out, which is only ever a dial hint.",
                listen_addr.ip(),
                listen_addr.port()
            );
        }
        std::process::exit(2)
    });
    eprintln!("listening on {listen_addr}");
    // Exclusive, opened above: the daemon appends every record it imports from
    // a peer, so it is a writer and must not share a log with another one.
    let node = Node::new(ledger, root);
    // `Spool::at` only names a directory; the server creates it when it first
    // queues something, and an absent one simply drains nothing.
    let spool = queue_path.as_ref().map(serve::Spool::at);
    match &queue_path {
        Some(path) => eprintln!("queue: draining {path} each round"),
        None => eprintln!("queue: none -- submissions arrive only from peers"),
    }
    let population = match &population_path {
        Some(path) => load_population(Path::new(path)).unwrap_or_else(|e| {
            eprintln!("population: {e}");
            std::process::exit(2)
        }),
        None => Population::default(),
    };
    // Publish before serving. A log written before verifier code was
    // content-addressed has objectives whose checkers were never copied into the
    // store, and without this their funder would be the one node on the network
    // unable to serve the very blobs its peers are about to ask it for.
    // Idempotent, and cheap: one stat per pin already held.
    let servable = node.publish_local_code();
    let missing = node.missing_code().len();
    eprintln!("verifier code: {servable} servable, {missing} unmet");

    let registry = node.registry().clone();
    let state = Arc::new(Mutex::new(State { node, population }));
    {
        let guard = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(error) = write_checkpoint(Path::new(&checkpoint_path), &root_key, &guard.node) {
            eprintln!("checkpoint: {error}");
            std::process::exit(2);
        }
    }
    let service = Arc::new(service);
    let accept_service = Arc::clone(&service);
    let accept_state = Arc::clone(&state);
    let accept_root_key = Arc::clone(&root_key);
    let accept_checkpoint_path = checkpoint_path.clone();
    let accept_population_path = population_path.clone();
    let accept_registry = registry.clone();
    thread::spawn(move || loop {
        // Accept **before** taking the lock, and this ordering is the whole
        // reason `Service::serve_node_once` exists.
        //
        // `listener.accept()` blocks until somebody dials. Holding the node's
        // mutex across it meant that on a node nobody was dialling, this thread
        // held the lock forever -- so the main loop below ran exactly once, at
        // startup, and then waited on the mutex for the life of the process. No
        // dialling, no peer seeding, no beacons, no DHT, no fetching of missing
        // verifier code, no draining of the submission queue. It looked healthy
        // because that single startup pass is enough to sync from a bootstrap
        // peer, which is exactly what a two-node test exercises.
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) => {
                eprintln!("accept: {error}");
                continue;
            }
        };
        let mut guard = accept_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let State { node, population } = &mut *guard;
        let outcome = match accept_population_path {
            Some(_) => {
                let mut scorer = RoundScorer::new(accept_registry.clone());
                accept_service
                    .serve_node_and_population(
                        stream,
                        node,
                        population,
                        PopLimits::default(),
                        |node, candidate| scorer.score(node, candidate),
                    )
                    .map(|(remote, _)| remote)
            }
            None => accept_service.serve_node_once(stream, node),
        };
        match outcome {
            Ok(remote) => {
                // The only positive signal this daemon ever gave was a growing
                // log file, checked by hand across two terminals. Every other
                // line here is a failure; a session that worked was silent.
                eprintln!(
                    "inbound session: {} ok, {} entries now",
                    peer_id_string(&remote),
                    node.ledger().len()
                );
                persist(
                    &guard,
                    &accept_checkpoint_path,
                    &accept_root_key,
                    accept_population_path.as_ref(),
                );
            }
            Err(error) => eprintln!("inbound session: {error}"),
        }
    });

    loop {
        // Peers with a reason to be useful first, then a random sample.
        //
        // Dialling every peer every tick is quadratic in the network, and the
        // tail of a fixed iteration order is always the last to hear anything.
        // The DHT narrows it further when something specific is missing: a node
        // whose log pins a checker it does not hold dials a peer that said it
        // has that blob, rather than three at random. With nothing missing this
        // is exactly the old random sample, so the DHT costs nothing in the
        // steady state. See `Service::peers_for` for what it cannot do yet.
        // Peer records first: the log names identities this node may never
        // have been given an address for, and seeding is what makes finding
        // the network part of obtaining the log rather than a second bootstrap
        // problem. Idempotent, so running it every tick costs a walk of the
        // peer records and picks up anything a sync round just imported.
        // Admit whatever `proofwork-serve` queued, before dialling anybody.
        //
        // This is what makes the topology in `docs/serving.md` actually
        // compose. A submission "lands in a spool directory, and the operator's
        // own node admits it" -- but a `Ledger` is single-writer by
        // enforcement, so `proofwork drain` wanted the write lock this daemon
        // holds. A node that was online could not accept a submission at all.
        //
        // The daemon *is* the operator's node and already holds the lock, so it
        // drains. The rules come from `serve::drain_into`, one copy shared with
        // the CLI: a second copy of admission in a second binary is the same
        // mistake as a second copy in a request handler, which is the argument
        // `docs/serving.md` already makes.
        //
        // Before the dial, deliberately: a record admitted this tick is one a
        // peer can learn about this tick, rather than five seconds later.
        if let Some(queue) = &spool {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let admissions = serve::drain_into(&mut guard.node, queue, &timestamp(), false);
            let drained = !admissions.is_empty();
            for (path, admission) in admissions {
                eprintln!("drain: {}", admission.note);
                // Removed whether admitted or refused. Nearly every refusal is
                // permanent -- a stale epoch, a citation that is not an
                // accepted claim -- and a queue that retries one never empties.
                if let Err(error) = queue.take(&path) {
                    eprintln!("drain: cannot remove {}: {error}", path.display());
                }
            }
            if drained {
                // Settlement is deferred to the close of the reveal epoch, so a
                // drain that admitted a reveal into an epoch that has already
                // closed settles here rather than waiting for a peer to dial.
                let _ = guard.node.settle_at(&timestamp());
                persist(
                    &guard,
                    &checkpoint_path,
                    &root_key,
                    population_path.as_ref(),
                );
            }
        }

        let needs = {
            let guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            service.seed_from_log(&guard.node);
            if let Some(responder) = &beacon {
                // Announce first, then listen: a node that has just started
                // becomes findable this tick rather than next.
                let _ = responder.announce(multicast::PORT);
                service.absorb_beacons(responder, BEACONS_PER_TICK);
            }
            guard.node.missing_code()
        };
        for endpoint in service.peers_for(&needs, fanout) {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let State { node, population } = &mut *guard;
            let outcome = match population_path {
                Some(_) => {
                    let mut scorer = RoundScorer::new(registry.clone());
                    service
                        .dial_node_and_population(
                            &endpoint,
                            node,
                            population,
                            PopLimits::default(),
                            |node, candidate| scorer.score(node, candidate),
                        )
                        .map(|_| ())
                }
                None => service.dial_node_once(&endpoint, node),
            };
            match outcome {
                Ok(()) => {
                    eprintln!(
                        "outbound session: {} ok, {} entries now",
                        peer_id_string(&endpoint.peer.id()),
                        node.ledger().len()
                    );
                    persist(
                        &guard,
                        &checkpoint_path,
                        &root_key,
                        population_path.as_ref(),
                    );
                }
                Err(error) => {
                    eprintln!("outbound session: {error}");
                    // Tell the DHT, or every lookup that chose this peer waits
                    // on it forever. `peers_for` hands out the next hop of each
                    // lookup in flight and expects exactly one answer per
                    // contact; this is the failure half.
                    service.unreachable(endpoint.peer.id());
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}
