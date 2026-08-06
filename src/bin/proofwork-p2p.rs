//! Long-running p2p node.
//!
//! Identity files and bootstrap files are local configuration. They are never
//! placed in the append-only ledger.

use proofwork::canonical::Value;
use proofwork::checkpoint::RootKey;
use proofwork::gossip::{Candidate, Population};
use proofwork::ledger::Ledger;
use proofwork::node::Node;
use proofwork::p2p::discovery::Endpoint;
use proofwork::p2p::handshake::{PeerIdentity, PeerPublic};
use proofwork::p2p::multicast;
use proofwork::p2p::pop::PopLimits;
use proofwork::p2p::service::{Service, DEFAULT_FANOUT};
use proofwork::records::Objective;
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

fn usage() -> ! {
    eprintln!("usage: proofwork-p2p --identity FILE --root-key FILE --checkpoint FILE --listen ADDR --log FILE --root DIR [--bootstrap FILE ...] [--population FILE] [--fanout N]");
    std::process::exit(2);
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

fn load_endpoint(path: &Path) -> Result<Endpoint, String> {
    let value = Value::from_json(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let addr = value
        .get("addr")
        .and_then(Value::as_str)
        .ok_or("bootstrap.addr missing")?
        .parse::<SocketAddr>()
        .map_err(|e| e.to_string())?;
    let public = hex_decode(
        value
            .get("public")
            .and_then(Value::as_str)
            .ok_or("bootstrap.public missing")?,
    )?;
    let peer = PeerPublic::from_bytes(&public).map_err(|e| e.to_string())?;
    Ok(Endpoint::new(addr, peer))
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
            "--fanout" => &mut fanout,
            "--bootstrap" => {
                bootstrap.push(args.next().unwrap_or_else(|| usage()));
                continue;
            }
            _ => usage(),
        };
        *slot = Some(args.next().unwrap_or_else(|| usage()));
    }
    let identity_path = identity_path.unwrap_or_else(|| usage());
    let root_key_path = root_key_path.unwrap_or_else(|| usage());
    let checkpoint_path = checkpoint_path.unwrap_or_else(|| usage());
    let listen_addr = listen_addr
        .unwrap_or_else(|| usage())
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| usage());
    let log = log.unwrap_or_else(|| usage());
    let root = root.unwrap_or_else(|| usage());
    let fanout = match fanout {
        Some(text) => text.parse::<usize>().unwrap_or_else(|_| usage()),
        None => DEFAULT_FANOUT,
    };
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
            Ok(endpoint) => service.add_bootstrap(endpoint),
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
        std::process::exit(2)
    });
    // Exclusive: the daemon appends every record it imports from a peer, so
    // it is a writer and must not share a log with another one.
    let node = Node::new(
        Ledger::open_exclusive(log).unwrap_or_else(|e| {
            eprintln!("ledger: {e}");
            std::process::exit(2)
        }),
        root,
    );
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
        let mut guard = accept_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let State { node, population } = &mut *guard;
        let outcome = match accept_population_path {
            Some(_) => {
                let mut scorer = RoundScorer::new(accept_registry.clone());
                accept_service
                    .accept_node_and_population(
                        &listener,
                        node,
                        population,
                        PopLimits::default(),
                        |node, candidate| scorer.score(node, candidate),
                    )
                    .map(|_| ())
            }
            None => accept_service.accept_node_once(&listener, node).map(|_| ()),
        };
        match outcome {
            Ok(()) => persist(
                &guard,
                &accept_checkpoint_path,
                &accept_root_key,
                accept_population_path.as_ref(),
            ),
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
                Ok(()) => persist(
                    &guard,
                    &checkpoint_path,
                    &root_key,
                    population_path.as_ref(),
                ),
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
