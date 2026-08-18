//! One long-running node: the p2p service and the HTTP server, in one process.
//!
//! # Why this is a library module and not a binary
//!
//! It used to be the body of `cairn-p2p`, and publishing the log was a
//! *second* process running `cairn-serve` against the same file. That
//! topology works — [`Ledger::open`] takes no lock, so a reader is safe beside
//! the daemon's exclusive writer — but it makes an operator run two units, keep
//! two sets of paths in agreement, and discover by reading `docs/serving.md`
//! that the queue one process fills is drained by the other.
//!
//! The two loops share nothing but a directory, so there was never a reason for
//! them to share nothing but a directory. [`run`] starts both, and both binaries
//! call it, so there is one implementation of "be a node" rather than one per
//! entry point.
//!
//! # What sharing a process does and does not change
//!
//! It does not change the locking. [`serve::Serving`] holds no [`Node`]: it
//! re-reads the log per request, exactly as it did across a process boundary, so
//! the HTTP thread never contends for the mutex the sync rounds hold. That is
//! why this is a thread and not a rewrite.
//!
//! It does change one failure mode, for the better. The submission queue is
//! drained by whoever holds the ledger's write lock, which is this process; with
//! HTTP in the same process, a node that accepts a submission is by construction
//! a node that can admit it. The split version could be configured — easily —
//! into a server queueing into a directory no daemon was watching.
//!
//! # The bind happens on the caller's thread
//!
//! Deliberately. A daemon whose HTTP listener failed to bind but whose p2p side
//! came up is a node an operator believes is publishing and which is not, and
//! the evidence is one warning line scrolled off the top of a log. Binding
//! before the loop starts turns that into a startup refusal with the address in
//! it.

use std::collections::BTreeMap;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::canonical::Value;
use crate::checkpoint::RootKey;
use crate::gossip::{Candidate, Population};
use crate::ledger::Ledger;
use crate::node::Node;
use crate::p2p::discovery::{peer_id_string, Endpoint};
use crate::p2p::handshake::{PeerIdentity, PeerPublic};
use crate::p2p::multicast;
use crate::p2p::pop::PopLimits;
use crate::p2p::service::Service;
use crate::records::Objective;
use crate::serve;
use crate::time::timestamp;
use crate::verifiers::VerifierRegistry;

/// Beacons folded in per tick.
///
/// Bounded because the beacon socket is reachable by anyone on the segment: an
/// unbounded drain is a way for one host to hold the daemon's main loop. Any
/// backlog is picked up next tick, and a node re-announces every
/// `multicast::INTERVAL_SECONDS` regardless, so nothing is lost by deferring it.
const BEACONS_PER_TICK: usize = 64;

/// Seconds between sync rounds.
const TICK_SECONDS: u64 = 5;

/// Everything [`run`] needs. Both binaries build one of these from their flags.
///
/// Paths are taken as owned values rather than borrowed: the daemon outlives
/// every scope a caller would lend them from, and threading lifetimes through a
/// process-lifetime loop buys nothing.
pub struct Config {
    /// The peer identity file. Generated on first use if absent.
    pub identity: PathBuf,
    /// The checkpoint signing key. Generated on first use if absent.
    pub root_key: PathBuf,
    /// Where the signed checkpoint is written after every round that changed
    /// anything.
    pub checkpoint: PathBuf,
    /// The p2p listen address.
    pub listen: SocketAddr,
    /// The append-only log. Opened **exclusively**: this process is a writer.
    pub log: PathBuf,
    /// Bundle root that pinned verifier paths resolve against.
    pub root: PathBuf,
    /// Bootstrap endpoint files. Dial hints only; the peer id decides identity.
    pub bootstrap: Vec<PathBuf>,
    /// Gossip population file. `None` runs record sync without the population
    /// half.
    pub population: Option<PathBuf>,
    /// Submission spool. Drained each round, by this process, because this
    /// process holds the write lock.
    pub queue: Option<PathBuf>,
    /// How many peers to dial per round.
    pub fanout: usize,
    /// Publish the log over HTTP from this same process. `None` runs p2p only.
    pub serve: Option<String>,
    /// Bound on undrained submissions, when serving.
    pub max_queued: usize,
    /// The at-rest key, when the log is sealed.
    ///
    /// `None` uses [`crate::store::Store::default_key_path`], which is what the
    /// CLI does — so a daemon on a machine with `~/.cairn/key` opens the
    /// same logs the CLI writes, instead of reporting them as spliced.
    pub key_file: Option<PathBuf>,
}

impl Config {
    /// The mandatory half, with the optional half at its defaults.
    pub fn new(
        identity: impl Into<PathBuf>,
        root_key: impl Into<PathBuf>,
        checkpoint: impl Into<PathBuf>,
        listen: SocketAddr,
        log: impl Into<PathBuf>,
        root: impl Into<PathBuf>,
    ) -> Config {
        Config {
            identity: identity.into(),
            root_key: root_key.into(),
            checkpoint: checkpoint.into(),
            listen,
            log: log.into(),
            root: root.into(),
            bootstrap: Vec::new(),
            population: None,
            queue: None,
            fanout: crate::p2p::service::DEFAULT_FANOUT,
            serve: None,
            max_queued: serve::DEFAULT_MAX_QUEUED,
            key_file: None,
        }
    }

    /// Where the at-rest key lives: the flag, or the CLI's own default.
    fn key_path(&self) -> PathBuf {
        match &self.key_file {
            Some(path) => path.clone(),
            None => crate::store::Store::new(&self.root).default_key_path(),
        }
    }
}

// -- local configuration files ----------------------------------------------
//
// Identity and bootstrap files are local configuration. They are never placed
// in the append-only ledger.

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
        crate::secret_file::write_new(path, value.canonical_string().as_bytes())
            .map_err(|e| e.to_string())?;
        return Ok(identity);
    }
    let value =
        Value::from_json(&crate::secret_file::read_to_string(path).map_err(|e| e.to_string())?)
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
        .is_some_and(|recorded| recorded == peer_id_string(&endpoint.peer.id()))
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
    let addr = crate::p2p::discovery::dialable(addr).ok_or_else(|| {
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
        crate::secret_file::write_new(path, value.canonical_string().as_bytes())
            .map_err(|e| e.to_string())?;
        return Ok(key);
    }
    let value =
        Value::from_json(&crate::secret_file::read_to_string(path).map_err(|e| e.to_string())?)
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
    let signed = key.sign_ledger(node.ledger(), timestamp());
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
fn persist(state: &State, checkpoint: &Path, key: &RootKey, population: Option<&PathBuf>) {
    if let Err(error) = write_checkpoint(checkpoint, key, &state.node) {
        log::warn!("checkpoint: {error}");
    }
    if let Some(path) = population {
        if let Err(error) = save_population(path, &state.population) {
            log::warn!("population: {error}");
        }
    }
}

/// Bind the HTTP listener, if this node is publishing.
///
/// Separated from the spawn so the bind failure is the caller's to report,
/// before anything else starts. See the module docs.
fn bind_http(config: &Config) -> Result<Option<(TcpListener, serve::Serving)>, String> {
    let Some(addr) = &config.serve else {
        return Ok(None);
    };
    let listener = TcpListener::bind(addr.as_str())
        .map_err(|error| format!("cannot bind the HTTP listener on {addr}: {error}"))?;
    let mut serving = serve::Serving::new(&config.log, &config.root);
    // The same key the daemon opened the log with. Without it the HTTP half
    // reports the operator's own sealed log as altered on every request, while
    // the p2p half beside it reads it perfectly.
    serving = serving.with_key(config.key_path(), None);
    // The checkpoint this daemon writes is the one it publishes. Two paths for
    // one file would be a way to serve a checkpoint nobody is updating.
    serving = serving.with_checkpoint(&config.checkpoint);
    if let Some(queue) = &config.queue {
        serving = serving
            .accepting_into(queue)
            .with_max_queued(config.max_queued);
    }
    // Before the loops start, for the reason the bind is here: a node whose
    // HTTP half cannot read the log is one that answers 500 to every request
    // while the p2p half beside it works perfectly.
    serving
        .check_startup()
        .map_err(|error| format!("cannot publish this log: {error}"))?;
    Ok(Some((listener, serving)))
}

/// Run the node until the process is killed.
///
/// Returns `Err` only for a startup failure the operator has to fix: an
/// unreadable identity file, a log another process holds, an address that
/// cannot be bound. Once the loops are running, failures are logged and stepped
/// over — a node that stops on the first unreachable peer is not a node.
pub fn run(config: Config) -> Result<(), String> {
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
    // Sealed if the log on disk is sealed, or if a key exists and the log is
    // new -- the same rule the CLI applies, from the same function, because a
    // daemon that guessed differently would refuse to open its operator's own
    // log and report it as spliced.
    let codec = crate::store::resolve_codec(&config.log, &config.key_path(), None)
        .map_err(|e| format!("at-rest key: {e}"))?;
    let ledger =
        Ledger::open_exclusive_with(&config.log, codec).map_err(|e| format!("ledger: {e}"))?;
    let identity = Arc::new(load_identity(&config.identity).map_err(|e| format!("identity: {e}"))?);
    let root_key = Arc::new(load_root_key(&config.root_key).map_err(|e| format!("root key: {e}"))?);

    let mut service = Service::new(Arc::clone(&identity));
    for path in &config.bootstrap {
        let (endpoint, placeholder) =
            load_endpoint(path).map_err(|e| format!("bootstrap {}: {e}", path.display()))?;
        if placeholder {
            // Loud, and at startup rather than at the first failed dial: a
            // placeholder key fails the handshake with a transport error
            // indistinguishable from a closed port, so an operator who has
            // already checked the address and the firewall has nothing left to
            // suspect. Said once here, the one remaining explanation is on
            // screen before the first dial rather than absent from all of them.
            log::warn!(
                "bootstrap {}: still carries the PLACEHOLDER key \
                 `cairn-gen-bootstrap` generated, which authenticates nobody. \
                 Dials to {} will fail their handshake and report a plain transport \
                 error. Replace \"public\" in that file with the seed's real key -- \
                 the seed operator can print theirs from the \"public\" field of \
                 their --identity file.",
                path.display(),
                endpoint.addr
            );
        }
        service.add_bootstrap(endpoint);
    }

    // Bound before either loop starts, so a node that cannot publish refuses at
    // startup rather than looking healthy while serving nothing.
    let http = bind_http(&config)?;

    // Zero-configuration discovery on the local segment. Optional by design:
    // a host with no multicast route is a node without LAN discovery, not a
    // node that cannot start, so a failure here is reported and stepped over.
    let beacon =
        match multicast::Responder::bind(service.identity(), config.listen.port(), multicast::PORT)
        {
            Ok(responder) => Some(responder),
            Err(error) => {
                log::warn!("multicast: {error} -- continuing without LAN discovery");
                None
            }
        };

    let listener = service.listen(config.listen).map_err(|e| {
        // The one bind failure worth explaining, because the address that
        // causes it is the address an operator has every reason to think is
        // right. A cloud instance's public address is NAT'd to it and is on no
        // local interface, so `--listen <public ip>:9000` cannot bind at all --
        // and the fix is the counterintuitive one of binding the wildcard and
        // publishing the public address in the bootstrap file instead.
        if !config.listen.ip().is_unspecified() {
            format!(
                "listen: {e}\nlisten: {} is not an address on this host. A cloud \
                 instance's public address is NAT'd to it and never appears on an \
                 interface -- bind 0.0.0.0:{} and put the public address in the \
                 bootstrap file you hand out, which is only ever a dial hint.",
                config.listen.ip(),
                config.listen.port()
            )
        } else {
            format!("listen: {e}")
        }
    })?;
    log::info!("listening on {}", config.listen);

    // Exclusive, opened above: the daemon appends every record it imports from
    // a peer, so it is a writer and must not share a log with another one.
    let node = Node::new(ledger, &config.root);
    // `Spool::at` only names a directory; the server creates it when it first
    // queues something, and an absent one simply drains nothing.
    let spool = config.queue.as_ref().map(serve::Spool::at);
    match &config.queue {
        Some(path) => log::info!("queue: draining {} each round", path.display()),
        None => log::info!("queue: none -- submissions arrive only from peers"),
    }
    let population = match &config.population {
        Some(path) => load_population(path).map_err(|e| format!("population: {e}"))?,
        None => Population::default(),
    };
    // Publish before serving. A log written before verifier code was
    // content-addressed has objectives whose checkers were never copied into the
    // store, and without this their funder would be the one node on the network
    // unable to serve the very blobs its peers are about to ask it for.
    // Idempotent, and cheap: one stat per pin already held.
    let servable = node.publish_local_code();
    let missing = node.missing_code().len();
    log::info!("verifier code: {servable} servable, {missing} unmet");

    let registry = node.registry().clone();
    let state = Arc::new(Mutex::new(State { node, population }));
    {
        let guard = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        write_checkpoint(&config.checkpoint, &root_key, &guard.node)
            .map_err(|e| format!("checkpoint: {e}"))?;
    }

    // The HTTP half. Spawned after the checkpoint exists, so the first request
    // for `/checkpoint` finds one.
    if let Some((listener, serving)) = http {
        // `serve` reports its own address and mode; the extra line is about the
        // topology, which is the part that changed.
        log::info!("publishing over HTTP from this process");
        thread::spawn(move || {
            if let Err(error) = serve::serve_on(listener, serving) {
                // The p2p half is still a node, so this is not fatal -- but it
                // is silent otherwise, and a node that stopped publishing an
                // hour ago looks exactly like one that never was asked.
                log::error!("http: {error}");
            }
        });
    }

    let service = Arc::new(service);
    let accept_service = Arc::clone(&service);
    let accept_state = Arc::clone(&state);
    let accept_root_key = Arc::clone(&root_key);
    let accept_checkpoint = config.checkpoint.clone();
    let accept_population = config.population.clone();
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
                log::warn!("accept: {error}");
                continue;
            }
        };
        let mut guard = accept_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let State { node, population } = &mut *guard;
        let outcome = match accept_population {
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
                log::info!(
                    "inbound session: {} ok, {} entries now",
                    peer_id_string(&remote),
                    node.ledger().len()
                );
                persist(
                    &guard,
                    &accept_checkpoint,
                    &accept_root_key,
                    accept_population.as_ref(),
                );
            }
            Err(error) => log::warn!("inbound session: {error}"),
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
        // Admit whatever was queued over HTTP, before dialling anybody.
        //
        // This is what makes the topology in `docs/serving.md` actually
        // compose. A submission "lands in a spool directory, and the operator's
        // own node admits it" -- but a `Ledger` is single-writer by
        // enforcement, so `cairn drain` wanted the write lock this daemon
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
                log::info!("drain: {}", admission.note);
                // Removed whether admitted or refused. Nearly every refusal is
                // permanent -- a stale epoch, a citation that is not an
                // accepted claim -- and a queue that retries one never empties.
                if let Err(error) = queue.take(&path) {
                    log::warn!("drain: cannot remove {}: {error}", path.display());
                }
            }
            if drained {
                // Settlement is deferred to the close of the reveal epoch, so a
                // drain that admitted a reveal into an epoch that has already
                // closed settles here rather than waiting for a peer to dial.
                let _ = guard.node.settle_at(&timestamp());
                persist(
                    &guard,
                    &config.checkpoint,
                    &root_key,
                    config.population.as_ref(),
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
        for endpoint in service.peers_for(&needs, config.fanout) {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let State { node, population } = &mut *guard;
            let outcome = match config.population {
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
                    log::info!(
                        "outbound session: {} ok, {} entries now",
                        peer_id_string(&endpoint.peer.id()),
                        node.ledger().len()
                    );
                    persist(
                        &guard,
                        &config.checkpoint,
                        &root_key,
                        config.population.as_ref(),
                    );
                }
                Err(error) => {
                    log::warn!("outbound session: {error}");
                    // Tell the DHT, or every lookup that chose this peer waits
                    // on it forever. `peers_for` hands out the next hop of each
                    // lookup in flight and expects exactly one answer per
                    // contact; this is the failure half.
                    service.unreachable(endpoint.peer.id());
                }
            }
        }
        thread::sleep(Duration::from_secs(TICK_SECONDS));
    }
}
