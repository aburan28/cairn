//! One long-running node: the p2p service and the HTTP server, in one process.
//!
//! # Why this is a library module and not a binary
//!
//! It used to be the body of `cairn-p2p` (a separate binary then; the
//! `cairn p2p` subcommand now), and publishing the log was a *second* process
//! running `cairn-serve` (now `cairn serve`) against the same file. That
//! topology works — [`Ledger::open`] takes no lock, so a reader is safe beside
//! the daemon's exclusive writer — but it makes an operator run two units, keep
//! two sets of paths in agreement, and discover by reading `docs/serving.md`
//! that the queue one process fills is drained by the other.
//!
//! The two loops share nothing but a directory, so there was never a reason for
//! them to share nothing but a directory. [`run`] starts both, and all three
//! entry points call it, so there is one implementation of "be a node" rather
//! than one per entry point.
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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::canonical::{short, Value};
use crate::checkpoint::RootKey;
use crate::crypto::envelope::CommitteeKey;
use crate::gossip::{Candidate, Population};
use crate::ledger::Ledger;
use crate::node::Node;
use crate::p2p::discovery::{peer_id_string, Endpoint};
use crate::p2p::handshake::{PeerIdentity, PeerPublic};
use crate::p2p::multicast;

/// Moves the LAN beacon port, or `off` disables beacons. See `run` in this
/// module for why a node must be able to opt out.
pub const BEACON_PORT_ENV: &str = "CAIRN_BEACON_PORT";
use crate::p2p::pop::PopLimits;
use crate::p2p::seeds::{self, Seed};
use crate::p2p::service::{SeedOutcome, Service, KEY_FETCH_BACKOFF};
use crate::p2p::sessions::{Direction, Sessions};
use crate::p2p::transport;
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
pub const TICK_SECONDS: u64 = 5;

/// Ticks between LAN beacon announcements.
const BEACON_EVERY_TICKS: u64 = multicast::INTERVAL_SECONDS.div_ceil(TICK_SECONDS);

/// Inbound sessions allowed in progress at once, handshake included.
///
/// A silent one holds its thread for at most the handshake timeout, so this bounds what
/// a peer that opens sockets and goes quiet can cost: a few idle threads, not
/// the accept loop.
const MAX_INBOUND_HANDSHAKES: usize = 16;

/// Releases one inbound handshake slot however the session ends.
struct InFlight(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Ticks between checks of the store against its cap: a minute. Walking the
/// data directory is not free, and a log does not grow by a meaningful
/// fraction of any sensible cap in sixty seconds.
const STORE_CHECK_TICKS: u64 = 12;

/// Everything [`run`] needs. All three entry points build one from their flags.
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
    /// How outbound dials leave this node, as a proxy configuration string.
    ///
    /// `None` or `"direct"` dials straight. `socks5://host:port` routes every
    /// dial through a SOCKS5 proxy — a Tor client, an obfs4/Snowflake bridge, a
    /// corporate egress — so a censoring firewall is something to route around
    /// rather than something that stops the node. See [`crate::p2p::proxy`].
    pub proxy: Option<String>,
    /// Serve MCP over this process's stdin/stdout against the same node state.
    ///
    /// Off for the standalone p2p and HTTP binaries. `cairn run` enables it so
    /// an MCP client can launch one process without creating a second ledger
    /// writer.
    pub mcp: bool,
    /// Serve the same MCP over Streamable HTTP on this address, for clients
    /// that cannot spawn a subprocess. Independent of [`Config::mcp`]: stdio
    /// and HTTP may serve together, each with its own sessions over the one
    /// shared node. Plain HTTP -- see `mcp::start_shared_http`.
    pub mcp_http: Option<String>,
    /// Ed25519 identity used to sign MCP submissions. This is deliberately
    /// separate from [`Config::identity`], which is the transport KEM key.
    pub mcp_identity: Option<PathBuf>,
    /// Total reward agents may fund through MCP `post_objective` while this
    /// process runs. `None` falls back to `CAIRN_MCP_MAX_SPEND`, then zero.
    pub mcp_max_spend: Option<u64>,
    /// Ed25519 identity this node's committee seats are registered under: the
    /// one that signed the peer record naming [`Config::identity`]'s transport
    /// id. With it, the node publishes the shares its seats owe for sealed
    /// submissions; without it, it still opens sealed submissions that others'
    /// shares have made openable. Falls back to [`Config::mcp_identity`].
    pub committee_identity: Option<PathBuf>,
    /// A store with a size cap to hold this node under while it runs.
    ///
    /// Checked once a minute: reclaimable content is
    /// evicted to make room, and when the pinned content alone outgrows the
    /// cap the node stops, which is what the cap means -- see
    /// [`crate::store`]: "a cap smaller than your log stops your node; it does
    /// not prune your log". `None`, or a store with no limit, checks nothing.
    pub store: Option<crate::store::Store>,
    /// Run the validator loop under this signing identity: every tick,
    /// re-verify claims it has not stood behind and post attestations under
    /// bond. `None` runs no loop. Falls back to [`crate::attestor::IDENTITY_ENV`].
    /// See [`crate::attestor`].
    pub attest_identity: Option<PathBuf>,
    /// Verifier runs per tick for that loop. Falls back to
    /// [`crate::attestor::LIMIT_ENV`], then [`crate::attestor::DEFAULT_LIMIT_PER_TICK`].
    pub attest_limit: Option<usize>,
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
            proxy: None,
            mcp: false,
            mcp_http: None,
            mcp_identity: None,
            mcp_max_spend: None,
            committee_identity: None,
            store: None,
            attest_identity: None,
            attest_limit: None,
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

fn load_endpoint(
    path: &Path,
    proxy: &crate::p2p::proxy::Proxy,
) -> Result<(Endpoint, bool), String> {
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
    let addr = crate::p2p::discovery::dialable_via(addr, proxy).ok_or_else(|| {
        if matches!(proxy, crate::p2p::proxy::Proxy::Direct) {
            format!("bootstrap.addr {addr:?} is neither an address nor a name that resolves")
        } else {
            format!(
                "bootstrap.addr {addr:?} is a name, and dials go through a proxy: resolving it \
                 here would tell this network's resolver whom this node is reaching. Use the \
                 peer's IP address"
            )
        }
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

// Both files below go through `secret_file::replace_public` rather than
// `fs::write`, which truncates in place: a daemon killed between the truncate
// and the last byte left a torn checkpoint that failed every reader's
// verification, or a torn population file that refused the next start -- and
// the daemon is killed mid-write routinely, since it rewrites both every round
// and an operator's `kill` lands wherever it lands. The public variant, not
// `replace`: `GET /checkpoint` serves this file and a reader copies it, so
// 0600 would be the wrong mode.

fn write_checkpoint(path: &Path, key: &RootKey, node: &Node) -> Result<(), String> {
    let signed = key.sign_ledger(node.ledger(), timestamp());
    crate::secret_file::replace_public(path, signed.to_value().canonical_string().as_bytes())
        .map_err(|e| e.to_string())
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
    crate::secret_file::replace_public(path, population.to_value().canonical_string().as_bytes())
        .map_err(|e| e.to_string())
}

/// Settle every epoch that has come due, and say whether the log changed.
///
/// Run once per tick, unconditionally. It used to run only after a drain that
/// admitted or refused something, and every p2p session settles on its own
/// through `apply_records` -- so a node with no reachable peers and an empty
/// spool never settled a closed epoch at all. Its contributors' claims sat
/// accepted and unpaid, and its checkpoint stood still, for as long as nobody
/// dialled it. That is the ordinary state of a node run alone, which is how
/// every node starts.
///
/// The answer is what gates the checkpoint rewrite. Nothing due is the common
/// case, and re-signing and rewriting the checkpoint every five seconds for a
/// log that has not moved is churn a reader polling `/checkpoint` would see as
/// change.
/// What a node needs to serve on sealed-submission committees.
struct Committee {
    /// The transport identity, as a committee key. See
    /// [`CommitteeKey::from_transport`].
    key: CommitteeKey,
    /// The identity the seats were registered under. `None` opens others'
    /// reveals but publishes no shares.
    signer: Option<crate::crypto::identity::Identity>,
    /// Commitments that failed to open, with how many shares were published
    /// at the time. Retried only once more shares arrive: the subset search is
    /// bounded, but repeating a failed one every tick is pure waste.
    failed: BTreeMap<String, usize>,
    /// Commitments whose share for this seat does not decrypt, already said
    /// once. It stays owed every tick, and the warning is worth one line.
    unopenable: BTreeSet<String>,
    /// Where this node's own sealed submissions keep their dealer secrets
    /// (`<log>.dealings`), to answer complaints about them.
    dealings: PathBuf,
}

/// Publish owed committee shares and open what has become openable.
///
/// The step that makes a sealed submission survive its submitter. Before it
/// existed, nothing in a running node ever published a share or opened a
/// reveal, so a sequencer that dropped a reveal simply won.
fn committee_tick(node: &mut Node, committee: &mut Committee, now: &str) -> bool {
    let Some(now_epoch) = crate::time::parse_rfc3339(now)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .map(|seconds| crate::partition::epoch_of(seconds, crate::partition::epoch_seconds()))
    else {
        return false;
    };
    let before = node.ledger().len();
    if let Some(signer) = &committee.signer {
        for (commitment, result) in
            node.post_owed_committee_shares(&committee.key, signer, now_epoch, now)
        {
            match result {
                Ok(_) => log::info!("committee: published our share of {}", short(&commitment)),
                Err(error @ crate::node::RuleViolation::ShareWillNotOpen { .. }) => {
                    if committee.unopenable.insert(commitment.clone()) {
                        log::warn!("committee: {error}");
                    }
                }
                Err(error) => log::debug!(
                    "committee: share of {} refused: {error}",
                    short(&commitment)
                ),
            }
        }
    }
    // Complaints first: a seat whose share does not open or does not check
    // says so inside the window, which is what obliges its dealer to answer.
    if let Some(signer) = &committee.signer {
        for (commitment, result) in
            node.post_owed_complaints(&committee.key, signer, now_epoch, now)
        {
            match result {
                Ok(_) => log::warn!(
                    "committee: our share of {} does not open or does not check; complained, \
                     and its dealer must answer",
                    short(&commitment)
                ),
                Err(error) => log::debug!(
                    "committee: complaint about {} refused: {error}",
                    short(&commitment)
                ),
            }
        }
    }
    // Then the answers this node owes as a dealer, and the dealings nothing
    // can use any more.
    let dealt = crate::sealed::dealings::load(&committee.dealings);
    if !dealt.is_empty() {
        for (commitment, result) in node.post_owed_answers(&dealt, now_epoch, now) {
            match result {
                Ok(_) => log::info!(
                    "dealer: answered a complaint about {} with the seat's share",
                    short(&commitment)
                ),
                Err(error) => log::warn!(
                    "dealer: could not answer a complaint about {}: {error}",
                    short(&commitment)
                ),
            }
        }
        for commitment in dealt.keys() {
            if node.answer_window_closed(commitment, now_epoch) {
                if let Err(error) = crate::sealed::dealings::forget(&committee.dealings, commitment)
                {
                    log::warn!(
                        "dealer: cannot delete the dealing for {}: {error}",
                        short(commitment)
                    );
                }
            }
        }
    }
    let failed = &committee.failed;
    let attempts = node.open_due_sealed(now_epoch, now, |commitment, published| {
        failed
            .get(commitment)
            .is_some_and(|tried| *tried >= published)
    });
    for (commitment, published, outcome) in attempts {
        match outcome {
            Ok(_) => {
                log::info!("committee: opened sealed submission {}", short(&commitment));
                committee.failed.remove(&commitment);
            }
            Err(error) => match retry_after(&error, published) {
                None => log::debug!("committee: {} waits: {error}", short(&commitment)),
                Some(tried) => {
                    log::warn!("committee: cannot open {}: {error}", short(&commitment));
                    committee.failed.insert(commitment, tried);
                }
            },
        }
    }
    node.ledger().len() != before
}

/// What to remember about a sealed submission that did not open, as the
/// published-share count past which it is worth trying again. `None` forgets
/// it, so the next tick retries.
///
/// A reveal held by the dealing windows clears with time, not with more
/// shares, so remembering it would skip every retry until a share arrived that
/// may never come -- and the committee would never reveal it. A disqualified
/// one opens for no number of shares, so it is never tried again.
fn retry_after(error: &crate::node::RuleViolation, published: usize) -> Option<usize> {
    use crate::node::RuleViolation;
    match error {
        RuleViolation::AwaitingComplaints { .. } | RuleViolation::AwaitingDealerAnswer { .. } => {
            None
        }
        RuleViolation::DealerDisqualified { .. } => Some(usize::MAX),
        _ => Some(published),
    }
}

fn settle_tick(node: &mut Node, now: &str) -> bool {
    let before = node.ledger().len();
    match node.settle_at(now) {
        Ok(outcomes) => {
            let paid = outcomes.iter().filter(|o| o.settled).count();
            if !outcomes.is_empty() {
                log::info!(
                    "settle: {} claim(s) in batch, {paid} paid, {} entries now",
                    outcomes.len(),
                    node.ledger().len()
                );
            }
        }
        Err(error) => log::warn!("settle: {error}"),
    }
    // Measured on the log rather than on the outcomes: a batch record is
    // appended even when every claim in it settled for zero, and it is the
    // log that the checkpoint signs.
    node.ledger().len() != before
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
pub(crate) struct State {
    pub(crate) node: Node,
    population: Population,
    /// An in-process MCP request appended to `node`; the daemon consumes this
    /// flag on its next tick and rewrites the checkpoint before advertising
    /// the new head.
    pub(crate) dirty: bool,
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
fn bind_http(
    config: &Config,
    sessions: Arc<Mutex<Sessions>>,
    peers: (&str, Option<usize>),
    journal: crate::journal::Shared,
    agents: Option<crate::mcp::SharedPresence>,
) -> Result<Option<(TcpListener, serve::Serving)>, String> {
    let Some(addr) = &config.serve else {
        return Ok(None);
    };
    let listener = TcpListener::bind(addr.as_str())
        .map_err(|error| format!("cannot bind the HTTP listener on {addr}: {error}"))?;
    let mut serving = serve::Serving::new(&config.log, &config.root);
    // The HTTP port, forwarded by the router only when the operator asks
    // (`CAIRN_PORTMAP_HTTP`): a fleet leader behind a home router that rented
    // machines must reach. It makes this node a public seed, so it is never
    // the default, and the decision is published either way.
    let bound = listener
        .local_addr()
        .map_err(|error| format!("the HTTP listener on {addr}: {error}"))?;
    let decision = crate::p2p::reach::decide_http(
        std::env::var(crate::p2p::reach::HTTP_ENV).ok().as_deref(),
        bound.ip(),
    );
    let external = Arc::new(Mutex::new(crate::p2p::reach::Report::off(
        crate::p2p::reach::Mode::Off,
        decision.note.clone().unwrap_or_default(),
        crate::time::unix_seconds(),
    )));
    if decision.mode != crate::p2p::reach::Mode::Off {
        log::warn!(
            "portmap: asking the router to forward the HTTP port {} ({}={}); this node's HTTP \
             side becomes reachable from the internet",
            bound.port(),
            crate::p2p::reach::HTTP_ENV,
            decision.mode.as_str()
        );
        let shared = Arc::clone(&external);
        let (mode, port) = (decision.mode, bound.port());
        thread::spawn(move || {
            crate::p2p::reach::run(mode, port, move |report| {
                *shared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = report;
            })
        });
    }
    serving = serving.with_http_external(external);
    // The same key the daemon opened the log with. Without it the HTTP half
    // reports the operator's own sealed log as altered on every request, while
    // the p2p half beside it reads it perfectly.
    serving = serving.with_key(config.key_path(), None);
    // The checkpoint this daemon writes is the one it publishes. Two paths for
    // one file would be a way to serve a checkpoint nobody is updating.
    serving = serving.with_checkpoint(&config.checkpoint);
    // The roster the p2p loops write into, so `GET /sessions` can say whom
    // this process has reached rather than repeating the log's address book
    // under a disclaimer.
    serving = serving.with_sessions(sessions);
    // One journal for the whole process: the p2p loops, the HTTP handlers and
    // the MCP session all narrate into it, and `GET /events` serves it.
    serving = serving.with_journal(journal);
    if let Some(agents) = agents {
        serving = serving.with_agents(agents);
    }
    // A fleet leader signs the records its workers hand it over HTTP, with
    // the ed25519 identity MCP submissions are signed with unless
    // `CAIRN_FLEET_IDENTITY` names another. Refused at startup when the
    // networks are mistyped or there is no key to sign with.
    serving = serving.fleet_from_env(config.mcp_identity.as_deref())?;
    serving = serving.with_peer_policy(peers.0, peers.1);
    if let Some(queue) = &config.queue {
        serving = serving
            .accepting_into(queue)
            .with_max_queued(config.max_queued);
    }
    // Optional, and a no-op when nothing is configured. A bad client id is a
    // line on stderr, not a node that refuses to publish.
    serving = serving.enable_google_from_env();
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
/// Returns `Err` for a startup failure the operator has to fix: an
/// unreadable identity file, a log another process holds, an address that
/// cannot be bound. Once the loops are running, failures are logged and stepped
/// over — a node that stops on the first unreachable peer is not a node.
///
/// With one exception, which is a decision rather than a failure: a store that
/// outgrows the size cap its operator set ([`Config::store`]). A full disk is
/// an accident and the node rides it out; a cap is an instruction, and a node
/// that kept writing past it would make the cap decoration.
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

    // How this node's dials leave it. Parsed once, at startup, so a
    // mistyped proxy is a refusal to start rather than a dial that silently
    // falls back to direct and hands a censor the fingerprint the operator
    // meant to hide.
    let proxy = match config.proxy.as_deref() {
        Some(text) => crate::p2p::proxy::Proxy::parse(text).map_err(|e| format!("proxy: {e}"))?,
        None => crate::p2p::proxy::Proxy::Direct,
    };
    match &proxy {
        crate::p2p::proxy::Proxy::Direct => {}
        crate::p2p::proxy::Proxy::Socks5 { addr, .. } => {
            log::info!("outbound dials route through SOCKS5 proxy {addr}");
        }
    }
    // This node's own transport id, said out loud once. It is the one thing a
    // peer needs from here that is not on the wire yet: `cairn peer` vouches
    // for a transport id, a bootstrap file carries the key that hashes to it,
    // and until now an operator asked to hand over "your peer id" had to
    // derive it from a 261 KiB key file themselves.
    log::info!(
        "peer id {} -- give this and the address below to anyone adding this node",
        peer_id_string(&identity.to_public().id())
    );
    let mut service = Service::with_proxy(Arc::clone(&identity), proxy);
    // Whom this node will peer with. Read before the bootstrap files so a
    // `bootstrap` policy can take their ids as they load; refused at startup
    // when mistyped, like the proxy, rather than silently open.
    let peer_policy = crate::fleet::PeerPolicy::from_env()
        .map_err(|e| format!("{}: {e}", crate::fleet::PEERS_ENV))?;
    let mut allowed_peers: BTreeSet<crate::p2p::handshake::PeerId> = match &peer_policy {
        crate::fleet::PeerPolicy::Open => BTreeSet::new(),
        crate::fleet::PeerPolicy::Allow { ids, .. } => ids.clone(),
    };
    let allow_bootstrap = matches!(
        &peer_policy,
        crate::fleet::PeerPolicy::Allow {
            bootstrap: true,
            ..
        }
    );
    for path in &config.bootstrap {
        let (endpoint, placeholder) = load_endpoint(path, service.proxy())
            .map_err(|e| format!("bootstrap {}: {e}", path.display()))?;
        if placeholder {
            // Loud, and at startup rather than at the first failed dial: a
            // placeholder key fails the handshake with a transport error
            // indistinguishable from a closed port, so an operator who has
            // already checked the address and the firewall has nothing left to
            // suspect. Said once here, the one remaining explanation is on
            // screen before the first dial rather than absent from all of them.
            log::warn!(
                "bootstrap {}: still carries the PLACEHOLDER key \
                 `cairn gen-bootstrap` generated, which authenticates nobody. \
                 Dials to {} will fail their handshake and report a plain transport \
                 error. Replace \"public\" in that file with the seed's real key -- \
                 the seed operator can print theirs from the \"public\" field of \
                 their --identity file.",
                path.display(),
                endpoint.addr
            );
        }
        if allow_bootstrap {
            allowed_peers.insert(endpoint.peer.id());
        }
        service.add_bootstrap(endpoint);
    }
    if !peer_policy.is_open() {
        if allowed_peers.is_empty() {
            return Err(format!(
                "{}={:?} names no peer at all: `bootstrap` needs at least one --bootstrap file, or list the peer ids to allow",
                crate::fleet::PEERS_ENV,
                std::env::var(crate::fleet::PEERS_ENV).unwrap_or_default()
            ));
        }
        log::info!(
            "peers: allowlist of {} ({}); every other peer is refused after the handshake, and nothing is learned from beacons, seeds or hints about anyone else",
            allowed_peers.len(),
            crate::fleet::PEERS_ENV
        );
        service.restrict_peers(allowed_peers);
    }

    // The seed list: built in, named by `CAIRN_SEEDS`, or off. Before this a
    // node reached `launch/seeds.json` only through `make seeds` and a
    // `--bootstrap` file, which Cairn.app never ran, so every node it started
    // was LAN-only. Read at startup so a named list that cannot be read is a
    // refusal here rather than a node that looks like a network that is down.
    let seed_source = seeds::Source::from_env();
    let mut seed_list = seed_source
        .load()
        .map_err(|e| format!("seeds ({}): {e}", seed_source.describe()))?;
    // The list compiled into the binary is already stale the day a seed moves.
    // Cairn.app never runs `make seeds`, so without this refresh a desktop
    // node dials the dead address forever and the only repair is a file the
    // person has to fetch by hand. The operator's own list (`CAIRN_SEEDS` a
    // path, or `off`) is left alone: they already chose it.
    if seed_source == seeds::Source::BuiltIn {
        match seeds::fetch_published() {
            Some(published) => {
                let before = seed_list.seeds.len();
                seed_list = seeds::merge(seed_list, published);
                let added = seed_list.seeds.len() - before;
                if added > 0 {
                    log::info!(
                        "seeds: published list added {added} seed(s) that this binary was not built with"
                    );
                }
            }
            None => log::warn!(
                "seeds: published list not read; dialling the list compiled into this binary"
            ),
        }
    }
    for skipped in &seed_list.skipped {
        log::warn!("seeds: skipping {}: {}", skipped.name, skipped.why);
    }
    let seed_list = seed_list.seeds;
    if seed_source == seeds::Source::Off {
        log::info!(
            "seeds: off ({}); this node dials only bootstrap files, its log's peers and the LAN",
            seeds::SEEDS_ENV
        );
    } else if seed_list.is_empty() {
        log::warn!(
            "seeds: {} names no seed this node can dial",
            seed_source.describe()
        );
    } else {
        log::info!(
            "seeds: {} from {}; {}=off runs without them",
            seed_list.len(),
            seed_source.describe(),
            seeds::SEEDS_ENV
        );
    }

    // Bound before either loop starts, so a node that cannot publish refuses at
    // startup rather than looking healthy while serving nothing.
    // Who this node has spoken to, for the HTTP half to publish. Created
    // before the listener is bound so the roster exists however the start
    // fails after this point, and shared with every loop that runs a session.
    let sessions = Arc::new(Mutex::new(Sessions::new(crate::time::unix_seconds())));
    // What this process saw happen, for `GET /events`. See `crate::journal`.
    let journal = crate::journal::Journal::shared(crate::time::unix_seconds());
    // Who is attached over MCP, for `GET /network`, when anyone can be.
    let agents = config.mcp.then(crate::mcp::Presence::shared);
    let http = bind_http(
        &config,
        Arc::clone(&sessions),
        (peer_policy.as_str(), service.allowed_peers()),
        Arc::clone(&journal),
        agents.clone(),
    )?;

    // Zero-configuration discovery on the local segment. Optional by design:
    // a host with no multicast route is a node without LAN discovery, not a
    // node that cannot start, so a failure here is reported and stepped over.
    //
    // `CAIRN_BEACON_PORT` moves the beacon port, or `off` turns beacons off.
    // For tests and demos, which learned this the hard way: once two nodes on
    // one host could really hear each other, a smoke test's node found the
    // developer's live node on the same segment, synced with it, and failed
    // because its claim had been settled somewhere else. A node meant to be
    // alone must be able to say so.
    let beacon_port = match std::env::var(BEACON_PORT_ENV) {
        Ok(raw) if raw.trim().eq_ignore_ascii_case("off") || raw.trim() == "0" => None,
        Ok(raw) => match raw.trim().parse::<u16>() {
            Ok(port) => Some(port),
            Err(_) => {
                log::warn!(
                    "{BEACON_PORT_ENV}={raw:?} is neither a port nor `off`; using {}",
                    multicast::PORT
                );
                Some(multicast::PORT)
            }
        },
        // Off by default behind a proxy. A beacon announces this node's peer id
        // and port to the local segment every interval, and a node that routes
        // through Tor or a bridge is hiding from whoever runs that segment.
        // Setting the variable explicitly still turns them on.
        Err(_) if !matches!(service.proxy(), crate::p2p::proxy::Proxy::Direct) => {
            log::info!(
                "multicast: beacons off because dials go through a proxy; \
                 {BEACON_PORT_ENV}={} turns them on",
                multicast::PORT
            );
            None
        }
        Err(_) => Some(multicast::PORT),
    };
    let beacon = beacon_port.and_then(|port| {
        match multicast::Responder::bind(service.identity(), config.listen.port(), port) {
            Ok(responder) => {
                // Said, as failing and `off` already are. A reader that hears
                // nothing has to guess, and the macOS app's Node pane did: it
                // printed a 30-second cadence (announcing happens every tick)
                // and the default port even when `CAIRN_BEACON_PORT` moved it.
                log::info!(
                    "multicast: beacon bound on {}:{port}; announcing every {}s",
                    multicast::GROUP,
                    BEACON_EVERY_TICKS * TICK_SECONDS
                );
                Some(responder)
            }
            Err(error) => {
                log::warn!("multicast: {error} -- continuing without LAN discovery");
                None
            }
        }
    });
    if beacon.is_none()
        && beacon_port.is_none()
        && matches!(service.proxy(), crate::p2p::proxy::Proxy::Direct)
    {
        log::info!("multicast: off ({BEACON_PORT_ENV}); no LAN discovery for this node");
    }

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
    sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .identify(service.identity(), config.listen);
    crate::journal::note(
        &journal,
        crate::journal::Kind::Node,
        crate::journal::Tone::Good,
        &format!(
            "Node started: peers reach it at {}{}{}",
            config.listen,
            config
                .serve
                .as_deref()
                .map(|addr| format!(", its reader and workers at http://{addr}"))
                .unwrap_or_default(),
            if config.mcp {
                ", and an agent over MCP on stdio"
            } else {
                ""
            }
        ),
        None,
    );

    // Ask the router to forward the p2p port, so a node behind a home router
    // can be dialled and not only dial. On a thread of its own: every call in
    // `reach` waits on a gateway that is usually not there, and the decision
    // not to ask is published too, so a reader sees why rather than a blank.
    // Off behind a proxy for the reason beacons are, and off on a loopback
    // listen because nothing outside this host can be forwarded to it.
    let decision = crate::p2p::reach::decide(
        std::env::var(crate::p2p::reach::ENV).ok().as_deref(),
        config.listen.ip(),
        !matches!(service.proxy(), crate::p2p::proxy::Proxy::Direct),
    );
    if let Some(note) = &decision.note {
        log::info!("portmap: {note}");
    }
    match decision.mode {
        crate::p2p::reach::Mode::Off => {
            sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .set_external(crate::p2p::reach::Report::off(
                    crate::p2p::reach::Mode::Off,
                    decision.note.clone().unwrap_or_default(),
                    crate::time::unix_seconds(),
                ));
        }
        mode => {
            log::info!(
                "portmap: {} ({}={}); asking the router to forward port {}",
                mode.as_str(),
                crate::p2p::reach::ENV,
                mode.as_str(),
                config.listen.port()
            );
            let roster = Arc::clone(&sessions);
            let port = config.listen.port();
            thread::spawn(move || {
                crate::p2p::reach::run(mode, port, move |report| {
                    roster
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .set_external(report);
                })
            });
        }
    }

    // Exclusive, opened above: the daemon appends every record it imports from
    // a peer, so it is a writer and must not share a log with another one.
    // Never `interactive()`, even with MCP on: this registry is the one the
    // shared node settles, admits and audits with, and those must honour the
    // objective's own declared bound or the same claim settles differently on
    // `cairn run` than on `cairn p2p` over the same log. The MCP server keeps
    // its client responsive by applying the ceiling to its own throwaway clone
    // in `score_candidate`, which records nothing.
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
    // The toolchains behind the kinds, as `GET /verifiers` reports them, so
    // a node that will answer `unavailable` to every Lean proof says so in
    // its first lines rather than at the first claim.
    log::info!(
        "verifiers: {}",
        describe_readiness(&node.registry().readiness())
    );
    // What the operator declared this node for, said once at startup like
    // the verifiers are. The HTTP half refuses an unknown role before this
    // point; a node with no HTTP half only ever publishes roles to its log.
    let declared = match crate::network::Roles::from_env() {
        Ok(roles) if roles.is_empty() => {
            log::info!(
                "roles: none declared ({} is unset); GET /network says so",
                crate::network::ROLES_ENV
            );
            roles
        }
        Ok(roles) => {
            log::info!(
                "roles: declared {}",
                roles
                    .iter()
                    .map(|role| role.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            roles
        }
        Err(error) => {
            log::warn!("roles: {error}");
            crate::network::Roles::default()
        }
    };
    // The same two facts, said to every peer in this node's hello, so their
    // rosters can show what this node offers (`GET /sessions`, `about`). A
    // declaration there as here: a peer that reads `verifier` has been told,
    // not shown.
    service.set_about(crate::p2p::sync::About {
        version: env!("CARGO_PKG_VERSION").to_string(),
        roles: declared
            .iter()
            .map(|role| role.as_str().to_string())
            .collect(),
        verifiers: node
            .registry()
            .readiness()
            .get("servable")
            .and_then(crate::canonical::Value::as_array)
            .map(|kinds| {
                kinds
                    .iter()
                    .filter_map(crate::canonical::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    });

    let registry = node.registry().clone();
    let state = Arc::new(Mutex::new(State {
        node,
        population,
        dirty: false,
    }));
    {
        let guard = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        write_checkpoint(&config.checkpoint, &root_key, &guard.node)
            .map_err(|e| format!("checkpoint: {e}"))?;
    }

    // One ceiling for the whole process, whatever transports serve it: stdio
    // and HTTP share the operator's per-run budget rather than each getting
    // one. See `mcp::Server::spend`.
    let spend = Arc::new(Mutex::new(crate::mcp::SpendCeiling::from_flag_or_env(
        config.mcp_max_spend,
    )?));
    let mcp_finished = if config.mcp {
        Some(
            crate::mcp::start_shared_stdio(
                Arc::clone(&state),
                config.mcp_identity.as_deref(),
                &config.log,
                &config.key_path(),
                Arc::clone(&spend),
                agents.clone().unwrap_or_else(crate::mcp::Presence::shared),
                Arc::clone(&journal),
            )
            .map_err(|error| format!("mcp: {error}"))?,
        )
    } else {
        None
    };

    // Bound before the first tick, so a bad --mcp-http address fails startup
    // rather than a node that is already peering. No completion handle: HTTP
    // clients come and go, and only stdio's single client supervises.
    if let Some(addr) = config.mcp_http.as_deref() {
        crate::mcp::start_shared_http(
            Arc::clone(&state),
            config.mcp_identity.as_deref(),
            &config.log,
            &config.key_path(),
            Arc::clone(&spend),
            addr,
        )
        .map_err(|error| format!("mcp http: {error}"))?;
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

    // Seeds are asked for their keys on a thread of their own. A seed that is
    // down costs `DIAL_TIMEOUT` per ask, and on the tick thread that would be
    // ten seconds a minute of no draining, no settling and no dialling of the
    // peers that *are* up -- for exactly the node that most needs them, the one
    // whose only other hope is the LAN. `Service` is shared by design; the
    // accept thread already learns into the same book.
    if !seed_list.is_empty() {
        let seeding = Arc::clone(&service);
        thread::spawn(move || loop {
            for (seed, outcome) in seed_list.iter().zip(seeding.seed_from_list(&seed_list)) {
                report_seed(seed, &outcome);
            }
            thread::sleep(Duration::from_secs(TICK_SECONDS));
        });
    }

    let accept_service = Arc::clone(&service);
    let accept_sessions = Arc::clone(&sessions);
    let accept_journal = Arc::clone(&journal);
    let accept_state = Arc::clone(&state);
    let accept_root_key = Arc::clone(&root_key);
    let accept_checkpoint = config.checkpoint.clone();
    let accept_population = config.population.clone();
    let accept_registry = registry.clone();
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
        let (stream, remote_addr) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                log::warn!("accept: {error}");
                continue;
            }
        };
        // The handshake runs off the accept thread. `Inbound::read` blocks for
        // up to the handshake timeout, so one dialler that connects and sends
        // nothing -- once every ten seconds is enough -- used to hold the only
        // accept thread and starve every honest inbound peer. The cap keeps
        // the same trick from turning into a thread per socket instead.
        if in_flight.fetch_add(1, std::sync::atomic::Ordering::AcqRel) >= MAX_INBOUND_HANDSHAKES {
            in_flight.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            log::debug!(
                "inbound session: {MAX_INBOUND_HANDSHAKES} handshakes already pending; dropped one"
            );
            continue;
        }
        let in_flight = Arc::clone(&in_flight);
        let accept_service = Arc::clone(&accept_service);
        let accept_sessions = Arc::clone(&accept_sessions);
        let accept_journal = Arc::clone(&accept_journal);
        let accept_state = Arc::clone(&accept_state);
        let accept_root_key = Arc::clone(&accept_root_key);
        let accept_checkpoint = accept_checkpoint.clone();
        let accept_population = accept_population.clone();
        let accept_registry = accept_registry.clone();
        thread::spawn(move || {
            let _slot = InFlight(in_flight);
            // The first frame is read **before** the lock, so a key request is
            // answered with nothing held. The tick thread below holds this lock
            // while it dials, and a peer's tick thread holds *its* lock while it
            // waits for our key; two fresh nodes that found each other in the
            // same tick sat like that until a handshake timeout, then one of
            // them saw a reset and backed off for a minute.
            let inbound = match transport::Inbound::read(stream) {
                Ok(inbound) => inbound,
                Err(error) => {
                    log::warn!("inbound session: {error}");
                    // Counted and not attributed: nobody was authenticated.
                    accept_sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .inbound_failed();
                    return;
                }
            };
            if inbound.is_key_request() {
                match accept_service.answer_key_request(inbound) {
                    Ok(true) => {
                        log::info!("served our transport key to a peer that heard our beacon")
                    }
                    Ok(false) => log::debug!("refused a key request that named another peer"),
                    Err(error) => log::warn!("key request: {error}"),
                }
                return;
            }
            let mut guard = accept_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let State {
                node, population, ..
            } = &mut *guard;
            // Exact, because the lock is held for the whole session: nothing
            // else appends between this read and the one after it.
            let before = node.ledger().len();
            let outcome = match accept_population {
                Some(_) => {
                    let mut scorer = RoundScorer::new(accept_registry.clone());
                    accept_service
                        .serve_inbound_and_population(
                            inbound,
                            node,
                            population,
                            PopLimits::default(),
                            |node, candidate| scorer.score(node, candidate),
                        )
                        .map(|(remote, _)| remote)
                }
                None => accept_service.serve_inbound_once(inbound, node),
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
                    let mut roster = accept_sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let contact = roster.succeeded(
                        remote,
                        Some(remote_addr),
                        Direction::Inbound,
                        node.ledger().len(),
                        crate::time::unix_seconds(),
                    );
                    if let Some(about) = accept_service.take_about(&remote) {
                        roster.learned(remote, about);
                    }
                    drop(roster);
                    if let Ok(contact) = contact {
                        narrate_session(
                            &accept_journal,
                            &peer_id_string(&remote),
                            remote_addr,
                            Direction::Inbound,
                            contact,
                            node.ledger().len().saturating_sub(before),
                        );
                    }
                    persist(
                        &guard,
                        &accept_checkpoint,
                        &accept_root_key,
                        accept_population.as_ref(),
                    );
                }
                Err(error) => {
                    log::warn!("inbound session: {error}");
                    // The handshake may have named the remote, but a session
                    // that failed is not one to attribute to a peer this
                    // node has not finished authenticating.
                    accept_sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .inbound_failed();
                }
            }
        });
    });

    let mut committee = Committee {
        key: CommitteeKey::from_transport(identity.public_key(), identity.secret_key())
            .map_err(|error| format!("committee key: {error}"))?,
        signer: match config
            .committee_identity
            .as_deref()
            .or(config.mcp_identity.as_deref())
        {
            Some(path) => Some(
                crate::mcp::load_identity(path).map_err(|error| format!("committee: {error}"))?,
            ),
            None => None,
        },
        failed: BTreeMap::new(),
        unopenable: BTreeSet::new(),
        dealings: crate::sealed::dealings::dir_for(&config.log),
    };
    match &committee.signer {
        Some(signer) => log::info!(
            "committee: serving seats registered to {}",
            short(&signer.submitter_id())
        ),
        None => log::info!(
            "committee: opening sealed submissions; no --committee-identity, so no seats served"
        ),
    }

    // The validator loop, when this node has an identity to attest under.
    // Off by default: standing behind a verdict stakes a bond, and a node
    // that did that without being asked would be spending its operator's
    // units on a role they never declared.
    let attest_path = config.attest_identity.clone().or_else(|| {
        std::env::var_os(crate::attestor::IDENTITY_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    });
    let mut attestor = match attest_path {
        Some(path) => {
            let identity =
                crate::mcp::load_identity(&path).map_err(|error| format!("attest: {error}"))?;
            let mut attestor = crate::attestor::Attestor::new(identity);
            let limit = config.attest_limit.or_else(|| {
                std::env::var(crate::attestor::LIMIT_ENV)
                    .ok()
                    .and_then(|text| text.trim().parse::<usize>().ok())
                    .filter(|limit| *limit > 0)
            });
            if let Some(limit) = limit {
                attestor.limit_per_tick = limit;
            }
            log::info!(
                "attest: standing behind what this node verifies, as {} ({} verifier run(s) per tick, {} units bonded each)",
                short(&attestor.attestor_id()),
                attestor.limit_per_tick,
                crate::node::VERIFICATION_BOND
            );
            Some(attestor)
        }
        None => None,
    };

    let mut ticks: u64 = 0;
    loop {
        if let Some(store) = config.store.as_ref() {
            if ticks.is_multiple_of(STORE_CHECK_TICKS) {
                hold_under_cap(store)?;
            }
        }
        ticks = ticks.wrapping_add(1);
        if mcp_finished.as_ref().is_some_and(|finished| {
            !matches!(
                finished.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            )
        }) {
            log::info!("mcp: stdin closed; stopping the combined node");
            return Ok(());
        }
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
        // the CLI: a second copy of admission behind a second subcommand is the same
        // mistake as a second copy in a request handler, which is the argument
        // `docs/serving.md` already makes.
        //
        // Before the dial, deliberately: a record admitted this tick is one a
        // peer can learn about this tick, rather than five seconds later.
        {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = timestamp();
            let mut changed = std::mem::take(&mut guard.dirty);
            if let Some(queue) = &spool {
                let admissions = serve::drain_into(&mut guard.node, queue, &now, false);
                changed |= !admissions.is_empty();
                for (path, admission) in admissions {
                    log::info!("drain: {}", admission.note);
                    // Removed whether admitted or refused. Nearly every refusal
                    // is permanent -- a stale epoch, a citation that is not an
                    // accepted claim -- and a queue that retries one never
                    // empties.
                    if let Err(error) = queue.take(&path) {
                        log::warn!("drain: cannot remove {}: {error}", path.display());
                    }
                }
            }
            // Settlement is deferred to the close of the reveal epoch, and the
            // clock closes epochs whether or not anything arrived this tick.
            // See `settle_tick` for what happened when this waited on a drain.
            changed |= committee_tick(&mut guard.node, &mut committee, &now);
            changed |= settle_tick(&mut guard.node, &now);
            // The validator loop, after settlement so a claim settled this
            // tick is attested this tick, and under the same lock because an
            // attestation is a record and this process holds the pen.
            if let Some(attestor) = attestor.as_mut() {
                let (tally, outcomes) = attestor.tick(&mut guard.node, &now);
                changed |= tally.posted > 0;
                for outcome in &outcomes {
                    if outcome.disagrees() {
                        log::warn!("attest: {outcome}");
                    } else if outcome.posted() {
                        log::info!("attest: {outcome}");
                    } else {
                        log::debug!("attest: {outcome}");
                    }
                }
                if tally.considered > 0 {
                    log::info!("attest: {tally}");
                }
            }
            if changed {
                persist(
                    &guard,
                    &config.checkpoint,
                    &root_key,
                    config.population.as_ref(),
                );
            }
        }

        // Beacons are heard outside the node lock. Nothing here reads the log,
        // and a key request to a beacon's sender can block on a dial: a host
        // on the segment announcing ids from a port it firewalls used to hold
        // the lock -- and every inbound session with it -- for that long.
        if let Some(responder) = &beacon {
            // Announce on the first tick, so a node that has just started is
            // findable at once, then every `multicast::INTERVAL_SECONDS`.
            // Announcing every tick sent six times the traffic documented.
            if ticks.wrapping_sub(1).is_multiple_of(BEACON_EVERY_TICKS) {
                let _ = responder.announce(beacon_port.unwrap_or(multicast::PORT));
            }
            let heard = service.absorb_beacons(responder, BEACONS_PER_TICK);
            // Discovery used to be silent until a session succeeded, which
            // reads as "not working" from outside for as long as the key
            // exchange takes. One line per tick that heard anything.
            if heard > 0 {
                log::info!("beacons: heard {heard} peer(s) on the local segment this tick");
            }
        }

        let needs = {
            let guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            service.seed_from_log(&guard.node);
            service.expire(crate::time::unix_seconds());
            sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .note_book(
                    service.known_peers(),
                    service.known_hints(),
                    crate::time::unix_seconds(),
                );
            guard.node.missing_code()
        };
        for endpoint in service.peers_for(&needs, config.fanout) {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let State {
                node, population, ..
            } = &mut *guard;
            // Exact for the reason the inbound side gives: the lock is held.
            let before = node.ledger().len();
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
                    let mut roster = sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let contact = roster.succeeded(
                        endpoint.peer.id(),
                        Some(endpoint.addr),
                        Direction::Outbound,
                        node.ledger().len(),
                        crate::time::unix_seconds(),
                    );
                    if let Some(about) = service.take_about(&endpoint.peer.id()) {
                        roster.learned(endpoint.peer.id(), about);
                    }
                    drop(roster);
                    if let Ok(contact) = contact {
                        narrate_session(
                            &journal,
                            &peer_id_string(&endpoint.peer.id()),
                            endpoint.addr,
                            Direction::Outbound,
                            contact,
                            node.ledger().len().saturating_sub(before),
                        );
                    }
                    persist(
                        &guard,
                        &config.checkpoint,
                        &root_key,
                        config.population.as_ref(),
                    );
                }
                Err(error) => {
                    // The address, not just the error. With more than one
                    // bootstrap file a bare "Connection refused" names neither
                    // which peer is down nor which file to look at, and the
                    // loop repeats it every five seconds forever.
                    //
                    // `Connection refused` in particular is worth telling apart
                    // from the placeholder-key warning at startup: this one
                    // comes from `transport::connect`, before a single
                    // handshake byte, so it means nothing is listening there.
                    // A wrong key gets *further* than this and fails in the
                    // exchange.
                    log::warn!(
                        "outbound session to {} ({}): {error}",
                        peer_id_string(&endpoint.peer.id()),
                        endpoint.addr
                    );
                    // Tell the DHT, or every lookup that chose this peer waits
                    // on it forever. `peers_for` hands out the next hop of each
                    // lookup in flight and expects exactly one answer per
                    // contact; this is the failure half.
                    service.unreachable(endpoint.peer.id());
                    let news = sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .failed(
                            endpoint.peer.id(),
                            Some(endpoint.addr),
                            Direction::Outbound,
                            &error.to_string(),
                            crate::time::unix_seconds(),
                        );
                    if news == Ok(true) {
                        let peer = peer_id_string(&endpoint.peer.id());
                        crate::journal::note(
                            &journal,
                            crate::journal::Kind::Peer,
                            crate::journal::Tone::Warn,
                            &format!(
                                "Could not reach node {} at {}: {error}",
                                crate::journal::short(&peer),
                                endpoint.addr
                            ),
                            Some(&peer),
                        );
                    }
                }
            }
        }
        thread::sleep(Duration::from_secs(TICK_SECONDS));
    }
}

/// Say what a successful session changed, in the journal: a peer reached
/// for the first time, a peer back after being lost, and records synced.
/// An ordinary session that imported nothing is silence -- it happens every
/// few seconds and changes nothing a person would want told.
fn narrate_session(
    journal: &crate::journal::Shared,
    peer: &str,
    addr: SocketAddr,
    direction: Direction,
    contact: crate::p2p::sessions::Contact,
    imported: usize,
) {
    use crate::journal::{note, short, span, Kind, Tone};
    use crate::p2p::sessions::Contact;
    let name = short(peer);
    let how = match direction {
        Direction::Inbound => format!("it dialled in from {addr}"),
        Direction::Outbound => format!("at {addr}"),
    };
    match contact {
        Contact::First => note(
            journal,
            Kind::Peer,
            Tone::Good,
            &format!("Connected to node {name} ({how})"),
            Some(peer),
        ),
        Contact::Back { silent_for } => note(
            journal,
            Kind::Peer,
            Tone::Good,
            &format!(
                "Node {name} is back after {} without a session ({how})",
                span(silent_for)
            ),
            Some(peer),
        ),
        Contact::Again => {}
    }
    if imported > 0 {
        note(
            journal,
            Kind::Peer,
            Tone::Good,
            &format!(
                "Synced {imported} new record{} from node {name}",
                if imported == 1 { "" } else { "s" }
            ),
            Some(peer),
        );
    }
}

/// Say what asking one seed came to.
///
/// Only what changed is said. A seed that is dialable, or was asked too
/// recently to ask again, is silence; a failure is said once per
/// `KEY_FETCH_BACKOFF`, because it is asked no more often than that. Before this
/// a node whose seed was down said nothing at all, which from the app reads as
/// "p2p does not work" rather than as "that machine is not answering".
fn report_seed(seed: &Seed, outcome: &SeedOutcome) {
    match outcome {
        SeedOutcome::Learned(addr) => log::info!(
            "seeds: {} answered at {addr} with the key its id names; dialable now",
            seed.name
        ),
        SeedOutcome::Failed { addr, error } => log::warn!(
            "seeds: {} at {addr} did not hand over its key ({error}); asking again in {}s. \
             A seed that never answers is down or firewalled -- {} names another list",
            seed.name,
            KEY_FETCH_BACKOFF.as_secs(),
            seeds::SEEDS_ENV
        ),
        SeedOutcome::Unresolvable => log::warn!(
            "seeds: {}: {:?} is neither an address nor a name that resolves; asking again in {}s",
            seed.name,
            seed.addr,
            KEY_FETCH_BACKOFF.as_secs()
        ),
        SeedOutcome::Proxied => log::warn!(
            "seeds: {}: {:?} is a name, and dials go through a proxy; resolving it here would \
             tell the local network which seed this node wants. List the seed by address to \
             use it; asking again in {}s",
            seed.name,
            seed.addr,
            KEY_FETCH_BACKOFF.as_secs()
        ),
        SeedOutcome::Excluded => log::debug!(
            "seeds: {} is outside this node's allowlist ({}); not asked",
            seed.name,
            crate::fleet::PEERS_ENV
        ),
        SeedOutcome::Dialable | SeedOutcome::Waiting | SeedOutcome::Ourselves => {}
    }
}

/// Evict reclaimable content until the store fits its cap, or refuse.
///
/// `Err` only for the refusal -- the pinned bytes alone are over the cap --
/// and its message is the store's own, which names both numbers and says to
/// raise the cap or move the store. Anything else that goes wrong measuring a
/// directory is logged and retried next time, like every other runtime
/// failure here.
fn hold_under_cap(store: &crate::store::Store) -> Result<(), String> {
    use crate::store::{format_size, quota, StoreError};
    match quota::reclaim(store, 0) {
        Ok(eviction) if !eviction.is_empty() => {
            log::info!(
                "store: evicted {} reclaimable file(s), {} freed, to stay under the {} cap",
                eviction.removed.len(),
                format_size(eviction.freed),
                store.limit().map(format_size).unwrap_or_default()
            );
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(error @ StoreError::QuotaExceeded { .. }) => {
            log::error!("store: {error}; stopping the node");
            Err(format!("store: {error}"))
        }
        Err(error) => {
            log::warn!("store: could not check the size cap: {error}");
            Ok(())
        }
    }
}

/// One line from [`VerifierRegistry::readiness`] for the startup log:
/// `lean at /path (Lean (version 4.x)), python3 at /path, sandbox sandbox-exec,
/// unservable: lean`.
fn describe_readiness(report: &Value) -> String {
    let tool = |name: &str| -> String {
        let row = report.get("toolchains").and_then(|t| t.get(name));
        match row.and_then(|r| r.get("path")).and_then(Value::as_str) {
            Some(path) => match row.and_then(|r| r.get("version")).and_then(Value::as_str) {
                Some(version) => format!("{name} at {path} ({version})"),
                None => format!("{name} at {path}"),
            },
            None => format!("{name} missing"),
        }
    };
    let sandbox = report
        .get("sandbox")
        .and_then(|s| s.get("mechanism"))
        .and_then(Value::as_str)
        .unwrap_or("?");
    let unservable: Vec<&str> = match report.get("unservable") {
        Some(Value::Object(fields)) => fields.keys().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    let mut line = format!("{}, {}, sandbox {sandbox}", tool("lean"), tool("python3"));
    if !unservable.is_empty() {
        line.push_str(&format!("; unservable: {}", unservable.join(", ")));
    }
    line
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_reveal_held_by_the_dealing_windows_is_retried_and_a_disqualified_one_is_not() {
        use crate::node::RuleViolation;
        let commitment = String::from("sha256:00");
        assert_eq!(
            retry_after(
                &RuleViolation::AwaitingComplaints {
                    commitment: commitment.clone()
                },
                3
            ),
            None
        );
        assert_eq!(
            retry_after(
                &RuleViolation::AwaitingDealerAnswer {
                    commitment: commitment.clone(),
                    seats: vec![1]
                },
                3
            ),
            None
        );
        assert_eq!(
            retry_after(
                &RuleViolation::DealerDisqualified {
                    commitment: commitment.clone(),
                    seats: vec![1]
                },
                3
            ),
            Some(usize::MAX)
        );
        assert_eq!(
            retry_after(
                &RuleViolation::NotEnoughShares {
                    commitment,
                    have: 2,
                    need: 3
                },
                2
            ),
            Some(2)
        );
    }
    use super::*;
    use crate::records::{commitment_hash, Claim, Commitment};

    /// `cairn run --max-size` was accepted and then ignored for the life of
    /// the node. This is the check that now runs every minute.
    #[test]
    fn a_store_over_its_cap_stops_the_node_and_never_loses_the_log() {
        let dir = std::env::temp_dir().join(format!(
            "cairn-daemon-cap-{}-{}",
            std::process::id(),
            timestamp().replace(':', "")
        ));
        let _ = fs::remove_dir_all(&dir);
        let store = crate::store::Store::new(&dir);
        store.prepare().expect("prepare");
        fs::write(store.log_path(), vec![b'x'; 1000]).expect("log");
        let cached = store.cache_dir().join("blob");
        fs::write(&cached, vec![b'y'; 1000]).expect("cache");

        // No cap, no work.
        assert_eq!(hold_under_cap(&store), Ok(()));
        assert!(cached.exists());

        // Room for the log but not the cache: the cache goes, the node stays.
        assert_eq!(
            hold_under_cap(&store.clone().with_limit(Some(1500))),
            Ok(())
        );
        assert!(!cached.exists(), "reclaimable content is evicted to fit");

        // No room for the log: the node stops, and says what to do about it.
        let refusal = hold_under_cap(&store.clone().with_limit(Some(500))).expect_err("over cap");
        assert!(refusal.contains("Raise the limit"), "{refusal}");
        assert_eq!(
            fs::metadata(store.log_path()).map(|m| m.len()).ok(),
            Some(1000),
            "the log is never pruned to fit"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // The same three instants `tests/p2p_convergence.rs` uses, for the same
    // reason: commit, reveal one epoch later, settle after the reveal epoch
    // has closed and waited out `FINALITY_EPOCHS`.
    const TS: &str = "2026-07-29T00:00:00+00:00";
    const TS_REVEAL: &str = "2026-07-29T00:10:00+00:00";
    const TS_SETTLE: &str = "2026-07-29T00:30:00+00:00";

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// A scratch node under `target/`, so a failed run leaves evidence.
    fn node(name: &str) -> Node {
        let dir = repo_root().join("target").join("daemon-tests");
        fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join(format!("{}-{name}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        Node::new(Ledger::open(path).expect("open ledger"), repo_root())
    }

    fn example(path: &str) -> Value {
        let text = fs::read_to_string(repo_root().join(path)).expect("read example");
        Value::from_json(&text).expect("parse")
    }

    /// One accepted claim in a closed epoch, and nobody else: no peer to dial,
    /// nothing in a spool. This is the state the tick loop must settle from
    /// on its own, and until `settle_tick` ran unconditionally it did not.
    #[test]
    fn a_tick_settles_a_due_epoch_with_no_peers_and_an_empty_spool() {
        let mut node = node("settles-alone");
        let objective = Objective::from_value(&example("examples/collatz/objective.json"))
            .expect("objective decodes");
        let objective_id = node.post_objective(&objective, TS).expect("post");
        let artifact = example("examples/collatz/artifact.json");
        let nonce = "n-alone";
        let hash = commitment_hash(&objective_id, "alone", &artifact, nonce);
        node.commit(&Commitment::new(&objective_id, "alone", &hash, TS), TS)
            .expect("commit");
        let claim =
            Claim::new(&objective_id, "alone", artifact, nonce, TS_REVEAL, vec![]).expect("claim");
        let revealed = node.reveal(&claim, TS_REVEAL).expect("reveal");
        assert!(revealed.is_pending(), "{}", revealed.note);

        // Before the epoch closes: nothing is due, and the tick must say so,
        // or the checkpoint would be rewritten every five seconds for a log
        // that has not moved.
        let height = node.ledger().len();
        assert!(!settle_tick(&mut node, TS_REVEAL));
        assert_eq!(node.ledger().len(), height);

        // After: the batch settles, and the answer gates the checkpoint.
        assert!(settle_tick(&mut node, TS_SETTLE));
        assert!(node.ledger().len() > height);
        assert!(
            node.settlement_for_claim(&revealed.claim_id).is_some(),
            "the claim was not paid"
        );

        // And once, not once per tick: a settled epoch is not due again.
        let height = node.ledger().len();
        assert!(!settle_tick(&mut node, TS_SETTLE));
        assert_eq!(node.ledger().len(), height);
    }

    /// Both files a round rewrites go through the atomic path: the file at the
    /// destination is always a complete write, whatever is beside it.
    #[test]
    fn checkpoint_and_population_are_replaced_whole() {
        let node = node("atomic-state");
        let dir = repo_root().join("target").join("daemon-tests");
        let checkpoint = dir.join(format!("{}-cp.json", std::process::id()));
        let population = dir.join(format!("{}-pop.json", std::process::id()));
        let key = RootKey::generate();
        write_checkpoint(&checkpoint, &key, &node).expect("checkpoint");
        let first = fs::read(&checkpoint).expect("read checkpoint");
        save_population(&population, &Population::default()).expect("population");
        // Overwritten, not appended to or truncated around: each rewrite is a
        // whole file, and what was there before is gone with no seam.
        write_checkpoint(&checkpoint, &key, &node).expect("checkpoint again");
        let second = fs::read(&checkpoint).expect("read checkpoint");
        assert_eq!(first.len(), second.len());
        assert!(load_population(&population).is_ok());
        let _ = fs::remove_file(checkpoint);
        let _ = fs::remove_file(population);
    }
}
