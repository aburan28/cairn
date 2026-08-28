//! Two nodes, no operator between them, converging on the same settled state.
//!
//! The unit tests in `p2p::sync` check the reconciliation algebra on synthetic
//! records. This checks the claim the project actually makes: that a peer which
//! receives only *inputs* — objectives, commitments, claims — re-derives every
//! verdict, reward and settlement for itself, and lands byte-for-byte where the
//! sender did, without being told any of it.
//!
//! Nothing here shares a ledger, a registry, or a process-global anything. The
//! second node is handed records and reaches its own conclusions.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use cairn::canonical::Value;
use cairn::gossip::{Candidate, Population};
use cairn::ledger::Ledger;
use cairn::node::Node;
use cairn::p2p::discovery::Endpoint;
use cairn::p2p::handshake::PeerIdentity;
use cairn::p2p::pop::PopLimits;
use cairn::p2p::service::Service;
use cairn::p2p::sync::{reconcile, Peer, Record, SyncError};
use cairn::records::{commitment_hash, Claim, Commitment, Objective};

const TS: &str = "2026-07-29T00:00:00+00:00";
/// One epoch after [`TS`]. A reveal must be in a strictly later epoch than the
/// commitment it opens, so commit and reveal cannot share a timestamp.
///
/// Claims are *built* with this instant too, which is what both CLIs do: a
/// claim's `created_at` is set when it is revealed. It matters here because a
/// receiver has only the record, so the record's own instant is the only stamp
/// two nodes can agree to file it under.
const TS_REVEAL: &str = "2026-07-29T00:10:00+00:00";
/// Two epochs after the reveal, not one: the reveal epoch must close *and*
/// wait out `FINALITY_EPOCHS` before its batch may settle. Both nodes use the
/// same three instants, which is what makes their settlements comparable at
/// all: the batch order is derived from the epoch.
///
/// Written as a literal rather than derived from `finality_epochs()`, unlike
/// the sweeps in `tests/simulation.rs`, because these tests are about two
/// nodes agreeing on an order and a fixed instant is part of what they hold in
/// common. If the constant is ever raised, this is the assertion that fails —
/// "alice did not settle the whole batch" — and the fix is one more epoch here.
const TS_SETTLE: &str = "2026-07-29T00:30:00+00:00";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Copy a directory tree, so a test can give a node its own verifier root.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("destination");
    for entry in std::fs::read_dir(from).expect("read source") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// A scratch ledger under `target/`, so a failed run leaves evidence and a
/// passing one leaves nothing anyone has to clean out of /tmp.
fn scratch(name: &str) -> PathBuf {
    let dir = repo_root().join("target").join("p2p-tests");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join(format!("{name}.jsonl"));
    let _ = std::fs::remove_file(&path);
    path
}

fn node(name: &str) -> Node {
    Node::new(
        Ledger::open(scratch(name)).expect("open ledger"),
        repo_root(),
    )
}

/// The shipped Collatz objective: a `certificate` verifier over pinned code.
fn collatz_objective() -> Objective {
    let text = std::fs::read_to_string(repo_root().join("examples/collatz/objective.json"))
        .expect("read objective");
    Objective::from_value(&Value::from_json(&text).expect("parse")).expect("decode")
}

fn collatz_artifact() -> Value {
    let text = std::fs::read_to_string(repo_root().join("examples/collatz/artifact.json"))
        .expect("read artifact");
    Value::from_json(&text).expect("parse")
}

/// The shipped cap-set objective: an `evaluator`, so candidates for it have a
/// score to re-derive. A `certificate` verifier produces none, which would make
/// every gossiped candidate for it unscoreable and the population test vacuous.
fn capset_objective() -> Objective {
    let text = std::fs::read_to_string(repo_root().join("examples/capset/objective.json"))
        .expect("read objective");
    Objective::from_value(&Value::from_json(&text).expect("parse")).expect("decode")
}

fn capset_artifact() -> Value {
    let text = std::fs::read_to_string(repo_root().join("examples/capset/artifact.json"))
        .expect("read artifact");
    Value::from_json(&text).expect("parse")
}

/// Pull the exchangeable records out of a node's log.
///
/// Deliberately *not* every entry: verdicts, settlements and frontier moves are
/// this node's own conclusions and are never shipped.
fn records_of(node: &Node) -> Vec<Record> {
    node.ledger()
        .entries()
        .iter()
        .filter(|e| ["objective", "commitment", "claim"].contains(&e.kind.as_str()))
        .map(|e| Record::new(e.kind.clone(), e.payload.clone()))
        .collect()
}

/// Replay received records into a node, in an order it chooses for itself.
///
/// This is what a real peer does after `ingest`: feed the inputs through the
/// same rules engine every other node runs. Ordering is the receiver's business
/// — objectives before the claims that name them — and the point of the test is
/// that the *outcome* does not depend on it.
///
/// Each record is stamped with its own `created_at`, mirroring the cold
/// replay path (`p2p::service::replay_records`). The local clock would put a
/// replayed commitment and the claim that opens it in the same epoch, and
/// every claim would be refused; the record's own instant is also the only
/// stamp two receivers agree on, which is what makes their epochs match.
/// The *live* boundary differs on one kind now: a commitment is admitted at
/// the receiver's own time, so one whose epoch has already closed at first
/// sight is refused -- that is the backdating fix in `apply_records`, and it
/// is exactly why a cold reconstruction like this one must keep the record's
/// stamp instead.
fn apply(node: &mut Node, records: &[Record]) {
    for kind in ["objective", "commitment", "claim"] {
        for record in records.iter().filter(|r| r.kind == kind) {
            let stamp = record
                .payload
                .get("created_at")
                .and_then(Value::as_str)
                .expect("every exchangeable record carries created_at")
                .to_string();
            match kind {
                "objective" => {
                    let o = Objective::from_value(&record.payload).expect("objective decodes");
                    let _ = node.post_objective(&o, &stamp);
                }
                "commitment" => {
                    let c = Commitment::from_value(&record.payload).expect("commitment decodes");
                    let _ = node.commit(&c, &stamp);
                }
                "claim" => {
                    let c = Claim::from_value(&record.payload).expect("claim decodes");
                    let _ = node.reveal(&c, &stamp);
                }
                _ => unreachable!(),
            }
        }
    }
    // Settlement is deferred to the close of the reveal epoch, so replaying the
    // inputs is only half of re-deriving the state; the receiver must also run
    // the batch. It reaches the same answer because the batch order is a
    // function of the epoch and the claims in it, not of arrival.
    let _ = node.settle_at(TS_SETTLE);
}

#[test]
fn a_peer_receives_inputs_and_derives_settlement_for_itself() {
    // -- alice does the work ------------------------------------------------
    let mut alice = node("alice");
    let objective = collatz_objective();
    let objective_id = alice.post_objective(&objective, TS).expect("post");

    let artifact = collatz_artifact();
    let nonce = "n-alice";
    let hash = commitment_hash(&objective_id, "alice", &artifact, nonce);
    alice
        .commit(&Commitment::new(&objective_id, "alice", &hash, TS), TS)
        .expect("commit");
    let claim =
        Claim::new(&objective_id, "alice", artifact, nonce, TS_REVEAL, vec![]).expect("claim");
    let revealed = alice.reveal(&claim, TS_REVEAL).expect("reveal");
    assert!(revealed.is_pending(), "{}", revealed.note);
    let outcome = alice
        .settle_at(TS_SETTLE)
        .expect("settle")
        .into_iter()
        .find(|o| o.claim_id == revealed.claim_id)
        .expect("the batch settled alice's claim");

    assert!(
        outcome.settled,
        "alice should have settled: {}",
        outcome.note
    );
    assert!(outcome.reward > 0);

    // -- reconcile: bob starts empty ---------------------------------------
    let mut a_peer = Peer::new();
    for r in records_of(&alice) {
        a_peer.insert(r).expect("alice's records are exchangeable");
    }
    let mut b_peer = Peer::new();

    // Bob accepts a record only if it decodes as the record kind it claims to
    // be. He does NOT accept anyone's verdict -- that comes later, from his own
    // verifier, when he replays.
    let (_, to_bob) =
        reconcile(&mut a_peer, &mut b_peer, |r: &Record| {
            match r.kind.as_str() {
                "objective" => Objective::from_value(&r.payload).map(|_| ()).map_err(|e| {
                    SyncError::MalformedMessage {
                        detail: format!("bad objective: {e}"),
                    }
                }),
                "commitment" => Commitment::from_value(&r.payload).map(|_| ()).map_err(|e| {
                    SyncError::MalformedMessage {
                        detail: format!("bad commitment: {e}"),
                    }
                }),
                "claim" => Claim::from_value(&r.payload).map(|_| ()).map_err(|e| {
                    SyncError::MalformedMessage {
                        detail: format!("bad claim: {e}"),
                    }
                }),
                other => Err(SyncError::NotExchangeable {
                    kind: other.to_string(),
                }),
            }
        });

    assert!(
        to_bob.is_clean(),
        "bob refused something: {:?}",
        to_bob.refused
    );
    assert_eq!(b_peer.len(), a_peer.len());
    assert_eq!(b_peer.len(), 3, "one objective, one commitment, one claim");

    // -- bob re-derives -----------------------------------------------------
    let mut bob = node("bob");
    let received: Vec<Record> = b_peer
        .ids()
        .iter()
        .map(|id| b_peer.get(id).unwrap().clone())
        .collect();
    apply(&mut bob, &received);

    // Bob reached the same settlement, having been told none of it.
    let a_settlement = alice.settlement_of(&objective_id).expect("alice settled");
    let b_settlement = bob
        .settlement_of(&objective_id)
        .expect("bob settled independently");
    assert_eq!(
        a_settlement.canonical_string(),
        b_settlement.canonical_string(),
        "two nodes derived different settlements from the same inputs"
    );

    // And bob's log passes its own audit, re-running the verifier from scratch.
    assert_eq!(bob.audit(true), Vec::<String>::new());
}

#[test]
fn a_replayed_commitment_and_its_claim_land_in_different_epochs() {
    // The failure this guards against is silent: stamp both with the local
    // clock on the way in and they share an epoch, the reveal is refused as
    // premature, and record sync goes on reporting success while importing no
    // work at all. Nothing in the API surfaces it -- the replay path discards
    // rule violations, because a peer's record being unacceptable here is
    // normal -- so only a test that counts the claims catches it.
    let mut alice = node("alice-epochs");
    let objective = collatz_objective();
    let objective_id = alice.post_objective(&objective, TS).expect("post");
    let artifact = collatz_artifact();
    let hash = commitment_hash(&objective_id, "alice", &artifact, "n");
    alice
        .commit(&Commitment::new(&objective_id, "alice", &hash, TS), TS)
        .expect("commit");
    let claim =
        Claim::new(&objective_id, "alice", artifact, "n", TS_REVEAL, vec![]).expect("claim");
    alice.reveal(&claim, TS_REVEAL).expect("reveal");

    let mut bob = node("bob-epochs");
    apply(&mut bob, &records_of(&alice));

    assert_eq!(
        bob.ledger().entries_of_kind("claim").len(),
        1,
        "the replayed claim was refused instead of admitted"
    );
    assert!(
        bob.settlement_of(&objective_id).is_some(),
        "the replayed claim was admitted but never settled"
    );
}

/// What a node running both halves of a round does with a gossiped candidate:
/// look the objective up in its *own* log and re-run the pinned verifier.
fn rescore(node: &Node, candidate: &Candidate) -> Option<i64> {
    let objectives = node.objectives();
    let objective = objectives.get(&candidate.objective_id)?;
    node.registry()
        .run(&objective.verifier, &candidate.artifact)
        .score()
}

#[test]
fn a_dialled_peer_learns_the_objective_before_it_scores_candidates_for_it() {
    // The ordering inside a round is load-bearing and invisible from outside
    // it. Candidates are scored against objectives, so if populations
    // reconciled first, a peer starting empty would refuse every candidate for
    // an objective arriving in the same round -- and would report a clean
    // session while doing it. The refusal is correct in isolation and wrong as
    // a design, which is exactly the kind of bug that survives review.
    //
    // The second half of the test is the rule that makes gossip safe at all:
    // the peer's claimed score is re-derived, never imported.
    let mut alice = node("alice-pop");
    let objective = capset_objective();
    let objective_id = alice.post_objective(&objective, TS).expect("post");
    let artifact = capset_artifact();

    let mut alice_pop = Population::default();
    alice_pop.add(Candidate::new(&objective_id, artifact.clone(), 20, "alice"));
    alice_pop.add(Candidate::new(&objective_id, artifact, 9_999, "mallory"));

    let bob_identity = Arc::new(PeerIdentity::generate());
    let bob_public = bob_identity.to_public();
    let bob_service = Service::new(bob_identity);
    let listener = bob_service
        .listen("127.0.0.1:0".parse().expect("loopback"))
        .expect("listen");
    let endpoint = Endpoint::new(listener.local_addr().expect("bound address"), bob_public);
    let bob_thread = thread::spawn(move || {
        let mut bob = node("bob-pop");
        let mut bob_pop = Population::default();
        bob_service
            .accept_node_and_population(
                &listener,
                &mut bob,
                &mut bob_pop,
                PopLimits::default(),
                rescore,
            )
            .expect("bob's round");
        (bob.objectives().len(), bob_pop)
    });

    let alice_service = Service::new(Arc::new(PeerIdentity::generate()));
    alice_service
        .dial_node_and_population(
            &endpoint,
            &mut alice,
            &mut alice_pop,
            PopLimits::default(),
            rescore,
        )
        .expect("alice's round");

    let (objectives, bob_pop) = bob_thread.join().expect("bob's thread");
    assert_eq!(objectives, 1, "bob did not import the objective");
    assert_eq!(
        bob_pop.len(),
        1,
        "bob kept {} candidates; the inflated one should have been dropped and \
         the honest one kept",
        bob_pop.len()
    );
    assert_eq!(
        bob_pop.best().map(|c| c.score),
        Some(20),
        "bob kept a score he did not re-derive"
    );
}

#[test]
fn a_peer_that_ships_its_conclusions_is_refused() {
    // The security property of the layer, end to end: alice's verdict and
    // settlement records exist in her log, and bob will not take them.
    let mut alice = node("alice-derived");
    let objective = collatz_objective();
    let objective_id = alice.post_objective(&objective, TS).expect("post");
    let artifact = collatz_artifact();
    let hash = commitment_hash(&objective_id, "alice", &artifact, "n");
    alice
        .commit(&Commitment::new(&objective_id, "alice", &hash, TS), TS)
        .expect("commit");
    let claim =
        Claim::new(&objective_id, "alice", artifact, "n", TS_REVEAL, vec![]).expect("claim");
    alice.reveal(&claim, TS_REVEAL).expect("reveal");
    alice.settle_at(TS_SETTLE).expect("settle");

    let derived: Vec<Record> = alice
        .ledger()
        .entries()
        .iter()
        .filter(|e| ["verdict", "settlement", "frontier"].contains(&e.kind.as_str()))
        .map(|e| Record::new(e.kind.clone(), e.payload.clone()))
        .collect();
    assert!(
        !derived.is_empty(),
        "alice should have derived records to try to push"
    );

    let mut bob = Peer::new();
    for r in &derived {
        assert!(
            matches!(
                bob.insert(r.clone()),
                Err(SyncError::NotExchangeable { .. })
            ),
            "bob accepted a {} record",
            r.kind
        );
    }
    assert_eq!(bob.len(), 0);
}

#[test]
fn the_receiver_reaches_the_same_state_whatever_order_records_arrive_in() {
    // A set has no order. If the derived state depended on arrival order, two
    // honest peers could disagree while holding identical records.
    let mut alice = node("alice-order");
    let objective = collatz_objective();
    let objective_id = alice.post_objective(&objective, TS).expect("post");
    let artifact = collatz_artifact();
    let hash = commitment_hash(&objective_id, "alice", &artifact, "n");
    alice
        .commit(&Commitment::new(&objective_id, "alice", &hash, TS), TS)
        .expect("commit");
    let claim =
        Claim::new(&objective_id, "alice", artifact, "n", TS_REVEAL, vec![]).expect("claim");
    alice.reveal(&claim, TS_REVEAL).expect("reveal");
    alice.settle_at(TS_SETTLE).expect("settle");

    let records = records_of(&alice);
    let mut forward = node("bob-forward");
    apply(&mut forward, &records);

    let mut reversed: Vec<Record> = records.clone();
    reversed.reverse();
    let mut backward = node("bob-backward");
    apply(&mut backward, &reversed);

    let a = forward
        .settlement_of(&objective_id)
        .expect("forward settled");
    let b = backward
        .settlement_of(&objective_id)
        .expect("backward settled");
    assert_eq!(a.canonical_string(), b.canonical_string());
    assert_eq!(forward.audit(true), Vec::<String>::new());
    assert_eq!(backward.audit(true), Vec::<String>::new());
}

#[test]
fn a_dialling_node_learns_who_holds_a_blob_and_asks_that_peer_next() {
    // The gap this closes: `p2p::code` is need-driven fetch with no way to
    // choose *whom* to need it from, so a node asks whoever the random dial
    // sample turned up. Here alice learns, from the session itself, that bob
    // holds the capset checker.
    //
    // Note what alice has to do to learn it: *ask*. There is no inventory
    // message -- `code` refuses one on privacy grounds and this round does not
    // reintroduce it -- so alice only hears about blobs she named, and the
    // answer is attributed to the session's peer id rather than to anything in
    // the message body. See `p2p::dht`.
    let objective = capset_objective();

    let bob_identity = Arc::new(PeerIdentity::generate());
    let bob_public = bob_identity.to_public();
    let bob_service = Service::new(bob_identity);
    let listener = bob_service
        .listen("127.0.0.1:0".parse().expect("loopback"))
        .expect("listen");
    let bob_addr = listener.local_addr().expect("bound address");
    let endpoint = Endpoint::new(bob_addr, bob_public.clone());

    // Bob's root is scratch too, not the repository. He publishes the checker
    // into his root's blob store, and the store under the repository is shared
    // with every demo script anyone has ever run here: if `demo.sh` already put
    // this blob there, publishing is a no-op, bob announces nothing new, and
    // alice records no provider. The test then fails on a developer machine and
    // passes in CI, which is the worst shape a test can have. The examples are
    // copied in because the checker is resolved by path relative to the root.
    let bob_root = repo_root()
        .join("target")
        .join("p2p-tests")
        .join("bob-root");
    let _ = std::fs::remove_dir_all(&bob_root);
    std::fs::create_dir_all(bob_root.join("examples")).expect("bob's root");
    copy_tree(
        &repo_root().join("examples").join("capset"),
        &bob_root.join("examples").join("capset"),
    );

    let bob_objective = objective.clone();
    let bob_thread = thread::spawn(move || {
        let mut bob = Node::new(
            Ledger::open(scratch("bob-dht")).expect("open ledger"),
            bob_root,
        );
        bob.post_objective(&bob_objective, TS).expect("post");
        // Bob is the funder, so he is the one node that certainly has the
        // checker on disk. Publishing moves it into the content-addressed store,
        // which is what makes him a *provider* rather than merely an owner.
        let published = bob.publish_local_code();
        assert!(published > 0, "bob published nothing to serve");
        bob_service
            .accept_node_once(&listener, &mut bob)
            .expect("bob's round");
        bob.registry().blobs().addresses()
    });

    // Alice must want the blob before she can learn who has it, so she posts
    // the same objective: that is what puts the checker in her want set. She
    // then both fetches it and records bob as a holder, because the DHT round
    // reuses the set the code round asked for rather than what is still missing
    // afterwards -- see `Service::exchange_dht_round`.
    //
    // Her verifier root is an empty scratch directory, not the repository. With
    // the repository as root she resolves the checker by path and needs nothing,
    // which is the shipped-tree case and not the one this is about.
    // Removed and recreated, not just created: the blob alice fetches lands in
    // a store under this root, and a leftover from the previous run would mean
    // she needs nothing and the test passes once and never again.
    let empty_root = repo_root().join("target").join("p2p-tests").join("no-root");
    let _ = std::fs::remove_dir_all(&empty_root);
    std::fs::create_dir_all(&empty_root).expect("empty root");
    let mut alice = Node::new(
        Ledger::open(scratch("alice-dht")).expect("open ledger"),
        empty_root,
    );
    alice.post_objective(&objective, TS).expect("post");
    let wanted = alice.missing_code();
    assert!(
        !wanted.is_empty(),
        "alice already holds the checker, so the ask would be empty"
    );
    let wanted_address = wanted.iter().next().expect("non-empty want set").clone();
    let alice_service = Service::new(Arc::new(PeerIdentity::generate()));
    alice_service
        .dial_node_once(&endpoint, &mut alice)
        .expect("alice's round");

    let bob_holds = bob_thread.join().expect("bob's thread");
    assert!(
        bob_holds.contains(&wanted_address),
        "bob does not hold the blob alice asked about"
    );

    // Alice heard the announcement, and attributed it to the peer she was
    // actually talking to.
    let now = cairn::time::unix_seconds();
    let (holders, _) =
        alice_service.with_directory(|directory| directory.lookup_providers(&wanted_address, now));
    assert_eq!(
        holders.len(),
        1,
        "alice recorded no provider for bob's blob"
    );
    assert_eq!(
        holders[0].peer_id(),
        bob_public.id(),
        "the provider record names a peer alice never spoke to"
    );
    assert_eq!(holders[0].addr, bob_addr);
}

#[test]
fn a_needed_blob_puts_its_known_holder_ahead_of_the_random_sample() {
    // The behaviour change, not just the bookkeeping: with something specific
    // missing, the peer that announced holding it is dialled first.
    let bob = Arc::new(PeerIdentity::generate()).to_public();
    let carol = Arc::new(PeerIdentity::generate()).to_public();
    let bob_addr = "127.0.0.1:9101".parse().expect("loopback");
    let carol_addr = "127.0.0.1:9102".parse().expect("loopback");

    let mut service = Service::new(Arc::new(PeerIdentity::generate()));
    service.add_bootstrap(Endpoint::new(bob_addr, bob.clone()));
    service.add_bootstrap(Endpoint::new(carol_addr, carol));

    let wanted = "ab".repeat(32);
    // Announced against the same clock `peers_for` reads. Announcing at zero
    // instead looks like it works and does not: the record expires 1800 seconds
    // after the epoch, `candidates` falls through to the nearest-peer list, and
    // which peer that is depends on two randomly generated ids.
    let now = cairn::time::unix_seconds();
    let mut needs = std::collections::BTreeSet::new();
    needs.insert(wanted.clone());
    service.with_directory(|directory| {
        directory.record_tell(
            bob.id(),
            bob_addr,
            &needs,
            std::slice::from_ref(&wanted),
            now,
        );
    });

    let chosen = service.peers_for(&needs, 1);
    assert_eq!(chosen.len(), 1);
    assert_eq!(
        chosen[0].peer.id(),
        bob.id(),
        "the node known to hold it was not asked first"
    );

    // And with nothing missing it is the plain random sample again, so the DHT
    // costs nothing in the steady state.
    let sampled = service.peers_for(&std::collections::BTreeSet::new(), 2);
    assert_eq!(sampled.len(), 2);
}

#[test]
fn a_lookup_crosses_a_hop_and_learns_the_key_it_needs_to_do_it() {
    // The roadmap item, end to end over the real objects: alice can reach bob
    // and nobody else; carol holds what alice wants; bob knows carol.
    //
    // Before the multi-hop driver alice's search ended at bob, because a
    // routing answer names a peer by id and address and never by key — so
    // carol was a name alice could hear and never dial. Two things have to
    // work together for this to pass: bob's answer has to *route* alice toward
    // carol, and alice has to be able to turn that name into a session by
    // fetching carol's key and checking it against the id.
    let alice_identity = Arc::new(PeerIdentity::generate());
    let bob = Arc::new(PeerIdentity::generate());
    let carol = Arc::new(PeerIdentity::generate());
    let bob_addr: std::net::SocketAddr = "127.0.0.1:9201".parse().expect("loopback");
    let carol_addr: std::net::SocketAddr = "127.0.0.1:9202".parse().expect("loopback");

    let mut alice = Service::new(alice_identity);
    alice.add_bootstrap(Endpoint::new(bob_addr, bob.to_public()));

    let wanted = "cd".repeat(32);
    let mut needs = std::collections::BTreeSet::new();
    needs.insert(wanted.clone());

    // Alice knows bob and nothing else, so the first hop can only be bob.
    let first = alice.peers_for(&needs, 2);
    assert_eq!(first.len(), 1, "alice can only reach bob");
    assert_eq!(first[0].peer.id(), bob.id());
    let bob_node = cairn::p2p::dht::NodeId::from_bytes(bob.id());
    assert_eq!(
        alice.with_directory(|d| d.ask_of(bob_node)),
        vec![wanted.clone()],
        "the lookup did not choose bob as its next hop"
    );

    // Bob answers: no holders, but carol is closer. This is the shape
    // `exchange_dht` puts on the wire; driving it through the directory keeps
    // the test about routing rather than about sockets, which
    // `a_dht_round_records_who_holds_a_blob` already covers.
    let carol_contact = cairn::p2p::dht::PeerContact::new(carol.id(), carol_addr, 0);
    alice.with_directory(|directory| {
        directory.on_providers(
            bob_node,
            &[cairn::p2p::dht::ProviderAnswer {
                address: wanted.clone(),
                holders: Vec::new(),
                closer: vec![carol_contact],
            }],
        )
    });

    // Alice has heard of carol. She cannot dial her yet — no key — so the hop
    // is deferred and carol's key is queued.
    let carol_node = cairn::p2p::dht::NodeId::from_bytes(carol.id());
    let second = alice.peers_for(&needs, 2);
    assert!(
        !second.iter().any(|e| e.peer.id() == carol.id()),
        "alice dialled a peer whose key she does not have"
    );
    assert!(
        alice
            .with_directory(|d| d.key_wants())
            .contains(&carol_node),
        "carol's key was not queued, so alice can never reach her"
    );

    // Bob serves the key on the next round. Verified against the id, which is
    // what makes relaying it safe: a peer id *is* sha256(public key).
    let key = cairn::p2p::dht::encode_key(carol.public_key().as_ref());
    let adopted = cairn::p2p::dht::decode_key(carol_node, &key).expect("carol's real key");
    alice.with_book(|book| {
        book.insert(Endpoint::new(
            carol_addr,
            cairn::p2p::handshake::PeerPublic::from_bytes(&adopted).expect("a key"),
        ))
    });
    alice.with_directory(|directory| directory.resolved_key(carol_node));

    // And now the hop lands: the second hop of a lookup that started with one
    // reachable peer reaches a peer alice had never heard of.
    let third = alice.peers_for(&needs, 2);
    assert!(
        third.iter().any(|e| e.peer.id() == carol.id()),
        "alice still cannot reach carol after learning her key"
    );
    assert_eq!(
        alice.with_directory(|d| d.ask_of(carol_node)),
        vec![wanted],
        "carol was dialled but not asked the question"
    );
}

#[test]
fn a_forged_key_never_reaches_the_address_book() {
    // The one check that makes fetching a key from a stranger safe. There is
    // no signature anywhere in this path and none is needed: the bytes hash to
    // the id that was asked for, or they are discarded.
    let carol = PeerIdentity::generate();
    let mallory = PeerIdentity::generate();
    let carol_node = cairn::p2p::dht::NodeId::from_bytes(carol.id());

    // Mallory's real, well-formed key, offered under carol's name.
    let forged = cairn::p2p::dht::encode_key(mallory.public_key().as_ref());
    assert_eq!(
        cairn::p2p::dht::decode_key(carol_node, &forged),
        None,
        "a key that does not hash to the id asked for was accepted"
    );
    // Carol's own key still works, so the check is not simply refusing
    // everything.
    let honest = cairn::p2p::dht::encode_key(carol.public_key().as_ref());
    assert!(cairn::p2p::dht::decode_key(carol_node, &honest).is_some());
}

#[test]
fn a_lookup_that_finds_a_holder_actually_dials_it() {
    // The step that makes a lookup worth running. The search can walk the
    // network perfectly and still accomplish nothing if the answer is dropped
    // on the floor -- which is exactly what the first draft did: `take_finished`
    // returned the holders and the service ignored them.
    //
    // The holders are relayed claims, so they must not enter the provider store
    // (that is what stops an unsigned DHT amplifying a lie). They are kept as
    // local dial hints instead: acted on, never re-served, consumed on use.
    let carol = PeerIdentity::generate();
    let bob = PeerIdentity::generate();
    let bob_addr: std::net::SocketAddr = "127.0.0.1:9301".parse().expect("loopback");
    let carol_addr: std::net::SocketAddr = "127.0.0.1:9302".parse().expect("loopback");

    let mut alice = Service::new(Arc::new(PeerIdentity::generate()));
    alice.add_bootstrap(Endpoint::new(bob_addr, bob.to_public()));
    // Alice can already reach carol; what she does not know is that carol has
    // the blob. That is the fact the lookup is for.
    alice.add_bootstrap(Endpoint::new(carol_addr, carol.to_public()));

    let wanted = "ef".repeat(32);
    let mut needs = std::collections::BTreeSet::new();
    needs.insert(wanted.clone());

    // Whichever peer the lookup picked as its next hop is the one that owes an
    // answer -- asserting it is bob would be asserting the XOR ordering of two
    // randomly generated ids, which is a coin flip rather than a test.
    let dialled = alice.peers_for(&needs, 2);
    assert!(!dialled.is_empty(), "the lookup chose nobody to ask");
    for endpoint in &dialled {
        let node = cairn::p2p::dht::NodeId::from_bytes(endpoint.peer.id());
        if alice.with_directory(|d| d.ask_of(node)).is_empty() {
            continue;
        }
        alice.with_directory(|directory| {
            directory.on_providers(
                node,
                &[cairn::p2p::dht::ProviderAnswer {
                    address: wanted.clone(),
                    holders: vec![cairn::p2p::dht::Holder::new(carol.id(), carol_addr)],
                    closer: Vec::new(),
                }],
            )
        });
    }

    // The round hands the finished lookup to the service, which is the step
    // `exchange_dht` performs on a live connection.
    let finished = alice.with_directory(|directory| directory.take_finished());
    assert_eq!(finished.len(), 1, "the lookup did not finish");
    assert_eq!(
        finished[0].1.len(),
        1,
        "the holder was lost before adoption"
    );
    alice.adopt_for_test(finished);

    // Never stored: a relayed claim that entered the provider store would be
    // re-served to other peers, which is the amplification this design refuses.
    let now = cairn::time::unix_seconds();
    let (stored, _) = alice.with_directory(|d| d.lookup_providers(&wanted, now));
    assert!(
        stored.is_empty(),
        "a relayed holder entered the provider store"
    );

    // But acted on: carol is dialled for the blob she was named as holding.
    assert_eq!(alice.pending_hints(), 1, "the holder never became a hint");
    let chosen = alice.peers_for(&needs, 1);
    assert_eq!(chosen.len(), 1);
    assert_eq!(
        chosen[0].peer.id(),
        carol.id(),
        "the lookup found carol and the service dialled somebody else"
    );

    // And consumed: a wrong hint costs one dial, not a permanent detour.
    // Checked on the hint itself rather than on who gets dialled next -- carol
    // is in the address book, so the random sample can return her again for
    // reasons that have nothing to do with the hint.
    assert_eq!(
        alice.pending_hints(),
        0,
        "the hint was not consumed, so a bad one would be retried for ever"
    );
}

#[test]
fn a_node_handed_a_log_is_handed_the_network_with_it() {
    // The roadmap item: identity discovery was a *second* bootstrap problem —
    // a node needed a log and an address list, obtained separately, with
    // nothing tying them together. A peer record puts the permanent half in the
    // permanent record.
    //
    // What it deliberately cannot do on its own is complete a dial: the record
    // carries a transport *id*, not the 261 KiB McEliece key. So a seeded
    // contact is routable immediately and dialable once its key arrives, which
    // is the same two-step the DHT already uses for a contact it hears about.
    use cairn::records::PeerRecord;

    let carol = PeerIdentity::generate();
    let carol_addr: std::net::SocketAddr = "127.0.0.1:9401".parse().expect("loopback");
    let announcer = cairn::crypto::identity::Identity::from_secret_bytes([11u8; 32]);

    let mut writer = Node::new(
        Ledger::open(scratch("peer-log")).expect("open ledger"),
        repo_root(),
    );
    let record = PeerRecord::new(
        announcer.submitter_id(),
        cairn::p2p::dht::NodeId::from_bytes(carol.id()).to_hex(),
        carol_addr.to_string(),
        1,
        TS,
    )
    .signed_with(&announcer);
    writer
        .post_peer(&record, TS)
        .expect("the record is admitted");

    // A node that has only the log.
    let alice = Service::new(Arc::new(PeerIdentity::generate()));
    assert_eq!(alice.known_peers(), 0, "alice starts with no address book");
    assert_eq!(alice.seed_from_log(&writer), 1);

    // Routable now.
    let carol_node = cairn::p2p::dht::NodeId::from_bytes(carol.id());
    let known: Vec<_> = alice.with_directory(|d| {
        d.routing()
            .contacts()
            .map(|c| (c.id, c.addr))
            .collect::<Vec<_>>()
    });
    assert_eq!(known, vec![(carol_node, carol_addr)]);
    // And queued for the key that makes it dialable, rather than silently
    // stuck as a name alice can never reach.
    assert!(
        alice
            .with_directory(|d| d.key_wants())
            .contains(&carol_node),
        "a seeded contact was not queued for its key"
    );

    // A second seeding is idempotent, which matters because a daemon runs it
    // every tick.
    assert_eq!(alice.seed_from_log(&writer), 1);
    assert_eq!(alice.with_directory(|d| d.routing().len()), 1);
}

#[test]
fn a_replayed_peer_record_cannot_steer_the_routing_table_back() {
    // What `dht::Contact::seq` exists for, in its own words: without a
    // freshness counter "a table has no way to tell a peer that *moved* from a
    // peer being *impersonated* by a stale record".
    //
    // The counter was available and simply not passed. `seed_from_log` called
    // the seq-less form, so every contact arrived at zero — and the table takes
    // the new contact when `seq >= held`, which at zero is always. Anyone who
    // once saw a peer record could re-offer the address that peer had left and
    // go on steering traffic at it, while the log itself was fully protected:
    // `Node::peers` resolves highest-seq-wins and the audit reports a record
    // that does not advance. All of that stopped at the routing table's edge.
    use cairn::records::PeerRecord;

    let moved = PeerIdentity::generate();
    let old_addr: std::net::SocketAddr = "127.0.0.1:9501".parse().expect("loopback");
    let new_addr: std::net::SocketAddr = "127.0.0.1:9502".parse().expect("loopback");
    let announcer = cairn::crypto::identity::Identity::from_secret_bytes([21u8; 32]);
    let transport = cairn::p2p::dht::NodeId::from_bytes(moved.id());

    let mut writer = Node::new(
        Ledger::open(scratch("peer-replay")).expect("open ledger"),
        repo_root(),
    );
    for (seq, addr) in [(1u64, old_addr), (2, new_addr)] {
        let record = PeerRecord::new(
            announcer.submitter_id(),
            transport.to_hex(),
            addr.to_string(),
            seq,
            TS,
        )
        .signed_with(&announcer);
        writer.post_peer(&record, TS).expect("admitted");
    }

    let alice = Service::new(Arc::new(PeerIdentity::generate()));
    assert_eq!(alice.seed_from_log(&writer), 1);
    let held = |service: &Service| -> Vec<std::net::SocketAddr> {
        service.with_directory(|d| d.routing().contacts().map(|c| c.addr).collect())
    };
    assert_eq!(held(&alice), vec![new_addr], "the move was not followed");

    // The replay: the old record, offered again, exactly as an attacker who
    // kept a copy would. Its signature is perfectly good — that is the point,
    // and why signature checking alone does not cover this.
    alice.note_contact_at(moved.id(), old_addr, 1);
    assert_eq!(
        held(&alice),
        vec![new_addr],
        "a stale record steered the table back to an address the peer had left"
    );

    // And a genuine later move is still followed, so this is freshness rather
    // than a table that has stopped listening.
    alice.note_contact_at(moved.id(), old_addr, 3);
    assert_eq!(held(&alice), vec![old_addr], "a newer record was ignored");
}

#[test]
fn a_peer_record_a_node_cannot_parse_is_skipped_not_fatal() {
    // The consensus layer bounds an address and never parses one — two
    // implementations disagreeing about an IPv6 form would be a split. So the
    // network layer is where a form this build cannot dial gets dropped, and
    // dropping one contact must not cost the rest of the log.
    use cairn::records::PeerRecord;

    let announcer = cairn::crypto::identity::Identity::from_secret_bytes([12u8; 32]);
    let other = cairn::crypto::identity::Identity::from_secret_bytes([13u8; 32]);
    let reachable = PeerIdentity::generate();

    let mut writer = Node::new(
        Ledger::open(scratch("peer-log-unparseable")).expect("open ledger"),
        repo_root(),
    );
    writer
        .post_peer(
            &PeerRecord::new(
                announcer.submitter_id(),
                "ab".repeat(32),
                // Admissible as a record; not a socket address this build dials.
                "peer.example.onion:9000",
                1,
                TS,
            )
            .signed_with(&announcer),
            TS,
        )
        .expect("an onion address is a legal record");
    writer
        .post_peer(
            &PeerRecord::new(
                other.submitter_id(),
                cairn::p2p::dht::NodeId::from_bytes(reachable.id()).to_hex(),
                "127.0.0.1:9402",
                1,
                TS,
            )
            .signed_with(&other),
            TS,
        )
        .expect("post");

    let alice = Service::new(Arc::new(PeerIdentity::generate()));
    assert_eq!(
        alice.seed_from_log(&writer),
        1,
        "the unparseable record cost the parseable one"
    );
    assert_eq!(alice.with_directory(|d| d.routing().len()), 1);
}

/// A beacon heard on the local segment becomes a routable contact, by the same
/// path a peer record does.
///
/// The point of the third hint source is that it needs no new machinery: an
/// address and a transport id, neither trusted, both settled by the handshake.
/// This asserts the two arrive in the routing table with the key queued, which
/// is exactly what `seed_from_log` promises for records.
#[test]
fn a_beacon_becomes_a_routable_contact_with_its_key_queued() {
    use cairn::p2p::multicast;

    let heard_id = PeerIdentity::generate();
    let alice = Service::new(Arc::new(PeerIdentity::generate()));
    assert_eq!(alice.known_peers(), 0);

    // Bind on a pid-derived port so concurrent runs do not collide, and step
    // over a host with no multicast route rather than failing there -- that is
    // the documented degradation, not a defect.
    let port = 41_000 + (std::process::id() % 20_000) as u16;
    let Ok(responder) = multicast::Responder::bind(alice.identity(), 9500, port) else {
        eprintln!("skipped: multicast unavailable on this host");
        return;
    };
    let Ok(sender) = std::net::UdpSocket::bind(("0.0.0.0", 0)) else {
        eprintln!("skipped: cannot bind a sender");
        return;
    };
    let _ = sender.set_multicast_loop_v4(true);
    let frame = multicast::Beacon::new(heard_id.id(), 9600).encode();
    if sender
        .send_to(
            &frame,
            std::net::SocketAddr::new(multicast::GROUP.into(), port),
        )
        .is_err()
    {
        eprintln!("skipped: multicast send unavailable on this host");
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(250));

    let taken = alice.absorb_beacons(&responder, 16);
    if taken == 0 {
        eprintln!("skipped: no multicast delivery on this host");
        return;
    }
    assert_eq!(taken, 1, "one beacon, one contact");

    let node_id = cairn::p2p::dht::NodeId::from_bytes(heard_id.id());
    let known: Vec<_> = alice.with_directory(|d| {
        d.routing()
            .contacts()
            .map(|c| (c.id, c.addr.port()))
            .collect::<Vec<_>>()
    });
    assert_eq!(
        known,
        vec![(node_id, 9600)],
        "the session port must come from the beacon, not from the sending socket"
    );
    assert!(
        alice.with_directory(|d| d.key_wants()).contains(&node_id),
        "a contact from a beacon was not queued for the key that makes it dialable"
    );
}

// ---------------------------------------------------------------------------
// Settlement ordering: the invariant, and where it currently breaks.
// ---------------------------------------------------------------------------

/// A batch of `n` claims that all settle together, authored by one node.
///
/// Distinct objectives rather than one: a non-progressive objective settles
/// once, so several claims in a single batch need several objectives. They
/// share a verifier and an artifact, and differ only in `goal`, which is enough
/// to give each a distinct id.
fn batch_of(node: &mut Node, n: usize) {
    let base = collatz_objective();
    let artifact = collatz_artifact();
    for i in 0..n {
        let objective = Objective::new(
            format!("GOAL-batch-{i}"),
            base.statement.clone(),
            base.verifier.clone(),
            base.reward,
            base.funder.clone(),
            TS,
            None,
            None,
        )
        .expect("valid objective");
        let id = node.post_objective(&objective, TS).expect("post");
        let submitter = format!("sub-{i}");
        let nonce = format!("n-{i}");
        let hash = commitment_hash(&id, &submitter, &artifact, &nonce);
        node.commit(&Commitment::new(&id, &submitter, hash, TS), TS)
            .expect("commit");
        let claim = Claim::new(
            &id,
            &submitter,
            artifact.clone(),
            &nonce,
            TS_REVEAL,
            Vec::new(),
        )
        .expect("valid claim");
        node.reveal(&claim, TS_REVEAL).expect("reveal");
    }
    let _ = node.settle_at(TS_SETTLE);
}

/// The claims a node paid, in the order it paid them.
fn settlement_order(node: &Node) -> Vec<String> {
    node.ledger()
        .entries_of_kind("settlement")
        .into_iter()
        .filter_map(|entry| {
            entry
                .payload
                .get("claim_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// **The ordering invariant.** Two nodes holding the same records must pay the
/// same claims in the same order.
///
/// This is not a nicety. A batch settles in order of
/// `H(beacon(epoch, anchor) ‖ commitment_hash)`, and that order decides who is
/// paid first out of a pool that can run out — so two nodes that disagree about
/// it disagree about who got money. Neither errors, and `audit` passes on both,
/// because each is internally consistent. It is the quietest possible way for a
/// network to fork.
///
/// Bob is given nothing but alice's *inputs* and re-derives the rest, which is
/// the whole premise of the project.
#[test]
fn two_nodes_holding_the_same_records_settle_in_the_same_order() {
    let mut alice = node("order-alice");
    batch_of(&mut alice, 6);

    let mut bob = node("order-bob");
    apply(&mut bob, &records_of(&alice));

    let theirs = settlement_order(&alice);
    let ours = settlement_order(&bob);
    assert_eq!(theirs.len(), 6, "alice did not settle the whole batch");
    assert_eq!(ours.len(), 6, "bob did not settle the whole batch");
    assert_eq!(
        ours, theirs,
        "two nodes with identical records paid the same claims in different \
         orders. The pool is finite, so this is a disagreement about who got \
         money -- and both logs audit clean, because each is internally \
         consistent."
    );
}

/// The mechanism behind the test above, isolated.
///
/// The batch order is keyed on `beacon(epoch, anchor)`, so the anchor is the
/// only input that could differ between two nodes holding the same records --
/// the epoch comes from each record's own `created_at` and already agrees.
/// Asserting on it directly says *why* an order diverged rather than only that
/// it did, and it is deterministic where a six-claim order comparison could
/// coincide by luck.
#[test]
fn the_settlement_anchor_is_the_same_on_both_nodes() {
    let mut alice = node("anchor-alice");
    batch_of(&mut alice, 6);

    let mut bob = node("anchor-bob");
    apply(&mut bob, &records_of(&alice));

    // The epoch the reveals landed in, whose close settles the batch.
    let epoch = cairn::time::parse_rfc3339(TS_REVEAL).expect("parse") as u64
        / cairn::partition::epoch_seconds();

    assert_eq!(
        bob.anchor_of_epoch(epoch),
        alice.anchor_of_epoch(epoch),
        "the settlement anchor differs between two nodes holding identical \
         records, so their beacons differ and their batches sort differently"
    );
}
