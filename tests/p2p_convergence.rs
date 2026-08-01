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

use proofwork::canonical::Value;
use proofwork::gossip::{Candidate, Population};
use proofwork::ledger::Ledger;
use proofwork::node::Node;
use proofwork::p2p::discovery::Endpoint;
use proofwork::p2p::handshake::PeerIdentity;
use proofwork::p2p::pop::PopLimits;
use proofwork::p2p::service::Service;
use proofwork::p2p::sync::{reconcile, Peer, Record, SyncError};
use proofwork::records::{commitment_hash, Claim, Commitment, Objective};

const TS: &str = "2026-07-29T00:00:00+00:00";
/// One epoch after [`TS`]. A reveal must be in a strictly later epoch than the
/// commitment it opens, so commit and reveal cannot share a timestamp.
///
/// Claims are *built* with this instant too, which is what both CLIs do: a
/// claim's `created_at` is set when it is revealed. It matters here because a
/// receiver has only the record, so the record's own instant is the only stamp
/// two nodes can agree to file it under.
const TS_REVEAL: &str = "2026-07-29T00:10:00+00:00";
/// One epoch after the reveal, so the reveal epoch has closed and its batch
/// settles. Both nodes use the same three instants, which is what makes their
/// settlements comparable at all: the batch order is derived from the epoch.
const TS_SETTLE: &str = "2026-07-29T00:20:00+00:00";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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
/// Each record is stamped with its own `created_at`, mirroring
/// `p2p::service::apply_records`. The local clock would put a replayed
/// commitment and the claim that opens it in the same epoch, and every claim
/// would be refused; the record's own instant is also the only stamp two
/// receivers agree on, which is what makes their epochs match.
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

    let bob_objective = objective.clone();
    let bob_thread = thread::spawn(move || {
        let mut bob = node("bob-dht");
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
    assert!(
        !alice.missing_code().is_empty(),
        "alice already holds the checker, so the ask would be empty"
    );
    let alice_service = Service::new(Arc::new(PeerIdentity::generate()));
    alice_service
        .dial_node_once(&endpoint, &mut alice)
        .expect("alice's round");

    let bob_holds = bob_thread.join().expect("bob's thread");
    assert!(
        !bob_holds.is_empty(),
        "bob holds no blobs to tell alice about"
    );

    // Alice heard the announcement, and attributed it to the peer she was
    // actually talking to.
    let now = proofwork::time::unix_seconds();
    let (holders, _) =
        alice_service.with_directory(|directory| directory.lookup_providers(&bob_holds[0], now));
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
    let now = proofwork::time::unix_seconds();
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
