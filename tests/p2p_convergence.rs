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

use proofwork::canonical::Value;
use proofwork::ledger::Ledger;
use proofwork::node::Node;
use proofwork::p2p::sync::{reconcile, Peer, Record, SyncError};
use proofwork::records::{commitment_hash, Claim, Commitment, Objective};

const TS: &str = "2026-07-29T00:00:00+00:00";

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
fn apply(node: &mut Node, records: &[Record]) {
    for kind in ["objective", "commitment", "claim"] {
        for record in records.iter().filter(|r| r.kind == kind) {
            match kind {
                "objective" => {
                    let o = Objective::from_value(&record.payload).expect("objective decodes");
                    let _ = node.post_objective(&o, TS);
                }
                "commitment" => {
                    let c = Commitment::from_value(&record.payload).expect("commitment decodes");
                    let _ = node.commit(&c, TS);
                }
                "claim" => {
                    let c = Claim::from_value(&record.payload).expect("claim decodes");
                    let _ = node.reveal(&c, TS);
                }
                _ => unreachable!(),
            }
        }
    }
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
    let claim = Claim::new(&objective_id, "alice", artifact, nonce, TS, vec![]).expect("claim");
    let outcome = alice.reveal(&claim, TS).expect("reveal");

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
    let claim = Claim::new(&objective_id, "alice", artifact, "n", TS, vec![]).expect("claim");
    alice.reveal(&claim, TS).expect("reveal");

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
    let claim = Claim::new(&objective_id, "alice", artifact, "n", TS, vec![]).expect("claim");
    alice.reveal(&claim, TS).expect("reveal");

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
