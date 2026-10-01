//! The lab's guarantees, checked as laws rather than examples.
//!
//! - **Replicas that hold the same ops agree on everything**, however the ops
//!   arrived: shuffled, duplicated, partitioned and re-merged. This is the
//!   whole convergence argument, so it is tested against random histories, not
//!   asserted.
//! - **A conflict is never lost**: concurrent writes stay visible until
//!   somebody who saw all of them supersedes them, and write-once paths can
//!   never be replaced.
//! - **Authority comes from the causal past**, and a revocation reaches every
//!   op concurrent with it — including a revoked admin's concurrent revocation
//!   of somebody else.
//! - **Every carrier moves the same thing**: a directory, a bundle file, and
//!   the encrypted network transport all converge two replicas, and none of
//!   them can slip in bytes under a name they do not hash to.
//! - **A run records what ran**: under gVisor when this host has it, the
//!   receipt and the outputs land in one op.
//!
//! Randomness comes from a small LCG, as in `tests/properties.rs`, so a
//! failure is replayable from its seed.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cairn::crypto::identity::Identity;
use cairn::lab::api::{self, ExecRequest, Expect, Input};
use cairn::lab::exec::{self, Preference};
use cairn::lab::op::{Body, EntryRef, Member, Op, Outcome, Policy, Role};
use cairn::lab::state::{Conflict, State};
use cairn::lab::store::Lab;
use cairn::lab::sync::{self, Peer};
use cairn::lab::tree::{self, Filter};
use cairn::lab::LabError;

// -- helpers -------------------------------------------------------------------------

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

fn temp(name: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "cairn-lab-it-{name}-{}-{n}-{}",
        std::process::id(),
        cairn::time::unix_seconds()
    ));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn id(seed: u8) -> Identity {
    Identity::from_secret_bytes([seed; 32])
}

fn writer(key: &Identity, roles: &[Role]) -> Member {
    Member {
        key: key.submitter_id(),
        roles: roles.iter().copied().collect(),
        peers: BTreeSet::new(),
    }
}

/// A space founded by `admin`, with `others` admitted as writers in genesis.
fn space(name: &str, admin: &Identity, others: &[&Identity], policy: Policy) -> Lab {
    let members = others
        .iter()
        .map(|other| writer(other, &[Role::Writer]))
        .collect();
    Lab::init(&temp(name), admin, name, members, policy).expect("init")
}

/// An empty replica of `lab`'s space, filled by syncing with it.
fn replica(lab: &mut Lab, name: &str) -> Lab {
    let dir = temp(name);
    Lab::create_empty(&dir, lab.space()).expect("empty");
    let mut copy = Lab::open(&dir).expect("open");
    sync::sync(&mut copy, lab).expect("sync");
    copy
}

fn write(lab: &mut Lab, who: &Identity, path: &str, text: &str) -> Op {
    api::write_file(lab, who, path, text.as_bytes(), false, Expect::Current).expect("write")
}

fn values(state: &State, path: &str) -> Vec<String> {
    state
        .files
        .get(path)
        .map(|vs| {
            vs.iter()
                .map(|v| v.blob.clone().unwrap_or_else(|| "deleted".into()))
                .collect()
        })
        .unwrap_or_default()
}

fn blob_of(text: &str) -> String {
    cairn::canonical::digest_bytes(text.as_bytes())
}

// -- convergence ------------------------------------------------------------------------

#[test]
fn replicas_that_hold_the_same_ops_agree_however_the_ops_arrived() {
    for seed in [1u64, 7, 42, 2026] {
        let mut rng = Lcg(seed);
        let people = [id(1), id(2), id(3)];
        let mut origin = space(
            &format!("conv-{seed}"),
            &people[0],
            &[&people[1], &people[2]],
            Policy {
                write_once: vec!["records/**".into()],
                ..Policy::default()
            },
        );
        let mut replicas: Vec<Lab> = (0..3)
            .map(|i| replica(&mut origin, &format!("conv-{seed}-r{i}")))
            .collect();

        for step in 0..80 {
            let r = rng.below(replicas.len());
            let who = &people[r];
            match rng.below(6) {
                0 | 1 => {
                    // A small path set, so concurrent writes collide.
                    let path = format!("notes/{}.md", rng.below(4));
                    write(&mut replicas[r], who, &path, &format!("{seed}-{step}"));
                }
                2 => {
                    let path = format!("records/R-{}.yaml", rng.below(6));
                    // A write-once path: the first write may collide with
                    // another replica's first write, which must stay visible.
                    let _ = api::write_file(
                        &mut replicas[r],
                        who,
                        &path,
                        format!("record {step}").as_bytes(),
                        false,
                        Expect::Absent,
                    );
                }
                3 => {
                    let task = format!("TASK-{}", rng.below(3));
                    let _ = api::claim(
                        &mut replicas[r],
                        who,
                        &task,
                        &format!("agent-{r}"),
                        600,
                        None,
                    );
                }
                4 => {
                    api::send(
                        &mut replicas[r],
                        who,
                        vec!["all".into()],
                        Some(format!("agent-{r}")),
                        &format!("step {step}"),
                        "",
                        Vec::new(),
                    )
                    .expect("send");
                }
                _ => {
                    let other = (r + 1 + rng.below(replicas.len() - 1)) % replicas.len();
                    let (a, b) = pair(&mut replicas, r, other);
                    sync::sync(a, b).expect("partial sync");
                }
            }
        }

        // Union of everything, delivered to two fresh replicas in two
        // different shuffled orders, with duplicates.
        let mut all: Vec<Op> = replicas
            .iter()
            .flat_map(|lab| lab.ops().iter().cloned())
            .collect();
        let mut first = all.clone();
        rng.shuffle(&mut first);
        rng.shuffle(&mut all);
        all.extend(first.iter().take(10).cloned());
        let fresh_a = fresh_from(&origin, &format!("conv-{seed}-fa"), first);
        let fresh_b = fresh_from(&origin, &format!("conv-{seed}-fb"), all);
        let expected = State::of(&fresh_a);
        assert_eq!(
            expected,
            State::of(&fresh_b),
            "seed {seed}: shuffled deliveries disagree"
        );

        // And the replicas themselves, gossiping until quiet, reach the same.
        for _ in 0..2 {
            for i in 0..replicas.len() {
                for j in 0..replicas.len() {
                    if i != j {
                        let (a, b) = pair(&mut replicas, i, j);
                        sync::sync(a, b).expect("sync");
                    }
                }
            }
        }
        for lab in &replicas {
            assert_eq!(
                expected,
                State::of(lab),
                "seed {seed}: gossip did not converge"
            );
        }
        // Some write-once collision should have happened at least once across
        // the seeds; when it does it must be a write-once conflict.
        for conflict in expected.conflicts() {
            if let Conflict::File {
                path, write_once, ..
            } = conflict
            {
                assert_eq!(write_once, path.starts_with("records/"), "{path}");
            }
        }
    }
}

fn pair(labs: &mut [Lab], i: usize, j: usize) -> (&mut Lab, &mut Lab) {
    assert_ne!(i, j);
    if i < j {
        let (left, right) = labs.split_at_mut(j);
        (&mut left[i], &mut right[0])
    } else {
        let (left, right) = labs.split_at_mut(i);
        (&mut right[0], &mut left[j])
    }
}

fn fresh_from(origin: &Lab, name: &str, ops: Vec<Op>) -> Lab {
    let dir = temp(name);
    Lab::create_empty(&dir, origin.space()).expect("empty");
    let mut lab = Lab::open(&dir).expect("open");
    let (added, refused) = lab.ingest_many(ops).expect("ingest");
    assert!(refused.is_empty(), "refused: {refused:?}");
    assert!(added > 0);
    lab
}

// -- conflicts ----------------------------------------------------------------------------

#[test]
fn concurrent_edits_stay_visible_until_someone_who_saw_both_supersedes_them() {
    let alice = id(10);
    let bob = id(11);
    let mut a = space("conflict", &alice, &[&bob], Policy::default());
    write(&mut a, &alice, "goal.yaml", "v1");
    let mut b = replica(&mut a, "conflict-b");

    // Both edit v1 without seeing each other.
    write(&mut a, &alice, "goal.yaml", "alice's v2");
    write(&mut b, &bob, "goal.yaml", "bob's v2");
    sync::sync(&mut a, &mut b).expect("sync");

    let state = State::of(&a);
    let mut current = values(&state, "goal.yaml");
    current.sort();
    let mut expected = vec![blob_of("alice's v2"), blob_of("bob's v2")];
    expected.sort();
    assert_eq!(current, expected, "both edits survive as siblings");
    assert_eq!(state.conflicts().len(), 1);
    assert_eq!(State::of(&b), state, "both replicas see the same conflict");

    // Resolving: a write superseding both.
    let seen: Vec<EntryRef> = state.files["goal.yaml"]
        .iter()
        .map(|v| v.version.entry.clone())
        .collect();
    api::write_file(
        &mut b,
        &bob,
        "goal.yaml",
        b"merged v3",
        false,
        Expect::Seen(seen),
    )
    .expect("resolve");
    sync::sync(&mut a, &mut b).expect("sync");
    let state = State::of(&a);
    assert_eq!(values(&state, "goal.yaml"), vec![blob_of("merged v3")]);
    assert!(state.conflicts().is_empty());

    // A write that supersedes only what it saw leaves a later edit standing.
    let stale: Vec<EntryRef> = state.files["goal.yaml"]
        .iter()
        .map(|v| v.version.entry.clone())
        .collect();
    write(&mut a, &alice, "goal.yaml", "alice's v4");
    api::write_file(
        &mut b,
        &bob,
        "goal.yaml",
        b"bob's v4",
        false,
        Expect::Seen(stale),
    )
    .expect("stale write");
    sync::sync(&mut a, &mut b).expect("sync");
    assert_eq!(State::of(&a).files["goal.yaml"].len(), 2);
}

#[test]
fn a_write_once_record_is_never_replaced_and_a_collision_stays_open() {
    let alice = id(20);
    let bob = id(21);
    let policy = Policy {
        write_once: vec!["ledger/**".into()],
        mutable: vec!["ledger/goals/*.yaml".into()],
        ignore: vec!["knowledge/INDEX.md".into()],
    };
    let mut a = space("once", &alice, &[&bob], policy);
    let mut b = replica(&mut a, "once-b");

    // Two different first writes to one immutable id: the collision case.
    api::write_file(
        &mut a,
        &alice,
        "ledger/decisions/DEC-1.yaml",
        b"alice",
        false,
        Expect::Absent,
    )
    .expect("a");
    api::write_file(
        &mut b,
        &bob,
        "ledger/decisions/DEC-1.yaml",
        b"bob",
        false,
        Expect::Absent,
    )
    .expect("b");
    sync::sync(&mut a, &mut b).expect("sync");
    let state = State::of(&a);
    let conflicts = state.conflicts();
    assert!(matches!(
        &conflicts[..],
        [Conflict::File {
            write_once: true,
            ..
        }]
    ));

    // The API refuses to replace it…
    let refused = api::write_file(
        &mut a,
        &alice,
        "ledger/decisions/DEC-1.yaml",
        b"fixed",
        false,
        Expect::Current,
    )
    .expect_err("write-once");
    assert!(matches!(refused, LabError::Refused(_)));

    // …and a hand-built replacement op is excluded by every view.
    let seen: Vec<EntryRef> = state.files["ledger/decisions/DEC-1.yaml"]
        .iter()
        .map(|v| v.version.entry.clone())
        .collect();
    let blob = a.blobs().put_bytes(b"sneaky").expect("blob");
    a.append(
        &alice,
        Body::Files {
            entries: vec![cairn::lab::op::FileEntry {
                path: "ledger/decisions/DEC-1.yaml".into(),
                blob: Some(blob),
                size: 6,
                exec: false,
                pred: seen,
            }],
        },
    )
    .expect("the op itself is admissible; the entry is not");
    let state = State::of(&a);
    assert_eq!(state.files["ledger/decisions/DEC-1.yaml"].len(), 2);
    assert!(state
        .excluded
        .iter()
        .any(|e| e.reason.contains("cannot be replaced")));

    // Mutable heads under the same tree edit normally; ignored paths never land.
    write(&mut a, &alice, "ledger/goals/GOAL-X.yaml", "head 1");
    write(&mut a, &alice, "ledger/goals/GOAL-X.yaml", "head 2");
    assert_eq!(
        values(&State::of(&a), "ledger/goals/GOAL-X.yaml"),
        vec![blob_of("head 2")]
    );
    assert!(api::write_file(
        &mut a,
        &alice,
        "knowledge/INDEX.md",
        b"x",
        false,
        Expect::Current
    )
    .is_err());
}

// -- membership ------------------------------------------------------------------------------

#[test]
fn a_revocation_reaches_every_op_concurrent_with_it() {
    let admin = id(30);
    let mallory = id(31);
    let mut a = space("revoke", &admin, &[&mallory], Policy::default());
    write(&mut a, &mallory, "before.md", "written while entitled");
    let mut m = replica(&mut a, "revoke-m");

    // The admin revokes; mallory, partitioned away, keeps writing.
    a.append(
        &admin,
        Body::Members {
            admit: Vec::new(),
            revoke: vec![mallory.submitter_id()],
        },
    )
    .expect("revoke");
    write(&mut m, &mallory, "after.md", "written after being revoked");
    sync::sync(&mut a, &mut m).expect("sync");

    for lab in [&a, &m] {
        let state = State::of(lab);
        assert!(
            state.files.contains_key("before.md"),
            "before the revocation stands"
        );
        assert!(
            !state.files.contains_key("after.md"),
            "concurrent with it is excluded"
        );
        assert!(!state.roster.is_member(&mallory.submitter_id()));
    }
    // Mallory cannot write any more at all, from either replica.
    let refused = api::write_file(&mut a, &mallory, "again.md", b"x", false, Expect::Current)
        .expect_err("revoked");
    assert!(matches!(refused, LabError::Refused(_)));

    // Re-admission after the revocation restores her, for what follows it.
    a.append(
        &admin,
        Body::Members {
            admit: vec![writer(&mallory, &[Role::Writer])],
            revoke: Vec::new(),
        },
    )
    .expect("readmit");
    write(&mut a, &mallory, "readmitted.md", "ok");
    let state = State::of(&a);
    assert!(state.files.contains_key("readmitted.md"));
    assert!(
        !state.files.contains_key("after.md"),
        "re-admission is not retroactive"
    );
}

#[test]
fn two_admins_revoking_each_other_at_once_resolve_the_same_way_everywhere() {
    let alice = id(40);
    let bob = id(41);
    let mut a = Lab::init(
        &temp("mutual"),
        &alice,
        "mutual",
        vec![writer(&bob, &[Role::Admin, Role::Writer])],
        Policy::default(),
    )
    .expect("init");
    let mut b = replica(&mut a, "mutual-b");
    a.append(
        &alice,
        Body::Members {
            admit: Vec::new(),
            revoke: vec![bob.submitter_id()],
        },
    )
    .expect("alice revokes bob");
    b.append(
        &bob,
        Body::Members {
            admit: Vec::new(),
            revoke: vec![alice.submitter_id()],
        },
    )
    .expect("bob revokes alice");
    sync::sync(&mut a, &mut b).expect("sync");
    let left = State::of(&a);
    let right = State::of(&b);
    assert_eq!(left, right);
    // Exactly one of them is still a member: whoever's revocation came first.
    let survivors = [&alice, &bob]
        .iter()
        .filter(|who| left.roster.is_member(&who.submitter_id()))
        .count();
    assert_eq!(survivors, 1, "{:?}", left.roster);
}

#[test]
fn a_revoked_admins_concurrent_admission_is_undone_with_everything_it_authorised() {
    let root = id(110);
    let rogue = id(111);
    let friend = id(112);
    let mut a = Lab::init(
        &temp("cascade"),
        &root,
        "cascade",
        vec![writer(&rogue, &[Role::Admin, Role::Writer])],
        Policy::default(),
    )
    .expect("init");
    let mut r = replica(&mut a, "cascade-r");

    // Root revokes the rogue admin. The rogue, not having seen it, admits a
    // friend, and the friend writes — all valid on the rogue's replica.
    a.append(
        &root,
        Body::Members {
            admit: Vec::new(),
            revoke: vec![rogue.submitter_id()],
        },
    )
    .expect("revoke");
    r.append(
        &rogue,
        Body::Members {
            admit: vec![writer(&friend, &[Role::Writer])],
            revoke: Vec::new(),
        },
    )
    .expect("rogue admits friend");
    write(&mut r, &friend, "friend.md", "planted");
    assert!(
        State::of(&r).files.contains_key("friend.md"),
        "valid before the merge"
    );

    sync::sync(&mut a, &mut r).expect("sync");
    for lab in [&a, &r] {
        let state = State::of(lab);
        assert!(
            !state.roster.is_member(&friend.submitter_id()),
            "the admission is undone"
        );
        assert!(
            !state.files.contains_key("friend.md"),
            "and so is what it authorised"
        );
        assert!(state.excluded.len() >= 2, "{:?}", state.excluded);
    }
    assert_eq!(State::of(&a), State::of(&r));
}

// -- leases -----------------------------------------------------------------------------------

#[test]
fn two_agents_racing_for_one_task_learn_after_one_sync_who_holds_it() {
    let a1 = id(50);
    let a2 = id(51);
    let mut a = space("lease", &a1, &[&a2], Policy::default());
    let mut b = replica(&mut a, "lease-b");
    let (first, view_a) = api::claim(&mut a, &a1, "TASK-1", "executor-1", 600, None).expect("a");
    let (second, view_b) = api::claim(&mut b, &a2, "TASK-1", "executor-2", 600, None).expect("b");
    // Before sync, each believes it holds the task.
    assert_eq!(view_a.holder.map(|c| c.id), Some(first.id.clone()));
    assert_eq!(view_b.holder.map(|c| c.id), Some(second.id.clone()));
    sync::sync(&mut a, &mut b).expect("sync");
    let now = api::now();
    let ta = State::of(&a).tasks(now).remove("TASK-1").expect("task");
    let tb = State::of(&b).tasks(now).remove("TASK-1").expect("task");
    assert_eq!(ta, tb, "both replicas agree");
    assert!(ta.holder.is_some());
    assert_eq!(ta.contended.len(), 1, "the loser is told it lost");

    // A lease past its ttl holds nothing; a completed release closes the task.
    let later = now + 10_000;
    assert!(State::of(&a).tasks(later)["TASK-1"].holder.is_none());
    let holder = ta.holder.expect("holder");
    let releaser = if holder.author == a1.submitter_id() {
        &a1
    } else {
        &a2
    };
    let lab = if holder.author == a1.submitter_id() {
        &mut a
    } else {
        &mut b
    };
    api::release(lab, releaser, &holder.id, Outcome::Completed, None).expect("release");
    sync::sync(&mut a, &mut b).expect("sync");
    assert!(State::of(&b).tasks(now)["TASK-1"].completed);

    // Nobody else may release a lease they do not hold.
    let (third, _) = api::claim(&mut a, &a1, "TASK-2", "executor-1", 600, None).expect("claim");
    sync::sync(&mut a, &mut b).expect("sync");
    api::release(&mut b, &a2, &third.id, Outcome::Abandoned, None).expect("op is admissible");
    sync::sync(&mut a, &mut b).expect("sync");
    let state = State::of(&a);
    assert!(
        state.tasks(now)["TASK-2"].holder.is_some(),
        "a stranger's release is void"
    );
    assert!(state.excluded.iter().any(|e| e.reason.contains("release")));
}

// -- carriers ------------------------------------------------------------------------------------

#[test]
fn a_bundle_moves_a_space_and_refuses_bytes_that_do_not_match_their_address() {
    let alice = id(60);
    let mut a = space("bundle", &alice, &[], Policy::default());
    write(&mut a, &alice, "data/x.txt", "some research data");
    write(&mut a, &alice, "data/y.txt", "more");
    let path = temp("bundle-file");
    let mut file = fs::File::create(&path).expect("create");
    let (ops, blobs) = sync::write_bundle(&a, &mut file, None).expect("bundle");
    drop(file);
    assert_eq!(ops, a.len());
    assert_eq!(blobs, 2);

    let dir = temp("bundle-into");
    Lab::create_empty(&dir, a.space()).expect("empty");
    let mut b = Lab::open(&dir).expect("open");
    let report =
        sync::read_bundle(&mut b, &mut fs::File::open(&path).expect("open")).expect("read");
    assert_eq!(report.ops_received, a.len());
    assert_eq!(State::of(&a), State::of(&b));
    assert!(sync::wanted_blobs(&b).is_empty());

    // Flip one byte of blob content inside the bundle: refused, not stored.
    let mut bytes = fs::read(&path).expect("read");
    let at = bytes
        .windows(b"some research data".len())
        .position(|w| w == b"some research data")
        .expect("content present");
    bytes[at] ^= 1;
    fs::write(&path, &bytes).expect("write");
    let dir = temp("bundle-tampered");
    Lab::create_empty(&dir, a.space()).expect("empty");
    let mut c = Lab::open(&dir).expect("open");
    let error = sync::read_bundle(&mut c, &mut fs::File::open(&path).expect("open"))
        .expect_err("tampered blob");
    assert!(matches!(error, LabError::Refused(_)), "{error}");
}

#[test]
fn a_replica_of_another_space_is_refused_by_every_carrier() {
    let alice = id(70);
    let mut a = space("space-a", &alice, &[], Policy::default());
    let mut b = space("space-b", &alice, &[], Policy::default());
    assert!(matches!(
        sync::sync(&mut a, &mut b),
        Err(LabError::Refused(_))
    ));
    let path = temp("cross-bundle");
    sync::write_bundle(&a, &mut fs::File::create(&path).expect("create"), None).expect("bundle");
    assert!(matches!(
        sync::read_bundle(&mut b, &mut fs::File::open(&path).expect("open")),
        Err(LabError::Refused(_))
    ));
}

#[test]
fn two_replicas_sync_over_the_encrypted_transport_and_strangers_are_turned_away() {
    use cairn::p2p::handshake::{peer_id_hex, PeerIdentity};
    let alice = id(80);
    let server_peer = PeerIdentity::generate();
    let client_peer = PeerIdentity::generate();
    let stranger_peer = PeerIdentity::generate();
    let server_id = peer_id_hex(&server_peer.id());
    let mut a = Lab::init(
        &temp("net"),
        &alice,
        "net",
        vec![Member {
            key: alice.submitter_id(),
            roles: [Role::Admin, Role::Writer].into_iter().collect(),
            peers: [peer_id_hex(&client_peer.id())].into_iter().collect(),
        }],
        Policy::default(),
    )
    .expect("init");
    write(&mut a, &alice, "shared.md", "over the wire");

    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        probe.local_addr().expect("addr").port()
    };
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let root = a.root().to_path_buf();
    std::thread::spawn(move || {
        let _ = sync::serve(&root, server_peer, addr, sync::Access::default());
    });
    // Wait for the listener.
    let mut ready = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "server did not start");

    let dir = temp("net-client");
    Lab::create_empty(&dir, a.space()).expect("empty");
    let mut b = Lab::open(&dir).expect("open");
    let mut remote =
        sync::RemotePeer::connect(addr, &server_id, &client_peer).expect("listed peer connects");
    let report = sync::sync(&mut b, &mut remote).expect("sync");
    assert_eq!(report.ops_received, a.len());
    assert_eq!(report.blobs_received, 1);
    assert_eq!(
        api::read_file(&b, &State::of(&b), "shared.md").expect("read"),
        b"over the wire"
    );

    // A write here travels back the same way.
    write(&mut b, &alice, "reply.md", "from the client");
    let report = sync::sync(&mut b, &mut remote).expect("sync back");
    assert_eq!(report.ops_sent, 1);
    a.refresh().expect("refresh");
    assert!(State::of(&a).files.contains_key("reply.md"));

    // A peer nobody lists completes a handshake and is refused service.
    let mut stranger = sync::RemotePeer::connect(addr, &server_id, &stranger_peer)
        .expect("the handshake itself succeeds");
    assert!(
        stranger.space_id().is_err(),
        "an unlisted peer gets nothing"
    );
}

// -- working copy ------------------------------------------------------------------------------

#[test]
fn checkout_edit_commit_supersedes_only_what_was_seen() {
    let alice = id(90);
    let bob = id(91);
    let mut a = space(
        "tree",
        &alice,
        &[&bob],
        Policy {
            write_once: vec!["records/**".into()],
            ..Policy::default()
        },
    );
    write(&mut a, &alice, "head.yaml", "status: active\n");
    api::write_file(
        &mut a,
        &alice,
        "records/R-1.yaml",
        b"immutable\n",
        false,
        Expect::Absent,
    )
    .expect("record");
    let mut b = replica(&mut a, "tree-b");

    let work = temp("tree-work");
    let state = State::of(&b);
    let report = tree::checkout(&b, &state, &work, &Filter::default(), false).expect("checkout");
    assert_eq!(report.written, 2);
    assert_eq!(
        fs::read_to_string(work.join("head.yaml")).expect("read"),
        "status: active\n"
    );

    // Meanwhile alice edits the head on her replica, and it reaches bob's
    // replica before bob commits.
    write(&mut a, &alice, "head.yaml", "status: active\nnext: alice\n");
    sync::sync(&mut b, &mut a).expect("sync");

    // Bob edits the file he checked out, plus a new record, and tries to edit
    // an immutable one.
    fs::write(work.join("head.yaml"), "status: active\nnext: bob\n").expect("edit");
    fs::create_dir_all(work.join("records")).expect("mkdir");
    fs::write(work.join("records/R-2.yaml"), "new record\n").expect("new");
    fs::write(work.join("records/R-1.yaml"), "edited!\n").expect("illegal edit");
    let report = tree::commit(&mut b, &bob, &work, &Filter::default()).expect("commit");
    assert_eq!(report.written, 2, "{report:?}");
    assert_eq!(
        report.refused.len(),
        1,
        "the immutable edit is refused before signing"
    );

    // Bob's edit superseded what bob saw, not alice's newer edit: a conflict.
    let state = State::of(&b);
    assert_eq!(state.files["head.yaml"].len(), 2);
    assert!(state.files.contains_key("records/R-2.yaml"));

    // A checkout shows both sides; committing an edit of the main file then
    // resolves it, because the checkout saw both.
    let work2 = temp("tree-work2");
    let report = tree::checkout(&b, &state, &work2, &Filter::default(), false).expect("checkout");
    assert_eq!(report.conflicts.len(), 1);
    fs::write(work2.join("head.yaml"), "status: active\nnext: both\n").expect("merge by hand");
    tree::commit(&mut b, &bob, &work2, &Filter::default()).expect("commit");
    let state = State::of(&b);
    assert_eq!(
        values(&state, "head.yaml"),
        vec![blob_of("status: active\nnext: both\n")]
    );
    assert!(state.conflicts().is_empty());

    // An untouched working copy has nothing to commit.
    let changes = tree::status(&b, &state, &work2, &Filter::default()).expect("status");
    assert!(changes.is_empty(), "{changes:?}");
}

// -- execution ------------------------------------------------------------------------------------

/// A minimal root filesystem: `/bin/sh` and the libraries it needs, copied
/// from the host. Enough to run a shell script, and hermetic.
fn tiny_rootfs(dir: &Path) -> bool {
    let shell = Path::new("/bin/sh");
    let Ok(real) = fs::canonicalize(shell) else {
        return false;
    };
    let Ok(output) = std::process::Command::new("ldd").arg(&real).output() else {
        return false;
    };
    let mut files = vec![real.clone()];
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        for token in line.split_whitespace() {
            if token.starts_with('/') {
                files.push(PathBuf::from(token));
            }
        }
    }
    for file in &files {
        let Ok(resolved) = fs::canonicalize(file) else {
            continue;
        };
        for target in [file, &resolved] {
            let dest = dir.join(target.strip_prefix("/").expect("absolute"));
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            let _ = fs::copy(&resolved, &dest);
        }
    }
    let sh = dir.join("bin/sh");
    fs::create_dir_all(dir.join("bin")).expect("bin");
    if !sh.exists() {
        let _ = fs::copy(&real, &sh);
    }
    sh.exists()
}

#[test]
fn a_run_under_gvisor_records_its_receipt_and_outputs_as_one_op() {
    exercise(Preference::Gvisor, "runsc");
}

#[test]
fn a_run_under_bubblewrap_honours_the_same_plan() {
    exercise(Preference::Bubblewrap, "bwrap");
}

/// One scenario, run under one backend: inputs read-only, outputs published,
/// a read-only root, the program's own exit status passed through, a missing
/// program reported as an infrastructure error, and a deadline enforced.
fn exercise(preference: Preference, backend: &str) {
    if exec::backend(preference).is_err() {
        eprintln!("{backend} is not usable on this host; skipping");
        return;
    }
    let alice = id(100);
    let mut lab = space(&format!("exec-{backend}"), &alice, &[], Policy::default());
    write(&mut lab, &alice, "inputs/params.txt", "n=42\n");
    let rootfs = temp("exec-rootfs");
    assert!(tiny_rootfs(&rootfs), "could not build a tiny rootfs");
    let (env, _) = cairn::lab::env::import(
        &mut lab,
        &alice,
        "tiny",
        &cairn::lab::env::Source::Dir(rootfs.clone()),
        &cairn::lab::env::ImportOptions::default(),
    )
    .expect("import");
    assert!(env.rootfs.join("bin/sh").exists());

    let sh = |script: &str| vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
    let mut request = ExecRequest::new(
        "tiny",
        sh(
            // Reads its input, writes an output, and proves the root is
            // read-only.
            "read line < /in/params.txt; echo \"got $line\" > /out/result.txt; \
             if echo x > /bin/forbidden 2>/dev/null; then echo writable; else echo readonly; fi; \
             echo done",
        ),
    );
    request.inputs.push(Input {
        prefix: "inputs".into(),
        target: "/in".into(),
    });
    request.publish = Some("runs/RUN-test-1".into());
    request.sandbox = preference;
    request.timeout = Duration::from_secs(60);
    let result = api::exec(&mut lab, &alice, &request).expect("exec");
    assert_eq!(result.outcome.backend, backend);
    assert!(result.outcome.error.is_none(), "{:?}", result.outcome);
    assert_eq!(
        result.outcome.exit_status,
        Some(0),
        "stderr: {}",
        result.stderr
    );
    assert!(result.stdout.contains("readonly"), "{}", result.stdout);
    assert!(result.stdout.contains("done"));

    let state = State::of(&lab);
    assert_eq!(
        api::read_file(&lab, &state, "runs/RUN-test-1/result.txt").expect("output"),
        b"got n=42\n"
    );
    let run = state.runs.last().expect("a run receipt");
    assert_eq!(run.id, result.op.id, "outputs and receipt are one op");
    assert_eq!(
        run.receipt.get("backend").and_then(|v| v.as_str()),
        Some(backend)
    );

    // The program's own status is the program's own status.
    let mut failing = ExecRequest::new("tiny", sh("exit 3"));
    failing.sandbox = preference;
    let result = api::exec(&mut lab, &alice, &failing).expect("exec");
    assert_eq!(result.outcome.exit_status, Some(3), "{:?}", result.outcome);
    assert!(result.outcome.error.is_none());

    // A program the environment does not have is not an exit status.
    let mut missing = ExecRequest::new("tiny", vec!["/no/such/program".into()]);
    missing.sandbox = preference;
    let result = api::exec(&mut lab, &alice, &missing).expect("exec");
    assert!(result.outcome.error.is_some(), "{:?}", result.outcome);
    assert_eq!(result.outcome.exit_status, None);

    // A timeout is a timeout, not an exit status.
    let mut slow = ExecRequest::new("tiny", sh("while :; do :; done"));
    slow.sandbox = preference;
    slow.timeout = Duration::from_secs(2);
    let result = api::exec(&mut lab, &alice, &slow).expect("exec");
    assert!(result.outcome.timed_out, "{:?}", result.outcome);
    assert!(!result.outcome.succeeded());
}
