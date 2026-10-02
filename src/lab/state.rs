//! What a space says: the deterministic fold from a set of ops to every view.
//!
//! Every function here reads the replica and nothing else — no clock except
//! the reader's `now` where a lease is evaluated, no file order, no local
//! settings. Two replicas holding the same ops therefore compute the same
//! [`State`], which is the whole convergence argument; `tests/lab.rs` checks it
//! against shuffled and partitioned deliveries rather than trusting it.
//!
//! # Order
//!
//! Every fold walks ops in `(lamport, id)` order ([`super::store::order_key`]).
//! Because the store is causally closed and every op's Lamport number exceeds
//! its dependencies', that order is a linear extension of causality — a cause
//! is always folded before its effect — and it is the same on every replica.
//!
//! # Exclusion: an op can be valid when it arrives and excluded later
//!
//! [`super::store::Lab::ingest`] admits an op whose author held the needed role
//! in its causal past. That is final for the op's *past*, but not for the
//! space: a revocation the author never saw makes everything they wrote
//! *concurrently* with it suspect, because otherwise a revoked key could keep
//! writing for ever by choosing `deps` that leave the revocation out. So here,
//! with the whole set in view:
//!
//! 1. A revocation is applied in `(lamport, id)` order, and is void if its own
//!    author was already revoked by an applied revocation it is concurrent
//!    with. Two admins revoking each other at once: the first in order wins.
//! 2. An op by a revoked key that is **concurrent** with the revocation —
//!    neither before it nor after it — is excluded. Before it: written while
//!    entitled. After it: its causal past contains the revocation, so ingest
//!    already required a re-admission.
//! 3. Membership ops excluded by (2) stop counting toward anybody's roster, so
//!    a revoked admin's concurrent admits are undone, and anything those
//!    members wrote is re-checked against the shrunken roster. Repeated to a
//!    fixpoint; membership ops are few.
//!
//! The price, stated in `docs/lab.md` too: views are not monotone. An op a
//! reader saw can vanish when a revocation reaches them, and until it does
//! they cannot know.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::op::{Body, EntryRef, Outcome, PathMode, Policy, Role};
use super::store::{order_key, Bits, Lab, Roster};
use crate::canonical::Value;

/// When and by whom an entry was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub entry: EntryRef,
    pub author: String,
    pub lamport: u64,
    pub time: String,
}

impl Version {
    fn order(&self) -> (u64, &str, u32) {
        (self.lamport, self.entry.op.as_str(), self.entry.index)
    }
}

/// One current value of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileValue {
    pub version: Version,
    /// `None` is a deletion.
    pub blob: Option<String>,
    pub size: u64,
    pub exec: bool,
}

/// One current value of a doc field. `Value::Null` is a deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldValue {
    pub version: Version,
    pub value: Value,
}

/// One current binding of an environment name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvValue {
    pub version: Version,
    pub tree: String,
    pub manifest: String,
}

/// A lease as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRecord {
    pub id: String,
    pub author: String,
    pub lamport: u64,
    pub time: String,
    pub task: String,
    pub holder: String,
    pub ttl: u64,
    pub note: Option<String>,
    /// `time + ttl`, in Unix seconds. `None` when `time` does not parse, which
    /// the op parser already refuses; kept optional rather than unwrapped.
    pub expires_at: Option<i64>,
}

/// How a lease was ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRecord {
    pub id: String,
    pub author: String,
    pub time: String,
    pub outcome: Outcome,
    pub note: Option<String>,
}

/// A message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRecord {
    pub id: String,
    pub author: String,
    pub lamport: u64,
    pub time: String,
    pub to: Vec<String>,
    pub from: Option<String>,
    pub subject: String,
    pub body: String,
    pub refs: Vec<String>,
}

/// A run receipt and the files it published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub id: String,
    pub author: String,
    pub lamport: u64,
    pub time: String,
    pub receipt: Value,
    pub files: Vec<(String, Option<String>, u64)>,
}

/// An op or entry the views ignore, and why. Reported, never silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excluded {
    pub op: String,
    pub entry: Option<u32>,
    pub reason: String,
}

/// Two or more current values where one was expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conflict {
    File {
        path: String,
        values: Vec<FileValue>,
        write_once: bool,
    },
    Field {
        doc: String,
        key: String,
        values: Vec<FieldValue>,
    },
    Env {
        name: String,
        values: Vec<EnvValue>,
    },
}

/// What one task's leases add up to at a reader's `now`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaskView {
    /// The live lease that holds the task: the first live one in
    /// `(lamport, id)` order.
    pub holder: Option<ClaimRecord>,
    /// Live leases that lost to `holder`.
    pub contended: Vec<ClaimRecord>,
    pub expired: Vec<ClaimRecord>,
    pub released: Vec<(ClaimRecord, ReleaseRecord)>,
    /// Some lease on this task was released `completed`.
    pub completed: bool,
}

/// Every view of a space, folded once.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct State {
    pub space: String,
    pub name: String,
    pub policy: Policy,
    /// Membership after every revocation, as the whole set says.
    pub roster: Roster,
    pub files: BTreeMap<String, Vec<FileValue>>,
    pub docs: BTreeMap<String, BTreeMap<String, Vec<FieldValue>>>,
    pub envs: BTreeMap<String, Vec<EnvValue>>,
    pub claims: Vec<ClaimRecord>,
    pub releases: BTreeMap<String, ReleaseRecord>,
    pub messages: Vec<MessageRecord>,
    pub acks: BTreeMap<String, BTreeSet<String>>,
    pub runs: Vec<RunRecord>,
    pub excluded: Vec<Excluded>,
    pub op_count: usize,
}

impl State {
    /// Fold a replica.
    pub fn of(lab: &Lab) -> State {
        let ops = lab.ops();
        let mut order: Vec<usize> = (0..ops.len()).collect();
        order.sort_by(|&a, &b| order_key(&ops[a]).cmp(&order_key(&ops[b])));

        let valid = validity(lab, &order);

        let mut state = State {
            space: lab.space().to_string(),
            op_count: ops.len(),
            ..State::default()
        };

        // Policy and name: genesis, then the last valid policy op in order.
        for &i in &order {
            if !valid.ok[i] {
                continue;
            }
            match &ops[i].body {
                Body::Genesis { name, policy, .. } => {
                    state.name = name.clone();
                    state.policy = policy.clone();
                }
                Body::Policy(policy) => state.policy = policy.clone(),
                _ => {}
            }
        }
        state.roster = valid.roster.clone();
        for (i, reason) in &valid.reasons {
            state.excluded.push(Excluded {
                op: ops[*i].id.clone(),
                entry: None,
                reason: reason.clone(),
            });
        }

        let mut file_entries: BTreeMap<String, Vec<FileValue>> = BTreeMap::new();
        let mut file_preds: HashMap<String, BTreeSet<EntryRef>> = HashMap::new();
        let mut fields: BTreeMap<(String, String), Vec<FieldValue>> = BTreeMap::new();
        let mut field_preds: HashMap<(String, String), BTreeSet<EntryRef>> = HashMap::new();
        let mut envs: BTreeMap<String, Vec<EnvValue>> = BTreeMap::new();
        let mut env_preds: HashMap<String, BTreeSet<EntryRef>> = HashMap::new();
        let mut claim_authors: HashMap<String, String> = HashMap::new();

        for &i in &order {
            if !valid.ok[i] {
                continue;
            }
            let op = &ops[i];
            let version = |index: u32| Version {
                entry: EntryRef {
                    op: op.id.clone(),
                    index,
                },
                author: op.author.clone(),
                lamport: op.lamport,
                time: op.time.clone(),
            };
            for (n, entry) in op.body.file_entries().iter().enumerate() {
                let index = n as u32;
                let mode = state.policy.mode(&entry.path);
                let refusal = match mode {
                    PathMode::Ignored => Some("path is ignored by the space's policy"),
                    PathMode::WriteOnce if entry.blob.is_none() => {
                        Some("a write-once path cannot be deleted")
                    }
                    PathMode::WriteOnce if !entry.pred.is_empty() => {
                        Some("a write-once path cannot be replaced; add a correction instead")
                    }
                    _ => None,
                };
                if let Some(reason) = refusal {
                    state.excluded.push(Excluded {
                        op: op.id.clone(),
                        entry: Some(index),
                        reason: format!("{}: {reason}", entry.path),
                    });
                    continue;
                }
                file_preds
                    .entry(entry.path.clone())
                    .or_default()
                    .extend(entry.pred.iter().cloned());
                file_entries
                    .entry(entry.path.clone())
                    .or_default()
                    .push(FileValue {
                        version: version(index),
                        blob: entry.blob.clone(),
                        size: entry.size,
                        exec: entry.exec,
                    });
            }
            match &op.body {
                Body::Doc {
                    doc,
                    fields: written,
                } => {
                    for (n, field) in written.iter().enumerate() {
                        let key = (doc.clone(), field.key.clone());
                        field_preds
                            .entry(key.clone())
                            .or_default()
                            .extend(field.pred.iter().cloned());
                        fields.entry(key).or_default().push(FieldValue {
                            version: version(n as u32),
                            value: field.value.clone(),
                        });
                    }
                }
                Body::Env {
                    name,
                    tree,
                    manifest,
                    pred,
                } => {
                    env_preds
                        .entry(name.clone())
                        .or_default()
                        .extend(pred.iter().cloned());
                    envs.entry(name.clone()).or_default().push(EnvValue {
                        version: version(0),
                        tree: tree.clone(),
                        manifest: manifest.clone(),
                    });
                }
                Body::Claim {
                    task,
                    holder,
                    ttl,
                    note,
                } => {
                    claim_authors.insert(op.id.clone(), op.author.clone());
                    state.claims.push(ClaimRecord {
                        id: op.id.clone(),
                        author: op.author.clone(),
                        lamport: op.lamport,
                        time: op.time.clone(),
                        task: task.clone(),
                        holder: holder.clone(),
                        ttl: *ttl,
                        note: note.clone(),
                        expires_at: op
                            .unix_time()
                            .and_then(|t| t.checked_add(i64::try_from(*ttl).ok()?)),
                    });
                }
                Body::Release {
                    claim,
                    outcome,
                    note,
                } => {
                    // Only the lease's author or an admin ends it, and only the
                    // first release in order counts: a lease ends once.
                    let entitled = claim_authors
                        .get(claim)
                        .is_some_and(|author| *author == op.author)
                        || valid.roster_at[i].has(&op.author, Role::Admin);
                    if !entitled {
                        state.excluded.push(Excluded {
                            op: op.id.clone(),
                            entry: None,
                            reason: format!(
                                "release of {} by someone who neither holds it nor administers the space",
                                crate::canonical::short(claim)
                            ),
                        });
                    } else if !state.releases.contains_key(claim) {
                        state.releases.insert(
                            claim.clone(),
                            ReleaseRecord {
                                id: op.id.clone(),
                                author: op.author.clone(),
                                time: op.time.clone(),
                                outcome: *outcome,
                                note: note.clone(),
                            },
                        );
                    }
                }
                Body::Msg {
                    to,
                    from,
                    subject,
                    body,
                    refs,
                } => state.messages.push(MessageRecord {
                    id: op.id.clone(),
                    author: op.author.clone(),
                    lamport: op.lamport,
                    time: op.time.clone(),
                    to: to.clone(),
                    from: from.clone(),
                    subject: subject.clone(),
                    body: body.clone(),
                    refs: refs.clone(),
                }),
                Body::Ack { msg, address } => {
                    state
                        .acks
                        .entry(msg.clone())
                        .or_default()
                        .insert(address.clone());
                }
                Body::Run { receipt, files } => state.runs.push(RunRecord {
                    id: op.id.clone(),
                    author: op.author.clone(),
                    lamport: op.lamport,
                    time: op.time.clone(),
                    receipt: receipt.clone(),
                    files: files
                        .iter()
                        .map(|f| (f.path.clone(), f.blob.clone(), f.size))
                        .collect(),
                }),
                _ => {}
            }
        }

        state.files = current(file_entries, &file_preds, |a, b| {
            // Content over a deletion, then the newest: a display rule for the
            // checkout, not a resolution — the conflict stays listed.
            b.blob
                .is_some()
                .cmp(&a.blob.is_some())
                .then_with(|| b.version.order().cmp(&a.version.order()))
        });
        let fields = current(fields, &field_preds, |a, b| {
            (!b.value.is_null())
                .cmp(&!a.value.is_null())
                .then_with(|| b.version.order().cmp(&a.version.order()))
        });
        for ((doc, key), values) in fields {
            state.docs.entry(doc).or_default().insert(key, values);
        }
        state.envs = current(envs, &env_preds, |a, b| {
            b.version.order().cmp(&a.version.order())
        });
        state
    }

    /// The value a checkout writes for `path`, if the path exists and is not
    /// deleted.
    pub fn winner(&self, path: &str) -> Option<&FileValue> {
        self.files
            .get(path)
            .and_then(|values| values.first())
            .filter(|value| value.blob.is_some())
    }

    /// Every live path under `prefix` (all of them for `""`), with its winner.
    pub fn list(&self, prefix: &str) -> Vec<(&str, &FileValue)> {
        self.files
            .iter()
            .filter(|(path, _)| prefix.is_empty() || under(path, prefix))
            .filter_map(|(path, values)| {
                values
                    .first()
                    .filter(|value| value.blob.is_some())
                    .map(|value| (path.as_str(), value))
            })
            .collect()
    }

    /// Every register holding more than one distinct value.
    pub fn conflicts(&self) -> Vec<Conflict> {
        let mut out = Vec::new();
        for (path, values) in &self.files {
            let distinct: BTreeSet<&Option<String>> = values.iter().map(|v| &v.blob).collect();
            if distinct.len() > 1 {
                out.push(Conflict::File {
                    path: path.clone(),
                    values: values.clone(),
                    write_once: self.policy.mode(path) == PathMode::WriteOnce,
                });
            }
        }
        for (doc, keys) in &self.docs {
            for (key, values) in keys {
                let distinct: BTreeSet<&Value> = values.iter().map(|v| &v.value).collect();
                if distinct.len() > 1 {
                    out.push(Conflict::Field {
                        doc: doc.clone(),
                        key: key.clone(),
                        values: values.clone(),
                    });
                }
            }
        }
        for (name, values) in &self.envs {
            let distinct: BTreeSet<&String> = values.iter().map(|v| &v.tree).collect();
            if distinct.len() > 1 {
                out.push(Conflict::Env {
                    name: name.clone(),
                    values: values.clone(),
                });
            }
        }
        out
    }

    /// Every task's leases, evaluated at `now` (Unix seconds).
    pub fn tasks(&self, now: i64) -> BTreeMap<String, TaskView> {
        let mut views: BTreeMap<String, TaskView> = BTreeMap::new();
        // `claims` is already in (lamport, id) order, so the first live lease
        // met is the one that holds the task.
        for claim in &self.claims {
            let view = views.entry(claim.task.clone()).or_default();
            if let Some(release) = self.releases.get(&claim.id) {
                if release.outcome == Outcome::Completed {
                    view.completed = true;
                }
                view.released.push((claim.clone(), release.clone()));
            } else if claim.expires_at.is_none_or(|end| end <= now) {
                view.expired.push(claim.clone());
            } else if view.holder.is_none() {
                view.holder = Some(claim.clone());
            } else {
                view.contended.push(claim.clone());
            }
        }
        views
    }

    /// Messages to `address` (or to `all`) that `address` has not acked.
    pub fn inbox(&self, address: &str) -> Vec<&MessageRecord> {
        self.messages
            .iter()
            .filter(|m| m.to.iter().any(|to| to == address || to == "all"))
            .filter(|m| !self.acks.get(&m.id).is_some_and(|by| by.contains(address)))
            .collect()
    }

    /// The doc fields with exactly one current value, as a plain object;
    /// conflicted fields are left out and listed by [`State::conflicts`].
    pub fn doc(&self, doc: &str) -> Option<Value> {
        let keys = self.docs.get(doc)?;
        let mut map = BTreeMap::new();
        for (key, values) in keys {
            if let Some(first) = values.first() {
                if !first.value.is_null() {
                    map.insert(key.clone(), first.value.clone());
                }
            }
        }
        Some(Value::Object(map))
    }
}

/// Whether `path` is `prefix` or lies under it as a directory.
pub fn under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// A multi-value register's current values: every entry no other entry for
/// the same key names in its `pred`, sorted winner first.
fn current<K: Ord + std::hash::Hash, T>(
    entries: BTreeMap<K, Vec<T>>,
    preds: &HashMap<K, BTreeSet<EntryRef>>,
    winner_first: impl Fn(&T, &T) -> std::cmp::Ordering,
) -> BTreeMap<K, Vec<T>>
where
    T: HasVersion,
{
    let mut out = BTreeMap::new();
    for (key, values) in entries {
        let replaced = preds.get(&key);
        let mut live: Vec<T> = values
            .into_iter()
            .filter(|value| !replaced.is_some_and(|set| set.contains(&value.version().entry)))
            .collect();
        live.sort_by(&winner_first);
        if !live.is_empty() {
            out.insert(key, live);
        }
    }
    out
}

trait HasVersion {
    fn version(&self) -> &Version;
}

impl HasVersion for FileValue {
    fn version(&self) -> &Version {
        &self.version
    }
}

impl HasVersion for FieldValue {
    fn version(&self) -> &Version {
        &self.version
    }
}

impl HasVersion for EnvValue {
    fn version(&self) -> &Version {
        &self.version
    }
}

// -- validity -------------------------------------------------------------------

struct Validity {
    /// Per op index: whether every view may read it.
    ok: Vec<bool>,
    /// Why each excluded op is excluded.
    reasons: Vec<(usize, String)>,
    /// Per op index: the roster its effective causal past establishes.
    roster_at: Vec<Roster>,
    /// The roster the whole set establishes.
    roster: Roster,
}

/// Decide which ops every view may read; see the module docs for the rules.
fn validity(lab: &Lab, order: &[usize]) -> Validity {
    let ops = lab.ops();
    let membership = lab.membership_indices();

    // Revocation ops in fold order, with the ancestors of each — the only
    // expensive part, and there are few revocations.
    let revocations: Vec<usize> = order
        .iter()
        .copied()
        .filter(|&i| matches!(&ops[i].body, Body::Members { revoke, .. } if !revoke.is_empty()))
        .collect();
    let ancestors: HashMap<usize, Vec<bool>> = revocations
        .iter()
        .map(|&r| (r, lab.ancestors_of(r)))
        .collect();

    // `x` and the revocation `r` are concurrent: neither is in the other's past.
    let concurrent = |x: usize, r: usize| -> bool {
        let r_before_x = lab
            .ordinal_of(r)
            .is_some_and(|ordinal| lab.past_bits(x).contains(ordinal));
        let x_before_r = ancestors.get(&r).is_some_and(|anc| anc[x]);
        x != r && !r_before_x && !x_before_r
    };

    let mut cache: HashMap<Bits, Roster> = HashMap::new();
    let roster_for = |bits: &Bits, cache: &mut HashMap<Bits, Roster>| -> Roster {
        if let Some(roster) = cache.get(bits) {
            return roster.clone();
        }
        let mut chosen: Vec<usize> = bits.ones().map(|ordinal| membership[ordinal]).collect();
        chosen.sort_by(|&a, &b| order_key(&ops[a]).cmp(&order_key(&ops[b])));
        let mut roster = Roster::default();
        for index in chosen {
            roster.apply(&ops[index].body);
        }
        cache.insert(bits.clone(), roster.clone());
        roster
    };

    // Each membership op is decided once, in fold order, from decisions about
    // earlier ones only — its causal past is all earlier, so everything it
    // depends on is already decided. Then any op that a *later* valid
    // revocation is concurrent with is forced out, and the pass repeats.
    //
    // Forcing only ever grows, so this terminates with one answer: a
    // revocation concurrent with M cannot owe its authority to M (M is not in
    // its past), and cannot have been voided by M (that needs M to revoke the
    // revocation's author, and then it would not be valid to force anything).
    let mut by_order: Vec<usize> = (0..membership.len()).collect();
    by_order.sort_by(|&a, &b| order_key(&ops[membership[a]]).cmp(&order_key(&ops[membership[b]])));
    let mut forced = Bits::default();
    let (excluded_membership, applied) = loop {
        let mut excluded = forced.clone();
        let mut applied: Vec<(usize, BTreeSet<String>)> = Vec::new();
        for &ordinal in &by_order {
            let m = membership[ordinal];
            if forced.contains(ordinal) || ops[m].is_genesis() {
                continue;
            }
            let effective = lab.past_bits(m).without(&excluded);
            let roster = roster_for(&effective, &mut cache);
            let author = &ops[m].author;
            let void = applied
                .iter()
                .any(|(r, keys)| keys.contains(author) && concurrent(m, *r));
            if !roster.has(author, Role::Admin) || void {
                excluded.set(ordinal);
                continue;
            }
            if let Body::Members { revoke, .. } = &ops[m].body {
                if !revoke.is_empty() {
                    applied.push((m, revoke.iter().cloned().collect()));
                }
            }
        }
        let mut grew = false;
        for &ordinal in &by_order {
            let m = membership[ordinal];
            if excluded.contains(ordinal) || ops[m].is_genesis() {
                continue;
            }
            let author = &ops[m].author;
            if applied
                .iter()
                .any(|(r, keys)| keys.contains(author) && concurrent(m, *r))
            {
                forced.set(ordinal);
                grew = true;
            }
        }
        if !grew {
            break (excluded, applied);
        }
    };

    let mut ok = vec![false; ops.len()];
    let mut reasons = Vec::new();
    let mut roster_at = vec![Roster::default(); ops.len()];
    for &i in order {
        let op = &ops[i];
        if op.is_genesis() {
            ok[i] = true;
            continue;
        }
        let effective = lab.past_bits(i).without(&excluded_membership);
        let roster = roster_for(&effective, &mut cache);
        let revoked_sideways = applied
            .iter()
            .find(|(r, keys)| keys.contains(&op.author) && concurrent(i, *r));
        let membership_excluded = lab
            .ordinal_of(i)
            .is_some_and(|ordinal| excluded_membership.contains(ordinal));
        let authorised = match op.body.required_role() {
            Some(role) => roster.has(&op.author, role),
            None => roster.is_member(&op.author),
        };
        if let Some((r, _)) = revoked_sideways {
            reasons.push((
                i,
                format!(
                    "author was revoked by {} and this op is concurrent with that revocation",
                    crate::canonical::short(&ops[*r].id)
                ),
            ));
        } else if membership_excluded {
            reasons.push((
                i,
                "membership change by an author who lost authority".into(),
            ));
        } else if !authorised {
            reasons.push((
                i,
                "author's authority came from a membership change that was undone".into(),
            ));
        } else {
            ok[i] = true;
        }
        roster_at[i] = roster;
    }

    let mut all = Bits::default();
    for ordinal in 0..membership.len() {
        all.set(ordinal);
    }
    let final_bits = all.without(&excluded_membership);
    let roster = roster_for(&final_bits, &mut cache);

    Validity {
        ok,
        reasons,
        roster_at,
        roster,
    }
}
