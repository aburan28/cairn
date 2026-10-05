//! The leader's registry of members: invites, joins, revocations, the journal.
//!
//! On disk beside the log, as `deposits/` is, one file per fact so the CLI and
//! the node never rewrite each other's files:
//!
//! ```text
//! <log dir>/fleet/
//!   invites/<invite key>.json        `cairn fleet invite`: the public key and terms
//!   invites/<invite key>.used/<key>  the node, one empty file per use, created exclusively
//!   members/<member key>.json        the node at join, or `cairn fleet admit`
//!   revoked/<member key>.json        `cairn fleet revoke`: sticky, by key
//!   journal.jsonl                    the node: which member had which record signed
//! ```
//!
//! Nothing here is secret. An invite's seed exists only in its token; a
//! member's secret only on its own box. The node rereads `members/` and
//! `revoked/` when either directory changes, so a revocation from the CLI
//! takes effect on the member's next request.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::canonical::Value;

use super::auth::{self, key_hex, parse_key, JoinRequest, Key, MemberAuth, Refusal, Token};

/// The registry's directory under a log's own.
pub fn dir_for_log(log: &Path) -> PathBuf {
    log.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("fleet")
}

/// What an invitation admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub key: Key,
    pub created_at: u64,
    pub expires_at: u64,
    pub uses: u32,
    /// Exactly this name, once.
    pub name: Option<String>,
    /// Each member is named `prefix-<first 12 hex of its key>`.
    pub prefix: Option<String>,
    /// A membership made with this invite ends this long after it was made.
    pub member_ttl: Option<u64>,
    pub note: Option<String>,
}

/// The terms `cairn fleet invite` asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Terms {
    pub uses: u32,
    pub expires_in: u64,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub member_ttl: Option<u64>,
    pub note: Option<String>,
}

/// One enrolled machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub key: Key,
    pub name: String,
    /// The invite it joined with; `None` for `cairn fleet admit`.
    pub invite: Option<Key>,
    pub joined_at: u64,
    pub expires_at: Option<u64>,
}

impl Member {
    pub fn expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|at| now >= at)
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("member", Value::string(key_hex(&self.key))),
            ("name", Value::string(self.name.clone())),
            (
                "invite",
                self.invite
                    .map(|k| Value::string(key_hex(&k)))
                    .unwrap_or(Value::Null),
            ),
            ("joined_at", Value::string(iso(self.joined_at))),
            (
                "expires_at",
                self.expires_at
                    .map(|at| Value::string(iso(at)))
                    .unwrap_or(Value::Null),
            ),
        ])
    }

    fn from_value(value: &Value) -> Option<Member> {
        Some(Member {
            key: parse_key(value.get("member")?.as_str()?)?,
            name: value.get("name")?.as_str()?.to_string(),
            invite: value
                .get("invite")
                .and_then(Value::as_str)
                .and_then(parse_key),
            joined_at: unix(value.get("joined_at")?.as_str()?)?,
            expires_at: value
                .get("expires_at")
                .and_then(Value::as_str)
                .and_then(unix),
        })
    }
}

/// A revocation, kept forever: a revoked key never comes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub key: Key,
    pub revoked_at: u64,
    pub reason: String,
}

impl Invite {
    fn to_value(&self) -> Value {
        let opt = |v: &Option<String>| v.clone().map(Value::string).unwrap_or(Value::Null);
        Value::object([
            ("invite", Value::string(key_hex(&self.key))),
            ("created_at", Value::string(iso(self.created_at))),
            ("expires_at", Value::string(iso(self.expires_at))),
            ("uses", Value::Int(i128::from(self.uses))),
            ("name", opt(&self.name)),
            ("prefix", opt(&self.prefix)),
            (
                "member_ttl_seconds",
                self.member_ttl
                    .map(|t| Value::Int(i128::from(t)))
                    .unwrap_or(Value::Null),
            ),
            ("note", opt(&self.note)),
        ])
    }

    fn from_value(value: &Value) -> Option<Invite> {
        let text = |field: &str| value.get(field).and_then(Value::as_str).map(String::from);
        Some(Invite {
            key: parse_key(value.get("invite")?.as_str()?)?,
            created_at: unix(value.get("created_at")?.as_str()?)?,
            expires_at: unix(value.get("expires_at")?.as_str()?)?,
            uses: u32::try_from(value.get("uses")?.as_u64()?).ok()?,
            name: text("name"),
            prefix: text("prefix"),
            member_ttl: value.get("member_ttl_seconds").and_then(Value::as_u64),
            note: text("note"),
        })
    }
}

fn iso(unix: u64) -> String {
    crate::time::format_iso8601_utc(i64::try_from(unix).unwrap_or(i64::MAX))
}

fn unix(text: &str) -> Option<u64> {
    u64::try_from(crate::time::parse_rfc3339(text)?).ok()
}

/// What the node holds in memory, refreshed when the directories change.
#[derive(Default)]
struct Cache {
    stamp: Option<(Option<SystemTime>, Option<SystemTime>)>,
    scanned_at: u64,
    members: BTreeMap<Key, Member>,
    revoked: BTreeMap<Key, Revocation>,
    /// When each member last made a request that verified. Memory only.
    seen: BTreeMap<Key, u64>,
}

/// The registry of one leader.
pub struct Registry {
    dir: PathBuf,
    leader: Key,
    cache: Mutex<Cache>,
    /// Joins are decided one at a time, so two cannot take the same name or
    /// the last use of an invite.
    joining: Mutex<()>,
}

/// Rescan at least this often even when no directory time moved, for file
/// systems whose timestamps are too coarse to see two changes in a second.
const RESCAN_SECONDS: u64 = 5;

impl Registry {
    pub fn new(dir: impl Into<PathBuf>, leader: Key) -> Registry {
        Registry {
            dir: dir.into(),
            leader,
            cache: Mutex::new(Cache::default()),
            joining: Mutex::new(()),
        }
    }

    pub fn for_log(log: &Path, leader: Key) -> Registry {
        Registry::new(dir_for_log(log), leader)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn leader(&self) -> Key {
        self.leader
    }

    fn sub(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn ensure(&self, name: &str) -> io::Result<PathBuf> {
        let path = self.sub(name);
        fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        }
        Ok(path)
    }

    // -- reading ------------------------------------------------------------------------

    fn stamp(&self) -> (Option<SystemTime>, Option<SystemTime>) {
        let modified = |name| fs::metadata(self.sub(name)).and_then(|m| m.modified()).ok();
        (modified("members"), modified("revoked"))
    }

    /// Run `f` over a cache no older than the directories.
    fn with_cache<T>(&self, now: u64, f: impl FnOnce(&mut Cache) -> T) -> T {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stamp = self.stamp();
        if cache.stamp != Some(stamp) || now.saturating_sub(cache.scanned_at) >= RESCAN_SECONDS {
            cache.members = read_dir_json(&self.sub("members"))
                .filter_map(|v| Member::from_value(&v))
                .map(|m| (m.key, m))
                .collect();
            cache.revoked = read_dir_json(&self.sub("revoked"))
                .filter_map(|v| {
                    Some(Revocation {
                        key: parse_key(v.get("member")?.as_str()?)?,
                        revoked_at: unix(v.get("revoked_at")?.as_str()?)?,
                        reason: v
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    })
                })
                .map(|r| (r.key, r))
                .collect();
            cache.stamp = Some(stamp);
            cache.scanned_at = now;
        }
        f(&mut cache)
    }

    /// The member a verified request came from, or why it is not one.
    pub fn verify_request(
        &self,
        auth: &MemberAuth,
        method: &str,
        target: &str,
        body: &[u8],
        now: u64,
    ) -> Result<Member, Refusal> {
        let member = self.with_cache(now, |cache| {
            if let Some(revocation) = cache.revoked.get(&auth.member) {
                return Err(Refusal::new(
                    401,
                    "member_revoked",
                    format!(
                        "this member key was revoked at {}{}; it cannot be used again",
                        iso(revocation.revoked_at),
                        if revocation.reason.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", revocation.reason)
                        }
                    ),
                ));
            }
            match cache.members.get(&auth.member) {
                None => Err(Refusal::new(
                    401,
                    "member_unknown",
                    "this key is not enrolled here; join with an invite from this leader \
                     (`cairn fleet join`)",
                )),
                Some(member) if member.expired(now) => Err(Refusal::new(
                    401,
                    "member_expired",
                    format!(
                        "this membership ended at {}; join again with a new invite",
                        iso(member.expires_at.unwrap_or(now))
                    ),
                )),
                Some(member) => Ok(member.clone()),
            }
        })?;
        auth::fresh(auth.time, now, auth::REQUEST_WINDOW_SECONDS)?;
        auth.verify(&self.leader, method, target, body)?;
        self.with_cache(now, |cache| {
            cache.seen.insert(member.key, now);
        });
        Ok(member)
    }

    /// The live member whose namespace holds `name`, if one does: a name a
    /// request must be signed by that member to use.
    pub fn reserved_by(&self, name: &str, now: u64) -> Option<Member> {
        self.with_cache(now, |cache| {
            cache
                .members
                .values()
                .find(|m| {
                    !cache.revoked.contains_key(&m.key)
                        && !m.expired(now)
                        && auth::covers(&m.name, name)
                })
                .cloned()
        })
    }

    /// Members enrolled and in good standing, and how many of them made a
    /// verified request within `live_within` seconds.
    pub fn counts(&self, now: u64, live_within: u64) -> (usize, usize) {
        self.with_cache(now, |cache| {
            let standing: Vec<&Member> = cache
                .members
                .values()
                .filter(|m| !cache.revoked.contains_key(&m.key) && !m.expired(now))
                .collect();
            let live = standing
                .iter()
                .filter(|m| {
                    cache
                        .seen
                        .get(&m.key)
                        .is_some_and(|at| now.saturating_sub(*at) <= live_within)
                })
                .count();
            (standing.len(), live)
        })
    }

    pub fn invite(&self, key: &Key) -> Option<Invite> {
        let text =
            fs::read_to_string(self.sub("invites").join(format!("{}.json", key_hex(key)))).ok()?;
        Invite::from_value(&Value::from_json(&text).ok()?)
    }

    fn uses_of(&self, key: &Key) -> Vec<Key> {
        let dir = self.sub("invites").join(format!("{}.used", key_hex(key)));
        fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|entry| parse_key(entry.ok()?.file_name().to_str()?))
            .collect()
    }

    // -- joining ------------------------------------------------------------------------

    /// Admit a member with a join request. Idempotent for a key already
    /// admitted under the same invite: the membership it has is returned.
    pub fn join(&self, request: &JoinRequest, now: u64) -> Result<Member, Refusal> {
        let _one_at_a_time = self
            .joining
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let invite = self.invite(&request.invite).ok_or_else(|| {
            Refusal::new(
                403,
                "invite_unknown",
                "no invite with this key is outstanding here: a mistyped token, a token for \
                 another leader, or an invite that was revoked",
            )
        })?;
        request.verify(&self.leader)?;
        auth::fresh(request.time, now, auth::JOIN_WINDOW_SECONDS)?;
        if request.member == self.leader {
            return Err(Refusal::new(
                403,
                "member_is_leader",
                "a member key cannot be the leader's own key",
            ));
        }
        // Standing and history first: a revoked key never returns, and a key
        // already admitted is answered with what it has.
        let (existing, revoked, taken) = self.with_cache(now, |cache| {
            (
                cache.members.get(&request.member).cloned(),
                cache.revoked.get(&request.member).cloned(),
                // Names held by members in good standing. An expired or
                // revoked membership frees its name; a key rejoining after
                // its own membership lapsed may take its old name back.
                cache
                    .members
                    .values()
                    .filter(|m| {
                        m.key != request.member
                            && !cache.revoked.contains_key(&m.key)
                            && !m.expired(now)
                    })
                    .map(|m| m.name.clone())
                    .collect::<Vec<_>>(),
            )
        });
        if let Some(revocation) = revoked {
            return Err(Refusal::new(
                403,
                "member_revoked",
                format!(
                    "this member key was revoked at {}; make a new key and join again",
                    iso(revocation.revoked_at)
                ),
            ));
        }
        if let Some(member) = existing {
            if member.invite == Some(request.invite) {
                // A replayed join is the same membership, in force or over:
                // replaying it cannot renew one whose time ran out, or a
                // rental's membership would last as long as its invite.
                if member.expired(now) {
                    return Err(Refusal::new(
                        403,
                        "member_expired",
                        format!(
                            "this membership ended at {}; joining again with the same invite \
                             cannot renew it. Ask for a new invite",
                            iso(member.expires_at.unwrap_or(now))
                        ),
                    ));
                }
                return Ok(member);
            }
            if !member.expired(now) {
                return Err(Refusal::new(
                    409,
                    "member_exists",
                    format!("this key is already a member, as {:?}", member.name),
                ));
            }
        }
        if now >= invite.expires_at {
            return Err(Refusal::new(
                403,
                "invite_expired",
                format!(
                    "this invite ended at {}; ask for a new one",
                    iso(invite.expires_at)
                ),
            ));
        }
        let used = self.uses_of(&request.invite);
        if !used.contains(&request.member) && used.len() >= invite.uses as usize {
            return Err(Refusal::new(
                403,
                "invite_spent",
                format!("this invite admitted all {} of its members", invite.uses),
            ));
        }
        let name = match (&invite.name, &invite.prefix) {
            (Some(name), _) => {
                if !request.name.is_empty() && request.name != *name {
                    return Err(Refusal::new(
                        403,
                        "name_not_invited",
                        format!("this invite is for {name:?}, not {:?}", request.name),
                    ));
                }
                name.clone()
            }
            (None, Some(prefix)) => format!("{prefix}-{}", &key_hex(&request.member)[..12]),
            (None, None) => {
                if request.name.is_empty() {
                    return Err(Refusal::new(
                        400,
                        "name_required",
                        "this invite names nobody, so the join must ask for a name",
                    ));
                }
                request.name.clone()
            }
        };
        if !auth::valid_name(&name) {
            return Err(Refusal::new(
                400,
                "bad_name",
                format!("{name:?} is not a member name"),
            ));
        }
        if taken.iter().any(|other| other == &name) {
            return Err(Refusal::new(
                409,
                "name_taken",
                format!("another member is already called {name:?}"),
            ));
        }
        let member = Member {
            key: request.member,
            name,
            invite: Some(request.invite),
            joined_at: now,
            expires_at: invite.member_ttl.map(|ttl| now.saturating_add(ttl)),
        };
        let internal = |e: io::Error| {
            Refusal::new(
                500,
                "internal",
                format!("cannot record the membership: {e}"),
            )
        };
        let used_dir = self
            .ensure(&format!("invites/{}.used", key_hex(&request.invite)))
            .map_err(internal)?;
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(used_dir.join(key_hex(&request.member)))
        {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(internal(e)),
        }
        self.write_member(&member).map_err(internal)?;
        Ok(member)
    }

    fn write_member(&self, member: &Member) -> io::Result<()> {
        let dir = self.ensure("members")?;
        write_atomically(
            &dir.join(format!("{}.json", key_hex(&member.key))),
            &member.to_value(),
        )?;
        self.invalidate();
        Ok(())
    }

    /// Forget the cache after a write of this registry's own, so the next
    /// read sees it even where directory times are too coarse to.
    fn invalidate(&self) {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stamp = None;
    }

    // -- the operator's side ------------------------------------------------------------

    /// Mint an invitation. The token is returned once and never stored.
    pub fn create_invite(&self, terms: &Terms, now: u64) -> io::Result<(Token, Invite)> {
        let token = Token::mint(self.leader);
        let invite = Invite {
            key: token.invite_key(),
            created_at: now,
            expires_at: now.saturating_add(terms.expires_in),
            uses: if terms.name.is_some() {
                1
            } else {
                terms.uses.max(1)
            },
            name: terms.name.clone(),
            prefix: terms.prefix.clone(),
            member_ttl: terms.member_ttl,
            note: terms.note.clone(),
        };
        let dir = self.ensure("invites")?;
        write_atomically(
            &dir.join(format!("{}.json", key_hex(&invite.key))),
            &invite.to_value(),
        )?;
        Ok((token, invite))
    }

    /// Every invite, with how many members it has admitted.
    pub fn invites(&self) -> Vec<(Invite, usize)> {
        let mut out: Vec<(Invite, usize)> = read_dir_json(&self.sub("invites"))
            .filter_map(|v| Invite::from_value(&v))
            .map(|invite| {
                let used = self.uses_of(&invite.key).len();
                (invite, used)
            })
            .collect();
        out.sort_by_key(|(invite, _)| invite.created_at);
        out
    }

    /// Withdraw an invite: nobody joins with it after this. Members it already
    /// admitted stay; `revoke_invited` removes those.
    pub fn revoke_invite(&self, key: &Key) -> io::Result<bool> {
        match fs::remove_file(self.sub("invites").join(format!("{}.json", key_hex(key)))) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Enroll a key by hand, with no invite and no token on any wire.
    pub fn admit(
        &self,
        key: Key,
        name: &str,
        ttl: Option<u64>,
        now: u64,
    ) -> Result<Member, Refusal> {
        if !auth::valid_name(name) {
            return Err(Refusal::new(
                400,
                "bad_name",
                format!("{name:?} is not a member name"),
            ));
        }
        if key == self.leader {
            return Err(Refusal::new(
                403,
                "member_is_leader",
                "a member key cannot be the leader's own key",
            ));
        }
        let (revoked, clash) = self.with_cache(now, |cache| {
            (
                cache.revoked.contains_key(&key),
                cache.members.values().any(|m| {
                    m.name == name
                        && m.key != key
                        && !cache.revoked.contains_key(&m.key)
                        && !m.expired(now)
                }),
            )
        });
        if revoked {
            return Err(Refusal::new(
                403,
                "member_revoked",
                "this key was revoked; a revoked key cannot be admitted again",
            ));
        }
        if clash {
            return Err(Refusal::new(
                409,
                "name_taken",
                format!("another member is already called {name:?}"),
            ));
        }
        let member = Member {
            key,
            name: name.to_string(),
            invite: None,
            joined_at: now,
            expires_at: ttl.map(|ttl| now.saturating_add(ttl)),
        };
        self.write_member(&member)
            .map_err(|e| Refusal::new(500, "internal", e.to_string()))?;
        Ok(member)
    }

    /// Every member ever enrolled, with its revocation if it has one.
    pub fn members(&self, now: u64) -> Vec<(Member, Option<Revocation>, Option<u64>)> {
        self.with_cache(now, |cache| {
            let mut out: Vec<_> = cache
                .members
                .values()
                .map(|m| {
                    (
                        m.clone(),
                        cache.revoked.get(&m.key).cloned(),
                        cache.seen.get(&m.key).copied(),
                    )
                })
                .collect();
            out.sort_by_key(|(m, _, _)| m.joined_at);
            out
        })
    }

    /// A member by name or by key. A name freed by a revocation or an expiry
    /// and taken again names the member holding it now.
    pub fn find(&self, name_or_key: &str, now: u64) -> Option<Member> {
        let key = parse_key(name_or_key);
        self.with_cache(now, |cache| {
            let mut matching: Vec<&Member> = cache
                .members
                .values()
                .filter(|m| Some(m.key) == key || m.name == name_or_key)
                .collect();
            matching.sort_by_key(|m| {
                (
                    !cache.revoked.contains_key(&m.key) && !m.expired(now),
                    m.joined_at,
                )
            });
            matching.last().map(|m| (*m).clone())
        })
    }

    /// Revoke a member key, forever.
    pub fn revoke(&self, key: &Key, reason: &str, now: u64) -> io::Result<Revocation> {
        let revocation = Revocation {
            key: *key,
            revoked_at: now,
            reason: reason.to_string(),
        };
        let dir = self.ensure("revoked")?;
        let path = dir.join(format!("{}.json", key_hex(key)));
        if let Ok(text) = fs::read_to_string(&path) {
            // Already revoked: the first revocation is the one that stands.
            if let Some(first) = Value::from_json(&text).ok().and_then(|v| {
                Some(Revocation {
                    key: *key,
                    revoked_at: unix(v.get("revoked_at")?.as_str()?)?,
                    reason: v.get("reason")?.as_str()?.to_string(),
                })
            }) {
                return Ok(first);
            }
        }
        write_atomically(
            &path,
            &Value::object([
                ("member", Value::string(key_hex(key))),
                ("revoked_at", Value::string(iso(now))),
                ("reason", Value::string(reason)),
            ]),
        )?;
        self.invalidate();
        Ok(revocation)
    }

    /// Revoke every member one invite admitted.
    pub fn revoke_invited(&self, invite: &Key, reason: &str, now: u64) -> io::Result<Vec<Member>> {
        let invited: Vec<Member> = self
            .members(now)
            .into_iter()
            .filter(|(m, revoked, _)| m.invite == Some(*invite) && revoked.is_none())
            .map(|(m, _, _)| m)
            .collect();
        for member in &invited {
            self.revoke(&member.key, reason, now)?;
        }
        Ok(invited)
    }

    /// One line per record signed for a member. Local to the leader.
    pub fn journal(
        &self,
        member: &Member,
        kind: &str,
        record: &str,
        objective: &str,
        now: u64,
    ) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let line = Value::object([
            ("at", Value::string(iso(now))),
            ("member", Value::string(key_hex(&member.key))),
            ("name", Value::string(member.name.clone())),
            ("kind", Value::string(kind)),
            ("record", Value::string(record)),
            ("objective", Value::string(objective)),
        ])
        .canonical_string();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("journal.jsonl"))?;
        // One write per line, under the size a pipe or file append keeps whole.
        file.write_all(format!("{line}\n").as_bytes())
    }
}

/// Every `*.json` in `dir` that parses, in no particular order.
fn read_dir_json(dir: &Path) -> impl Iterator<Item = Value> {
    fs::read_dir(dir).into_iter().flatten().filter_map(|entry| {
        let path = entry.ok()?.path();
        if path.extension()? != "json" {
            return None;
        }
        Value::from_json(&fs::read_to_string(path).ok()?).ok()
    })
}

/// Write by rename, so a reader never sees half a file and the directory's
/// time moves, which is how the node notices.
fn write_atomically(path: &Path, value: &Value) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("entry"),
        std::process::id()
    ));
    {
        let mut file = fs::File::create(&temp)?;
        file.write_all(value.canonical_string().as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&temp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "cairn-fleet-{tag}-{}-{}",
                std::process::id(),
                crate::time::unix_seconds()
            ));
            let _ = fs::remove_dir_all(&dir);
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const NOW: u64 = 1_791_234_567;

    fn leader() -> Identity {
        Identity::from_secret_bytes([1; 32])
    }

    fn registry(scratch: &Scratch) -> Registry {
        Registry::new(&scratch.0, leader().public().to_bytes())
    }

    fn join(
        registry: &Registry,
        token: &Token,
        member: &Identity,
        name: &str,
        at: u64,
    ) -> Result<Member, Refusal> {
        let request = JoinRequest::sign(&registry.leader(), &token.invite(), member, name, at);
        registry.join(&request, at)
    }

    #[test]
    fn an_invite_admits_its_named_member_once_and_the_member_signs_from_anywhere() {
        let scratch = Scratch::new("named");
        let registry = registry(&scratch);
        let terms = Terms {
            uses: 5,
            expires_in: 3600,
            name: Some("gpu-box-1".into()),
            ..Terms::default()
        };
        let (token, invite) = registry.create_invite(&terms, NOW).unwrap();
        assert_eq!(invite.uses, 1, "a named invite admits one machine");
        let member = Identity::from_secret_bytes([4; 32]);
        let admitted = join(&registry, &token, &member, "", NOW + 10).unwrap();
        assert_eq!(admitted.name, "gpu-box-1");
        assert_eq!(admitted.invite, Some(invite.key));

        // A replay of the same join is the same membership.
        assert_eq!(
            join(&registry, &token, &member, "", NOW + 20).unwrap(),
            admitted
        );
        // A second machine finds the invite spent.
        let second = Identity::from_secret_bytes([5; 32]);
        assert_eq!(
            join(&registry, &token, &second, "", NOW + 30)
                .unwrap_err()
                .reason,
            "invite_spent"
        );

        let body = b"{}";
        let auth = MemberAuth::sign(
            &member,
            &registry.leader(),
            NOW + 40,
            "POST",
            "/progress",
            body,
        );
        let verified = registry
            .verify_request(&auth, "POST", "/progress", body, NOW + 41)
            .unwrap();
        assert_eq!(verified.name, "gpu-box-1");
        assert_eq!(registry.counts(NOW + 41, 180), (1, 1));
        assert_eq!(
            registry
                .reserved_by("gpu-box-1/gpu3", NOW + 41)
                .map(|m| m.name),
            Some("gpu-box-1".to_string())
        );
        assert!(registry.reserved_by("gpu-box-10", NOW + 41).is_none());

        // Every way a request fails.
        let stale = MemberAuth::sign(
            &member,
            &registry.leader(),
            NOW - 1000,
            "POST",
            "/progress",
            body,
        );
        assert_eq!(
            registry
                .verify_request(&stale, "POST", "/progress", body, NOW + 41)
                .unwrap_err()
                .reason,
            "clock_skew"
        );
        assert_eq!(
            registry
                .verify_request(&auth, "POST", "/progress", b"{\"x\":1}", NOW + 41)
                .unwrap_err()
                .reason,
            "bad_signature"
        );
        let stranger = Identity::from_secret_bytes([9; 32]);
        let unknown = MemberAuth::sign(
            &stranger,
            &registry.leader(),
            NOW + 40,
            "POST",
            "/progress",
            body,
        );
        assert_eq!(
            registry
                .verify_request(&unknown, "POST", "/progress", body, NOW + 41)
                .unwrap_err()
                .reason,
            "member_unknown"
        );
    }

    #[test]
    fn a_prefix_invite_names_members_by_key_and_counts_its_uses_exactly() {
        let scratch = Scratch::new("prefix");
        let registry = registry(&scratch);
        let terms = Terms {
            uses: 2,
            expires_in: 3600,
            prefix: Some("rented".into()),
            member_ttl: Some(600),
            ..Terms::default()
        };
        let (token, _) = registry.create_invite(&terms, NOW).unwrap();
        let a = Identity::from_secret_bytes([4; 32]);
        let b = Identity::from_secret_bytes([5; 32]);
        let c = Identity::from_secret_bytes([6; 32]);
        let first = join(&registry, &token, &a, "", NOW).unwrap();
        assert_eq!(first.name, format!("rented-{}", &a.submitter_id()[..12]));
        assert_eq!(first.expires_at, Some(NOW + 600));
        join(&registry, &token, &b, "", NOW).unwrap();
        assert_eq!(
            join(&registry, &token, &c, "", NOW).unwrap_err().reason,
            "invite_spent"
        );
        assert_eq!(registry.invites()[0].1, 2);

        // The membership ends by itself, and a replay of its join cannot
        // renew it; a new invite can.
        let body = b"{}";
        let auth = MemberAuth::sign(&a, &registry.leader(), NOW + 700, "POST", "/progress", body);
        assert_eq!(
            registry
                .verify_request(&auth, "POST", "/progress", body, NOW + 700)
                .unwrap_err()
                .reason,
            "member_expired"
        );
        assert_eq!(registry.counts(NOW + 700, 180).0, 0);
        assert_eq!(
            join(&registry, &token, &a, "", NOW + 700)
                .unwrap_err()
                .reason,
            "member_expired"
        );
        let renewal_terms = Terms {
            uses: 1,
            expires_in: 3600,
            prefix: Some("rented".into()),
            ..Terms::default()
        };
        let (renewal, _) = registry.create_invite(&renewal_terms, NOW + 700).unwrap();
        let again = join(&registry, &renewal, &a, "", NOW + 701).unwrap();
        assert_eq!(
            again.name, first.name,
            "the key keeps its name, which its old membership freed"
        );
        assert_eq!(again.expires_at, None);
    }

    #[test]
    fn revocation_is_immediate_sticky_and_by_key() {
        let scratch = Scratch::new("revoke");
        let registry = registry(&scratch);
        let terms = Terms {
            uses: 3,
            expires_in: 3600,
            ..Terms::default()
        };
        let (token, invite) = registry.create_invite(&terms, NOW).unwrap();
        let member = Identity::from_secret_bytes([4; 32]);
        let admitted = join(&registry, &token, &member, "box-a", NOW).unwrap();
        let body = b"{}";
        let auth = MemberAuth::sign(
            &member,
            &registry.leader(),
            NOW + 1,
            "POST",
            "/progress",
            body,
        );
        registry
            .verify_request(&auth, "POST", "/progress", body, NOW + 1)
            .unwrap();

        // The CLI writes the tombstone; the node sees it on the next request.
        let cli = Registry::new(&scratch.0, registry.leader());
        cli.revoke(&admitted.key, "box returned", NOW + 2).unwrap();
        assert_eq!(
            registry
                .verify_request(&auth, "POST", "/progress", body, NOW + 2)
                .unwrap_err()
                .reason,
            "member_revoked"
        );
        // The first revocation stands; a second does not move its time.
        assert_eq!(
            cli.revoke(&admitted.key, "again", NOW + 9)
                .unwrap()
                .revoked_at,
            NOW + 2
        );
        // A replayed join, or a fresh invite, cannot bring the key back.
        assert_eq!(
            join(&registry, &token, &member, "box-a", NOW + 3)
                .unwrap_err()
                .reason,
            "member_revoked"
        );
        let (fresh, _) = registry.create_invite(&terms, NOW + 4).unwrap();
        assert_eq!(
            join(&registry, &fresh, &member, "box-b", NOW + 5)
                .unwrap_err()
                .reason,
            "member_revoked"
        );
        // The name is free again for a new key.
        let replacement = Identity::from_secret_bytes([7; 32]);
        assert_eq!(
            join(&registry, &fresh, &replacement, "box-a", NOW + 6)
                .unwrap()
                .name,
            "box-a"
        );
        assert!(registry.reserved_by("box-a", NOW + 6).is_some());

        // Revoking an invite's members, then the invite.
        let others = registry
            .revoke_invited(&invite.key, "batch over", NOW + 7)
            .unwrap();
        assert!(
            others.is_empty(),
            "the only member of that invite was already revoked"
        );
        assert!(registry.revoke_invite(&invite.key).unwrap());
        assert_eq!(
            join(
                &registry,
                &token,
                &Identity::from_secret_bytes([8; 32]),
                "box-c",
                NOW + 8
            )
            .unwrap_err()
            .reason,
            "invite_unknown"
        );
    }

    #[test]
    fn joins_are_refused_for_every_reason_the_design_names() {
        let scratch = Scratch::new("refusals");
        let registry = registry(&scratch);
        let (open, _) = registry
            .create_invite(
                &Terms {
                    uses: 5,
                    expires_in: 100,
                    ..Terms::default()
                },
                NOW,
            )
            .unwrap();
        let member = Identity::from_secret_bytes([4; 32]);
        assert_eq!(
            join(&registry, &open, &member, "", NOW).unwrap_err().reason,
            "name_required"
        );
        let skewed = JoinRequest::sign(&registry.leader(), &open.invite(), &member, "box", NOW);
        assert_eq!(
            registry.join(&skewed, NOW + 1000).unwrap_err().reason,
            "clock_skew",
            "a join signed far from the leader's clock is refused before the invite's expiry is"
        );
        let late = JoinRequest::sign(
            &registry.leader(),
            &open.invite(),
            &member,
            "box",
            NOW + 200,
        );
        assert_eq!(
            registry.join(&late, NOW + 200).unwrap_err().reason,
            "invite_expired"
        );
        assert_eq!(
            join(&registry, &open, &leader(), "box", NOW)
                .unwrap_err()
                .reason,
            "member_is_leader"
        );
        join(&registry, &open, &member, "box", NOW).unwrap();
        let other = Identity::from_secret_bytes([5; 32]);
        assert_eq!(
            join(&registry, &open, &other, "box", NOW)
                .unwrap_err()
                .reason,
            "name_taken"
        );

        // A token minted for another leader does not open this one.
        let foreign = Token::mint(Identity::from_secret_bytes([2; 32]).public().to_bytes());
        assert_eq!(
            join(&registry, &foreign, &other, "box2", NOW)
                .unwrap_err()
                .reason,
            "invite_unknown"
        );

        // Manual admission refuses the same things.
        assert_eq!(
            registry
                .admit(other.public().to_bytes(), "box", None, NOW)
                .unwrap_err()
                .reason,
            "name_taken"
        );
        assert_eq!(
            registry
                .admit(other.public().to_bytes(), "a b", None, NOW)
                .unwrap_err()
                .reason,
            "bad_name"
        );
        let manual = registry
            .admit(other.public().to_bytes(), "manual-1", Some(60), NOW)
            .unwrap();
        assert_eq!(manual.invite, None);
        assert_eq!(
            registry.find("manual-1", NOW).map(|m| m.key),
            Some(manual.key)
        );
        assert_eq!(
            registry.find(&other.submitter_id(), NOW).map(|m| m.name),
            Some("manual-1".into())
        );
    }

    #[test]
    fn the_journal_is_one_line_per_signed_record() {
        let scratch = Scratch::new("journal");
        let registry = registry(&scratch);
        let member = Member {
            key: [4; 32],
            name: "box".into(),
            invite: None,
            joined_at: NOW,
            expires_at: None,
        };
        registry
            .journal(&member, "commitment", "sha256:aa", "sha256:oo", NOW)
            .unwrap();
        registry
            .journal(&member, "claim", "sha256:bb", "sha256:oo", NOW + 1)
            .unwrap();
        let text = fs::read_to_string(scratch.0.join("journal.jsonl")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first = Value::from_json(lines[0]).unwrap();
        assert_eq!(first.get("name").unwrap().as_str(), Some("box"));
        assert_eq!(first.get("record").unwrap().as_str(), Some("sha256:aa"));
    }
}
