//! The fleet's credentials: invite tokens, the join string, signed requests.
//!
//! Everything here is `docs/design/fleet-enrollment.md` §4–§6, byte for byte:
//! the strings a member signs are fixed text, one field per line, so a client
//! in any language can build them and a fixed key gives a fixed signature
//! (ed25519 is deterministic), which is what the golden test below pins.
//!
//! Three keys, three jobs. The **leader key** is what settlements pay and
//! signs nothing new here. An **invite key** is minted per invitation; its
//! seed exists only inside the token and its one use is to sign joins. A
//! **member key** is made on the worker box and signs requests to one leader.
//! Each signed message opens with its own domain line, which can never be the
//! canonical encoding of a record, so neither an invite nor a member key can
//! be made to sign one (the cross-protocol hazard in
//! [`crate::crypto::identity`]).

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::canonical::Value;
use crate::crypto::identity::{verify_bytes, Identity, Signature};

/// The token's first field, and the version of everything below.
pub const TOKEN_PREFIX: &str = "cairn-invite1";
/// The first line of every join string.
pub const JOIN_DOMAIN: &str = "cairn-fleet-join/1";
/// The first line of every request string.
pub const REQUEST_DOMAIN: &str = "cairn-fleet-request/1";
/// The `Authorization` scheme a member's request carries.
pub const SCHEME: &str = "CairnMember";
/// How far a member's signed time may be from the leader's clock.
pub const REQUEST_WINDOW_SECONDS: u64 = 120;
/// The same for a join, which happens at boot, when clocks are least settled.
pub const JOIN_WINDOW_SECONDS: u64 = 300;
/// The longest member name: room for `name/gpu0` under the roster's own cap.
pub const MAX_NAME_CHARS: usize = 40;

/// An ed25519 public key.
pub type Key = [u8; 32];

/// Why a credential was refused, with the status and the machine-readable
/// reason the HTTP side answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub reason: &'static str,
    pub message: String,
}

impl Refusal {
    pub fn new(status: u16, reason: &'static str, message: impl Into<String>) -> Refusal {
        Refusal {
            status,
            reason,
            message: message.into(),
        }
    }

    fn malformed(message: impl Into<String>) -> Refusal {
        Refusal::new(400, "malformed_credential", message)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

/// Lowercase hex of a key.
pub fn key_hex(key: &Key) -> String {
    crate::hex::encode(key)
}

/// A key from 64 lowercase hex characters; any other spelling is refused, so
/// one key has one spelling.
pub fn parse_key(text: &str) -> Option<Key> {
    if text.len() != 64 {
        return None;
    }
    crate::hex::decode(text)?.try_into().ok()
}

fn parse_signature(text: &str) -> Option<Signature> {
    if text.len() != 128 {
        return None;
    }
    let bytes: [u8; 64] = crate::hex::decode(text)?.try_into().ok()?;
    Some(Signature::from_bytes(bytes))
}

/// Canonical decimal seconds: digits only, no sign, no leading zero.
fn parse_time(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.len() <= 12
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if canonical {
        text.parse().ok()
    } else {
        None
    }
}

/// Whether `time` is within `window` seconds of `now`. The refusal names both
/// clocks, so a box whose clock drifted can see why.
pub fn fresh(time: u64, now: u64, window: u64) -> Result<(), Refusal> {
    if time.abs_diff(now) <= window {
        return Ok(());
    }
    Err(Refusal::new(
        401,
        "clock_skew",
        format!(
            "the request is signed at {time} and this node's clock says {now}: {} s apart, \
             past the {window} s allowed. Fix the clock on the machine that signed it (NTP)",
            time.abs_diff(now)
        ),
    ))
}

// -- names ----------------------------------------------------------------------------

/// `[A-Za-z0-9._-]`, at most [`MAX_NAME_CHARS`]: what a member may be called.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_CHARS
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether a member called `member` owns the roster name `name`: the name
/// itself, or anything under `member/`. One box, four GPUs, four slices.
pub fn covers(member: &str, name: &str) -> bool {
    match name.strip_prefix(member) {
        Some("") => true,
        Some(rest) => rest.len() > 1 && rest.starts_with('/'),
        None => false,
    }
}

// -- the token -------------------------------------------------------------------------

/// An invitation: the leader's key, which the worker pins, and the seed of a
/// one-purpose key that signs joins. Printed once by `cairn fleet invite`.
pub struct Token {
    pub leader: Key,
    seed: Zeroizing<[u8; 32]>,
}

impl Token {
    /// A fresh invitation to the leader `leader`.
    pub fn mint(leader: Key) -> Token {
        let invite = Identity::generate(&mut OsRng);
        Token {
            leader,
            seed: invite.to_secret_bytes(),
        }
    }

    /// The key that signs joins.
    pub fn invite(&self) -> Identity {
        Identity::from_secret_bytes(*self.seed)
    }

    /// Its public half: the invite's name on the leader.
    pub fn invite_key(&self) -> Key {
        self.invite().public().to_bytes()
    }

    pub fn parse(text: &str) -> Result<Token, Refusal> {
        let text = text.trim();
        let mut parts = text.split('.');
        let (Some(prefix), Some(leader), Some(seed), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Refusal::malformed(format!(
                "an invite token is {TOKEN_PREFIX}.<leader key>.<invite seed>: three fields \
                 separated by dots"
            )));
        };
        if prefix != TOKEN_PREFIX {
            return Err(Refusal::malformed(format!(
                "this token starts {prefix:?}; this cairn reads {TOKEN_PREFIX}"
            )));
        }
        let leader = parse_key(leader).ok_or_else(|| {
            Refusal::malformed("the token's leader key is not 64 lowercase hex characters")
        })?;
        let seed = parse_key(seed).ok_or_else(|| {
            Refusal::malformed(
                "the token's invite seed is not 64 lowercase hex characters; was it cut short \
                 when it was pasted?",
            )
        })?;
        Ok(Token {
            leader,
            seed: Zeroizing::new(seed),
        })
    }

    /// The text to hand a worker. It holds a secret: whoever has it can join.
    pub fn render(&self) -> String {
        format!(
            "{TOKEN_PREFIX}.{}.{}",
            key_hex(&self.leader),
            crate::hex::encode(self.seed.as_slice())
        )
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Token {{ leader: {}, seed: <redacted> }}",
            key_hex(&self.leader)
        )
    }
}

// -- joining ---------------------------------------------------------------------------

/// The string both join signatures cover.
pub fn join_string(leader: &Key, invite: &Key, member: &Key, name: &str, time: u64) -> String {
    format!(
        "{JOIN_DOMAIN}\nleader {}\ninvite {}\nmember {}\nname {name}\ntime {time}",
        key_hex(leader),
        key_hex(invite),
        key_hex(member)
    )
}

/// What `POST /fleet/join` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub invite: Key,
    pub member: Key,
    /// The name asked for; empty asks the leader to choose.
    pub name: String,
    pub time: u64,
    pub invite_signature: Signature,
    pub member_signature: Signature,
}

impl JoinRequest {
    /// Sign a join to `leader` with the invite key and the new member key.
    pub fn sign(
        leader: &Key,
        invite: &Identity,
        member: &Identity,
        name: &str,
        time: u64,
    ) -> JoinRequest {
        let invite_key = invite.public().to_bytes();
        let member_key = member.public().to_bytes();
        let text = join_string(leader, &invite_key, &member_key, name, time);
        JoinRequest {
            invite: invite_key,
            member: member_key,
            name: name.to_string(),
            time,
            invite_signature: invite.sign_bytes(text.as_bytes()),
            member_signature: member.sign_bytes(text.as_bytes()),
        }
    }

    /// Both signatures, over the string rebuilt with *this* leader's key.
    pub fn verify(&self, leader: &Key) -> Result<(), Refusal> {
        let text = join_string(leader, &self.invite, &self.member, &self.name, self.time);
        verify_bytes(&self.invite, text.as_bytes(), &self.invite_signature).map_err(|_| {
            Refusal::new(
                403,
                "bad_invite_signature",
                "the invite signature does not verify for this leader: a different token, a \
                 token for a different leader, or a request altered on the way",
            )
        })?;
        verify_bytes(&self.member, text.as_bytes(), &self.member_signature).map_err(|_| {
            Refusal::new(
                403,
                "bad_member_signature",
                "the member key did not sign this join, so it cannot be enrolled: proof of \
                 possession failed",
            )
        })
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("invite", Value::string(key_hex(&self.invite))),
            ("member", Value::string(key_hex(&self.member))),
            ("name", Value::string(self.name.clone())),
            ("time", Value::Int(i128::from(self.time))),
            (
                "invite_signature",
                Value::string(self.invite_signature.to_hex()),
            ),
            (
                "member_signature",
                Value::string(self.member_signature.to_hex()),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<JoinRequest, Refusal> {
        let text = |field: &str| {
            value
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| Refusal::malformed(format!("a join needs a string {field:?}")))
        };
        let key = |field: &str| {
            parse_key(text(field)?).ok_or_else(|| {
                Refusal::malformed(format!("{field:?} is not 64 lowercase hex characters"))
            })
        };
        let signature = |field: &str| {
            parse_signature(text(field)?).ok_or_else(|| {
                Refusal::malformed(format!("{field:?} is not 128 lowercase hex characters"))
            })
        };
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !name.is_empty() && !valid_name(&name) {
            return Err(Refusal::new(
                400,
                "bad_name",
                format!(
                    "a member name is letters, digits, '.', '_' and '-', at most \
                     {MAX_NAME_CHARS} characters; {name:?} is not one"
                ),
            ));
        }
        let time = value
            .get("time")
            .and_then(Value::as_u64)
            .ok_or_else(|| Refusal::malformed("a join needs a non-negative integer \"time\""))?;
        Ok(JoinRequest {
            invite: key("invite")?,
            member: key("member")?,
            name,
            time,
            invite_signature: signature("invite_signature")?,
            member_signature: signature("member_signature")?,
        })
    }
}

// -- signed requests ---------------------------------------------------------------------

/// SHA-256 of a body, as the request string carries it.
pub fn body_digest(body: &[u8]) -> String {
    crate::hex::encode(&Sha256::digest(body))
}

/// The string a member signs for one request.
pub fn request_string(
    leader: &Key,
    member: &Key,
    time: u64,
    method: &str,
    target: &str,
    body: &[u8],
) -> String {
    format!(
        "{REQUEST_DOMAIN}\nleader {}\nmember {}\ntime {time}\nmethod {method}\ntarget {target}\nbody {}",
        key_hex(leader),
        key_hex(member),
        body_digest(body)
    )
}

/// `Authorization: CairnMember <member key> <time> <signature>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberAuth {
    pub member: Key,
    pub time: u64,
    pub signature: Signature,
}

impl MemberAuth {
    /// Sign one request to `leader`.
    pub fn sign(
        member: &Identity,
        leader: &Key,
        time: u64,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> MemberAuth {
        let key = member.public().to_bytes();
        let text = request_string(leader, &key, time, method, target, body);
        MemberAuth {
            member: key,
            time,
            signature: member.sign_bytes(text.as_bytes()),
        }
    }

    /// Whether a header value is in this scheme at all, before parsing it.
    pub fn is_scheme(header: &str) -> bool {
        header
            .split_whitespace()
            .next()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
    }

    pub fn parse(header: &str) -> Result<MemberAuth, Refusal> {
        let mut words = header.split_whitespace();
        let (Some(scheme), Some(member), Some(time), Some(signature), None) = (
            words.next(),
            words.next(),
            words.next(),
            words.next(),
            words.next(),
        ) else {
            return Err(Refusal::new(
                401,
                "malformed_authorization",
                format!("the Authorization header is `{SCHEME} <member key> <time> <signature>`"),
            ));
        };
        if !scheme.eq_ignore_ascii_case(SCHEME) {
            return Err(Refusal::new(
                401,
                "malformed_authorization",
                format!("this node reads the {SCHEME} scheme, not {scheme:?}"),
            ));
        }
        let bad = |what: &str| {
            Refusal::new(
                401,
                "malformed_authorization",
                format!("the Authorization header's {what} is malformed"),
            )
        };
        Ok(MemberAuth {
            member: parse_key(member).ok_or_else(|| bad("member key"))?,
            time: parse_time(time).ok_or_else(|| bad("time"))?,
            signature: parse_signature(signature).ok_or_else(|| bad("signature"))?,
        })
    }

    pub fn render(&self) -> String {
        format!(
            "{SCHEME} {} {} {}",
            key_hex(&self.member),
            self.time,
            self.signature.to_hex()
        )
    }

    /// The signature over the request this node actually received.
    pub fn verify(
        &self,
        leader: &Key,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> Result<(), Refusal> {
        let text = request_string(leader, &self.member, self.time, method, target, body);
        verify_bytes(&self.member, text.as_bytes(), &self.signature).map_err(|_| {
            Refusal::new(
                401,
                "bad_signature",
                "the member signature does not cover this request: signed for another leader, \
                 another path or another body, or altered on the way",
            )
        })
    }
}

// -- the member file -----------------------------------------------------------------

/// What `cairn fleet join` writes on the worker box: where the leader is, its
/// pinned key, this member's name and its secret. Mode 0600.
#[derive(Clone)]
pub struct MemberFile {
    pub node: String,
    pub leader: Key,
    pub name: String,
    pub member: Identity,
    pub expires_at: Option<u64>,
}

impl MemberFile {
    pub fn to_value(&self) -> Value {
        Value::object([
            ("node", Value::string(self.node.clone())),
            ("leader", Value::string(key_hex(&self.leader))),
            ("name", Value::string(self.name.clone())),
            ("member", Value::string(self.member.submitter_id())),
            (
                "secret",
                Value::string(crate::hex::encode(self.member.to_secret_bytes().as_slice())),
            ),
            (
                "expires_at",
                match self.expires_at {
                    Some(at) => Value::Int(i128::from(at)),
                    None => Value::Null,
                },
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<MemberFile, String> {
        let text = |field: &str| {
            value
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("a member file needs a string {field:?}"))
        };
        let leader = parse_key(text("leader")?)
            .ok_or("the member file's \"leader\" is not 64 lowercase hex")?;
        let secret = Zeroizing::new(
            parse_key(text("secret")?)
                .ok_or("the member file's \"secret\" is not 64 lowercase hex")?,
        );
        let member = Identity::from_secret_bytes(*secret);
        if let Ok(declared) = text("member") {
            if declared != member.submitter_id() {
                return Err(format!(
                    "the member file says its key is {declared} but its secret is {}'s; the \
                     file is damaged",
                    member.submitter_id()
                ));
            }
        }
        let name = text("name")?.to_string();
        if !valid_name(&name) {
            return Err(format!(
                "the member file's name {name:?} is not a member name"
            ));
        }
        Ok(MemberFile {
            node: text("node")?.to_string(),
            leader,
            name,
            member,
            expires_at: value.get("expires_at").and_then(Value::as_u64),
        })
    }

    pub fn load(path: &Path) -> Result<MemberFile, String> {
        let text = crate::secret_file::read_to_string(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let value = Value::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        MemberFile::from_value(&value).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Write it with mode 0600, refusing to replace a file already there:
    /// through [`crate::secret_file`], like every other secret this crate
    /// keeps, so a symlink planted at the path is not followed.
    pub fn save_new(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let text = Zeroizing::new(format!("{}\n", self.to_value().canonical_string()));
        crate::secret_file::write_new(path, text.as_bytes())
    }

    /// The `Authorization` value for one request to this member's leader.
    pub fn authorize(&self, time: u64, method: &str, target: &str, body: &[u8]) -> String {
        MemberAuth::sign(&self.member, &self.leader, time, method, target, body).render()
    }

    /// The name a worker on this box reports under: the member's own, or
    /// `name/suffix` for one of several workers.
    pub fn worker_name(&self, suffix: Option<&str>) -> String {
        match suffix.filter(|s| !s.is_empty()) {
            Some(suffix) => format!("{}/{suffix}", self.name),
            None => self.name.clone(),
        }
    }
}

impl fmt::Debug for MemberFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemberFile {{ node: {}, leader: {}, name: {}, member: {}, secret: <redacted> }}",
            self.node,
            key_hex(&self.leader),
            self.name,
            self.member.submitter_id()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> Identity {
        Identity::from_secret_bytes([byte; 32])
    }

    #[test]
    fn a_token_round_trips_and_refuses_what_is_not_one() {
        let leader = identity(1).public().to_bytes();
        let token = Token::mint(leader);
        let text = token.render();
        assert!(text.starts_with("cairn-invite1."));
        let back = Token::parse(&text).unwrap();
        assert_eq!(back.leader, leader);
        assert_eq!(back.invite_key(), token.invite_key());
        assert_eq!(Token::parse(&format!("  {text}\n")).unwrap().leader, leader);
        assert!(!format!("{token:?}").contains(&text[text.len() - 64..]));

        for bad in [
            "",
            "cairn-invite2.aa.bb",
            &text[..text.len() - 1],
            &text.to_uppercase(),
            &format!("{text}.extra"),
        ] {
            let refusal = Token::parse(bad).unwrap_err();
            assert_eq!(refusal.reason, "malformed_credential", "{bad:?}");
        }
    }

    #[test]
    fn names_are_a_short_alphabet_and_own_their_namespace() {
        for good in ["gpu-box-1", "rented-3f9a2c1b0d4e", "a", "box.lan_2"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["", "a b", "a/b", "ünï", &"x".repeat(41), "a|b"] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(covers("gpu-box-1", "gpu-box-1"));
        assert!(covers("gpu-box-1", "gpu-box-1/gpu0"));
        assert!(!covers("gpu-box-1", "gpu-box-1/"));
        assert!(!covers("gpu-box-1", "gpu-box-10"));
        assert!(!covers("gpu-box-1", "gpu-box"));
    }

    #[test]
    fn a_join_verifies_for_its_leader_only_and_needs_both_signatures() {
        let leader = identity(1).public().to_bytes();
        let other = identity(2).public().to_bytes();
        let invite = identity(3);
        let member = identity(4);
        let join = JoinRequest::sign(&leader, &invite, &member, "gpu-box-1", 1_791_234_567);
        join.verify(&leader).unwrap();
        assert_eq!(
            join.verify(&other).unwrap_err().reason,
            "bad_invite_signature"
        );

        let back = JoinRequest::from_value(&join.to_value()).unwrap();
        assert_eq!(back, join);

        let mut renamed = join.clone();
        renamed.name = "gpu-box-2".into();
        assert_eq!(
            renamed.verify(&leader).unwrap_err().reason,
            "bad_invite_signature"
        );

        // A member key the joiner does not hold: the invite signed, the member
        // signature is somebody else's.
        let mut stolen = join.clone();
        stolen.member = identity(5).public().to_bytes();
        let text = join_string(
            &leader,
            &stolen.invite,
            &stolen.member,
            "gpu-box-1",
            1_791_234_567,
        );
        stolen.invite_signature = invite.sign_bytes(text.as_bytes());
        assert_eq!(
            stolen.verify(&leader).unwrap_err().reason,
            "bad_member_signature"
        );

        let mut value = join.to_value();
        if let Value::Object(map) = &mut value {
            map.insert("name".into(), Value::string("a b"));
        }
        assert_eq!(
            JoinRequest::from_value(&value).unwrap_err().reason,
            "bad_name"
        );
    }

    #[test]
    fn a_request_signature_binds_every_field_of_the_string() {
        let leader = identity(1).public().to_bytes();
        let member = identity(4);
        let body = br#"{"type":"commitment"}"#;
        let auth = MemberAuth::sign(
            &member,
            &leader,
            1_791_234_567,
            "POST",
            "/submit?kind=commitment",
            body,
        );
        auth.verify(&leader, "POST", "/submit?kind=commitment", body)
            .unwrap();
        let header = auth.render();
        assert!(header.starts_with("CairnMember "));
        assert_eq!(MemberAuth::parse(&header).unwrap(), auth);
        assert!(MemberAuth::is_scheme(&header));
        assert!(!MemberAuth::is_scheme("Bearer abc"));

        let other_leader = identity(2).public().to_bytes();
        for (leader_key, method, target, body_bytes) in [
            (other_leader, "POST", "/submit?kind=commitment", &body[..]),
            (leader, "PUT", "/submit?kind=commitment", &body[..]),
            (leader, "POST", "/submit?kind=claim", &body[..]),
            (
                leader,
                "POST",
                "/submit?kind=commitment",
                &br#"{"type":"claim"}"#[..],
            ),
        ] {
            assert_eq!(
                auth.verify(&leader_key, method, target, body_bytes)
                    .unwrap_err()
                    .reason,
                "bad_signature"
            );
        }
        let mut later = auth.clone();
        later.time += 1;
        assert!(later
            .verify(&leader, "POST", "/submit?kind=commitment", body)
            .is_err());

        for bad in [
            "",
            "Bearer abc",
            "CairnMember",
            &format!(
                "CairnMember {} 0123 {}",
                key_hex(&auth.member),
                auth.signature.to_hex()
            ),
            &format!(
                "CairnMember {} -5 {}",
                key_hex(&auth.member),
                auth.signature.to_hex()
            ),
            &format!("{header} extra"),
            &header.to_uppercase().replace("CAIRNMEMBER", "CairnMember"),
        ] {
            assert_eq!(
                MemberAuth::parse(bad).unwrap_err().reason,
                "malformed_authorization",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_request_string_and_its_signature_are_golden() {
        // Fixed keys, a fixed request: every client in every language checks
        // itself against these two values.
        let leader = identity(1).public().to_bytes();
        let member = identity(4);
        assert_eq!(
            key_hex(&leader),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        let text = request_string(
            &leader,
            &member.public().to_bytes(),
            1_791_234_567,
            "POST",
            "/submit?kind=commitment",
            b"{}",
        );
        assert_eq!(
            text,
            format!(
                "cairn-fleet-request/1\nleader {}\nmember {}\ntime 1791234567\nmethod POST\n\
                 target /submit?kind=commitment\nbody {}",
                key_hex(&leader),
                member.submitter_id(),
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
            )
        );
        let header = MemberAuth::sign(
            &member,
            &leader,
            1_791_234_567,
            "POST",
            "/submit?kind=commitment",
            b"{}",
        )
        .render();
        assert_eq!(header, GOLDEN_HEADER);
    }

    /// `CairnMember` for the member seed `[4; 32]` (key `ca93ac17…`) to the
    /// leader seed `[1; 32]` (key `8a88e3dd…`) over `{}` at 1791234567, POST
    /// /submit?kind=commitment. Taken from a run and reproduced byte for byte
    /// by OpenSSL 3.0's Ed25519 (`openssl pkeyutl -sign -rawin` over the
    /// request string), then frozen: a change here is a change to the wire
    /// format, and every client in every language checks itself against it.
    const GOLDEN_HEADER: &str = "CairnMember \
        ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c 1791234567 \
        17f88fee85b5e24e5ffb8a89cabdbb3d57a3b26472793fcb5e2c1b7ca938c822\
        66dccea573eed997c022e7943b4060d75d2dcea755fa98e7a9c093fa3fa7a40f";

    #[test]
    fn freshness_is_symmetric_and_names_both_clocks() {
        assert!(fresh(1000, 1120, 120).is_ok());
        assert!(fresh(1120, 1000, 120).is_ok());
        let refusal = fresh(1000, 1121, 120).unwrap_err();
        assert_eq!(refusal.reason, "clock_skew");
        assert!(refusal.message.contains("1000") && refusal.message.contains("1121"));
    }

    #[test]
    fn a_member_file_round_trips_and_writes_only_once() {
        let dir = std::env::temp_dir().join(format!("cairn-member-file-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("fleet.json");
        let file = MemberFile {
            node: "http://203.0.113.7:8080".into(),
            leader: identity(1).public().to_bytes(),
            name: "gpu-box-1".into(),
            member: identity(4),
            expires_at: Some(1_791_300_000),
        };
        file.save_new(&path).unwrap();
        assert!(
            file.save_new(&path).is_err(),
            "a second join must not overwrite the first"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let back = MemberFile::load(&path).unwrap();
        assert_eq!(back.leader, file.leader);
        assert_eq!(back.name, "gpu-box-1");
        assert_eq!(back.member.submitter_id(), file.member.submitter_id());
        assert_eq!(back.expires_at, Some(1_791_300_000));
        assert_eq!(back.worker_name(Some("gpu0")), "gpu-box-1/gpu0");
        assert_eq!(back.worker_name(None), "gpu-box-1");
        assert!(!format!("{back:?}").contains(&crate::hex::encode(
            back.member.to_secret_bytes().as_slice()
        )));

        let mut lie = file.to_value();
        if let Value::Object(map) = &mut lie {
            map.insert("member".into(), Value::string(identity(5).submitter_id()));
        }
        assert!(MemberFile::from_value(&lie)
            .unwrap_err()
            .contains("damaged"));
        let _ = fs::remove_dir_all(&dir);
    }
}
