//! Optional Google sign-in for a browser looking at this node.
//!
//! # What this is
//!
//! An OAuth 2 authorization-code login with PKCE (S256). When an operator sets
//! `CAIRN_GOOGLE_CLIENT_ID`, a person can sign in and this node will remember
//! that browser for a while. The memory is an HMAC cookie. There is no account
//! table, and nothing about the Google profile is appended to the log.
//!
//! # What this is not
//!
//! Not a cairn identity. A submitter is an ed25519 key; a fleet member is
//! another; a Google `sub` is neither, and no rule in `node.rs` reads this
//! module. Not required. With the variable unset — the default — the node is
//! anonymous and every route answers exactly as it did. A misconfigured client
//! id does not stop the node: sign-in is the part that stays off.
//!
//! # Why `curl`, and not a TLS crate
//!
//! Talking to Google means HTTPS. `tests/cipher_policy.rs` fails the build if
//! a TLS stack enters the dependency tree, because node-to-node authentication
//! is a key and not a certificate authority. The same exception the deposit
//! client already uses applies here: the system `curl` does the one HTTPS hop,
//! to Google's fixed token and userinfo URLs, and the secret rides on its
//! stdin rather than on a command line. A node without `curl` still serves;
//! only the callback fails.
//!
//! # Why the session is not the access token
//!
//! The access token is spent once, on userinfo, and dropped. What the browser
//! holds is this node's own tag over `(sub, email, name, iat, exp)`. Google
//! being down later does not sign anybody out, and a stolen token response is
//! not a long-lived credential for this node. The HMAC key lives in the
//! secrets directory, mode 0600, beside the other operator secrets — not in
//! the log, which is replicated.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use hmac::{Hmac, KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::canonical::Value;
use crate::secret_file;
use crate::secrets;

type HmacSha256 = Hmac<Sha256>;

/// How long a signed-in browser stays signed in.
pub const SESSION_SECONDS: u64 = 14 * 24 * 60 * 60;
/// How long a sign-in attempt may sit between the redirect and the callback.
const PENDING_SECONDS: u64 = 10 * 60;
/// Outstanding sign-in attempts. Past this, new ones wait; nothing is evicted
/// while it is still fresh, because evicting would let a flood cancel a
/// person's real attempt.
const MAX_PENDING: usize = 256;
/// A cookie minted for longer than the session plus a minute is not one this
/// node wrote. The minute is clock step, not a second lifetime.
const SESSION_SKEW_SECONDS: u64 = 60;
const SESSION_COOKIE: &str = "cairn_google";
const STATE_COOKIE: &str = "cairn_google_state";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const KEY_FILE: &str = "google_session_key";

/// The environment an operator sets. All of it is optional.
pub const CLIENT_ID_ENV: &str = "CAIRN_GOOGLE_CLIENT_ID";
pub const CLIENT_SECRET_ENV: &str = "CAIRN_GOOGLE_CLIENT_SECRET";
/// Named secret used when [`CLIENT_SECRET_ENV`] is unset. The client id is
/// public; the secret is not, so it belongs with the other named secrets.
pub const CLIENT_SECRET_NAME: &str = "GOOGLE_CLIENT_SECRET";
pub const REDIRECT_URI_ENV: &str = "CAIRN_GOOGLE_REDIRECT_URI";
pub const PUBLIC_URL_ENV: &str = "CAIRN_PUBLIC_URL";
/// `1` forces the `Secure` cookie attribute, `0` forces it off. Unset follows
/// the redirect: on for `https`, off for localhost `http`, because a `Secure`
/// cookie is dropped by a browser that came in over plaintext and the local
/// node is plaintext.
pub const COOKIE_SECURE_ENV: &str = "CAIRN_GOOGLE_COOKIE_SECURE";

/// What the process environment said, already split out so a test can pass it
/// without mutating the process.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub public_url: Option<String>,
    /// `None` means "follow the redirect scheme".
    pub cookie_secure: Option<bool>,
}

/// The outcome of reading those settings. `Anonymous` is the ordinary node.
#[derive(Debug)]
pub enum Outcome {
    Anonymous,
    Misconfigured(String),
    Ready(Config),
}

/// A client id and redirect that are safe to send a browser to.
pub struct Config {
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
    redirect_uri: String,
    cookie_secure: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("cookie_secure", &self.cookie_secure)
            .finish()
    }
}

/// HTTPS to Google's two fixed URLs. The production client is `curl`. Tests
/// supply a script.
pub trait TokenClient: Send + Sync {
    fn post_form(&self, url: &str, body: &str) -> Result<String, String>;
    fn get_bearer(&self, url: &str, access_token: &str) -> Result<String, String>;
}

/// One HTTP answer. The server writes it; this module does not own a socket.
pub struct Answer {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

struct Pending {
    verifier: String,
    next: String,
    created: u64,
}

enum Mode {
    Anonymous,
    Misconfigured(String),
    Ready(Config),
}

/// The sign-in state for one process.
pub struct GoogleAuth {
    mode: Mode,
    key: Zeroizing<[u8; 32]>,
    pending: Mutex<BTreeMap<String, Pending>>,
    client: Arc<dyn TokenClient>,
}

impl GoogleAuth {
    /// The default: nobody can sign in, and nothing asks them to.
    pub fn anonymous() -> GoogleAuth {
        GoogleAuth {
            mode: Mode::Anonymous,
            key: Zeroizing::new([0; 32]),
            pending: Mutex::new(BTreeMap::new()),
            client: Arc::new(Unavailable),
        }
    }

    /// Read the operator's settings. Never refuses to exist: a bad setting
    /// comes back as [`GoogleAuth::banner`]'s misconfiguration line and the
    /// node still serves.
    pub fn from_env() -> GoogleAuth {
        let settings = Settings {
            client_id: env_nonempty(CLIENT_ID_ENV),
            client_secret: env_nonempty(CLIENT_SECRET_ENV).or_else(secret_from_file),
            redirect_uri: env_nonempty(REDIRECT_URI_ENV),
            public_url: env_nonempty(PUBLIC_URL_ENV),
            cookie_secure: env_secure_flag(),
        };
        match resolve(settings) {
            Outcome::Anonymous => GoogleAuth::anonymous(),
            Outcome::Misconfigured(reason) => GoogleAuth::misconfigured(reason),
            Outcome::Ready(config) => match load_or_create_key(&secrets::default_dir()) {
                Ok(key) => GoogleAuth::with_client(config, key, Arc::new(CurlClient)),
                Err(reason) => GoogleAuth::misconfigured(reason),
            },
        }
    }

    pub fn with_client(config: Config, key: [u8; 32], client: Arc<dyn TokenClient>) -> GoogleAuth {
        GoogleAuth {
            mode: Mode::Ready(config),
            key: Zeroizing::new(key),
            pending: Mutex::new(BTreeMap::new()),
            client,
        }
    }

    fn misconfigured(reason: String) -> GoogleAuth {
        GoogleAuth {
            mode: Mode::Misconfigured(reason),
            key: Zeroizing::new([0; 32]),
            pending: Mutex::new(BTreeMap::new()),
            client: Arc::new(Unavailable),
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.mode, Mode::Ready(_))
    }

    /// A line for stderr at startup. `None` when sign-in was not asked for,
    /// which is the common case and should not look like a warning.
    pub fn banner(&self) -> Option<String> {
        match &self.mode {
            Mode::Anonymous => None,
            Mode::Misconfigured(reason) => Some(format!(
                "google sign-in is off ({reason}); this node runs anonymously"
            )),
            Mode::Ready(_) => Some(
                "google sign-in is optional at /auth/google; anonymous use is unchanged"
                    .to_string(),
            ),
        }
    }

    /// What `GET /` says about sign-in, without looking at a browser.
    pub fn index_value(&self) -> Value {
        let (mode, available) = match &self.mode {
            Mode::Anonymous => ("anonymous", false),
            Mode::Misconfigured(_) => ("misconfigured", false),
            Mode::Ready(_) => ("ready", true),
        };
        Value::object([
            ("provider", Value::string("google")),
            ("required", Value::Bool(false)),
            ("anonymous_ok", Value::Bool(true)),
            ("available", Value::Bool(available)),
            ("mode", Value::string(mode)),
        ])
    }

    /// How `GET /` should spell the login route.
    pub fn index_route(&self) -> String {
        match &self.mode {
            Mode::Ready(_) => "GET /auth/google".to_string(),
            Mode::Anonymous => {
                "GET /auth/google (disabled: anonymous node; set CAIRN_GOOGLE_CLIENT_ID to offer sign-in)".to_string()
            }
            Mode::Misconfigured(reason) => {
                format!("GET /auth/google (disabled: {})", one_line(reason, 120))
            }
        }
    }

    /// `GET /auth`. Always answers. A cookie that does not verify is an
    /// anonymous browser, not an error — a stale cookie after a key rotation
    /// is the ordinary way to be signed out.
    pub fn status(&self, cookie_header: Option<&str>, now: u64) -> Answer {
        let mut fields = vec![
            ("provider", Value::string("google")),
            ("required", Value::Bool(false)),
            ("anonymous_ok", Value::Bool(true)),
        ];
        match &self.mode {
            Mode::Anonymous => {
                fields.push(("mode", Value::string("anonymous")));
                fields.push(("available", Value::Bool(false)));
                fields.push(("authenticated", Value::Bool(false)));
            }
            Mode::Misconfigured(reason) => {
                fields.push(("mode", Value::string("misconfigured")));
                fields.push(("available", Value::Bool(false)));
                fields.push(("authenticated", Value::Bool(false)));
                fields.push(("reason", Value::string(reason.clone())));
            }
            Mode::Ready(_) => {
                fields.push(("mode", Value::string("ready")));
                fields.push(("available", Value::Bool(true)));
                let account = cookie_header
                    .and_then(|header| cookie(header, SESSION_COOKIE))
                    .and_then(|value| self.open(value, now));
                match account {
                    Some(account) => {
                        fields.push(("authenticated", Value::Bool(true)));
                        fields.push(("account", account_value(&account)));
                    }
                    None => {
                        fields.push(("authenticated", Value::Bool(false)));
                        fields.push(("login", Value::string("/auth/google")));
                    }
                }
            }
        }
        json_answer(200, Value::object(fields))
    }

    /// `GET /auth/google`. Sends the browser to Google, or explains why this
    /// node will not.
    pub fn start(&self, next: Option<&str>, default_next: &str, now: u64) -> Answer {
        let Mode::Ready(config) = &self.mode else {
            return self.status(None, now).with_status(404);
        };
        let next = match sanitize_next(next, default_next) {
            Ok(next) => next,
            Err(reason) => return json_answer(400, error_value("bad_next", reason)),
        };
        let verifier = random_token();
        let state = random_token();
        let challenge = pkce_challenge(&verifier);
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending.retain(|_, entry| now.saturating_sub(entry.created) <= PENDING_SECONDS);
            if pending.len() >= MAX_PENDING {
                return json_answer(
                    429,
                    error_value(
                        "too_many_sign_ins",
                        "too many sign-in attempts are in progress; try again in a few minutes. anonymous use is unaffected",
                    ),
                );
            }
            pending.insert(
                state.clone(),
                Pending {
                    verifier,
                    next,
                    created: now,
                },
            );
        }
        let location = authorization_url(config, &state, &challenge);
        let cookie = set_cookie(STATE_COOKIE, &state, PENDING_SECONDS, config.cookie_secure);
        redirect_answer(location, vec![cookie])
    }

    /// `GET /auth/google/callback`.
    pub fn callback(
        &self,
        code: Option<&str>,
        query_state: Option<&str>,
        cookie_header: Option<&str>,
        now: u64,
    ) -> Answer {
        let Mode::Ready(config) = &self.mode else {
            return self.status(None, now).with_status(404);
        };
        let (Some(code), Some(query_state)) = (code, query_state) else {
            return json_answer(
                400,
                error_value(
                    "missing_code",
                    "google sent this browser back without a code and a state. start again at /auth/google",
                ),
            );
        };
        if code.len() > 2048 || query_state.len() > 256 {
            return json_answer(
                400,
                error_value("bad_callback", "the callback is not one this node issued"),
            );
        }
        let cookie_state = cookie_header.and_then(|header| cookie(header, STATE_COOKIE));
        if cookie_state != Some(query_state) {
            // The server-side state alone would let someone who learned the
            // state finish the flow in a different browser. The cookie is
            // what binds it to the browser that asked.
            return json_answer(
                400,
                error_value(
                    "state_mismatch",
                    "this callback does not match the browser that started it. start again at /auth/google",
                ),
            );
        }
        let pending = {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending.retain(|_, entry| now.saturating_sub(entry.created) <= PENDING_SECONDS);
            pending.remove(query_state)
        };
        let Some(pending) = pending else {
            return json_answer(
                400,
                error_value(
                    "unknown_state",
                    "this sign-in attempt is unknown, expired, or already used. start again at /auth/google",
                ),
            );
        };
        let form = Zeroizing::new(token_form(config, code, &pending.verifier));
        let token_body = match self.client.post_form(TOKEN_URL, &form) {
            Ok(body) => body,
            Err(error) => return google_down(&error, config),
        };
        let access = match parse_access_token(&token_body) {
            Ok(access) => access,
            Err(error) => return google_down(&error, config),
        };
        let info = match self.client.get_bearer(USERINFO_URL, &access) {
            Ok(body) => body,
            Err(error) => return google_down(&error, config),
        };
        let account = match parse_userinfo(&info) {
            Ok(account) => account,
            Err(error) => return google_down(&error, config),
        };
        // The access token ends here. The cookie is ours, not Google's.
        drop(access);
        let session = self.seal(&account, now);
        let cookies = vec![
            set_cookie(
                SESSION_COOKIE,
                &session,
                SESSION_SECONDS,
                config.cookie_secure,
            ),
            clear_cookie(STATE_COOKIE, config.cookie_secure),
        ];
        redirect_answer(pending.next, cookies)
    }

    /// `POST /auth/logout`. Idempotent: signed out is the state it leaves,
    /// whether or not a session was present.
    pub fn logout(&self) -> Answer {
        let secure = match &self.mode {
            Mode::Ready(config) => config.cookie_secure,
            _ => false,
        };
        let mut answer = json_answer(
            200,
            Value::object([
                ("authenticated", Value::Bool(false)),
                ("anonymous_ok", Value::Bool(true)),
            ]),
        );
        answer.headers.push((
            "set-cookie".to_string(),
            clear_cookie(SESSION_COOKIE, secure),
        ));
        answer
            .headers
            .push(("set-cookie".to_string(), clear_cookie(STATE_COOKIE, secure)));
        answer
    }

    fn open(&self, cookie_value: &str, now: u64) -> Option<Account> {
        if !self.is_ready() || cookie_value.len() > 4096 {
            return None;
        }
        let mut parts = cookie_value.split('.');
        let (Some("v1"), Some(payload_b64), Some(tag_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let payload = b64url_decode(payload_b64)?;
        let tag = b64url_decode(tag_b64)?;
        if !mac_ok(&*self.key, &payload, &tag) {
            return None;
        }
        let text = String::from_utf8(payload).ok()?;
        let value = Value::from_json(&text).ok()?;
        if value.get("v").and_then(Value::as_i64) != Some(1) {
            return None;
        }
        let sub = value.get("sub").and_then(Value::as_str)?;
        if !valid_sub(sub) {
            return None;
        }
        let iat = value.get("iat").and_then(Value::as_u64)?;
        let exp = value.get("exp").and_then(Value::as_u64)?;
        let life = exp.saturating_sub(iat);
        if life == 0 || life > SESSION_SECONDS + SESSION_SKEW_SECONDS {
            return None;
        }
        if iat > now.saturating_add(SESSION_SKEW_SECONDS) || now >= exp {
            return None;
        }
        Some(Account {
            sub: sub.to_string(),
            email: optional_text(&value, "email"),
            name: optional_text(&value, "name"),
        })
    }

    fn seal(&self, account: &Account, now: u64) -> String {
        let exp = now.saturating_add(SESSION_SECONDS);
        let payload = Value::object([
            ("email", opt_string(account.email.as_deref())),
            ("exp", Value::Int(exp as i128)),
            ("iat", Value::Int(now as i128)),
            ("name", opt_string(account.name.as_deref())),
            ("sub", Value::string(&account.sub)),
            ("v", Value::Int(1)),
        ]);
        let bytes = payload.canonical_bytes();
        let tag = mac(&*self.key, &bytes);
        format!("v1.{}.{}", b64url_encode(&bytes), b64url_encode(&tag))
    }
}

impl Answer {
    fn with_status(mut self, status: u16) -> Answer {
        self.status = status;
        self
    }
}

struct Account {
    sub: String,
    email: Option<String>,
    name: Option<String>,
}

/// Decide whether the settings name a working client, a node that should stay
/// anonymous, or a node whose operator asked and got the setting wrong.
pub fn resolve(settings: Settings) -> Outcome {
    let Some(client_id) = settings
        .client_id
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
    else {
        return Outcome::Anonymous;
    };
    if !valid_client_id(&client_id) {
        return Outcome::Misconfigured(format!(
            "{CLIENT_ID_ENV} should be a Google client id ending in .apps.googleusercontent.com"
        ));
    }
    let redirect = match (
        settings
            .redirect_uri
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        settings
            .public_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    ) {
        (Some(uri), _) => uri.to_string(),
        (None, Some(public)) => match redirect_from_public(public) {
            Ok(uri) => uri,
            Err(reason) => return Outcome::Misconfigured(reason),
        },
        (None, None) => {
            return Outcome::Misconfigured(format!(
                "{CLIENT_ID_ENV} is set but neither {REDIRECT_URI_ENV} nor {PUBLIC_URL_ENV} is; \
                 Google has to send the browser back to this node. sign-in is off, and the node \
                 still runs anonymously"
            ));
        }
    };
    if let Err(reason) = validate_redirect(&redirect) {
        return Outcome::Misconfigured(reason);
    }
    let client_secret = match settings.client_secret {
        None => None,
        Some(secret) => {
            let secret = secret.trim().to_string();
            if secret.is_empty() {
                None
            } else if !valid_secret(&secret) {
                return Outcome::Misconfigured(format!(
                    "{CLIENT_SECRET_ENV} is set but is not a printable secret this node will send. \
                     leave it unset for a public PKCE client"
                ));
            } else {
                Some(Zeroizing::new(secret))
            }
        }
    };
    let cookie_secure = settings
        .cookie_secure
        .unwrap_or_else(|| redirect.starts_with("https://"));
    Outcome::Ready(Config {
        client_id,
        client_secret,
        redirect_uri: redirect,
        cookie_secure,
    })
}

/// Create the session key, or read the one already beside the other secrets.
///
/// A file of the wrong length is left in place and reported. Overwriting it
/// would silently mint a new key over something the operator may have meant
/// to keep, and signing people out is a one-line `rm` they can choose.
pub fn load_or_create_key(dir: &Path) -> Result<[u8; 32], String> {
    secrets::prepare(dir).map_err(|error| {
        format!("cannot prepare the secrets directory for the google session key: {error}")
    })?;
    let path = dir.join(KEY_FILE);
    if path.exists() {
        let bytes = secret_file::read(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let key: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            format!(
                "{} is {} bytes, not 32; delete it to mint a new session key. sign-in is off until then",
                path.display(),
                bytes.len()
            )
        })?;
        return Ok(key);
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    secret_file::replace(&path, &key)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    Ok(key)
}

fn secret_from_file() -> Option<String> {
    secrets::get(&secrets::default_dir(), CLIENT_SECRET_NAME).ok()
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_secure_flag() -> Option<bool> {
    match std::env::var(COOKIE_SECURE_ENV) {
        Ok(value) if value.trim() == "1" => Some(true),
        Ok(value) if value.trim() == "0" => Some(false),
        _ => None,
    }
}

fn redirect_from_public(public_url: &str) -> Result<String, String> {
    let base = public_url.trim().trim_end_matches('/');
    if base.contains('/') && !base.starts_with("https://") && !base.starts_with("http://") {
        return Err(format!(
            "{PUBLIC_URL_ENV} should be an origin like https://cairn.example, with no path"
        ));
    }
    // An origin has one scheme and one host. A second slash after the scheme
    // would be a path, and the callback has to be exactly the route we serve.
    let after_scheme = base.split_once("://").map(|(_, rest)| rest).unwrap_or(base);
    if after_scheme.is_empty() || after_scheme.contains('/') {
        return Err(format!(
            "{PUBLIC_URL_ENV} should be an origin like https://cairn.example, with no path"
        ));
    }
    Ok(format!("{base}/auth/google/callback"))
}

fn validate_redirect(uri: &str) -> Result<(), String> {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return Err(format!(
            "{REDIRECT_URI_ENV} must be https://…/auth/google/callback, or http://localhost / http://127.0.0.1 for a local node"
        ));
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((hostport, path)) => (hostport, format!("/{path}")),
        None => {
            return Err(format!(
                "{REDIRECT_URI_ENV} must end in /auth/google/callback"
            ));
        }
    };
    if path != "/auth/google/callback" {
        return Err(format!(
            "{REDIRECT_URI_ENV} must end in /auth/google/callback, which is the route this node serves"
        ));
    }
    if hostport.is_empty()
        || hostport.contains('@')
        || hostport.contains('\\')
        || hostport.bytes().any(|b| b.is_ascii_control() || b == b' ')
    {
        return Err(format!(
            "{REDIRECT_URI_ENV} has a host this node will not send a browser to"
        ));
    }
    let host = hostport
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(hostport);
    let local = host == "localhost" || host == "127.0.0.1";
    match scheme {
        "https" => Ok(()),
        "http" if local => Ok(()),
        "http" => Err(format!(
            "{REDIRECT_URI_ENV} is plaintext on a public host. the authorization code would travel in the clear; use the https address of the reverse proxy, or http://127.0.0.1 / http://localhost for a local node"
        )),
        _ => Err(format!("{REDIRECT_URI_ENV} must be https, or http on localhost")),
    }
}

fn valid_client_id(id: &str) -> bool {
    (10..=200).contains(&id.len())
        && id.ends_with(".apps.googleusercontent.com")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn valid_secret(secret: &str) -> bool {
    (8..=512).contains(&secret.len()) && secret.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn valid_sub(sub: &str) -> bool {
    (1..=255).contains(&sub.len())
        && sub
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn authorization_url(config: &Config, state: &str, challenge: &str) -> String {
    let query = form_pairs(&[
        ("client_id", &config.client_id),
        ("redirect_uri", &config.redirect_uri),
        ("response_type", "code"),
        ("scope", "openid email profile"),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        // Online: we do not want a refresh token. There is nowhere to keep one
        // that would not become an account store.
        ("access_type", "online"),
        ("prompt", "select_account"),
    ]);
    format!("{AUTH_URL}?{query}")
}

fn token_form(config: &Config, code: &str, verifier: &str) -> String {
    let mut form = form_pairs(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", &config.client_id),
        ("redirect_uri", &config.redirect_uri),
        ("code_verifier", verifier),
    ]);
    if let Some(secret) = &config.client_secret {
        form.push_str("&client_secret=");
        form.push_str(&form_encode(secret));
    }
    form
}

fn form_pairs(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", form_encode(key), form_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// RFC 7636 S256: BASE64URL(SHA256(verifier)), no padding.
fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    b64url_encode(&digest)
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    b64url_encode(&bytes)
}

fn sanitize_next(next: Option<&str>, default_next: &str) -> Result<String, &'static str> {
    let Some(next) = next.filter(|next| !next.is_empty()) else {
        return Ok(default_next.to_string());
    };
    if next.len() > 512 {
        return Err("next is too long");
    }
    let bytes = next.as_bytes();
    // One leading slash, and not two: `//host` is a scheme-relative URL, and
    // a redirect there would leave this node.
    if bytes.first() != Some(&b'/') || next.starts_with("//") || next.starts_with("/\\") {
        return Err("next must be a path on this node");
    }
    if next.contains('\\') || next.contains("..") || next.contains('@') || next.contains(':') {
        return Err("next must be a path on this node");
    }
    if next.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("next must be a path on this node");
    }
    Ok(next.to_string())
}

fn parse_access_token(body: &str) -> Result<Zeroizing<String>, String> {
    let value = Value::from_json(body)
        .map_err(|_| "google's token answer was not json this node accepts".to_string())?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        if error.len() <= 64
            && error
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(format!("google refused the sign-in ({error})"));
        }
        return Err("google refused the sign-in".to_string());
    }
    let token = value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| {
            !token.is_empty() && token.len() <= 4096 && !token.bytes().any(|b| b.is_ascii_control())
        })
        .ok_or_else(|| "google's token answer had no access token".to_string())?;
    Ok(Zeroizing::new(token.to_string()))
}

fn parse_userinfo(body: &str) -> Result<Account, String> {
    let value = Value::from_json(body)
        .map_err(|_| "google's userinfo answer was not json this node accepts".to_string())?;
    let sub = value
        .get("sub")
        .and_then(Value::as_str)
        .filter(|sub| valid_sub(sub))
        .ok_or_else(|| "google's userinfo answer had no usable subject".to_string())?
        .to_string();
    // An unverified email is a string Google did not stand behind. The `sub`
    // is the identifier; the email is only a label, and only when verified.
    let email = if value.get("email_verified").and_then(Value::as_bool) == Some(true) {
        value
            .get("email")
            .and_then(Value::as_str)
            .filter(|email| valid_email(email))
            .map(str::to_string)
    } else {
        None
    };
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(clean_name)
        .filter(|name| !name.is_empty());
    Ok(Account { sub, email, name })
}

fn valid_email(email: &str) -> bool {
    if email.len() > 254 || email.matches('@').count() != 1 {
        return false;
    }
    if !email.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.contains('.')
}

fn clean_name(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_control() {
            continue;
        }
        if out.chars().count() == 80 {
            break;
        }
        out.push(ch);
    }
    out.trim().to_string()
}

fn optional_text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn opt_string(text: Option<&str>) -> Value {
    match text {
        Some(text) => Value::string(text),
        None => Value::Null,
    }
}

fn account_value(account: &Account) -> Value {
    Value::object([
        ("sub", Value::string(&account.sub)),
        ("email", opt_string(account.email.as_deref())),
        ("name", opt_string(account.name.as_deref())),
    ])
}

fn error_value(reason: &str, message: &str) -> Value {
    Value::object([
        ("error", Value::string(message)),
        ("reason", Value::string(reason)),
        ("anonymous_ok", Value::Bool(true)),
    ])
}

fn google_down(error: &str, config: &Config) -> Answer {
    let secret = config.client_secret.as_deref().map(String::as_str);
    let error = redact(error, secret);
    json_answer(
        502,
        error_value(
            "google_unavailable",
            &format!("{error}. this node is still usable anonymously"),
        ),
    )
}

fn redact(text: &str, secret: Option<&str>) -> String {
    let mut text = text.replace(['\n', '\r'], " ");
    if let Some(secret) = secret {
        if secret.len() >= 4 {
            text = text.replace(secret, "[redacted]");
        }
    }
    one_line(&text, 180)
}

fn one_line(text: &str, max: usize) -> String {
    let text = text.replace(['\n', '\r'], " ");
    if text.chars().count() <= max {
        text
    } else {
        text.chars().take(max).collect()
    }
}

fn json_answer(status: u16, body: Value) -> Answer {
    Answer {
        status,
        content_type: "application/json",
        body: body.canonical_string().into_bytes(),
        headers: Vec::new(),
    }
}

fn redirect_answer(location: String, cookies: Vec<String>) -> Answer {
    let mut headers = vec![("location".to_string(), location)];
    for cookie in cookies {
        headers.push(("set-cookie".to_string(), cookie));
    }
    Answer {
        status: 302,
        content_type: "text/plain",
        body: b"Redirecting.\n".to_vec(),
        headers,
    }
}

fn set_cookie(name: &str, value: &str, max_age: u64, secure: bool) -> String {
    let mut cookie = format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn clear_cookie(name: &str, secure: bool) -> String {
    set_cookie(name, "", 0, secure)
}

/// The value of one cookie, if the header carries it.
pub fn cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for part in header.split(';') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if key.trim() == name {
            return Some(value.trim());
        }
    }
    None
}

fn mac(key: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn mac_ok(key: &[u8], payload: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(payload);
    mac.verify_slice(tag).is_ok()
}

fn b64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
        2 => {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    fn val(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let (a, b, c, d) = (
            val(bytes[i])?,
            val(bytes[i + 1])?,
            val(bytes[i + 2])?,
            val(bytes[i + 3])?,
        );
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    match bytes.len() - i {
        0 => {}
        2 => {
            let (a, b) = (val(bytes[i])?, val(bytes[i + 1])?);
            let n = ((a as u32) << 18) | ((b as u32) << 12);
            out.push((n >> 16) as u8);
        }
        3 => {
            let (a, b, c) = (val(bytes[i])?, val(bytes[i + 1])?, val(bytes[i + 2])?);
            let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6);
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
        }
        _ => return None,
    }
    Some(out)
}

struct Unavailable;

impl TokenClient for Unavailable {
    fn post_form(&self, _: &str, _: &str) -> Result<String, String> {
        Err("google sign-in is not configured".to_string())
    }
    fn get_bearer(&self, _: &str, _: &str) -> Result<String, String> {
        Err("google sign-in is not configured".to_string())
    }
}

struct CurlClient;

impl TokenClient for CurlClient {
    fn post_form(&self, url: &str, body: &str) -> Result<String, String> {
        curl_https(url, Some(body), None)
    }
    fn get_bearer(&self, url: &str, access_token: &str) -> Result<String, String> {
        curl_https(url, None, Some(access_token))
    }
}

/// One HTTPS request through the system `curl`. The URL is one of the two
/// constants above; a caller that built it from request data would be an SSRF
/// hole, which is why this function also refuses anything that is not https.
fn curl_https(url: &str, form: Option<&str>, bearer: Option<&str>) -> Result<String, String> {
    if !matches!(url, TOKEN_URL | USERINFO_URL) {
        return Err("refusing a google request to a url this node did not pin".to_string());
    }
    if bearer.is_some_and(|token| token.bytes().any(|b| b.is_ascii_control())) {
        return Err("google returned an access token this node will not send on".to_string());
    }
    let mut command = Command::new("curl");
    command.args([
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--max-time",
        "20",
        "--max-redirs",
        "0",
    ]);
    if form.is_some() {
        command.args([
            "--request",
            "POST",
            "--header",
            "content-type: application/x-www-form-urlencoded",
            "--data-binary",
            "@-",
        ]);
    }
    if let Some(token) = bearer {
        command.arg("--header");
        command.arg(format!("authorization: Bearer {token}"));
    }
    command.arg(url);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "curl is not installed; google sign-in uses it for HTTPS because this crate does not link a TLS stack".to_string()
        } else {
            format!("could not run curl: {error}")
        }
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        if let Some(form) = form {
            stdin
                .write_all(form.as_bytes())
                .map_err(|error| format!("could not write the token request: {error}"))?;
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("curl failed: {error}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "google sign-in request failed ({})",
            one_line(&err, 180)
        ));
    }
    if output.stdout.len() > 65_536 {
        return Err("google's answer was larger than 64 KiB".to_string());
    }
    String::from_utf8(output.stdout).map_err(|_| "google's answer was not utf-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn ready_settings() -> Settings {
        Settings {
            client_id: Some("123-abc.apps.googleusercontent.com".to_string()),
            client_secret: Some("supersecretvalue".to_string()),
            redirect_uri: Some("https://cairn.example/auth/google/callback".to_string()),
            public_url: None,
            cookie_secure: None,
        }
    }

    fn config() -> Config {
        match resolve(ready_settings()) {
            Outcome::Ready(config) => config,
            other => panic!("expected a ready config, got {other:?}"),
        }
    }

    struct Script {
        token: String,
        userinfo: String,
        form: Mutex<String>,
        bearer: Mutex<String>,
    }

    impl TokenClient for Script {
        fn post_form(&self, url: &str, body: &str) -> Result<String, String> {
            assert_eq!(url, TOKEN_URL);
            *self.form.lock().unwrap() = body.to_string();
            Ok(self.token.clone())
        }
        fn get_bearer(&self, url: &str, access_token: &str) -> Result<String, String> {
            assert_eq!(url, USERINFO_URL);
            *self.bearer.lock().unwrap() = access_token.to_string();
            Ok(self.userinfo.clone())
        }
    }

    fn scripted(token: &str, userinfo: &str) -> (GoogleAuth, Arc<Script>) {
        let script = Arc::new(Script {
            token: token.to_string(),
            userinfo: userinfo.to_string(),
            form: Mutex::new(String::new()),
            bearer: Mutex::new(String::new()),
        });
        let auth = GoogleAuth::with_client(config(), [9u8; 32], script.clone());
        (auth, script)
    }

    fn header<'a>(answer: &'a Answer, name: &str) -> &'a str {
        answer
            .headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("no {name} header"))
    }

    fn query_param(url: &str, key: &str) -> String {
        let query = url.split_once('?').map(|(_, query)| query).unwrap_or("");
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if k == key {
                return v.to_string();
            }
        }
        panic!("{key} missing from {url}");
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("cairn-google-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            TempDir { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn unset_is_anonymous_and_stays_that_way() {
        let auth = GoogleAuth::anonymous();
        let status = auth.status(None, 1);
        let body = Value::from_json(std::str::from_utf8(&status.body).unwrap()).unwrap();
        assert_eq!(body.get("required"), Some(&Value::Bool(false)));
        assert_eq!(body.get("anonymous_ok"), Some(&Value::Bool(true)));
        assert_eq!(body.get("available"), Some(&Value::Bool(false)));
        assert_eq!(body.get("authenticated"), Some(&Value::Bool(false)));
        assert_eq!(body.get("mode"), Some(&Value::string("anonymous")));
        assert!(auth.banner().is_none());
        let start = auth.start(None, "/", 1);
        assert_eq!(start.status, 404);
        let logged_out = String::from_utf8(auth.logout().body).unwrap();
        assert!(
            logged_out.contains("anonymous_ok"),
            "logout did not say anonymous use remains: {logged_out}"
        );
    }

    #[test]
    fn a_bad_client_id_does_not_become_a_login() {
        let outcome = resolve(Settings {
            client_id: Some("not-a-google-client".to_string()),
            ..Settings::default()
        });
        assert!(matches!(outcome, Outcome::Misconfigured(_)));
        let outcome = resolve(Settings {
            client_id: Some("123-abc.apps.googleusercontent.com".to_string()),
            redirect_uri: Some("http://cairn.example/auth/google/callback".to_string()),
            ..Settings::default()
        });
        match outcome {
            Outcome::Misconfigured(reason) => assert!(reason.contains("plaintext"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn public_url_builds_the_callback_and_localhost_http_is_allowed() {
        let outcome = resolve(Settings {
            client_id: Some("123-abc.apps.googleusercontent.com".to_string()),
            public_url: Some("https://cairn.example/".to_string()),
            cookie_secure: None,
            ..Settings::default()
        });
        let Outcome::Ready(config) = outcome else {
            panic!("expected ready");
        };
        assert_eq!(
            config.redirect_uri,
            "https://cairn.example/auth/google/callback"
        );
        assert!(config.cookie_secure);

        let outcome = resolve(Settings {
            client_id: Some("123-abc.apps.googleusercontent.com".to_string()),
            redirect_uri: Some("http://127.0.0.1:8080/auth/google/callback".to_string()),
            cookie_secure: None,
            ..Settings::default()
        });
        let Outcome::Ready(config) = outcome else {
            panic!("expected ready");
        };
        assert!(!config.cookie_secure);
    }

    #[test]
    fn pkce_s256_matches_the_rfc_vector() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_authorization_url_carries_pkce_and_not_the_secret() {
        let (auth, _) = scripted("{}", "{}");
        let answer = auth.start(Some("/ui/"), "/", 1_000);
        assert_eq!(answer.status, 302);
        let location = header(&answer, "location");
        assert!(location.starts_with(AUTH_URL), "{location}");
        assert!(
            location.contains("code_challenge_method=S256"),
            "{location}"
        );
        assert!(location.contains("code_challenge="), "{location}");
        assert!(!location.contains("supersecretvalue"), "{location}");
        assert!(!location.contains("client_secret"), "{location}");
        let state = query_param(location, "state");
        let cookie = header(&answer, "set-cookie");
        assert!(
            cookie.contains(&format!("{STATE_COOKIE}={state}")),
            "{cookie}"
        );
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("Secure"), "{cookie}");
    }

    #[test]
    fn next_cannot_leave_the_node() {
        let (auth, _) = scripted("{}", "{}");
        for next in [
            "https://evil.example",
            "//evil.example",
            "/\\evil",
            "/ui/../../etc",
            "/foo:bar",
            "/ok@host",
        ] {
            let answer = auth.start(Some(next), "/ui/", 1);
            assert_eq!(answer.status, 400, "{next}");
        }
        let answer = auth.start(Some("/objectives/?q=1"), "/", 1);
        assert_eq!(answer.status, 302);
    }

    #[test]
    fn callback_signs_in_and_a_second_use_of_the_state_does_not() {
        let (auth, script) = scripted(
            r#"{"access_token":"access-token-1","token_type":"Bearer","expires_in":3600}"#,
            r#"{"sub":"110169484474386276334","name":"Ada Lovelace","email":"ada@example.com","email_verified":true}"#,
        );
        let start = auth.start(Some("/ui/"), "/", 1_000);
        let state = query_param(header(&start, "location"), "state");
        let cookies = format!("{STATE_COOKIE}={state}");
        let done = auth.callback(Some("code-1"), Some(&state), Some(&cookies), 1_010);
        assert_eq!(done.status, 302, "{}", String::from_utf8_lossy(&done.body));
        assert_eq!(header(&done, "location"), "/ui/");
        let form = script.form.lock().unwrap().clone();
        assert!(form.contains("code_verifier="), "{form}");
        assert!(form.contains("client_secret=supersecretvalue"), "{form}");
        assert_eq!(script.bearer.lock().unwrap().as_str(), "access-token-1");
        let session = done
            .headers
            .iter()
            .find(|(_, value)| value.starts_with(SESSION_COOKIE))
            .map(|(_, value)| value.as_str())
            .unwrap();
        let value = session
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;
        let status = auth.status(Some(&format!("{SESSION_COOKIE}={value}")), 1_010);
        let body = Value::from_json(std::str::from_utf8(&status.body).unwrap()).unwrap();
        assert_eq!(body.get("authenticated"), Some(&Value::Bool(true)));
        assert_eq!(body.get("required"), Some(&Value::Bool(false)));
        assert_eq!(
            body.get("account")
                .and_then(|a| a.get("email"))
                .and_then(Value::as_str),
            Some("ada@example.com")
        );
        let again = auth.callback(Some("code-1"), Some(&state), Some(&cookies), 1_010);
        assert_eq!(again.status, 400);

        let mut forged = value.to_string();
        let last = forged.pop().unwrap();
        forged.push(if last == 'a' { 'b' } else { 'a' });
        let forged_status = auth.status(Some(&format!("{SESSION_COOKIE}={forged}")), 1_010);
        let forged_body =
            Value::from_json(std::str::from_utf8(&forged_status.body).unwrap()).unwrap();
        assert_eq!(forged_body.get("authenticated"), Some(&Value::Bool(false)));
    }

    #[test]
    fn the_state_cookie_has_to_be_the_browsers() {
        let (auth, _) = scripted("{}", "{}");
        let start = auth.start(None, "/", 1);
        let state = query_param(header(&start, "location"), "state");
        let answer = auth.callback(
            Some("code"),
            Some(&state),
            Some("cairn_google_state=other"),
            1,
        );
        assert_eq!(answer.status, 400);
        let body = std::str::from_utf8(&answer.body).unwrap();
        assert!(body.contains("state_mismatch"), "{body}");
    }

    #[test]
    fn an_unverified_email_is_not_a_label() {
        let (auth, _) = scripted(
            r#"{"access_token":"access-token-1","expires_in":1}"#,
            r#"{"sub":"abc","email":"ada@example.com","email_verified":false,"name":"Ada\nLovelace"}"#,
        );
        let start = auth.start(None, "/ui/", 50);
        let state = query_param(header(&start, "location"), "state");
        let done = auth.callback(
            Some("code"),
            Some(&state),
            Some(&format!("{STATE_COOKIE}={state}")),
            50,
        );
        assert_eq!(done.status, 302);
        let session = done
            .headers
            .iter()
            .find(|(_, value)| value.starts_with(SESSION_COOKIE))
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap();
        let status = auth.status(Some(session), 50);
        let body = Value::from_json(std::str::from_utf8(&status.body).unwrap()).unwrap();
        let account = body.get("account").unwrap();
        assert_eq!(account.get("email"), Some(&Value::Null));
        assert_eq!(
            account.get("name").and_then(Value::as_str),
            Some("AdaLovelace")
        );
    }

    #[test]
    fn a_session_expires_and_does_not_open_under_another_key() {
        let (auth, _) = scripted(
            r#"{"access_token":"t","expires_in":1}"#,
            r#"{"sub":"abc","email_verified":false}"#,
        );
        let start = auth.start(None, "/", 1_000);
        let state = query_param(header(&start, "location"), "state");
        let done = auth.callback(
            Some("c"),
            Some(&state),
            Some(&format!("{STATE_COOKIE}={state}")),
            1_000,
        );
        let session = done
            .headers
            .iter()
            .find(|(_, value)| value.starts_with(SESSION_COOKIE))
            .unwrap()
            .1
            .clone();
        let still = auth.status(Some(&session), 1_010);
        let still = Value::from_json(std::str::from_utf8(&still.body).unwrap()).unwrap();
        assert_eq!(still.get("authenticated"), Some(&Value::Bool(true)));
        let later = auth.status(Some(&session), 1_000 + SESSION_SECONDS);
        let body = Value::from_json(std::str::from_utf8(&later.body).unwrap()).unwrap();
        assert_eq!(body.get("authenticated"), Some(&Value::Bool(false)));

        let other = GoogleAuth::with_client(config(), [1u8; 32], Arc::new(Unavailable));
        let foreign = other.status(Some(&session), 1_000);
        let foreign = Value::from_json(std::str::from_utf8(&foreign.body).unwrap()).unwrap();
        assert_eq!(foreign.get("authenticated"), Some(&Value::Bool(false)));
    }

    #[test]
    fn logout_clears_the_cookie_and_anonymous_use_needs_none() {
        let (auth, _) = scripted("{}", "{}");
        let answer = auth.logout();
        assert_eq!(answer.status, 200);
        let clears: Vec<_> = answer
            .headers
            .iter()
            .filter(|(name, _)| name == "set-cookie")
            .map(|(_, value)| value.as_str())
            .collect();
        assert!(clears
            .iter()
            .any(|c| c.starts_with("cairn_google=;") && c.contains("Max-Age=0")));
        assert!(clears.iter().any(|c| c.starts_with("cairn_google_state=;")));
    }

    #[test]
    fn the_session_key_is_created_once_and_a_corrupt_file_is_kept() {
        let dir = TempDir::new();
        let first = load_or_create_key(&dir.path).unwrap();
        let second = load_or_create_key(&dir.path).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path.join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(dir.path.join(KEY_FILE), b"short").unwrap();
        let error = load_or_create_key(&dir.path).unwrap_err();
        assert!(error.contains("not 32"), "{error}");
        assert_eq!(std::fs::read(dir.path.join(KEY_FILE)).unwrap(), b"short");
    }

    #[test]
    fn curl_refuses_a_url_it_did_not_pin() {
        let error = curl_https("https://evil.example/token", Some("x"), None).unwrap_err();
        assert!(error.contains("did not pin"), "{error}");
    }
}
