//! Deposit grants: mediated uploads to stranger-owned storage.
//!
//! A **deposit** is a named place to put bytes (a directory, an S3 prefix, …).
//! A **grant** is a short-lived, single-use right to put one object under that
//! deposit's prefix. The node that holds the credentials issues the grant; the
//! contributor never sees the key.
//!
//! Stage A is node-local: deposit configs live under `<data-dir>/deposits/` and
//! credential *values* live in [`crate::secrets`]. Nothing about a deposit
//! enters the log, so two nodes can point the same objective at different
//! buckets. Stage B (pinning the public location on an `Objective`) is designed
//! in `docs/design/deposit-grants.md` and is not yet consensus-critical.
//!
//! # Why not an AWS/GCS SDK
//!
//! `tests/cipher_policy.rs` refuses TLS crates, and every cloud SDK pulls one.
//! Providers here are thin adapters: the `file` backend writes the local disk;
//! the `s3` backend mints a SigV4 query-string URL (pure HMAC-SHA256) and, when
//! the node itself must push bytes, shells out to system `curl` for the HTTPS
//! hop. Adding GCS or Azure is another adapter of the same shape — not a record
//! kind and not a consensus change.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::hex;
use crate::secrets::{self, SecretsError};

type HmacSha256 = Hmac<Sha256>;

/// Default lifetime of a grant, in seconds.
pub const DEFAULT_TTL_SECS: u64 = 15 * 60;

/// Default per-object size cap when a deposit does not name one.
///
/// Large enough for a campaign DP shard demos care about; small enough that a
/// leaked grant cannot fill a funder's bucket in one PUT. Campaign operators
/// that need more raise it on the deposit config.
pub const DEFAULT_MAX_BYTES: u64 = 32 << 20;

/// Hard ceiling on a proxied body through `cairn serve`.
///
/// Presigned S3 uploads bypass the node entirely, so this only bounds the
/// `file` backend and the S3-via-curl proxy path. Larger than
/// [`crate::serve::MAX_BODY_BYTES`] on purpose: a deposit is not a claim.
pub const MAX_PROXY_BYTES: u64 = 64 << 20;

/// Unexpired grants kept at once. Each is a file, and anyone who can reach a
/// node may ask for one, so this is the ceiling on what that costs the disk.
pub const MAX_OUTSTANDING_GRANTS: usize = 1024;

/// A deposit provider. The protocol speaks deposits and grants; these are the
/// adapters that actually move bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// A directory on the node. Demos, tests, air-gapped campaigns.
    File,
    /// An S3 bucket. Credentials from `cairn secret`, never handed out.
    S3,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::File => "file",
            Provider::S3 => "s3",
        }
    }

    pub fn parse(text: &str) -> Option<Provider> {
        match text {
            "file" => Some(Provider::File),
            "s3" => Some(Provider::S3),
            _ => None,
        }
    }
}

/// How the contributor delivers the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadMode {
    /// Contributor → cairn → store. Used by `file`, and by `s3` when the CLI
    /// redeems a grant locally through curl.
    Proxy,
    /// Contributor → store with a short-lived signed URL. Preferred for S3:
    /// the node never sees the body, and no TLS crate enters this binary.
    Presigned,
}

impl UploadMode {
    pub fn as_str(self) -> &'static str {
        match self {
            UploadMode::Proxy => "proxy",
            UploadMode::Presigned => "presigned",
        }
    }

    fn parse(text: &str) -> Option<UploadMode> {
        match text {
            "proxy" => Some(UploadMode::Proxy),
            "presigned" => Some(UploadMode::Presigned),
            _ => None,
        }
    }
}

/// Public configuration for one deposit. Secret *names* only — never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSpec {
    pub name: String,
    pub provider: Provider,
    /// Absolute root for the `file` provider.
    pub root: Option<PathBuf>,
    /// S3 bucket name.
    pub bucket: Option<String>,
    /// Key prefix inside the bucket (no leading slash; trailing slash optional).
    pub prefix: Option<String>,
    /// AWS region, e.g. `us-west-2`.
    pub region: Option<String>,
    /// Secret name for the access key id. Default `AWS_ACCESS_KEY_ID`.
    pub access_key_secret: String,
    /// Secret name for the secret access key. Default `AWS_SECRET_ACCESS_KEY`.
    pub secret_key_secret: String,
    /// Optional session token secret name (temporary credentials).
    pub session_token_secret: Option<String>,
    /// Default max object size for grants against this deposit.
    pub max_bytes: u64,
    /// Default grant lifetime.
    pub ttl_secs: u64,
}

impl DepositSpec {
    /// A `file` deposit writing under `root`.
    pub fn file(name: impl Into<String>, root: impl Into<PathBuf>) -> DepositSpec {
        DepositSpec {
            name: name.into(),
            provider: Provider::File,
            root: Some(root.into()),
            bucket: None,
            prefix: None,
            region: None,
            access_key_secret: String::from("AWS_ACCESS_KEY_ID"),
            secret_key_secret: String::from("AWS_SECRET_ACCESS_KEY"),
            session_token_secret: None,
            max_bytes: DEFAULT_MAX_BYTES,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    /// An `s3` deposit. Secret names default to the usual AWS env spellings.
    pub fn s3(
        name: impl Into<String>,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        region: impl Into<String>,
    ) -> DepositSpec {
        DepositSpec {
            name: name.into(),
            provider: Provider::S3,
            root: None,
            bucket: Some(bucket.into()),
            prefix: Some(normalize_prefix(&prefix.into())),
            region: Some(region.into()),
            access_key_secret: String::from("AWS_ACCESS_KEY_ID"),
            secret_key_secret: String::from("AWS_SECRET_ACCESS_KEY"),
            session_token_secret: None,
            max_bytes: DEFAULT_MAX_BYTES,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    pub fn to_json(&self) -> String {
        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), serde_json::Value::String(self.name.clone()));
        obj.insert(
            "provider".into(),
            serde_json::Value::String(self.provider.as_str().into()),
        );
        if let Some(root) = &self.root {
            obj.insert(
                "root".into(),
                serde_json::Value::String(root.display().to_string()),
            );
        }
        if let Some(bucket) = &self.bucket {
            obj.insert("bucket".into(), serde_json::Value::String(bucket.clone()));
        }
        if let Some(prefix) = &self.prefix {
            obj.insert("prefix".into(), serde_json::Value::String(prefix.clone()));
        }
        if let Some(region) = &self.region {
            obj.insert("region".into(), serde_json::Value::String(region.clone()));
        }
        obj.insert(
            "access_key_secret".into(),
            serde_json::Value::String(self.access_key_secret.clone()),
        );
        obj.insert(
            "secret_key_secret".into(),
            serde_json::Value::String(self.secret_key_secret.clone()),
        );
        if let Some(token) = &self.session_token_secret {
            obj.insert(
                "session_token_secret".into(),
                serde_json::Value::String(token.clone()),
            );
        }
        obj.insert(
            "max_bytes".into(),
            serde_json::Value::Number(self.max_bytes.into()),
        );
        obj.insert(
            "ttl_secs".into(),
            serde_json::Value::Number(self.ttl_secs.into()),
        );
        serde_json::Value::Object(obj).to_string()
    }

    pub fn from_json(text: &str) -> Result<DepositSpec, DepositError> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|source| DepositError::Json {
                context: String::from("deposit config"),
                source,
            })?;
        let obj = value.as_object().ok_or_else(|| {
            DepositError::Invalid(String::from("deposit config must be an object"))
        })?;
        let name = string_field(obj, "name")?;
        if !valid_deposit_name(&name) {
            return Err(DepositError::BadName(name));
        }
        let provider_text = string_field(obj, "provider")?;
        let provider = Provider::parse(&provider_text).ok_or_else(|| {
            DepositError::Invalid(format!(
                "unknown provider {provider_text:?}; expected file or s3"
            ))
        })?;
        let root = optional_string(obj, "root").map(PathBuf::from);
        let bucket = optional_string(obj, "bucket");
        let prefix = optional_string(obj, "prefix").map(|p| normalize_prefix(&p));
        let region = optional_string(obj, "region");
        let access_key_secret = optional_string(obj, "access_key_secret")
            .unwrap_or_else(|| String::from("AWS_ACCESS_KEY_ID"));
        let secret_key_secret = optional_string(obj, "secret_key_secret")
            .unwrap_or_else(|| String::from("AWS_SECRET_ACCESS_KEY"));
        let session_token_secret = optional_string(obj, "session_token_secret");
        let max_bytes = optional_u64(obj, "max_bytes")?.unwrap_or(DEFAULT_MAX_BYTES);
        let ttl_secs = optional_u64(obj, "ttl_secs")?.unwrap_or(DEFAULT_TTL_SECS);
        let spec = DepositSpec {
            name,
            provider,
            root,
            bucket,
            prefix,
            region,
            access_key_secret,
            secret_key_secret,
            session_token_secret,
            max_bytes,
            ttl_secs,
        };
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), DepositError> {
        if !valid_deposit_name(&self.name) {
            return Err(DepositError::BadName(self.name.clone()));
        }
        match self.provider {
            Provider::File => {
                if self.root.is_none() {
                    return Err(DepositError::Invalid(String::from(
                        "file deposit needs a root directory",
                    )));
                }
            }
            Provider::S3 => {
                if self.bucket.as_ref().is_none_or(|b| b.is_empty()) {
                    return Err(DepositError::Invalid(String::from(
                        "s3 deposit needs a bucket",
                    )));
                }
                if self.region.as_ref().is_none_or(|r| r.is_empty()) {
                    return Err(DepositError::Invalid(String::from(
                        "s3 deposit needs a region",
                    )));
                }
            }
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_PROXY_BYTES {
            return Err(DepositError::Invalid(format!(
                "max_bytes must be between 1 and {MAX_PROXY_BYTES}"
            )));
        }
        if self.ttl_secs == 0 {
            return Err(DepositError::Invalid(String::from(
                "ttl_secs must be positive",
            )));
        }
        Ok(())
    }

    /// Public view suitable for CLI / MCP output. Never includes secret values.
    pub fn public_summary(&self) -> String {
        match self.provider {
            Provider::File => format!(
                "{}\n  provider: file\n  root: {}\n  max_bytes: {}\n  ttl_secs: {}",
                self.name,
                self.root
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                self.max_bytes,
                self.ttl_secs,
            ),
            Provider::S3 => format!(
                "{}\n  provider: s3\n  bucket: {}\n  prefix: {}\n  region: {}\n  \
                 access_key_secret: {}\n  secret_key_secret: {}\n  max_bytes: {}\n  ttl_secs: {}",
                self.name,
                self.bucket.as_deref().unwrap_or(""),
                self.prefix.as_deref().unwrap_or(""),
                self.region.as_deref().unwrap_or(""),
                self.access_key_secret,
                self.secret_key_secret,
                self.max_bytes,
                self.ttl_secs,
            ),
        }
    }
}

/// A short-lived right to PUT one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub deposit: String,
    pub submitter: String,
    /// Object key the PUT must use. Minted by the node, not chosen by the uploader.
    pub key: String,
    pub max_bytes: u64,
    /// Optional SHA-256 hex the body must match.
    pub digest: Option<String>,
    pub expires_at: u64,
    pub consumed: bool,
    pub mode: UploadMode,
    /// For [`UploadMode::Presigned`], the signed URL. Absent for proxy grants —
    /// the contributor PUTs to the node's `/deposit/upload/{id}` instead.
    pub put_url: Option<String>,
}

impl Grant {
    pub fn to_json(&self) -> String {
        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), serde_json::Value::String(self.id.clone()));
        obj.insert(
            "deposit".into(),
            serde_json::Value::String(self.deposit.clone()),
        );
        obj.insert(
            "submitter".into(),
            serde_json::Value::String(self.submitter.clone()),
        );
        obj.insert("key".into(), serde_json::Value::String(self.key.clone()));
        obj.insert(
            "max_bytes".into(),
            serde_json::Value::Number(self.max_bytes.into()),
        );
        if let Some(digest) = &self.digest {
            obj.insert("digest".into(), serde_json::Value::String(digest.clone()));
        }
        obj.insert(
            "expires_at".into(),
            serde_json::Value::Number(self.expires_at.into()),
        );
        obj.insert("consumed".into(), serde_json::Value::Bool(self.consumed));
        obj.insert(
            "mode".into(),
            serde_json::Value::String(self.mode.as_str().into()),
        );
        if let Some(url) = &self.put_url {
            obj.insert("put_url".into(), serde_json::Value::String(url.clone()));
        }
        serde_json::Value::Object(obj).to_string()
    }

    /// Contributor-facing view: never includes cloud keys, and for proxy mode
    /// names the relative upload path the serve endpoint answers.
    pub fn public_response(&self, proxy_base: Option<&str>) -> serde_json::Value {
        let put_url = match self.mode {
            UploadMode::Presigned => self.put_url.clone().unwrap_or_default(),
            UploadMode::Proxy => match proxy_base {
                Some(base) => format!("{}/deposit/upload/{}", base.trim_end_matches('/'), self.id),
                None => format!("/deposit/upload/{}", self.id),
            },
        };
        let mut obj = serde_json::Map::new();
        obj.insert(
            "grant_id".into(),
            serde_json::Value::String(self.id.clone()),
        );
        obj.insert(
            "deposit".into(),
            serde_json::Value::String(self.deposit.clone()),
        );
        obj.insert("key".into(), serde_json::Value::String(self.key.clone()));
        obj.insert(
            "max_bytes".into(),
            serde_json::Value::Number(self.max_bytes.into()),
        );
        obj.insert(
            "expires_at".into(),
            serde_json::Value::Number(self.expires_at.into()),
        );
        obj.insert(
            "mode".into(),
            serde_json::Value::String(self.mode.as_str().into()),
        );
        obj.insert("put_url".into(), serde_json::Value::String(put_url));
        if let Some(digest) = &self.digest {
            obj.insert("digest".into(), serde_json::Value::String(digest.clone()));
        }
        serde_json::Value::Object(obj)
    }

    fn from_json(text: &str) -> Result<Grant, DepositError> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|source| DepositError::Json {
                context: String::from("grant"),
                source,
            })?;
        let obj = value
            .as_object()
            .ok_or_else(|| DepositError::Invalid(String::from("grant must be an object")))?;
        let mode_text = string_field(obj, "mode")?;
        let mode = UploadMode::parse(&mode_text)
            .ok_or_else(|| DepositError::Invalid(format!("unknown upload mode {mode_text:?}")))?;
        Ok(Grant {
            id: string_field(obj, "id")?,
            deposit: string_field(obj, "deposit")?,
            submitter: string_field(obj, "submitter")?,
            key: string_field(obj, "key")?,
            max_bytes: optional_u64(obj, "max_bytes")?
                .ok_or_else(|| DepositError::Invalid(String::from("grant missing max_bytes")))?,
            digest: optional_string(obj, "digest"),
            expires_at: optional_u64(obj, "expires_at")?
                .ok_or_else(|| DepositError::Invalid(String::from("grant missing expires_at")))?,
            consumed: obj
                .get("consumed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            mode,
            put_url: optional_string(obj, "put_url"),
        })
    }
}

/// Proof that a grant was redeemed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub grant_id: String,
    pub deposit: String,
    pub key: String,
    pub bytes: u64,
    pub digest: String,
}

impl Receipt {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "grant_id": self.grant_id,
            "deposit": self.deposit,
            "key": self.key,
            "bytes": self.bytes,
            "digest": self.digest,
        })
        .to_string()
    }
}

/// On-disk layout for deposit configs and outstanding grants.
///
/// ```text
/// <dir>/<name>.json          public DepositSpec
/// <dir>/.grants/<id>.json    outstanding / consumed grants
/// ```
#[derive(Debug, Clone)]
pub struct DepositDir {
    dir: PathBuf,
}

impl DepositDir {
    pub fn at(dir: impl Into<PathBuf>) -> DepositDir {
        DepositDir { dir: dir.into() }
    }

    /// Default location beside a node's data: `<store-root>/deposits`.
    pub fn under_store(store_root: impl AsRef<Path>) -> DepositDir {
        DepositDir::at(store_root.as_ref().join("deposits"))
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    pub fn prepare(&self) -> Result<(), DepositError> {
        fs::create_dir_all(&self.dir).map_err(|source| DepositError::Io {
            context: format!("creating {}", self.dir.display()),
            source,
        })?;
        fs::create_dir_all(self.grants_dir()).map_err(|source| DepositError::Io {
            context: format!("creating {}", self.grants_dir().display()),
            source,
        })?;
        Ok(())
    }

    fn grants_dir(&self) -> PathBuf {
        self.dir.join(".grants")
    }

    fn spec_path(&self, name: &str) -> Result<PathBuf, DepositError> {
        if !valid_deposit_name(name) {
            return Err(DepositError::BadName(name.to_string()));
        }
        Ok(self.dir.join(format!("{name}.json")))
    }

    fn grant_path(&self, id: &str) -> Result<PathBuf, DepositError> {
        if !valid_grant_id(id) {
            return Err(DepositError::Invalid(format!("bad grant id {id:?}")));
        }
        Ok(self.grants_dir().join(format!("{id}.json")))
    }

    /// Write or replace a deposit config. Secret *names* only.
    pub fn add(&self, spec: &DepositSpec) -> Result<PathBuf, DepositError> {
        spec.validate()?;
        self.prepare()?;
        let path = self.spec_path(&spec.name)?;
        let body = spec.to_json();
        write_atomic(&path, body.as_bytes())?;
        Ok(path)
    }

    pub fn load(&self, name: &str) -> Result<DepositSpec, DepositError> {
        let path = self.spec_path(name)?;
        if !path.exists() {
            return Err(DepositError::MissingDeposit(name.to_string()));
        }
        let text = fs::read_to_string(&path).map_err(|source| DepositError::Io {
            context: format!("reading {}", path.display()),
            source,
        })?;
        DepositSpec::from_json(&text)
    }

    /// Names of configured deposits, sorted.
    pub fn list(&self) -> Result<Vec<String>, DepositError> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|source| DepositError::Io {
            context: format!("listing {}", self.dir.display()),
            source,
        })? {
            let entry = entry.map_err(|source| DepositError::Io {
                context: format!("listing {}", self.dir.display()),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if valid_deposit_name(stem) {
                    names.push(stem.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn save_grant(&self, grant: &Grant) -> Result<(), DepositError> {
        self.prepare()?;
        let path = self.grant_path(&grant.id)?;
        write_atomic(&path, grant.to_json().as_bytes())
    }

    /// Delete grants past their expiry, and say how many unexpired remain.
    /// A grant that will not parse is left alone and counted: nothing here
    /// deletes a file it cannot read.
    pub fn prune_grants(&self, now: u64) -> Result<usize, DepositError> {
        let dir = self.grants_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(source) => {
                return Err(DepositError::Io {
                    context: format!("listing {}", dir.display()),
                    source,
                })
            }
        };
        let mut live = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let expired = fs::read_to_string(&path)
                .ok()
                .and_then(|text| Grant::from_json(&text).ok())
                .is_some_and(|grant| now > grant.expires_at);
            if expired {
                let _ = fs::remove_file(&path);
            } else {
                live += 1;
            }
        }
        Ok(live)
    }

    pub fn load_grant(&self, id: &str) -> Result<Grant, DepositError> {
        let path = self.grant_path(id)?;
        if !path.exists() {
            return Err(DepositError::MissingGrant(id.to_string()));
        }
        let text = fs::read_to_string(&path).map_err(|source| DepositError::Io {
            context: format!("reading {}", path.display()),
            source,
        })?;
        Grant::from_json(&text)
    }
}

/// Issue a grant against a configured deposit.
///
/// `proxy_base` is the public origin of this node (e.g. `http://host:8080`)
/// used to fill `put_url` for proxy mode. For S3, a presigned URL is minted
/// and `mode` is [`UploadMode::Presigned`].
pub fn issue_grant(
    deposits: &DepositDir,
    deposit_name: &str,
    submitter: &str,
    max_bytes: Option<u64>,
    digest: Option<&str>,
    proxy_base: Option<&str>,
    secrets_dir: &Path,
) -> Result<Grant, DepositError> {
    let spec = deposits.load(deposit_name)?;
    if submitter.is_empty() || submitter.len() > 128 {
        return Err(DepositError::Invalid(String::from(
            "submitter must be 1..=128 characters",
        )));
    }
    if submitter.contains('/') || submitter.contains('\\') || submitter.contains("..") {
        return Err(DepositError::Invalid(String::from(
            "submitter must not contain path separators",
        )));
    }
    let max_bytes = max_bytes.unwrap_or(spec.max_bytes);
    if max_bytes == 0 || max_bytes > spec.max_bytes {
        return Err(DepositError::Invalid(format!(
            "max_bytes must be between 1 and {} for this deposit",
            spec.max_bytes
        )));
    }
    if let Some(digest) = digest {
        if hex::decode(digest).as_ref().map(|b| b.len()) != Some(32) {
            return Err(DepositError::Invalid(String::from(
                "digest must be 64 lowercase hex characters (sha-256)",
            )));
        }
    }

    // `POST /deposit/grant` is open to anyone who can reach the node, and
    // each grant is a file. Expired grants are deleted here, and past a
    // ceiling of live ones the answer is "come back later", so a loop of
    // requests cannot fill the disk.
    if deposits.prune_grants(now_secs())? >= MAX_OUTSTANDING_GRANTS {
        return Err(DepositError::Unavailable(format!(
            "{MAX_OUTSTANDING_GRANTS} grants are outstanding; try again once some expire"
        )));
    }

    let mut id_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut id_bytes);
    let id = hex::encode(&id_bytes);
    let submitter_short = short_submitter(submitter);
    let prefix = spec.prefix.as_deref().unwrap_or("");
    let key = format!("{prefix}{}/{}/{id}", spec.name, submitter_short,);

    let expires_at = now_secs().saturating_add(spec.ttl_secs);
    let (mode, put_url) = match spec.provider {
        Provider::File => (UploadMode::Proxy, None),
        Provider::S3 => {
            let url = presign_s3_put(&spec, &key, max_bytes, expires_at, secrets_dir)?;
            (UploadMode::Presigned, Some(url))
        }
    };

    let grant = Grant {
        id,
        deposit: spec.name.clone(),
        submitter: submitter.to_string(),
        key,
        max_bytes,
        digest: digest.map(str::to_string),
        expires_at,
        consumed: false,
        mode,
        put_url,
    };
    deposits.save_grant(&grant)?;
    // Rebuild with proxy put_url filled for the caller convenience; disk keeps
    // the raw grant (put_url already set for presigned).
    let mut response = grant;
    if response.mode == UploadMode::Proxy {
        response.put_url = Some(match proxy_base {
            Some(base) => format!(
                "{}/deposit/upload/{}",
                base.trim_end_matches('/'),
                response.id
            ),
            None => format!("/deposit/upload/{}", response.id),
        });
    }
    Ok(response)
}

/// Write an upload body to a fresh private file in the temp directory.
fn staged_upload(body: &[u8]) -> Result<PathBuf, DepositError> {
    let io_error = |source| DepositError::Io {
        context: String::from("staging an s3 upload"),
        source,
    };
    for _ in 0..16 {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let path = std::env::temp_dir().join(format!(
            "cairn-deposit-put-{}-{}",
            std::process::id(),
            hex::encode(&random)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                use std::io::Write as _;
                if let Err(source) = file.write_all(body).and_then(|()| file.sync_all()) {
                    let _ = fs::remove_file(&path);
                    return Err(io_error(source));
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error(source)),
        }
    }
    Err(io_error(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a staging file",
    )))
}

/// Redeem a grant by writing `body` through the deposit's provider.
///
/// For `file`, writes the local path. For `s3`, shells out to `curl` against
/// the grant's presigned URL (or mints a fresh one if the grant was proxy —
/// Stage A always presigns S3 at issue time). Consumes the grant on success.
pub fn redeem_grant(
    deposits: &DepositDir,
    grant_id: &str,
    body: &[u8],
    secrets_dir: &Path,
) -> Result<Receipt, DepositError> {
    let mut grant = deposits.load_grant(grant_id)?;
    if grant.consumed {
        return Err(DepositError::Consumed(grant.id));
    }
    let now = now_secs();
    if now > grant.expires_at {
        return Err(DepositError::Expired(grant.id));
    }
    if body.len() as u64 > grant.max_bytes {
        return Err(DepositError::TooLarge {
            got: body.len() as u64,
            max: grant.max_bytes,
        });
    }
    let digest = hex::encode(&Sha256::digest(body));
    if let Some(expected) = &grant.digest {
        if expected != &digest {
            return Err(DepositError::DigestMismatch {
                expected: expected.clone(),
                got: digest,
            });
        }
    }

    let spec = deposits.load(&grant.deposit)?;
    match spec.provider {
        Provider::File => {
            let root = spec
                .root
                .as_ref()
                .ok_or_else(|| DepositError::Invalid(String::from("file deposit missing root")))?;
            put_file(root, &grant.key, body)?;
        }
        Provider::S3 => {
            let url = match &grant.put_url {
                Some(url) => url.clone(),
                None => presign_s3_put(
                    &spec,
                    &grant.key,
                    grant.max_bytes,
                    grant.expires_at,
                    secrets_dir,
                )?,
            };
            curl_put(&url, body)?;
        }
    }

    grant.consumed = true;
    deposits.save_grant(&grant)?;
    Ok(Receipt {
        grant_id: grant.id,
        deposit: grant.deposit,
        key: grant.key,
        bytes: body.len() as u64,
        digest,
    })
}

fn put_file(root: &Path, key: &str, body: &[u8]) -> Result<(), DepositError> {
    // Refuse path escape: the key is minted by us, but defend the write site
    // anyway so a corrupted grant file cannot write outside the root.
    if key.contains("..") || Path::new(key).is_absolute() {
        return Err(DepositError::Invalid(String::from(
            "object key must be a relative path without ..",
        )));
    }
    let dest = root.join(key);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|source| DepositError::Io {
            context: format!("creating {}", parent.display()),
            source,
        })?;
    }
    write_atomic(&dest, body)
}

/// Mint a SigV4 query-string pre-signed PUT URL for `key`.
///
/// `max_bytes` is recorded on the grant and enforced when this node proxies
/// the body; it is not bound into the signature because the body length is
/// not known at issue time, and signing a guessed `Content-Length` would
/// reject every honest smaller PUT. A future Stage A follow-up can switch
/// S3 to a POST policy with `content-length-range` for hard cloud-side caps.
fn presign_s3_put(
    spec: &DepositSpec,
    key: &str,
    _max_bytes: u64,
    expires_at: u64,
    secrets_dir: &Path,
) -> Result<String, DepositError> {
    let bucket = spec
        .bucket
        .as_deref()
        .ok_or_else(|| DepositError::Invalid(String::from("s3 deposit missing bucket")))?;
    let region = spec
        .region
        .as_deref()
        .ok_or_else(|| DepositError::Invalid(String::from("s3 deposit missing region")))?;
    let access_key = secrets::get(secrets_dir, &spec.access_key_secret).map_err(map_secrets)?;
    let secret_key = secrets::get(secrets_dir, &spec.secret_key_secret).map_err(map_secrets)?;
    let session_token = match &spec.session_token_secret {
        Some(name) => Some(secrets::get(secrets_dir, name).map_err(map_secrets)?),
        None => None,
    };

    let now = now_secs();
    let expires_in = expires_at.saturating_sub(now).max(1);
    // Cap at seven days, AWS's own limit for query-string auth with IAM keys.
    let expires_in = expires_in.min(7 * 24 * 60 * 60);

    let amz_date = amz_date_time(now);
    let date_stamp = &amz_date[..8];
    let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let credential = format!("{access_key}/{credential_scope}");

    let host = format!("{bucket}.s3.{region}.amazonaws.com");
    let canonical_uri = format!(
        "/{}",
        key.split('/')
            .map(percent_encode)
            .collect::<Vec<_>>()
            .join("/")
    );

    let mut query: Vec<(String, String)> = vec![
        ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
        ("X-Amz-Credential".into(), credential),
        ("X-Amz-Date".into(), amz_date.clone()),
        ("X-Amz-Expires".into(), expires_in.to_string()),
        ("X-Amz-SignedHeaders".into(), "host".into()),
    ];
    if let Some(token) = &session_token {
        query.push(("X-Amz-Security-Token".into(), token.clone()));
    }
    query.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_headers = format!("host:{host}\n");
    let signed_headers = "host";
    let canonical_request = format!(
        "PUT\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD"
    );
    let canonical_hash = hex::encode(&Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}");
    let signing_key = aws_signing_key(secret_key.as_bytes(), date_stamp, region, "s3");
    let mut mac = HmacSha256::new_from_slice(&signing_key).expect("HMAC accepts any key length");
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(&mac.finalize().into_bytes());

    Ok(format!(
        "https://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}"
    ))
}

/// Derive an AWS SigV4 signing key. Pure HMAC — no network, no TLS.
pub fn aws_signing_key(secret: &[u8], date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let mut k_date = HmacSha256::new_from_slice(&[b"AWS4", secret].concat())
        .expect("HMAC accepts any key length");
    k_date.update(date_stamp.as_bytes());
    let k_date = k_date.finalize().into_bytes();

    let mut k_region = HmacSha256::new_from_slice(&k_date).expect("HMAC");
    k_region.update(region.as_bytes());
    let k_region = k_region.finalize().into_bytes();

    let mut k_service = HmacSha256::new_from_slice(&k_region).expect("HMAC");
    k_service.update(service.as_bytes());
    let k_service = k_service.finalize().into_bytes();

    let mut k_signing = HmacSha256::new_from_slice(&k_service).expect("HMAC");
    k_signing.update(b"aws4_request");
    k_signing.finalize().into_bytes().to_vec()
}

fn curl_put(url: &str, body: &[u8]) -> Result<(), DepositError> {
    // Temp file rather than stdin: some curl builds buffer differently, and a
    // named file makes Content-Length unambiguous for the presigned binding.
    // A random name created exclusively at 0600: `pid-seconds` was shared by
    // two uploads redeemed in the same second (one stored the other's
    // bytes), and predictable in a shared /tmp.
    let tmp = staged_upload(body)?;
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--request",
            "PUT",
            "--upload-file",
        ])
        .arg(&tmp)
        .arg("--header")
        .arg(format!("Content-Length: {}", body.len()))
        .arg(url)
        .output()
        .map_err(|source| DepositError::Io {
            context: String::from("running curl for s3 PUT"),
            source,
        });
    let _ = fs::remove_file(&tmp);
    let output = output?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DepositError::Unavailable(format!(
            "s3 PUT via curl failed (is curl installed, and are the credentials valid?): {stderr}"
        )));
    }
    Ok(())
}

fn map_secrets(error: SecretsError) -> DepositError {
    match error {
        SecretsError::Missing(name) => DepositError::Unavailable(format!(
            "secret {name:?} is not set; configure it with `cairn secret set` \
             before issuing grants against this deposit"
        )),
        other => DepositError::Invalid(other.to_string()),
    }
}

/// Deposit names are filesystem-safe identifiers.
pub fn valid_deposit_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') && name.len() <= 64
}

fn valid_grant_id(id: &str) -> bool {
    id.len() == 64 && hex::decode(id).is_some()
}

fn short_submitter(submitter: &str) -> String {
    // Keep the path short and free of characters S3 / filesystems dislike.
    let cleaned: String = submitter
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    if cleaned.is_empty() {
        String::from("anon")
    } else {
        cleaned
    }
}

fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_start_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.ends_with('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/")
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn amz_date_time(secs: u64) -> String {
    // YYYYMMDD'T'HHMMSS'Z' without pulling in a time crate.
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}{month:02}{day:02}T{hour:02}{min:02}{sec:02}Z")
}

/// Days since Unix epoch → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(*byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), DepositError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| DepositError::Io {
        context: format!("creating {}", parent.display()),
        source,
    })?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("deposit"),
        std::process::id()
    ));
    {
        let mut file = fs::File::create(&tmp).map_err(|source| DepositError::Io {
            context: format!("writing {}", tmp.display()),
            source,
        })?;
        file.write_all(bytes).map_err(|source| DepositError::Io {
            context: format!("writing {}", tmp.display()),
            source,
        })?;
        file.sync_all().map_err(|source| DepositError::Io {
            context: format!("syncing {}", tmp.display()),
            source,
        })?;
    }
    fs::rename(&tmp, path).map_err(|source| DepositError::Io {
        context: format!("renaming {} -> {}", tmp.display(), path.display()),
        source,
    })
}

fn string_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, DepositError> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| DepositError::Invalid(format!("missing string field {key:?}")))
}

fn optional_string(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

fn optional_u64(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<u64>, DepositError> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| DepositError::Invalid(format!("{key} is not a u64")))
            .map(Some),
        Some(_) => Err(DepositError::Invalid(format!("{key} is not a number"))),
    }
}

#[derive(Debug)]
pub enum DepositError {
    BadName(String),
    MissingDeposit(String),
    MissingGrant(String),
    Expired(String),
    Consumed(String),
    TooLarge {
        got: u64,
        max: u64,
    },
    DigestMismatch {
        expected: String,
        got: String,
    },
    /// The node cannot serve this grant right now (missing credentials, curl
    /// missing, …). Distinct from a refusal: retry may help.
    Unavailable(String),
    Invalid(String),
    Json {
        context: String,
        source: serde_json::Error,
    },
    Io {
        context: String,
        source: io::Error,
    },
}

impl std::fmt::Display for DepositError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DepositError::BadName(name) => write!(
                f,
                "deposit name {name:?} must match [A-Za-z0-9][A-Za-z0-9_-]{{0,63}}"
            ),
            DepositError::MissingDeposit(name) => {
                write!(f, "deposit {name:?} is not configured on this node")
            }
            DepositError::MissingGrant(id) => write!(f, "grant {id:?} is unknown"),
            DepositError::Expired(id) => write!(
                f,
                "grant {id:?} has expired; request a new one with deposit grant / request_upload_grant"
            ),
            DepositError::Consumed(id) => write!(
                f,
                "grant {id:?} was already used; grants are single-use"
            ),
            DepositError::TooLarge { got, max } => {
                write!(f, "body is {got} bytes; grant allows at most {max}")
            }
            DepositError::DigestMismatch { expected, got } => {
                write!(f, "body digest {got} does not match grant digest {expected}")
            }
            DepositError::Unavailable(message) => write!(f, "unavailable: {message}"),
            DepositError::Invalid(message) => write!(f, "{message}"),
            DepositError::Json { context, source } => write!(f, "{context}: {source}"),
            DepositError::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for DepositError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DepositError::Json { source, .. } => Some(source),
            DepositError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-deposit-{}-{name}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn deposit_names_are_path_safe() {
        assert!(valid_deposit_name("ecc2k130-campaign"));
        assert!(valid_deposit_name("a"));
        assert!(!valid_deposit_name(""));
        assert!(!valid_deposit_name("../x"));
        assert!(!valid_deposit_name("a/b"));
        assert!(!valid_deposit_name("-bad"));
    }

    #[test]
    fn expired_grants_are_deleted_and_live_ones_counted() {
        let root = scratch("prune-root");
        let dir = DepositDir::at(scratch("prune-cfg"));
        let secrets = scratch("prune-secrets");
        secrets::prepare(&secrets).unwrap();
        dir.add(&DepositSpec::file("demo", &root)).unwrap();
        let live = issue_grant(&dir, "demo", "alice", None, None, None, &secrets).unwrap();
        let mut stale = issue_grant(&dir, "demo", "bob", None, None, None, &secrets).unwrap();
        stale.expires_at = 1;
        stale.put_url = None;
        dir.save_grant(&stale).unwrap();

        assert_eq!(dir.prune_grants(now_secs()).unwrap(), 1);
        assert!(dir.load_grant(&live.id).is_ok());
        assert!(matches!(
            dir.load_grant(&stale.id),
            Err(DepositError::MissingGrant(_))
        ));
    }

    #[test]
    fn upload_staging_files_are_private_and_never_shared() {
        let first = staged_upload(b"one").unwrap();
        let second = staged_upload(b"two").unwrap();
        assert_ne!(first, second, "two uploads in one second shared a file");
        assert_eq!(fs::read(&first).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&first).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_file(first);
        let _ = fs::remove_file(second);
    }

    #[test]
    fn file_deposit_grant_and_put_round_trip() {
        let root = scratch("file-root");
        let dir = DepositDir::at(scratch("cfg"));
        let secrets = scratch("secrets");
        secrets::prepare(&secrets).unwrap();

        let spec = DepositSpec::file("demo", &root);
        dir.add(&spec).unwrap();

        let grant = issue_grant(
            &dir,
            "demo",
            "alice",
            Some(1024),
            None,
            Some("http://127.0.0.1:8080"),
            &secrets,
        )
        .unwrap();
        assert_eq!(grant.mode, UploadMode::Proxy);
        assert!(grant
            .put_url
            .as_deref()
            .unwrap()
            .contains("/deposit/upload/"));
        assert!(grant.key.starts_with("demo/alice/"));

        let body = b"distinguished-points";
        let receipt = redeem_grant(&dir, &grant.id, body, &secrets).unwrap();
        assert_eq!(receipt.bytes, body.len() as u64);
        assert_eq!(receipt.digest, hex::encode(&Sha256::digest(body)));

        let written = fs::read(root.join(&grant.key)).unwrap();
        assert_eq!(written, body);

        // Single use.
        assert!(matches!(
            redeem_grant(&dir, &grant.id, body, &secrets),
            Err(DepositError::Consumed(_))
        ));

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn digest_binding_refuses_a_different_body() {
        let root = scratch("digest-root");
        let dir = DepositDir::at(scratch("digest-cfg"));
        let secrets = scratch("digest-secrets");
        secrets::prepare(&secrets).unwrap();
        dir.add(&DepositSpec::file("d", &root)).unwrap();

        let want = hex::encode(&Sha256::digest(b"right"));
        let grant = issue_grant(&dir, "d", "bob", Some(64), Some(&want), None, &secrets).unwrap();
        assert!(matches!(
            redeem_grant(&dir, &grant.id, b"wrong", &secrets),
            Err(DepositError::DigestMismatch { .. })
        ));
        redeem_grant(&dir, &grant.id, b"right", &secrets).unwrap();

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn oversized_put_is_refused() {
        let root = scratch("size-root");
        let dir = DepositDir::at(scratch("size-cfg"));
        let secrets = scratch("size-secrets");
        secrets::prepare(&secrets).unwrap();
        dir.add(&DepositSpec::file("d", &root)).unwrap();
        let grant = issue_grant(&dir, "d", "c", Some(4), None, None, &secrets).unwrap();
        assert!(matches!(
            redeem_grant(&dir, &grant.id, b"12345", &secrets),
            Err(DepositError::TooLarge { .. })
        ));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn s3_grant_needs_credentials_and_presigns() {
        let dir = DepositDir::at(scratch("s3-cfg"));
        let secrets = scratch("s3-secrets");
        secrets::prepare(&secrets).unwrap();
        dir.add(&DepositSpec::s3(
            "camp",
            "ecc2k130-example",
            "dp/",
            "us-west-2",
        ))
        .unwrap();

        // Missing secrets → unavailable, not a panic and not a refusal that
        // looks like the artifact is wrong.
        let err = issue_grant(&dir, "camp", "alice", None, None, None, &secrets).unwrap_err();
        assert!(matches!(err, DepositError::Unavailable(_)), "{err}");

        secrets::set(&secrets, "AWS_ACCESS_KEY_ID", "AKIAEXAMPLEKEY00000").unwrap();
        secrets::set(
            &secrets,
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        .unwrap();

        let grant = issue_grant(&dir, "camp", "alice", Some(1024), None, None, &secrets).unwrap();
        assert_eq!(grant.mode, UploadMode::Presigned);
        let url = grant.put_url.as_deref().unwrap();
        assert!(url.starts_with("https://ecc2k130-example.s3.us-west-2.amazonaws.com/"));
        assert!(url.contains("X-Amz-Signature="));
        assert!(url.contains("dp/camp/alice/"));
        // No secret material in the URL beyond the signature of a request.
        assert!(!url.contains("wJalrXUtnFEMI"));

        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn aws_signing_key_matches_the_aws_example() {
        // From https://docs.aws.amazon.com/IAM/latest/UserGuide/signature-v4-examples.html
        // (Signing key derivation example). A round-trip alone would pass for
        // any self-consistent HMAC; this pins the bytes against AWS's vector.
        let key = aws_signing_key(
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(&key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[test]
    fn public_summary_never_embeds_secret_values() {
        let spec = DepositSpec::s3("x", "bucket", "p/", "eu-west-1");
        let summary = spec.public_summary();
        assert!(summary.contains("AWS_ACCESS_KEY_ID"));
        assert!(!summary.contains("AKIA"));
        let json = spec.to_json();
        assert!(json.contains("access_key_secret"));
        assert!(!json.contains("wJalr"));
    }

    #[test]
    fn list_and_load_round_trip() {
        let dir = DepositDir::at(scratch("list"));
        dir.add(&DepositSpec::file("a", scratch("a-root"))).unwrap();
        dir.add(&DepositSpec::file("b", scratch("b-root"))).unwrap();
        assert_eq!(dir.list().unwrap(), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(dir.load("a").unwrap().provider, Provider::File);
        let _ = fs::remove_dir_all(dir.path());
    }
}
