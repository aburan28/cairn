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

/// Unexpired grants one network address may hold. Without it, one requester
/// could take all [`MAX_OUTSTANDING_GRANTS`] and leave nobody else a grant
/// until they expired. Loopback is the operator and is not counted.
pub const MAX_GRANTS_PER_ADDRESS: usize = 64;

/// What a contributor asks a grant for.
#[derive(Debug, Clone, Copy, Default)]
pub struct GrantRequest<'a> {
    pub deposit: &'a str,
    pub submitter: &'a str,
    /// A ceiling below the deposit's own. `None` takes the deposit's.
    pub max_bytes: Option<u64>,
    /// The exact length of the object, when the contributor knows it.
    pub size: Option<u64>,
    /// SHA-256 hex the object must have, when the contributor knows it.
    pub digest: Option<&'a str>,
    /// Campaign slot the object belongs to. Required by [`KeyShape::Ecc2kDp`]
    /// deposits, refused by all others.
    pub slot: Option<u64>,
    /// The network address asking, for [`MAX_GRANTS_PER_ADDRESS`]. `None` from
    /// the CLI and MCP, which run as the operator.
    pub requester: Option<&'a str>,
}

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

/// The shape of keys a deposit mints. Keys are always minted, never chosen,
/// so an uploader cannot overwrite or squat another object; the shape only
/// decides what the minted key looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyShape {
    /// `{prefix}{deposit}/{submitter}/{random-id}`. Opaque to everyone but
    /// the node that minted it.
    #[default]
    Default,
    /// `dp/slot-N/<stream>-<offset>-<sha>.bin`: the ECC2K-130 campaign's
    /// content-keyed shape, as `dp_ingest.py`'s `ORBIT_KEY_RE` defines it.
    /// The stream id is minted random per grant and the sha-256 is the
    /// body's own, so the key stays unguessable while telling the ingester
    /// which slot produced it and what bytes to expect. Grants against this
    /// shape require a slot and a digest, and redemption writes the
    /// `.bin.json` commit marker beside the body.
    Ecc2kDp,
}

impl KeyShape {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyShape::Default => "default",
            KeyShape::Ecc2kDp => "ecc2k-dp",
        }
    }

    pub fn parse(text: &str) -> Option<KeyShape> {
        match text {
            "default" => Some(KeyShape::Default),
            "ecc2k-dp" => Some(KeyShape::Ecc2kDp),
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
    /// The shape of keys grants mint. See [`KeyShape`].
    pub key_shape: KeyShape,
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
            key_shape: KeyShape::Default,
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
            key_shape: KeyShape::Default,
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
        // Always written, so a config says what it mints. Read back leniently:
        // configs written before shapes existed mean the default one.
        obj.insert(
            "key_shape".into(),
            serde_json::Value::String(self.key_shape.as_str().into()),
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
        let key_shape = match optional_string(obj, "key_shape") {
            None => KeyShape::Default,
            Some(text) => KeyShape::parse(&text).ok_or_else(|| {
                DepositError::Invalid(format!(
                    "unknown key_shape {text:?}; expected default or ecc2k-dp"
                ))
            })?,
        };
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
            key_shape,
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
        if self.key_shape == KeyShape::Ecc2kDp && self.prefix.as_deref().unwrap_or("").is_empty() {
            // The ingester lists `dp/`; keys minted outside it would land in
            // the bucket and never be read. Refused here, where the fix is a
            // flag, rather than discovered as objects the campaign ignores.
            return Err(DepositError::Invalid(String::from(
                "an ecc2k-dp deposit needs a key prefix (the campaign lists dp/)",
            )));
        }
        Ok(())
    }

    /// Public view suitable for CLI / MCP output. Never includes secret values.
    pub fn public_summary(&self) -> String {
        match self.provider {
            Provider::File => format!(
                "{}\n  provider: file\n  root: {}\n  max_bytes: {}\n  ttl_secs: {}\n  key_shape: {}",
                self.name,
                self.root
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                self.max_bytes,
                self.ttl_secs,
                self.key_shape.as_str(),
            ),
            Provider::S3 => format!(
                "{}\n  provider: s3\n  bucket: {}\n  prefix: {}\n  region: {}\n  \
                 access_key_secret: {}\n  secret_key_secret: {}\n  max_bytes: {}\n  ttl_secs: {}\n  \
                 key_shape: {}",
                self.name,
                self.bucket.as_deref().unwrap_or(""),
                self.prefix.as_deref().unwrap_or(""),
                self.region.as_deref().unwrap_or(""),
                self.access_key_secret,
                self.secret_key_secret,
                self.max_bytes,
                self.ttl_secs,
                self.key_shape.as_str(),
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
    /// Optional exact length the body must have.
    pub size: Option<u64>,
    /// The address that asked, when it was a remote one. Kept on disk only, to
    /// count against [`MAX_GRANTS_PER_ADDRESS`]; never in a response.
    pub issued_to: Option<String>,
    pub expires_at: u64,
    pub consumed: bool,
    pub mode: UploadMode,
    /// For [`UploadMode::Presigned`], the signed URL. Absent for proxy grants —
    /// the contributor PUTs to the node's `/deposit/upload/{id}` instead.
    pub put_url: Option<String>,
    /// For presigned grants against [`KeyShape::Ecc2kDp`], the signed URL for
    /// the `.bin.json` commit marker the contributor PUTs after the body, and
    /// the marker bytes it must carry. Absent otherwise: proxy redemptions
    /// write the marker themselves, and other shapes have no marker.
    pub marker_put_url: Option<String>,
    pub marker: Option<String>,
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
        if let Some(size) = self.size {
            obj.insert("size".into(), serde_json::Value::Number(size.into()));
        }
        if let Some(address) = &self.issued_to {
            obj.insert(
                "issued_to".into(),
                serde_json::Value::String(address.clone()),
            );
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
        if let Some(url) = &self.marker_put_url {
            obj.insert(
                "marker_put_url".into(),
                serde_json::Value::String(url.clone()),
            );
        }
        if let Some(marker) = &self.marker {
            obj.insert("marker".into(), serde_json::Value::String(marker.clone()));
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
        if let Some(size) = self.size {
            obj.insert("size".into(), serde_json::Value::Number(size.into()));
        }
        // A presigned URL signs these headers, so the PUT must carry them
        // exactly: the store, not this node, then refuses any other length or
        // any other bytes.
        if self.mode == UploadMode::Presigned {
            let mut headers = serde_json::Map::new();
            if let Some(size) = self.size {
                headers.insert(
                    "Content-Length".into(),
                    serde_json::Value::String(size.to_string()),
                );
            }
            if let Some(checksum) = self.digest.as_deref().and_then(checksum_header) {
                headers.insert(CHECKSUM_HEADER.into(), serde_json::Value::String(checksum));
            }
            obj.insert("headers".into(), serde_json::Value::Object(headers));
        }
        // The commit marker the ingester reads beside a campaign body: what to
        // PUT, where, and with which signed headers. Additive: older readers
        // ignore fields they do not know.
        if let (Some(url), Some(marker)) = (&self.marker_put_url, &self.marker) {
            obj.insert(
                "marker_put_url".into(),
                serde_json::Value::String(url.clone()),
            );
            obj.insert("marker".into(), serde_json::Value::String(marker.clone()));
            let mut headers = serde_json::Map::new();
            headers.insert(
                "Content-Length".into(),
                serde_json::Value::String(marker.len().to_string()),
            );
            if let Some(checksum) =
                checksum_header(&hex::encode(&Sha256::digest(marker.as_bytes())))
            {
                headers.insert(CHECKSUM_HEADER.into(), serde_json::Value::String(checksum));
            }
            obj.insert("marker_headers".into(), serde_json::Value::Object(headers));
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
            size: optional_u64(obj, "size")?,
            issued_to: optional_string(obj, "issued_to"),
            expires_at: optional_u64(obj, "expires_at")?
                .ok_or_else(|| DepositError::Invalid(String::from("grant missing expires_at")))?,
            consumed: obj
                .get("consumed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            mode,
            put_url: optional_string(obj, "put_url"),
            marker_put_url: optional_string(obj, "marker_put_url"),
            marker: optional_string(obj, "marker"),
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
        self.prune_grants_counting(now, None).map(|(live, _)| live)
    }

    /// [`DepositDir::prune_grants`], also counting the unexpired grants issued
    /// to `requester`.
    pub fn prune_grants_counting(
        &self,
        now: u64,
        requester: Option<&str>,
    ) -> Result<(usize, usize), DepositError> {
        let dir = self.grants_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(source) => {
                return Err(DepositError::Io {
                    context: format!("listing {}", dir.display()),
                    source,
                })
            }
        };
        let (mut live, mut theirs) = (0, 0);
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let grant = fs::read_to_string(&path)
                .ok()
                .and_then(|text| Grant::from_json(&text).ok());
            if grant.as_ref().is_some_and(|grant| now > grant.expires_at) {
                let _ = fs::remove_file(&path);
                continue;
            }
            live += 1;
            if requester.is_some()
                && grant.is_some_and(|grant| grant.issued_to.as_deref() == requester)
            {
                theirs += 1;
            }
        }
        Ok((live, theirs))
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

/// Bytes of one campaign distinguished-point record. A campaign body must be
/// a whole number of these; the ingester silently truncates a tail that is
/// not, so anything short of exact is refused before it is stored.
const ECC2K_DP_RECORD_BYTES: u64 = 32;

/// The `.bin.json` commit marker the campaign ingester reads beside a body:
/// the producer's own sha-256, record count, clock, and format label. Written
/// after the body, so its presence means the object is complete; a body that
/// does not match its marker is refused, never stored.
fn commit_marker(digest: &str, records: u64, produced_at: u64) -> String {
    serde_json::json!({
        "sha256": digest,
        "records": records,
        "producedAt": produced_at,
        "format": "ecc2k130-gpu-packed32",
    })
    .to_string()
}

/// Mint an ECC2K-130 campaign key: `dp/slot-N/<stream>-0-<sha>.bin`, the
/// shape `dp_ingest.py`'s `ORBIT_KEY_RE` recognises. The stream id is minted
/// random per grant and the sha-256 is the body's own, so the key is as
/// unguessable as the default random one while telling the ingester which
/// slot produced it. Offset 0: one grant is one self-contained stream.
fn campaign_key(prefix: &str, slot: u64, digest: &str) -> String {
    let mut stream = [0u8; 16];
    OsRng.fill_bytes(&mut stream);
    format!(
        "{prefix}slot-{slot:05}/{stream}-0-{digest}.bin",
        stream = hex::encode(&stream),
    )
}

/// Issue a grant against a configured deposit.
///
/// `proxy_base` is the public origin of this node (e.g. `http://host:8080`)
/// used to fill `put_url` for proxy mode.
///
/// For S3, the grant is [`UploadMode::Presigned`] only when the request names
/// both the exact `size` and the `digest`: the URL then signs `Content-Length`
/// and `x-amz-checksum-sha256`, so the store itself refuses any other length
/// or any other bytes, however often the URL is used before it expires.
/// Otherwise it is [`UploadMode::Proxy`]: the body comes through this node,
/// which enforces `max_bytes` and signs the exact length and digest of what it
/// forwards. Before, a presigned PUT signed only `host`, so `max_bytes` was
/// advisory for S3 and a leaked URL could fill the bucket.
pub fn issue_grant(
    deposits: &DepositDir,
    request: &GrantRequest<'_>,
    proxy_base: Option<&str>,
    secrets_dir: &Path,
) -> Result<Grant, DepositError> {
    let spec = deposits.load(request.deposit)?;
    let submitter = request.submitter;
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
    let max_bytes = request.max_bytes.unwrap_or(spec.max_bytes);
    if max_bytes == 0 || max_bytes > spec.max_bytes {
        return Err(DepositError::Invalid(format!(
            "max_bytes must be between 1 and {} for this deposit",
            spec.max_bytes
        )));
    }
    if let Some(size) = request.size {
        if size == 0 || size > max_bytes {
            return Err(DepositError::Invalid(format!(
                "size must be between 1 and {max_bytes}"
            )));
        }
    }
    if let Some(digest) = request.digest {
        if hex::decode(digest).as_ref().map(|b| b.len()) != Some(32) {
            return Err(DepositError::Invalid(String::from(
                "digest must be 64 lowercase hex characters (sha-256)",
            )));
        }
    }
    if spec.key_shape == KeyShape::Ecc2kDp {
        if request.slot.is_none() {
            return Err(DepositError::Invalid(String::from(
                "an ecc2k-dp grant needs a slot: the key names which slot produced it",
            )));
        }
        match request.digest {
            Some(digest) if digest == digest.to_ascii_lowercase() => {}
            Some(_) => {
                return Err(DepositError::Invalid(String::from(
                    "digest must be 64 lowercase hex characters (sha-256)",
                )));
            }
            None => {
                return Err(DepositError::Invalid(String::from(
                    "an ecc2k-dp grant needs a digest: the key names the body's sha-256",
                )));
            }
        }
        // Checked again at redeem against the actual body; refusing the size
        // here as well is what stops a presigned contributor PUTting bytes
        // the ingester would truncate.
        if let Some(size) = request.size {
            if size % ECC2K_DP_RECORD_BYTES != 0 {
                return Err(DepositError::Invalid(format!(
                    "an ecc2k-dp body must be a whole number of {ECC2K_DP_RECORD_BYTES}-byte records"
                )));
            }
        }
    } else if request.slot.is_some() {
        return Err(DepositError::Invalid(String::from(
            "slot is only for ecc2k-dp deposits",
        )));
    }

    // `POST /deposit/grant` is open to anyone who can reach the node, and
    // each grant is a file. Expired grants are deleted here, and past a
    // ceiling of live ones the answer is "come back later", so a loop of
    // requests cannot fill the disk -- and past a smaller ceiling per
    // address, one requester cannot take every grant there is.
    let (live, theirs) = deposits.prune_grants_counting(now_secs(), request.requester)?;
    if live >= MAX_OUTSTANDING_GRANTS {
        return Err(DepositError::Unavailable(format!(
            "{MAX_OUTSTANDING_GRANTS} grants are outstanding; try again once some expire"
        )));
    }
    if theirs >= MAX_GRANTS_PER_ADDRESS {
        return Err(DepositError::Unavailable(format!(
            "this address holds {MAX_GRANTS_PER_ADDRESS} unexpired grants; use or let some \
             expire first"
        )));
    }

    let mut id_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut id_bytes);
    let id = hex::encode(&id_bytes);
    let prefix = spec.prefix.as_deref().unwrap_or("");
    let key = match spec.key_shape {
        KeyShape::Default => {
            let submitter_short = short_submitter(submitter);
            format!("{prefix}{}/{}/{id}", spec.name, submitter_short,)
        }
        // Validated above: an ecc2k-dp request carries a slot and a lowercase
        // digest, or issue has already returned.
        KeyShape::Ecc2kDp => campaign_key(
            prefix,
            request.slot.expect("slot validated above"),
            request.digest.expect("digest validated above"),
        ),
    };

    let expires_at = now_secs().saturating_add(spec.ttl_secs);
    let (mode, put_url) = match spec.provider {
        Provider::File => (UploadMode::Proxy, None),
        Provider::S3 => match (request.size, request.digest) {
            (Some(size), Some(digest)) => {
                let url = presign_s3_put(&spec, &key, size, digest, expires_at, secrets_dir)?;
                (UploadMode::Presigned, Some(url))
            }
            // Through this node, which signs what it forwards. The credentials
            // are read now anyway, so a node that could never forward says so
            // before anyone uploads.
            _ => {
                s3_credentials(&spec, secrets_dir)?;
                (UploadMode::Proxy, None)
            }
        },
    };

    // A campaign grant's marker, signed alongside the body when the body is
    // presigned: the contributor PUTs the body, then PUTs this at the marker
    // URL. Proxy redemptions write it themselves in `redeem_grant`.
    let (marker_put_url, marker) = match (spec.key_shape, request.size, request.digest, &put_url) {
        (KeyShape::Ecc2kDp, Some(size), Some(digest), Some(_)) => {
            let marker = commit_marker(digest, size / ECC2K_DP_RECORD_BYTES, now_secs());
            let marker_digest = hex::encode(&Sha256::digest(marker.as_bytes()));
            let url = presign_s3_put(
                &spec,
                &format!("{key}.json"),
                marker.len() as u64,
                &marker_digest,
                expires_at,
                secrets_dir,
            )?;
            (Some(url), Some(marker))
        }
        _ => (None, None),
    };

    let grant = Grant {
        id,
        deposit: spec.name.clone(),
        submitter: submitter.to_string(),
        key,
        max_bytes,
        digest: request.digest.map(str::to_string),
        size: request.size,
        issued_to: request.requester.map(str::to_string),
        expires_at,
        consumed: false,
        mode,
        put_url,
        marker_put_url,
        marker,
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
    if let Some(size) = grant.size {
        if body.len() as u64 != size {
            return Err(DepositError::Invalid(format!(
                "the grant is for exactly {size} bytes; this body has {}",
                body.len()
            )));
        }
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
    if spec.key_shape == KeyShape::Ecc2kDp
        && (body.is_empty() || body.len() as u64 % ECC2K_DP_RECORD_BYTES != 0)
    {
        // Before anything is stored: the ingester truncates a partial tail
        // rather than refusing it, so a short body would become fewer points
        // than its marker claims.
        return Err(DepositError::Invalid(format!(
            "an ecc2k-dp body must be a non-empty whole number of 32-byte records; \
             this one is {} bytes",
            body.len()
        )));
    }
    match spec.provider {
        Provider::File => {
            let root = spec
                .root
                .as_ref()
                .ok_or_else(|| DepositError::Invalid(String::from("file deposit missing root")))?;
            put_file(root, &grant.key, body)?;
            if spec.key_shape == KeyShape::Ecc2kDp {
                put_file(
                    root,
                    &format!("{}.json", grant.key),
                    commit_marker(&digest, body.len() as u64 / ECC2K_DP_RECORD_BYTES, now)
                        .as_bytes(),
                )?;
            }
        }
        Provider::S3 => {
            // Signed for exactly these bytes, whatever the grant was issued
            // with: the length and digest checked above are what the store
            // will be told to insist on.
            let url = presign_s3_put(
                &spec,
                &grant.key,
                body.len() as u64,
                &digest,
                grant.expires_at,
                secrets_dir,
            )?;
            curl_put(&url, body, &digest)?;
            // After the body, so the marker's presence means the object is
            // complete. A failed marker leaves the grant unconsumed: the same
            // bytes re-PUT to the same key are a no-op, so retrying is safe
            // and reissuing (a new key, a duplicate body) is not needed.
            if spec.key_shape == KeyShape::Ecc2kDp {
                let marker = commit_marker(&digest, body.len() as u64 / ECC2K_DP_RECORD_BYTES, now);
                let marker_digest = hex::encode(&Sha256::digest(marker.as_bytes()));
                let marker_url = presign_s3_put(
                    &spec,
                    &format!("{}.json", grant.key),
                    marker.len() as u64,
                    &marker_digest,
                    grant.expires_at,
                    secrets_dir,
                )?;
                curl_put(&marker_url, marker.as_bytes(), &marker_digest)?;
            }
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

/// The header S3 checks a body's SHA-256 against.
const CHECKSUM_HEADER: &str = "x-amz-checksum-sha256";

/// `x-amz-checksum-sha256`'s value for a hex SHA-256: the same digest in
/// standard base64.
fn checksum_header(hex_digest: &str) -> Option<String> {
    hex::decode(hex_digest)
        .filter(|bytes| bytes.len() == 32)
        .map(|bytes| base64(&bytes))
}

/// Standard base64 with padding. Written out for one 32-byte digest rather
/// than taking a crate for it.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The access key, secret key and optional session token an S3 deposit
/// names, read from the operator's secrets.
fn s3_credentials(
    spec: &DepositSpec,
    secrets_dir: &Path,
) -> Result<(String, String, Option<String>), DepositError> {
    let access_key = secrets::get(secrets_dir, &spec.access_key_secret).map_err(map_secrets)?;
    let secret_key = secrets::get(secrets_dir, &spec.secret_key_secret).map_err(map_secrets)?;
    let session_token = match &spec.session_token_secret {
        Some(name) => Some(secrets::get(secrets_dir, name).map_err(map_secrets)?),
        None => None,
    };
    Ok((access_key, secret_key, session_token))
}

/// Mint a SigV4 query-string pre-signed PUT URL for exactly `length` bytes
/// whose SHA-256 is `digest`.
///
/// Both are signed headers: `Content-Length`, so the store refuses any other
/// length, and `x-amz-checksum-sha256`, so it refuses any other bytes. Signing
/// only `host` with `UNSIGNED-PAYLOAD`, as this did before, left `max_bytes`
/// advisory: a leaked URL could put any amount of anything at the key until it
/// expired.
fn presign_s3_put(
    spec: &DepositSpec,
    key: &str,
    length: u64,
    digest: &str,
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
    let checksum = checksum_header(digest).ok_or_else(|| {
        DepositError::Invalid(String::from(
            "digest must be 64 lowercase hex characters (sha-256)",
        ))
    })?;
    let (access_key, secret_key, session_token) = s3_credentials(spec, secrets_dir)?;

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
        ("X-Amz-SignedHeaders".into(), SIGNED_HEADERS.into()),
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

    // Lowercase names, sorted, as SigV4 requires; SIGNED_HEADERS lists the
    // same names in the same order.
    let canonical_headers =
        format!("content-length:{length}\nhost:{host}\n{CHECKSUM_HEADER}:{checksum}\n");
    let canonical_request = format!(
        "PUT\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{SIGNED_HEADERS}\nUNSIGNED-PAYLOAD"
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

/// The headers a presigned PUT signs, in SigV4's order.
const SIGNED_HEADERS: &str = "content-length;host;x-amz-checksum-sha256";

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

fn curl_put(url: &str, body: &[u8], digest: &str) -> Result<(), DepositError> {
    let checksum = checksum_header(digest).ok_or_else(|| {
        DepositError::Invalid(String::from(
            "digest must be 64 lowercase hex characters (sha-256)",
        ))
    })?;
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
        .arg("--header")
        .arg(format!("{CHECKSUM_HEADER}: {checksum}"))
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

/// Normalize a key prefix: no leading slash, trailing slash unless empty.
pub fn normalize_prefix(prefix: &str) -> String {
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
        let live = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "demo",
                submitter: "alice",
                max_bytes: None,
                digest: None,
                ..GrantRequest::default()
            },
            None,
            &secrets,
        )
        .unwrap();
        let mut stale = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "demo",
                submitter: "bob",
                max_bytes: None,
                digest: None,
                ..GrantRequest::default()
            },
            None,
            &secrets,
        )
        .unwrap();
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
            &GrantRequest {
                deposit: "demo",
                submitter: "alice",
                max_bytes: Some(1024),
                digest: None,
                ..GrantRequest::default()
            },
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
        let grant = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "d",
                submitter: "bob",
                max_bytes: Some(64),
                digest: Some(&want),
                ..GrantRequest::default()
            },
            None,
            &secrets,
        )
        .unwrap();
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
        let grant = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "d",
                submitter: "c",
                max_bytes: Some(4),
                digest: None,
                ..GrantRequest::default()
            },
            None,
            &secrets,
        )
        .unwrap();
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
        let err = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "camp",
                submitter: "alice",
                max_bytes: None,
                digest: None,
                ..GrantRequest::default()
            },
            None,
            &secrets,
        )
        .unwrap_err();
        assert!(matches!(err, DepositError::Unavailable(_)), "{err}");

        secrets::set(&secrets, "AWS_ACCESS_KEY_ID", "AKIAEXAMPLEKEY00000").unwrap();
        secrets::set(
            &secrets,
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        .unwrap();

        // Without the exact size and digest, the upload comes through this
        // node, which enforces max_bytes and signs what it forwards.
        let proxied = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "camp",
                submitter: "alice",
                max_bytes: Some(1024),
                digest: None,
                ..GrantRequest::default()
            },
            None,
            &secrets,
        )
        .unwrap();
        assert_eq!(proxied.mode, UploadMode::Proxy);
        assert!(proxied
            .put_url
            .as_deref()
            .unwrap()
            .contains("/deposit/upload/"));

        // With both, the URL is presigned for exactly those bytes: the store
        // checks the signed length and checksum, not this node.
        let body = b"distinguished points";
        let digest = hex::encode(&Sha256::digest(body));
        let grant = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "camp",
                submitter: "alice",
                max_bytes: Some(1024),
                size: Some(body.len() as u64),
                digest: Some(&digest),
                slot: None,
                requester: None,
            },
            None,
            &secrets,
        )
        .unwrap();
        assert_eq!(grant.mode, UploadMode::Presigned);
        let url = grant.put_url.as_deref().unwrap();
        assert!(url.starts_with("https://ecc2k130-example.s3.us-west-2.amazonaws.com/"));
        assert!(url.contains("X-Amz-Signature="));
        assert!(url.contains("X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-checksum-sha256"));
        assert!(url.contains("dp/camp/alice/"));
        // No secret material in the URL beyond the signature of a request.
        assert!(!url.contains("wJalrXUtnFEMI"));
        let public = grant.public_response(None);
        assert_eq!(public["headers"]["Content-Length"], body.len().to_string());
        assert_eq!(
            public["headers"]["x-amz-checksum-sha256"],
            base64(&Sha256::digest(body))
        );
        // A size above the ceiling is refused at issue.
        let too_big = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "camp",
                submitter: "alice",
                max_bytes: Some(8),
                size: Some(9),
                ..GrantRequest::default()
            },
            None,
            &secrets,
        );
        assert!(
            matches!(too_big, Err(DepositError::Invalid(_))),
            "{too_big:?}"
        );

        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        // RFC 4648 §10, and the checksum S3 expects for the empty body.
        for (input, output) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input), output);
        }
        assert_eq!(
            checksum_header(&hex::encode(&Sha256::digest(b""))).as_deref(),
            Some("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
        );
    }

    #[test]
    fn a_grant_for_an_exact_size_takes_no_other() {
        let root = scratch("exact-root");
        let dir = DepositDir::at(scratch("exact-cfg"));
        let secrets = scratch("exact-secrets");
        secrets::prepare(&secrets).unwrap();
        dir.add(&DepositSpec::file("d", &root)).unwrap();
        let grant = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "d",
                submitter: "c",
                size: Some(4),
                ..GrantRequest::default()
            },
            None,
            &secrets,
        )
        .unwrap();
        assert!(matches!(
            redeem_grant(&dir, &grant.id, b"123", &secrets),
            Err(DepositError::Invalid(_))
        ));
        redeem_grant(&dir, &grant.id, b"1234", &secrets).unwrap();
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn one_address_cannot_hold_every_grant() {
        let root = scratch("per-address-root");
        let dir = DepositDir::at(scratch("per-address-cfg"));
        let secrets = scratch("per-address-secrets");
        secrets::prepare(&secrets).unwrap();
        dir.add(&DepositSpec::file("d", &root)).unwrap();
        let ask = |requester: Option<&str>| {
            issue_grant(
                &dir,
                &GrantRequest {
                    deposit: "d",
                    submitter: "s",
                    requester,
                    ..GrantRequest::default()
                },
                None,
                &secrets,
            )
        };
        for _ in 0..MAX_GRANTS_PER_ADDRESS {
            ask(Some("203.0.113.7")).unwrap();
        }
        assert!(matches!(
            ask(Some("203.0.113.7")),
            Err(DepositError::Unavailable(_))
        ));
        // Somebody else still gets one, and so does the operator.
        ask(Some("198.51.100.2")).unwrap();
        ask(None).unwrap();
        // The address is kept on disk to count with, never handed out.
        let grant = ask(Some("198.51.100.2")).unwrap();
        assert!(!grant
            .public_response(None)
            .to_string()
            .contains("198.51.100.2"));
        let _ = fs::remove_dir_all(root);
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

    fn campaign_dir(name: &str) -> (DepositDir, PathBuf) {
        let root = scratch(name);
        let dir = DepositDir::at(scratch(&format!("{name}-cfg")));
        let secrets = scratch(&format!("{name}-secrets"));
        secrets::prepare(&secrets).unwrap();
        let mut spec = DepositSpec::file("camp", &root);
        spec.prefix = Some(String::from("dp/"));
        spec.key_shape = KeyShape::Ecc2kDp;
        dir.add(&spec).unwrap();
        (dir, secrets)
    }

    /// The minted key against `dp_ingest.py`'s `ORBIT_KEY_RE`, by hand: this
    /// crate has no regex dependency and will not grow one for a test.
    fn assert_orbit_key(key: &str, slot: &str, digest: &str) {
        let head = format!("dp/slot-{slot}/");
        assert!(key.starts_with(&head), "{key}");
        let tail = key.strip_prefix(&head).unwrap();
        assert!(tail.ends_with(".bin"), "{key}");
        let parts: Vec<&str> = tail.strip_suffix(".bin").unwrap().split('-').collect();
        assert_eq!(parts.len(), 3, "{key}");
        assert_eq!(parts[0].len(), 32, "{key}");
        assert!(parts[0].bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
        assert_eq!(parts[1], "0", "{key}");
        assert_eq!(parts[2], digest, "{key}");
    }

    #[test]
    fn campaign_grants_mint_ingester_shaped_keys() {
        let (dir, secrets) = campaign_dir("orbit-keys");
        let body = vec![7u8; 64];
        let digest = hex::encode(&Sha256::digest(&body));
        let ask = |slot: Option<u64>, digest: Option<&str>, size: Option<u64>| {
            issue_grant(
                &dir,
                &GrantRequest {
                    deposit: "camp",
                    submitter: "slot-7-worker",
                    max_bytes: None,
                    size,
                    digest,
                    slot,
                    requester: None,
                },
                None,
                &secrets,
            )
        };
        // No slot, no digest, or a digest the key could not spell: all refused
        // before anything is minted.
        assert!(ask(None, Some(&digest), None).is_err());
        assert!(ask(Some(7), None, None).is_err());
        assert!(ask(Some(7), Some(&digest.to_ascii_uppercase()), None).is_err());
        assert!(ask(Some(7), Some(&digest), Some(33)).is_err());
        let first = ask(Some(7), Some(&digest), Some(64)).unwrap();
        assert_orbit_key(&first.key, "00007", &digest);
        // The stream id is minted per grant: two grants for the same body are
        // two objects, never one key written twice.
        let second = ask(Some(7), Some(&digest), Some(64)).unwrap();
        assert_orbit_key(&second.key, "00007", &digest);
        assert_ne!(first.key, second.key);
        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn campaign_redeem_writes_body_and_marker() {
        let (dir, secrets) = campaign_dir("orbit-put");
        let body = vec![9u8; 64];
        let digest = hex::encode(&Sha256::digest(&body));
        let grant = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "camp",
                submitter: "slot-3-worker",
                max_bytes: None,
                size: Some(64),
                digest: Some(&digest),
                slot: Some(3),
                requester: None,
            },
            None,
            &secrets,
        )
        .unwrap();
        let receipt = redeem_grant(&dir, &grant.id, &body, &secrets).unwrap();
        assert_eq!(receipt.key, grant.key);
        assert_eq!(receipt.digest, digest);
        let root = dir.load("camp").unwrap().root.unwrap();
        assert_eq!(fs::read(root.join(&grant.key)).unwrap(), body);
        let marker: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join(format!("{}.json", grant.key))).unwrap(),
        )
        .unwrap();
        assert_eq!(marker["sha256"], digest);
        assert_eq!(marker["records"], 2);
        assert_eq!(marker["format"], "ecc2k130-gpu-packed32");
        assert!(marker["producedAt"].as_u64().unwrap() > 0);

        // A body the ingester would truncate is refused before anything lands.
        let bad = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "camp",
                submitter: "slot-3-worker",
                max_bytes: None,
                size: None,
                digest: Some(&hex::encode(&Sha256::digest([0u8; 33]))),
                slot: Some(3),
                requester: None,
            },
            None,
            &secrets,
        )
        .unwrap();
        assert!(redeem_grant(&dir, &bad.id, &[0u8; 33], &secrets).is_err());
        assert!(redeem_grant(&dir, &bad.id, &[], &secrets).is_err());
        // ... and the refusal consumed nothing: the grant is still redeemable.
        let good_body = vec![1u8; 32];
        let good = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "camp",
                submitter: "slot-3-worker",
                max_bytes: None,
                size: Some(32),
                digest: Some(&hex::encode(&Sha256::digest(&good_body))),
                slot: Some(3),
                requester: None,
            },
            None,
            &secrets,
        )
        .unwrap();
        redeem_grant(&dir, &good.id, &good_body, &secrets).unwrap();
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn campaign_presigned_grant_carries_a_signed_marker() {
        let dir = DepositDir::at(scratch("orbit-presign-cfg"));
        let secrets = scratch("orbit-presign-secrets");
        secrets::prepare(&secrets).unwrap();
        secrets::set(&secrets, "AWS_ACCESS_KEY_ID", "AKIAEXAMPLEKEY00000").unwrap();
        secrets::set(
            &secrets,
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        .unwrap();
        let mut spec = DepositSpec::s3("camp", "ecc2k130-example", "dp/", "us-west-2");
        spec.key_shape = KeyShape::Ecc2kDp;
        dir.add(&spec).unwrap();

        let body = vec![3u8; 96];
        let digest = hex::encode(&Sha256::digest(&body));
        let grant = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "camp",
                submitter: "fleet-gpu",
                max_bytes: None,
                size: Some(96),
                digest: Some(&digest),
                slot: Some(140),
                requester: None,
            },
            None,
            &secrets,
        )
        .unwrap();
        assert_eq!(grant.mode, UploadMode::Presigned);
        assert_orbit_key(&grant.key, "00140", &digest);
        // The contributor PUTs the body, then PUTs the marker: both URLs are
        // signed, and the marker bytes are the node's, not theirs to invent.
        let marker_url = grant.marker_put_url.as_deref().unwrap();
        assert!(marker_url.contains("X-Amz-Signature="));
        assert!(marker_url.contains(".json?"));
        let marker: serde_json::Value =
            serde_json::from_str(grant.marker.as_deref().unwrap()).unwrap();
        assert_eq!(marker["sha256"], digest);
        assert_eq!(marker["records"], 3);
        let public = grant.public_response(None);
        assert_eq!(public["marker_put_url"], marker_url);
        assert!(public["marker_headers"]["Content-Length"]
            .as_str()
            .unwrap()
            .parse::<usize>()
            .is_ok());
        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn slot_is_refused_outside_campaign_deposits() {
        let root = scratch("slot-root");
        let dir = DepositDir::at(scratch("slot-cfg"));
        let secrets = scratch("slot-secrets");
        secrets::prepare(&secrets).unwrap();
        dir.add(&DepositSpec::file("demo", &root)).unwrap();
        let err = issue_grant(
            &dir,
            &GrantRequest {
                deposit: "demo",
                submitter: "alice",
                max_bytes: None,
                digest: None,
                size: None,
                slot: Some(1),
                requester: None,
            },
            None,
            &secrets,
        )
        .unwrap_err();
        assert!(matches!(err, DepositError::Invalid(_)), "{err}");
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(dir.path());
        let _ = fs::remove_dir_all(secrets);
    }

    #[test]
    fn campaign_deposits_need_a_prefix_and_old_configs_stay_default() {
        let mut spec = DepositSpec::s3("camp", "b", "", "us-west-2");
        spec.key_shape = KeyShape::Ecc2kDp;
        assert!(spec.validate().is_err());
        // ... while the default shape never cared about prefixes.
        let plain = DepositSpec::s3("camp", "b", "", "us-west-2");
        assert!(plain.validate().is_ok());
        // Configs written before shapes existed carry no key_shape and still
        // load, as the default one.
        let json = r#"{"name":"d","provider":"file","root":"/tmp/x"}"#;
        assert_eq!(
            DepositSpec::from_json(json).unwrap().key_shape,
            KeyShape::Default
        );
        let json = r#"{"name":"d","provider":"file","root":"/tmp/x","key_shape":"ecc2k"}"#;
        assert!(DepositSpec::from_json(json).is_err());
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
