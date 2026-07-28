//! Canonical serialization and content addressing.
//!
//! Consensus-critical. Two implementations that disagree about an object's bytes
//! disagree about its identity, and therefore about which objective was funded
//! and which artifact was accepted. `conformance/vectors.json` pins the format
//! against the Python reference implementation; if this module and that file
//! disagree, this module is wrong.
//!
//! # The format
//!
//! - Object keys sorted, no insignificant whitespace, UTF-8 output.
//! - Non-ASCII stays **raw UTF-8**; it is never `\u`-escaped.
//! - Escapes: `"` and `\`, the five short forms `\b \t \n \f \r`, and every
//!   other control character below 0x20 as `\u00XX`. `DEL` (0x7f) and `/` are
//!   **not** escaped.
//! - Integers only, bounded to signed 128-bit.
//!
//! # Why floats are unrepresentable rather than rejected
//!
//! The Python reference checks for floats at runtime and raises. Here [`Value`]
//! simply has no float variant, so a float cannot enter a record at all -- the
//! failure moves from a test that has to remember to run to a program that does
//! not compile. IEEE-754 doubles do not round-trip identically through every
//! JSON implementation and do not reproduce bitwise across heterogeneous
//! hardware, which is exactly the disagreement this type prevents.
//!
//! # Why key sorting agrees across languages
//!
//! Python sorts `str` by Unicode code point; Rust's `BTreeMap<String, _>` sorts
//! by UTF-8 byte order. Those orders coincide -- UTF-8 is constructed so that
//! byte-wise comparison reproduces code-point comparison -- so the two
//! implementations agree without either having to special-case the other.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};

pub const DIGEST_PREFIX: &str = "sha256:";

/// A canonically serializable value. Deliberately missing a float variant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// A float appeared in input JSON. It cannot be canonically serialized.
    Float(String),
    /// An integer outside the signed 128-bit range the format specifies.
    IntegerOutOfRange(String),
    /// Input was not valid JSON.
    Malformed(String),
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalError::Float(at) => write!(
                f,
                "{at}: float values are not canonically serializable; carry a \
                 scaled integer or a decimal string instead"
            ),
            CanonicalError::IntegerOutOfRange(at) => {
                write!(
                    f,
                    "{at}: integer outside the signed 128-bit canonical range"
                )
            }
            CanonicalError::Malformed(why) => write!(f, "malformed JSON: {why}"),
        }
    }
}

impl std::error::Error for CanonicalError {}

impl Value {
    pub fn object<I, K>(pairs: I) -> Value
    where
        I: IntoIterator<Item = (K, Value)>,
        K: Into<String>,
    {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    pub fn string(s: impl Into<String>) -> Value {
        Value::String(s.into())
    }

    pub fn array<I: IntoIterator<Item = Value>>(items: I) -> Value {
        Value::Array(items.into_iter().collect())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Integer accessor. Returns `None` for `Bool`, which is *not* an integer
    /// here even though many languages conflate the two.
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_i128().and_then(|i| i64::try_from(i).ok())
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_i128().and_then(|i| u64::try_from(i).ok())
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Parse JSON text into a canonical value, refusing floats at the boundary.
    ///
    /// This is the only place untrusted JSON enters the system, which is why
    /// float rejection lives here: past this point the type system carries the
    /// guarantee and no further checking is needed.
    pub fn from_json(text: &str) -> Result<Value, CanonicalError> {
        let parsed: serde_json::Value =
            serde_json::from_str(text).map_err(|e| CanonicalError::Malformed(e.to_string()))?;
        Value::from_serde(&parsed, "$")
    }

    fn from_serde(value: &serde_json::Value, path: &str) -> Result<Value, CanonicalError> {
        match value {
            serde_json::Value::Null => Ok(Value::Null),
            serde_json::Value::Bool(b) => Ok(Value::Bool(*b)),
            serde_json::Value::String(s) => Ok(Value::String(s.clone())),
            serde_json::Value::Number(n) => {
                // With `arbitrary_precision` the number is kept as text, so an
                // integer too large for i128 is distinguishable from a float
                // rather than silently becoming one.
                let raw = n.to_string();
                if raw.contains('.') || raw.contains('e') || raw.contains('E') {
                    return Err(CanonicalError::Float(path.to_string()));
                }
                raw.parse::<i128>()
                    .map(Value::Int)
                    .map_err(|_| CanonicalError::IntegerOutOfRange(path.to_string()))
            }
            serde_json::Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for (i, item) in items.iter().enumerate() {
                    out.push(Value::from_serde(item, &format!("{path}[{i}]"))?);
                }
                Ok(Value::Array(out))
            }
            serde_json::Value::Object(map) => {
                let mut out = BTreeMap::new();
                for (key, item) in map {
                    out.insert(
                        key.clone(),
                        Value::from_serde(item, &format!("{path}.{key}"))?,
                    );
                }
                Ok(Value::Object(out))
            }
        }
    }

    /// The one canonical byte encoding of this value.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out.into_bytes()
    }

    pub fn canonical_string(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::String(s) => write_escaped(s, out),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                // BTreeMap iterates in UTF-8 byte order, which equals code-point
                // order, which is what the reference implementation sorts by.
                for (i, (key, item)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped(key, out);
                    out.push(':');
                    item.write_canonical(out);
                }
                out.push('}');
            }
        }
    }

    /// Content address of this value, as `sha256:<hex>`.
    pub fn digest(&self) -> String {
        digest_bytes(&self.canonical_bytes())
    }
}

/// Escape exactly as the reference implementation does.
///
/// Every deviation here is a consensus fault, so the rules are spelled out
/// rather than delegated to a JSON library whose defaults could change:
/// short forms for the five conventional control characters, `\u00XX` for the
/// rest below 0x20, and everything else -- including DEL and all non-ASCII --
/// emitted raw.
fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn digest_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{DIGEST_PREFIX}{:x}", hasher.finalize())
}

/// Display form, e.g. `sha256:ab12cd34`. Never use for equality.
pub fn short(identifier: &str) -> String {
    match identifier.strip_prefix(DIGEST_PREFIX) {
        Some(rest) => format!("{DIGEST_PREFIX}{}", &rest[..rest.len().min(8)]),
        None => identifier.chars().take(8).collect(),
    }
}

/// Binary Merkle root over pre-hashed leaves.
///
/// An odd node is **promoted**, not duplicated. Duplicating the last leaf lets
/// two different leaf sets produce one root -- Bitcoin's CVE-2012-2459.
pub fn merkle_root(leaves: &[String]) -> Option<String> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            let joined = format!("{}{}", level[i], level[i + 1]);
            next.push(digest_bytes(joined.as_bytes()));
            i += 2;
        }
        if level.len() % 2 == 1 {
            next.push(level[level.len() - 1].clone());
        }
        level = next;
    }
    Some(level.remove(0))
}

/// Convenience for building object values in record code.
#[macro_export]
macro_rules! obj {
    ($($key:expr => $value:expr),* $(,)?) => {{
        let mut map = std::collections::BTreeMap::new();
        $( map.insert(String::from($key), $value); )*
        $crate::canonical::Value::Object(map)
    }};
}
