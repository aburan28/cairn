//! Canonical serialization and content addressing.
//!
//! The contract this whole crate exists to check. Written from the format
//! description rather than from the primary implementation's source, because
//! an implementation that agrees by construction proves nothing about the
//! format -- it only proves the two files are copies.
//!
//! The format:
//!
//! - Object keys sorted by code point, no insignificant whitespace, UTF-8.
//! - Non-ASCII stays raw; it is never `\u`-escaped.
//! - Escapes: `"` and `\`, the five short forms `\b \t \n \f \r`, and every
//!   other control character below 0x20 as `\u00XX`. DEL and `/` are not
//!   escaped.
//! - Integers only. No float variant exists, so a float cannot enter a record
//!   at all: IEEE-754 doubles do not round-trip identically through every JSON
//!   implementation, which is precisely the disagreement this format forbids.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};

pub const DIGEST_PREFIX: &str = "sha256:";

/// Recursion ceiling for the decoder. A deliberately deep document must be
/// refused rather than overflow the stack.
const MAX_DEPTH: usize = 128;

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
pub struct CanonicalError(pub String);

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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

    pub fn string(text: impl Into<String>) -> Value {
        Value::String(text.into())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// Integers only, and never a bool. Many languages conflate the two; a
    /// format whose ids must match across them cannot.
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Int(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_i128().and_then(|v| i64::try_from(v).ok())
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_i128().and_then(|v| u64::try_from(v).ok())
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
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

    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_string().into_bytes()
    }

    pub fn canonical_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    pub fn digest(&self) -> String {
        digest_bytes(&self.canonical_bytes())
    }

    fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(value) => out.push_str(&value.to_string()),
            Value::String(text) => escape(text, out),
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                // BTreeMap iterates in UTF-8 byte order, which for UTF-8 is
                // code-point order -- the order the format specifies.
                for (index, (key, item)) in map.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    escape(key, out);
                    out.push(':');
                    item.write(out);
                }
                out.push('}');
            }
        }
    }

    /// Parse JSON into a canonical value, refusing floats at the boundary.
    ///
    /// Hand-rolled, like the encoder. Handing a JSON library authority over
    /// what a record's bytes mean would give that library's private
    /// conventions consensus weight -- a real failure the primary
    /// implementation hit, where a library decoded an object whose first key
    /// was its own internal number token as a *number*.
    pub fn from_json(text: &str) -> Result<Value, CanonicalError> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            text,
            at: 0,
        };
        parser.skip_space();
        let value = parser.value(0, "$")?;
        parser.skip_space();
        if parser.at != text.len() {
            return Err(parser.bad("trailing characters after the value"));
        }
        Ok(value)
    }
}

fn escape(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

pub fn digest_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{DIGEST_PREFIX}{:x}", hasher.finalize())
}

/// Display form. By characters, never bytes: these strings come from records
/// other people wrote, and slicing one mid-character panics.
pub fn short(identifier: &str) -> String {
    match identifier.strip_prefix(DIGEST_PREFIX) {
        Some(rest) => format!(
            "{DIGEST_PREFIX}{}",
            rest.chars().take(8).collect::<String>()
        ),
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
        let mut index = 0;
        while index + 1 < level.len() {
            next.push(digest_bytes(
                format!("{}{}", level[index], level[index + 1]).as_bytes(),
            ));
            index += 2;
        }
        if level.len() % 2 == 1 {
            next.push(level[level.len() - 1].clone());
        }
        level = next;
    }
    Some(level.remove(0))
}

// -- decoding ---------------------------------------------------------------

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn bad(&self, why: &str) -> CanonicalError {
        CanonicalError(format!("malformed JSON: {why} at byte {}", self.at))
    }

    fn value(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalError("malformed JSON: too deeply nested".into()));
        }
        match self.peek() {
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.array(depth, path),
            Some(b'{') => self.map(depth, path),
            Some(b'-' | b'0'..=b'9') => self.number(path),
            Some(_) => Err(self.bad("unexpected character")),
            None => Err(self.bad("unexpected end of input")),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, CanonicalError> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(self.bad("invalid literal"))
        }
    }

    fn array(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        self.at += 1;
        self.skip_space();
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(out));
        }
        loop {
            out.push(self.value(depth + 1, &format!("{path}[{}]", out.len()))?);
            self.skip_space();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_space();
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(out));
                }
                _ => return Err(self.bad("expected ',' or ']'")),
            }
        }
    }

    fn map(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        self.at += 1;
        self.skip_space();
        let mut out = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(out));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.bad("expected a string key"));
            }
            let key = self.string()?;
            self.skip_space();
            if self.peek() != Some(b':') {
                return Err(self.bad("expected ':'"));
            }
            self.at += 1;
            self.skip_space();
            let value = self.value(depth + 1, &format!("{path}.{key}"))?;
            // Last wins, which is what `json.loads` does.
            out.insert(key, value);
            self.skip_space();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_space();
                }
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(out));
                }
                _ => return Err(self.bad("expected ',' or '}'")),
            }
        }
    }

    fn number(&mut self, path: &str) -> Result<Value, CanonicalError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.at += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.bad("leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(self.bad("expected a digit")),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.at += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.bad("expected a digit after '.'"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.bad("expected a digit in the exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        if is_float {
            return Err(CanonicalError(format!(
                "{path}: float values are not canonically serializable"
            )));
        }
        self.text[start..self.at]
            .parse::<i128>()
            .map(Value::Int)
            .map_err(|_| {
                CanonicalError(format!(
                    "{path}: integer outside the signed 128-bit canonical range"
                ))
            })
    }

    fn string(&mut self) -> Result<String, CanonicalError> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.bad("unterminated string"));
            };
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let Some(escape) = self.peek() else {
                        return Err(self.bad("unterminated escape"));
                    };
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.bad("unknown escape")),
                    }
                }
                0x00..=0x1F => return Err(self.bad("raw control character in string")),
                byte if byte < 0x80 => {
                    out.push(byte as char);
                    self.at += 1;
                }
                _ => {
                    // Input is a &str, so the sequence is already valid UTF-8.
                    let ch = self.text[self.at..].chars().next().expect("valid utf-8");
                    out.push(ch);
                    self.at += ch.len_utf8();
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, CanonicalError> {
        let high = self.hex4()?;
        if (0xDC00..=0xDFFF).contains(&high) {
            return Err(self.bad("lone trailing surrogate"));
        }
        if (0xD800..=0xDBFF).contains(&high) {
            if self.peek() != Some(b'\\') {
                return Err(self.bad("lone leading surrogate"));
            }
            self.at += 1;
            if self.peek() != Some(b'u') {
                return Err(self.bad("lone leading surrogate"));
            }
            self.at += 1;
            let low = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(self.bad("lone leading surrogate"));
            }
            let code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
            return char::from_u32(code).ok_or_else(|| self.bad("invalid escape"));
        }
        char::from_u32(high).ok_or_else(|| self.bad("invalid escape"))
    }

    fn hex4(&mut self) -> Result<u32, CanonicalError> {
        let slice = self
            .text
            .get(self.at..self.at + 4)
            .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| self.bad("expected four hex digits"))?;
        self.at += 4;
        Ok(u32::from_str_radix(slice, 16).expect("checked hex"))
    }
}
