//! Canonical serialization and content addressing.
//!
//! Consensus-critical. Two implementations that disagree about an object's bytes
//! disagree about its identity, and therefore about which objective was funded
//! and which artifact was accepted. `conformance/vectors.json` pins the format,
//! and is frozen rather than regenerated: it was produced by a Python reference
//! implementation this crate replaced, which is exactly why it is kept —
//! evidence from another language beats a description of this program's own
//! behaviour. If this module and that file disagree, this module is wrong.
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
//! [`Value`] has no float variant, so a float cannot enter a record at all --
//! the failure moves from a check that has to run to a program that does not
//! compile. The Python reference this crate replaced could only test for floats
//! at runtime and raise; making it unrepresentable is the whole advantage of
//! the type system here. IEEE-754 doubles do not round-trip identically through every
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
    ///
    /// Hand-rolled for the same reason the encoder is. Routing this through a
    /// JSON library gives that library's private conventions consensus weight:
    /// `serde_json` with `arbitrary_precision` decodes an object whose first
    /// key is its internal number token (`$serde_json::private::Number`) as a
    /// *number*, so the same bytes parsed here and by any decoder without that
    /// quirk produced two different values — and therefore two different
    /// digests. That was found against the Python reference of the day and is
    /// not a fact about Python: a second implementation reaching for the same
    /// crate today would reintroduce it. A decoder spelled out in this file
    /// cannot drift under a dependency update.
    pub fn from_json(text: &str) -> Result<Value, CanonicalError> {
        let mut parser = Parser { text, pos: 0 };
        parser.skip_whitespace();
        let value = parser.parse_value(0, "$")?;
        parser.skip_whitespace();
        if parser.pos != text.len() {
            return Err(parser.malformed("trailing characters after the value"));
        }
        Ok(value)
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

/// Recursion ceiling for [`Value::from_json`]. Matches the limit the previous
/// serde_json-based decoder enforced, so nothing that parsed before is refused
/// now, and a deliberately deep document cannot overflow the stack.
const MAX_DEPTH: usize = 128;

/// The decoder behind [`Value::from_json`]. Strict JSON (RFC 8259), no
/// extensions: no `NaN`/`Infinity`, no comments, no trailing commas, no raw
/// control characters inside strings. Duplicate object keys keep the last
/// value, which is what both `json.loads` and the previous decoder did.
struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn malformed(&self, why: &str) -> CanonicalError {
        CanonicalError::Malformed(format!("{why} at byte {}", self.pos))
    }

    fn expect(&mut self, byte: u8) -> Result<(), CanonicalError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.malformed(&format!("expected {:?}", byte as char)))
        }
    }

    fn parse_value(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalError::Malformed(
                "recursion limit exceeded".to_string(),
            ));
        }
        match self.peek() {
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => self.parse_string().map(Value::String),
            Some(b'[') => self.parse_array(depth, path),
            Some(b'{') => self.parse_object(depth, path),
            Some(b'-' | b'0'..=b'9') => self.parse_number(path),
            Some(_) => Err(self.malformed("unexpected character")),
            None => Err(self.malformed("unexpected end of input")),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, CanonicalError> {
        if self.text[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.malformed("invalid literal"))
        }
    }

    fn parse_array(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        self.expect(b'[')?;
        self.skip_whitespace();
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(out));
        }
        loop {
            let item = self.parse_value(depth + 1, &format!("{path}[{}]", out.len()))?;
            out.push(item);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_whitespace();
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(out));
                }
                _ => return Err(self.malformed("expected ',' or ']'")),
            }
        }
    }

    fn parse_object(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        self.expect(b'{')?;
        self.skip_whitespace();
        let mut out = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(out));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.malformed("expected a string key"));
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.parse_value(depth + 1, &format!("{path}.{key}"))?;
            out.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_whitespace();
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(out));
                }
                _ => return Err(self.malformed("expected ',' or '}'")),
            }
        }
    }

    fn parse_number(&mut self, path: &str) -> Result<Value, CanonicalError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // `0`, or a nonzero digit followed by more. A longer run starting with
        // zero is not JSON.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.malformed("leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.malformed("expected a digit")),
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.malformed("expected a digit after '.'"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.malformed("expected a digit in the exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        // The whole grammar is consumed before the float refusal so that
        // `1.5x` is malformed JSON rather than "a float", same as before.
        if float {
            return Err(CanonicalError::Float(path.to_string()));
        }
        self.text[start..self.pos]
            .parse::<i128>()
            .map(Value::Int)
            .map_err(|_| CanonicalError::IntegerOutOfRange(path.to_string()))
    }

    fn parse_string(&mut self) -> Result<String, CanonicalError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.malformed("unterminated string"));
            };
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let Some(escape) = self.peek() else {
                        return Err(self.malformed("unterminated escape"));
                    };
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.parse_unicode_escape()?),
                        _ => return Err(self.malformed("unknown escape")),
                    }
                }
                0x00..=0x1F => {
                    return Err(self.malformed("raw control character in string"));
                }
                b if b < 0x80 => {
                    out.push(b as char);
                    self.pos += 1;
                }
                _ => {
                    // Multi-byte UTF-8. The input is a `&str`, so the sequence
                    // is already valid; copy the whole character through.
                    let ch = self.text[self.pos..].chars().next().expect("valid utf-8");
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    /// `\uXXXX`, with a surrogate pair combined into one character. A lone
    /// surrogate is refused: it is not a character, and `String` cannot hold
    /// it anyway.
    fn parse_unicode_escape(&mut self) -> Result<char, CanonicalError> {
        let high = self.hex4()?;
        if (0xDC00..=0xDFFF).contains(&high) {
            return Err(self.malformed("lone trailing surrogate"));
        }
        if (0xD800..=0xDBFF).contains(&high) {
            if self.peek() != Some(b'\\') {
                return Err(self.malformed("lone leading surrogate"));
            }
            self.pos += 1;
            if self.peek() != Some(b'u') {
                return Err(self.malformed("lone leading surrogate"));
            }
            self.pos += 1;
            let low = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(self.malformed("lone leading surrogate"));
            }
            let code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
            return char::from_u32(code).ok_or_else(|| self.malformed("invalid escape"));
        }
        char::from_u32(high).ok_or_else(|| self.malformed("invalid escape"))
    }

    fn hex4(&mut self) -> Result<u32, CanonicalError> {
        let slice = self
            .text
            .get(self.pos..self.pos + 4)
            .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| self.malformed("expected four hex digits"))?;
        self.pos += 4;
        Ok(u32::from_str_radix(slice, 16).expect("checked hex"))
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
///
/// By characters, not bytes: identifiers reach here from records other people
/// wrote, and byte-slicing an attacker-chosen string panics mid-character.
pub fn short(identifier: &str) -> String {
    match identifier.strip_prefix(DIGEST_PREFIX) {
        Some(rest) => {
            let head: String = rest.chars().take(8).collect();
            format!("{DIGEST_PREFIX}{head}")
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_library_private_number_token_stays_an_object() {
        // Regression. `serde_json` with `arbitrary_precision` decodes an object
        // whose first key is its internal number token as a *number*, so this
        // input used to parse as `{"x":42}` here while the reference of the day
        // — and the encoder in this very file — saw an object. Same bytes, two
        // digests: a consensus split one crafted record away.
        let text = r#"{"x":{"$serde_json::private::Number":"42"}}"#;
        let value = Value::from_json(text).expect("valid JSON object");
        let inner = value.get("x").expect("x is present");
        assert!(
            inner.as_object().is_some(),
            "the object literal must stay an object, got {inner:?}"
        );
        assert_eq!(
            inner
                .get("$serde_json::private::Number")
                .and_then(Value::as_str),
            Some("42")
        );
        // And the digest round-trips through the canonical encoding.
        let reparsed = Value::from_json(&value.canonical_string()).expect("round trip");
        assert_eq!(reparsed, value);

        // The float-shaped variant used to fail the whole parse as a float.
        let float_shaped = r#"{"$serde_json::private::Number":"1.5"}"#;
        assert!(Value::from_json(float_shaped).is_ok());
    }

    #[test]
    fn scalars_parse_and_floats_are_refused_with_a_path() {
        assert_eq!(Value::from_json("null"), Ok(Value::Null));
        assert_eq!(Value::from_json("true"), Ok(Value::Bool(true)));
        assert_eq!(Value::from_json("false"), Ok(Value::Bool(false)));
        assert_eq!(Value::from_json("42"), Ok(Value::Int(42)));
        assert_eq!(Value::from_json("-0"), Ok(Value::Int(0)));
        assert_eq!(Value::from_json(" 7 "), Ok(Value::Int(7)));
        assert_eq!(
            Value::from_json(&i128::MAX.to_string()),
            Ok(Value::Int(i128::MAX))
        );
        assert_eq!(
            Value::from_json(&i128::MIN.to_string()),
            Ok(Value::Int(i128::MIN))
        );

        assert_eq!(
            Value::from_json("{\"a\":[1,2.5]}"),
            Err(CanonicalError::Float("$.a[1]".to_string()))
        );
        assert_eq!(
            Value::from_json("1e3"),
            Err(CanonicalError::Float("$".to_string()))
        );
        assert_eq!(
            Value::from_json("170141183460469231731687303715884105728"),
            Err(CanonicalError::IntegerOutOfRange("$".to_string()))
        );
    }

    #[test]
    fn malformed_json_is_refused_not_repaired() {
        for bad in [
            "",
            "  ",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{\"a\"}",
            "{a:1}",
            "01",
            "-",
            "1.",
            ".5",
            "+1",
            "nul",
            "truex",
            "1 2",
            "NaN",
            "Infinity",
            "'single'",
            "\"unterminated",
            "\"bad escape \\q\"",
            "\"raw tab \t\"",
            "\"lone surrogate \\ud800\"",
            "\"backwards pair \\udc00\\ud800\"",
        ] {
            let parsed = Value::from_json(bad);
            assert!(
                matches!(parsed, Err(CanonicalError::Malformed(_))),
                "{bad:?} parsed to {parsed:?}"
            );
        }
        // A float followed by garbage is refused as a float: the number
        // grammar completes before the trailing junk is reached. Either error
        // is a refusal; this pins which one so a change is a decision.
        assert!(matches!(
            Value::from_json("1.5.2"),
            Err(CanonicalError::Float(_))
        ));
    }

    #[test]
    fn strings_unescape_the_way_the_encoder_escapes() {
        let value =
            Value::from_json(r#""\" \\ \/ \b \f \n \r \t \u00e9 \ud83d\ude00 é""#).expect("valid");
        assert_eq!(
            value.as_str(),
            Some("\" \\ / \u{08} \u{0c} \n \r \t é 😀 é")
        );
        // Everything the encoder writes must read back as itself.
        let original = Value::string("control \u{01} tab\tnewline\nquote\"backslash\\ é 😀");
        let reparsed = Value::from_json(&original.canonical_string()).expect("round trip");
        assert_eq!(reparsed, original);
    }

    #[test]
    fn duplicate_keys_keep_the_last_value() {
        // What `json.loads` does, and what the previous decoder did.
        let value = Value::from_json(r#"{"a":1,"a":2}"#).expect("valid");
        assert_eq!(value.get("a"), Some(&Value::Int(2)));
    }

    #[test]
    fn deep_nesting_is_bounded_not_a_stack_overflow() {
        let deep_ok = format!("{}1{}", "[".repeat(100), "]".repeat(100));
        assert!(Value::from_json(&deep_ok).is_ok());
        let too_deep = format!("{}1{}", "[".repeat(500), "]".repeat(500));
        assert!(matches!(
            Value::from_json(&too_deep),
            Err(CanonicalError::Malformed(_))
        ));
    }

    #[test]
    fn short_never_panics_on_attacker_chosen_identifiers() {
        // Regression: the digest arm sliced bytes, so a multi-byte character
        // straddling index 8 panicked — reachable from any record id another
        // peer chose.
        assert_eq!(short("sha256:1234567é9"), "sha256:1234567é");
        assert_eq!(short("sha256:abcdef012345"), "sha256:abcdef01");
        assert_eq!(short("sha256:ab"), "sha256:ab");
        assert_eq!(short("é234567890"), "é2345678");
        assert_eq!(short("plain"), "plain");
    }
}
