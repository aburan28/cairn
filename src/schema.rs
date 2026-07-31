//! Hard validation gate against the documents in `spec/`.
//!
//! The schemas are the published contract for objective and claim shape. The
//! code validators in [`crate::records`] remain authoritative for *semantic*
//! rules (sealed refusal, ratchet shape, verifier-kind registration); this
//! module refuses structurally malformed JSON *before* those constructors run,
//! so a body the published schema rejects can never reach the log.
//!
//! The validator interprets the schema documents rather than restating them in
//! Rust. A hand-written field-by-field checker is easier to read but drifts:
//! the file in `spec/` is what third parties implement against, and a checker
//! that has quietly diverged from it is worse than no checker, because it makes
//! two implementations disagree about which objectives exist. Interpreting the
//! document makes drift impossible by construction.
//!
//! Only the JSON Schema keywords actually used by `spec/*.json` are
//! implemented, and an unrecognised keyword is an *error*, not a no-op. Failing
//! closed matters: silently ignoring a keyword someone adds to the schema would
//! turn a tightened contract into an unenforced comment.

use std::collections::BTreeMap;
use std::fmt;

use crate::canonical::Value;

/// Embedded copies of the schema documents so a binary run from any cwd
/// enforces the same gate. `include_str!` rather than a runtime read: a node
/// whose gate depends on a file it may not find is a node with no gate.
pub const OBJECTIVE_SCHEMA_JSON: &str = include_str!("../spec/objective.schema.json");
pub const CLAIM_SCHEMA_JSON: &str = include_str!("../spec/claim.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// The instance fails a schema constraint.
    Invalid { path: String, detail: String },
    /// The schema document itself is unusable — malformed, or using a keyword
    /// this validator does not implement. Distinct from `Invalid` because it
    /// indicts the repository, not the submitted body.
    Unusable { path: String, detail: String },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::Invalid { path, detail } => {
                write!(f, "schema violation at {path}: {detail}")
            }
            SchemaError::Unusable { path, detail } => {
                write!(f, "unusable schema at {path}: {detail}")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

impl SchemaError {
    fn invalid(path: &str, detail: impl Into<String>) -> SchemaError {
        SchemaError::Invalid {
            path: path.to_string(),
            detail: detail.into(),
        }
    }

    fn unusable(path: &str, detail: impl Into<String>) -> SchemaError {
        SchemaError::Unusable {
            path: path.to_string(),
            detail: detail.into(),
        }
    }
}

/// Validate an objective body against `spec/objective.schema.json`.
pub fn validate_objective(value: &Value) -> Result<(), SchemaError> {
    validate_against(OBJECTIVE_SCHEMA_JSON, value)
}

/// Validate a claim body against `spec/claim.schema.json`.
pub fn validate_claim(value: &Value) -> Result<(), SchemaError> {
    validate_against(CLAIM_SCHEMA_JSON, value)
}

fn validate_against(schema_text: &str, value: &Value) -> Result<(), SchemaError> {
    let schema = Value::from_json(schema_text)
        .map_err(|e| SchemaError::unusable("#", format!("schema is not JSON: {e}")))?;
    check(&schema, "#", value, "$")
}

/// Keywords that carry documentation or identity rather than constraints.
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "$comment",
    "default",
    "examples",
];

fn check(schema: &Value, spath: &str, value: &Value, path: &str) -> Result<(), SchemaError> {
    let map = schema
        .as_object()
        .ok_or_else(|| SchemaError::unusable(spath, "schema node is not an object"))?;

    for key in map.keys() {
        if !ANNOTATIONS.contains(&key.as_str()) && !is_supported_keyword(key) {
            return Err(SchemaError::unusable(
                spath,
                format!("keyword {key:?} is not implemented by this validator"),
            ));
        }
    }

    if let Some(expected) = map.get("const") {
        if value != expected {
            return Err(SchemaError::invalid(
                path,
                format!("must equal {}", render(expected)),
            ));
        }
    }

    if let Some(kinds) = map.get("type") {
        check_type(kinds, spath, value, path)?;
    }

    if let Some(options) = map.get("enum") {
        let options = options
            .as_array()
            .ok_or_else(|| SchemaError::unusable(spath, "\"enum\" is not an array"))?;
        if !options.iter().any(|option| option == value) {
            let rendered: Vec<String> = options.iter().map(render).collect();
            return Err(SchemaError::invalid(
                path,
                format!("{} is not one of [{}]", render(value), rendered.join(", ")),
            ));
        }
    }

    // Every remaining keyword is type-conditional: JSON Schema applies
    // `minLength` only to strings, `required` only to objects, and so on. A
    // `null` deadline therefore skips the date-time check without needing a
    // special case here.
    match value {
        Value::String(text) => check_string(map, spath, text, path)?,
        Value::Int(n) => check_integer(map, spath, *n, path)?,
        Value::Object(fields) => check_object(map, spath, fields, path)?,
        Value::Array(items) => check_array(map, spath, items, path)?,
        Value::Bool(_) | Value::Null => {}
    }

    Ok(())
}

fn is_supported_keyword(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "const"
            | "enum"
            | "required"
            | "properties"
            | "additionalProperties"
            | "items"
            | "uniqueItems"
            | "minLength"
            | "minimum"
            | "pattern"
            | "format"
    )
}

fn check_type(kinds: &Value, spath: &str, value: &Value, path: &str) -> Result<(), SchemaError> {
    let names: Vec<&str> = match kinds {
        Value::String(one) => vec![one.as_str()],
        Value::Array(many) => many
            .iter()
            .map(|k| {
                k.as_str()
                    .ok_or_else(|| SchemaError::unusable(spath, "\"type\" entry is not a string"))
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(SchemaError::unusable(
                spath,
                "\"type\" is not a string or array",
            ))
        }
    };

    let mut matched = false;
    for name in &names {
        let ok = match *name {
            "object" => matches!(value, Value::Object(_)),
            "array" => matches!(value, Value::Array(_)),
            "string" => matches!(value, Value::String(_)),
            // `canonical::Value` has no float variant by design, so "number"
            // and "integer" coincide here. Keeping both accepted means a
            // schema written by someone who did not know that still works.
            "integer" | "number" => matches!(value, Value::Int(_)),
            "boolean" => matches!(value, Value::Bool(_)),
            "null" => matches!(value, Value::Null),
            other => {
                return Err(SchemaError::unusable(
                    spath,
                    format!("unknown type name {other:?}"),
                ))
            }
        };
        matched |= ok;
    }
    if !matched {
        return Err(SchemaError::invalid(
            path,
            format!(
                "expected {} but found {}",
                names.join(" or "),
                type_of(value)
            ),
        ));
    }
    Ok(())
}

fn check_string(
    map: &BTreeMap<String, Value>,
    spath: &str,
    text: &str,
    path: &str,
) -> Result<(), SchemaError> {
    if let Some(min) = map.get("minLength") {
        let min = min.as_u64().ok_or_else(|| {
            SchemaError::unusable(spath, "\"minLength\" is not a non-negative integer")
        })?;
        if (text.chars().count() as u64) < min {
            return Err(SchemaError::invalid(
                path,
                format!("must be at least {min} character(s) long"),
            ));
        }
    }
    if let Some(pattern) = map.get("pattern") {
        let pattern = pattern
            .as_str()
            .ok_or_else(|| SchemaError::unusable(spath, "\"pattern\" is not a string"))?;
        if !pattern_matches(pattern, text).map_err(|why| SchemaError::unusable(spath, why))? {
            return Err(SchemaError::invalid(
                path,
                format!("does not match /{pattern}/"),
            ));
        }
    }
    if let Some(format) = map.get("format") {
        let format = format
            .as_str()
            .ok_or_else(|| SchemaError::unusable(spath, "\"format\" is not a string"))?;
        match format {
            "date-time" => {
                if crate::time::parse_rfc3339(text).is_none() {
                    return Err(SchemaError::invalid(
                        path,
                        "is not an RFC-3339 date-time (YYYY-MM-DDTHH:MM:SS with a UTC offset)",
                    ));
                }
            }
            other => {
                return Err(SchemaError::unusable(
                    spath,
                    format!("format {other:?} is not implemented by this validator"),
                ))
            }
        }
    }
    Ok(())
}

fn check_integer(
    map: &BTreeMap<String, Value>,
    spath: &str,
    n: i128,
    path: &str,
) -> Result<(), SchemaError> {
    if let Some(minimum) = map.get("minimum") {
        let minimum = minimum
            .as_i128()
            .ok_or_else(|| SchemaError::unusable(spath, "\"minimum\" is not an integer"))?;
        if n < minimum {
            return Err(SchemaError::invalid(path, format!("must be >= {minimum}")));
        }
    }
    Ok(())
}

fn check_object(
    map: &BTreeMap<String, Value>,
    spath: &str,
    fields: &BTreeMap<String, Value>,
    path: &str,
) -> Result<(), SchemaError> {
    if let Some(required) = map.get("required") {
        let required = required
            .as_array()
            .ok_or_else(|| SchemaError::unusable(spath, "\"required\" is not an array"))?;
        for name in required {
            let name = name.as_str().ok_or_else(|| {
                SchemaError::unusable(spath, "\"required\" entry is not a string")
            })?;
            if !fields.contains_key(name) {
                return Err(SchemaError::invalid(
                    path,
                    format!("missing required property {name:?}"),
                ));
            }
        }
    }

    let properties = match map.get("properties") {
        Some(p) => Some(
            p.as_object()
                .ok_or_else(|| SchemaError::unusable(spath, "\"properties\" is not an object"))?,
        ),
        None => None,
    };

    let additional_allowed =
        match map.get("additionalProperties") {
            Some(Value::Bool(allowed)) => *allowed,
            None => true,
            Some(_) => return Err(SchemaError::unusable(
                spath,
                "\"additionalProperties\" must be a boolean here; subschemas are not implemented",
            )),
        };

    for (name, child) in fields {
        match properties.and_then(|p| p.get(name)) {
            Some(subschema) => check(
                subschema,
                &format!("{spath}/properties/{name}"),
                child,
                &format!("{path}.{name}"),
            )?,
            None if additional_allowed => {}
            None => {
                return Err(SchemaError::invalid(
                    path,
                    format!("unknown property {name:?} is not allowed"),
                ))
            }
        }
    }
    Ok(())
}

fn check_array(
    map: &BTreeMap<String, Value>,
    spath: &str,
    items: &[Value],
    path: &str,
) -> Result<(), SchemaError> {
    if let Some(subschema) = map.get("items") {
        for (i, item) in items.iter().enumerate() {
            check(
                subschema,
                &format!("{spath}/items"),
                item,
                &format!("{path}[{i}]"),
            )?;
        }
    }
    if map.get("uniqueItems") == Some(&Value::Bool(true)) {
        for i in 1..items.len() {
            if items[..i].contains(&items[i]) {
                return Err(SchemaError::invalid(
                    path,
                    format!("duplicate entry {} at index {i}", render(&items[i])),
                ));
            }
        }
    }
    Ok(())
}

/// Anchored matcher for the tiny regex dialect the schemas actually use:
/// literals, `[...]` character classes (with ranges and a leading `^`
/// negation), and `{n}` exact repetition, between a required `^` and `$`.
///
/// A general regex engine is a dependency and an attack surface (catastrophic
/// backtracking on a pattern an objective author controls) for one production:
/// `^sha256:[0-9a-f]{64}$`. Anything outside the dialect is reported as an
/// unusable schema rather than silently passing, so widening `spec/*.json`
/// fails loudly here instead of quietly disabling the check.
fn pattern_matches(pattern: &str, text: &str) -> Result<bool, String> {
    let body = pattern
        .strip_prefix('^')
        .and_then(|p| p.strip_suffix('$'))
        .ok_or_else(|| format!("pattern /{pattern}/ is not anchored with ^ and $"))?;

    let chars: Vec<char> = body.chars().collect();
    let subject: Vec<char> = text.chars().collect();
    let mut at = 0usize;
    let mut pos = 0usize;

    while at < chars.len() {
        let (matcher, next) = parse_atom(&chars, at)?;
        at = next;
        let repeat = match parse_repeat(&chars, at)? {
            Some((n, next)) => {
                at = next;
                n
            }
            None => 1,
        };
        for _ in 0..repeat {
            match subject.get(pos) {
                Some(c) if matcher.accepts(*c) => pos += 1,
                _ => return Ok(false),
            }
        }
    }
    Ok(pos == subject.len())
}

enum Atom {
    Literal(char),
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

impl Atom {
    fn accepts(&self, c: char) -> bool {
        match self {
            Atom::Literal(want) => *want == c,
            Atom::Class { negated, ranges } => {
                let hit = ranges.iter().any(|(lo, hi)| *lo <= c && c <= *hi);
                hit != *negated
            }
        }
    }
}

fn parse_atom(chars: &[char], at: usize) -> Result<(Atom, usize), String> {
    match chars[at] {
        '[' => {
            let mut i = at + 1;
            let negated = chars.get(i) == Some(&'^');
            if negated {
                i += 1;
            }
            let mut ranges = Vec::new();
            loop {
                match chars.get(i) {
                    None => return Err("unterminated character class".into()),
                    Some(']') => {
                        i += 1;
                        break;
                    }
                    Some(&lo) => {
                        if chars.get(i + 1) == Some(&'-')
                            && chars.get(i + 2).is_some_and(|c| *c != ']')
                        {
                            let hi = chars[i + 2];
                            ranges.push((lo, hi));
                            i += 3;
                        } else {
                            ranges.push((lo, lo));
                            i += 1;
                        }
                    }
                }
            }
            Ok((Atom::Class { negated, ranges }, i))
        }
        c if "\\.*+?()|{}".contains(c) => Err(format!(
            "regex metacharacter {c:?} is outside the supported dialect"
        )),
        c => Ok((Atom::Literal(c), at + 1)),
    }
}

fn parse_repeat(chars: &[char], at: usize) -> Result<Option<(usize, usize)>, String> {
    if chars.get(at) != Some(&'{') {
        return Ok(None);
    }
    let mut i = at + 1;
    let mut digits = String::new();
    while let Some(c) = chars.get(i) {
        if c.is_ascii_digit() {
            digits.push(*c);
            i += 1;
        } else {
            break;
        }
    }
    if chars.get(i) != Some(&'}') || digits.is_empty() {
        return Err("only exact {n} repetition is supported".into());
    }
    let n = digits
        .parse::<usize>()
        .map_err(|_| "repetition count is out of range".to_string())?;
    Ok(Some((n, i + 1)))
}

fn type_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Int(_) => "integer",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn render(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::String(s) => format!("{s:?}"),
        Value::Array(_) => "an array".into(),
        Value::Object(_) => "an object".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objective_value() -> Value {
        Value::from_json(
            r#"{
              "goal": "G",
              "statement": "find a witness",
              "verifier": {"kind": "certificate", "checker": "c.py", "checker_sha256": "00"},
              "reward": 10,
              "funder": "treasury",
              "created_at": "2026-07-28T00:00:00+00:00"
            }"#,
        )
        .unwrap()
    }

    fn claim_value() -> Value {
        Value::from_json(
            r#"{
              "objective_id": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
              "submitter": "alice",
              "artifact": {"witness": 3},
              "nonce": "n",
              "created_at": "2026-07-28T00:00:00+00:00"
            }"#,
        )
        .unwrap()
    }

    fn with(base: &Value, key: &str, value: Value) -> Value {
        let mut body = base.clone();
        if let Value::Object(map) = &mut body {
            map.insert(key.into(), value);
        }
        body
    }

    #[test]
    fn a_well_formed_objective_passes() {
        validate_objective(&objective_value()).unwrap();
    }

    #[test]
    fn a_well_formed_claim_passes() {
        validate_claim(&claim_value()).unwrap();
    }

    #[test]
    fn extra_fields_are_refused() {
        let body = with(&objective_value(), "surprise", Value::Int(1));
        let err = validate_objective(&body).unwrap_err();
        assert!(err.to_string().contains("surprise"), "{err}");
    }

    #[test]
    fn unknown_verifier_kind_is_refused_at_the_schema_gate() {
        let body = with(
            &objective_value(),
            "verifier",
            Value::object([("kind", Value::string("haruspicy"))]),
        );
        let err = validate_objective(&body).unwrap_err();
        assert!(err.to_string().contains("haruspicy"), "{err}");
    }

    #[test]
    fn every_registered_verifier_kind_is_in_the_published_enum() {
        // The schema enum and the registry are two lists of the same thing;
        // adding a kind to one and not the other makes `post` refuse an
        // objective the node would happily verify.
        for kind in crate::verifiers::Kind::ALL {
            let body = with(
                &objective_value(),
                "verifier",
                Value::object([("kind", Value::string(kind.as_str()))]),
            );
            validate_objective(&body)
                .unwrap_or_else(|e| panic!("kind {} rejected by schema: {e}", kind.as_str()));
        }
    }

    #[test]
    fn a_non_string_kind_is_a_schema_violation_not_a_crash() {
        let body = with(
            &objective_value(),
            "verifier",
            Value::object([("kind", Value::Int(7))]),
        );
        assert!(validate_objective(&body).is_err());
    }

    #[test]
    fn a_negative_reward_is_refused() {
        let body = with(&objective_value(), "reward", Value::Int(-1));
        let err = validate_objective(&body).unwrap_err();
        assert!(err.to_string().contains(">= 0"), "{err}");
    }

    #[test]
    fn an_empty_statement_is_refused() {
        let body = with(&objective_value(), "statement", Value::string(""));
        assert!(validate_objective(&body).is_err());
    }

    #[test]
    fn a_null_deadline_skips_the_date_time_check() {
        let body = with(&objective_value(), "deadline", Value::Null);
        validate_objective(&body).unwrap();
    }

    #[test]
    fn a_garbage_deadline_is_refused() {
        let body = with(&objective_value(), "deadline", Value::string("soon"));
        assert!(validate_objective(&body).is_err());
    }

    #[test]
    fn confidentiality_accepts_null_and_the_three_names() {
        for value in [
            Value::Null,
            Value::string("public"),
            Value::string("embargoed"),
            Value::string("sealed"),
        ] {
            validate_objective(&with(&objective_value(), "confidentiality", value)).unwrap();
        }
        assert!(validate_objective(&with(
            &objective_value(),
            "confidentiality",
            Value::string("secret")
        ))
        .is_err());
    }

    #[test]
    fn a_claim_id_must_be_a_sha256_digest() {
        for bad in ["", "sha256:zz", "sha512:00", "0".repeat(64).as_str()] {
            let body = with(&claim_value(), "objective_id", Value::string(bad));
            assert!(validate_claim(&body).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn duplicate_citations_are_refused() {
        let one = Value::string(format!("sha256:{}", "1".repeat(64)));
        let body = with(
            &claim_value(),
            "cites",
            Value::array([one.clone(), one.clone()]),
        );
        let err = validate_claim(&body).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn the_shipped_schemas_use_no_unimplemented_keyword() {
        // `check` reports `Unusable` for a keyword it does not implement, but
        // only along the path an instance happens to take. Walk the documents
        // directly so a keyword added to a branch no test exercises still
        // trips here rather than silently doing nothing in production.
        for text in [OBJECTIVE_SCHEMA_JSON, CLAIM_SCHEMA_JSON] {
            let doc = Value::from_json(text).unwrap();
            walk(&doc, "#");
        }

        fn walk(node: &Value, spath: &str) {
            let Some(map) = node.as_object() else { return };
            for key in map.keys() {
                assert!(
                    ANNOTATIONS.contains(&key.as_str()) || is_supported_keyword(key),
                    "{spath}: keyword {key:?} is in the schema but not implemented"
                );
            }
            if let Some(pattern) = map.get("pattern").and_then(Value::as_str) {
                pattern_matches(pattern, "")
                    .unwrap_or_else(|e| panic!("{spath}: unsupported pattern: {e}"));
            }
            if let Some(properties) = map.get("properties").and_then(Value::as_object) {
                for (name, child) in properties {
                    walk(child, &format!("{spath}/properties/{name}"));
                }
            }
            if let Some(items) = map.get("items") {
                walk(items, &format!("{spath}/items"));
            }
        }
    }

    #[test]
    fn the_pattern_dialect_matches_what_it_claims() {
        assert!(pattern_matches(
            "^sha256:[0-9a-f]{64}$",
            &format!("sha256:{}", "a".repeat(64))
        )
        .unwrap());
        assert!(!pattern_matches(
            "^sha256:[0-9a-f]{64}$",
            &format!("sha256:{}", "a".repeat(63))
        )
        .unwrap());
        assert!(!pattern_matches(
            "^sha256:[0-9a-f]{64}$",
            &format!("sha256:{}", "A".repeat(64))
        )
        .unwrap());
        assert!(pattern_matches("^[^x]$", "y").unwrap());
        assert!(!pattern_matches("^[^x]$", "x").unwrap());
        // Outside the dialect: reported, never quietly treated as a match.
        assert!(pattern_matches("[0-9]+", "1").is_err());
        assert!(pattern_matches("^a.c$", "abc").is_err());
    }
}
