//! Piecework: pay per verified unit of a problem somebody divided.
//!
//! The ratchet pays for *moving a frontier*, which needs a scalar score and
//! a problem where one result beats another. A whole class of research work
//! has neither: a search that produces many independent, individually
//! checkable outputs and is done when enough of them exist. A distributed
//! Pollard rho is one -- every distinguished point is a certificate of about
//! `2^d` group operations and is also the shared state the search runs on --
//! and relation collection for index calculus, exhaustive-search slices, and
//! any "unit `n` of `N`" decomposition are the same shape.
//!
//! Before this block existed such an objective could pay exactly one claim
//! (a certificate settles once) or none (a 2^65-operation search produces
//! nothing checkable before the final answer). Neither buys a coordinator
//! any contributors.
//!
//! # The rule
//!
//! An objective carrying `piecework` pays `unit_price` to every accepted
//! claim whose unit is **novel**, from a pool of `reward`, until the pool is
//! exhausted; a claim that arrives when less than a unit is left is paid the
//! remainder, and the next one nothing. The objective never "settles" as a
//! whole: it is closed when the pool is empty, and open until then.
//!
//! *Novel* means no **paid** claim has answered the same unit yet, and
//! which unit a claim answers is decided by [`Piecework::key`]:
//!
//! - **absent**: the artifact itself is the unit. This is the rho shape --
//!   the artifact is one distinguished point, a second submitter reaching the
//!   same point produces byte-identical bytes, and nothing beyond the log's
//!   own settlements is needed to notice.
//! - **present**: the artifact field named by `key` is the unit. Two
//!   *different* artifacts for the same unit pay once -- the second is a
//!   different answer to a question that has already been paid for. This is
//!   the "unit `n` of `N`" shape.
//!
//! A claim can also carry **many** units at once. When the block names an
//! `items` field, the artifact's array under that name is the batch, every
//! element is one unit keyed exactly as above (by its own digest, or by the
//! field(s) `key` names *of the element*), and the claim pays `unit_price`
//! for every element that is novel -- across the log and within the batch --
//! capped by what is left in the pool. This is what lets a rho search at
//! `2^44` steps per point ship a claim per hour instead of a claim per
//! point, and what lets an element carry provenance (a walker index, a
//! step count) that a sampled audit can re-walk without that provenance
//! becoming a way to re-mint a public point: `key` names the fields that
//! *are* the point, and the rest is ignored for novelty.
//!
//! `key` may therefore be one field name or a list of them. One name keys
//! on that field's value; a list keys on the sub-object of exactly those
//! fields, so a unit that lacks any of them names no unit at all.
//!
//! Paid, not merely seen. A rejected claim was not an answer, and letting it
//! consume a unit would let anybody retire a whole objective with garbage; an
//! accepted claim that arrived after the pool ran dry did the work and was
//! never paid for it, and a top-up objective pinning the same job should be
//! able to pay it. So the novelty history is the settlement history -- of
//! this objective and of every other objective carrying the same verifier
//! and the same piecework block, which is what "the same job" means here.
//!
//! # The split
//!
//! `units` declares how many units the problem divides into, which is what
//! turns [`crate::partition`]'s per-epoch slice of a `2^32` space into a
//! concrete range of unit indices a node should work. Nothing enforces the
//! split -- that is the whole point of `partition`, and the duplicate rule is
//! what makes ignoring it cost the ignorer and nobody else.
//!
//! # Notes for the port
//!
//! Every quantity here is integer money and integer counts. `payout` is a
//! `min`, `payout_for` is a saturating product under that `min`,
//! `unit_range` is two floor divisions done in `u128`, and all of them are
//! reproduced in `reference/rust/src/piecework.rs` and pinned by the
//! `piecework` section of `conformance/vectors.json`.

use std::fmt;

use crate::canonical::Value;

/// Size of the assignment space [`crate::partition::SPACE`], restated so this
/// module's arithmetic is readable on its own.
const SPACE: u128 = 1 << 32;

/// A piecework block is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceworkError {
    NotAnObject,
    MissingField {
        field: &'static str,
    },
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
    /// A unit price of zero pays nobody for anything and reads as "free"
    /// while behaving as "never". Refused so the number means what it says.
    ZeroUnitPrice,
    /// A problem divided into zero units is not divided.
    ZeroUnits,
    /// An empty key names no field, which would make every artifact the
    /// same unit.
    EmptyKey,
    /// A field name in a key list may not contain `,`: the list is joined
    /// with it in the novelty key, and two lists that join to the same
    /// string would be one key.
    KeyFieldWithComma,
    /// An empty `items` names no array, so no claim could carry a batch.
    EmptyItems,
    OutOfRange {
        field: &'static str,
        value: i128,
    },
}

impl fmt::Display for PieceworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PieceworkError::NotAnObject => f.write_str("piecework must be an object"),
            PieceworkError::MissingField { field } => write!(f, "piecework needs {field:?}"),
            PieceworkError::InvalidField { field, expected } => {
                write!(f, "piecework field {field:?} must be {expected}")
            }
            PieceworkError::ZeroUnitPrice => f.write_str("piecework unit_price must be at least 1"),
            PieceworkError::ZeroUnits => f.write_str("piecework units must be at least 1"),
            PieceworkError::EmptyKey => f.write_str("piecework key must name an artifact field"),
            PieceworkError::KeyFieldWithComma => {
                f.write_str("a piecework key field may not contain a comma")
            }
            PieceworkError::EmptyItems => {
                f.write_str("piecework items must name the artifact field holding the batch")
            }
            PieceworkError::OutOfRange { field, value } => {
                write!(f, "piecework field {field:?} is out of range: {value}")
            }
        }
    }
}

impl std::error::Error for PieceworkError {}

/// What names a unit within an artifact (or, in a batch, within one
/// element of it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitKey {
    /// One field: its value is the unit.
    Field(String),
    /// Several fields: the sub-object of exactly these is the unit, so
    /// anything else the element carries (provenance, a step count) does
    /// not make it a different unit.
    Fields(Vec<String>),
}

impl UnitKey {
    /// The key as it appears in the block: a string, or an array of them.
    pub fn to_value(&self) -> Value {
        match self {
            UnitKey::Field(field) => Value::string(field.clone()),
            UnitKey::Fields(fields) => {
                Value::Array(fields.iter().map(|f| Value::string(f.clone())).collect())
            }
        }
    }
}

/// Per-unit payout parameters. Part of the objective's id when present, like
/// the ratchet: a coordinator cannot lower the price after work has started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piecework {
    /// What one novel accepted unit pays, in the smallest unit of account.
    pub unit_price: u64,
    /// How many units the problem divides into, if the coordinator says. Read
    /// by [`Piecework::unit_range`] to turn an assignment into unit indices;
    /// nothing else consults it.
    pub units: Option<u64>,
    /// What names a unit. Absent means the unit is the whole artifact (or,
    /// with `items`, the whole element) -- see the module docs.
    pub key: Option<UnitKey>,
    /// The artifact field holding an array of units, for a batch. Absent
    /// means the artifact is one unit.
    pub items: Option<String>,
}

impl Piecework {
    pub fn new(
        unit_price: u64,
        units: Option<u64>,
        key: Option<UnitKey>,
        items: Option<String>,
    ) -> Result<Piecework, PieceworkError> {
        let piecework = Piecework {
            unit_price,
            units,
            key,
            items,
        };
        piecework.validate()?;
        Ok(piecework)
    }

    pub fn validate(&self) -> Result<(), PieceworkError> {
        if self.unit_price == 0 {
            return Err(PieceworkError::ZeroUnitPrice);
        }
        if self.units == Some(0) {
            return Err(PieceworkError::ZeroUnits);
        }
        match &self.key {
            None => {}
            Some(UnitKey::Field(field)) => {
                if field.is_empty() {
                    return Err(PieceworkError::EmptyKey);
                }
            }
            Some(UnitKey::Fields(fields)) => {
                if fields.is_empty() || fields.iter().any(String::is_empty) {
                    return Err(PieceworkError::EmptyKey);
                }
                if fields.iter().any(|f| f.contains(',')) {
                    return Err(PieceworkError::KeyFieldWithComma);
                }
            }
        }
        if self.items.as_deref().is_some_and(str::is_empty) {
            return Err(PieceworkError::EmptyItems);
        }
        Ok(())
    }

    /// Decode a `piecework` block. Unknown fields are ignored, as they are
    /// for a ratchet: the block is inside the id verbatim, so two
    /// implementations cannot disagree about its bytes, only about what they
    /// read from them -- and what they read is pinned by the vectors.
    pub fn from_value(value: &Value) -> Result<Piecework, PieceworkError> {
        if value.as_object().is_none() {
            return Err(PieceworkError::NotAnObject);
        }
        let unit_price = match value.get("unit_price") {
            None => {
                return Err(PieceworkError::MissingField {
                    field: "unit_price",
                })
            }
            Some(raw) => {
                // `as_i128` refuses booleans; `True` is not one unit of money.
                let raw = raw.as_i128().ok_or(PieceworkError::InvalidField {
                    field: "unit_price",
                    expected: "an integer",
                })?;
                u64::try_from(raw).map_err(|_| PieceworkError::OutOfRange {
                    field: "unit_price",
                    value: raw,
                })?
            }
        };
        let units = match value.get("units") {
            None | Some(Value::Null) => None,
            Some(raw) => {
                let raw = raw.as_i128().ok_or(PieceworkError::InvalidField {
                    field: "units",
                    expected: "an integer",
                })?;
                Some(u64::try_from(raw).map_err(|_| PieceworkError::OutOfRange {
                    field: "units",
                    value: raw,
                })?)
            }
        };
        let key = match value.get("key") {
            None | Some(Value::Null) => None,
            Some(Value::String(key)) => Some(UnitKey::Field(key.clone())),
            Some(Value::Array(fields)) => {
                let mut names = Vec::with_capacity(fields.len());
                for field in fields {
                    match field {
                        Value::String(name) => names.push(name.clone()),
                        _ => {
                            return Err(PieceworkError::InvalidField {
                                field: "key",
                                expected: "a string naming an artifact field, or an array of them",
                            })
                        }
                    }
                }
                Some(UnitKey::Fields(names))
            }
            Some(_) => {
                return Err(PieceworkError::InvalidField {
                    field: "key",
                    expected: "a string naming an artifact field, or an array of them",
                })
            }
        };
        let items = match value.get("items") {
            None | Some(Value::Null) => None,
            Some(Value::String(items)) => Some(items.clone()),
            Some(_) => {
                return Err(PieceworkError::InvalidField {
                    field: "items",
                    expected: "a string naming the artifact field holding the batch",
                })
            }
        };
        Piecework::new(unit_price, units, key, items)
    }

    /// The canonical block, optional fields omitted when unset.
    pub fn to_value(&self) -> Value {
        let mut pairs = vec![("unit_price", Value::Int(i128::from(self.unit_price)))];
        if let Some(units) = self.units {
            pairs.push(("units", Value::Int(i128::from(units))));
        }
        if let Some(key) = &self.key {
            pairs.push(("key", key.to_value()));
        }
        if let Some(items) = &self.items {
            pairs.push(("items", Value::string(items.clone())));
        }
        Value::object(pairs)
    }

    /// What identifies one unit for the novelty rule, or `None` when the
    /// unit names nothing under [`Piecework::key`]. `unit` is the artifact
    /// itself, or one element of the batch when `items` is set; callers
    /// wanting the claim's whole set of keys use [`Piecework::unit_keys`].
    ///
    /// Prefixed so a unit key can never collide with a claim's `artifact_id`
    /// in the per-batch consumed set, which holds both. Under the digest
    /// mode the key is the unit's own digest rather than the
    /// objective-scoped `artifact_id`, so a top-up objective that pins the
    /// same job shares one novelty history with the original. A field list
    /// keys on the digest of the sub-object of exactly those fields, under
    /// the comma-joined field names.
    pub fn novelty_key(&self, unit: &Value) -> Option<String> {
        match &self.key {
            None => Some(format!("piece:{}", unit.digest())),
            Some(UnitKey::Field(key)) => unit
                .get(key)
                .map(|value| format!("piece:{}:{}", key, value.digest())),
            Some(UnitKey::Fields(fields)) => {
                let mut sub = std::collections::BTreeMap::new();
                for field in fields {
                    sub.insert(field.clone(), unit.get(field)?.clone());
                }
                Some(format!(
                    "piece:{}:{}",
                    fields.join(","),
                    Value::Object(sub).digest()
                ))
            }
        }
    }

    /// Every unit a claim's artifact carries, in artifact order, each once:
    /// the artifact's own key when the block names no `items`, and the key
    /// of each element of the batch when it does. An element that names no
    /// unit is left out; a batch that is not an array carries nothing.
    ///
    /// Distinct within the batch by construction, so a batch cannot be paid
    /// twice for one unit by listing it twice.
    pub fn unit_keys(&self, artifact: &Value) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |key: Option<String>| {
            if let Some(key) = key {
                if !out.contains(&key) {
                    out.push(key);
                }
            }
        };
        match &self.items {
            None => push(self.novelty_key(artifact)),
            Some(items) => {
                if let Some(Value::Array(elements)) = artifact.get(items) {
                    for element in elements {
                        push(self.novelty_key(element));
                    }
                }
            }
        }
        out
    }

    /// What one more novel unit pays when `remaining` is left in the pool.
    pub fn payout(&self, remaining: u64) -> u64 {
        self.unit_price.min(remaining)
    }

    /// What `novel` novel units pay at once when `remaining` is left: the
    /// product, capped by the pool. Saturating, so a batch that would
    /// overflow `u64` at the price is simply "the whole pool".
    pub fn payout_for(&self, novel: u64, remaining: u64) -> u64 {
        let owed = u128::from(self.unit_price) * u128::from(novel);
        u64::try_from(owed.min(u128::from(remaining))).unwrap_or(remaining)
    }

    /// Map an assignment's slice `[lo, hi)` of the `2^32` space onto
    /// `[first, end)` of `[0, units)`.
    ///
    /// Two floor divisions, so consecutive slices tile the unit space with
    /// no gap and no overlap, and the last slice (whose `hi` is exactly
    /// `2^32`) ends at `units`. `None` when the objective declares no unit
    /// count. A malformed slice (`hi < lo`, or past the space) yields an
    /// empty range rather than a panic: an assignment that covers nothing
    /// is the fail-closed direction.
    pub fn unit_range(&self, slice: (u64, u64)) -> Option<(u64, u64)> {
        let units = u128::from(self.units?);
        let (lo, hi) = (u128::from(slice.0), u128::from(slice.1));
        if hi < lo || hi > SPACE {
            return Some((0, 0));
        }
        let first = lo * units / SPACE;
        let end = hi * units / SPACE;
        // Both products are at most 2^32 * 2^64 < 2^128, and both quotients
        // are at most `units`, which fits u64.
        Some((first as u64, end as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(pairs: Vec<(&str, Value)>) -> Value {
        Value::object(pairs)
    }

    #[test]
    fn decodes_and_reencodes_its_own_block() {
        let value = block(vec![
            ("unit_price", Value::Int(100)),
            ("units", Value::Int(1 << 20)),
            ("key", Value::string("unit")),
        ]);
        let piecework = Piecework::from_value(&value).unwrap();
        assert_eq!(piecework.unit_price, 100);
        assert_eq!(piecework.units, Some(1 << 20));
        assert_eq!(piecework.key, Some(UnitKey::Field("unit".into())));
        assert_eq!(piecework.to_value(), value);
        let minimal = block(vec![("unit_price", Value::Int(7))]);
        let piecework = Piecework::from_value(&minimal).unwrap();
        assert_eq!(piecework.to_value(), minimal);
        assert_eq!(piecework.units, None);
        assert_eq!(piecework.key, None);
        assert_eq!(piecework.items, None);
        let batch = block(vec![
            ("unit_price", Value::Int(100)),
            ("items", Value::string("dps")),
            (
                "key",
                Value::Array(vec![Value::string("x"), Value::string("y")]),
            ),
        ]);
        let piecework = Piecework::from_value(&batch).unwrap();
        assert_eq!(piecework.items.as_deref(), Some("dps"));
        assert_eq!(
            piecework.key,
            Some(UnitKey::Fields(vec!["x".into(), "y".into()]))
        );
        assert_eq!(piecework.to_value(), batch);
    }

    #[test]
    fn refuses_what_it_should() {
        assert_eq!(
            Piecework::from_value(&Value::Int(1)),
            Err(PieceworkError::NotAnObject)
        );
        assert_eq!(
            Piecework::from_value(&block(vec![])),
            Err(PieceworkError::MissingField {
                field: "unit_price"
            })
        );
        assert_eq!(
            Piecework::from_value(&block(vec![("unit_price", Value::Int(0))])),
            Err(PieceworkError::ZeroUnitPrice)
        );
        assert_eq!(
            Piecework::from_value(&block(vec![("unit_price", Value::Bool(true))])),
            Err(PieceworkError::InvalidField {
                field: "unit_price",
                expected: "an integer"
            })
        );
        assert_eq!(
            Piecework::from_value(&block(vec![("unit_price", Value::Int(-5))])),
            Err(PieceworkError::OutOfRange {
                field: "unit_price",
                value: -5
            })
        );
        assert_eq!(
            Piecework::from_value(&block(vec![
                ("unit_price", Value::Int(1)),
                ("units", Value::Int(0))
            ])),
            Err(PieceworkError::ZeroUnits)
        );
        assert_eq!(
            Piecework::from_value(&block(vec![
                ("unit_price", Value::Int(1)),
                ("key", Value::string(""))
            ])),
            Err(PieceworkError::EmptyKey)
        );
        assert_eq!(
            Piecework::from_value(&block(vec![
                ("unit_price", Value::Int(1)),
                ("key", Value::Int(3))
            ])),
            Err(PieceworkError::InvalidField {
                field: "key",
                expected: "a string naming an artifact field, or an array of them"
            })
        );
        assert_eq!(
            Piecework::from_value(&block(vec![
                ("unit_price", Value::Int(1)),
                ("key", Value::Array(vec![Value::string("x"), Value::Int(1)]))
            ])),
            Err(PieceworkError::InvalidField {
                field: "key",
                expected: "a string naming an artifact field, or an array of them"
            })
        );
        assert_eq!(
            Piecework::from_value(&block(vec![
                ("unit_price", Value::Int(1)),
                ("key", Value::Array(vec![]))
            ])),
            Err(PieceworkError::EmptyKey)
        );
        assert_eq!(
            Piecework::from_value(&block(vec![
                ("unit_price", Value::Int(1)),
                ("key", Value::Array(vec![Value::string("a,b")]))
            ])),
            Err(PieceworkError::KeyFieldWithComma)
        );
        assert_eq!(
            Piecework::from_value(&block(vec![
                ("unit_price", Value::Int(1)),
                ("items", Value::string(""))
            ])),
            Err(PieceworkError::EmptyItems)
        );
        assert_eq!(
            Piecework::from_value(&block(vec![
                ("unit_price", Value::Int(1)),
                ("items", Value::Int(4))
            ])),
            Err(PieceworkError::InvalidField {
                field: "items",
                expected: "a string naming the artifact field holding the batch"
            })
        );
    }

    #[test]
    fn novelty_key_follows_the_mode() {
        let artifact = block(vec![("unit", Value::Int(7)), ("proof", Value::string("x"))]);
        let other = block(vec![("unit", Value::Int(7)), ("proof", Value::string("y"))]);
        let digest_mode = Piecework::new(1, None, None, None).unwrap();
        assert_ne!(
            digest_mode.novelty_key(&artifact),
            digest_mode.novelty_key(&other)
        );
        assert_eq!(
            digest_mode.novelty_key(&artifact),
            Some(format!("piece:{}", artifact.digest()))
        );
        let unit_mode = Piecework::new(1, None, Some(UnitKey::Field("unit".into())), None).unwrap();
        assert_eq!(
            unit_mode.novelty_key(&artifact),
            unit_mode.novelty_key(&other)
        );
        assert_eq!(unit_mode.novelty_key(&block(vec![])), None);
        // A field list keys on exactly those fields: provenance is ignored.
        let point = |x: i128, walker: i128| {
            block(vec![
                ("x", Value::Int(x)),
                ("y", Value::Int(2)),
                ("walker", Value::Int(walker)),
            ])
        };
        let fields = Piecework::new(
            1,
            None,
            Some(UnitKey::Fields(vec!["x".into(), "y".into()])),
            None,
        )
        .unwrap();
        assert_eq!(
            fields.novelty_key(&point(1, 7)),
            fields.novelty_key(&point(1, 8))
        );
        assert_ne!(
            fields.novelty_key(&point(1, 7)),
            fields.novelty_key(&point(3, 7))
        );
        let sub = block(vec![("x", Value::Int(1)), ("y", Value::Int(2))]);
        assert_eq!(
            fields.novelty_key(&point(1, 7)),
            Some(format!("piece:x,y:{}", sub.digest()))
        );
        assert_eq!(fields.novelty_key(&block(vec![("x", Value::Int(1))])), None);
    }

    #[test]
    fn a_batch_carries_one_key_per_distinct_element() {
        let point = |x: i128, walker: i128| {
            block(vec![
                ("x", Value::Int(x)),
                ("y", Value::Int(2)),
                ("walker", Value::Int(walker)),
            ])
        };
        let batch = Piecework::new(
            1,
            None,
            Some(UnitKey::Fields(vec!["x".into(), "y".into()])),
            Some("dps".into()),
        )
        .unwrap();
        let artifact = block(vec![(
            "dps",
            Value::Array(vec![
                point(1, 7),
                point(1, 8), // the same point relabelled: not a second unit
                point(3, 7),
                block(vec![("x", Value::Int(9))]), // names no unit
            ]),
        )]);
        let keys = batch.unit_keys(&artifact);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], batch.novelty_key(&point(1, 7)).unwrap());
        assert_eq!(keys[1], batch.novelty_key(&point(3, 7)).unwrap());
        // Not an array, or absent: nothing.
        assert!(batch
            .unit_keys(&block(vec![("dps", Value::Int(1))]))
            .is_empty());
        assert!(batch.unit_keys(&block(vec![])).is_empty());
        // Without `items` the artifact is the one unit, as before.
        let single = Piecework::new(1, None, None, None).unwrap();
        assert_eq!(
            single.unit_keys(&artifact),
            vec![single.novelty_key(&artifact).unwrap()]
        );
    }

    #[test]
    fn payout_is_capped_by_the_pool() {
        let piecework = Piecework::new(100, None, None, None).unwrap();
        assert_eq!(piecework.payout(1000), 100);
        assert_eq!(piecework.payout(100), 100);
        assert_eq!(piecework.payout(37), 37);
        assert_eq!(piecework.payout(0), 0);
        assert_eq!(piecework.payout_for(1, 1000), 100);
        assert_eq!(piecework.payout_for(3, 1000), 300);
        assert_eq!(piecework.payout_for(3, 250), 250);
        assert_eq!(piecework.payout_for(0, 250), 0);
        assert_eq!(piecework.payout_for(u64::MAX, 250), 250);
        assert_eq!(
            Piecework::new(u64::MAX, None, None, None)
                .unwrap()
                .payout_for(u64::MAX, u64::MAX),
            u64::MAX
        );
    }

    #[test]
    fn unit_ranges_tile_the_unit_space() {
        let piecework = Piecework::new(1, Some(1000), None, None).unwrap();
        let space = 1u64 << 32;
        // Eight equal slices, as `Assignment::share` produces them.
        let step = space / 8;
        let mut covered = Vec::new();
        for i in 0..8u64 {
            let lo = i * step;
            let hi = if i == 7 { space } else { lo + step };
            let (first, end) = piecework.unit_range((lo, hi)).unwrap();
            covered.push((first, end));
        }
        assert_eq!(covered[0].0, 0);
        assert_eq!(covered[7].1, 1000);
        for pair in covered.windows(2) {
            assert_eq!(pair[0].1, pair[1].0, "gap or overlap between {pair:?}");
        }
        // Fewer units than slices: some slices are empty, none overlap.
        let tiny = Piecework::new(1, Some(3), None, None).unwrap();
        let mut total = 0;
        for i in 0..8u64 {
            let lo = i * step;
            let hi = if i == 7 { space } else { lo + step };
            let (first, end) = tiny.unit_range((lo, hi)).unwrap();
            total += end - first;
        }
        assert_eq!(total, 3);
        assert_eq!(
            Piecework::new(1, None, None, None)
                .unwrap()
                .unit_range((0, 10)),
            None
        );
        assert_eq!(piecework.unit_range((10, 5)), Some((0, 0)));
        assert_eq!(piecework.unit_range((0, space + 1)), Some((0, 0)));
    }
}
