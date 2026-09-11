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
//! `min`, `unit_range` is two floor divisions done in `u128`, and both are
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
            PieceworkError::OutOfRange { field, value } => {
                write!(f, "piecework field {field:?} is out of range: {value}")
            }
        }
    }
}

impl std::error::Error for PieceworkError {}

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
    /// The artifact field that names a unit. Absent means the artifact is
    /// the unit -- see the module docs.
    pub key: Option<String>,
}

impl Piecework {
    pub fn new(
        unit_price: u64,
        units: Option<u64>,
        key: Option<String>,
    ) -> Result<Piecework, PieceworkError> {
        let piecework = Piecework {
            unit_price,
            units,
            key,
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
        if self.key.as_deref().is_some_and(|key| key.is_empty()) {
            return Err(PieceworkError::EmptyKey);
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
            Some(Value::String(key)) => Some(key.clone()),
            Some(_) => {
                return Err(PieceworkError::InvalidField {
                    field: "key",
                    expected: "a string naming an artifact field",
                })
            }
        };
        Piecework::new(unit_price, units, key)
    }

    /// The canonical block, optional fields omitted when unset.
    pub fn to_value(&self) -> Value {
        let mut pairs = vec![("unit_price", Value::Int(i128::from(self.unit_price)))];
        if let Some(units) = self.units {
            pairs.push(("units", Value::Int(i128::from(units))));
        }
        if let Some(key) = &self.key {
            pairs.push(("key", Value::string(key.clone())));
        }
        Value::object(pairs)
    }

    /// What identifies an artifact's unit for the novelty rule, or `None`
    /// when the artifact names no unit under [`Piecework::key`].
    ///
    /// Prefixed so a unit key can never collide with a claim's `artifact_id`
    /// in the per-batch consumed set, which holds both. Under the digest
    /// mode the key is the artifact's own digest rather than the
    /// objective-scoped `artifact_id`, so a top-up objective that pins the
    /// same job shares one novelty history with the original.
    pub fn novelty_key(&self, artifact: &Value) -> Option<String> {
        match &self.key {
            None => Some(format!("piece:{}", artifact.digest())),
            Some(key) => artifact
                .get(key)
                .map(|unit| format!("piece:{}:{}", key, unit.digest())),
        }
    }

    /// What one more novel unit pays when `remaining` is left in the pool.
    pub fn payout(&self, remaining: u64) -> u64 {
        self.unit_price.min(remaining)
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
        assert_eq!(piecework.key.as_deref(), Some("unit"));
        assert_eq!(piecework.to_value(), value);
        let minimal = block(vec![("unit_price", Value::Int(7))]);
        let piecework = Piecework::from_value(&minimal).unwrap();
        assert_eq!(piecework.to_value(), minimal);
        assert_eq!(piecework.units, None);
        assert_eq!(piecework.key, None);
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
                expected: "a string naming an artifact field"
            })
        );
    }

    #[test]
    fn novelty_key_follows_the_mode() {
        let artifact = block(vec![("unit", Value::Int(7)), ("proof", Value::string("x"))]);
        let other = block(vec![("unit", Value::Int(7)), ("proof", Value::string("y"))]);
        let digest_mode = Piecework::new(1, None, None).unwrap();
        assert_ne!(
            digest_mode.novelty_key(&artifact),
            digest_mode.novelty_key(&other)
        );
        assert_eq!(
            digest_mode.novelty_key(&artifact),
            Some(format!("piece:{}", artifact.digest()))
        );
        let unit_mode = Piecework::new(1, None, Some("unit".into())).unwrap();
        assert_eq!(
            unit_mode.novelty_key(&artifact),
            unit_mode.novelty_key(&other)
        );
        assert_eq!(unit_mode.novelty_key(&block(vec![])), None);
    }

    #[test]
    fn payout_is_capped_by_the_pool() {
        let piecework = Piecework::new(100, None, None).unwrap();
        assert_eq!(piecework.payout(1000), 100);
        assert_eq!(piecework.payout(100), 100);
        assert_eq!(piecework.payout(37), 37);
        assert_eq!(piecework.payout(0), 0);
    }

    #[test]
    fn unit_ranges_tile_the_unit_space() {
        let piecework = Piecework::new(1, Some(1000), None).unwrap();
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
        let tiny = Piecework::new(1, Some(3), None).unwrap();
        let mut total = 0;
        for i in 0..8u64 {
            let lo = i * step;
            let hi = if i == 7 { space } else { lo + step };
            let (first, end) = tiny.unit_range((lo, hi)).unwrap();
            total += end - first;
        }
        assert_eq!(total, 3);
        assert_eq!(
            Piecework::new(1, None, None).unwrap().unit_range((0, 10)),
            None
        );
        assert_eq!(piecework.unit_range((10, 5)), Some((0, 0)));
        assert_eq!(piecework.unit_range((0, space + 1)), Some((0, 0)));
    }
}
