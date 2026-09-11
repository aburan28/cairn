//! Piecework: pay per verified unit, from a pool, until it is gone.
//!
//! Mirrors the primary's `src/piecework.rs` and is pinned against it by the
//! `piecework` section of the conformance vectors. Four things two
//! implementations must agree on byte for byte: what a unit's novelty key
//! is, which units a claim carries (one, or a batch under `items`), what
//! `n` more novel units pay, and how a `2^32`-space slice maps onto unit
//! indices. Everything else about piecework is settlement logic in
//! `node.rs`.

use std::collections::BTreeMap;

use crate::canonical::Value;

const SPACE: u128 = 1 << 32;

/// One field, or the sub-object of several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitKey {
    Field(String),
    Fields(Vec<String>),
}

impl UnitKey {
    pub fn to_value(&self) -> Value {
        match self {
            UnitKey::Field(field) => Value::string(field.clone()),
            UnitKey::Fields(fields) => {
                Value::Array(fields.iter().map(|f| Value::string(f.clone())).collect())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piecework {
    pub unit_price: u64,
    pub units: Option<u64>,
    pub key: Option<UnitKey>,
    pub items: Option<String>,
}

impl Piecework {
    pub fn from_value(value: &Value) -> Result<Piecework, String> {
        if value.as_object().is_none() {
            return Err("piecework must be an object".into());
        }
        let unit_price = match value.get("unit_price") {
            None => return Err("piecework needs a unit_price".into()),
            Some(Value::Int(n)) if *n >= 1 => {
                u64::try_from(*n).map_err(|_| "piecework unit_price does not fit in u64")?
            }
            Some(Value::Int(_)) => return Err("piecework unit_price must be at least 1".into()),
            Some(_) => return Err("piecework unit_price must be an integer".into()),
        };
        let units = match value.get("units") {
            None | Some(Value::Null) => None,
            Some(Value::Int(n)) if *n >= 1 => {
                Some(u64::try_from(*n).map_err(|_| "piecework units does not fit in u64")?)
            }
            Some(Value::Int(_)) => return Err("piecework units must be at least 1".into()),
            Some(_) => return Err("piecework units must be an integer".into()),
        };
        let key = match value.get("key") {
            None | Some(Value::Null) => None,
            Some(Value::String(key)) if !key.is_empty() => Some(UnitKey::Field(key.clone())),
            Some(Value::String(_)) => return Err("piecework key must name a field".into()),
            Some(Value::Array(fields)) => {
                let mut names = Vec::with_capacity(fields.len());
                for field in fields {
                    match field {
                        Value::String(name) if name.is_empty() => {
                            return Err("piecework key must name a field".into())
                        }
                        Value::String(name) if name.contains(',') => {
                            return Err("a piecework key field may not contain a comma".into())
                        }
                        Value::String(name) => names.push(name.clone()),
                        _ => return Err("piecework key fields must be strings".into()),
                    }
                }
                if names.is_empty() {
                    return Err("piecework key must name a field".into());
                }
                Some(UnitKey::Fields(names))
            }
            Some(_) => return Err("piecework key must be a string or an array of them".into()),
        };
        let items = match value.get("items") {
            None | Some(Value::Null) => None,
            Some(Value::String(items)) if !items.is_empty() => Some(items.clone()),
            Some(Value::String(_)) => return Err("piecework items must name a field".into()),
            Some(_) => return Err("piecework items must be a string".into()),
        };
        Ok(Piecework {
            unit_price,
            units,
            key,
            items,
        })
    }

    /// `piece:<digest>` with no key; `piece:<field>:<digest of the field>`
    /// with one; `piece:<f1,f2,…>:<digest of the sub-object>` with a list.
    /// `None` when the unit lacks a named field.
    pub fn novelty_key(&self, unit: &Value) -> Option<String> {
        match &self.key {
            None => Some(format!("piece:{}", unit.digest())),
            Some(UnitKey::Field(key)) => unit
                .get(key)
                .map(|value| format!("piece:{}:{}", key, value.digest())),
            Some(UnitKey::Fields(fields)) => {
                let mut sub = BTreeMap::new();
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

    /// The claim's units, in order, each once: the artifact's key, or one
    /// per element of the array under `items`.
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

    pub fn payout(&self, remaining: u64) -> u64 {
        self.unit_price.min(remaining)
    }

    /// `min(unit_price * novel, remaining)`, the product taken in u128.
    pub fn payout_for(&self, novel: u64, remaining: u64) -> u64 {
        let owed = u128::from(self.unit_price) * u128::from(novel);
        u64::try_from(owed.min(u128::from(remaining))).unwrap_or(remaining)
    }

    /// Two floor divisions in u128; see the primary for why that tiles.
    pub fn unit_range(&self, slice: (u64, u64)) -> Option<(u64, u64)> {
        let units = u128::from(self.units?);
        let (lo, hi) = (u128::from(slice.0), u128::from(slice.1));
        if hi < lo || hi > SPACE {
            return Some((0, 0));
        }
        Some(((lo * units / SPACE) as u64, (hi * units / SPACE) as u64))
    }
}
