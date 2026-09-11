//! Piecework: pay per verified unit, from a pool, until it is gone.
//!
//! Mirrors the primary's `src/piecework.rs` and is pinned against it by the
//! `piecework` section of the conformance vectors. Three things two
//! implementations must agree on byte for byte: what a unit's novelty key
//! is, what one more unit pays, and how a `2^32`-space slice maps onto unit
//! indices. Everything else about piecework is settlement logic in `node.rs`.

use crate::canonical::Value;

const SPACE: u128 = 1 << 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piecework {
    pub unit_price: u64,
    pub units: Option<u64>,
    pub key: Option<String>,
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
            Some(Value::String(key)) if !key.is_empty() => Some(key.clone()),
            Some(Value::String(_)) => return Err("piecework key must name a field".into()),
            Some(_) => return Err("piecework key must be a string".into()),
        };
        Ok(Piecework {
            unit_price,
            units,
            key,
        })
    }

    /// `piece:<artifact digest>` with no key; `piece:<key>:<field digest>`
    /// with one. `None` when the artifact has no such field.
    pub fn novelty_key(&self, artifact: &Value) -> Option<String> {
        match &self.key {
            None => Some(format!("piece:{}", artifact.digest())),
            Some(key) => artifact
                .get(key)
                .map(|unit| format!("piece:{}:{}", key, unit.digest())),
        }
    }

    pub fn payout(&self, remaining: u64) -> u64 {
        self.unit_price.min(remaining)
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
