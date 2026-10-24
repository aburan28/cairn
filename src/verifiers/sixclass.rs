//! Native verifier for six-class distinguished-point piecework.
//!
//! Its receipt proves a point equation and the class/DP predicate. Walker
//! provenance still needs sampled re-walks, just like existing rho piecework.
use num_bigint::BigUint;

use super::Verdict;
use crate::canonical::Value;

type Point = Option<(BigUint, BigUint)>;
const WALK: &str = "six-class-rho-secp-tight-v2/rust1";

struct Curve {
    p: BigUint,
    n: BigUint,
    b: BigUint,
    beta: BigUint,
    g: Point,
    q: Point,
    branches: u64,
    dp_bits: u64,
    job_id: String,
}

fn hex(raw: &str, max_digits: usize) -> Option<BigUint> {
    if raw.is_empty()
        || raw.len() > max_digits
        || !raw
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    BigUint::parse_bytes(raw.as_bytes(), 16)
}

fn num(raw: &str) -> BigUint {
    BigUint::parse_bytes(raw.as_bytes(), 16).expect("fixed curve constant")
}

fn point(value: &Value, p: &BigUint) -> Option<Point> {
    let x = hex(value.get("x")?.as_str()?, 64)?;
    let y = hex(value.get("y")?.as_str()?, 64)?;
    if &x >= p || &y >= p {
        return None;
    }
    Some(Some((x, y)))
}

fn sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % p
    } else {
        (p - ((b - a) % p)) % p
    }
}

fn on_curve(pt: &Point, p: &BigUint, b: &BigUint) -> bool {
    match pt {
        Some((x, y)) => (y * y) % p == ((x * x * x) + b) % p,
        None => false,
    }
}

fn add(left: &Point, right: &Point, p: &BigUint) -> Point {
    let (Some((x1, y1)), Some((x2, y2))) = (left, right) else {
        return if left.is_none() {
            right.clone()
        } else {
            left.clone()
        };
    };
    if x1 == x2 && ((y1 + y2) % p).eq(&BigUint::from(0u8)) {
        return None;
    }
    let (num, den) = if left == right {
        (
            (BigUint::from(3u8) * x1 * x1) % p,
            (BigUint::from(2u8) * y1) % p,
        )
    } else {
        (sub(y2, y1, p), sub(x2, x1, p))
    };
    if den == BigUint::from(0u8) {
        return None;
    }
    let slope = (num * den.modpow(&(p - BigUint::from(2u8)), p)) % p;
    let xx = sub(&sub(&(&slope * &slope % p), x1, p), x2, p);
    let yy = sub(&(&slope * sub(x1, &xx, p) % p), y1, p);
    Some((xx, yy))
}

fn mul(base: &Point, scalar: &BigUint, p: &BigUint) -> Point {
    let mut acc = None;
    let mut step = base.clone();
    let mut k = scalar.clone();
    while k != BigUint::from(0u8) {
        if (&k & BigUint::from(1u8)) == BigUint::from(1u8) {
            acc = add(&acc, &step, p);
        }
        step = add(&step, &step, p);
        k >>= 1;
    }
    acc
}

fn parse_spec(spec: &Value) -> Result<Curve, Verdict> {
    let invalid = || Verdict::invalid_spec("malformed native sixclass_dp spec");
    if spec.get("walk").and_then(Value::as_str) != Some(WALK) {
        return Err(invalid());
    }
    let label = spec
        .get("curve")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let (p, n, b, beta, gx, gy) = match label {
        "p25" => ("203136d", "202fd77", "2", "cb89ec", "7f3fd1", "8c37a8"),
        "secp256k1" => (
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            "7",
            "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ),
        _ => return Err(invalid()),
    };
    let p = num(p);
    let n = num(n);
    let b = num(b);
    let beta = num(beta);
    let g = Some((num(gx), num(gy)));
    let q = point(spec.get("target").ok_or_else(invalid)?, &p).ok_or_else(invalid)?;
    if !on_curve(&q, &p, &b) || mul(&q, &n, &p).is_some() {
        return Err(invalid());
    }
    let branches = spec
        .get("num_branches")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let dp_bits = spec
        .get("dp_bits")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    if !(2..=2048).contains(&branches) || !branches.is_power_of_two() || dp_bits > 64 {
        return Err(invalid());
    }
    let job_id = spec
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if job_id.len() != 64 || hex(job_id, 64).is_none() {
        return Err(invalid());
    }
    Ok(Curve {
        p,
        n,
        b,
        beta,
        g,
        q,
        branches,
        dp_bits,
        job_id: job_id.into(),
    })
}

fn check_dp(curve: &Curve, item: &Value) -> bool {
    if item.get("job_id").and_then(Value::as_str) != Some(curve.job_id.as_str())
        || item.get("walker").and_then(Value::as_u64).is_none()
        || item.get("steps").and_then(Value::as_u64).is_none()
    {
        return false;
    }
    let Some(Some((x, y))) = point(item, &curve.p) else {
        return false;
    };
    let Some(a) = item
        .get("a")
        .and_then(Value::as_str)
        .and_then(|s| hex(s, 64))
    else {
        return false;
    };
    let Some(b) = item
        .get("b")
        .and_then(Value::as_str)
        .and_then(|s| hex(s, 64))
    else {
        return false;
    };
    if a >= curve.n || b >= curve.n {
        return false;
    }
    let pt = Some((x.clone(), y.clone()));
    if !on_curve(&pt, &curve.p, &curve.b) {
        return false;
    }
    let bx = (&x * &curve.beta) % &curve.p;
    let b2x = (&bx * &curve.beta) % &curve.p;
    if x > bx || x > b2x || y > (&curve.p - &y) {
        return false;
    }
    let branch_bits = curve.branches.trailing_zeros();
    let mask = (BigUint::from(1u8) << curve.dp_bits) - BigUint::from(1u8);
    if ((&y >> branch_bits) & mask) != BigUint::from(0u8) {
        return false;
    }
    let lhs = add(
        &mul(&curve.g, &a, &curve.p),
        &mul(&curve.q, &b, &curve.p),
        &curve.p,
    );
    lhs == pt
}

pub fn verify(spec: &Value, artifact: &Value) -> Verdict {
    let curve = match parse_spec(spec) {
        Ok(c) => c,
        Err(verdict) => return verdict,
    };
    let Some(items) = artifact.get("dps").and_then(Value::as_array) else {
        return Verdict::reject("artifact needs dps array");
    };
    if items.is_empty() || items.len() > 64 {
        return Verdict::reject("dps count must be 1..64");
    }
    let mut trails = std::collections::BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        if !check_dp(&curve, item) {
            return Verdict::reject(format!("invalid six-class DP at index {index}"));
        }
        let trail = (
            item.get("walker").and_then(Value::as_u64).unwrap(),
            item.get("steps").and_then(Value::as_u64).unwrap(),
        );
        if !trails.insert(trail) {
            return Verdict::reject(format!("duplicate six-class trail at index {index}"));
        }
    }
    Verdict::accept(format!(
        "verified {} native six-class distinguished points",
        items.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p25_batch_accepts_and_tampered_coefficient_rejects() {
        let objective = Value::from_json(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/crypto-goals/sixclass-p25-piecework/objective.json"
        )))
        .unwrap();
        let spec = objective.get("verifier").unwrap();
        let sample = Value::from_json(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/crypto-goals/sixclass-p25-piecework/sample-dp.json"
        )))
        .unwrap();
        assert_eq!(verify(spec, &sample).status, super::super::Status::Accept);
        let mut bad = sample.clone();
        if let Value::Object(root) = &mut bad {
            if let Value::Array(items) = root.get_mut("dps").unwrap() {
                if let Value::Object(record) = &mut items[0] {
                    record.insert("a".into(), Value::string("1"));
                }
            }
        }
        assert_eq!(verify(spec, &bad).status, super::super::Status::Reject);
        if let Value::Object(root) = &mut bad {
            root.insert(
                "dps".into(),
                Value::Array(vec![
                    sample.get("dps").unwrap().as_array().unwrap()[0].clone(),
                    sample.get("dps").unwrap().as_array().unwrap()[0].clone(),
                ]),
            );
        }
        assert_eq!(verify(spec, &bad).status, super::super::Status::Reject);
    }
}
