//! Independent native check of six-class distinguished-point certificates.
use num_bigint::BigUint;

use crate::canonical::Value;
use crate::verifiers::{Status, Verdict};

type Pt = Option<(BigUint, BigUint)>;

fn h(s: &str) -> Option<BigUint> {
    if s.is_empty()
        || s.len() > 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    BigUint::parse_bytes(s.as_bytes(), 16)
}

fn fixed(s: &str) -> BigUint {
    h(s).expect("fixed constant")
}

fn read_pt(v: &Value, prime: &BigUint) -> Option<Pt> {
    let x = h(v.get("x")?.as_str()?)?;
    let y = h(v.get("y")?.as_str()?)?;
    if x >= *prime || y >= *prime {
        return None;
    }
    Some(Some((x, y)))
}

fn minus(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a + p - (b % p)) % p
}

fn curve(pt: &Pt, p: &BigUint, b: &BigUint) -> bool {
    let Some((x, y)) = pt else { return false };
    ((y * y) + p - ((x * x * x + b) % p)) % p == BigUint::from(0u8)
}

fn sum(lhs: &Pt, rhs: &Pt, p: &BigUint) -> Pt {
    match (lhs, rhs) {
        (None, _) => rhs.clone(),
        (_, None) => lhs.clone(),
        (Some((x, y)), Some((xx, yy))) => {
            if x == xx && (y + yy) % p == BigUint::from(0u8) {
                return None;
            }
            let (top, bottom) = if x == xx {
                (BigUint::from(3u8) * x * x % p, BigUint::from(2u8) * y % p)
            } else {
                (minus(yy, y, p), minus(xx, x, p))
            };
            if bottom == BigUint::from(0u8) {
                return None;
            }
            let m = top * bottom.modpow(&(p - BigUint::from(2u8)), p) % p;
            let rx = minus(&minus(&(&m * &m % p), x, p), xx, p);
            let ry = minus(&(&m * minus(x, &rx, p) % p), y, p);
            Some((rx, ry))
        }
    }
}

fn times(pt: &Pt, scalar: &BigUint, p: &BigUint) -> Pt {
    let mut out = None;
    for byte in scalar.to_bytes_be() {
        for shift in (0..8).rev() {
            out = sum(&out, &out, p);
            if (byte >> shift) & 1 == 1 {
                out = sum(&out, pt, p);
            }
        }
    }
    out
}

struct Job {
    p: BigUint,
    n: BigUint,
    b: BigUint,
    beta: BigUint,
    g: Pt,
    q: Pt,
    id: String,
    branch_bits: u32,
    dp_bits: u64,
}

fn job(spec: &Value) -> Option<Job> {
    if spec.get("walk")?.as_str()? != "six-class-rho-secp-tight-v2/rust1" {
        return None;
    }
    let (p, n, b, beta, gx, gy) = match spec.get("curve")?.as_str()? {
        "p25" => ("203136d", "202fd77", "2", "cb89ec", "7f3fd1", "8c37a8"),
        "secp256k1" => (
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            "7",
            "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ),
        _ => return None,
    };
    let p = fixed(p);
    let n = fixed(n);
    let b = fixed(b);
    let beta = fixed(beta);
    let branches = spec.get("num_branches")?.as_u64()?;
    let dp_bits = spec.get("dp_bits")?.as_u64()?;
    if !(2..=2048).contains(&branches) || !branches.is_power_of_two() || dp_bits > 64 {
        return None;
    }
    let id = spec.get("job_id")?.as_str()?;
    if id.len() != 64 || h(id).is_none() {
        return None;
    }
    let q = read_pt(spec.get("target")?, &p)?;
    if !curve(&q, &p, &b) || times(&q, &n, &p).is_some() {
        return None;
    }
    Some(Job {
        p,
        n,
        b,
        beta,
        g: Some((fixed(gx), fixed(gy))),
        q,
        id: id.into(),
        branch_bits: branches.trailing_zeros(),
        dp_bits,
    })
}

fn valid_one(j: &Job, v: &Value) -> bool {
    if v.get("job_id").and_then(Value::as_str) != Some(j.id.as_str())
        || v.get("walker").and_then(Value::as_u64).is_none()
        || v.get("steps").and_then(Value::as_u64).is_none()
    {
        return false;
    }
    let Some(pt) = read_pt(v, &j.p) else {
        return false;
    };
    let Some((x, y)) = &pt else { return false };
    let Some(a) = v.get("a").and_then(Value::as_str).and_then(h) else {
        return false;
    };
    let Some(b) = v.get("b").and_then(Value::as_str).and_then(h) else {
        return false;
    };
    if a >= j.n || b >= j.n || !curve(&pt, &j.p, &j.b) {
        return false;
    }
    let second = (x * &j.beta) % &j.p;
    let third = (&second * &j.beta) % &j.p;
    if x > &second || x > &third || y > &(&j.p - y) {
        return false;
    }
    let mask = (BigUint::from(1u8) << j.dp_bits) - BigUint::from(1u8);
    if ((y >> j.branch_bits) & mask) != BigUint::from(0u8) {
        return false;
    }
    sum(&times(&j.g, &a, &j.p), &times(&j.q, &b, &j.p), &j.p) == pt
}

pub fn verify(spec: &Value, artifact: &Value) -> Verdict {
    let Some(j) = job(spec) else {
        return Verdict::plain(Status::InvalidSpec, "malformed native sixclass_dp spec");
    };
    let Some(dps) = artifact.get("dps").and_then(Value::as_array) else {
        return Verdict::plain(Status::Reject, "artifact needs dps array");
    };
    if dps.is_empty() || dps.len() > 64 {
        return Verdict::plain(Status::Reject, "dps count must be 1..64");
    }
    for (i, dp) in dps.iter().enumerate() {
        if !valid_one(&j, dp) {
            return Verdict::plain(Status::Reject, format!("invalid six-class DP at index {i}"));
        }
    }
    Verdict::plain(
        Status::Accept,
        format!(
            "verified {} native six-class distinguished points",
            dps.len()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_and_tamper_agree_with_primary() {
        let base = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/crypto-goals/sixclass-p25-piecework/"
        );
        let objective =
            Value::from_json(&std::fs::read_to_string(format!("{base}objective.json")).unwrap())
                .unwrap();
        let spec = objective.get("verifier").unwrap();
        let sample =
            Value::from_json(&std::fs::read_to_string(format!("{base}sample-dp.json")).unwrap())
                .unwrap();
        assert_eq!(verify(spec, &sample).status, Status::Accept);
        let mut wrong = sample.clone();
        if let Value::Object(root) = &mut wrong {
            if let Value::Array(rows) = root.get_mut("dps").unwrap() {
                if let Value::Object(dp) = &mut rows[0] {
                    dp.insert("a".into(), Value::string("1"));
                }
            }
        }
        assert_eq!(verify(spec, &wrong).status, Status::Reject);
    }
}
