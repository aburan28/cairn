//! The ECC2K-130 orbit walk, native, for `cairn-solver/v1`.
//!
//! One round: read the assignment, pick a unit of the worker's slice, walk
//! trails of it on every thread offered until the round is nearly over, and
//! print the distinguished orbits reached as `{"dps": [...]}` lines the
//! objective's checker (`checkers/ecc2k130_orbit_batch.py`) accepts.
//!
//! The walk is the job's (`jobs/ecc2k130.json`), read at startup and checked
//! the way `tools/orbit_dp.py` checks it: `R_0 = Q + sum_i c_i sigma^i(P)` over
//! the 128 bits of `splitmix64(seed)`, one step `R <- R + sigma^j(R)` with
//! `j = j_base + ((HW(x) / 2) mod 8)`, `HW` read in the job's normal basis, and
//! a point distinguished at `HW(x) <= dp_max_weight`, tested before each step.
//!
//! Speed comes from two things and nothing clever: the field multiply is the
//! CPU's carry-less multiply (PMULL on arm64, PCLMULQDQ on x86-64), and each
//! thread walks a few trails side by side so that one field inversion serves
//! all of them (Montgomery's trick). Few lanes rather than thousands, because
//! a round's scratch directory is deleted when it ends: a trail still open at
//! the deadline is lost, so a lane has to finish several trails per round for
//! most of the work to count.
//!
//! Every orbit is re-derived from its witness (`[mu*alpha_0]P + [mu]Q`) before
//! it is printed, so a wrong point never reaches a batch the checker refuses
//! whole.
//!
//! An assignment carrying `"trails": N` walks exactly the first N trails of the
//! round's unit and stops: that is what the package's known-answer tests use,
//! so they end on their own instead of at a deadline. A node's assignment has
//! no such key, and the round runs until shortly before `CAIRN_ROUND_SECONDS`.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// -- GF(2^131) = F_2[z] / (z^131 + z^13 + z^2 + z + 1) --------------------------

/// Three little-endian words; the top one holds three bits.
type Fe = [u64; 3];

const M: usize = 131;
/// The only field this file multiplies in. A job naming another is refused.
const POLY_HEX: &str = "800000000000000000000000000002007";

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
#[inline(always)]
fn clmul(a: u64, b: u64) -> (u64, u64) {
    // SAFETY: the `aes` target feature (which carries PMULL) is enabled for the
    // whole build; every Apple silicon Mac has it.
    let r: u128 = unsafe { core::arch::aarch64::vmull_p64(a, b) };
    (r as u64, (r >> 64) as u64)
}

#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
#[inline(always)]
fn clmul(a: u64, b: u64) -> (u64, u64) {
    use core::arch::x86_64::*;
    // SAFETY: built with `pclmulqdq` and `sse4.1`, and `main` refuses a CPU
    // without them before any field arithmetic runs.
    unsafe {
        let r = _mm_clmulepi64_si128(
            _mm_cvtsi64_si128(a as i64),
            _mm_cvtsi64_si128(b as i64),
            0,
        );
        (
            _mm_cvtsi128_si64(r) as u64,
            _mm_extract_epi64::<1>(r) as u64,
        )
    }
}

#[cfg(not(any(
    all(target_arch = "aarch64", target_feature = "aes"),
    all(target_arch = "x86_64", target_feature = "pclmulqdq")
)))]
#[inline(always)]
fn clmul(a: u64, b: u64) -> (u64, u64) {
    let mut r: u128 = 0;
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            r ^= (a as u128) << i;
        }
    }
    (r as u64, (r >> 64) as u64)
}

/// Reduce a product of up to 261 bits.
#[inline(always)]
fn reduce(c0: u64, c1: u64, c2: u64, c3: u64, c4: u64) -> Fe {
    // h = c >> 131, at most 130 bits; z^131 = z^13 + z^2 + z + 1.
    let h0 = (c2 >> 3) | (c3 << 61);
    let h1 = (c3 >> 3) | (c4 << 61);
    let h2 = c4 >> 3;
    let t0 = h0 ^ (h0 << 1) ^ (h0 << 2) ^ (h0 << 13);
    let t1 = h1 ^ (h1 << 1) ^ (h1 << 2) ^ (h1 << 13) ^ (h0 >> 63) ^ (h0 >> 62) ^ (h0 >> 51);
    let t2 = h2 ^ (h2 << 1) ^ (h2 << 2) ^ (h2 << 13) ^ (h1 >> 63) ^ (h1 >> 62) ^ (h1 >> 51);
    let r2 = (c2 & 7) ^ t2;
    // What folded past bit 130 the first time: at most 12 bits.
    let g = r2 >> 3;
    [c0 ^ t0 ^ g ^ (g << 1) ^ (g << 2) ^ (g << 13), c1 ^ t1, r2 & 7]
}

#[inline(always)]
fn mul(a: &Fe, b: &Fe) -> Fe {
    let (p00l, p00h) = clmul(a[0], b[0]);
    let (p01l, p01h) = clmul(a[0], b[1]);
    let (p10l, p10h) = clmul(a[1], b[0]);
    let (p11l, p11h) = clmul(a[1], b[1]);
    let (p02l, p02h) = clmul(a[0], b[2]);
    let (p20l, p20h) = clmul(a[2], b[0]);
    let (p12l, p12h) = clmul(a[1], b[2]);
    let (p21l, p21h) = clmul(a[2], b[1]);
    let (p22l, _) = clmul(a[2], b[2]);
    reduce(
        p00l,
        p00h ^ p01l ^ p10l,
        p01h ^ p10h ^ p02l ^ p11l ^ p20l,
        p02h ^ p11h ^ p20h ^ p12l ^ p21l,
        p12h ^ p21h ^ p22l,
    )
}

#[inline(always)]
fn sqr(a: &Fe) -> Fe {
    let (l0, h0) = clmul(a[0], a[0]);
    let (l1, h1) = clmul(a[1], a[1]);
    let (l2, _) = clmul(a[2], a[2]);
    reduce(l0, h0, l1, h1, l2)
}

#[inline(always)]
fn sqr_n(a: &Fe, n: u32) -> Fe {
    let mut r = *a;
    for _ in 0..n {
        r = sqr(&r);
    }
    r
}

#[inline(always)]
fn add(a: &Fe, b: &Fe) -> Fe {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2]]
}

fn is_zero(a: &Fe) -> bool {
    a[0] | a[1] | a[2] == 0
}

/// `a^(2^131 - 2)` by Itoh-Tsujii: 130 squarings, 9 multiplications.
fn inv(a: &Fe) -> Fe {
    let b2 = mul(&sqr(a), a);
    let b4 = mul(&sqr_n(&b2, 2), &b2);
    let b8 = mul(&sqr_n(&b4, 4), &b4);
    let b16 = mul(&sqr_n(&b8, 8), &b8);
    let b32 = mul(&sqr_n(&b16, 16), &b16);
    let b64 = mul(&sqr_n(&b32, 32), &b32);
    let b128 = mul(&sqr_n(&b64, 64), &b64);
    let b129 = mul(&sqr(&b128), a);
    let b130 = mul(&sqr(&b129), a);
    sqr(&b130)
}

fn bit(a: &Fe, i: usize) -> bool {
    (a[i / 64] >> (i % 64)) & 1 == 1
}

fn set_bit(a: &mut Fe, i: usize) {
    a[i / 64] |= 1 << (i % 64);
}

fn weight(a: &Fe) -> u32 {
    a[0].count_ones() + a[1].count_ones() + a[2].count_ones()
}

/// Compare as 131-bit integers.
fn less(a: &Fe, b: &Fe) -> bool {
    (a[2], a[1], a[0]) < (b[2], b[1], b[0])
}

fn rotl1(a: &Fe) -> Fe {
    let top = (a[2] >> 2) & 1;
    [(a[0] << 1) | top, (a[1] << 1) | (a[0] >> 63), ((a[2] << 1) | (a[1] >> 63)) & 7]
}

fn least_rotation(a: &Fe) -> Fe {
    let mut best = *a;
    let mut c = *a;
    for _ in 1..M {
        c = rotl1(&c);
        if less(&c, &best) {
            best = c;
        }
    }
    best
}

// -- hex ------------------------------------------------------------------------

fn parse_hex_words<const N: usize>(text: &str) -> Result<[u64; N], String> {
    let digits = text.trim();
    if digits.is_empty() || digits.len() > N * 16 {
        return Err(format!("{text:?} is not a hex number of at most {} bits", N * 64));
    }
    let mut out = [0u64; N];
    for (i, ch) in digits.chars().rev().enumerate() {
        let v = ch.to_digit(16).ok_or_else(|| format!("{text:?} is not hex"))? as u64;
        out[i / 16] |= v << (4 * (i % 16));
    }
    Ok(out)
}

fn fe_hex(text: &str) -> Result<Fe, String> {
    let v = parse_hex_words::<3>(text)?;
    if v[2] >> 3 != 0 {
        return Err(format!("{text:?} has more than {M} bits"));
    }
    Ok(v)
}

fn to_hex(words: &[u64]) -> String {
    let mut s = String::new();
    for w in words.iter().rev() {
        if s.is_empty() {
            if *w != 0 {
                s = format!("{w:x}");
            }
        } else {
            s.push_str(&format!("{w:016x}"));
        }
    }
    if s.is_empty() {
        s.push('0');
    }
    s
}

// -- integers mod n (the witness) -------------------------------------------------

type U = [u64; 3];

fn u_less(a: &U, b: &U) -> bool {
    (a[2], a[1], a[0]) < (b[2], b[1], b[0])
}

fn u_add(a: &U, b: &U) -> U {
    let (s0, c0) = a[0].overflowing_add(b[0]);
    let (s1, c1a) = a[1].overflowing_add(b[1]);
    let (s1, c1b) = s1.overflowing_add(c0 as u64);
    let s2 = a[2].wrapping_add(b[2]).wrapping_add((c1a || c1b) as u64);
    [s0, s1, s2]
}

fn u_sub(a: &U, b: &U) -> U {
    let (d0, b0) = a[0].overflowing_sub(b[0]);
    let (d1, b1a) = a[1].overflowing_sub(b[1]);
    let (d1, b1b) = d1.overflowing_sub(b0 as u64);
    let d2 = a[2].wrapping_sub(b[2]).wrapping_sub((b1a || b1b) as u64);
    [d0, d1, d2]
}

/// Arithmetic mod an `n` below 2^190: plenty for a 130-bit group order.
struct Modn {
    n: U,
}

impl Modn {
    fn add(&self, a: &U, b: &U) -> U {
        let s = u_add(a, b);
        if u_less(&s, &self.n) {
            s
        } else {
            u_sub(&s, &self.n)
        }
    }

    fn reduce(&self, a: &U) -> U {
        // Only used on inputs below 2^192; shift-and-subtract.
        let mut r = [0u64; 3];
        for i in (0..192).rev() {
            r = self.add(&r, &r);
            if (a[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.add(&r, &[1, 0, 0]);
            }
        }
        r
    }

    fn mul(&self, a: &U, b: &U) -> U {
        let mut r = [0u64; 3];
        for i in (0..192).rev() {
            r = self.add(&r, &r);
            if (b[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.add(&r, a);
            }
        }
        r
    }

    fn pow(&self, base: &U, mut e: u64) -> U {
        let mut r = [1u64, 0, 0];
        let mut b = *base;
        while e > 0 {
            if e & 1 == 1 {
                r = self.mul(&r, &b);
            }
            b = self.mul(&b, &b);
            e >>= 1;
        }
        r
    }
}

// -- the curve y^2 + xy = x^3 + a x^2 + b, affine ------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Pt {
    x: Fe,
    y: Fe,
}

fn on_curve(p: &Pt, a: &Fe, b: &Fe) -> bool {
    let x2 = sqr(&p.x);
    let lhs = add(&sqr(&p.y), &mul(&p.x, &p.y));
    let rhs = add(&add(&mul(&x2, &p.x), &mul(a, &x2)), b);
    lhs == rhs
}

fn frob(p: &Pt, k: u32) -> Pt {
    Pt { x: sqr_n(&p.x, k), y: sqr_n(&p.y, k) }
}

/// Chord addition of two points with different abscissae.
fn add_raw(p: &Pt, q: &Pt, a: &Fe) -> Pt {
    let d = add(&p.x, &q.x);
    let l = mul(&add(&p.y, &q.y), &inv(&d));
    let x3 = add(&add(&add(&sqr(&l), &l), &d), a);
    let y3 = add(&add(&mul(&l, &add(&p.x, &x3)), &x3), &p.y);
    Pt { x: x3, y: y3 }
}

/// Full group law, `None` the identity.
fn padd(p: Option<Pt>, q: Option<Pt>, a: &Fe) -> Option<Pt> {
    let (p, q) = match (p, q) {
        (None, q) => return q,
        (p, None) => return p,
        (Some(p), Some(q)) => (p, q),
    };
    if p.x == q.x {
        if p.y == q.y && !is_zero(&p.x) {
            return pdbl(&p, a);
        }
        return None;
    }
    Some(add_raw(&p, &q, a))
}

fn pdbl(p: &Pt, a: &Fe) -> Option<Pt> {
    if is_zero(&p.x) {
        return None;
    }
    let l = add(&p.x, &mul(&p.y, &inv(&p.x)));
    let x3 = add(&add(&sqr(&l), &l), a);
    let y3 = add(&sqr(&p.x), &mul(&add(&l, &[1, 0, 0]), &x3));
    Some(Pt { x: x3, y: y3 })
}

/// `[c]P + [d]Q`.
fn shamir(p: &Pt, c: &U, q: &Pt, d: &U, a: &Fe) -> Option<Pt> {
    let pq = padd(Some(*p), Some(*q), a);
    let mut r: Option<Pt> = None;
    for i in (0..192).rev() {
        r = match r {
            Some(t) => pdbl(&t, a),
            None => None,
        };
        let bc = (c[i / 64] >> (i % 64)) & 1 == 1;
        let bd = (d[i / 64] >> (i % 64)) & 1 == 1;
        let addend = match (bc, bd) {
            (false, false) => continue,
            (true, false) => Some(*p),
            (false, true) => Some(*q),
            (true, true) => pq,
        };
        r = padd(r, addend, a);
    }
    r
}

// -- a small JSON reader: objects, arrays, strings, integers -------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)] // read whole, used in part
enum Json {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(map) => map.get(key),
            _ => None,
        }
    }
    fn int(&self) -> Option<i128> {
        match self {
            Json::Int(v) => Some(*v),
            _ => None,
        }
    }
    fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
}

struct Reader<'a> {
    s: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> Result<(), String> {
        self.ws();
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", c as char, self.i))
        }
    }
    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > 64 {
            return Err("JSON nested too deeply".into());
        }
        self.ws();
        match self.s.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut map = BTreeMap::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(map));
                }
                loop {
                    self.ws();
                    let key = match self.value(depth + 1)? {
                        Json::Str(k) => k,
                        _ => return Err("object keys must be strings".into()),
                    };
                    self.eat(b':')?;
                    let v = self.value(depth + 1)?;
                    map.insert(key, v);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(map));
                        }
                        _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
                    }
                }
            }
            Some(b'"') => {
                self.i += 1;
                let mut out = String::new();
                loop {
                    let c = *self.s.get(self.i).ok_or("unterminated string")?;
                    self.i += 1;
                    match c {
                        b'"' => return Ok(Json::Str(out)),
                        b'\\' => {
                            let e = *self.s.get(self.i).ok_or("unterminated escape")?;
                            self.i += 1;
                            match e {
                                b'"' => out.push('"'),
                                b'\\' => out.push('\\'),
                                b'/' => out.push('/'),
                                b'n' => out.push('\n'),
                                b't' => out.push('\t'),
                                b'r' => out.push('\r'),
                                b'b' => out.push('\u{8}'),
                                b'f' => out.push('\u{c}'),
                                b'u' => {
                                    let hex = self.s.get(self.i..self.i + 4).ok_or("short \\u")?;
                                    self.i += 4;
                                    let code = u32::from_str_radix(
                                        std::str::from_utf8(hex).map_err(|e| e.to_string())?,
                                        16,
                                    )
                                    .map_err(|e| e.to_string())?;
                                    out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                                }
                                _ => return Err("bad escape".into()),
                            }
                        }
                        _ => {
                            // Copy the rest of a UTF-8 sequence through untouched.
                            let start = self.i - 1;
                            let mut end = self.i;
                            while end < self.s.len() && (self.s[end] & 0xC0) == 0x80 {
                                end += 1;
                            }
                            out.push_str(
                                std::str::from_utf8(&self.s[start..end]).map_err(|e| e.to_string())?,
                            );
                            self.i = end;
                        }
                    }
                }
            }
            Some(b't') if self.s[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(Json::Bool(true))
            }
            Some(b'f') if self.s[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(Json::Bool(false))
            }
            Some(b'n') if self.s[self.i..].starts_with(b"null") => {
                self.i += 4;
                Ok(Json::Null)
            }
            Some(c) if *c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                self.i += 1;
                while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                    self.i += 1;
                }
                if matches!(self.s.get(self.i), Some(b'.' | b'e' | b'E')) {
                    return Err("floats are not part of the contract".into());
                }
                let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|e| e.to_string())?;
                text.parse::<i128>().map(Json::Int).map_err(|e| format!("{text}: {e}"))
            }
            _ => Err(format!("unexpected input at byte {}", self.i)),
        }
    }
}

fn parse_json(text: &str) -> Result<Json, String> {
    let mut r = Reader { s: text.as_bytes(), i: 0 };
    let v = r.value(0)?;
    r.ws();
    if r.i != r.s.len() {
        return Err(format!("trailing input at byte {}", r.i));
    }
    Ok(v)
}

// -- the job --------------------------------------------------------------------------

struct Job {
    a: Fe,
    p: Pt,
    q: Pt,
    n: Modn,
    /// `s^i mod n`, `i < m`.
    spow: Vec<U>,
    /// `1 + s^(j_base + t) mod n`.
    factor: Vec<U>,
    j_base: u32,
    start_terms: usize,
    trail_bits: u32,
    dp_max_weight: u32,
    max_batch: usize,
    units: u64,
    seed_tweak: u64,
    max_steps: u64,
    /// `sigma^i(P)` for `i < min(m, start_terms)`.
    frob_p: Vec<Pt>,
    nb: NormalBasis,
    inverter: Inverter,
}

const J_COUNT: usize = 8;

fn field(job: &Json, key: &str) -> Result<Json, String> {
    job.get(key).cloned().ok_or_else(|| format!("the job has no {key:?}"))
}

fn hex_of(job: &Json, key: &str) -> Result<String, String> {
    field(job, key)?
        .str()
        .map(str::to_string)
        .ok_or_else(|| format!("job {key:?} must be a hex string"))
}

fn int_of(job: &Json, key: &str) -> Result<i128, String> {
    field(job, key)?.int().ok_or_else(|| format!("job {key:?} must be an integer"))
}

fn point_of(job: &Json, key: &str) -> Result<Pt, String> {
    let p = field(job, key)?;
    let x = p.get("x").and_then(Json::str).ok_or_else(|| format!("job {key}.x"))?;
    let y = p.get("y").and_then(Json::str).ok_or_else(|| format!("job {key}.y"))?;
    Ok(Pt { x: fe_hex(x)?, y: fe_hex(y)? })
}

impl Job {
    fn load(text: &str) -> Result<Job, String> {
        let job = parse_json(text)?;
        if int_of(&job, "version")? != 2 {
            return Err("job version is not 2".into());
        }
        if field(&job, "family")?.str() != Some("koblitz-frobenius-rho") {
            return Err("job family is not koblitz-frobenius-rho".into());
        }
        if field(&job, "witness")?.str() != Some("j-counts") {
            return Err("this walker carries j-counts witnesses only".into());
        }
        if int_of(&job, "m")? != M as i128 || hex_of(&job, "poly")? != POLY_HEX {
            return Err(format!("this walker is built for GF(2^131) mod {POLY_HEX} only"));
        }
        if int_of(&job, "j_count")? != J_COUNT as i128 {
            return Err(format!("this walker carries {J_COUNT} branch counters"));
        }
        let a = fe_hex(&hex_of(&job, "a")?)?;
        let b = fe_hex(&hex_of(&job, "b")?)?;
        if !(is_zero(&a) || a == [1, 0, 0]) {
            return Err("a Koblitz curve has a in {0, 1}".into());
        }
        let p = point_of(&job, "generator")?;
        let q = point_of(&job, "target")?;
        let n_words = parse_hex_words::<3>(&hex_of(&job, "order")?)?;
        if n_words[2] >> 62 != 0 {
            return Err("order is too large".into());
        }
        let n = Modn { n: n_words };
        let s = n.reduce(&parse_hex_words::<3>(&hex_of(&job, "frobenius_eigenvalue")?)?);
        let small = |key: &str, lo: i128, hi: i128| -> Result<i128, String> {
            let v = int_of(&job, key)?;
            if v < lo || v > hi {
                return Err(format!("job {key:?} = {v} is outside [{lo}, {hi}]"));
            }
            Ok(v)
        };
        let j_base = small("j_base", 1, 64)? as u32;
        let start_terms = small("start_terms", 1, 4096)? as usize;
        let trail_bits = small("trail_bits", 1, 32)? as u32;
        let dp_max_weight = small("dp_max_weight", 0, M as i128)? as u32;
        let max_batch = small("max_batch", 1, 4096)? as usize;
        let units = small("units", 1, 1i128 << (64 - trail_bits))? as u64;
        let seed_tweak = small("seed", 0, u64::MAX as i128)? as u64;
        let cap = small("max_steps_per_walker", 0, u64::MAX as i128)? as u64;
        let nb_gen = fe_hex(&hex_of(&job, "nb_generator")?)?;

        if !on_curve(&p, &a, &b) {
            return Err("generator is not on the curve".into());
        }
        if !on_curve(&q, &a, &b) {
            return Err("target is not on the curve".into());
        }
        let zero = [0u64; 3];
        if shamir(&p, &n.n, &q, &zero, &a).is_some() || shamir(&p, &zero, &q, &n.n, &a).is_some() {
            return Err("P or Q does not have the job's order".into());
        }
        let two = [2u64, 0, 0];
        if n.add(&n.add(&n.mul(&s, &s), &s), &two) != zero {
            return Err("frobenius_eigenvalue is not a root of s^2 + s + 2 mod n".into());
        }
        if Some(frob(&p, 1)) != shamir(&p, &s, &q, &zero, &a) {
            return Err("frobenius_eigenvalue does not act as sigma on <P>".into());
        }
        let mut spow = vec![[1u64, 0, 0]; M];
        for i in 1..M {
            spow[i] = n.mul(&spow[i - 1], &s);
        }
        let factor = (0..J_COUNT)
            .map(|t| n.add(&[1, 0, 0], &n.pow(&s, (j_base as usize + t) as u64)))
            .collect();
        let frob_p = (0..start_terms.min(M)).map(|i| frob(&p, i as u32)).collect();
        let nb = NormalBasis::new(&nb_gen)?;
        Ok(Job {
            a,
            p,
            q,
            n,
            spow,
            factor,
            j_base,
            start_terms,
            trail_bits,
            dp_max_weight,
            max_batch,
            units,
            seed_tweak,
            max_steps: if cap == 0 { u64::MAX } else { cap },
            frob_p,
            nb,
            inverter: Inverter::new(),
        })
    }

    fn seed_of(&self, unit: u64, trail: u64) -> u64 {
        (unit << self.trail_bits) | trail
    }

    fn start_bits(&self, seed: u64) -> Vec<u64> {
        (0..self.start_terms.div_ceil(64))
            .map(|i| splitmix64(seed ^ self.seed_tweak, i as u64))
            .collect()
    }

    /// `R_0`, or `None` for a degenerate seed (two summands share an abscissa).
    fn start(&self, seed: u64) -> Option<Pt> {
        let words = self.start_bits(seed);
        let mut r = self.q;
        for i in 0..self.start_terms {
            if (words[i >> 6] >> (i & 63)) & 1 == 1 {
                let s = if i < self.frob_p.len() {
                    self.frob_p[i]
                } else {
                    frob(&self.p, (i % M) as u32)
                };
                if r.x == s.x {
                    return None;
                }
                r = add_raw(&r, &s, &self.a);
            }
        }
        Some(r)
    }

    fn alpha0(&self, seed: u64) -> U {
        let words = self.start_bits(seed);
        let mut alpha = [0u64; 3];
        for i in 0..self.start_terms {
            if (words[i >> 6] >> (i & 63)) & 1 == 1 {
                alpha = self.n.add(&alpha, &self.spow[i % M]);
            }
        }
        alpha
    }

    /// What the checker computes: the orbit the witness reaches, if any.
    fn orbit_of_witness(&self, seed: u64, counts: &[u64; J_COUNT]) -> Option<Fe> {
        let mut mu = [1u64, 0, 0];
        for (t, &c) in counts.iter().enumerate() {
            if c > 0 {
                mu = self.n.mul(&mu, &self.n.pow(&self.factor[t], c));
            }
        }
        let c = self.n.mul(&mu, &self.alpha0(seed));
        let end = shamir(&self.p, &c, &self.q, &mu, &self.a)?;
        Some(least_rotation(&self.nb.coords(&end.x)))
    }
}

fn splitmix64(seed: u64, index: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E3779B97F4A7C15u64.wrapping_mul(index + 1));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

// -- linear maps over GF(2), by table ---------------------------------------------------

/// A GF(2)-linear map of field elements, applied `B` bits of the input at a
/// time: `ceil(131 / B)` table reads instead of 131 conditional additions.
struct LinMap<const B: usize> {
    table: Vec<Fe>,
}

impl<const B: usize> LinMap<B> {
    const CHUNKS: usize = M.div_ceil(B);

    /// The map that sends `z^k` to `images[k]`.
    fn from_images(images: &[Fe]) -> Self {
        let mut table = vec![[0u64; 3]; Self::CHUNKS << B];
        for c in 0..Self::CHUNKS {
            for v in 0..1usize << B {
                let mut acc = [0u64; 3];
                for b in 0..B {
                    let k = B * c + b;
                    if (v >> b) & 1 == 1 && k < M {
                        acc = add(&acc, &images[k]);
                    }
                }
                table[(c << B) | v] = acc;
            }
        }
        LinMap { table }
    }

    /// `x -> x^(2^k)`.
    fn squarings(k: u32) -> Self {
        let images: Vec<Fe> = (0..M)
            .map(|i| {
                let mut z = [0u64; 3];
                set_bit(&mut z, i);
                sqr_n(&z, k)
            })
            .collect();
        Self::from_images(&images)
    }

    #[inline(always)]
    fn apply(&self, x: &Fe) -> Fe {
        let mask = (1u64 << B) - 1;
        let mut acc = [0u64; 3];
        for c in 0..Self::CHUNKS {
            let off = B * c;
            let v = ((x[off / 64] >> (off % 64)) & mask) as usize;
            let e = &self.table[(c << B) | v];
            acc[0] ^= e[0];
            acc[1] ^= e[1];
            acc[2] ^= e[2];
        }
        acc
    }
}

/// Field inversion for the walk: Itoh-Tsujii with its long runs of squarings
/// (8, 16, 32 and 64 in a row) replaced by one table pass each.
struct Inverter {
    sq8: LinMap<4>,
    sq16: LinMap<4>,
    sq32: LinMap<4>,
    sq64: LinMap<4>,
}

impl Inverter {
    fn new() -> Inverter {
        Inverter {
            sq8: LinMap::squarings(8),
            sq16: LinMap::squarings(16),
            sq32: LinMap::squarings(32),
            sq64: LinMap::squarings(64),
        }
    }

    fn inv(&self, a: &Fe) -> Fe {
        let b2 = mul(&sqr(a), a);
        let b4 = mul(&sqr_n(&b2, 2), &b2);
        let b8 = mul(&sqr_n(&b4, 4), &b4);
        let b16 = mul(&self.sq8.apply(&b8), &b8);
        let b32 = mul(&self.sq16.apply(&b16), &b16);
        let b64 = mul(&self.sq32.apply(&b32), &b32);
        let b128 = mul(&self.sq64.apply(&b64), &b64);
        let b129 = mul(&sqr(&b128), a);
        let b130 = mul(&sqr(&b129), a);
        sqr(&b130)
    }
}

// -- the normal basis weight and orbits are read in ------------------------------------

/// `x ->` its coordinates over `gamma^(2^i)`.
struct NormalBasis {
    map: LinMap<NB_CHUNK>,
}

const NB_CHUNK: usize = 4;

impl NormalBasis {
    fn new(gamma: &Fe) -> Result<NormalBasis, String> {
        // Columns gamma^(2^i); invert the matrix they form, over GF(2).
        let mut cols = Vec::with_capacity(M);
        let mut cur = *gamma;
        for _ in 0..M {
            cols.push(cur);
            cur = sqr(&cur);
        }
        // Row i of [C | I], C[i][j] = bit i of cols[j].
        let mut left = vec![[0u64; 3]; M];
        let mut right = vec![[0u64; 3]; M];
        for i in 0..M {
            for (j, col) in cols.iter().enumerate() {
                if bit(col, i) {
                    set_bit(&mut left[i], j);
                }
            }
            set_bit(&mut right[i], i);
        }
        for col in 0..M {
            let pivot = (col..M).find(|&r| bit(&left[r], col)).ok_or("nb_generator is not a normal element")?;
            left.swap(col, pivot);
            right.swap(col, pivot);
            for r in 0..M {
                if r != col && bit(&left[r], col) {
                    left[r] = add(&left[r], &left[col]);
                    right[r] = add(&right[r], &right[col]);
                }
            }
        }
        // Now right[i] is row i of C^-1: coordinate i of x is the parity of
        // right[i] & x, and column k of C^-1 is the coordinates of z^k.
        let images: Vec<Fe> = (0..M)
            .map(|k| {
                let mut v = [0u64; 3];
                for (i, r) in right.iter().enumerate() {
                    if bit(r, k) {
                        set_bit(&mut v, i);
                    }
                }
                v
            })
            .collect();
        Ok(NormalBasis { map: LinMap::from_images(&images) })
    }

    #[inline(always)]
    fn coords(&self, x: &Fe) -> Fe {
        self.map.apply(x)
    }

    #[inline(always)]
    fn weight(&self, x: &Fe) -> u32 {
        weight(&self.coords(x))
    }
}

// -- the walk ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Lane {
    r: Pt,
    w: u32,
    counts: [u64; J_COUNT],
    steps: u64,
    seed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Dp {
    seed: u64,
    x: Fe,
    counts: [u64; J_COUNT],
    steps: u64,
}

/// Where a round's trails come from.
struct Trails {
    next: AtomicU64,
    /// Exclusive bound on the trail counter; `u64::MAX` when the round runs
    /// to its deadline.
    limit: u64,
    first_unit: u64,
    slice_first: u64,
    slice_end: u64,
    /// Exactly these seeds instead (`--scan`).
    list: Vec<u64>,
}

impl Trails {
    fn new(limit: u64, first_unit: u64, slice_first: u64, slice_end: u64) -> Trails {
        Trails { next: AtomicU64::new(0), limit, first_unit, slice_first, slice_end, list: Vec::new() }
    }

    fn of(list: Vec<u64>) -> Trails {
        Trails { next: AtomicU64::new(0), limit: list.len() as u64, first_unit: 0, slice_first: 0, slice_end: 1, list }
    }

    /// The next seed, or `None` when the round has walked all it was given.
    fn take(&self, job: &Job) -> Option<u64> {
        let k = self.next.fetch_add(1, Ordering::Relaxed);
        if k >= self.limit {
            return None;
        }
        if !self.list.is_empty() {
            return Some(self.list[k as usize]);
        }
        let per_unit = 1u64 << job.trail_bits;
        let width = self.slice_end - self.slice_first;
        let unit = self.slice_first + (self.first_unit - self.slice_first + k / per_unit) % width;
        Some(job.seed_of(unit, k % per_unit))
    }
}

#[derive(Default, Clone, Copy)]
struct Tally {
    steps: u64,
    trails: u64,
    degenerate: u64,
    abandoned: u64,
}

/// One thread: `lanes` trails side by side until the trails or the time run out.
fn walk(job: &Job, trails: &Trails, lanes: usize, cap: u64, deadline: Instant, found: &Mutex<Vec<Dp>>) -> Tally {
    let mut tally = Tally::default();
    let mut out = Vec::new();
    let mut live: Vec<Lane> = Vec::with_capacity(lanes);
    let refill = |live: &mut Vec<Lane>, tally: &mut Tally, out: &mut Vec<Dp>| {
        while live.len() < lanes {
            let Some(seed) = trails.take(job) else { return };
            tally.trails += 1;
            let Some(r) = job.start(seed) else {
                tally.degenerate += 1;
                continue;
            };
            let w = job.nb.weight(&r.x);
            if w <= job.dp_max_weight {
                out.push(Dp { seed, x: least_rotation(&job.nb.coords(&r.x)), counts: [0; J_COUNT], steps: 0 });
                continue;
            }
            live.push(Lane { r, w, counts: [0; J_COUNT], steps: 0, seed });
        }
    };
    refill(&mut live, &mut tally, &mut out);
    let mut d = vec![[0u64; 3]; lanes];
    let mut e = vec![[0u64; 3]; lanes];
    let mut pre = vec![[0u64; 3]; lanes];
    let mut bad = vec![false; lanes];
    let mut iteration: u64 = 0;
    while !live.is_empty() {
        iteration += 1;
        if iteration % 256 == 0 && Instant::now() >= deadline {
            break;
        }
        let k = live.len();
        let mut acc = [1u64, 0, 0];
        for i in 0..k {
            let lane = &live[i];
            let j = job.j_base + ((lane.w >> 1) % J_COUNT as u32);
            let xs = sqr_n(&lane.r.x, j);
            let ys = sqr_n(&lane.r.y, j);
            let mut di = add(&lane.r.x, &xs);
            bad[i] = is_zero(&di);
            if bad[i] {
                // sigma^j(R) = +-R: only for x in GF(2), never on a trail of
                // the prime-order subgroup. Keep the batch invertible and
                // retire the lane below.
                di = [1, 0, 0];
            }
            d[i] = di;
            e[i] = add(&lane.r.y, &ys);
            pre[i] = acc;
            acc = mul(&acc, &di);
        }
        let mut inv_acc = job.inverter.inv(&acc);
        let mut i = k;
        while i > 0 {
            i -= 1;
            let inv_d = mul(&inv_acc, &pre[i]);
            inv_acc = mul(&inv_acc, &d[i]);
            let lane = &mut live[i];
            let l = mul(&e[i], &inv_d);
            let x3 = if bad[i] { [0; 3] } else { add(&add(&add(&sqr(&l), &l), &d[i]), &job.a) };
            let y3 = add(&add(&mul(&l, &add(&lane.r.x, &x3)), &x3), &lane.r.y);
            let branch = ((lane.w >> 1) % J_COUNT as u32) as usize;
            lane.r = Pt { x: x3, y: y3 };
            lane.counts[branch] += 1;
            lane.steps += 1;
            lane.w = job.nb.weight(&x3);
        }
        tally.steps += k as u64;
        // Retire what finished, refill, keep the rest in place.
        let mut i = 0;
        let mut retired = false;
        while i < live.len() {
            let lane = live[i];
            if is_zero(&lane.r.x) {
                // The identity or a 2-torsion point: off the walk; nothing to pay.
                tally.abandoned += 1;
                live.swap_remove(i);
                retired = true;
            } else if lane.w <= job.dp_max_weight {
                out.push(Dp {
                    seed: lane.seed,
                    x: least_rotation(&job.nb.coords(&lane.r.x)),
                    counts: lane.counts,
                    steps: lane.steps,
                });
                live.swap_remove(i);
                retired = true;
            } else if lane.steps >= cap {
                // The job's cap: a trail this long earns nothing.
                tally.abandoned += 1;
                live.swap_remove(i);
                retired = true;
            } else {
                i += 1;
            }
        }
        if retired {
            refill(&mut live, &mut tally, &mut out);
        }
    }
    tally.abandoned += live.len() as u64;
    found.lock().unwrap_or_else(|p| p.into_inner()).extend(out);
    tally
}

// -- the round --------------------------------------------------------------------------

fn fail(code: i32, message: &str) -> ! {
    eprintln!("ecc2k130-orbit: {message}");
    std::process::exit(code);
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.trim().parse::<u64>().ok())
}

fn element(dp: &Dp) -> String {
    let j: Vec<String> = dp.counts.iter().map(u64::to_string).collect();
    format!(
        "{{\"j\":[{}],\"seed\":\"{}\",\"x\":\"{}\"}}",
        j.join(","),
        to_hex(&[dp.seed]),
        to_hex(&dp.x)
    )
}

/// A seed for choosing a unit that no other round anywhere is likely to pick:
/// the process's own random hasher keys, mixed with what the round was given.
fn random_u64(salt: &str) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write(salt.as_bytes());
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish()
}

struct Args {
    job: String,
    lanes: usize,
    bench: Option<u64>,
}

fn args() -> Args {
    let mut out = Args { job: String::new(), lanes: 16, bench: None };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| fail(2, &format!("{a} needs a value")));
        match a.as_str() {
            "--job" => out.job = value(),
            "--lanes" => {
                out.lanes = value().parse().ok().filter(|&n| (1..=1024).contains(&n)).unwrap_or_else(|| fail(2, "--lanes is 1 to 1024"))
            }
            "--scan" => {
                let job = value();
                let first: u64 = value().parse().unwrap_or_else(|_| fail(2, "--scan JOB FIRST COUNT CAP"));
                let count: u64 = value().parse().unwrap_or_else(|_| fail(2, "--scan JOB FIRST COUNT CAP"));
                let cap: u64 = value().parse().unwrap_or_else(|_| fail(2, "--scan JOB FIRST COUNT CAP"));
                scan(&job, first, count, cap);
                std::process::exit(0);
            }
            "--bench" => out.bench = Some(value().parse().unwrap_or_else(|_| fail(2, "--bench SECONDS"))),
            _ => fail(2, &format!("unknown argument {a:?}")),
        }
    }
    if out.job.is_empty() {
        fail(2, "--job PATH is required");
    }
    out
}

/// Units whose trails 0 and 1 both end within `cap` steps: what a quick
/// known-answer test needs.
fn scan(job_path: &str, first: u64, count: u64, cap: u64) {
    let job = Job::load(&std::fs::read_to_string(job_path).unwrap()).unwrap();
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let far = Instant::now() + Duration::from_secs(1 << 30);
    let run = |seeds: Vec<u64>| -> Vec<Dp> {
        let trails = Trails::of(seeds);
        let found = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| walk(&job, &trails, 16, cap, far, &found));
            }
        });
        found.into_inner().unwrap()
    };
    let zero: Vec<Dp> = run((first..first + count).map(|u| job.seed_of(u, 0)).collect());
    let units: Vec<u64> = zero.iter().map(|d| d.seed >> job.trail_bits).collect();
    let one = run(units.iter().map(|&u| job.seed_of(u, 1)).collect());
    let mut both: Vec<(u64, u64, u64)> = one
        .iter()
        .map(|d1| {
            let u = d1.seed >> job.trail_bits;
            let d0 = zero.iter().find(|d| d.seed >> job.trail_bits == u).unwrap();
            (d0.steps.max(d1.steps), u, d0.steps + d1.steps)
        })
        .collect();
    both.sort();
    eprintln!("{} of {count} units end trail 0 within {cap} steps; {} end trails 0 and 1", zero.len(), both.len());
    for (worst, u, sum) in both {
        println!("unit {u}: longest {worst}, total {sum}");
    }
}

fn main() {
    let started = Instant::now();
    #[cfg(target_arch = "x86_64")]
    if !std::is_x86_feature_detected!("pclmulqdq") || !std::is_x86_feature_detected!("sse4.1") {
        fail(3, "this CPU has no PCLMULQDQ/SSE4.1, which this build needs");
    }
    let args = args();
    let job_text = std::fs::read_to_string(&args.job).unwrap_or_else(|e| fail(2, &format!("{}: {e}", args.job)));
    let job = Job::load(&job_text).unwrap_or_else(|e| fail(2, &format!("{}: {e}", args.job)));

    let threads = env_u64("CAIRN_THREADS")
        .map(|n| n.clamp(1, 512) as usize)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    let round_seconds = env_u64("CAIRN_ROUND_SECONDS").unwrap_or(60).max(1);
    let round = env_u64("CAIRN_ROUND").unwrap_or(0);

    let (trails, deadline, label) = if let Some(seconds) = args.bench {
        let t = Trails::new(u64::MAX, 0, 0, job.units);
        (t, started + Duration::from_secs(seconds), "bench".to_string())
    } else {
        let line = match std::env::var("CAIRN_ASSIGNMENT") {
            Ok(text) if !text.trim().is_empty() => text,
            _ => {
                let mut text = String::new();
                std::io::stdin().read_to_string(&mut text).unwrap_or_else(|e| fail(2, &format!("stdin: {e}")));
                text
            }
        };
        let assignment = parse_json(line.trim()).unwrap_or_else(|e| fail(2, &format!("bad assignment: {e}")));
        let units = assignment.get("units").unwrap_or_else(|| fail(2, "the assignment has no unit range"));
        let first = units.get("first").and_then(Json::int);
        let end = units.get("end").and_then(Json::int);
        let (first, end) = match (first, end) {
            (Some(f), Some(e)) if 0 <= f && f < e && e <= job.units as i128 => (f as u64, e as u64),
            _ => fail(2, "the assignment has no usable unit range"),
        };
        let width = end - first;
        // Grace for verifying, printing and exiting before the jail's clock.
        let grace = (round_seconds / 30).clamp(2, 20);
        let deadline = started + Duration::from_secs(round_seconds.saturating_sub(grace).max(1));
        match assignment.get("trails") {
            Some(n) => {
                let n = n.int().filter(|&n| n >= 1 && n <= 1i128 << job.trail_bits)
                    .unwrap_or_else(|| fail(2, "trails must be 1 to 2^trail_bits")) as u64;
                let unit = first + round % width;
                let t = Trails::new(n, unit, first, end);
                (t, deadline, format!("unit {unit}, trails 0..{n}"))
            }
            None => {
                let worker = std::env::var("CAIRN_WORKER").unwrap_or_default();
                let unit = first + random_u64(&format!("{line}\n{worker}\n{round}")) % width;
                let t = Trails::new(u64::MAX, unit, first, end);
                (t, deadline, format!("unit {unit} onward"))
            }
        }
    };

    let found = Mutex::new(Vec::new());
    let walked = Instant::now();
    let tallies: Vec<Tally> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                std::thread::Builder::new()
                    .stack_size(256 << 10)
                    .spawn_scoped(scope, || walk(&job, &trails, args.lanes, job.max_steps, deadline, &found))
                    .unwrap_or_else(|e| fail(1, &format!("cannot start a thread: {e}")))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| fail(1, "a walker thread panicked"))).collect()
    });
    let seconds = walked.elapsed().as_secs_f64();
    let total = tallies.iter().fold(Tally::default(), |a, t| Tally {
        steps: a.steps + t.steps,
        trails: a.trails + t.trails,
        degenerate: a.degenerate + t.degenerate,
        abandoned: a.abandoned + t.abandoned,
    });

    let mut dps = found.into_inner().unwrap_or_else(|p| p.into_inner());
    dps.sort();
    // Re-derive every orbit from its witness, as the checker will.
    let mut good = Vec::with_capacity(dps.len());
    for dp in dps {
        match job.orbit_of_witness(dp.seed, &dp.counts) {
            Some(x) if x == dp.x && weight(&x) <= job.dp_max_weight => good.push(dp),
            _ => eprintln!("ecc2k130-orbit: seed {:x}: the witness does not reach the orbit walked; dropped", dp.seed),
        }
    }
    eprintln!(
        "ecc2k130-orbit: {label}; {threads} thread(s) x {} lane(s); {} steps in {:.1} s ({:.2} M steps/s); \
         {} trail(s) started, {} distinguished, {} degenerate, {} open at the end",
        args.lanes,
        total.steps,
        seconds,
        total.steps as f64 / seconds.max(1e-9) / 1e6,
        total.trails,
        good.len(),
        total.degenerate,
        total.abandoned,
    );
    if args.bench.is_some() {
        for dp in &good {
            eprintln!("  seed {:x}: {} steps -> {}", dp.seed, dp.steps, to_hex(&dp.x));
        }
        return;
    }

    // Batches of at most max_batch, no orbit twice in one: a second trail to
    // an orbit is a collision, worth more than the orbit, and goes in a batch
    // of its own.
    let mut batches: Vec<Vec<Dp>> = Vec::new();
    for dp in good {
        if batches.iter().flatten().any(|o| o.x == dp.x) {
            eprintln!(
                "ecc2k130-orbit: COLLISION: orbit {} reached again from seed {:x}; keep both batches and run tools/orbit_dp.py collide",
                to_hex(&dp.x),
                dp.seed
            );
        }
        match batches.iter_mut().find(|b| b.len() < job.max_batch && b.iter().all(|o| o.x != dp.x)) {
            Some(b) => b.push(dp),
            None => batches.push(vec![dp]),
        }
    }
    const MAX_LINES: usize = 256;
    if batches.len() > MAX_LINES {
        eprintln!("ecc2k130-orbit: {} batches; printing the first {MAX_LINES}", batches.len());
        batches.truncate(MAX_LINES);
    }
    let mut stdout = std::io::stdout().lock();
    for batch in &batches {
        let items: Vec<String> = batch.iter().map(element).collect();
        writeln!(stdout, "{{\"dps\":[{}]}}", items.join(",")).unwrap_or_else(|e| fail(1, &format!("stdout: {e}")));
    }
}
