//! Exact rational payoffs.
//!
//! An equilibrium claim is a claim about a comparison: *no player can raise its
//! own payoff by deviating*. If that comparison runs on `f64`, the claim is not
//! decidable. Two payoffs that are equal in the mechanism -- and equality is the
//! interesting case, because it separates a *strict* equilibrium from a
//! knife-edge one -- differ in the last bit after a few multiplications, and the
//! harness reports "no profitable deviation" or "deviation gain 1e-17" depending
//! on the order the terms were summed in.
//!
//! So payoffs are exact rationals over `i128`. The rest of this crate refuses
//! floats because two honest nodes must agree on an identity
//! ([`crate::canonical`]); this module refuses them for a different reason --
//! two honest *analysts* must agree on whether an inequality is strict.
//!
//! # Why saturation is the overflow policy here, and not elsewhere
//!
//! Money arithmetic in this crate returns an error rather than wrapping, because
//! a wrapped settlement mints currency. Nothing in this module is money: these
//! are modelled expectations over a hypothetical parameter set, so there is no
//! value to protect and no caller who can act on an `Err`. Writing a payoff
//! function in terms of `Result` would make the interesting code -- the payoff
//! algebra in [`super::game`] -- unreadable, which is a real cost against a
//! benefit that does not exist.
//!
//! Instead, saturation is made *unreachable* rather than merely handled:
//! [`super::NodeParams::validate`] bounds every input, [`Rat`] normalises after
//! every operation, and [`Rat::is_extreme`] lets a report state that no payoff
//! ever came near the bound. `checked_*` is available for callers that want the
//! partiality back.

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// An exact rational: `num / den`, normalised, with `den > 0`.
///
/// Normalisation is an invariant rather than a convenience, and it is what
/// makes the derived `PartialEq` correct: `1/2` and `2/4` are the same value, so
/// they must be the same bit pattern, or a `BTreeMap<Rat, _>` would hold both.
/// [`Ord`] is still hand-written, because structural ordering of `(num, den)`
/// pairs is not numeric ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rat {
    num: i128,
    den: i128,
}

/// The largest magnitude a numerator or denominator may hold.
///
/// One below `i128::MAX` in magnitude on the negative side, so that [`Rat::neg`]
/// is total: `-i128::MIN` is the one negation that overflows, and refusing to
/// represent `i128::MIN` at all is cheaper than checking for it at every use.
const LIMIT: i128 = i128::MAX;

impl Rat {
    pub const ZERO: Rat = Rat { num: 0, den: 1 };
    pub const ONE: Rat = Rat { num: 1, den: 1 };
    /// The saturation bound. A payoff equal to this is a modelling failure, not
    /// a large payoff -- see [`Rat::is_extreme`].
    pub const MAX: Rat = Rat { num: LIMIT, den: 1 };
    pub const MIN: Rat = Rat {
        num: -LIMIT,
        den: 1,
    };

    /// `num / den`, normalised. `None` if `den` is zero.
    ///
    /// A zero denominator is not "very large"; it is a division with no answer,
    /// so it is refused at construction rather than saturated. `i128::MIN` in
    /// either position is refused for the same reason it is excluded from
    /// `LIMIT`: it has no negation.
    pub fn new(num: i128, den: i128) -> Option<Rat> {
        if den == 0 || num == i128::MIN || den == i128::MIN {
            return None;
        }
        Some(Rat::normalise(num, den))
    }

    /// `n / 1`.
    pub fn int(n: i64) -> Rat {
        Rat {
            num: i128::from(n),
            den: 1,
        }
    }

    /// `n / 1` for a `u64` amount of the ledger's unit of account.
    ///
    /// `u64::MAX` is about `1.8e19` and fits `i128` with 19 digits to spare,
    /// which is the headroom the whole no-overflow argument rests on.
    pub fn units(n: u64) -> Rat {
        Rat {
            num: i128::from(n),
            den: 1,
        }
    }

    /// A probability or rate `num / den`. `None` unless it lies in `[0, 1]`.
    ///
    /// Separate from [`Rat::new`] because a "probability" outside `[0, 1]` is
    /// never a modelling choice -- it is a transposed argument -- and the type
    /// system is the cheapest place to catch it.
    pub fn rate(num: u32, den: u32) -> Option<Rat> {
        if den == 0 || num > den {
            return None;
        }
        Some(Rat::normalise(i128::from(num), i128::from(den)))
    }

    pub fn numerator(&self) -> i128 {
        self.num
    }

    /// Always positive.
    pub fn denominator(&self) -> i128 {
        self.den
    }

    pub fn is_zero(&self) -> bool {
        self.num == 0
    }

    pub fn is_positive(&self) -> bool {
        self.num > 0
    }

    pub fn is_negative(&self) -> bool {
        self.num < 0
    }

    /// True if this value sits at the saturation bound.
    ///
    /// A report that finds an extreme payoff must say so rather than draw a
    /// conclusion from it: saturation destroys the ordering that every
    /// equilibrium predicate in [`super::game`] depends on. Under
    /// [`super::NodeParams::validate`] this is unreachable, and
    /// `saturation_is_unreachable_under_validated_params` is the test that keeps
    /// it that way.
    /// Equality rather than `>=`, because `LIMIT` *is* `i128::MAX`: a
    /// numerator cannot exceed it, so the comparison would be one that can never
    /// be true. The saturating operators are the only way to reach this value
    /// and they land on it exactly.
    pub fn is_extreme(&self) -> bool {
        self.num == LIMIT || self.num == -LIMIT
    }

    pub fn abs(&self) -> Rat {
        Rat {
            num: self.num.saturating_abs(),
            den: self.den,
        }
    }

    /// Largest integer `k` with `k <= self`.
    pub fn floor(&self) -> i128 {
        let quotient = self.num / self.den;
        if self.num % self.den < 0 {
            quotient - 1
        } else {
            quotient
        }
    }

    pub fn checked_add(self, other: Rat) -> Option<Rat> {
        // Reduce by the gcd of the denominators before cross-multiplying: for
        // the rates this harness deals in (a handful of distinct denominators,
        // used over and over) that is the difference between denominators that
        // stay small and denominators that grow with every term.
        let g = gcd(self.den, other.den);
        let left_scale = other.den / g;
        let right_scale = self.den / g;
        let num = self
            .num
            .checked_mul(left_scale)?
            .checked_add(other.num.checked_mul(right_scale)?)?;
        let den = self.den.checked_mul(left_scale)?;
        Rat::new(num, den)
    }

    pub fn checked_sub(self, other: Rat) -> Option<Rat> {
        self.checked_add(other.checked_neg()?)
    }

    pub fn checked_mul(self, other: Rat) -> Option<Rat> {
        // Cross-cancel first. `(a/b) * (c/d)` with `a` and `d` sharing a factor
        // overflows if multiplied naively and does not if cancelled, and the
        // common case here is exactly that: an amount times a rate whose
        // denominator divides it.
        let left = gcd(self.num, other.den);
        let right = gcd(other.num, self.den);
        let num = (self.num / left).checked_mul(other.num / right)?;
        let den = (self.den / right).checked_mul(other.den / left)?;
        Rat::new(num, den)
    }

    /// `None` if `other` is zero.
    pub fn checked_div(self, other: Rat) -> Option<Rat> {
        if other.num == 0 {
            return None;
        }
        self.checked_mul(Rat::new(other.den, other.num)?)
    }

    pub fn checked_neg(self) -> Option<Rat> {
        Some(Rat {
            num: self.num.checked_neg()?,
            den: self.den,
        })
    }

    /// Split into `parts` equal shares. `None` if `parts` is zero.
    ///
    /// Named rather than left to `/` because dividing a pool among nodes is the
    /// single most common operation in this module and `x / Rat::int(n as i64)`
    /// reads worse and casts.
    pub fn share(self, parts: u32) -> Option<Rat> {
        if parts == 0 {
            return None;
        }
        self.checked_div(Rat::int(i64::from(parts)))
    }

    /// Truncated decimal rendering, for reports.
    ///
    /// Truncation, never rounding, and never a float on the way: this exists so
    /// a human can read a payoff, and a printed value that has been rounded is a
    /// value that can be printed as equal to another one it is not equal to.
    /// `Display` prints the exact fraction; this prints an approximation and the
    /// caller has to ask for it.
    pub fn to_decimal(&self, places: u32) -> String {
        let sign = if self.num < 0 { "-" } else { "" };
        let num = self.num.unsigned_abs();
        let den = self.den.unsigned_abs();
        let whole = num / den;
        let mut rest = num % den;
        if places == 0 {
            return format!("{sign}{whole}");
        }
        let mut digits = String::with_capacity(places as usize);
        for _ in 0..places {
            // `rest < den <= u128::MAX / 10` is not guaranteed for adversarial
            // denominators, so the multiply is checked; a denominator that large
            // cannot arise from validated parameters, and printing fewer digits
            // beats panicking in a formatter.
            rest = match rest.checked_mul(10) {
                Some(scaled) => scaled,
                None => break,
            };
            digits.push_str(&(rest / den).to_string());
            rest %= den;
        }
        format!("{sign}{whole}.{digits}")
    }

    fn normalise(num: i128, den: i128) -> Rat {
        if num == 0 {
            return Rat::ZERO;
        }
        let (num, den) = if den < 0 {
            // Negating both is safe: `i128::MIN` is refused at construction and
            // never produced, since normalisation only ever shrinks magnitudes.
            (num.saturating_neg(), den.saturating_neg())
        } else {
            (num, den)
        };
        let g = gcd(num, den);
        Rat {
            num: num / g,
            den: den / g,
        }
    }

    /// Compare without overflowing, by continued fractions.
    ///
    /// Cross-multiplication is the obvious implementation and is wrong at the
    /// edges: `a*d` and `c*b` can both overflow while `a/b` and `c/d` are
    /// perfectly ordinary. The fast path tries it anyway, because it succeeds
    /// for every value this harness produces; the fallback compares integer
    /// parts and recurses on the reciprocals, which is exact and cannot overflow
    /// because it only ever divides.
    fn compare(&self, other: &Rat) -> Ordering {
        if let (Some(left), Some(right)) = (
            self.num.checked_mul(other.den),
            other.num.checked_mul(self.den),
        ) {
            return left.cmp(&right);
        }
        let (mut a_num, mut a_den) = (self.num, self.den);
        let (mut b_num, mut b_den) = (other.num, other.den);
        let mut flipped = false;
        loop {
            let a_whole = floor_div(a_num, a_den);
            let b_whole = floor_div(b_num, b_den);
            if a_whole != b_whole {
                let ordering = a_whole.cmp(&b_whole);
                return if flipped {
                    ordering.reverse()
                } else {
                    ordering
                };
            }
            let a_rest = a_num - a_whole * a_den;
            let b_rest = b_num - b_whole * b_den;
            // Equal integer parts and at least one exact remainder: whichever
            // has the zero remainder is the smaller, unless both do.
            match (a_rest == 0, b_rest == 0) {
                (true, true) => return Ordering::Equal,
                (true, false) => {
                    return if flipped {
                        Ordering::Greater
                    } else {
                        Ordering::Less
                    }
                }
                (false, true) => {
                    return if flipped {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                }
                (false, false) => {}
            }
            // Take reciprocals of the fractional parts, which inverts the order.
            (a_num, a_den) = (a_den, a_rest);
            (b_num, b_den) = (b_den, b_rest);
            flipped = !flipped;
        }
    }
}

impl Default for Rat {
    fn default() -> Rat {
        Rat::ZERO
    }
}

impl Ord for Rat {
    fn cmp(&self, other: &Rat) -> Ordering {
        self.compare(other)
    }
}

impl PartialOrd for Rat {
    fn partial_cmp(&self, other: &Rat) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Exact fraction, or a bare integer when the denominator is one.
impl fmt::Display for Rat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.den == 1 {
            write!(f, "{}", self.num)
        } else {
            write!(f, "{}/{}", self.num, self.den)
        }
    }
}

// The operator impls saturate. See the module docs: nothing here is money, and
// the parameter validation upstream makes the bound unreachable.
impl Add for Rat {
    type Output = Rat;
    fn add(self, other: Rat) -> Rat {
        self.checked_add(other).unwrap_or(if other.is_negative() {
            Rat::MIN
        } else {
            Rat::MAX
        })
    }
}

impl Sub for Rat {
    type Output = Rat;
    fn sub(self, other: Rat) -> Rat {
        self.checked_sub(other).unwrap_or(if other.is_negative() {
            Rat::MAX
        } else {
            Rat::MIN
        })
    }
}

impl Mul for Rat {
    type Output = Rat;
    fn mul(self, other: Rat) -> Rat {
        self.checked_mul(other)
            .unwrap_or(if self.is_negative() != other.is_negative() {
                Rat::MIN
            } else {
                Rat::MAX
            })
    }
}

/// Division by zero yields [`Rat::ZERO`].
///
/// The alternative -- panicking in an operator -- would be the only panic in the
/// crate, and the callers that can genuinely divide by a modelled zero (an empty
/// set of nodes to share a pool between) want "nobody was paid", which is what
/// zero says. [`Rat::checked_div`] is there for callers that need to tell the
/// two apart.
impl Div for Rat {
    type Output = Rat;
    fn div(self, other: Rat) -> Rat {
        self.checked_div(other).unwrap_or(Rat::ZERO)
    }
}

impl Neg for Rat {
    type Output = Rat;
    fn neg(self) -> Rat {
        self.checked_neg().unwrap_or(Rat::MIN)
    }
}

impl std::iter::Sum for Rat {
    fn sum<I: Iterator<Item = Rat>>(iter: I) -> Rat {
        iter.fold(Rat::ZERO, |acc, x| acc + x)
    }
}

/// Greatest common divisor, always positive, `gcd(0, x) == |x|`, `gcd(0, 0) == 1`.
///
/// The `gcd(0, 0)` case returns one rather than zero so that callers can divide
/// by the result unconditionally. It arises for `0/1`, which normalisation
/// short-circuits, so the value is a safety net rather than a live path.
fn gcd(a: i128, b: i128) -> i128 {
    let mut a = a.saturating_abs();
    let mut b = b.saturating_abs();
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    if a == 0 {
        1
    } else {
        a
    }
}

/// `floor(a / b)` for `b > 0`, rounding towards negative infinity.
fn floor_div(a: i128, b: i128) -> i128 {
    let quotient = a / b;
    if a % b < 0 {
        quotient - 1
    } else {
        quotient
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(num: i128, den: i128) -> Rat {
        Rat::new(num, den).expect("test rational is well formed")
    }

    #[test]
    fn construction_normalises() {
        assert_eq!(r(2, 4), r(1, 2));
        assert_eq!(r(-2, -4), r(1, 2));
        assert_eq!(r(2, -4), r(-1, 2));
        assert_eq!(r(0, 5), Rat::ZERO);
        // Normalised representation is unique, which is what makes the derived
        // PartialEq a value comparison.
        assert_eq!(r(1, 2).numerator(), 1);
        assert_eq!(r(1, 2).denominator(), 2);
        assert_eq!(r(-1, 2).denominator(), 2, "sign lives in the numerator");
    }

    #[test]
    fn a_zero_denominator_is_refused_not_saturated() {
        assert_eq!(Rat::new(1, 0), None);
        assert_eq!(Rat::new(0, 0), None);
        assert_eq!(Rat::rate(1, 0), None);
    }

    #[test]
    fn i128_min_is_unrepresentable_so_negation_is_total() {
        assert_eq!(Rat::new(i128::MIN, 1), None);
        assert_eq!(Rat::new(1, i128::MIN), None);
        assert_eq!(-Rat::MIN, Rat::MAX);
        assert_eq!(-Rat::MAX, Rat::MIN);
    }

    #[test]
    fn rate_refuses_values_outside_the_unit_interval() {
        assert_eq!(Rat::rate(3, 2), None, "a probability above one");
        assert_eq!(Rat::rate(0, 100), Some(Rat::ZERO));
        assert_eq!(Rat::rate(100, 100), Some(Rat::ONE));
        assert_eq!(Rat::rate(1, 100), Some(r(1, 100)));
    }

    #[test]
    fn arithmetic_is_exact_where_floats_are_not() {
        // The canonical float embarrassment: 0.1 + 0.2 != 0.3.
        assert_eq!(r(1, 10) + r(2, 10), r(3, 10));
        // And the one that matters here: a tenth summed ten times is one, so a
        // payoff accumulated term by term compares equal to the closed form.
        let mut total = Rat::ZERO;
        for _ in 0..10 {
            total = total + r(1, 10);
        }
        assert_eq!(total, Rat::ONE);
        assert_eq!(r(1, 3) * r(3, 1), Rat::ONE);
        assert_eq!(r(1, 3) / r(1, 3), Rat::ONE);
        assert_eq!(r(7, 3) - r(1, 3), Rat::int(2));
    }

    #[test]
    fn ordering_is_numeric_not_structural() {
        assert!(r(1, 3) < r(1, 2), "bigger denominator, smaller value");
        assert!(r(-1, 2) < Rat::ZERO);
        assert!(r(-1, 2) < r(-1, 3));
        assert!(Rat::int(2) > r(3, 2));
        let mut values = vec![r(1, 2), r(-3, 4), Rat::ZERO, r(1, 3), Rat::int(5)];
        values.sort();
        assert_eq!(
            values,
            vec![r(-3, 4), Rat::ZERO, r(1, 3), r(1, 2), Rat::int(5)]
        );
    }

    #[test]
    fn comparison_survives_operands_whose_cross_product_overflows() {
        // The bug the continued-fraction fallback exists for: both cross
        // products overflow i128, while the values themselves are near one.
        let big = i128::MAX / 3;
        let left = r(big, big - 1);
        let right = r(big - 2, big - 3);
        assert!(
            left.num.checked_mul(right.den).is_none(),
            "fast path is out"
        );
        // (big)/(big-1) < (big-2)/(big-3): both exceed one, and the one with the
        // smaller terms exceeds it by more.
        assert_eq!(left.cmp(&right), Ordering::Less);
        assert_eq!(right.cmp(&left), Ordering::Greater);
        assert_eq!(left.cmp(&left), Ordering::Equal);
    }

    #[test]
    fn comparison_fallback_agrees_with_cross_multiplication_everywhere_both_work() {
        // Exhaustive over small fractions: the two paths must never disagree.
        for a_num in -6i128..=6 {
            for a_den in 1i128..=6 {
                for b_num in -6i128..=6 {
                    for b_den in 1i128..=6 {
                        let left = r(a_num, a_den);
                        let right = r(b_num, b_den);
                        let cross = (a_num * b_den).cmp(&(b_num * a_den));
                        assert_eq!(
                            left.cmp(&right),
                            cross,
                            "{left} vs {right} disagreed with cross-multiplication"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn checked_operations_report_overflow_rather_than_saturating() {
        let huge = r(LIMIT, 1);
        assert_eq!(huge.checked_add(Rat::ONE), None);
        assert_eq!(huge.checked_mul(Rat::int(2)), None);
        assert_eq!(Rat::ONE.checked_div(Rat::ZERO), None);
        assert_eq!(Rat::ONE.share(0), None);
        // And the saturating operators are what the payoff algebra sees.
        assert_eq!(huge + Rat::ONE, Rat::MAX);
        assert_eq!(huge * Rat::int(2), Rat::MAX);
        assert_eq!(-huge * Rat::int(2), Rat::MIN);
        assert_eq!(Rat::ONE / Rat::ZERO, Rat::ZERO, "nobody was paid");
    }

    #[test]
    fn cross_cancellation_keeps_realistic_products_in_range() {
        // The product that would overflow if multiplied before cancelling: the
        // whole u64 unit of account times a one-in-a-million rate.
        let amount = Rat::units(u64::MAX);
        let rate = Rat::rate(1, 1_000_000).expect("valid rate");
        let product = amount
            .checked_mul(rate)
            .expect("cancellation keeps this in range");
        assert!(!product.is_extreme());
        assert_eq!(product * Rat::int(1_000_000), amount);
    }

    #[test]
    fn is_extreme_flags_only_the_saturation_bound() {
        assert!(Rat::MAX.is_extreme());
        assert!(Rat::MIN.is_extreme());
        assert!(!Rat::units(u64::MAX).is_extreme());
        assert!(!Rat::ZERO.is_extreme());
    }

    #[test]
    fn share_divides_a_pool_without_rounding() {
        let pool = Rat::units(1000);
        assert_eq!(pool.share(3), Some(r(1000, 3)));
        // Three shares of a thousand add back to exactly a thousand, which is
        // the property integer division would lose.
        let third = pool.share(3).expect("nonzero parts");
        assert_eq!(third + third + third, pool);
    }

    #[test]
    fn floor_rounds_towards_negative_infinity() {
        assert_eq!(r(7, 2).floor(), 3);
        assert_eq!(r(-7, 2).floor(), -4);
        assert_eq!(Rat::int(4).floor(), 4);
        assert_eq!(Rat::ZERO.floor(), 0);
    }

    #[test]
    fn decimal_rendering_truncates_and_never_rounds() {
        assert_eq!(r(1, 3).to_decimal(4), "0.3333");
        assert_eq!(r(2, 3).to_decimal(4), "0.6666", "truncated, not rounded");
        assert_eq!(r(-2, 3).to_decimal(2), "-0.66");
        assert_eq!(r(5, 2).to_decimal(0), "2");
        assert_eq!(Rat::int(7).to_decimal(2), "7.00");
        assert_eq!(Rat::ZERO.to_decimal(1), "0.0");
    }

    #[test]
    fn display_shows_the_exact_fraction() {
        assert_eq!(r(1, 3).to_string(), "1/3");
        assert_eq!(Rat::int(5).to_string(), "5");
        assert_eq!(r(-1, 3).to_string(), "-1/3");
    }

    #[test]
    fn gcd_is_positive_and_never_zero() {
        assert_eq!(gcd(12, 18), 6);
        assert_eq!(gcd(-12, 18), 6);
        assert_eq!(gcd(0, 5), 5);
        assert_eq!(gcd(0, 0), 1, "callers divide by this unconditionally");
    }

    #[test]
    fn sum_folds_to_zero_on_an_empty_iterator() {
        let empty: Vec<Rat> = Vec::new();
        assert_eq!(empty.into_iter().sum::<Rat>(), Rat::ZERO);
        assert_eq!(
            vec![r(1, 2), r(1, 3), r(1, 6)].into_iter().sum::<Rat>(),
            Rat::ONE
        );
    }
}
