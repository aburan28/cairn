//! The ratchet: progressive bounties that make publishing the profitable move.
//!
//! The coordination problem in a research network is mostly self-inflicted. A
//! winner-take-all bounty gives every participant a reason to hoard: if I
//! publish an improvement so you can build on it, you can extend it by epsilon
//! and take the whole prize. So nobody shares, everybody duplicates everybody
//! else's work, and the network's throughput collapses to that of its best solo
//! participant. People then reach for elaborate coordination machinery --
//! work-unit dispatchers, locks, reservation protocols -- when the actual bug is
//! the payment structure.
//!
//! Change the structure and most of the problem dissolves:
//!
//! > An objective carries a monotone best-known score. Whoever moves it from
//! > `s0` to `s1` is paid in proportion to the distance moved. Publishing is how
//! > you get paid, so publishing immediately is optimal, and the ledger records
//! > who moved the frontier as a side effect of paying them.
//!
//! Three consequences worth stating:
//!
//! - **Copying is worthless.** Resubmitting a known artifact scores no
//!   improvement and pays zero. The thing that made hoarding rational is gone.
//! - **Duplicated work becomes visible.** The frontier is public, so nobody
//!   wastes compute rediscovering a solution that is already beaten.
//! - **Attribution is mechanical.** An improvement must cite the frontier entry
//!   it improved on -- checkable, not a judgement call -- so citation flow pays
//!   the previous holder automatically. Standing on shoulders is enforced by the
//!   submission rule rather than by etiquette.
//!
//! # The payout curve
//!
//! Payouts use a cumulative formula so they telescope exactly:
//!
//! ```text
//! cumulative(s)    = reward * (clamp(s) - baseline) / (target - baseline)
//! payout(s0 -> s1) = cumulative(s1) - cumulative(s0)
//! ```
//!
//! Total paid over any sequence of improvements equals `cumulative(final)` --
//! never more than `reward`, and exactly `reward` once the target is reached.
//! Integer arithmetic throughout, with truncating division: rounding cannot leak
//! or invent a unit no matter how finely the improvements are chopped up,
//! because every payout is a difference of the *same* floor function and the
//! intermediate roundings cancel.
//!
//! # Why this module is where the Rust port earns its keep
//!
//! The reference implementation is Python, where `reward * progress` is a
//! bignum and cannot overflow. Here both factors are `u64` and their product is
//! not -- with a realistic `reward` near 1e18 and a span of similar size, a
//! `u64` multiply wraps, and it wraps on the path that decides how much money
//! somebody is owed. Silent wrapping is not an option, so:
//!
//! - the product is formed in `u128`, where two `u64` factors always fit;
//! - the division happens before narrowing back to `u64`;
//! - the narrowing is checked and returns [`RatchetError::Overflow`] rather
//!   than truncating;
//! - the span is computed in `i128`, since `target - baseline` overflows `i64`
//!   whenever the two straddle zero at the extremes;
//! - division guards `span == 0` even though [`Ratchet::validate`] makes a
//!   zero span unconstructible. Defence in depth is warranted on a money path,
//!   and the guard costs one comparison per settlement.
//!
//! This is why [`Ratchet::cumulative`] and [`Ratchet::payout`] return `Result`
//! while the reference implementation's return plain integers. It is a real
//! difference in the failure modes of the two languages, not ceremony.

use std::fmt;
use std::str::FromStr;

use crate::canonical::Value;

/// Wire spelling of [`Direction::Maximize`], as it appears in a ratchet record.
pub const MAXIMIZE: &str = "maximize";
/// Wire spelling of [`Direction::Minimize`].
pub const MINIMIZE: &str = "minimize";

/// Which way a better score points.
///
/// The reference implementation carries this as a string and re-checks it on
/// every construction. An enum makes "direction must be maximize or minimize" a
/// property of the type: past the decoding boundary in [`Ratchet::from_value`]
/// no further validation is possible or needed, and a `match` on it is
/// exhaustive, so adding a third direction later cannot silently fall through to
/// the maximize branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Direction {
    /// Higher scores are better; `target` lies above `baseline`.
    #[default]
    Maximize,
    /// Lower scores are better; `target` lies below `baseline`.
    Minimize,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::Maximize => MAXIMIZE,
            Direction::Minimize => MINIMIZE,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Direction {
    type Err = RatchetError;

    fn from_str(s: &str) -> Result<Direction, RatchetError> {
        match s {
            MAXIMIZE => Ok(Direction::Maximize),
            MINIMIZE => Ok(Direction::Minimize),
            other => Err(RatchetError::UnknownDirection {
                direction: other.to_string(),
            }),
        }
    }
}

/// A ratchet is malformed, or its arithmetic cannot be completed exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetError {
    /// The value being decoded is not an object.
    NotAnObject { record: &'static str },
    /// A required field is absent. The reference implementation raises
    /// `KeyError` here; a typed error is the Rust equivalent.
    MissingField {
        record: &'static str,
        field: &'static str,
    },
    /// A field is present with the wrong shape. Booleans land here too:
    /// [`Value::as_i128`] refuses them, which reproduces the reference
    /// implementation's explicit `isinstance(value, bool)` rejection. `True` is
    /// not one unit of money.
    InvalidField {
        record: &'static str,
        field: &'static str,
        expected: &'static str,
    },
    /// An integer field outside the range this crate represents it in. Python's
    /// ints are unbounded, so a record it wrote can legitimately carry a value
    /// no `i64`/`u64` field here can hold; refusing it beats truncating it.
    OutOfRange { field: &'static str, value: i128 },
    /// `reward` is negative or above `u64::MAX`. Negative is refused by the
    /// reference implementation too; the upper bound is this crate's.
    RewardOutOfRange { reward: i128 },
    /// `direction` was a string, but not one of the two known spellings.
    UnknownDirection { direction: String },
    /// `min_improvement` below 1. A ratchet that accepts a zero-sized
    /// improvement pays for standing still.
    MinImprovementTooSmall,
    /// Maximizing with `target <= baseline`: there is no distance to move, and
    /// `cumulative` would divide by zero or by a negative span.
    TargetNotAboveBaseline { baseline: i64, target: i64 },
    /// Minimizing with `target >= baseline`. Same reason, mirrored.
    TargetNotBelowBaseline { baseline: i64, target: i64 },
    /// `span == 0` on a division path. [`Ratchet::validate`] makes this
    /// unreachable through the constructors; it is caught anyway because a
    /// panicking divide-by-zero inside a settlement is a far worse outcome than
    /// a refused settlement.
    DegenerateSpan,
    /// A money computation could not be represented exactly. Unreachable for
    /// any ratchet that passed [`Ratchet::validate`] -- `cumulative <= reward`
    /// always holds -- but reported rather than wrapped, because a wrapped
    /// payout is an invented or destroyed unit of account.
    Overflow { what: &'static str },
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RatchetError::NotAnObject { record } => {
                write!(f, "{record}: record must be an object")
            }
            RatchetError::MissingField { record, field } => {
                write!(f, "{record}: missing required field {field:?}")
            }
            RatchetError::InvalidField {
                record,
                field,
                expected,
            } => write!(f, "{record}: field {field:?} must be {expected}"),
            RatchetError::OutOfRange { field, value } => write!(
                f,
                "{field} {value} is outside the range this implementation represents"
            ),
            RatchetError::RewardOutOfRange { reward } => write!(
                f,
                "reward {reward} must be non-negative and at most \
                 18446744073709551615 units"
            ),
            RatchetError::UnknownDirection { direction } => write!(
                f,
                "direction must be {MAXIMIZE} or {MINIMIZE}, not {direction:?}"
            ),
            RatchetError::MinImprovementTooSmall => {
                f.write_str("min_improvement must be at least 1")
            }
            RatchetError::TargetNotAboveBaseline { baseline, target } => write!(
                f,
                "target must exceed baseline when maximizing (baseline {baseline}, \
                 target {target})"
            ),
            RatchetError::TargetNotBelowBaseline { baseline, target } => write!(
                f,
                "target must be below baseline when minimizing (baseline {baseline}, \
                 target {target})"
            ),
            RatchetError::DegenerateSpan => {
                f.write_str("ratchet span is zero; there is no distance to pay for")
            }
            RatchetError::Overflow { what } => {
                write!(f, "{what} overflowed; refusing to wrap on a money path")
            }
        }
    }
}

impl std::error::Error for RatchetError {}

// -- decoding helpers ------------------------------------------------------

fn required<'a>(
    value: &'a Value,
    record: &'static str,
    field: &'static str,
) -> Result<&'a Value, RatchetError> {
    value
        .get(field)
        .ok_or(RatchetError::MissingField { record, field })
}

fn required_int(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<i128, RatchetError> {
    required(value, record, field)?
        .as_i128()
        .ok_or(RatchetError::InvalidField {
            record,
            field,
            expected: "an integer",
        })
}

fn required_i64(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<i64, RatchetError> {
    let raw = required_int(value, record, field)?;
    i64::try_from(raw).map_err(|_| RatchetError::OutOfRange { field, value: raw })
}

fn required_u64(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<u64, RatchetError> {
    let raw = required_int(value, record, field)?;
    u64::try_from(raw).map_err(|_| RatchetError::OutOfRange { field, value: raw })
}

fn required_string(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<String, RatchetError> {
    match required(value, record, field)? {
        Value::String(s) => Ok(s.clone()),
        _ => Err(RatchetError::InvalidField {
            record,
            field,
            expected: "a string",
        }),
    }
}

// -- ratchet ---------------------------------------------------------------

/// Progressive-bounty parameters attached to an objective.
///
/// The fields are public so that a caller can read the pool it is settling
/// against (`node` checks `ratchet.reward` against `objective.reward`: there is
/// one pool, not two). That means a struct literal can build an invalid ratchet,
/// exactly as in [`crate::records`], so the invariants live in
/// [`Ratchet::validate`] and are run by [`Ratchet::new`] and
/// [`Ratchet::from_value`]. Code that assembles a `Ratchet` by hand from
/// untrusted input must call `validate` before trusting its arithmetic.
///
/// Two invariants the reference implementation checks at runtime are gone from
/// `validate` because the types already carry them: `reward >= 0` (`u64`) and
/// "these fields are integers, not bools or floats" ([`Value`] has no float
/// variant and [`Value::as_i128`] refuses bools).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ratchet {
    /// Score the objective starts from. Anything at or below it (at or above,
    /// when minimizing) has moved nothing and pays nothing.
    pub baseline: i64,
    /// Score at which the pool is exactly exhausted. Overshooting pays no more.
    pub target: i64,
    /// The whole pool, in the smallest unit of account. Paid out in full if and
    /// only if the frontier reaches `target`.
    pub reward: u64,
    pub direction: Direction,
    /// Smallest score movement that counts. Raising it blocks epsilon-farming
    /// at the cost of also blocking genuine small gains -- a real tradeoff, not
    /// a free win.
    pub min_improvement: u64,
}

impl Ratchet {
    /// Build a validated ratchet. Argument order matches the reference
    /// implementation's dataclass fields.
    pub fn new(
        baseline: i64,
        target: i64,
        reward: u64,
        direction: Direction,
        min_improvement: u64,
    ) -> Result<Ratchet, RatchetError> {
        let ratchet = Ratchet {
            baseline,
            target,
            reward,
            direction,
            min_improvement,
        };
        ratchet.validate()?;
        Ok(ratchet)
    }

    /// The invariants the reference implementation enforces in `__post_init__`.
    ///
    /// The direction checks are not style: they are what guarantees
    /// `span() > 0`, and therefore what makes the division in
    /// [`Ratchet::cumulative`] well defined for every score.
    pub fn validate(&self) -> Result<(), RatchetError> {
        if self.min_improvement < 1 {
            return Err(RatchetError::MinImprovementTooSmall);
        }
        match self.direction {
            Direction::Maximize if self.target <= self.baseline => {
                Err(RatchetError::TargetNotAboveBaseline {
                    baseline: self.baseline,
                    target: self.target,
                })
            }
            Direction::Minimize if self.target >= self.baseline => {
                Err(RatchetError::TargetNotBelowBaseline {
                    baseline: self.baseline,
                    target: self.target,
                })
            }
            _ => Ok(()),
        }
    }

    // -- geometry ----------------------------------------------------------

    /// Distance from baseline to target, always non-negative.
    ///
    /// Computed in `i128`: `target - baseline` overflows `i64` for a ratchet
    /// whose endpoints straddle zero at the extremes (`i64::MIN` to `i64::MAX`
    /// is `u64::MAX`, one past what `i64` can hold). The widened difference
    /// always fits `u64` afterwards, since that is the largest gap two `i64`s
    /// can have.
    pub fn span(&self) -> u64 {
        let diff = i128::from(self.target) - i128::from(self.baseline);
        // |diff| <= u64::MAX for any pair of i64 endpoints, so the conversion
        // is total; the fallback exists only to keep this function panic-free.
        u64::try_from(diff.unsigned_abs()).unwrap_or(u64::MAX)
    }

    /// Distance from baseline toward target, clamped to `[0, span]`.
    ///
    /// Clamping at both ends is what makes the curve monotone and bounded: work
    /// below the baseline is not negative progress that could claw money back,
    /// and overshooting the target does not mint progress the pool cannot fund.
    pub fn progress(&self, score: i64) -> u64 {
        let raw: i128 = match self.direction {
            Direction::Maximize => i128::from(score) - i128::from(self.baseline),
            Direction::Minimize => i128::from(self.baseline) - i128::from(score),
        };
        let span = i128::from(self.span());
        // Written out rather than with `clamp`, which panics when min > max.
        let clamped = if raw <= 0 {
            0
        } else if raw >= span {
            span
        } else {
            raw
        };
        // clamped is in [0, span] and span <= u64::MAX, so this is total. Zero
        // is the conservative fallback: under-paying can be corrected by a
        // later improvement, over-paying cannot be corrected at all.
        u64::try_from(clamped).unwrap_or(0)
    }

    /// Does moving from `old` to `new` clear the minimum improvement?
    ///
    /// `None` means the frontier is empty, which is not the same as a score of
    /// `baseline` in general but has the same progress: zero.
    pub fn improves(&self, old: Option<i64>, new: i64) -> bool {
        let gained = match old {
            None => i128::from(self.progress(new)),
            // In i128 because the difference of two u64 progresses is signed:
            // a regression must come out negative, not wrap to something huge.
            Some(old) => i128::from(self.progress(new)) - i128::from(self.progress(old)),
        };
        gained >= i128::from(self.min_improvement)
    }

    // -- money -------------------------------------------------------------

    /// Total the objective has paid out once the frontier reaches `score`.
    ///
    /// `reward * progress / span`, with the product formed in `u128`. Two `u64`
    /// factors always fit `u128`, so the multiply cannot lose information; the
    /// quotient is at most `reward` because `progress <= span`, so the narrowing
    /// back to `u64` cannot lose information either. Both steps are checked
    /// anyway -- this is the arithmetic that decides what somebody is paid, and
    /// a wrapped result here is an invented unit of account.
    ///
    /// Division truncates, matching Python's `//` on non-negative operands.
    /// Truncation is deliberate: it can only ever pay less than the exact real
    /// number, so the pool cannot be overspent by rounding.
    pub fn cumulative(&self, score: i64) -> Result<u64, RatchetError> {
        let span = self.span();
        if span == 0 {
            // Unreachable via `new`/`from_value`; see the type's docs.
            return Err(RatchetError::DegenerateSpan);
        }
        let product = u128::from(self.reward)
            .checked_mul(u128::from(self.progress(score)))
            .ok_or(RatchetError::Overflow {
                what: "reward * progress",
            })?;
        let paid = product / u128::from(span);
        u64::try_from(paid).map_err(|_| RatchetError::Overflow {
            what: "cumulative payout",
        })
    }

    /// What an improvement from `old` to `new` earns. Never negative.
    ///
    /// A regression pays zero rather than clawing anything back: the ledger is
    /// append-only and money already settled cannot be unsettled, so the only
    /// safe floor is zero. `saturating_sub` is the `max(0, ...)` of the
    /// reference implementation, expressed in a type where negative is
    /// unrepresentable.
    pub fn payout(&self, old: Option<i64>, new: i64) -> Result<u64, RatchetError> {
        let before = match old {
            None => 0,
            Some(old) => self.cumulative(old)?,
        };
        let after = self.cumulative(new)?;
        Ok(after.saturating_sub(before))
    }

    /// Has the pool been paid out in full?
    pub fn exhausted(&self, score: i64) -> bool {
        self.progress(score) >= self.span()
    }

    // -- serialization -----------------------------------------------------

    /// Canonical form. Every field is always present, defaults included: this
    /// block is part of the objective's content address, so a ratchet that
    /// omitted its defaults would give the same objective two different ids
    /// depending on how it was built.
    pub fn to_value(&self) -> Value {
        Value::object([
            ("baseline", Value::Int(i128::from(self.baseline))),
            ("target", Value::Int(i128::from(self.target))),
            ("reward", Value::Int(i128::from(self.reward))),
            ("direction", Value::string(self.direction.as_str())),
            (
                "min_improvement",
                Value::Int(i128::from(self.min_improvement)),
            ),
        ])
    }

    /// Decode a ratchet block. `direction` defaults to maximize and
    /// `min_improvement` to 1, matching the reference implementation's
    /// `data.get(key, default)`; `baseline`, `target` and `reward` are
    /// required.
    ///
    /// A key present but explicitly `null` is an error rather than a fallback to
    /// the default. That is the reference behaviour -- `data.get("direction",
    /// MAXIMIZE)` returns `None` for a present null, which then fails its
    /// membership check -- and it is the right one: a null in a money parameter
    /// is a bug upstream, not a request for the default.
    pub fn from_value(value: &Value) -> Result<Ratchet, RatchetError> {
        const RECORD: &str = "ratchet";
        if value.as_object().is_none() {
            return Err(RatchetError::NotAnObject { record: RECORD });
        }

        let baseline = required_i64(value, RECORD, "baseline")?;
        let target = required_i64(value, RECORD, "target")?;

        let raw_reward = required_int(value, RECORD, "reward")?;
        let reward = u64::try_from(raw_reward)
            .map_err(|_| RatchetError::RewardOutOfRange { reward: raw_reward })?;

        let direction = match value.get("direction") {
            None => Direction::Maximize,
            Some(Value::String(s)) => Direction::from_str(s)?,
            Some(_) => {
                return Err(RatchetError::InvalidField {
                    record: RECORD,
                    field: "direction",
                    expected: "a string",
                })
            }
        };

        let min_improvement = match value.get("min_improvement") {
            None => 1,
            Some(other) => {
                let raw = other.as_i128().ok_or(RatchetError::InvalidField {
                    record: RECORD,
                    field: "min_improvement",
                    expected: "an integer",
                })?;
                if raw < 1 {
                    return Err(RatchetError::MinImprovementTooSmall);
                }
                u64::try_from(raw).map_err(|_| RatchetError::OutOfRange {
                    field: "min_improvement",
                    value: raw,
                })?
            }
        };

        Ratchet::new(baseline, target, reward, direction, min_improvement)
    }
}

// -- frontier entry --------------------------------------------------------

/// Who currently holds an objective's best-known score.
///
/// Appended to the log on every advance, never edited: the sequence of entries
/// for one objective *is* the improvement history, and an auditor replays it to
/// confirm that the frontier only ever moved forward and that the settlements
/// alongside it sum to no more than the pool.
///
/// `paid_cumulative` is carried explicitly rather than recomputed so that an
/// auditor can compare the operator's arithmetic against its own instead of
/// inheriting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierEntry {
    pub objective_id: String,
    /// The claim that moved the frontier here. The next improver must cite it;
    /// that is what makes attribution mechanical rather than a judgement call.
    pub claim_id: String,
    /// Submitter of `claim_id`.
    pub holder: String,
    pub score: i64,
    /// Everything the objective has paid on this curve so far, this entry's own
    /// payout included. Bounded above by the ratchet's `reward`.
    pub paid_cumulative: u64,
}

impl FrontierEntry {
    pub fn new(
        objective_id: impl Into<String>,
        claim_id: impl Into<String>,
        holder: impl Into<String>,
        score: i64,
        paid_cumulative: u64,
    ) -> FrontierEntry {
        FrontierEntry {
            objective_id: objective_id.into(),
            claim_id: claim_id.into(),
            holder: holder.into(),
            score,
            paid_cumulative,
        }
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("objective_id", Value::string(self.objective_id.clone())),
            ("claim_id", Value::string(self.claim_id.clone())),
            ("holder", Value::string(self.holder.clone())),
            ("score", Value::Int(i128::from(self.score))),
            (
                "paid_cumulative",
                Value::Int(i128::from(self.paid_cumulative)),
            ),
        ])
    }

    /// Decode a `frontier` log payload. Every field is required, mirroring the
    /// reference implementation's `FrontierEntry(**payload)`, which raises on a
    /// missing or extra key. Unknown keys are ignored here rather than refused:
    /// a reader must be able to replay a log written by a later version, and
    /// the fields it does understand are the ones it audits.
    pub fn from_value(value: &Value) -> Result<FrontierEntry, RatchetError> {
        const RECORD: &str = "frontier";
        if value.as_object().is_none() {
            return Err(RatchetError::NotAnObject { record: RECORD });
        }
        Ok(FrontierEntry {
            objective_id: required_string(value, RECORD, "objective_id")?,
            claim_id: required_string(value, RECORD, "claim_id")?,
            holder: required_string(value, RECORD, "holder")?,
            score: required_i64(value, RECORD, "score")?,
            paid_cumulative: required_u64(value, RECORD, "paid_cumulative")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maximize(baseline: i64, target: i64, reward: u64) -> Ratchet {
        Ratchet::new(baseline, target, reward, Direction::Maximize, 1).expect("valid ratchet")
    }

    // -- the arithmetic -----------------------------------------------------

    #[test]
    fn payouts_telescope_to_the_pool() {
        let r = maximize(0, 100, 1_000_000);
        let mut total: u64 = 0;
        let mut previous = None;
        for score in [5, 17, 40, 41, 88, 100] {
            total += r.payout(previous, score).expect("payout");
            previous = Some(score);
        }
        assert_eq!(total, 1_000_000);
    }

    #[test]
    fn pool_is_never_overspent_however_the_curve_is_chopped() {
        // Someone submitting 100 one-point improvements must not extract more
        // than someone submitting a single 100-point improvement.
        let one_at_a_time: Vec<i64> = (1..=100).collect();
        for reward in [1u64, 7, 999, 1_000_000, 1_000_000_007] {
            for steps in [vec![50, 100], vec![1, 2, 3, 99, 100], one_at_a_time.clone()] {
                let r = maximize(0, 100, reward);
                let mut total: u64 = 0;
                let mut previous = None;
                for score in steps {
                    total += r.payout(previous, score).expect("payout");
                    previous = Some(score);
                }
                assert_eq!(total, reward, "reward {reward}");
            }
        }
    }

    #[test]
    fn overshooting_the_target_pays_no_more() {
        let r = maximize(0, 10, 1000);
        assert_eq!(r.payout(None, 10), Ok(1000));
        assert_eq!(r.payout(None, 10_000), Ok(1000));
        assert_eq!(r.payout(Some(10), 10_000), Ok(0));
    }

    #[test]
    fn no_payout_below_baseline() {
        let r = maximize(50, 100, 1000);
        assert_eq!(r.payout(None, 10), Ok(0));
        assert_eq!(r.payout(None, 50), Ok(0));
        assert_eq!(r.payout(None, 75), Ok(500));
    }

    #[test]
    fn regression_pays_nothing() {
        let r = maximize(0, 100, 1000);
        assert_eq!(r.payout(Some(80), 20), Ok(0));
        assert!(!r.improves(Some(80), 20));
    }

    #[test]
    fn minimize_direction() {
        let r = Ratchet::new(100, 0, 1000, Direction::Minimize, 1).expect("valid");
        assert_eq!(r.payout(None, 50), Ok(500));
        assert_eq!(r.payout(Some(50), 25), Ok(250));
        assert!(!r.improves(Some(50), 75));
    }

    #[test]
    fn min_improvement_blocks_epsilon_farming() {
        let r = Ratchet::new(0, 1000, 1000, Direction::Maximize, 10).expect("valid");
        assert!(!r.improves(Some(100), 105));
        assert!(r.improves(Some(100), 110));
        // Also on the empty frontier: the first entry must clear the bar too,
        // or epsilon-farming just starts one submission earlier.
        assert!(!r.improves(None, 5));
        assert!(r.improves(None, 10));
    }

    #[test]
    fn negative_scores_are_ordinary() {
        let r = maximize(-100, 100, 1000);
        assert_eq!(r.span(), 200);
        assert_eq!(r.progress(-100), 0);
        assert_eq!(r.progress(-50), 50);
        assert_eq!(r.progress(0), 100);
        assert_eq!(r.cumulative(0), Ok(500));
        assert_eq!(r.payout(Some(-50), 0), Ok(250));
    }

    // -- overflow: the reason this module exists in Rust ---------------------

    #[test]
    fn span_does_not_overflow_when_endpoints_straddle_zero() {
        let r = maximize(i64::MIN, i64::MAX, 1);
        assert_eq!(r.span(), u64::MAX);
        let down = Ratchet::new(i64::MAX, i64::MIN, 1, Direction::Minimize, 1).expect("valid");
        assert_eq!(down.span(), u64::MAX);
        // Midpoint of the widest possible span.
        assert_eq!(r.progress(0), 1u64 << 63);
        assert_eq!(down.progress(0), (1u64 << 63) - 1);
    }

    #[test]
    fn a_huge_reward_times_a_huge_progress_does_not_wrap() {
        // reward * progress here is ~2^127: it wraps catastrophically in u64
        // and is exact in u128. The pool is paid out in full at target and not
        // one unit more.
        let r = maximize(i64::MIN, i64::MAX, u64::MAX);
        assert_eq!(r.span(), u64::MAX);
        assert_eq!(r.cumulative(i64::MAX), Ok(u64::MAX));
        // u64::MAX * 2^63 / u64::MAX == 2^63, exactly.
        assert_eq!(r.cumulative(0), Ok(1u64 << 63));
        assert_eq!(r.payout(Some(0), i64::MAX), Ok(u64::MAX - (1u64 << 63)));
        // Telescoping still holds at this scale.
        let first = r.payout(None, 0).expect("payout");
        let second = r.payout(Some(0), i64::MAX).expect("payout");
        assert_eq!(first.checked_add(second), Some(u64::MAX));
    }

    #[test]
    fn realistic_money_scale_stays_exact() {
        // ~1e18 units against a ~1e18 span: the product is ~1e36, far past u64.
        let reward: u64 = 1_000_000_000_000_000_000;
        let target: i64 = 1_000_000_000_000_000_000;
        let r = maximize(0, target, reward);
        assert_eq!(r.cumulative(target), Ok(reward));
        assert_eq!(r.cumulative(target / 2), Ok(reward / 2));
        assert_eq!(r.cumulative(1), Ok(1));
        assert_eq!(r.payout(Some(target / 2), target), Ok(reward / 2));
    }

    #[test]
    fn truncation_never_overspends_at_scale() {
        // An awkward span that divides nothing evenly, walked one unit at a
        // time: the sum of the floors must still not exceed the pool.
        let r = maximize(0, 97, u64::MAX);
        let mut total: u128 = 0;
        let mut previous = None;
        for score in 1..=97 {
            total += u128::from(r.payout(previous, score).expect("payout"));
            previous = Some(score);
        }
        assert_eq!(total, u128::from(u64::MAX));
    }

    #[test]
    fn a_degenerate_span_is_refused_rather_than_dividing_by_zero() {
        // Unreachable through `new`, reachable through a struct literal, which
        // is why the guard is there. It must not panic.
        let degenerate = Ratchet {
            baseline: 7,
            target: 7,
            reward: 1000,
            direction: Direction::Maximize,
            min_improvement: 1,
        };
        assert_eq!(degenerate.span(), 0);
        assert_eq!(degenerate.progress(9), 0);
        assert_eq!(degenerate.cumulative(9), Err(RatchetError::DegenerateSpan));
        assert_eq!(
            degenerate.payout(None, 9),
            Err(RatchetError::DegenerateSpan)
        );
        assert!(!degenerate.improves(None, 9));
        assert_eq!(
            degenerate.validate(),
            Err(RatchetError::TargetNotAboveBaseline {
                baseline: 7,
                target: 7
            })
        );
    }

    #[test]
    fn exhaustion_is_reported_at_and_past_the_target() {
        let r = maximize(0, 10, 1000);
        assert!(!r.exhausted(9));
        assert!(r.exhausted(10));
        assert!(r.exhausted(11));
        let down = Ratchet::new(10, 0, 1000, Direction::Minimize, 1).expect("valid");
        assert!(!down.exhausted(1));
        assert!(down.exhausted(0));
        assert!(down.exhausted(-7));
    }

    // -- validation ---------------------------------------------------------

    #[test]
    fn invalid_ratchets_are_refused() {
        assert_eq!(
            Ratchet::new(100, 10, 1, Direction::Maximize, 1),
            Err(RatchetError::TargetNotAboveBaseline {
                baseline: 100,
                target: 10
            })
        );
        assert_eq!(
            Ratchet::new(0, 10, 1, Direction::Minimize, 1),
            Err(RatchetError::TargetNotBelowBaseline {
                baseline: 0,
                target: 10
            })
        );
        assert_eq!(
            Ratchet::new(0, 10, 1, Direction::Maximize, 0),
            Err(RatchetError::MinImprovementTooSmall)
        );
        // "reward must be non-negative" is unrepresentable rather than checked:
        // there is no way to pass -1 as a u64.
    }

    #[test]
    fn a_negative_or_oversized_reward_is_refused_at_the_boundary() {
        let bad = crate::obj! {
            "baseline" => Value::Int(0),
            "target" => Value::Int(10),
            "reward" => Value::Int(-1),
        };
        assert_eq!(
            Ratchet::from_value(&bad),
            Err(RatchetError::RewardOutOfRange { reward: -1 })
        );
        let huge = crate::obj! {
            "baseline" => Value::Int(0),
            "target" => Value::Int(10),
            "reward" => Value::Int(i128::from(u64::MAX) + 1),
        };
        assert_eq!(
            Ratchet::from_value(&huge),
            Err(RatchetError::RewardOutOfRange {
                reward: i128::from(u64::MAX) + 1
            })
        );
    }

    #[test]
    fn a_score_endpoint_beyond_i64_is_refused_rather_than_truncated() {
        let bad = crate::obj! {
            "baseline" => Value::Int(0),
            "target" => Value::Int(i128::from(i64::MAX) + 1),
            "reward" => Value::Int(10),
        };
        assert_eq!(
            Ratchet::from_value(&bad),
            Err(RatchetError::OutOfRange {
                field: "target",
                value: i128::from(i64::MAX) + 1
            })
        );
    }

    // -- serialization ------------------------------------------------------

    #[test]
    fn round_trips_through_canonical_form() {
        let r = Ratchet::new(9, 20, 1_100_000, Direction::Maximize, 3).expect("valid");
        assert_eq!(Ratchet::from_value(&r.to_value()), Ok(r.clone()));
        assert_eq!(
            r.to_value().canonical_string(),
            "{\"baseline\":9,\"direction\":\"maximize\",\"min_improvement\":3,\
             \"reward\":1100000,\"target\":20}"
        );
    }

    #[test]
    fn defaults_match_the_reference_implementation() {
        let minimal = crate::obj! {
            "baseline" => Value::Int(0),
            "target" => Value::Int(100),
            "reward" => Value::Int(1_000_000),
        };
        let r = Ratchet::from_value(&minimal).expect("valid");
        assert_eq!(r.direction, Direction::Maximize);
        assert_eq!(r.min_improvement, 1);
    }

    #[test]
    fn missing_and_malformed_fields_are_reported() {
        let missing = crate::obj! {
            "baseline" => Value::Int(0),
            "reward" => Value::Int(10),
        };
        assert_eq!(
            Ratchet::from_value(&missing),
            Err(RatchetError::MissingField {
                record: "ratchet",
                field: "target"
            })
        );
        assert_eq!(
            Ratchet::from_value(&Value::Int(3)),
            Err(RatchetError::NotAnObject { record: "ratchet" })
        );
        let sideways = crate::obj! {
            "baseline" => Value::Int(0),
            "target" => Value::Int(10),
            "reward" => Value::Int(10),
            "direction" => Value::string("sideways"),
        };
        assert_eq!(
            Ratchet::from_value(&sideways),
            Err(RatchetError::UnknownDirection {
                direction: "sideways".to_string()
            })
        );
        // A bool is not an integer here, matching the reference implementation's
        // explicit isinstance(value, bool) rejection.
        let boolean = crate::obj! {
            "baseline" => Value::Int(0),
            "target" => Value::Int(10),
            "reward" => Value::Bool(true),
        };
        assert_eq!(
            Ratchet::from_value(&boolean),
            Err(RatchetError::InvalidField {
                record: "ratchet",
                field: "reward",
                expected: "an integer"
            })
        );
        // Present-but-null is an error, not a fallback to the default.
        let nulled = crate::obj! {
            "baseline" => Value::Int(0),
            "target" => Value::Int(10),
            "reward" => Value::Int(10),
            "direction" => Value::Null,
        };
        assert!(Ratchet::from_value(&nulled).is_err());
    }

    #[test]
    fn frontier_entries_round_trip() {
        let entry = FrontierEntry::new("sha256:obj", "sha256:claim", "alice", -12, 400_000);
        assert_eq!(FrontierEntry::from_value(&entry.to_value()), Ok(entry));
    }

    #[test]
    fn a_frontier_entry_needs_every_field() {
        let partial = crate::obj! {
            "objective_id" => Value::string("sha256:obj"),
            "claim_id" => Value::string("sha256:claim"),
            "holder" => Value::string("alice"),
            "score" => Value::Int(4),
        };
        assert_eq!(
            FrontierEntry::from_value(&partial),
            Err(RatchetError::MissingField {
                record: "frontier",
                field: "paid_cumulative"
            })
        );
        let negative_paid = crate::obj! {
            "objective_id" => Value::string("sha256:obj"),
            "claim_id" => Value::string("sha256:claim"),
            "holder" => Value::string("alice"),
            "score" => Value::Int(4),
            "paid_cumulative" => Value::Int(-1),
        };
        assert_eq!(
            FrontierEntry::from_value(&negative_paid),
            Err(RatchetError::OutOfRange {
                field: "paid_cumulative",
                value: -1
            })
        );
    }

    // -- conformance --------------------------------------------------------

    /// The `ratchet` block of `conformance/vectors.json`, transcribed. The
    /// integration test reads the file; this keeps the expected numbers visible
    /// next to the arithmetic they pin.
    #[test]
    fn matches_the_conformance_vectors() {
        struct Case {
            baseline: i64,
            target: i64,
            reward: u64,
            direction: Direction,
            /// (score, progress, cumulative)
            points: &'static [(i64, u64, u64)],
        }
        let cases = [
            Case {
                baseline: 0,
                target: 100,
                reward: 1_000_000,
                direction: Direction::Maximize,
                points: &[
                    (0, 0, 0),
                    (1, 1, 10_000),
                    (33, 33, 330_000),
                    (50, 50, 500_000),
                    (99, 99, 990_000),
                    (100, 100, 1_000_000),
                    (105, 100, 1_000_000),
                ],
            },
            Case {
                baseline: 9,
                target: 20,
                reward: 1_100_000,
                direction: Direction::Maximize,
                points: &[
                    (9, 0, 0),
                    (10, 1, 100_000),
                    (12, 3, 300_000),
                    (14, 5, 500_000),
                    (19, 10, 1_000_000),
                    (20, 11, 1_100_000),
                    (25, 11, 1_100_000),
                ],
            },
            Case {
                baseline: 100,
                target: 0,
                reward: 1000,
                direction: Direction::Minimize,
                points: &[
                    (100, 0, 0),
                    (99, 1, 10),
                    (67, 33, 330),
                    (50, 50, 500),
                    (1, 99, 990),
                    (0, 100, 1000),
                    (-5, 100, 1000),
                ],
            },
            Case {
                baseline: 0,
                target: 7,
                reward: 10,
                direction: Direction::Maximize,
                // Truncation is visible here: 3/7 of 10 pays 4, not 4.28...
                points: &[
                    (0, 0, 0),
                    (1, 1, 1),
                    (2, 2, 2),
                    (3, 3, 4),
                    (6, 6, 8),
                    (7, 7, 10),
                    (12, 7, 10),
                ],
            },
            Case {
                baseline: 0,
                target: 3,
                reward: 1_000_000_000_000_000_000,
                direction: Direction::Maximize,
                points: &[
                    (0, 0, 0),
                    (1, 1, 333_333_333_333_333_333),
                    (2, 2, 666_666_666_666_666_666),
                    (3, 3, 1_000_000_000_000_000_000),
                    (8, 3, 1_000_000_000_000_000_000),
                ],
            },
        ];

        for case in cases {
            let r = Ratchet::new(case.baseline, case.target, case.reward, case.direction, 1)
                .expect("valid ratchet");
            for &(score, progress, cumulative) in case.points {
                assert_eq!(r.progress(score), progress, "progress at {score}");
                assert_eq!(r.cumulative(score), Ok(cumulative), "cumulative at {score}");
            }
        }
    }

    #[test]
    fn errors_display_usefully() {
        assert_eq!(
            RatchetError::MinImprovementTooSmall.to_string(),
            "min_improvement must be at least 1"
        );
        assert!(RatchetError::UnknownDirection {
            direction: "sideways".to_string()
        }
        .to_string()
        .contains("maximize"));
        assert!(RatchetError::Overflow {
            what: "reward * progress"
        }
        .to_string()
        .contains("money"));
    }

    #[test]
    fn direction_parses_and_prints() {
        assert_eq!(Direction::from_str(MAXIMIZE), Ok(Direction::Maximize));
        assert_eq!(Direction::from_str(MINIMIZE), Ok(Direction::Minimize));
        assert!(Direction::from_str("Maximize").is_err());
        assert_eq!(Direction::Minimize.to_string(), "minimize");
        assert_eq!(Direction::default(), Direction::Maximize);
    }
}
