//! Progressive bounties: pay for distance moved, not for arriving first.
//!
//! A winner-take-all bounty gives everyone a reason to hoard, so nobody shares
//! and everyone rediscovers the same partial results. Paying for the distance
//! an improvement moves makes publishing immediately the profitable move, and
//! payouts telescope -- the pool is exactly exhausted at the target however
//! the curve is chopped.

use crate::canonical::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Maximize,
    Minimize,
}

impl Direction {
    pub fn parse(text: &str) -> Option<Direction> {
        match text {
            "maximize" => Some(Direction::Maximize),
            "minimize" => Some(Direction::Minimize),
            _ => None,
        }
    }

    /// A comparison, never a subtraction: `score - threshold` can overflow
    /// i64 when the two straddle zero at the extremes.
    pub fn clears(&self, score: i64, threshold: i64) -> bool {
        match self {
            Direction::Maximize => score >= threshold,
            Direction::Minimize => score <= threshold,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ratchet {
    pub baseline: i64,
    pub target: i64,
    pub reward: u64,
    pub direction: Direction,
    pub min_improvement: u64,
}

impl Ratchet {
    pub fn from_value(value: &Value) -> Result<Ratchet, String> {
        let int = |name: &str| -> Result<i64, String> {
            value
                .get(name)
                .and_then(Value::as_i64)
                .ok_or_else(|| format!("ratchet needs an integer {name:?}"))
        };
        let direction = match value.get("direction") {
            None => Direction::Maximize,
            Some(Value::String(text)) => Direction::parse(text)
                .ok_or_else(|| format!("unknown ratchet direction {text:?}"))?,
            Some(_) => return Err("ratchet direction must be a string".into()),
        };
        let reward = value
            .get("reward")
            .and_then(Value::as_u64)
            .ok_or("ratchet needs an integer reward")?;
        let ratchet = Ratchet {
            baseline: int("baseline")?,
            target: int("target")?,
            reward,
            direction,
            min_improvement: match value.get("min_improvement") {
                None => 1,
                Some(Value::Int(n)) if *n >= 1 => {
                    u64::try_from(*n).map_err(|_| "ratchet min_improvement does not fit in u64")?
                }
                Some(Value::Int(_)) => {
                    return Err("ratchet min_improvement must be at least 1".into())
                }
                Some(_) => return Err("ratchet min_improvement must be an integer".into()),
            },
        };
        if ratchet.span() == 0 {
            return Err("ratchet target must differ from baseline".into());
        }
        Ok(ratchet)
    }

    /// Distance from baseline to target. `u64` because i64::MIN..i64::MAX
    /// spans exactly u64::MAX -- the widest legal span is representable, and
    /// the subtraction is done in i128 so it cannot wrap on the way.
    pub fn span(&self) -> u64 {
        let raw = match self.direction {
            Direction::Maximize => i128::from(self.target) - i128::from(self.baseline),
            Direction::Minimize => i128::from(self.baseline) - i128::from(self.target),
        };
        u64::try_from(raw.max(0)).unwrap_or(0)
    }

    /// Distance from baseline toward target, clamped to `[0, span]`.
    pub fn progress(&self, score: i64) -> u64 {
        let raw = match self.direction {
            Direction::Maximize => i128::from(score) - i128::from(self.baseline),
            Direction::Minimize => i128::from(self.baseline) - i128::from(score),
        };
        let span = i128::from(self.span());
        u64::try_from(raw.clamp(0, span)).unwrap_or(0)
    }

    pub fn improves(&self, old: Option<i64>, new: i64) -> bool {
        // In i128 because the difference of two progresses is signed: a
        // regression must come out negative, not wrap to something huge.
        let gained = match old {
            None => i128::from(self.progress(new)),
            Some(old) => i128::from(self.progress(new)) - i128::from(self.progress(old)),
        };
        gained >= i128::from(self.min_improvement)
    }

    /// Total paid once the frontier reaches `score`. `u128` intermediate:
    /// `reward * progress` overflows u64 at realistic values.
    pub fn cumulative(&self, score: i64) -> u64 {
        let span = u128::from(self.span());
        if span == 0 {
            return 0;
        }
        let total = u128::from(self.reward) * u128::from(self.progress(score)) / span;
        u64::try_from(total).unwrap_or(u64::MAX)
    }

    /// What moving `old -> new` earns. Never negative: a regression pays zero
    /// rather than clawing back.
    pub fn payout(&self, old: Option<i64>, new: i64) -> u64 {
        let before = old.map_or(0, |old| self.cumulative(old));
        self.cumulative(new).saturating_sub(before)
    }

    pub fn exhausted(&self, score: i64) -> bool {
        self.progress(score) >= self.span()
    }
}
