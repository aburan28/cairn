//! How far the world can differ from the model before the answer changes.
//!
//! [`super::design::Report`] answers a question about one parameter set: at
//! *these* costs and *this* fraud rate, is honesty an equilibrium. That is the
//! right question and it is not the one a designer actually has, because
//!
//! > **nobody knows the parameters.** Verification cost is a guess, the fraud
//! > rate is a fact about people who have not shown up yet, and canary leak is
//! > an engineering property of a pipeline that does not exist.
//!
//! A verdict at a point is worth very little on its own. `passes` at the
//! reference parameters could mean the mechanism is sound, or it could mean the
//! reference parameters were chosen -- consciously or not -- to be a point where
//! it passes. The two are indistinguishable from the verdict.
//!
//! What distinguishes them is the **size of the region**. If honesty survives a
//! fourfold error in verification cost, the guess not being exactly right stops
//! mattering. If it breaks at a 4% error, the mechanism is a bet on a
//! measurement nobody has taken, and saying so is more useful than a green tick.
//!
//! So this module answers the question one level up: for each parameter, how far
//! can it move before [`super::design::Report::passes`] stops holding, and which
//! parameter is closest to breaking. That last line is the output that changes
//! what somebody does next, because it names the number worth measuring first.
//!
//! # Both directions, because one of them is a surprise
//!
//! Every parameter is searched upward *and* downward rather than in the
//! direction a designer expects to be dangerous. That is not thoroughness for
//! its own sake. [`super::NodeParams::fraud_rate`] can break the mechanism by
//! getting **smaller**: where the canary is weak, the only reason to check is
//! the chance of catching real fraud, so the more honest the network the weaker
//! the incentive to verify it. A search that only looked upward would call that
//! parameter safe.
//!
//! # A ladder of ratios, not a bisection
//!
//! The obvious implementation is to bisect for the exact boundary. Two things
//! are wrong with it. It is only correct if the predicate is monotone in that
//! parameter, which is guaranteed for none of these -- `fraud_rate` appears in
//! the verify payoff, the stamp payoff and the sample composition, and there is
//! no argument its net effect is one-signed everywhere. And an exact boundary
//! claims a precision the inputs do not have: reporting that verification cost
//! breaks at 487 implies somebody could tell 486 from 487, when the number
//! itself is a guess.
//!
//! So each parameter is scanned **outward from its current value on a geometric
//! ladder**, and the first rung that fails is the margin. This finds the nearest
//! break by construction rather than by assumption, needs no monotonicity, and
//! reports at the precision the question deserves: *survives doubling, does not
//! survive tripling.*
//!
//! # Cost
//!
//! Every rung is a full [`Report`], which is cubic in the node count -- about a
//! second at a hundred nodes. A full margin table is therefore minutes of work
//! and is opt-in rather than part of the default report. That is the honest
//! trade: the predicate is the real solver running against the real payoff
//! functions, and a cheaper re-derived approximation of it could drift from the
//! mechanism in exactly the way this module exists to detect.

use std::fmt;

use super::design::{DesignError, Report};
use super::exact::Rat;
use super::{NodeParams, MAX_RATE_DEN};

/// Grid the rate parameters are expressed on.
///
/// [`MAX_RATE_DEN`], because a rate with a finer denominator is refused by
/// [`NodeParams::validate`](super::NodeParams::validate) -- so a margin
/// expressed more finely would name a parameter set that cannot exist.
const GRID: i128 = MAX_RATE_DEN;

/// The ladder, as `(numerator, denominator)` multipliers of the current value.
///
/// Geometric and deliberately coarse at the top: the difference between "breaks
/// at 200x" and "breaks at 1000x" is not a difference anybody acts on, while the
/// difference between 1.25x and 2x decides whether a parameter needs measuring.
/// Resolution where it matters, and none where it does not.
const LADDER: [(i128, i128); 12] = [
    (5, 4),
    (3, 2),
    (2, 1),
    (3, 1),
    (5, 1),
    (8, 1),
    (16, 1),
    (32, 1),
    (64, 1),
    (200, 1),
    (1_000, 1),
    (10_000, 1),
];

/// Which way a parameter moves to break the mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toward {
    /// The parameter has to get larger.
    Up,
    /// The parameter has to get smaller. The interesting case.
    Down,
}

impl fmt::Display for Toward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Toward::Up => "raising",
            Toward::Down => "lowering",
        })
    }
}

/// What a parameter is measured in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    /// Ledger units.
    Money,
    /// A rate in `[0, 1]`, held as a numerator on `GRID`.
    Rate,
}

/// One parameter, and how to move it.
///
/// Function pointers rather than a macro: the table is the readable artifact,
/// and a macro would hide the one thing a reader wants to check -- that the
/// getter and the setter name the same field.
struct Knob {
    name: &'static str,
    unit: Unit,
    get: fn(&NodeParams) -> u64,
    set: fn(&mut NodeParams, u64),
}

impl Knob {
    fn ceiling(&self) -> u64 {
        match self.unit {
            Unit::Money => super::MAX_UNITS,
            Unit::Rate => GRID as u64,
        }
    }
}

/// Every parameter this module perturbs.
///
/// Not every field of [`NodeParams`]. The committee shape (`committee`,
/// `threshold`, `nodes`) is structural -- moving it changes which game is being
/// played rather than how expensive it is -- so it belongs to
/// [`super::design::committee_window`], which sweeps it exhaustively and reports
/// the whole safe set instead of a distance to the nearest edge.
fn knobs() -> Vec<Knob> {
    vec![
        Knob {
            name: "verify_cost",
            unit: Unit::Money,
            get: |p| p.verify_cost,
            set: |p, v| p.verify_cost = v,
        },
        Knob {
            name: "storage_cost",
            unit: Unit::Money,
            get: |p| p.storage_cost,
            set: |p, v| p.storage_cost = v,
        },
        Knob {
            name: "operating_cost",
            unit: Unit::Money,
            get: |p| p.operating_cost,
            set: |p, v| p.operating_cost = v,
        },
        Knob {
            name: "publish_cost",
            unit: Unit::Money,
            get: |p| p.publish_cost,
            set: |p, v| p.publish_cost = v,
        },
        Knob {
            name: "stake",
            unit: Unit::Money,
            get: |p| p.stake,
            set: |p, v| p.stake = v,
        },
        Knob {
            name: "catch_bounty",
            unit: Unit::Money,
            get: |p| p.catch_bounty,
            set: |p, v| p.catch_bounty = v,
        },
        Knob {
            name: "sealed_value",
            unit: Unit::Money,
            get: |p| p.sealed_value,
            set: |p, v| p.sealed_value = v,
        },
        Knob {
            name: "settled_value",
            unit: Unit::Money,
            get: |p| p.settled_value,
            set: |p, v| p.settled_value = v,
        },
        Knob {
            name: "canary_rate",
            unit: Unit::Rate,
            get: |p| numerator(p.canary_rate),
            set: |p, v| p.canary_rate = from_numerator(v),
        },
        Knob {
            name: "canary_leak",
            unit: Unit::Rate,
            get: |p| numerator(p.canary_leak),
            set: |p, v| p.canary_leak = from_numerator(v),
        },
        Knob {
            name: "canary_valid_share",
            unit: Unit::Rate,
            get: |p| numerator(p.canary_valid_share),
            set: |p, v| p.canary_valid_share = from_numerator(v),
        },
        Knob {
            name: "fraud_rate",
            unit: Unit::Rate,
            get: |p| numerator(p.fraud_rate),
            set: |p, v| p.fraud_rate = from_numerator(v),
        },
        Knob {
            name: "slash_rate",
            unit: Unit::Rate,
            get: |p| numerator(p.slash_rate),
            set: |p, v| p.slash_rate = from_numerator(v),
        },
        Knob {
            name: "audit_rate",
            unit: Unit::Rate,
            get: |p| numerator(p.audit_rate),
            set: |p, v| p.audit_rate = from_numerator(v),
        },
        Knob {
            name: "detection_rate",
            unit: Unit::Rate,
            get: |p| numerator(p.detection_rate),
            set: |p, v| p.detection_rate = from_numerator(v),
        },
        Knob {
            name: "capital_rate",
            unit: Unit::Rate,
            get: |p| numerator(p.capital_rate),
            set: |p, v| p.capital_rate = from_numerator(v),
        },
        Knob {
            name: "fee",
            unit: Unit::Rate,
            get: |p| numerator(p.fee),
            set: |p, v| p.fee = from_numerator(v),
        },
    ]
}

/// How far one parameter can move before the mechanism stops working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Margin {
    pub parameter: &'static str,
    /// The value in the parameter set being analysed. Ledger units for money,
    /// a numerator on `GRID` for rates.
    pub current: u64,
    /// The first rung of the ladder at which [`Report::passes`] is false.
    ///
    /// `None` means no rung broke it -- the parameter can move by four orders of
    /// magnitude either way and the mechanism still holds. That is a real answer,
    /// and usually means this parameter is not what the mechanism rests on.
    pub breaks_at: Option<u64>,
    /// Which way it had to move.
    pub toward: Toward,
    /// The ladder rung that broke it, as a multiplier of `current`.
    ///
    /// Always at least one. This is the number to read: `2` means the mechanism
    /// tolerates a doubling of this parameter and not a tripling.
    pub factor: Option<Rat>,
    /// True when the current point already fails, so there is no margin to
    /// report and the mechanism is broken *here* rather than nearby.
    pub already_broken: bool,
}

impl Margin {
    /// True if no rung of the ladder broke this parameter.
    pub fn unbreakable(&self) -> bool {
        self.breaks_at.is_none() && !self.already_broken
    }
}

impl fmt::Display for Margin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.already_broken {
            return write!(
                f,
                "{}: already failing at the current value",
                self.parameter
            );
        }
        match (self.breaks_at, self.factor) {
            (Some(at), Some(factor)) => write!(
                f,
                "{}: {} survives {}x, breaks {} to {}",
                self.parameter,
                self.current,
                factor.to_decimal(2),
                self.toward,
                at
            ),
            _ => write!(
                f,
                "{}: {} survives every rung of the ladder",
                self.parameter, self.current
            ),
        }
    }
}

/// Margins for every parameter, tightest first.
///
/// The order is the point. A table sorted by parameter name is a table; a table
/// sorted by margin is a **priority list**, and its first row is the number
/// worth measuring before anything else is built.
pub fn margins(params: &NodeParams) -> Result<Vec<Margin>, DesignError> {
    params.validate()?;
    let broken_here = !passes(params)?;
    let mut found = Vec::new();
    for knob in knobs() {
        found.push(margin_of(params, &knob, broken_here)?);
    }
    // Tightest first; unbreakable last; ties keep table order so the output is
    // deterministic.
    found.sort_by(|a, b| match (a.factor, b.factor) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    Ok(found)
}

/// The parameter closest to breaking.
///
/// The single most useful line the harness can print, because it turns "the
/// mechanism works" into "the mechanism works, and here is the measurement it is
/// betting on".
pub fn binding(params: &NodeParams) -> Result<Option<Margin>, DesignError> {
    Ok(margins(params)?.into_iter().find(|m| m.factor.is_some()))
}

fn passes(params: &NodeParams) -> Result<bool, DesignError> {
    match Report::of(params) {
        Ok(report) => Ok(report.passes()),
        // A profile space past the enumeration budget is a limit of the tool,
        // not a verdict about the mechanism, and must not be read as a failure.
        Err(DesignError::Game(_)) => Ok(true),
        Err(other) => Err(other),
    }
}

/// Does this parameter set pass with one knob moved?
///
/// An invalid parameter set is not a mechanism failure -- it is not a network at
/// all -- so it counts as safe and the ladder walks past it. Conflating the two
/// would report `canary_rate` as the most fragile knob in the model, because
/// pushing it far enough makes canaries plus fraud exceed the whole sample.
fn passes_at(params: &NodeParams, knob: &Knob, value: u64) -> Result<bool, DesignError> {
    let mut probe = params.clone();
    (knob.set)(&mut probe, value);
    if probe.validate().is_err() {
        return Ok(true);
    }
    passes(&probe)
}

fn margin_of(params: &NodeParams, knob: &Knob, broken_here: bool) -> Result<Margin, DesignError> {
    let current = (knob.get)(params);
    if broken_here {
        return Ok(Margin {
            parameter: knob.name,
            current,
            breaks_at: None,
            toward: Toward::Up,
            factor: None,
            already_broken: true,
        });
    }

    // Walk outward. The first rung that fails in either direction is the margin,
    // and checking both at each rung is what makes "nearest" mean nearest rather
    // than "nearest in the direction I guessed".
    for (num, den) in LADDER {
        let up = scale(current, num, den).min(knob.ceiling());
        if up != current && !passes_at(params, knob, up)? {
            return Ok(Margin {
                parameter: knob.name,
                current,
                breaks_at: Some(up),
                toward: Toward::Up,
                factor: Rat::new(num, den),
                already_broken: false,
            });
        }
        let down = scale(current, den, num);
        if down != current && !passes_at(params, knob, down)? {
            return Ok(Margin {
                parameter: knob.name,
                current,
                breaks_at: Some(down),
                toward: Toward::Down,
                factor: Rat::new(num, den),
                already_broken: false,
            });
        }
    }
    Ok(Margin {
        parameter: knob.name,
        current,
        breaks_at: None,
        toward: Toward::Up,
        factor: None,
        already_broken: false,
    })
}

/// `value * num / den`, saturating, in `i128` so the product cannot wrap.
fn scale(value: u64, num: i128, den: i128) -> u64 {
    let scaled = i128::from(value).saturating_mul(num) / den.max(1);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

/// A rate as a numerator on `GRID`.
fn numerator(rate: Rat) -> u64 {
    let scaled = rate.numerator().saturating_mul(GRID) / rate.denominator().max(1);
    u64::try_from(scaled.clamp(0, GRID)).unwrap_or(0)
}

/// The inverse. Out-of-range values clamp rather than panic: the caller is a
/// ladder that walks past the end, and
/// [`NodeParams::validate`](super::NodeParams::validate) is what decides whether
/// the result is a network.
fn from_numerator(value: u64) -> Rat {
    let clamped = u32::try_from(value.min(GRID as u64)).unwrap_or(0);
    Rat::rate(clamped, GRID as u32).unwrap_or(Rat::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A network small enough to analyse repeatedly.
    ///
    /// `Report::of` is cubic in the node count -- about a second at a hundred
    /// nodes and ten milliseconds at twenty -- and a margin table is hundreds of
    /// reports. The properties under test are about the *search*, not about the
    /// reference network's exact numbers, and those come from the CLI.
    fn small() -> NodeParams {
        NodeParams {
            nodes: 20,
            committee: 15,
            threshold: 10,
            ..NodeParams::reference()
        }
    }

    #[test]
    fn a_passing_network_reports_a_binding_constraint_and_it_is_the_tightest() {
        let params = small();
        assert!(
            Report::of(&params).expect("reports").passes(),
            "the fixture must pass, or there is no margin to measure"
        );

        let binding = binding(&params).expect("solves").expect("something binds");
        let factor = binding.factor.expect("a binding constraint has a factor");
        for margin in margins(&params).expect("solves") {
            if let Some(theirs) = margin.factor {
                assert!(
                    factor <= theirs,
                    "{margin} is tighter than the reported binding constraint"
                );
            }
        }
    }

    #[test]
    fn a_reported_break_is_real_at_the_value_it_names() {
        // The whole claim, checked rather than inferred from the search: at the
        // reported value the mechanism fails, and at the current value it does
        // not. A margin that could not be reproduced this way would be an
        // artifact of the ladder.
        let params = small();
        let all = margins(&params).expect("solves");
        let mut checked = 0;
        for margin in &all {
            let Some(at) = margin.breaks_at else { continue };
            let knob = knobs()
                .into_iter()
                .find(|k| k.name == margin.parameter)
                .expect("in the table");
            let mut broken = params.clone();
            (knob.set)(&mut broken, at);
            assert!(
                broken.validate().is_ok(),
                "{} reported a break outside the valid range",
                margin.parameter
            );
            assert!(
                !Report::of(&broken).expect("reports").passes(),
                "{} does not actually break at {at}",
                margin.parameter
            );
            checked += 1;
        }
        assert!(checked > 0, "no margin was found to check");
    }

    #[test]
    fn margins_are_sorted_tightest_first_with_the_unbreakable_last() {
        let all = margins(&small()).expect("solves");
        assert!(!all.is_empty());
        let mut previous: Option<Rat> = None;
        let mut seen_unbreakable = false;
        for margin in &all {
            match margin.factor {
                Some(factor) => {
                    assert!(
                        !seen_unbreakable,
                        "a breakable parameter sorted after an unbreakable one"
                    );
                    if let Some(before) = previous {
                        assert!(before <= factor, "margins are not sorted");
                    }
                    previous = Some(factor);
                }
                None => seen_unbreakable = true,
            }
        }
    }

    #[test]
    fn both_directions_are_searched_so_a_downward_break_is_findable() {
        // `settled_value` is the fee pool's only source, and shrinking it stops
        // paying for the security it buys. A search that only looked upward
        // would call it safe -- and the same blind spot hides the perverse
        // comparative static on `fraud_rate`.
        let params = small();
        let all = margins(&params).expect("solves");
        assert!(
            all.iter()
                .any(|m| m.toward == Toward::Down && m.factor.is_some()),
            "no downward break found anywhere; the search is one-directional"
        );
    }

    #[test]
    fn an_invalid_parameter_set_is_out_of_range_rather_than_a_failure() {
        // Pushing `canary_rate` to the top of the grid makes canaries plus fraud
        // exceed the whole sample, which is not a network. Counting that as a
        // break would report the mechanism's most important knob as its most
        // fragile.
        let params = small();
        let knob = knobs()
            .into_iter()
            .find(|k| k.name == "canary_rate")
            .expect("in the table");
        let mut absurd = params.clone();
        (knob.set)(&mut absurd, GRID as u64);
        assert!(absurd.validate().is_err(), "not a network");
        assert!(
            passes_at(&params, &knob, GRID as u64).expect("total"),
            "out of range must not read as a break"
        );
    }

    #[test]
    fn a_network_that_already_fails_reports_that_rather_than_a_margin() {
        // Switch canaries off: the docs' example of the trap standing. There is
        // no margin to report, and inventing one would be worse than saying so.
        let params = NodeParams {
            canary_rate: Rat::ZERO,
            ..small()
        };
        assert!(!Report::of(&params).expect("reports").passes());
        let all = margins(&params).expect("solves");
        assert!(all.iter().all(|m| m.already_broken));
        assert!(all.iter().all(|m| !m.unbreakable()));
        assert!(binding(&params).expect("solves").is_none());
        assert!(all[0].to_string().contains("already failing"));
    }

    #[test]
    fn rates_round_trip_through_the_grid() {
        for rate in [
            Rat::ZERO,
            Rat::ONE,
            Rat::rate(1, 2).expect("valid"),
            Rat::rate(1, 100).expect("valid"),
            Rat::rate(1, 1_000).expect("valid"),
            Rat::rate(1, 10_000).expect("valid"),
            Rat::rate(19, 2_000).expect("valid"),
        ] {
            assert_eq!(
                from_numerator(numerator(rate)),
                rate,
                "{rate} did not survive the grid"
            );
        }
        // The ladder walks past the end, so clamping is the contract.
        assert_eq!(from_numerator(u64::MAX), Rat::ONE);
        assert_eq!(
            scale(u64::MAX, 10_000, 1),
            u64::MAX,
            "saturating, not wrapping"
        );
        assert_eq!(scale(0, 5, 4), 0);
    }

    #[test]
    fn the_ladder_is_geometric_and_starts_fine() {
        // Resolution where a decision changes, none where it does not: the gap
        // between 1.25x and 2x decides whether a parameter needs measuring, and
        // the gap between 200x and 1000x decides nothing.
        let mut previous = Rat::ONE;
        for (num, den) in LADDER {
            let step = Rat::new(num, den).expect("a valid ratio");
            assert!(step > previous, "the ladder must increase");
            previous = step;
        }
        assert_eq!(LADDER[0], (5, 4), "the first rung is a 25% error");
    }
}
