//! Where a population *lands*, as opposed to where it could rest.
//!
//! Equilibrium analysis answers a static question: is there a profile nobody
//! wants to leave. It does not say which of several such profiles a real network
//! ends up in, and when a mechanism has both an honest equilibrium and a lazy
//! one -- which is the normal case for the verifier's dilemma -- that is the
//! only question anyone cares about.
//!
//! So: sequential better-reply dynamics. One operator at a time notices it is
//! doing worse than it could, switches to a best response, and the next one
//! looks. No mixing, no differential equations, no floating point -- the state is
//! a vector of integer counts and every comparison is exact, so a trajectory is
//! reproducible rather than merely plausible.
//!
//! The number this produces is [`tipping_point`]: how many operators have to
//! start out lazy before the network stops recovering. A mechanism whose honest
//! profile is a strict Nash equilibrium can still have a tipping point of three,
//! and three operators is a group chat.
//!
//! # What one-at-a-time buys, and what it costs
//!
//! Moving a single player per step makes the process deterministic and makes
//! every rest point a genuine Nash equilibrium -- if nobody moves, nobody had a
//! profitable deviation. It cannot model simultaneous revision, where everyone
//! best-responds to the same stale state and overshoots together; that produces
//! cycles this will not find. Cycles it *can* find are detected and reported
//! rather than silently truncated.

use std::collections::BTreeSet;

use super::exact::Rat;
use super::game::{everyone, symmetric_best_responses, Counts, GameError, Symmetric};

/// How a trajectory ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    /// Nobody wants to move. A rest point of better-reply dynamics is a Nash
    /// equilibrium by construction.
    Rest,
    /// The trajectory revisited a state it had already been in.
    Cycle,
    /// The step budget ran out with the population still moving.
    Exhausted,
}

/// A run of the dynamics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trajectory {
    /// Every state visited, starting with the initial one.
    pub path: Vec<Counts>,
    pub ending: Ending,
}

impl Trajectory {
    /// The state the population ended in.
    pub fn final_state(&self) -> &[u32] {
        // `path` always holds the starting state, so this cannot be empty.
        self.path.last().map(Vec::as_slice).unwrap_or(&[])
    }

    /// True if the population ended with everyone playing `action`.
    pub fn converged_to(&self, action: usize) -> bool {
        let state = self.final_state();
        state
            .iter()
            .enumerate()
            .all(|(index, count)| (index == action) == (*count > 0))
    }
}

/// Run better-reply dynamics from `start` until it rests, cycles, or runs out.
///
/// Each step moves exactly one operator from whichever currently-played action
/// is doing worst to that operator's best response. Ties break to the lowest
/// action index so the run is a function of the input; the tie-break matters
/// only in states where somebody is indifferent, which are precisely the states
/// a weak equilibrium is made of.
pub fn settle<S: Symmetric + ?Sized>(
    game: &S,
    start: &[u32],
    max_steps: usize,
) -> Result<Trajectory, GameError> {
    let mut state = start.to_vec();
    if state.len() != game.actions()
        || state.iter().copied().map(u64::from).sum::<u64>() != u64::from(game.population())
    {
        return Err(GameError::MalformedProfile);
    }
    let mut path = vec![state.clone()];
    let mut seen: BTreeSet<Counts> = BTreeSet::new();
    seen.insert(state.clone());
    for _ in 0..max_steps {
        let step = worst_off(game, &state)?;
        let (from, to) = match step {
            Some(pair) => pair,
            None => {
                return Ok(Trajectory {
                    path,
                    ending: Ending::Rest,
                })
            }
        };
        state[from] -= 1;
        state[to] += 1;
        path.push(state.clone());
        if !seen.insert(state.clone()) {
            return Ok(Trajectory {
                path,
                ending: Ending::Cycle,
            });
        }
    }
    Ok(Trajectory {
        path,
        ending: Ending::Exhausted,
    })
}

/// The largest available gain from moving one player, as `(from, to)`.
///
/// `None` when no player has a profitable switch -- the definition of a rest
/// point, and the reason a rest point is a Nash equilibrium.
fn worst_off<S: Symmetric + ?Sized>(
    game: &S,
    state: &[u32],
) -> Result<Option<(usize, usize)>, GameError> {
    let mut best: Option<(Rat, usize, usize)> = None;
    for from in 0..game.actions() {
        if state[from] == 0 {
            continue;
        }
        let mut others = state.to_vec();
        others[from] -= 1;
        let current = game.payoff(from, &others);
        for to in symmetric_best_responses(game, &others)? {
            if to == from {
                continue;
            }
            let gain = game.payoff(to, &others) - current;
            if gain.is_positive() && best.as_ref().is_none_or(|(found, _, _)| gain > *found) {
                best = Some((gain, from, to));
            }
        }
    }
    Ok(best.map(|(_, from, to)| (from, to)))
}

/// Did the population end somewhere payoff-identical to universal `resident`?
///
/// The obvious test -- "did everyone go back to playing `resident`" -- is wrong,
/// and wrong in a way that matters. In the custody game a member of a
/// sub-threshold cartel plays `open-early` and earns exactly what an honest
/// member earns, because its cartel never reaches the threshold and nothing
/// happens. A profile-identity test calls that a collapse. It is not: nobody is
/// better off, nobody is worse off, and no submission was front-run.
///
/// So the test is on payoffs. A shock is absorbed when every action still being
/// played pays exactly what the honest action paid before the shock -- which
/// covers both the case where the population literally returned and the case
/// where it drifted somewhere behaviourally indistinguishable. Anything else,
/// better or worse, counts as having moved.
fn absorbed<S: Symmetric + ?Sized>(
    game: &S,
    resident: usize,
    state: &[u32],
) -> Result<bool, GameError> {
    let honest = everyone(game, resident);
    let baseline_others = match others_of(&honest, resident) {
        Some(others) => others,
        None => return Err(GameError::MalformedProfile),
    };
    let baseline = game.payoff(resident, &baseline_others);
    for action in 0..game.actions() {
        if state[action] == 0 {
            continue;
        }
        let others = match others_of(state, action) {
            Some(others) => others,
            None => return Err(GameError::MalformedProfile),
        };
        if game.payoff(action, &others) != baseline {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `state` with one player removed from `action`.
fn others_of(state: &[u32], action: usize) -> Option<Counts> {
    let mut others = state.to_vec();
    let slot = others.get_mut(action)?;
    *slot = slot.checked_sub(1)?;
    Some(others)
}

/// The smallest number of defectors from which the network does not recover.
///
/// Start the population at `mutants` operators playing `mutant` and the rest
/// playing `resident`, then let it run. If it settles somewhere payoff-identical
/// to universal honesty ([`absorbed`]), the network self-healed from a shock of
/// that size. The first size it does not heal from is the tipping point -- and
/// it is the honest summary of how much slack a mechanism has, in a way "the
/// honest profile is a strict Nash equilibrium" is not.
///
/// `None` means the network recovered from every shock up to the whole
/// population, which is the answer a designer wants.
pub fn tipping_point<S: Symmetric + ?Sized>(
    game: &S,
    resident: usize,
    mutant: usize,
    max_steps: usize,
) -> Result<Option<u32>, GameError> {
    if resident >= game.actions() || mutant >= game.actions() || resident == mutant {
        return Err(GameError::MalformedProfile);
    }
    let population = game.population();
    for mutants in 1..=population {
        let mut start = vec![0u32; game.actions()];
        start[resident] = population - mutants;
        start[mutant] = mutants;
        let run = settle(game, &start, max_steps)?;
        if !absorbed(game, resident, run.final_state())? {
            return Ok(Some(mutants));
        }
    }
    Ok(None)
}

/// Where the population goes when it starts out entirely honest and one
/// operator is nudged.
///
/// A convenience for the common report line: the trajectory from a single
/// defector, which is the smallest shock a live network is guaranteed to receive.
pub fn from_one_defector<S: Symmetric + ?Sized>(
    game: &S,
    resident: usize,
    mutant: usize,
    max_steps: usize,
) -> Result<Trajectory, GameError> {
    let mut start = everyone(game, resident);
    if resident >= game.actions() || mutant >= game.actions() || start[resident] == 0 {
        return Err(GameError::MalformedProfile);
    }
    start[resident] -= 1;
    start[mutant] += 1;
    settle(game, &start, max_steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incentive::mechanism::{Attest, Verification};
    use crate::incentive::{NodeParams, Rat};

    /// Contributing costs `cost` and adds `value` to a pot split `n` ways.
    struct PublicGood {
        players: u32,
        cost: Rat,
        value: Rat,
    }

    impl Symmetric for PublicGood {
        fn actions(&self) -> usize {
            2
        }
        fn population(&self) -> u32 {
            self.players
        }
        fn payoff(&self, own: usize, others: &[u32]) -> Rat {
            let contributors = others[0] + if own == 0 { 1 } else { 0 };
            let share = (self.value * Rat::int(i64::from(contributors)))
                .share(self.players)
                .unwrap_or(Rat::ZERO);
            if own == 0 {
                share - self.cost
            } else {
                share
            }
        }
    }

    #[test]
    fn a_public_good_unravels_all_the_way_to_nobody() {
        let game = PublicGood {
            players: 8,
            cost: Rat::int(3),
            value: Rat::int(8),
        };
        let run = settle(&game, &everyone(&game, 0), 100).expect("valid start");
        assert_eq!(run.ending, Ending::Rest);
        assert!(run.converged_to(1), "everyone stops contributing");
        assert_eq!(run.path.len(), 9, "one defection per step, eight of them");
        // And it unravels from a single defector, which is the whole tragedy:
        // the tipping point is one.
        assert_eq!(
            tipping_point(&game, 0, 1, 100).expect("valid actions"),
            Some(1)
        );
    }

    #[test]
    fn a_rest_point_is_reached_when_nobody_can_gain() {
        let game = PublicGood {
            players: 6,
            cost: Rat::int(1),
            value: Rat::int(12),
        };
        let run = settle(&game, &everyone(&game, 1), 100).expect("valid start");
        assert_eq!(run.ending, Ending::Rest);
        assert!(run.converged_to(0), "contributing is worth it here");
        assert_eq!(
            tipping_point(&game, 0, 1, 100).expect("valid actions"),
            None,
            "the population recovers from any number of defectors"
        );
    }

    #[test]
    fn the_reference_network_recovers_from_every_shock() {
        let params = NodeParams::reference();
        let game = Verification::new(&params).expect("validated");
        let run = from_one_defector(&game, Attest::Verify.index(), Attest::Stamp.index(), 10_000)
            .expect("valid actions");
        assert_eq!(run.ending, Ending::Rest);
        assert!(run.converged_to(Attest::Verify.index()));
        assert_eq!(
            tipping_point(&game, Attest::Verify.index(), Attest::Stamp.index(), 10_000)
                .expect("valid actions"),
            None
        );
    }

    #[test]
    fn without_canaries_the_network_is_bistable_rather_than_merely_worse() {
        // Switch canaries off and the reference network does not collapse --
        // the bond is large enough that a lone defector still loses. What
        // changes is subtler and worse: a second equilibrium appears, and the
        // only way in is for essentially everyone to move at once.
        //
        // That is the shape of the danger. The network is not eroded one lazy
        // operator at a time; it is fine until it is not. A coordinated cartel,
        // a shared client default, or a single popular piece of software that
        // skips the check gets there in one step, and once there nobody
        // individually wants to leave.
        let params = NodeParams {
            canary_rate: Rat::ZERO,
            ..NodeParams::reference()
        };
        let game = Verification::new(&params).expect("validated");
        let verify = Attest::Verify.index();
        let stamp = Attest::Stamp.index();

        // Both profiles are equilibria: the trap exists.
        for profile in [everyone(&game, verify), everyone(&game, stamp)] {
            assert!(crate::incentive::game::symmetric_stability(&game, &profile)
                .expect("valid counts")
                .is_some());
        }
        // But erosion does not reach it -- only a total defection does.
        assert_eq!(
            tipping_point(&game, verify, stamp, 10_000).expect("valid actions"),
            Some(params.nodes)
        );
        let run = from_one_defector(&game, verify, stamp, 10_000).expect("valid actions");
        assert!(run.converged_to(verify), "one defector is reabsorbed");
    }

    #[test]
    fn a_thin_bond_turns_the_trap_into_a_slope() {
        // The same network with a bond small enough that the conditional slash
        // no longer covers the cost of checking: now a single defector is
        // enough, because each defection makes the next one more attractive.
        // Bistable and unrecoverable are different failures and want different
        // fixes -- canaries for the first, a bigger bond for the second.
        let params = NodeParams {
            canary_rate: Rat::ZERO,
            stake: 1_000,
            ..NodeParams::reference()
        };
        let game = Verification::new(&params).expect("validated");
        assert_eq!(
            tipping_point(&game, Attest::Verify.index(), Attest::Stamp.index(), 10_000)
                .expect("valid actions"),
            Some(1)
        );
        let run = from_one_defector(&game, Attest::Verify.index(), Attest::Stamp.index(), 10_000)
            .expect("valid actions");
        assert!(run.converged_to(Attest::Stamp.index()));
    }

    #[test]
    fn a_malformed_start_is_refused() {
        let game = PublicGood {
            players: 4,
            cost: Rat::int(1),
            value: Rat::int(8),
        };
        assert_eq!(
            settle(&game, &[1, 1], 10).expect_err("counts must sum to n"),
            GameError::MalformedProfile
        );
        assert_eq!(
            tipping_point(&game, 0, 0, 10).expect_err("resident cannot be the mutant"),
            GameError::MalformedProfile
        );
    }

    #[test]
    fn a_step_budget_of_zero_reports_exhaustion_rather_than_rest() {
        let game = PublicGood {
            players: 8,
            cost: Rat::int(3),
            value: Rat::int(8),
        };
        let run = settle(&game, &everyone(&game, 0), 0).expect("valid start");
        assert_eq!(run.ending, Ending::Exhausted);
        assert_eq!(run.path.len(), 1);
    }
}
