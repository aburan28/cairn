//! The solvers: what it means to *evaluate* an incentive, mechanically.
//!
//! "Are node operators incentivised correctly" is not one question, and the
//! usual mistake is to answer the weakest version of it and stop. This module
//! implements the ladder, weakest first. Each rung is a strictly stronger
//! guarantee than the one below, and the mechanism in [`super::mechanism`] earns a
//! different rung in each of its sub-games -- which is the useful output.
//!
//! | rung | predicate | what it rules out |
//! |---|---|---|
//! | individual rationality | payoff >= outside option | operators not showing up at all |
//! | Nash | no *profitable* unilateral deviation | one operator defecting alone |
//! | strict Nash | no *weakly* profitable unilateral deviation | indifference resolved badly, laziness, bribery at zero price |
//! | dominance | best regardless of what anyone else does | needing to predict others; the coordination trap |
//! | k-resilience | no coalition of size <= k gains | cartels, one operator behind many machines |
//! | invasion resistance | a resident population repels m mutants | a defecting minority growing into a majority |
//!
//! # Why Nash on its own is close to worthless here
//!
//! A mechanism whose honest profile is *a* Nash equilibrium can still have a
//! dishonest profile that is also one -- and if the dishonest one pays better,
//! that is where a population lands. The verifier's dilemma in [`super::mechanism`]
//! is exactly this shape: "everybody rubber-stamps" is an equilibrium under any
//! slashing rule whose trigger is *another node catching the fraud*, because if
//! nobody checks, nobody is caught, and no slash ever fires. No amount of
//! increasing the penalty fixes it. That is why [`pure_equilibria`] enumerates
//! *all* equilibria rather than checking the one the designer hoped for, and why
//! [`dominance`] is reported separately: a strictly dominant honest action is
//! the only rung that makes the bad equilibrium disappear rather than merely
//! coexist.
//!
//! # Two representations
//!
//! [`Game`] is the general finite normal form -- named players, per-player
//! action sets, exact payoffs -- and everything about it is exponential in the
//! number of players. That is fine for the committee sub-game, where the
//! players are a handful of named roles.
//!
//! [`Symmetric`] is the representation that scales: `n` interchangeable
//! operators, so a strategy profile is a *count* per action rather than a choice
//! per player, and the profile space grows polynomially instead. A network of a
//! thousand nodes is analysable in this form and not in the other.

use std::collections::BTreeSet;
use std::fmt;

use super::exact::Rat;

/// Enumeration budget, in profiles.
///
/// Every exhaustive search here refuses to start rather than running for an
/// unbounded time: an analysis tool that hangs teaches the user nothing, and a
/// refusal names the parameter that made the space too big.
const MAX_PROFILES: u128 = 1 << 22;

/// Everything the solvers refuse to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GameError {
    /// The profile space exceeds `MAX_PROFILES`.
    TooLarge { profiles: u128 },
    /// A profile whose length or contents do not match the game.
    MalformedProfile,
    /// A game with no players, or a player with no actions. Not an edge case to
    /// handle downstream -- "the best action" has no meaning in an empty set, so
    /// it is refused where it is first observable.
    Degenerate,
}

impl fmt::Display for GameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GameError::TooLarge { profiles } => write!(
                f,
                "profile space of {profiles} exceeds the {MAX_PROFILES} enumeration budget"
            ),
            GameError::MalformedProfile => write!(f, "profile does not match the game"),
            GameError::Degenerate => {
                write!(f, "a game needs a player and every player needs an action")
            }
        }
    }
}

impl std::error::Error for GameError {}

/// A finite game in normal form, with exact payoffs.
///
/// Deliberately a trait rather than a payoff matrix. The node game's payoffs are
/// a few lines of algebra over a parameter set; materialising them into a table
/// would mean the table and the algebra could disagree, and the table is the one
/// that would be tested.
pub trait Game {
    fn players(&self) -> usize;

    /// How many actions `player` has. Must be positive.
    fn actions(&self, player: usize) -> usize;

    /// Payoff to `player` under `profile`, where `profile[i]` is player `i`'s
    /// action index.
    ///
    /// Implementations may assume `profile` is well formed; the solvers in this
    /// module only ever construct valid profiles, and [`check`] validates the
    /// ones that come from outside.
    fn payoff(&self, player: usize, profile: &[usize]) -> Rat;

    /// Human-readable name for an action, used by reports.
    fn action_name(&self, player: usize, action: usize) -> String {
        let _ = player;
        format!("a{action}")
    }

    /// Human-readable name for a player.
    fn player_name(&self, player: usize) -> String {
        format!("p{player}")
    }
}

/// How firmly a profile holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stability {
    /// Every unilateral deviation makes the deviator *strictly* worse off.
    ///
    /// The rung worth designing for. A weak equilibrium is one where somebody is
    /// indifferent, and an indifferent node operator is one whose behaviour is
    /// decided by something outside the model -- laziness, a competitor's bribe,
    /// or the cost of the extra line of code. Those all point the same way, and
    /// it is not the way the designer hoped.
    Strict,
    /// No deviation is profitable, but at least one is free.
    Weak,
}

/// A unilateral deviation that a player would take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deviation {
    pub player: usize,
    pub from: usize,
    pub to: usize,
    /// Payoff after minus payoff before. Positive for a profitable deviation,
    /// zero for a free one.
    pub gain: Rat,
}

/// One action beating another for a player, whatever everyone else does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dominance {
    /// Strictly better against *every* profile of the others.
    Strict,
    /// Never worse, and strictly better somewhere.
    Weak,
}

/// A group of players who all gain by moving together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoalitionDeviation {
    /// Player indices, ascending.
    pub members: Vec<usize>,
    /// The action each member switches to, aligned with `members`.
    pub actions: Vec<usize>,
    /// The coalition's total gain. Under [`Criterion::EveryMember`] every member
    /// also gains individually; under [`Criterion::Transferable`] only the total
    /// is guaranteed positive.
    pub gain: Rat,
}

/// What counts as a coalition being better off.
///
/// The distinction is not academic and it is usually got wrong. A *strong
/// equilibrium* asks whether a deviation exists that helps **every** member --
/// so a cartel that enriches four members and costs the fifth one unit is not a
/// violation. That is the right test when the members cannot pay each other.
///
/// On a network with a settlement layer they can always pay each other, so the
/// binding test is whether the deviation raises the coalition's **total**: the
/// winners can compensate the loser out of the proceeds and the deviation
/// happens anyway. Committee collusion in [`super::mechanism`] is exactly this shape
/// -- the members who publish shares early can split the stolen bounty -- so the
/// harness reports the transferable criterion by default and the per-member one
/// alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Criterion {
    /// Every member strictly gains. The strong-equilibrium test.
    EveryMember,
    /// The coalition's total strictly rises, with side payments assumed.
    Transferable,
}

// ---------------------------------------------------------------------------
// General finite games
// ---------------------------------------------------------------------------

/// Validate a game and, if given, a profile against it.
pub fn check<G: Game + ?Sized>(game: &G, profile: Option<&[usize]>) -> Result<(), GameError> {
    let players = game.players();
    if players == 0 {
        return Err(GameError::Degenerate);
    }
    for player in 0..players {
        if game.actions(player) == 0 {
            return Err(GameError::Degenerate);
        }
    }
    if let Some(profile) = profile {
        if profile.len() != players {
            return Err(GameError::MalformedProfile);
        }
        for (player, action) in profile.iter().enumerate() {
            if *action >= game.actions(player) {
                return Err(GameError::MalformedProfile);
            }
        }
    }
    Ok(())
}

/// Size of the profile space, or [`GameError::TooLarge`].
fn profile_count<G: Game + ?Sized>(game: &G) -> Result<u128, GameError> {
    let mut total: u128 = 1;
    for player in 0..game.players() {
        total = total
            .checked_mul(game.actions(player) as u128)
            .ok_or(GameError::TooLarge {
                profiles: u128::MAX,
            })?;
        if total > MAX_PROFILES {
            return Err(GameError::TooLarge { profiles: total });
        }
    }
    Ok(total)
}

/// Every action that maximises `player`'s payoff, holding the others fixed.
///
/// Returns the full argmax rather than one element, because the *size* of the
/// set is the finding: more than one best response means the player is
/// indifferent, which is how a weak equilibrium is detected.
pub fn best_responses<G: Game + ?Sized>(
    game: &G,
    player: usize,
    profile: &[usize],
) -> Result<Vec<usize>, GameError> {
    check(game, Some(profile))?;
    if player >= game.players() {
        return Err(GameError::MalformedProfile);
    }
    let mut candidate = profile.to_vec();
    let mut best: Option<Rat> = None;
    let mut winners = Vec::new();
    for action in 0..game.actions(player) {
        candidate[player] = action;
        let payoff = game.payoff(player, &candidate);
        match best {
            Some(current) if payoff > current => {
                best = Some(payoff);
                winners.clear();
                winners.push(action);
            }
            Some(current) if payoff == current => winners.push(action),
            Some(_) => {}
            None => {
                best = Some(payoff);
                winners.push(action);
            }
        }
    }
    Ok(winners)
}

/// The most profitable unilateral deviation available to anyone, if one exists.
///
/// Ties are broken by the lowest player index and then the lowest action index,
/// so the answer is a function of the game rather than of iteration order. Free
/// deviations (`gain == 0`) are *not* returned -- use [`stability`] to find
/// those, which keeps "is this a Nash equilibrium" and "is it strict" as
/// separate questions with separate answers.
pub fn best_deviation<G: Game + ?Sized>(
    game: &G,
    profile: &[usize],
) -> Result<Option<Deviation>, GameError> {
    check(game, Some(profile))?;
    let mut candidate = profile.to_vec();
    let mut best: Option<Deviation> = None;
    for player in 0..game.players() {
        let current = game.payoff(player, profile);
        for action in 0..game.actions(player) {
            if action == profile[player] {
                continue;
            }
            candidate[player] = action;
            let gain = game.payoff(player, &candidate) - current;
            if gain.is_positive() && best.as_ref().is_none_or(|found| gain > found.gain) {
                best = Some(Deviation {
                    player,
                    from: profile[player],
                    to: action,
                    gain,
                });
            }
        }
        candidate[player] = profile[player];
    }
    Ok(best)
}

/// Whether `profile` is a Nash equilibrium, and how firmly.
///
/// `None` means some player has a profitable deviation.
pub fn stability<G: Game + ?Sized>(
    game: &G,
    profile: &[usize],
) -> Result<Option<Stability>, GameError> {
    check(game, Some(profile))?;
    let mut strict = true;
    for player in 0..game.players() {
        let responses = best_responses(game, player, profile)?;
        if !responses.contains(&profile[player]) {
            return Ok(None);
        }
        if responses.len() > 1 {
            strict = false;
        }
    }
    Ok(Some(if strict {
        Stability::Strict
    } else {
        Stability::Weak
    }))
}

/// Every pure-strategy Nash equilibrium, in profile order.
///
/// This is the function that earns its keep. Checking whether the *intended*
/// profile is an equilibrium answers a question the designer chose; enumerating
/// them all answers the question an attacker asks, which is where else the
/// system can sit. A mechanism with two equilibria is a mechanism whose outcome
/// is decided by history rather than by design.
pub fn pure_equilibria<G: Game + ?Sized>(
    game: &G,
) -> Result<Vec<(Vec<usize>, Stability)>, GameError> {
    check(game, None)?;
    profile_count(game)?;
    let mut found = Vec::new();
    let mut profile = vec![0usize; game.players()];
    loop {
        if let Some(kind) = stability(game, &profile)? {
            found.push((profile.clone(), kind));
        }
        if !advance(game, &mut profile) {
            break;
        }
    }
    Ok(found)
}

/// Odometer step through the profile space. Returns false when it wraps.
fn advance<G: Game + ?Sized>(game: &G, profile: &mut [usize]) -> bool {
    advance_from(game, profile, None)
}

/// Odometer step over everyone *except* `skip`.
///
/// [`dominance`] needs this and cannot use [`advance`]: it writes the compared
/// actions into `profile[player]` on every iteration, so a carry into that slot
/// is overwritten before it can be observed and the odometer never reaches its
/// last state. The result is not a wrong answer but a loop that does not
/// terminate, which is why the two are separate functions rather than one
/// function with a comment.
fn advance_others<G: Game + ?Sized>(game: &G, profile: &mut [usize], skip: usize) -> bool {
    advance_from(game, profile, Some(skip))
}

fn advance_from<G: Game + ?Sized>(game: &G, profile: &mut [usize], skip: Option<usize>) -> bool {
    for player in (0..profile.len()).rev() {
        if skip == Some(player) {
            continue;
        }
        profile[player] += 1;
        if profile[player] < game.actions(player) {
            return true;
        }
        profile[player] = 0;
    }
    false
}

/// Does `action` dominate `other` for `player`, across all profiles of the rest?
///
/// The strongest rung a single action can reach. An action that strictly
/// dominates every alternative needs no belief about anyone else's behaviour,
/// which is what makes it robust to the thing Nash analysis cannot see: an
/// operator who is wrong about what the others are doing, or who has not thought
/// about it at all.
pub fn dominance<G: Game + ?Sized>(
    game: &G,
    player: usize,
    action: usize,
    other: usize,
) -> Result<Option<Dominance>, GameError> {
    check(game, None)?;
    if player >= game.players()
        || action >= game.actions(player)
        || other >= game.actions(player)
        || action == other
    {
        return Err(GameError::MalformedProfile);
    }
    profile_count(game)?;
    let mut profile = vec![0usize; game.players()];
    let mut strict_everywhere = true;
    let mut better_somewhere = false;
    loop {
        profile[player] = action;
        let mine = game.payoff(player, &profile);
        profile[player] = other;
        let theirs = game.payoff(player, &profile);
        if mine < theirs {
            return Ok(None);
        }
        if mine == theirs {
            strict_everywhere = false;
        } else {
            better_somewhere = true;
        }
        if !advance_others(game, &mut profile, player) {
            break;
        }
    }
    Ok(if strict_everywhere {
        Some(Dominance::Strict)
    } else if better_somewhere {
        Some(Dominance::Weak)
    } else {
        None
    })
}

/// The action that dominates every alternative for `player`, if there is one.
pub fn dominant_action<G: Game + ?Sized>(
    game: &G,
    player: usize,
) -> Result<Option<(usize, Dominance)>, GameError> {
    check(game, None)?;
    if player >= game.players() {
        return Err(GameError::MalformedProfile);
    }
    let count = game.actions(player);
    for action in 0..count {
        let mut weakest: Option<Dominance> = Some(Dominance::Strict);
        for other in 0..count {
            if other == action {
                continue;
            }
            match dominance(game, player, action, other)? {
                Some(Dominance::Strict) => {}
                Some(Dominance::Weak) => weakest = Some(Dominance::Weak),
                None => {
                    weakest = None;
                    break;
                }
            }
        }
        if let Some(kind) = weakest {
            return Ok(Some((action, kind)));
        }
    }
    Ok(None)
}

/// The most rewarding joint deviation by a coalition of at most `max_size`.
///
/// A Nash equilibrium says nothing about groups, and every interesting attack on
/// a network is a group: a mining pool, a cartel of committee members, one
/// operator running forty machines. This is the `k`-resilience test -- if it
/// returns `None` for `max_size = k`, no group of `k` or fewer can gain.
///
/// The search is `C(n, k) * a^k` and is bounded by `MAX_PROFILES`; for the
/// large-`n` case use [`invasion`] on the symmetric representation instead,
/// which answers the same question in the shape that scales.
pub fn coalition_deviation<G: Game + ?Sized>(
    game: &G,
    profile: &[usize],
    max_size: usize,
    criterion: Criterion,
) -> Result<Option<CoalitionDeviation>, GameError> {
    check(game, Some(profile))?;
    let players = game.players();
    let max_size = max_size.min(players);
    let mut best: Option<CoalitionDeviation> = None;
    let mut budget = MAX_PROFILES;
    for size in 1..=max_size {
        let mut members: Vec<usize> = (0..size).collect();
        loop {
            let before: Vec<Rat> = members
                .iter()
                .map(|member| game.payoff(*member, profile))
                .collect();
            let mut candidate = profile.to_vec();
            let mut choices = vec![0usize; size];
            loop {
                // Skip the null deviation and any assignment where a member does
                // not actually move: a "coalition" whose members stand still is
                // just a smaller coalition, already covered by an earlier size.
                let moved = members
                    .iter()
                    .zip(&choices)
                    .all(|(member, action)| *action != profile[*member]);
                if moved {
                    budget = match budget.checked_sub(1) {
                        Some(left) => left,
                        None => {
                            return Err(GameError::TooLarge {
                                profiles: MAX_PROFILES,
                            })
                        }
                    };
                    for (member, action) in members.iter().zip(&choices) {
                        candidate[*member] = *action;
                    }
                    let after: Vec<Rat> = members
                        .iter()
                        .map(|member| game.payoff(*member, &candidate))
                        .collect();
                    let gains: Vec<Rat> = after
                        .iter()
                        .zip(&before)
                        .map(|(now, then)| *now - *then)
                        .collect();
                    let total: Rat = gains.iter().copied().sum();
                    let qualifies = match criterion {
                        Criterion::EveryMember => gains.iter().all(Rat::is_positive),
                        Criterion::Transferable => total.is_positive(),
                    };
                    if qualifies && best.as_ref().is_none_or(|found| total > found.gain) {
                        best = Some(CoalitionDeviation {
                            members: members.clone(),
                            actions: choices.clone(),
                            gain: total,
                        });
                    }
                    for (member, _) in members.iter().zip(&choices) {
                        candidate[*member] = profile[*member];
                    }
                }
                if !advance_choices(game, &members, &mut choices) {
                    break;
                }
            }
            if !advance_subset(&mut members, players) {
                break;
            }
        }
    }
    Ok(best)
}

/// Odometer over the coalition's joint action choice.
fn advance_choices<G: Game + ?Sized>(game: &G, members: &[usize], choices: &mut [usize]) -> bool {
    for slot in (0..choices.len()).rev() {
        choices[slot] += 1;
        if choices[slot] < game.actions(members[slot]) {
            return true;
        }
        choices[slot] = 0;
    }
    false
}

/// Next `k`-subset in lexicographic order. Returns false after the last.
fn advance_subset(members: &mut [usize], players: usize) -> bool {
    let size = members.len();
    if size == 0 {
        return false;
    }
    let mut slot = size;
    while slot > 0 {
        slot -= 1;
        if members[slot] < players - (size - slot) {
            members[slot] += 1;
            for next in slot + 1..size {
                members[next] = members[next - 1] + 1;
            }
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Symmetric population games
// ---------------------------------------------------------------------------

/// `n` interchangeable players, so a profile is a count per action.
///
/// This is the representation a network of operators actually has: nobody cares
/// *which* node rubber-stamps, only how many do. Collapsing the profile to a
/// count is not an approximation -- it is exact whenever players are
/// interchangeable -- and it turns an `a^n` search into a search over
/// compositions of `n`, which is polynomial in `n` for fixed `a`.
pub trait Symmetric {
    /// Number of actions available to each player. Must be positive.
    fn actions(&self) -> usize;

    /// Number of players. Must be positive.
    fn population(&self) -> u32;

    /// Payoff to one player choosing `own`, when the **other** `n - 1` players
    /// are distributed as `others`.
    ///
    /// `others` has one entry per action and sums to `n - 1`. Excluding the
    /// player from the counts is what makes the deviation question expressible:
    /// "if I switch, what happens to *me*" needs my own action separated out.
    fn payoff(&self, own: usize, others: &[u32]) -> Rat;

    fn action_name(&self, action: usize) -> String {
        format!("a{action}")
    }
}

/// What counts as an invasion succeeding.
///
/// The distinction is not pedantry. In a threshold scheme a cartel member below
/// the threshold earns *exactly* what an honest member earns -- it has learned
/// nothing and forfeited nothing -- so a cartel can assemble at zero cost and
/// become profitable, discontinuously, at the threshold. Asking only about
/// strict gains reports the threshold and misses the free assembly; asking only
/// about weak gains reports the free assembly and buries the threshold. Both are
/// findings, so both are askable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invades {
    /// A mutant does at least as well as a resident. Catches neutral drift: a
    /// mutation with no cost spreads by chance, and nothing pushes it back out.
    WeaklyBetter,
    /// A mutant does strictly better. The size of group that actually profits.
    StrictlyBetter,
}

/// A resident population that mutants tried to invade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invasion {
    /// The action the residents play.
    pub resident: usize,
    /// The action the mutants switched to.
    pub mutant: usize,
    /// The smallest number of mutants at which a mutant does at least as well as
    /// a resident.
    pub mutants: u32,
    /// The mutant's advantage at that size, under the gate that was asked for.
    pub gain: Rat,
}

/// Counts of players per action, summing to the population.
pub type Counts = Vec<u32>;

fn check_symmetric<S: Symmetric + ?Sized>(game: &S) -> Result<(), GameError> {
    if game.actions() == 0 || game.population() == 0 {
        return Err(GameError::Degenerate);
    }
    Ok(())
}

/// Split `counts` into "one player playing `own`" and "everybody else".
fn others_of(counts: &[u32], own: usize) -> Option<Counts> {
    let mut others = counts.to_vec();
    let slot = others.get_mut(own)?;
    *slot = slot.checked_sub(1)?;
    Some(others)
}

/// Best responses for a player facing `others`.
pub fn symmetric_best_responses<S: Symmetric + ?Sized>(
    game: &S,
    others: &[u32],
) -> Result<Vec<usize>, GameError> {
    check_symmetric(game)?;
    if others.len() != game.actions()
        || others.iter().copied().map(u64::from).sum::<u64>() + 1 != u64::from(game.population())
    {
        return Err(GameError::MalformedProfile);
    }
    let mut best: Option<Rat> = None;
    let mut winners = Vec::new();
    for action in 0..game.actions() {
        let payoff = game.payoff(action, others);
        match best {
            Some(current) if payoff > current => {
                best = Some(payoff);
                winners.clear();
                winners.push(action);
            }
            Some(current) if payoff == current => winners.push(action),
            Some(_) => {}
            None => {
                best = Some(payoff);
                winners.push(action);
            }
        }
    }
    Ok(winners)
}

/// Whether a count vector is a symmetric Nash equilibrium, and how firmly.
///
/// Only actions that somebody is actually playing are checked, which is the
/// definition: nobody can be made worse off by a switch they are not making.
pub fn symmetric_stability<S: Symmetric + ?Sized>(
    game: &S,
    counts: &[u32],
) -> Result<Option<Stability>, GameError> {
    check_symmetric(game)?;
    if counts.len() != game.actions()
        || counts.iter().copied().map(u64::from).sum::<u64>() != u64::from(game.population())
    {
        return Err(GameError::MalformedProfile);
    }
    let mut strict = true;
    for action in 0..game.actions() {
        if counts[action] == 0 {
            continue;
        }
        let others = others_of(counts, action).ok_or(GameError::MalformedProfile)?;
        let responses = symmetric_best_responses(game, &others)?;
        if !responses.contains(&action) {
            return Ok(None);
        }
        if responses.len() > 1 {
            strict = false;
        }
    }
    Ok(Some(if strict {
        Stability::Strict
    } else {
        Stability::Weak
    }))
}

/// Every symmetric pure equilibrium, as count vectors.
///
/// Enumerates compositions of `n` into `actions()` parts. That is
/// `C(n + a - 1, a - 1)` profiles -- a few hundred thousand for a thousand nodes
/// and three actions, and refused above `MAX_PROFILES`.
pub fn symmetric_equilibria<S: Symmetric + ?Sized>(
    game: &S,
) -> Result<Vec<(Counts, Stability)>, GameError> {
    check_symmetric(game)?;
    let mut found = Vec::new();
    let mut budget = MAX_PROFILES;
    let mut counts = vec![0u32; game.actions()];
    compositions(game.population(), 0, &mut counts, &mut |counts| {
        budget = budget.checked_sub(1).ok_or(GameError::TooLarge {
            profiles: MAX_PROFILES,
        })?;
        if let Some(kind) = symmetric_stability(game, counts)? {
            found.push((counts.to_vec(), kind));
        }
        Ok(())
    })?;
    Ok(found)
}

/// Enumerate every way to write `total` as an ordered sum over `counts.len()` slots.
fn compositions<F>(
    total: u32,
    slot: usize,
    counts: &mut Counts,
    visit: &mut F,
) -> Result<(), GameError>
where
    F: FnMut(&[u32]) -> Result<(), GameError>,
{
    if slot + 1 == counts.len() {
        counts[slot] = total;
        return visit(counts);
    }
    for taken in 0..=total {
        counts[slot] = taken;
        compositions(total - taken, slot + 1, counts, visit)?;
    }
    counts[slot] = 0;
    Ok(())
}

/// The monomorphic profile in which everybody plays `action`.
pub fn everyone<S: Symmetric + ?Sized>(game: &S, action: usize) -> Counts {
    let mut counts = vec![0u32; game.actions()];
    if let Some(slot) = counts.get_mut(action) {
        *slot = game.population();
    }
    counts
}

/// How many defectors it takes before defecting pays.
///
/// This is the number a security argument actually needs, and it is not the Nash
/// answer. "One node cannot gain by deviating alone" is compatible with "eleven
/// nodes acting together all gain" -- and eleven nodes is a Telegram group, not a
/// conspiracy. Searching upward from one mutant reports the smallest group that
/// works, which is a budget an attacker can be asked to meet.
///
/// `gate` decides whether a mutant that merely *ties* counts as having invaded.
/// It usually should -- a neutral mutant drifts, and a population that has
/// drifted may then be past a threshold where mutating strictly pays -- but
/// asking the strict question separately is what reports the size of the group
/// that actually profits. See [`Invades`].
pub fn invasion<S: Symmetric + ?Sized>(
    game: &S,
    resident: usize,
    max_mutants: u32,
    gate: Invades,
) -> Result<Option<Invasion>, GameError> {
    check_symmetric(game)?;
    if resident >= game.actions() {
        return Err(GameError::MalformedProfile);
    }
    let population = game.population();
    let ceiling = max_mutants.min(population);
    let mut best: Option<Invasion> = None;
    for mutant in 0..game.actions() {
        if mutant == resident {
            continue;
        }
        for size in 1..=ceiling {
            // The deviator's own view: `size - 1` fellow mutants among the
            // others, the rest resident.
            let mut others = vec![0u32; game.actions()];
            others[mutant] = size - 1;
            others[resident] = population - size;
            let gain = game.payoff(mutant, &others) - game.payoff(resident, &others);
            let succeeded = match gate {
                Invades::WeaklyBetter => !gain.is_negative(),
                Invades::StrictlyBetter => gain.is_positive(),
            };
            if succeeded {
                let found = Invasion {
                    resident,
                    mutant,
                    mutants: size,
                    gain,
                };
                let better = match &best {
                    None => true,
                    Some(current) => (found.mutants, current.gain) < (current.mutants, found.gain),
                };
                if better {
                    best = Some(found);
                }
                break;
            }
        }
    }
    Ok(best)
}

// ---------------------------------------------------------------------------
// Sybil resistance
// ---------------------------------------------------------------------------

/// A mechanism in which one operator may appear as several identities.
///
/// Kept separate from [`Game`] because sybil resistance is not a statement about
/// a profile. It is a statement about the *map from resources to payoff*: an
/// operator with a fixed budget of stake and hardware asks whether to present it
/// as one node or as forty, and a mechanism is sybil-proof exactly when the
/// answer is one.
///
/// Almost every per-node reward is sybil-*attracting* by construction. A pool
/// split evenly per node pays `k` times as much to `k` identities; only rewards
/// proportional to a resource that cannot itself be split for free -- stake,
/// storage actually held, verification actually performed -- resist it.
pub trait Sybil {
    /// Total payoff to one operator presenting as `identities` identities,
    /// holding its real resources fixed.
    fn payoff_with(&self, identities: u32) -> Rat;
}

/// The number of identities an operator would choose, and what splitting buys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SybilResult {
    /// The profit-maximising identity count within the range searched.
    pub best: u32,
    /// Payoff at `best` minus payoff at one identity. Zero when the mechanism is
    /// sybil-proof over the range.
    pub gain: Rat,
}

/// Search identity counts `1..=max_identities` for a profitable split.
pub fn sybil_gain<S: Sybil + ?Sized>(model: &S, max_identities: u32) -> SybilResult {
    let honest = model.payoff_with(1);
    let mut best = 1;
    let mut best_payoff = honest;
    for identities in 2..=max_identities.max(1) {
        let payoff = model.payoff_with(identities);
        if payoff > best_payoff {
            best_payoff = payoff;
            best = identities;
        }
    }
    SybilResult {
        best,
        gain: best_payoff - honest,
    }
}

// ---------------------------------------------------------------------------
// Individual rationality
// ---------------------------------------------------------------------------

/// Whether a payoff clears an outside option.
///
/// The rung below Nash, and the one skipped most often. An equilibrium in which
/// every operator earns less than the price of the electricity is a stable
/// prediction about a network that does not exist. Every report in
/// [`super::mechanism`] states this first, because if it fails the rest is arithmetic
/// about an empty set.
pub fn individually_rational(payoff: Rat, outside_option: Rat) -> bool {
    payoff >= outside_option
}

/// Player indices mentioned by a coalition deviation, as a set for reporting.
pub fn members_of(deviation: &CoalitionDeviation) -> BTreeSet<usize> {
    deviation.members.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payoff-matrix game, for testing the solvers against textbook answers.
    struct Matrix {
        /// `payoffs[player][profile_index]`, profile index in odometer order.
        payoffs: Vec<Vec<Rat>>,
        actions: Vec<usize>,
    }

    impl Matrix {
        /// Two players, two actions each, payoffs given row-major as
        /// `[(row, col); 4]` for profiles (0,0), (0,1), (1,0), (1,1).
        fn two_by_two(cells: [(i64, i64); 4]) -> Matrix {
            let rows = cells.iter().map(|(r, _)| Rat::int(*r)).collect();
            let cols = cells.iter().map(|(_, c)| Rat::int(*c)).collect();
            Matrix {
                payoffs: vec![rows, cols],
                actions: vec![2, 2],
            }
        }

        fn index(&self, profile: &[usize]) -> usize {
            profile
                .iter()
                .zip(&self.actions)
                .fold(0, |acc, (action, count)| acc * count + action)
        }
    }

    impl Game for Matrix {
        fn players(&self) -> usize {
            self.actions.len()
        }
        fn actions(&self, player: usize) -> usize {
            self.actions[player]
        }
        fn payoff(&self, player: usize, profile: &[usize]) -> Rat {
            self.payoffs[player][self.index(profile)]
        }
    }

    /// Prisoner's dilemma: action 0 cooperate, action 1 defect.
    fn prisoners_dilemma() -> Matrix {
        Matrix::two_by_two([(3, 3), (0, 5), (5, 0), (1, 1)])
    }

    /// Stag hunt: two equilibria, one payoff-dominant and one risk-dominant.
    fn stag_hunt() -> Matrix {
        Matrix::two_by_two([(4, 4), (0, 3), (3, 0), (3, 3)])
    }

    #[test]
    fn prisoners_dilemma_has_one_equilibrium_and_it_is_strict() {
        let game = prisoners_dilemma();
        let equilibria = pure_equilibria(&game).expect("small game");
        assert_eq!(equilibria, vec![(vec![1, 1], Stability::Strict)]);
    }

    #[test]
    fn defection_strictly_dominates_in_the_prisoners_dilemma() {
        let game = prisoners_dilemma();
        assert_eq!(
            dominant_action(&game, 0).expect("small game"),
            Some((1, Dominance::Strict))
        );
        assert_eq!(
            dominance(&game, 0, 1, 0).expect("small game"),
            Some(Dominance::Strict)
        );
        assert_eq!(dominance(&game, 0, 0, 1).expect("small game"), None);
    }

    #[test]
    fn the_prisoners_dilemma_is_a_nash_equilibrium_a_pair_can_still_escape() {
        // The whole reason coalition analysis is a separate rung: (defect,
        // defect) is an unimpeachable Nash equilibrium and both players prefer
        // (cooperate, cooperate).
        let game = prisoners_dilemma();
        assert_eq!(
            stability(&game, &[1, 1]).expect("small game"),
            Some(Stability::Strict)
        );
        let escape = coalition_deviation(&game, &[1, 1], 2, Criterion::EveryMember)
            .expect("small game")
            .expect("both players gain by cooperating together");
        assert_eq!(escape.members, vec![0, 1]);
        assert_eq!(escape.actions, vec![0, 0]);
        assert_eq!(escape.gain, Rat::int(4), "two apiece");
        // No single player can do it alone.
        assert_eq!(
            coalition_deviation(&game, &[1, 1], 1, Criterion::EveryMember).expect("small game"),
            None
        );
    }

    #[test]
    fn stag_hunt_has_two_equilibria_which_is_the_finding() {
        // A designer who checks only the profile they hoped for sees "stag,
        // stag is an equilibrium" and ships. Enumeration shows the trap.
        let game = stag_hunt();
        let equilibria = pure_equilibria(&game).expect("small game");
        assert_eq!(
            equilibria,
            vec![
                (vec![0, 0], Stability::Strict),
                (vec![1, 1], Stability::Strict)
            ]
        );
        assert_eq!(dominant_action(&game, 0).expect("small game"), None);
    }

    #[test]
    fn best_deviation_finds_the_largest_gain_and_ignores_free_moves() {
        let game = prisoners_dilemma();
        let deviation = best_deviation(&game, &[0, 0])
            .expect("small game")
            .expect("defection pays");
        assert_eq!(deviation.player, 0, "ties break to the lowest index");
        assert_eq!(deviation.gain, Rat::int(2));
        assert_eq!(best_deviation(&game, &[1, 1]).expect("small game"), None);
    }

    #[test]
    fn a_weak_equilibrium_is_reported_as_weak() {
        // Player 0 is indifferent between its actions when player 1 plays 0.
        let game = Matrix::two_by_two([(1, 1), (0, 0), (1, 0), (0, 0)]);
        assert_eq!(
            stability(&game, &[0, 0]).expect("small game"),
            Some(Stability::Weak)
        );
        assert_eq!(
            best_responses(&game, 0, &[0, 0]).expect("small game"),
            vec![0, 1],
            "indifference is visible as a two-element argmax"
        );
    }

    #[test]
    fn transferable_criterion_catches_a_cartel_the_per_member_test_misses() {
        // Deviating together raises the total by 1 but costs player 1 a unit.
        // Without side payments the cartel does not form; with them it does.
        let game = Matrix::two_by_two([(0, 0), (0, 0), (0, 0), (5, -1)]);
        assert_eq!(
            coalition_deviation(&game, &[0, 0], 2, Criterion::EveryMember).expect("small game"),
            None
        );
        let bribed = coalition_deviation(&game, &[0, 0], 2, Criterion::Transferable)
            .expect("small game")
            .expect("the winner can compensate the loser");
        assert_eq!(bribed.gain, Rat::int(4));
        assert_eq!(members_of(&bribed), BTreeSet::from([0, 1]));
    }

    #[test]
    fn degenerate_games_are_refused_rather_than_answered() {
        struct Empty;
        impl Game for Empty {
            fn players(&self) -> usize {
                0
            }
            fn actions(&self, _player: usize) -> usize {
                0
            }
            fn payoff(&self, _player: usize, _profile: &[usize]) -> Rat {
                Rat::ZERO
            }
        }
        assert_eq!(pure_equilibria(&Empty), Err(GameError::Degenerate));
        let game = prisoners_dilemma();
        assert_eq!(
            stability(&game, &[0]).expect_err("wrong length"),
            GameError::MalformedProfile
        );
        assert_eq!(
            stability(&game, &[0, 2]).expect_err("action out of range"),
            GameError::MalformedProfile
        );
    }

    #[test]
    fn an_oversized_profile_space_is_refused_not_attempted() {
        struct Wide;
        impl Game for Wide {
            fn players(&self) -> usize {
                40
            }
            fn actions(&self, _player: usize) -> usize {
                4
            }
            fn payoff(&self, _player: usize, _profile: &[usize]) -> Rat {
                Rat::ZERO
            }
        }
        assert!(matches!(
            pure_equilibria(&Wide),
            Err(GameError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_dominance_odometer_skips_the_players_own_slot() {
        // Regression: sweeping the opponents' profiles with the full-width
        // odometer let a carry land in the slot `dominance` overwrites every
        // iteration, so the sweep never finished. It hung rather than answering
        // wrongly, which is the failure mode a two-player test catches only if
        // somebody runs it.
        let game = prisoners_dilemma();
        let mut profile = vec![0, 0];
        let mut seen = vec![profile.clone()];
        while advance_others(&game, &mut profile, 0) {
            seen.push(profile.clone());
        }
        assert_eq!(seen, vec![vec![0, 0], vec![0, 1]], "only player 1 moves");
        // And the full-width odometer still covers everything.
        let mut all = vec![0, 0];
        let mut count = 1;
        while advance(&game, &mut all) {
            count += 1;
        }
        assert_eq!(count, 4);
    }

    #[test]
    fn subsets_enumerate_each_combination_once() {
        let mut members = vec![0, 1];
        let mut seen = vec![members.clone()];
        while advance_subset(&mut members, 4) {
            seen.push(members.clone());
        }
        assert_eq!(
            seen,
            vec![
                vec![0, 1],
                vec![0, 2],
                vec![0, 3],
                vec![1, 2],
                vec![1, 3],
                vec![2, 3]
            ]
        );
    }

    // -- symmetric games ----------------------------------------------------

    /// `n` players choose contribute (0) or free-ride (1). Contributing costs
    /// `cost` and adds `value` to a pot split evenly among everyone.
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
            let pot = self.value * Rat::int(i64::from(contributors));
            let share = pot.share(self.players).unwrap_or(Rat::ZERO);
            if own == 0 {
                share - self.cost
            } else {
                share
            }
        }
    }

    #[test]
    fn a_public_good_collapses_to_universal_free_riding() {
        // The verifier's dilemma in its bare form: contributing is socially
        // optimal and privately irrational, at every population size.
        let game = PublicGood {
            players: 10,
            cost: Rat::int(3),
            value: Rat::int(10),
        };
        let all_free = everyone(&game, 1);
        assert_eq!(
            symmetric_stability(&game, &all_free).expect("valid counts"),
            Some(Stability::Strict)
        );
        let all_contribute = everyone(&game, 0);
        assert_eq!(
            symmetric_stability(&game, &all_contribute).expect("valid counts"),
            None,
            "somebody always prefers to stop paying"
        );
        let equilibria = symmetric_equilibria(&game).expect("small population");
        assert_eq!(equilibria, vec![(vec![0, 10], Stability::Strict)]);
    }

    #[test]
    fn a_public_good_worth_more_than_it_costs_still_needs_no_coordination() {
        // value/players > cost makes contributing dominant -- the design target.
        let game = PublicGood {
            players: 4,
            cost: Rat::int(1),
            value: Rat::int(8),
        };
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, 0)).expect("valid counts"),
            Some(Stability::Strict)
        );
        assert_eq!(
            invasion(&game, 0, 4, Invades::WeaklyBetter).expect("valid resident"),
            None,
            "no group of free-riders gains"
        );
    }

    #[test]
    fn invasion_reports_the_smallest_group_that_gains() {
        /// Defecting pays only once at least three defectors exist.
        struct Threshold;
        impl Symmetric for Threshold {
            fn actions(&self) -> usize {
                2
            }
            fn population(&self) -> u32 {
                20
            }
            fn payoff(&self, own: usize, others: &[u32]) -> Rat {
                let defectors = others[1] + if own == 1 { 1 } else { 0 };
                if own == 1 && defectors >= 3 {
                    Rat::int(10)
                } else if own == 1 {
                    Rat::int(0)
                } else {
                    Rat::int(5)
                }
            }
        }
        let found = invasion(&Threshold, 0, 20, Invades::WeaklyBetter)
            .expect("valid resident")
            .expect("three defectors gain");
        assert_eq!(found.mutants, 3);
        assert_eq!(found.gain, Rat::int(5));
        // A single defector cannot do it, which is exactly what a Nash check
        // would have reported as "secure".
        assert_eq!(
            symmetric_stability(&Threshold, &everyone(&Threshold, 0)).expect("valid counts"),
            Some(Stability::Strict)
        );
        assert_eq!(
            invasion(&Threshold, 0, 2, Invades::WeaklyBetter).expect("valid resident"),
            None
        );
    }

    #[test]
    fn a_neutral_mutant_counts_as_an_invasion() {
        struct Flat;
        impl Symmetric for Flat {
            fn actions(&self) -> usize {
                2
            }
            fn population(&self) -> u32 {
                5
            }
            fn payoff(&self, _own: usize, _others: &[u32]) -> Rat {
                Rat::int(1)
            }
        }
        let found = invasion(&Flat, 0, 5, Invades::WeaklyBetter)
            .expect("valid resident")
            .expect("drift is not resistance");
        assert_eq!((found.mutants, found.gain), (1, Rat::ZERO));
    }

    #[test]
    fn symmetric_counts_are_validated() {
        let game = PublicGood {
            players: 4,
            cost: Rat::int(1),
            value: Rat::int(8),
        };
        assert_eq!(
            symmetric_stability(&game, &[1, 1]).expect_err("counts must sum to n"),
            GameError::MalformedProfile
        );
        assert_eq!(
            symmetric_best_responses(&game, &[1, 1]).expect_err("others must sum to n-1"),
            GameError::MalformedProfile
        );
        assert_eq!(
            symmetric_best_responses(&game, &[2, 1]).expect("sums to three"),
            vec![0]
        );
    }

    #[test]
    fn compositions_cover_the_simplex_exactly_once() {
        let mut counts = vec![0u32; 3];
        let mut seen = Vec::new();
        compositions(3, 0, &mut counts, &mut |counts| {
            seen.push(counts.to_vec());
            Ok(())
        })
        .expect("no budget in this helper");
        assert_eq!(seen.len(), 10, "C(3+2, 2)");
        assert!(seen.iter().all(|c| c.iter().sum::<u32>() == 3));
        let unique: BTreeSet<Vec<u32>> = seen.iter().cloned().collect();
        assert_eq!(unique.len(), seen.len());
    }

    // -- sybil --------------------------------------------------------------

    #[test]
    fn an_even_per_node_split_is_sybil_attracting() {
        /// The mechanism to never build: a pool divided by node count.
        struct PerNode {
            pool: Rat,
            nodes: u32,
        }
        impl Sybil for PerNode {
            fn payoff_with(&self, identities: u32) -> Rat {
                let total = self.nodes + identities - 1;
                self.pool.share(total).unwrap_or(Rat::ZERO) * Rat::int(i64::from(identities))
            }
        }
        let model = PerNode {
            pool: Rat::int(100),
            nodes: 10,
        };
        let result = sybil_gain(&model, 40);
        assert_eq!(result.best, 40, "split as far as the search allows");
        assert!(result.gain.is_positive());
    }

    #[test]
    fn a_stake_weighted_split_is_sybil_proof() {
        /// The same pool, divided by stake rather than by headcount. Splitting
        /// stake across identities changes nothing, which is the point.
        struct PerStake {
            pool: Rat,
            mine: Rat,
            total: Rat,
        }
        impl Sybil for PerStake {
            fn payoff_with(&self, _identities: u32) -> Rat {
                self.pool * self.mine / self.total
            }
        }
        let model = PerStake {
            pool: Rat::int(100),
            mine: Rat::int(10),
            total: Rat::int(50),
        };
        let result = sybil_gain(&model, 40);
        assert_eq!(
            result,
            SybilResult {
                best: 1,
                gain: Rat::ZERO
            }
        );
    }

    #[test]
    fn individual_rationality_admits_exact_indifference() {
        assert!(individually_rational(Rat::int(5), Rat::int(5)));
        assert!(!individually_rational(Rat::int(4), Rat::int(5)));
    }
}
