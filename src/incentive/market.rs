//! The agent-to-agent market, as a fourth sub-game.
//!
//! [`docs/agent-market.md`](https://github.com/aburan28/proofwork/blob/main/docs/agent-market.md)
//! spends four thousand words arguing about whether agents should be able to
//! sell each other sub-frontier candidates, and ends by saying the argument
//! should be *solved* rather than continued. This is that solver.
//!
//! It is a **gate**, not a feature. Nothing here changes a record, a payout or a
//! rule; what it decides is whether the market in that document is worth
//! building at all. The scope note there is explicit that Stage 2 proceeds
//! "only if the harness says the population survives it", and the harness had
//! not been written.
//!
//! # The question, stated so it can have a wrong answer
//!
//! `gossip.rs` assumes candidates worth mutating circulate freely, and they do
//! circulate freely *because nothing prices them*. Introduce a price and each
//! holder faces a choice it did not have before. The four actions are
//! [`Trade`], and the one that matters is whether [`Trade::Gossip`] survives the
//! arrival of [`Trade::Sell`].
//!
//! Two answers would both be findings, and they point opposite ways:
//!
//! - **Gossip is still a best response.** Then the market is additive: agents
//!   that want to sell can, the commons keeps working, and Stage 2 is worth
//!   building.
//! - **Selling takes over.** Then the market is *bistable* in exactly the way
//!   verification is without canaries, a shared client default gets there in one
//!   step, and the thing being proposed destroys the population it was meant to
//!   enrich.
//!
//! The answer turns out to be both, which is why the interesting number is not
//! whether gossip is an equilibrium but which equilibrium a network *returns*
//! to. `docs/agent-market.md` has the table.
//!
//! # Where the model is generous, stated up front
//!
//! Every modelling choice below that is not forced has been made in the
//! direction that flatters the market, so that a negative result is hard to
//! argue with. Three of them:
//!
//! **Reciprocity can be withheld.** A gossip network cannot really exclude a
//! lurker: whoever receives a candidate can pass it on, and nothing checks that
//! a peer shares before it is shared with. [`MarketParams::reciprocity_exclusion`]
//! is the fraction of the commons a non-sharer actually loses, and it is a
//! parameter rather than a constant precisely because assuming perfect exclusion
//! would make gossip look like a private club when it is a public good. The
//! reference value is well below one, in the same spirit as
//! [`super::NodeParams::canary_leak`]: no report should quietly assume the
//! mechanism's best case.
//!
//! **Giving a candidate away costs you it.** Every action is scored on the same
//! option value, and what separates them is how many rivals each one creates:
//! a hoarder creates none, a seller creates one (and only if a buyer turns up),
//! a gossiper and a publisher create the whole population. Without that term the
//! model is incoherent rather than merely rough — selling would strictly
//! dominate hoarding at every profile, because a sale is a copy and the seller
//! keeps the original.
//!
//! **The price is set by scarcity alone.** A seller receives
//! `candidate_value × (1 − sharers/(n−1))`, so a candidate freely circulating is
//! worth nothing and a unique one is worth its full value to its holder. There
//! is no bargaining, no lemons discount, and no cost of finding a buyer beyond
//! [`MarketParams::buyer_share`].
//!
//! # What this deliberately does not model
//!
//! **Techniques.** Unpriceable, and `agent-market.md` explains why at length;
//! nothing here would change that.
//!
//! **The reserved citation share.** Question 3 in that document — the smallest
//! reserve that makes citation dilution unprofitable at a given fanout — is a
//! question about *citation flow*, answered by `FlowParams::with_reserved` and
//! the flow harness, not by this game. Putting it here would mean two models of
//! one mechanism.
//!
//! **Reputation.** Ruled out in scope, and it would break the one invariant the
//! whole document turns on: no protocol payment may be a function of trade
//! volume, or a sybil pair trading a worthless good in a circle mints standing
//! for free.

use super::exact::Rat;
use super::game::{Sybil, Symmetric};
use super::{rate, ParamError, MAX_RATE_DEN, MAX_UNITS};

/// What an agent does with a sub-frontier candidate it holds.
///
/// Four actions, and the fourth is what makes the first three interesting.
/// A three-action version — share it, sell it, sit on it — has no way to express
/// the thing that makes a candidate *sub*-frontier: publishing it is available,
/// and mostly not worth it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trade {
    /// Put it on the gossip transport. Earns nothing directly, and buys the
    /// reciprocity of everyone else doing the same.
    Gossip,
    /// Offer it for a price. Keeps the candidate — information is not consumed
    /// by being sold — and forfeits whatever share of the commons a network can
    /// actually withhold from a non-sharer.
    Sell,
    /// Keep it and try to finish alone. Pays the candidate's full value if
    /// nobody beats you to the frontier, and that chance falls as more of the
    /// population circulates candidates of its own.
    Hoard,
    /// Submit it. Pays the ratchet's delta plus citation flow *if* it turns out
    /// to advance the frontier, costs a submission attempt either way, and puts
    /// the candidate in a log everybody reads — so a publisher contributes to
    /// the commons at least as much as a gossiper and is treated as one.
    Publish,
}

impl Trade {
    pub const ALL: [Trade; 4] = [Trade::Gossip, Trade::Sell, Trade::Hoard, Trade::Publish];

    pub fn index(self) -> usize {
        match self {
            Trade::Gossip => 0,
            Trade::Sell => 1,
            Trade::Hoard => 2,
            Trade::Publish => 3,
        }
    }

    pub fn from_index(index: usize) -> Option<Trade> {
        Trade::ALL.get(index).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Trade::Gossip => "gossip",
            Trade::Sell => "sell",
            Trade::Hoard => "hoard",
            Trade::Publish => "publish",
        }
    }
}

/// What somebody has to measure before any of this means anything.
///
/// Separate from [`super::NodeParams`] rather than bolted onto it, and the
/// reason is not tidiness: these are facts about *agents searching an objective*
/// and those are facts about *operators running machines*. Merging them would
/// make every existing node report carry seven numbers it does not use, and make
/// every market report validate against a committee threshold it does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketParams {
    /// Agents holding candidates on one objective. Interchangeable, which is
    /// what keeps the symmetric representation honest here.
    pub agents: u32,

    /// What a candidate is worth to the agent holding it: the value of riding it
    /// to the frontier alone, before anyone else's progress is accounted for.
    /// The base of both the hoarding option value and the sale price.
    pub candidate_value: u64,

    /// What a fully-sharing population is worth to one searcher, per epoch.
    /// The commons this whole question is about — if it is small, nothing is at
    /// risk and the market is free.
    pub population_value: u64,

    /// Paid on advancing the frontier: the ratchet's delta plus the citation
    /// flow that follows it.
    ///
    /// One number rather than two because the model never has cause to separate
    /// them — they arrive together and are spent together. `agent-market.md`
    /// writes it as `Δ + φ`.
    pub publish_reward: u64,

    /// What one submission attempt costs the submitter: the commit, the epoch
    /// wait, the reveal.
    ///
    /// **Without this term the game is degenerate**, and the way it fails is
    /// instructive. Publishing gives full reciprocity *and* a shot at the
    /// reward, so with a free attempt it weakly dominates gossip at every
    /// profile and the interesting question never gets asked. What makes a
    /// candidate sub-frontier is precisely that submitting it is not worth the
    /// attempt.
    pub submit_cost: u64,

    /// Probability that a candidate, published, turns out to advance the
    /// frontier. Small by construction: a candidate that reliably advanced it
    /// would be published rather than traded.
    pub advance_rate: Rat,

    /// Fraction of agents holding enough settled balance to buy. A market with
    /// no buyers prices nothing, and this is the term that says so.
    pub buyer_share: Rat,

    /// Protocol fee on a trade.
    ///
    /// It exists to be *reported*, not to be tuned. `agent-market.md` is
    /// emphatic that no protocol payment may key off trade volume, so this is a
    /// cost to the seller and reaches nobody's balance in the model. Raising it
    /// makes selling worse and never makes anything better.
    pub market_fee: Rat,

    /// The share of the commons a network can actually withhold from an agent
    /// that takes and does not give.
    ///
    /// At one, gossip is a club with a membership rule and freeloading is
    /// impossible. At zero it is a pure public good and taking is free. Reality
    /// is near the bottom of that range — whoever receives a candidate can pass
    /// it on — so a value near one is the assumption that would make this whole
    /// report worthless.
    pub reciprocity_exclusion: Rat,
}

impl MarketParams {
    /// A reference market, chosen the way [`super::NodeParams::reference`] is:
    /// so the interesting constraints are close to binding rather than
    /// comfortably satisfied.
    pub fn reference() -> MarketParams {
        MarketParams {
            agents: 50,

            // A candidate worth a fifth of what advancing the frontier pays.
            // Sub-frontier by construction: real, and not yet an improvement.
            candidate_value: 2_000,
            population_value: 6_000,
            publish_reward: 10_000,
            submit_cost: 300,

            // One candidate in fifty turns out to advance the frontier, so
            // publishing one is worth 200 against a 300-unit attempt. Negative
            // by a hundred, which is what *makes* it a sub-frontier candidate:
            // if submitting paid on its own merits nobody would be holding it.
            advance_rate: rate(1, 50),

            buyer_share: rate(1, 5),
            market_fee: rate(1, 50),

            // A fifth, not a half and certainly not one. A gossip network
            // withholds badly: the candidate a lurker was not given directly
            // reaches it second-hand from whoever was.
            reciprocity_exclusion: rate(1, 5),
        }
    }

    pub fn validate(&self) -> Result<(), ParamError> {
        if self.agents < 2 {
            // Two, not one. A one-agent market has no reciprocity term and no
            // buyer, so every payoff collapses and the report would be about
            // arithmetic rather than about a market.
            return Err(ParamError::Empty { field: "agents" });
        }
        for (field, value) in [
            ("candidate_value", self.candidate_value),
            ("population_value", self.population_value),
            ("publish_reward", self.publish_reward),
            ("submit_cost", self.submit_cost),
        ] {
            if value > MAX_UNITS {
                return Err(ParamError::TooLarge { field, value });
            }
        }
        for (field, value) in [
            ("advance_rate", self.advance_rate),
            ("buyer_share", self.buyer_share),
            ("market_fee", self.market_fee),
            ("reciprocity_exclusion", self.reciprocity_exclusion),
        ] {
            if value.is_negative() || value > Rat::ONE || value.denominator() > MAX_RATE_DEN {
                return Err(ParamError::BadRate { field, value });
            }
        }
        Ok(())
    }

    /// Expected value of publishing one candidate, before the commons.
    ///
    /// Negative whenever a candidate is genuinely sub-frontier, which is the
    /// condition that makes the rest of the game non-trivial. Reported rather
    /// than asserted, because a parameter set where it is positive is a
    /// parameter set describing something other than a sub-frontier candidate —
    /// and the caller should be told that rather than get a confident answer to
    /// the wrong question.
    pub fn publish_margin(&self) -> Rat {
        self.advance_rate * Rat::units(self.publish_reward) - Rat::units(self.submit_cost)
    }

    /// Whether these parameters actually describe a sub-frontier candidate.
    pub fn is_sub_frontier(&self) -> bool {
        self.publish_margin() < Rat::ZERO
    }
}

impl Default for MarketParams {
    fn default() -> MarketParams {
        MarketParams::reference()
    }
}

/// The market, as `n` interchangeable agents each holding one candidate.
///
/// # The payoffs
///
/// Write `n` for the agent count, `k` for the number of *other* agents that
/// share — gossipers plus publishers, since a published candidate is in the log
/// and reaches everyone — and `σ = k / (n − 1)`. Then with `V` the candidate
/// value, `P` the population value, `x` the exclusion fraction, `ρ` the buyer
/// share, `f` the market fee, `φ` the advance rate, `R` the publish reward and
/// `c` the submission cost:
///
/// ```text
/// commons(shares)  = P·σ·(1 if shares else 1 − x)
/// option(rivals)   = V·max(0, 1 − φ·(k + rivals))
///
/// gossip           = commons(true)  + option(n − 1)
/// publish          = commons(true)  + option(n − 1) + φ·R − c
/// sell             = commons(false) + option(ρ)     + ρ·(1 − f)·V·(1 − σ)
/// hoard            = commons(false) + option(0)
/// ```
///
/// # Why each term has the shape it has
///
/// **Every action is scored on the same option value, and they differ in how
/// many rivals each creates.** This is the term that makes the model coherent
/// rather than merely rough. A sale is a *copy* — the seller keeps the original
/// — so without it, selling would strictly dominate hoarding at every profile
/// and the game would have nothing to say. What a seller actually gives up is
/// exclusivity, against exactly one buyer and only if one turns up; what a
/// gossiper gives up is exclusivity against everybody.
///
/// **Beaten linearly in the rival count, not in the fraction.** Each rival has
/// an independent per-epoch chance `φ` of pushing the frontier past this
/// candidate, so the chance of being beaten is `1 − (1 − φ)^rivals` and `φ·rivals`
/// is its union bound. Exact exponentiation is not available: [`Rat`] is
/// `i128 / i128` and `50^49` is `10^83`, so the alternative to the bound is
/// floating point, which this module does not have. The bound over-states how
/// often a hoarder is beaten, and it is floored at zero rather than allowed to
/// go negative — an agent cannot be *paid* for losing a race.
///
/// **The commons is linear in `σ`.** A searcher's benefit from the population is
/// proportional to how much of it is circulating. Diminishing returns would be
/// more realistic and would make gossip look *worse* at high `σ`, which is the
/// direction that would flatter the market.
///
/// **A seller's price falls to zero as `σ` rises.** Nobody pays for what is
/// already circulating. This is the term that makes the market self-limiting,
/// and it is why the two equilibria are not mirror images: gossip does not
/// suppress selling by punishing it, it suppresses selling by making the good
/// worthless.
pub struct Market<'a> {
    params: &'a MarketParams,
}

impl<'a> Market<'a> {
    pub fn new(params: &'a MarketParams) -> Result<Market<'a>, ParamError> {
        params.validate()?;
        Ok(Market { params })
    }

    pub fn params(&self) -> &MarketParams {
        self.params
    }

    /// The share of *other* agents that put their candidate where others can
    /// use it.
    fn sharing_fraction(&self, sharers: u32) -> Rat {
        Rat::units(u64::from(sharers))
            .share(self.params.agents - 1)
            .unwrap_or(Rat::ZERO)
    }

    /// What the population is worth to one agent, given how much of it shares
    /// and whether this agent does.
    pub fn commons(&self, sharers: u32, shares: bool) -> Rat {
        let full = Rat::units(self.params.population_value) * self.sharing_fraction(sharers);
        if shares {
            full
        } else {
            full * (Rat::ONE - self.params.reciprocity_exclusion)
        }
    }

    /// What this agent's candidate is still worth to it, given `sharers` other
    /// agents racing with candidates of their own and `created` more that it
    /// handed its own candidate to.
    ///
    /// `created` is a [`Rat`] rather than a count because a seller creates a
    /// rival only when a buyer turns up, which happens with probability
    /// [`MarketParams::buyer_share`].
    pub fn option_value(&self, sharers: u32, created: Rat) -> Rat {
        let rivals = Rat::units(u64::from(sharers)) + created;
        let beaten = self.params.advance_rate * rivals;
        let survives = if beaten > Rat::ONE {
            Rat::ZERO
        } else {
            Rat::ONE - beaten
        };
        Rat::units(self.params.candidate_value) * survives
    }

    /// Every other agent, as a rival count. What gossiping and publishing both
    /// give away.
    fn everyone_else(&self) -> Rat {
        Rat::units(u64::from(self.params.agents - 1))
    }

    /// Payoff to an agent that gossips.
    pub fn gossip_payoff(&self, sharers: u32) -> Rat {
        self.commons(sharers, true) + self.option_value(sharers, self.everyone_else())
    }

    /// Payoff to an agent that publishes.
    ///
    /// `sharers` excludes this agent, as everywhere here — a publisher's own
    /// contribution to the commons is not a benefit it collects from itself.
    pub fn publish_payoff(&self, sharers: u32) -> Rat {
        self.commons(sharers, true)
            + self.option_value(sharers, self.everyone_else())
            + self.params.publish_margin()
    }

    /// What a seller is paid, before the commons and before what the sale costs
    /// it in exclusivity.
    pub fn price(&self, sharers: u32) -> Rat {
        let scarcity = Rat::ONE - self.sharing_fraction(sharers);
        self.params.buyer_share
            * (Rat::ONE - self.params.market_fee)
            * Rat::units(self.params.candidate_value)
            * scarcity
    }

    /// Payoff to an agent that sells.
    pub fn sell_payoff(&self, sharers: u32) -> Rat {
        self.commons(sharers, false)
            + self.option_value(sharers, self.params.buyer_share)
            + self.price(sharers)
    }

    /// Payoff to an agent that hoards.
    pub fn hoard_payoff(&self, sharers: u32) -> Rat {
        self.commons(sharers, false) + self.option_value(sharers, Rat::ZERO)
    }
}

impl Symmetric for Market<'_> {
    fn actions(&self) -> usize {
        Trade::ALL.len()
    }

    fn population(&self) -> u32 {
        self.params.agents
    }

    fn payoff(&self, own: usize, others: &[u32]) -> Rat {
        let own = match Trade::from_index(own) {
            Some(action) => action,
            // Unreachable through the solvers, which only pass indices they got
            // from `actions()`. Zero is the answer that cannot flatter anything.
            None => return Rat::ZERO,
        };
        // Publishers count as sharers: a submitted candidate is in a log
        // everybody reads, which is strictly more available than a gossiped one.
        let sharers = others.get(Trade::Gossip.index()).copied().unwrap_or(0)
            + others.get(Trade::Publish.index()).copied().unwrap_or(0);
        match own {
            Trade::Gossip => self.gossip_payoff(sharers),
            Trade::Sell => self.sell_payoff(sharers),
            Trade::Hoard => self.hoard_payoff(sharers),
            Trade::Publish => self.publish_payoff(sharers),
        }
    }

    fn action_name(&self, action: usize) -> String {
        Trade::from_index(action)
            .map(|a| a.name().to_string())
            .unwrap_or_else(|| format!("a{action}"))
    }
}

/// The smallest share of the commons a network must be able to withhold before
/// universal gossip is an equilibrium at all.
///
/// The inverse question, in the shape [`super::design`] asks all of its: given
/// everything else, what does the *mechanism* have to achieve. And it is the
/// number this whole module exists to produce, because
/// [`MarketParams::reciprocity_exclusion`] is the one parameter here that a
/// protocol could plausibly move — the others are facts about agents and
/// objectives.
///
/// Monotone, which is what makes a bisection legitimate: raising the exclusion
/// lowers what a seller and a hoarder collect and leaves a gossiper's payoff
/// untouched, so once gossip is a strict best response it stays one. Searched
/// over `k / steps` for an exact denominator rather than to a tolerance, for the
/// reason every solver in this crate is exact: a tolerance is a float wearing a
/// different hat.
///
/// `None` means no exclusion short of total makes gossip stable — which would
/// mean the commons cannot survive the market at these parameters, whatever the
/// transport does.
pub fn minimum_exclusion(params: &MarketParams, steps: u32) -> Result<Option<Rat>, ParamError> {
    params.validate()?;
    let steps = steps.max(1);
    let stable = |numerator: u32| -> Result<bool, ParamError> {
        let Some(exclusion) = Rat::rate(numerator, steps) else {
            return Ok(false);
        };
        let probe = MarketParams {
            reciprocity_exclusion: exclusion,
            ..params.clone()
        };
        let market = Market::new(&probe)?;
        let sharers = probe.agents - 1;
        let gossip = market.gossip_payoff(sharers);
        Ok(gossip > market.sell_payoff(sharers) && gossip > market.hoard_payoff(sharers))
    };
    if !stable(steps)? {
        return Ok(None);
    }
    let (mut low, mut high) = (0u32, steps);
    while low < high {
        let middle = low + (high - low) / 2;
        if stable(middle)? {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(Rat::rate(low, steps))
}

/// One operator running `identities` agents, holding its real search capacity
/// fixed.
///
/// **The answer is known before the code runs, and the code exists to price
/// it.** `agent-market.md` states that no protocol payment may be a function of
/// trade volume, because a sybil pair can trade a worthless good in a circle at
/// any price for free. What this measures is the *other* half: whether an
/// operator gains by splitting its search across many identities under the
/// mechanism as designed, where no payment keys off volume.
///
/// The capacity split is what makes the question non-trivial. An operator with
/// one candidate's worth of search does not get `k` candidates by declaring `k`
/// identities — it gets `k` identities each holding `1/k` of a candidate — so
/// the sale revenue is invariant and only the *commons* term moves. It moves
/// **against** splitting: each identity buys reciprocity separately, and
/// reciprocity is a per-agent benefit that does not divide.
///
/// So a report showing zero gain here is not the mechanism being clever. It is
/// the absence of a volume-keyed payment doing exactly what the document said it
/// would, and it is worth measuring precisely because adding one later would
/// break it silently.
pub struct SplitAgents<'a> {
    market: Market<'a>,
    /// How much of the population shares, as a count of the *other* agents.
    /// Fixed across the identity counts being compared: the question is what
    /// splitting buys against a given world, not what it buys against a world
    /// that reacts.
    sharers: u32,
}

impl<'a> SplitAgents<'a> {
    pub fn new(params: &'a MarketParams, sharers: u32) -> Result<SplitAgents<'a>, ParamError> {
        Ok(SplitAgents {
            market: Market::new(params)?,
            sharers: sharers.min(params.agents.saturating_sub(1)),
        })
    }
}

impl Sybil for SplitAgents<'_> {
    fn payoff_with(&self, identities: u32) -> Rat {
        let identities = identities.max(1);
        let params = self.market.params();
        // One operator's search capacity, divided: `j` identities each holding a
        // candidate worth `V / j`, not `j` candidates worth `V`.
        let split = MarketParams {
            candidate_value: params.candidate_value / u64::from(identities),
            ..params.clone()
        };
        let market = match Market::new(&split) {
            Ok(market) => market,
            Err(_) => return Rat::ZERO,
        };
        // The commons is counted **once**, and that is the whole modelling
        // decision here. It is a stream of candidates from other agents, not a
        // per-identity payment: an operator with fixed search capacity gets the
        // same stream however many masks it wears, and the same candidates twice
        // are worth what they were worth once. Counting it per identity would
        // report a sybil gain that is an artefact of the model rather than a
        // property of the mechanism — and would be the exact mistake
        // `agent-market.md` warns against, a payment keyed on how many you are
        // rather than on what you did.
        let per_identity =
            market.option_value(self.sharers, params.buyer_share) + market.price(self.sharers);
        market.commons(self.sharers, false) + per_identity * Rat::units(u64::from(identities))
    }
}

/// Everything the harness can say about a market, in one value.
///
/// The four questions `agent-market.md` asks, answered, plus the two numbers
/// that decide what to do about the answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketReport {
    pub params: MarketParams,
    /// Whether publishing is worth it on its own. If it is, these parameters
    /// describe something other than a sub-frontier candidate and every line
    /// below is answering the wrong question.
    pub sub_frontier: bool,
    /// Every symmetric pure equilibrium, as `(counts, strict)`.
    pub equilibria: Vec<(Vec<u32>, bool)>,
    /// Sellers needed before a gossiping population stops healing.
    pub tipping_point: Option<u32>,
    /// The cheapest deviation from universal gossip that strictly profits, as
    /// `(action, coalition size)`.
    ///
    /// Carries the *action* rather than assuming it is selling, and that is not
    /// pedantry: at small populations with a leaky commons the cheapest way out
    /// of universal gossip is **hoarding**, by a single agent. Filtering for
    /// sellers would have reported that as "never profitable", which is the
    /// opposite of what it means.
    pub breaks_commons: Option<(usize, u32)>,
    /// The cheapest deviation from universal selling — the way out of the trap,
    /// if there is one.
    pub escapes_market: Option<(usize, u32)>,
    /// Smallest withholding a transport must achieve for gossip to be stable.
    pub exclusion_needed: Option<Rat>,
    /// What an operator gains by splitting across identities. Zero is the
    /// expected answer and the one worth pinning.
    pub sybil_gain: Rat,
}

impl MarketReport {
    pub fn of(params: &MarketParams) -> Result<MarketReport, ParamError> {
        use super::game::{invasion, sybil_gain, symmetric_equilibria, Invades, Stability};
        let market = Market::new(params)?;
        let equilibria = symmetric_equilibria(&market)
            .map(|found| {
                found
                    .into_iter()
                    .map(|(counts, kind)| (counts, kind == Stability::Strict))
                    .collect()
            })
            .unwrap_or_default();
        let tipping_point = super::dynamics::tipping_point(
            &market,
            Trade::Gossip.index(),
            Trade::Sell.index(),
            MAX_SETTLE_STEPS,
        )
        .ok()
        .flatten();
        // `invasion` searches every deviation and reports the cheapest, and the
        // cheapest is not always the one being asked about -- at twenty agents
        // with a leaky commons a single *hoarder* breaks universal gossip. The
        // action is carried through rather than filtered out, because a filter
        // here would report that case as "selling is never profitable", which
        // is true and deeply misleading.
        let cheapest = |resident: usize| {
            invasion(&market, resident, params.agents, Invades::StrictlyBetter)
                .ok()
                .flatten()
                .map(|found| (found.mutant, found.mutants))
        };
        let breaks_commons = cheapest(Trade::Gossip.index());
        let escapes_market = cheapest(Trade::Sell.index());
        let split = SplitAgents::new(params, params.agents / 2)?;

        Ok(MarketReport {
            params: params.clone(),
            sub_frontier: params.is_sub_frontier(),
            equilibria,
            tipping_point,
            breaks_commons,
            escapes_market,
            exclusion_needed: minimum_exclusion(params, EXCLUSION_STEPS)?,
            sybil_gain: sybil_gain(&split, MAX_SPLIT_IDENTITIES).gain,
        })
    }

    /// Whether the market is safe to build at these parameters.
    ///
    /// Deliberately *not* a bool the caller can read as a verdict on the design.
    /// It says the commons survives contact with a market, which is a much
    /// narrower claim than "build it" — the barrier out of the selling
    /// equilibrium is what decides that, and it is reported separately because
    /// it points the other way.
    pub fn commons_survives(&self) -> bool {
        let all_gossip: Vec<u32> = {
            let mut counts = vec![0u32; Trade::ALL.len()];
            counts[Trade::Gossip.index()] = self.params.agents;
            counts
        };
        self.equilibria
            .iter()
            .any(|(counts, strict)| *strict && *counts == all_gossip)
    }
}

/// Iteration cap for the replicator settle. Generous: the populations here are
/// small and a run that has not converged in this many steps is cycling, which
/// [`super::dynamics::settle`] reports rather than spins on.
const MAX_SETTLE_STEPS: usize = 5_000;
/// Denominator the exclusion bisection searches over. A tenth of a percent is
/// finer than anybody can measure a gossip network's leakiness.
const EXCLUSION_STEPS: u32 = 1_000;
/// Identity counts the sybil search covers.
const MAX_SPLIT_IDENTITIES: u32 = 16;

impl std::fmt::Display for MarketReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = &self.params;
        writeln!(
            f,
            "{} agents, candidate worth {}, commons worth {}, {} buy",
            p.agents, p.candidate_value, p.population_value, p.buyer_share
        )?;
        if !self.sub_frontier {
            writeln!(
                f,
                "  WARNING publishing pays {} on its own, so these are not \
                 sub-frontier candidates and nothing below answers the question",
                p.publish_margin()
            )?;
        }
        writeln!(f)?;
        writeln!(f, "equilibria")?;
        for (counts, strict) in &self.equilibria {
            let played: Vec<String> = counts
                .iter()
                .enumerate()
                .filter(|(_, n)| **n > 0)
                .map(|(action, n)| {
                    let name = Trade::from_index(action)
                        .map(Trade::name)
                        .unwrap_or("?")
                        .to_string();
                    format!("{name} x{n}")
                })
                .collect();
            writeln!(
                f,
                "  {:<28} {}",
                played.join(" + "),
                if *strict { "strict" } else { "weak" }
            )?;
        }
        writeln!(f)?;
        writeln!(f, "barriers")?;
        let barrier = |found: Option<(usize, u32)>| match found {
            Some((action, size)) => format!(
                "{size} ({})",
                Trade::from_index(action).map(Trade::name).unwrap_or("?")
            ),
            None => String::from("no deviation ever profits"),
        };
        writeln!(
            f,
            "  {:<28} {}",
            "to break universal gossip",
            barrier(self.breaks_commons)
        )?;
        writeln!(
            f,
            "  {:<28} {}",
            "to leave universal selling",
            barrier(self.escapes_market)
        )?;
        writeln!(
            f,
            "  {:<28} {}",
            "tipping point",
            self.tipping_point
                .map(|n| format!("{n} sellers"))
                .unwrap_or_else(|| String::from("heals from anything"))
        )?;
        writeln!(
            f,
            "  {:<28} {}",
            "exclusion needed",
            self.exclusion_needed
                .map(|r| r.to_string())
                .unwrap_or_else(|| String::from("no amount suffices"))
        )?;
        writeln!(f, "  {:<28} {}", "sybil gain", self.sybil_gain)?;
        writeln!(f)?;
        if !self.commons_survives() {
            return writeln!(
                f,
                "verdict  universal gossip is not a strict equilibrium here, so a \
                 market at these parameters costs the search population that \
                 feeds it"
            );
        }
        match (self.breaks_commons, self.escapes_market) {
            (Some((_, into)), None) => writeln!(
                f,
                "verdict  the commons survives, and the selling equilibrium is a \
                 trap with no exit: {into} agents enter it and no coalition ever \
                 profits by leaving"
            ),
            (Some((_, into)), Some((_, out))) if out > into => writeln!(
                f,
                "verdict  the commons survives, and the market is a one-way door: \
                 {into} agents to enter the selling equilibrium, {out} to leave it"
            ),
            (Some((_, into)), Some((_, out))) => writeln!(
                f,
                "verdict  the commons survives and is the sticky equilibrium: \
                 {into} agents to break it against {out} to leave the market"
            ),
            (None, _) => writeln!(
                f,
                "verdict  the commons survives and no deviation from it ever profits"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incentive::dynamics;
    use crate::incentive::game::{
        everyone, invasion, sybil_gain, symmetric_best_responses, symmetric_equilibria,
        symmetric_stability, Invades, Stability,
    };

    fn reference() -> MarketParams {
        MarketParams::reference()
    }

    #[test]
    fn the_reference_market_validates() {
        assert_eq!(reference().validate(), Ok(()));
        assert_eq!(MarketParams::default(), MarketParams::reference());
    }

    /// The premise, checked rather than assumed.
    ///
    /// If publishing paid on its own merits the candidate would not be
    /// sub-frontier and every answer below would be about a different question.
    #[test]
    fn the_reference_candidate_is_actually_sub_frontier() {
        let params = reference();
        assert!(
            params.is_sub_frontier(),
            "publishing pays {} on its own, so this is not a sub-frontier candidate",
            params.publish_margin()
        );
    }

    /// **Question 1.** Is `Gossip` still a best response once `Sell` exists?
    ///
    /// Against a population that gossips, yes — and the reason is worth reading
    /// off the payoffs rather than taking on trust. A seller in a sharing
    /// population is selling something everybody already has, so the price term
    /// collapses to nothing and all that is left is the reciprocity it gave up.
    #[test]
    fn gossip_survives_the_arrival_of_a_market() {
        let params = reference();
        let market = Market::new(&params).expect("valid");
        let all_gossip = everyone(&market, Trade::Gossip.index());
        // `others` rather than a full profile: the question is what *one* agent
        // should do when the other n-1 all gossip, so its own choice is left
        // out of the counts.
        let mut others = vec![0u32; Trade::ALL.len()];
        others[Trade::Gossip.index()] = params.agents - 1;
        let best = symmetric_best_responses(&market, &others).expect("solvable");
        assert!(
            best.contains(&Trade::Gossip.index()),
            "gossip is not a best response to gossip: best responses were {best:?}"
        );
        assert!(
            !best.contains(&Trade::Sell.index()),
            "selling ties with gossip in a fully sharing population, which means \
             the scarcity term is not doing its job"
        );
        assert!(
            !best.contains(&Trade::Hoard.index()),
            "hoarding ties with gossip in a fully sharing population, which means \
             the option value is not decaying"
        );
        assert_eq!(
            symmetric_stability(&market, &all_gossip).expect("solvable"),
            Some(Stability::Strict),
            "universal gossip is not a strict equilibrium"
        );
    }

    /// **Question 2.** Is there a rival equilibrium where everybody sells?
    ///
    /// There is, and it is the single most important line in this file. The
    /// market is **bistable**: both universal gossip and universal selling are
    /// equilibria, and which one a network lands in is decided by where it
    /// starts rather than by which is better. That is the same shape as
    /// verification without canaries, and it means a shared client default
    /// picks the outcome.
    #[test]
    fn everybody_selling_is_also_an_equilibrium() {
        let params = reference();
        let market = Market::new(&params).expect("valid");
        let equilibria = symmetric_equilibria(&market).expect("solvable");
        let names: Vec<String> = equilibria
            .iter()
            .map(|(counts, kind)| {
                let played: Vec<String> = counts
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| **n > 0)
                    .map(|(action, n)| format!("{}x{n}", market.action_name(action)))
                    .collect();
                format!("{} [{kind:?}]", played.join(" + "))
            })
            .collect();
        let holds = |counts: &[u32]| equilibria.iter().any(|(found, _)| found == counts);
        let all_sell = everyone(&market, Trade::Sell.index());
        assert!(
            holds(&all_sell),
            "universal selling is not an equilibrium; the report's central \
             finding has changed: {names:?}"
        );
        let all_gossip = everyone(&market, Trade::Gossip.index());
        assert!(
            holds(&all_gossip),
            "universal gossip is not an equilibrium: {names:?}"
        );
    }

    /// How much slack the commons has, as a number rather than as a mood.
    ///
    /// The tipping point is the first shock the population does not heal from,
    /// and it is the honest summary that "gossip is a strict Nash equilibrium"
    /// is not: an equilibrium can be strict and still one nudge from collapsing.
    #[test]
    fn the_commons_has_a_measurable_tipping_point() {
        let params = reference();
        let market = Market::new(&params).expect("valid");
        let point =
            dynamics::tipping_point(&market, Trade::Gossip.index(), Trade::Sell.index(), 2_000)
                .expect("solvable");
        match point {
            Some(sellers) => {
                assert!(
                    sellers > 1,
                    "a single seller flips the whole population, which would make \
                     the market unbuildable rather than merely risky"
                );
                assert!(
                    sellers < params.agents,
                    "the population healed from every shock short of unanimity, \
                     which contradicts the bistability above"
                );
            }
            None => panic!(
                "no tipping point: the commons recovered from a population of \
                 pure sellers, which contradicts `everybody_selling_is_also_an_equilibrium`"
            ),
        }
    }

    /// A single defector does not take the network with it.
    ///
    /// The smallest shock a live network is guaranteed to receive, and the one
    /// that decides whether the honest equilibrium is worth anything in
    /// practice.
    #[test]
    fn one_seller_is_absorbed() {
        let params = reference();
        let market = Market::new(&params).expect("valid");
        let run =
            dynamics::from_one_defector(&market, Trade::Gossip.index(), Trade::Sell.index(), 2_000)
                .expect("solvable");
        let end = run.final_state();
        assert_eq!(
            end[Trade::Sell.index()],
            0,
            "one seller survived in a gossiping population: {end:?}"
        );
    }

    /// The exclusion parameter is load-bearing, and this is what it bears.
    ///
    /// At zero exclusion the commons is a pure public good: taking costs
    /// nothing, so selling is free money on top of it and gossip stops being a
    /// best response. The reference value is a fifth precisely so that no report
    /// rests on a gossip network policing its own membership — and this test is
    /// the reason that choice is not cosmetic.
    #[test]
    fn a_commons_nobody_can_withhold_loses_to_the_market() {
        let params = MarketParams {
            reciprocity_exclusion: Rat::ZERO,
            ..reference()
        };
        let market = Market::new(&params).expect("valid");
        let all_gossip = everyone(&market, Trade::Gossip.index());
        assert!(
            market.sell_payoff(params.agents - 1) > market.gossip_payoff(params.agents - 1),
            "with nothing withheld, selling did not beat gossiping in a fully \
             sharing population -- then the exclusion term is decoration and the \
             reference value could be anything"
        );
        assert_eq!(
            symmetric_stability(&market, &all_gossip).expect("solvable"),
            None,
            "with nothing withheld, universal gossip should not be an equilibrium \
             at all: a seller keeps the commons *and* keeps its candidate"
        );
    }

    /// **Question 4.** Splitting an identity buys nothing.
    ///
    /// Not because the mechanism resists it, but because there is nothing keyed
    /// on volume to attack — which is the property `agent-market.md` says must
    /// never be traded away. Measured so that trading it away later fails here
    /// rather than in a live network.
    #[test]
    fn splitting_an_agent_across_identities_buys_nothing() {
        let params = reference();
        let split = SplitAgents::new(&params, 0).expect("valid");
        let result = sybil_gain(&split, 16);
        assert!(
            result.gain <= Rat::ZERO,
            "an operator gained {} by presenting as {} identities",
            result.gain,
            result.best
        );
    }

    /// And the same question against a population that is already sharing,
    /// where the commons term is nonzero and splitting has something to
    /// multiply.
    #[test]
    fn splitting_buys_nothing_against_a_sharing_population_either() {
        let params = reference();
        let split = SplitAgents::new(&params, params.agents / 2).expect("valid");
        let result = sybil_gain(&split, 16);
        // Strictly positive here would be the interesting failure: reciprocity
        // is collected per identity, so a mechanism that paid for *being a
        // peer* rather than for sharing would reward the split.
        assert!(
            result.gain <= Rat::ZERO,
            "splitting bought {} against a half-sharing population at {} identities",
            result.gain,
            result.best
        );
    }

    /// **The finding that decides the scope question.** The market is a one-way
    /// door.
    ///
    /// Breaking the commons takes a coalition of 18 sellers out of 50. Getting
    /// back out of the selling equilibrium takes 34 — nearly twice as many.
    /// Both equilibria are strict, so neither drifts, but they are not
    /// symmetric: the barrier into the trap is half the barrier out of it.
    ///
    /// That asymmetry is why `agent-market.md`'s Stage 2 stays gated. A network
    /// that slides into universal selling does not slide back, and "a shared
    /// client default gets there in one step" is a sentence about a default
    /// that eighteen agents could set by choosing it.
    #[test]
    fn the_trap_is_easier_to_enter_than_to_leave() {
        let params = reference();
        let market = Market::new(&params).expect("valid");
        let into = invasion(
            &market,
            Trade::Gossip.index(),
            params.agents,
            Invades::StrictlyBetter,
        )
        .expect("solvable")
        .expect("the commons can be broken");
        let out_of = invasion(
            &market,
            Trade::Sell.index(),
            params.agents,
            Invades::StrictlyBetter,
        )
        .expect("solvable")
        .expect("the selling equilibrium can be left");
        // At fifty agents and the reference exclusion. The direction is not
        // universal -- `the_exclusion_decides_which_equilibrium_is_sticky` is
        // the same measurement at two hundred, where it reverses.
        assert_eq!(into.mutant, Trade::Sell.index());
        assert_eq!(out_of.mutant, Trade::Gossip.index());
        assert!(
            out_of.mutants > into.mutants,
            "leaving the selling equilibrium took {} agents against {} to enter \
             it -- the direction of the asymmetry has flipped, which reverses \
             the recommendation this module exists to make",
            out_of.mutants,
            into.mutants
        );
    }

    /// **Which way the door swings is set by the one knob a protocol has.**
    ///
    /// The finding that changes what to do, and it is not the one the first
    /// draft of this file reported. Vary the exclusion — how much of the gossip
    /// stream a transport can withhold from an agent that takes and does not
    /// give — and the asymmetry *flips*:
    ///
    /// | exclusion | n | to break gossip | to leave selling |
    /// |---|---|---|---|
    /// | 1/100 | 200 | 28 | 174 |
    /// | 1/20 | 200 | 88 | 114 |
    /// | 1/5 | 200 | 151 | 51 |
    ///
    /// At a leaky commons the selling equilibrium is the sticky one and gets
    /// stickier with population; at the reference exclusion the commons is the
    /// sticky one and *that* gets stickier with population. The crossover sits
    /// somewhere near a twentieth.
    ///
    /// This is why the seven-parts-in-a-thousand threshold reported by
    /// [`minimum_exclusion`] is not the whole answer and must not be quoted as
    /// one. It is what makes gossip an equilibrium *at all*. What decides which
    /// equilibrium a network falls into and stays in is a much larger number.
    #[test]
    fn the_exclusion_decides_which_equilibrium_is_sticky() {
        let barriers = |exclusion: Rat| {
            let params = MarketParams {
                agents: 200,
                reciprocity_exclusion: exclusion,
                ..reference()
            };
            let market = Market::new(&params).expect("valid");
            let cheapest = |resident: usize| {
                invasion(&market, resident, params.agents, Invades::StrictlyBetter)
                    .expect("solvable")
                    .expect("some deviation profits")
                    .mutants
            };
            (
                cheapest(Trade::Gossip.index()),
                cheapest(Trade::Sell.index()),
            )
        };
        let (leaky_in, leaky_out) = barriers(Rat::rate(1, 100).expect("a rate"));
        assert!(
            leaky_out > leaky_in,
            "with a leaky commons the market should be the sticky equilibrium, \
             but breaking gossip took {leaky_in} and leaving the market {leaky_out}"
        );
        let (tight_in, tight_out) = barriers(reference().reciprocity_exclusion);
        assert!(
            tight_in > tight_out,
            "at the reference exclusion the commons should be the sticky \
             equilibrium, but breaking gossip took {tight_in} and leaving the \
             market {tight_out}"
        );
    }

    /// A small population with a leaky commons is broken by a *hoarder*, not a
    /// seller — and the report says so rather than reporting "selling never
    /// profits".
    ///
    /// The reason [`MarketReport::breaks_commons`] carries an action. A filter
    /// for sellers would turn this case into a `None` that reads as safety.
    #[test]
    fn the_cheapest_deviation_is_not_always_the_one_being_asked_about() {
        let params = MarketParams {
            agents: 20,
            reciprocity_exclusion: Rat::rate(1, 100).expect("a rate"),
            ..reference()
        };
        let report = MarketReport::of(&params).expect("valid");
        let (action, size) = report
            .breaks_commons
            .expect("something breaks a leaky twenty-agent commons");
        assert_eq!(
            action,
            Trade::Hoard.index(),
            "expected hoarding to be the cheapest break at these parameters, got {}",
            Trade::from_index(action).map(Trade::name).unwrap_or("?")
        );
        assert_eq!(size, 1, "it took {size} hoarders, not one");
    }

    /// The number a protocol could actually act on.
    ///
    /// Everything else here is a fact about agents and objectives. How much of
    /// the commons a transport can withhold from a non-sharer is a design
    /// choice, so it is the one knob, and this is what it has to reach.
    #[test]
    fn the_commons_needs_a_measurable_amount_of_exclusion() {
        let params = reference();
        let needed = minimum_exclusion(&params, 1_000)
            .expect("valid")
            .expect("some exclusion makes gossip stable");
        assert!(
            needed > Rat::ZERO,
            "gossip is stable with nothing withheld at all, which contradicts \
             `a_commons_nobody_can_withhold_loses_to_the_market`"
        );
        assert!(
            needed <= params.reciprocity_exclusion,
            "the reference exclusion of {} is below the {needed} this market \
             needs, so every equilibrium result above is describing a network \
             that does not exist",
            params.reciprocity_exclusion
        );
    }

    /// And it is a real threshold rather than an artefact of the grid: one step
    /// below, gossip is not stable.
    #[test]
    fn one_step_below_the_threshold_the_commons_fails() {
        let params = reference();
        let steps = 1_000u32;
        let needed = minimum_exclusion(&params, steps)
            .expect("valid")
            .expect("a threshold");
        let below = Rat::rate(
            u32::try_from(needed.numerator() * i128::from(steps) / needed.denominator())
                .expect("in range")
                .saturating_sub(1),
            steps,
        )
        .expect("a rate");
        let weaker = MarketParams {
            reciprocity_exclusion: below,
            ..params
        };
        let market = Market::new(&weaker).expect("valid");
        let sharers = weaker.agents - 1;
        assert!(
            market.gossip_payoff(sharers) <= market.sell_payoff(sharers)
                || market.gossip_payoff(sharers) <= market.hoard_payoff(sharers),
            "gossip was still stable one step below the reported threshold, so \
             the bisection is not finding the smallest value"
        );
    }

    /// A market with no buyers changes nothing, which is the sanity check that
    /// the sale term is what is driving the result.
    #[test]
    fn with_no_buyers_the_market_is_inert() {
        let params = MarketParams {
            buyer_share: Rat::ZERO,
            ..reference()
        };
        let market = Market::new(&params).expect("valid");
        let all_gossip = everyone(&market, Trade::Gossip.index());
        assert_eq!(
            symmetric_stability(&market, &all_gossip).expect("solvable"),
            Some(Stability::Strict)
        );
        assert_eq!(
            market.sell_payoff(params.agents - 1),
            market.hoard_payoff(params.agents - 1),
            "with no buyer, selling should be indistinguishable from hoarding: \
             no price, and nobody to hand a rival candidate to"
        );
    }

    /// A coalition of sellers is what actually threatens the commons, and its
    /// size is the number worth quoting.
    #[test]
    fn a_coalition_of_sellers_needs_to_be_large_to_profit() {
        let params = reference();
        let market = Market::new(&params).expect("valid");
        let found = invasion(
            &market,
            Trade::Gossip.index(),
            params.agents,
            Invades::StrictlyBetter,
        )
        .expect("solvable");
        match found {
            Some(found) => {
                assert_eq!(
                    found.mutant,
                    Trade::Sell.index(),
                    "the cheapest invasion of a gossiping population is {}, not \
                     selling -- which is a different finding and should be \
                     reported as one",
                    market.action_name(found.mutant)
                );
                assert!(
                    found.mutants > 1,
                    "a lone seller profits against a gossiping population, which \
                     contradicts `one_seller_is_absorbed`"
                );
            }
            // Also a coherent finding, and a stronger one -- but it cannot
            // coexist with the bistability above, so say which it is.
            None => panic!(
                "no coalition ever profits against universal gossip, which \
                 contradicts `everybody_selling_is_also_an_equilibrium`"
            ),
        }
    }
}
