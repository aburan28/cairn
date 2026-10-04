//! cairn's node game, written down.
//!
//! Three sub-games, one per service, each in the representation that suits it.
//! All payoffs are **marginal**: the cost of running a node at all
//! ([`NodeParams::fixed_cost`]) is sunk with respect to every choice here and
//! appears only in the participation constraint. Conflating the two is the
//! standard way a mechanism comes out looking incentive-compatible because it is
//! expensive, and it hides the fact that the two constraints are fixed by
//! different knobs -- which is the most useful thing this module has to say:
//!
//! > **The size of the reward pool decides how many nodes there are. It has no
//! > effect whatever on whether they do the work.**
//!
//! The pool share cancels out of every honest-versus-lazy comparison below,
//! because a rubber-stamping node collects it too. Only the slash, the catch
//! bounty and the canary rate move that comparison. Paying operators more is
//! therefore an answer to "nobody is running nodes" and never an answer to
//! "nobody is checking anything", and a design that reaches for it in the second
//! case is buying nothing.
//!
//! One lazy strategy escapes even those three knobs. An attestor that copies the
//! verdict the admitting node already logged collects the pool share too, passes
//! every canary, and is slashed only when the admitter was wrong *and* somebody
//! else looked. Against it the slash and the canary rate cancel as well, and
//! what is left is the cost of a check -- so a pool paid for attestations on
//! claims whose verdict is readable buys copies. Only sealing the verdict until
//! attestations close moves that comparison. See [`Attest::Echo`].

use super::exact::Rat;
use super::game::{Sybil, Symmetric};
use super::{NodeParams, ParamError};

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// What an operator does with an artifact it has been sampled to check.
///
/// Five actions, not two. The two-action version -- check or do not check --
/// hides the attacks that matter: there are *three* ways to attest without
/// looking, and they need different defences.
///
/// `Echo` is appended rather than slotted in beside `Stamp` so every index a
/// report, a sweep or a pinned test already uses keeps its meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attest {
    /// Re-run the pinned verifier and report what it said.
    Verify,
    /// Accept without running anything. The cheap lie, and the dangerous one:
    /// nobody is harmed *visibly*, so nobody is motivated to catch it.
    Stamp,
    /// Reject without running anything. The other cheap lie, and the harmless
    /// one -- it takes money from a submitter, and the submitter will dispute
    /// it. See [`Verification::payoff`].
    Reject,
    /// Run a node, but attest to nothing.
    Abstain,
    /// Attest whatever the admitting node already wrote to the log, and stamp
    /// where there is nothing to copy.
    ///
    /// Not a lie at all, which is what makes it the hard one. A node appends
    /// `claim` and then `verdict` at admission, and attestations come after, so
    /// a copied verdict is right exactly as often as the admitter was -- on
    /// canaries too, because a canary is admitted like anything else. It is
    /// only an action while some paid claim's verdict is readable: see
    /// [`NodeParams::blind_sample`].
    Echo,
}

impl Attest {
    pub const ALL: [Attest; 5] = [
        Attest::Verify,
        Attest::Stamp,
        Attest::Reject,
        Attest::Abstain,
        Attest::Echo,
    ];

    /// The four actions that need no verdict to copy: the whole game when every
    /// paid claim is sealed, and the original one.
    pub const BLIND: [Attest; 4] = [
        Attest::Verify,
        Attest::Stamp,
        Attest::Reject,
        Attest::Abstain,
    ];

    pub fn index(self) -> usize {
        match self {
            Attest::Verify => 0,
            Attest::Stamp => 1,
            Attest::Reject => 2,
            Attest::Abstain => 3,
            Attest::Echo => 4,
        }
    }

    pub fn from_index(index: usize) -> Option<Attest> {
        Attest::ALL.get(index).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Attest::Verify => "verify",
            Attest::Stamp => "rubber-stamp",
            Attest::Reject => "reject-blind",
            Attest::Abstain => "abstain",
            Attest::Echo => "echo-admitter",
        }
    }
}

/// The verifier's dilemma, as `n` interchangeable operators.
///
/// # The payoffs, and where each term comes from
///
/// Write `k` for the number of nodes attesting at all, `v` for the number
/// actually verifying, `q` for the effective canary rate, `g` for the fraction
/// of canaries that are valid, `p` for the genuine fraud rate, `R` for the
/// verification pool, `S'` for the slashable stake and `beta` for the catch
/// bounty.
///
/// ```text
/// verify   R/k - cost + (q(1-g) + p) * beta/v
/// stamp    R/k        - S' * (q(1-g) + p * [v > 0])
/// reject   R/k        - S' * (q*g + (1 - q - p))
/// abstain  0
/// ```
///
/// Four things in that table are load-bearing.
///
/// **`R/k` appears identically in three rows.** A rubber-stamper is paid the
/// same as a verifier, because the mechanism cannot tell them apart -- that is
/// the whole problem, stated in algebra. So it cancels, and the pool size is
/// irrelevant to the honest-versus-lazy comparison.
///
/// **`p * [v > 0]` is the indicator that ruins everything.** A stamper is
/// punished for accepting a genuinely invalid artifact only if somebody else
/// proves it invalid, which requires somebody else to have verified. At `v = 0`
/// the term vanishes, so universal rubber-stamping is a Nash equilibrium *at any
/// slash rate*. This is not a parameter to tune, it is a fixed point to escape;
/// `everybody_stamping_is_an_equilibrium_at_any_slash` proves it holds for
/// slashes up to the entire modelling range.
///
/// **`q(1-g)` has no such indicator.** A canary's verdict is known to the
/// protocol in advance, so slashing on one is unconditional and survives `v = 0`.
/// That single difference is what moves the equilibrium, and it is why
/// [`super::design::minimum_canary_rate`] exists.
///
/// **The `reject` row needs no canary at all** beyond the valid ones. A blind
/// rejection denies a submitter their bounty, and the submitter -- unlike every
/// other party in this game -- is strictly motivated to re-run the verifier and
/// dispute it. So the `(1 - q - p)` term, wrongful rejections of real valid
/// work, is punished at essentially rate one. False rejections police
/// themselves; false acceptances do not. Every mechanism here is downstream of
/// that asymmetry.
///
/// # The fifth row: echo the admitter
///
/// Write `b` for the share of paid claims whose verdict is sealed while they
/// are attested ([`NodeParams::blind_sample`]), `e` for the share of genuinely
/// invalid submissions the admitter accepted
/// ([`NodeParams::admitter_error_rate`]) and `h` for the number echoing. On a
/// claim whose verdict is shown, and with `D = q(1-g)`:
///
/// ```text
/// verify   R/k - cost + (D + p(1-e)) * beta/(v+h) + p*e * beta/v
/// echo     R/k        + (D + p(1-e)) * beta/(v+h) - S' * p*e * [v > 0]
/// ```
///
/// and on a sealed claim the echoer has nothing to copy and plays the better of
/// stamp, reject and abstain, while every other row is the table above. Each
/// row's payoff is `(1-b)` times its shown-claim value plus `b` times its
/// sealed one.
///
/// **There is no canary term in the echo row.** The log already carries every
/// canary's correct verdict, written by the admitter, so a copy passes all of
/// them, known-good and known-bad alike. The only way an echo is wrong is that
/// the admitter was, and that is caught exactly like a stamper's fraud -- only
/// if somebody else verified, `[v > 0]` -- with the admitter's error in place
/// of fraud. So the echo row has Stamp's fatal indicator and none of the term
/// that rescues Stamp.
///
/// **The catch bounty on a correct verdict is shared with the echoers.** The
/// bounty a verifier earns for rejecting a canary or a fraud the admitter also
/// rejected is earned by a signed `reject` on that claim, and an echoer signed
/// the same `reject`. The protocol cannot pay one and not the other, for the
/// same reason it cannot pay `R/k` to a verifier and not to a stamper. Only a
/// verdict that *overturns* the admitter -- `p * e` -- distinguishes a node
/// that looked, and only that term is the verifier's alone. Giving the
/// verifier the whole bounty here would let the model pay it for catching
/// artifacts the admitter had already caught, which is paying for nothing the
/// mechanism can observe.
///
/// **So `cost` is the whole comparison.** Echo against verify, one deviator in
/// an honest network, is `cost - p*e*(beta/n + S')`: the pool cancels, the
/// canary rate cancels, and at an honest admitter (`e = 0`) the slash cancels
/// too. Universal echo is a strict Nash equilibrium at any canary rate and any
/// slash, and no amount of either changes it -- a lone verifier among echoers
/// gains `p*e*beta - cost`, which is negative whenever catching the admitter's
/// mistakes pays less than checking. `tests` pins both.
///
/// **The sealed fallback is the better of the three blind moves, not a fixed
/// one.** Stamping a sealed claim keeps the pool share and risks the canary
/// slash; abstaining forfeits both. Which wins depends on whether `R/k` covers
/// `S' * (q(1-g) + p[v>0])` -- at the reference it does, by 2,500 to 2,300 --
/// and a model that fixed either would understate the echoer whenever the
/// other was better, which is the direction a threshold must never err in.
/// For the *other* players' counts an echoer is counted as attesting on sealed
/// claims either way. That is exact when stamping is its better fallback; when
/// abstaining is, it understates what a verifier earns on the sealed claims
/// the echoers left, which makes universal echo look *more* stable than it is
/// -- the safe direction for [`super::design::minimum_blind_sample`].
///
/// **What the five-action game cannot see.** A real attestor knows which claims
/// are sealed, so it need not commit to one policy across both kinds: it can
/// verify the sealed claims and echo the rest. Payoffs are additive across
/// claims and every interaction term above is within one claim, so that
/// policy beats always verifying by `(1-b)` times the shown-claim gain, which
/// is positive at *every* `b < 1`. The game's `Echo` is the operator that never
/// runs a checker; [`Verification::selective_echo_gain`] is the one that runs
/// it only where it must. A blind share stops the first. Only declining to pay
/// for shown claims stops the second.
///
/// # What the model leaves out
///
/// Every node is sampled onto the same artifact, so "somebody else verified"
/// means `v > 0` exactly. Under real sampling, a stamper is caught only if a
/// verifier drew the same item, which *weakens* the conditional term further and
/// makes the canary argument stronger, not weaker. Modelling full redundancy is
/// therefore the conservative choice.
pub struct Verification<'a> {
    params: &'a NodeParams,
    /// Whether [`Attest::Echo`] is an action: false when every paid claim is
    /// sealed, and false for [`Verification::blind`] whatever the parameters say.
    echo: bool,
}

impl<'a> Verification<'a> {
    /// The game these parameters describe: five actions if some paid claim's
    /// verdict is readable, the original four if none is.
    ///
    /// Four rather than five-with-an-inert-echo when nothing is readable,
    /// because an echoer with nothing to copy *is* a stamper, and a duplicate
    /// action would demote every strict equilibrium containing stampers to a
    /// weak one for a reason that is a property of the encoding, not of the
    /// mechanism.
    pub fn new(params: &'a NodeParams) -> Result<Verification<'a>, ParamError> {
        params.validate()?;
        Ok(Verification {
            params,
            echo: params.echo_possible(),
        })
    }

    /// The four-action game, whatever [`NodeParams::blind_sample`] says: the
    /// game on a sealed claim, and the profiles in which nobody echoes.
    ///
    /// What [`super::design::Report`] enumerates. Five actions at a hundred
    /// nodes is `C(104, 4)` = 4.6 million profiles, past the solver's budget,
    /// so the echo deviations are checked directly against the profiles they
    /// threaten instead -- see [`super::design::EchoFinding`].
    pub fn blind(params: &'a NodeParams) -> Result<Verification<'a>, ParamError> {
        params.validate()?;
        Ok(Verification {
            params,
            echo: false,
        })
    }

    pub fn params(&self) -> &NodeParams {
        self.params
    }

    /// Whether [`Attest::Echo`] is one of this game's actions.
    pub fn echo_available(&self) -> bool {
        self.echo
    }

    /// Rate at which a rubber-stamper meets an artifact the protocol *knows* is
    /// invalid: the effective canary rate times the invalid share of canaries.
    ///
    /// The whole deterrent against [`Attest::Stamp`], in one number.
    pub fn stamp_deterrent(&self) -> Rat {
        self.params.effective_canary_rate() * (Rat::ONE - self.params.canary_valid_share)
    }

    /// Rate at which a blind rejecter meets an artifact the protocol knows is
    /// valid.
    pub fn reject_deterrent(&self) -> Rat {
        self.params.effective_canary_rate() * self.params.canary_valid_share
    }

    /// Payoff to a node that verifies, given how many others do.
    ///
    /// Split out because [`super::design`] solves against it directly, and a
    /// solver that reconstructs the payoff from counts would be a second copy of
    /// this algebra that could drift from the first.
    pub fn verify_payoff(&self, attesters: u32, verifiers: u32) -> Rat {
        let bounty_rate = self.stamp_deterrent() + self.params.fraud_rate;
        self.pool_share(attesters) - Rat::units(self.params.verify_cost)
            + bounty_rate
                * Rat::units(self.params.catch_bounty)
                    .share(verifiers)
                    .unwrap_or(Rat::ZERO)
    }

    /// Payoff to a node that verifies when `echoers` of the attesters copy the
    /// admitter instead.
    ///
    /// With no echoers this *is* [`Verification::verify_payoff`] -- returned by
    /// that function rather than re-derived, so the four-action results cannot
    /// move by so much as a denominator when echo is merely possible.
    pub fn verify_payoff_among(&self, attesters: u32, verifiers: u32, echoers: u32) -> Rat {
        if echoers == 0 {
            return self.verify_payoff(attesters, verifiers);
        }
        let params = self.params;
        let bounty = Rat::units(params.catch_bounty);
        let shown = Rat::ONE - params.blind_sample;
        let alone = bounty.share(verifiers).unwrap_or(Rat::ZERO);
        let shared = bounty
            .share(verifiers.saturating_add(echoers))
            .unwrap_or(Rat::ZERO);
        let overturned = params.fraud_rate * params.admitter_error_rate;
        // On a shown claim the bounty for agreeing with a correct admitter is
        // split with everybody who signed the same verdict; only overturning a
        // wrong one is this node's alone. On a sealed claim the echoers are
        // stamping, so the old split among verifiers stands.
        let on_shown = (self.agreed_rate() * shared) + overturned * alone;
        let on_sealed = (self.stamp_deterrent() + params.fraud_rate) * alone;
        self.pool_share(attesters) - Rat::units(params.verify_cost)
            + shown * on_shown
            + params.blind_sample * on_sealed
    }

    /// Payoff to a node that accepts without checking.
    ///
    /// `others_verifying` is deliberately the count *excluding* this node: the
    /// conditional slash depends on somebody else having looked, and passing the
    /// total here is the off-by-one that would silently make the mechanism look
    /// sound.
    pub fn stamp_payoff(&self, attesters: u32, others_verifying: u32) -> Rat {
        let caught = self.stamp_deterrent()
            + if others_verifying > 0 {
                self.params.fraud_rate
            } else {
                Rat::ZERO
            };
        self.pool_share(attesters) - self.params.slash() * caught
    }

    /// Payoff to a node that rejects without checking.
    pub fn reject_payoff(&self, attesters: u32) -> Rat {
        let genuine_valid = Rat::ONE - self.params.effective_canary_rate() - self.params.fraud_rate;
        let caught = self.reject_deterrent() + genuine_valid;
        self.pool_share(attesters) - self.params.slash() * caught
    }

    /// Payoff to a node that copies the admitter's verdict where it can read it
    /// and makes the best blind move where it cannot.
    ///
    /// `others_verifying` excludes this node, as for
    /// [`Verification::stamp_payoff`]; `echoers` *includes* it, because it is a
    /// divisor of a bounty this node shares in.
    pub fn echo_payoff(&self, attesters: u32, others_verifying: u32, echoers: u32) -> Rat {
        let shown = Rat::ONE - self.params.blind_sample;
        let on_shown = self.echo_shown_payoff(attesters, others_verifying, echoers);
        let on_sealed = self.blind_fallback(attesters, others_verifying);
        shown * on_shown + self.params.blind_sample * on_sealed
    }

    /// What an echoer earns on a claim whose verdict it can read.
    fn echo_shown_payoff(&self, attesters: u32, others_verifying: u32, echoers: u32) -> Rat {
        let params = self.params;
        let shared = Rat::units(params.catch_bounty)
            .share(others_verifying.saturating_add(echoers))
            .unwrap_or(Rat::ZERO);
        // No canary term: the admitter already wrote every canary's right
        // answer. The only wrong copy is of a wrong admitter, and that needs
        // somebody else to have looked -- Stamp's indicator, without Stamp's
        // unconditional half.
        let caught = if others_verifying > 0 {
            params.fraud_rate * params.admitter_error_rate
        } else {
            Rat::ZERO
        };
        self.pool_share(attesters) + self.agreed_rate() * shared - params.slash() * caught
    }

    /// The best an operator that does not run the checker can do on a sealed
    /// claim: stamp, reject or abstain, whichever pays.
    fn blind_fallback(&self, attesters: u32, others_verifying: u32) -> Rat {
        self.stamp_payoff(attesters, others_verifying)
            .max(self.reject_payoff(attesters))
            .max(Rat::ZERO)
    }

    /// What one operator gains over always verifying, in an otherwise honest
    /// network, by verifying the sealed claims and echoing the shown ones.
    ///
    /// The deviation the five-action game cannot express, because its actions
    /// are policies over the whole sample and this one conditions on what the
    /// attestor can see. Payoffs are additive across claims and every term is
    /// within one claim, so it is exactly `(1-b)` times what echoing a shown
    /// claim gains over verifying it -- positive at every `b < 1` whenever an
    /// echo is cheaper than a check. Zero when nothing is shown.
    pub fn selective_echo_gain(&self) -> Rat {
        let params = self.params;
        let shown = Rat::ONE - params.blind_sample;
        if shown.is_zero() {
            return Rat::ZERO;
        }
        let nodes = params.nodes;
        let others = nodes.saturating_sub(1);
        let verify_shown = self.pool_share(nodes) - Rat::units(params.verify_cost)
            + (self.stamp_deterrent() + params.fraud_rate)
                * Rat::units(params.catch_bounty)
                    .share(nodes)
                    .unwrap_or(Rat::ZERO);
        shown * (self.echo_shown_payoff(nodes, others, 1) - verify_shown)
    }

    /// Rate of invalid artifacts the admitter itself rejected: invalid canaries
    /// and the fraud it caught. The bounty on these goes to everybody who signed
    /// `reject`, looking or not.
    fn agreed_rate(&self) -> Rat {
        self.stamp_deterrent()
            + self.params.fraud_rate * (Rat::ONE - self.params.admitter_error_rate)
    }

    fn pool_share(&self, attesters: u32) -> Rat {
        self.params
            .verify_pool()
            .share(attesters)
            .unwrap_or(Rat::ZERO)
    }
}

impl Symmetric for Verification<'_> {
    fn actions(&self) -> usize {
        if self.echo {
            Attest::ALL.len()
        } else {
            Attest::BLIND.len()
        }
    }

    fn population(&self) -> u32 {
        self.params.nodes
    }

    fn payoff(&self, own: usize, others: &[u32]) -> Rat {
        let own = match Attest::from_index(own) {
            // An index past `actions()` -- Echo in the four-action game -- is
            // refused like any other out-of-range index.
            Some(action) if own < self.actions() => action,
            // Unreachable through the solvers, which only pass indices they got
            // from `actions()`. Abstention is the payoff-zero answer, which is
            // the one that cannot mislead a report.
            _ => return Rat::ZERO,
        };
        let count = |action: Attest| others.get(action.index()).copied().unwrap_or(0);
        let others_verifying = count(Attest::Verify);
        let others_echoing = count(Attest::Echo);
        let others_attesting =
            others_verifying + count(Attest::Stamp) + count(Attest::Reject) + others_echoing;
        let attesting = others_attesting + if own == Attest::Abstain { 0 } else { 1 };
        match own {
            Attest::Verify => {
                self.verify_payoff_among(attesting, others_verifying + 1, others_echoing)
            }
            Attest::Stamp => self.stamp_payoff(attesting, others_verifying),
            Attest::Reject => self.reject_payoff(attesting),
            Attest::Abstain => Rat::ZERO,
            Attest::Echo => self.echo_payoff(attesting, others_verifying, others_echoing + 1),
        }
    }

    fn action_name(&self, action: usize) -> String {
        Attest::from_index(action)
            .map(|a| a.name().to_string())
            .unwrap_or_else(|| format!("a{action}"))
    }
}

// ---------------------------------------------------------------------------
// Availability
// ---------------------------------------------------------------------------

/// Whether an operator actually keeps the log it is paid to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Serve {
    /// Store the log and answer challenges against it.
    Store,
    /// Collect the pool share and hope nobody asks.
    Freeload,
}

impl Serve {
    pub const ALL: [Serve; 2] = [Serve::Store, Serve::Freeload];

    pub fn index(self) -> usize {
        match self {
            Serve::Store => 0,
            Serve::Freeload => 1,
        }
    }

    pub fn from_index(index: usize) -> Option<Serve> {
        Serve::ALL.get(index).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Serve::Store => "store",
            Serve::Freeload => "freeload",
        }
    }
}

/// Storage, which is the easy one -- and worth reading for *why* it is easy.
///
/// ```text
/// store     R/n - storage_cost
/// freeload  (1-a) * R/n - a * S'
/// ```
///
/// A challenge asks for a Merkle path from a random leaf to a root the protocol
/// already published ([`crate::canonical::merkle_root`]). The protocol knows the
/// right answer, so a node that cannot produce the path has proved something
/// about itself, unconditionally and without anyone else's cooperation. No
/// canaries are needed here for the same reason they *are* needed for
/// verification: **the ground truth already exists.**
///
/// The failure mode is not incentive-compatibility, it is arithmetic: the
/// challenge rate `a` has to clear `storage_cost / (R/n + S')`. A node cheap to
/// challenge and expensive to audit is a node that stops storing.
pub struct Availability<'a> {
    params: &'a NodeParams,
}

impl<'a> Availability<'a> {
    pub fn new(params: &'a NodeParams) -> Result<Availability<'a>, ParamError> {
        params.validate()?;
        Ok(Availability { params })
    }

    pub fn store_payoff(&self, claimants: u32) -> Rat {
        self.pool_share(claimants) - Rat::units(self.params.storage_cost)
    }

    pub fn freeload_payoff(&self, claimants: u32) -> Rat {
        let audit = self.params.audit_rate;
        (Rat::ONE - audit) * self.pool_share(claimants) - audit * self.params.slash()
    }

    fn pool_share(&self, claimants: u32) -> Rat {
        self.params
            .availability_pool()
            .share(claimants)
            .unwrap_or(Rat::ZERO)
    }
}

impl Symmetric for Availability<'_> {
    fn actions(&self) -> usize {
        Serve::ALL.len()
    }

    fn population(&self) -> u32 {
        self.params.nodes
    }

    fn payoff(&self, own: usize, others: &[u32]) -> Rat {
        // Everyone claims a share, honestly or not, so the denominator is the
        // whole population however the counts fall.
        let claimants = others.iter().copied().sum::<u32>() + 1;
        match Serve::from_index(own) {
            Some(Serve::Store) => self.store_payoff(claimants),
            Some(Serve::Freeload) => self.freeload_payoff(claimants),
            None => Rat::ZERO,
        }
    }

    fn action_name(&self, action: usize) -> String {
        Serve::from_index(action)
            .map(|a| a.name().to_string())
            .unwrap_or_else(|| format!("a{action}"))
    }
}

// ---------------------------------------------------------------------------
// Custody
// ---------------------------------------------------------------------------

/// What a committee member does with the Shamir share it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Share {
    /// Publish at epoch end, as designed.
    Publish,
    /// Never publish. If enough members do this the submission never opens, the
    /// submitter is never paid, and a rival wins the bounty: censorship,
    /// executed by the committee that exists to prevent it.
    Withhold,
    /// Pool shares with other members before epoch end and reconstruct early.
    /// Reaching the threshold opens the envelope while the artifact is still
    /// worth front-running.
    OpenEarly,
}

impl Share {
    pub const ALL: [Share; 3] = [Share::Publish, Share::Withhold, Share::OpenEarly];

    pub fn index(self) -> usize {
        match self {
            Share::Publish => 0,
            Share::Withhold => 1,
            Share::OpenEarly => 2,
        }
    }

    pub fn from_index(index: usize) -> Option<Share> {
        Share::ALL.get(index).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Share::Publish => "publish",
            Share::Withhold => "withhold",
            Share::OpenEarly => "open-early",
        }
    }
}

/// The `t`-of-`n` committee from [`crate::sealed`], and the vice it sits in.
///
/// ```text
/// publish     [opened] * r - publish_cost
/// withhold    -S' + [not opened] * V/withholders
/// open-early  [opened] * r - publish_cost + [cartel >= t] * (V/cartel - d * S')
/// ```
///
/// Two attacks live in one game and they pull the threshold in opposite
/// directions:
///
/// - **Open early.** Any `t` members can reconstruct the key before the epoch
///   ends and front-run the submission. It takes `t` colluders, so raising `t`
///   makes it harder.
/// - **Withhold.** Any `n - t + 1` members can make reconstruction impossible,
///   denying the submitter the bounty their rival then collects. It takes
///   `n - t + 1` colluders, so raising `t` makes it *easier*.
///
/// There is therefore a window of thresholds where neither attack pays, and for
/// a committee that is too small relative to the value it guards, the window is
/// empty. [`super::design::committee_window`] computes it, and the closed form
/// it must agree with is derived there.
///
/// The third asymmetry, and the reason liveness is the cheap half of this: a
/// share that never appears **names its holder**, because the shares were
/// committed in advance. Withholding is attributable and slashable on the spot.
/// Opening early is invisible -- the cartel learns a secret, and nothing about
/// the log changes -- so it can only be punished at some detection rate `d < 1`,
/// which is why the stake condition carries a `d` and the withholding one does
/// not.
pub struct Custody<'a> {
    params: &'a NodeParams,
}

impl<'a> Custody<'a> {
    pub fn new(params: &'a NodeParams) -> Result<Custody<'a>, ParamError> {
        params.validate()?;
        Ok(Custody { params })
    }

    /// Fee paid to one member for publishing its share on time.
    pub fn publication_fee(&self) -> Rat {
        self.params
            .custody_pool()
            .share(self.params.committee)
            .unwrap_or(Rat::ZERO)
    }

    /// Payoff to a member that publishes, given whether the envelope opened.
    pub fn publish_payoff(&self, opened: bool) -> Rat {
        let earned = if opened {
            self.publication_fee()
        } else {
            Rat::ZERO
        };
        earned - Rat::units(self.params.publish_cost)
    }

    /// Payoff to a member that withholds its share.
    pub fn withhold_payoff(&self, opened: bool, withholders: u32) -> Rat {
        let stolen = if opened {
            Rat::ZERO
        } else {
            Rat::units(self.params.sealed_value)
                .share(withholders)
                .unwrap_or(Rat::ZERO)
        };
        stolen - self.params.slash()
    }

    /// Payoff to a member of an early-opening cartel of size `cartel`.
    pub fn open_early_payoff(&self, opened: bool, cartel: u32) -> Rat {
        let gain = if cartel >= self.params.threshold {
            Rat::units(self.params.sealed_value)
                .share(cartel)
                .unwrap_or(Rat::ZERO)
                - self.params.detection_rate * self.params.slash()
        } else {
            // Below the threshold a cartel member behaves exactly like an
            // honest one and learns nothing. Joining is *free*, which is the
            // uncomfortable part: a cartel can assemble by drift and only
            // becomes profitable, discontinuously, at the threshold.
            Rat::ZERO
        };
        self.publish_payoff(opened) + gain
    }
}

impl Symmetric for Custody<'_> {
    fn actions(&self) -> usize {
        Share::ALL.len()
    }

    fn population(&self) -> u32 {
        self.params.committee
    }

    fn payoff(&self, own: usize, others: &[u32]) -> Rat {
        let own = match Share::from_index(own) {
            Some(action) => action,
            None => return Rat::ZERO,
        };
        let others_publishing = others.get(Share::Publish.index()).copied().unwrap_or(0);
        let others_withholding = others.get(Share::Withhold.index()).copied().unwrap_or(0);
        let others_early = others.get(Share::OpenEarly.index()).copied().unwrap_or(0);
        // An early-opening member still publishes at epoch end: it has already
        // extracted its value and has no reason to forfeit stake as well.
        let publishing =
            others_publishing + others_early + if own == Share::Withhold { 0 } else { 1 };
        let opened = publishing >= self.params.threshold;
        match own {
            Share::Publish => self.publish_payoff(opened),
            Share::Withhold => self.withhold_payoff(opened, others_withholding + 1),
            Share::OpenEarly => self.open_early_payoff(opened, others_early + 1),
        }
    }

    fn action_name(&self, action: usize) -> String {
        Share::from_index(action)
            .map(|a| a.name().to_string())
            .unwrap_or_else(|| format!("a{action}"))
    }
}

// ---------------------------------------------------------------------------
// Sybil
// ---------------------------------------------------------------------------

/// How a service pool is divided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardRule {
    /// Evenly, one share per node.
    PerNode,
    /// In proportion to stake.
    PerStake,
}

impl RewardRule {
    pub fn name(self) -> &'static str {
        match self {
            RewardRule::PerNode => "even per-node split",
            RewardRule::PerStake => "stake-weighted split",
        }
    }
}

/// One operator, fixed real resources, choosing how many identities to wear.
///
/// Sybil resistance is not a property of a strategy profile, so it does not
/// belong in the games above: it is a property of the map from resources to
/// payoff. The operator's stake and its verification budget are held constant
/// and only the identity count varies, which is exactly the choice a real
/// operator faces and exactly the one an even split gets wrong.
pub struct SplitIdentities<'a> {
    params: &'a NodeParams,
    rule: RewardRule,
    pool: Rat,
}

impl<'a> SplitIdentities<'a> {
    /// Against the verification pool, under `rule` -- which may deliberately
    /// differ from [`NodeParams::reward_rule`], so a report can price the rule
    /// it did *not* choose.
    pub fn verification(
        params: &'a NodeParams,
        rule: RewardRule,
    ) -> Result<SplitIdentities<'a>, ParamError> {
        params.validate()?;
        Ok(SplitIdentities {
            params,
            rule,
            pool: params.verify_pool(),
        })
    }
}

impl Sybil for SplitIdentities<'_> {
    fn payoff_with(&self, identities: u32) -> Rat {
        let identities = identities.max(1);
        // The rest of the network is unchanged; this operator replaces its one
        // identity with `identities` of them, each holding `stake/identities`.
        let others = self.params.nodes.saturating_sub(1);
        let earned = match self.rule {
            RewardRule::PerNode => {
                let total = others.saturating_add(identities);
                self.pool.share(total).unwrap_or(Rat::ZERO) * Rat::int(i64::from(identities))
            }
            // Stake is conserved by splitting, so a stake-weighted share is
            // exactly invariant. That invariance is the whole property.
            RewardRule::PerStake => {
                let mine = Rat::units(self.params.stake);
                let network = mine * Rat::int(i64::from(self.params.nodes.max(1)));
                self.pool * mine / network
            }
        };
        // Each identity is sampled separately, so each one pays to check.
        earned - Rat::units(self.params.verify_cost) * Rat::int(i64::from(identities))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incentive::game::{
        everyone, invasion, sybil_gain, symmetric_equilibria, symmetric_stability, Invades,
        Stability,
    };
    use crate::incentive::MAX_UNITS;

    fn reference() -> NodeParams {
        NodeParams::reference()
    }

    fn counts(game: &dyn Symmetric, pairs: &[(usize, u32)]) -> Vec<u32> {
        let mut counts = vec![0u32; game.actions()];
        for (action, count) in pairs {
            counts[*action] = *count;
        }
        counts
    }

    // -- verification -------------------------------------------------------

    #[test]
    fn the_pool_share_cancels_out_of_the_honest_versus_lazy_comparison() {
        // The claim in the module docs, made mechanical: multiply the pool by
        // forty and the gap between verifying and stamping does not move.
        let small = reference();
        let large = NodeParams {
            settled_value: small.settled_value * 40,
            ..small.clone()
        };
        let gap = |params: &NodeParams| {
            let game = Verification::new(params).expect("validated");
            game.verify_payoff(params.nodes, params.nodes)
                - game.stamp_payoff(params.nodes, params.nodes - 1)
        };
        assert_eq!(gap(&small), gap(&large));
        assert!(
            large.verify_pool() > small.verify_pool(),
            "the pools really do differ"
        );
    }

    #[test]
    fn everybody_stamping_is_an_equilibrium_at_any_slash_when_there_are_no_canaries() {
        // The structural result. Remove canaries and the punishment for
        // rubber-stamping is conditional on somebody else looking; if nobody
        // looks, nobody is punished, and no amount of stake changes that.
        for stake in [1_000u64, 1_000_000, 1_000_000_000, MAX_UNITS] {
            let params = NodeParams {
                canary_rate: Rat::ZERO,
                stake,
                slash_rate: Rat::ONE,
                ..reference()
            };
            let game = Verification::new(&params).expect("validated");
            let all_stamp = everyone(&game, Attest::Stamp.index());
            assert_eq!(
                symmetric_stability(&game, &all_stamp).expect("valid counts"),
                Some(Stability::Strict),
                "universal rubber-stamping survives a slash of {stake}"
            );
        }
    }

    #[test]
    fn canaries_are_what_break_the_rubber_stamp_equilibrium() {
        // Same network, same slash, canaries switched on: the equilibrium goes.
        let params = NodeParams {
            canary_rate: Rat::rate(1, 100).expect("a valid rate"),
            canary_leak: Rat::ZERO,
            ..reference()
        };
        let game = Verification::new(&params).expect("validated");
        let all_stamp = everyone(&game, Attest::Stamp.index());
        assert_eq!(
            symmetric_stability(&game, &all_stamp).expect("valid counts"),
            None
        );
        let all_verify = everyone(&game, Attest::Verify.index());
        assert_eq!(
            symmetric_stability(&game, &all_verify).expect("valid counts"),
            Some(Stability::Strict)
        );
    }

    #[test]
    fn the_reference_network_verifies_and_repels_every_size_of_defection() {
        let params = reference();
        let game = Verification::new(&params).expect("validated");
        let all_verify = everyone(&game, Attest::Verify.index());
        assert_eq!(
            symmetric_stability(&game, &all_verify).expect("valid counts"),
            Some(Stability::Strict)
        );
        assert_eq!(
            invasion(
                &game,
                Attest::Verify.index(),
                params.nodes,
                Invades::WeaklyBetter
            )
            .expect("valid resident"),
            None,
            "no coalition of any size gains by defecting together"
        );
    }

    #[test]
    fn blind_rejection_is_dominated_because_the_submitter_disputes_it() {
        // No canary is needed to punish this one: the party who loses money is
        // motivated to re-run the verifier, which nobody is for an acceptance.
        let params = reference();
        let game = Verification::new(&params).expect("validated");
        for attesters in [1u32, 2, 50, params.nodes] {
            assert!(
                game.reject_payoff(attesters) < game.verify_payoff(attesters, attesters),
                "blind rejection beat verification at {attesters} attesters"
            );
            assert!(
                game.reject_payoff(attesters) < game.stamp_payoff(attesters, attesters - 1),
                "blind rejection beat rubber-stamping at {attesters} attesters"
            );
        }
    }

    #[test]
    fn a_fully_leaky_canary_leaves_the_bad_equilibrium_standing() {
        // The engineering assumption stated as a payoff: canaries a node can
        // recognise are worth precisely nothing.
        let params = NodeParams {
            canary_leak: Rat::ONE,
            ..reference()
        };
        let game = Verification::new(&params).expect("validated");
        assert_eq!(game.stamp_deterrent(), Rat::ZERO);
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Attest::Stamp.index()))
                .expect("valid counts"),
            Some(Stability::Strict)
        );
    }

    #[test]
    fn a_more_honest_network_is_a_less_verified_one_without_canaries() {
        // The perverse comparative static, and the reason bounty-only schemes
        // fail exactly where they look least necessary: with no canaries the
        // only reason to check is the chance of catching real fraud, so the
        // rarer fraud is, the weaker the incentive to look for it.
        let honest = NodeParams {
            canary_rate: Rat::ZERO,
            fraud_rate: Rat::rate(1, 100_000).expect("a valid rate"),
            ..reference()
        };
        let crooked = NodeParams {
            canary_rate: Rat::ZERO,
            fraud_rate: Rat::rate(1, 10).expect("a valid rate"),
            ..reference()
        };
        let incentive = |params: &NodeParams| {
            let game = Verification::new(params).expect("validated");
            // What a lone verifier gains over stamping when nobody else checks.
            game.verify_payoff(params.nodes, 1) - game.stamp_payoff(params.nodes, 0)
        };
        assert!(incentive(&honest) < incentive(&crooked));
        assert!(
            incentive(&honest).is_negative(),
            "in an honest network nobody bothers to check"
        );
    }

    #[test]
    fn abstention_beats_attesting_when_the_pool_cannot_cover_the_cost() {
        let params = NodeParams {
            settled_value: 0,
            ..reference()
        };
        let game = Verification::new(&params).expect("validated");
        let equilibria = symmetric_equilibria(&game).expect("small enough");
        assert!(
            equilibria
                .iter()
                .all(|(counts, _)| counts[Attest::Verify.index()] < params.nodes),
            "an unfunded network does not verify"
        );
    }

    // -- echo -----------------------------------------------------------------

    /// The protocol as built: the admitter's verdict is in the log before
    /// anybody attests, on every claim.
    fn shown() -> NodeParams {
        NodeParams {
            blind_sample: Rat::ZERO,
            ..reference()
        }
    }

    /// Echo minus verify for one operator in an otherwise honest network.
    fn lone_echo_gain(game: &Verification) -> Rat {
        let mut others = everyone(game, Attest::Verify.index());
        others[Attest::Verify.index()] -= 1;
        game.payoff(Attest::Echo.index(), &others) - game.payoff(Attest::Verify.index(), &others)
    }

    #[test]
    fn with_verdicts_shown_echoing_beats_verifying_by_exactly_the_cost_of_a_check() {
        // An honest admitter is never wrong, so a copy is never caught, and
        // everything else -- the pool share, the bounty on the canaries the
        // admitter already rejected -- is paid to a copy and a check alike. What
        // is left is the check.
        let params = shown();
        let game = Verification::new(&params).expect("validated");
        assert_eq!(game.actions(), Attest::ALL.len());
        assert_eq!(lone_echo_gain(&game), Rat::units(params.verify_cost));
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Attest::Verify.index()))
                .expect("valid counts"),
            None,
            "the reference network's honest profile does not survive a readable verdict"
        );
        let found = invasion(
            &game,
            Attest::Verify.index(),
            params.nodes,
            Invades::StrictlyBetter,
        )
        .expect("valid resident")
        .expect("somebody defects");
        assert_eq!(found.mutant, Attest::Echo.index());
        assert_eq!(found.mutants, 1, "one copier is enough");
    }

    #[test]
    fn everybody_echoing_is_an_equilibrium_at_any_canary_rate_and_any_slash() {
        // The echo row has Stamp's conditional slash and none of the canary
        // term that rescues Stamp, so the knobs that close the rubber-stamp trap
        // do not touch this one. Canary rates run to the top of what the sample
        // admits (canary plus fraud at most one), stakes to the modelling bound,
        // at a 100% slash.
        for canary_rate in [
            Rat::ZERO,
            Rat::rate(1, 100).expect("a valid rate"),
            Rat::rate(1, 2).expect("a valid rate"),
            Rat::rate(999, 1_000).expect("a valid rate"),
        ] {
            for stake in [1_000u64, 1_000_000, 1_000_000_000, MAX_UNITS] {
                let params = NodeParams {
                    canary_rate,
                    stake,
                    slash_rate: Rat::ONE,
                    ..shown()
                };
                let game = Verification::new(&params).expect("validated");
                assert_eq!(
                    symmetric_stability(&game, &everyone(&game, Attest::Echo.index()))
                        .expect("valid counts"),
                    Some(Stability::Strict),
                    "universal echo survives canary rate {canary_rate} and a slash of {stake}"
                );
            }
        }
        // The contrast: the same canary rate that ends the rubber-stamp trap.
        let params = shown();
        let game = Verification::new(&params).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Attest::Stamp.index()))
                .expect("valid counts"),
            None
        );
    }

    #[test]
    fn a_sloppy_admitter_deters_echo_only_while_somebody_else_checks() {
        // An admitter that waves through every fraud makes a copy wrong at the
        // fraud rate, and with others checking that costs `p * (beta/n + S')`,
        // which here is more than the check saves. But the penalty needs a
        // verifier, so in a network of copiers it never fires: a lone verifier
        // earns only `p * beta` for overturning the admitter, less than it pays.
        let params = NodeParams {
            admitter_error_rate: Rat::ONE,
            ..shown()
        };
        let game = Verification::new(&params).expect("validated");
        let shared = Rat::units(params.catch_bounty)
            .share(params.nodes)
            .expect("nodes");
        assert_eq!(
            lone_echo_gain(&game),
            Rat::units(params.verify_cost) - params.fraud_rate * (shared + params.slash())
        );
        assert!(lone_echo_gain(&game).is_negative());
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Attest::Echo.index()))
                .expect("valid counts"),
            Some(Stability::Strict),
            "the trap stands however wrong the admitter is"
        );
    }

    #[test]
    fn the_pool_cancels_against_echo_too_and_what_is_left_is_the_cost_of_a_check() {
        // The module's claim, extended to the fifth row. Multiply the pool by
        // forty: echo against stamp does not move, as before. Echo against
        // verify does not move either -- and what it equals is the cost of one
        // check, with no canary term and no slash in it. So the two knobs that
        // decide honest-versus-lazy for a stamper decide nothing for a copier.
        let small = shown();
        let large = NodeParams {
            settled_value: small.settled_value * 40,
            ..small.clone()
        };
        let gaps = |params: &NodeParams| {
            let game = Verification::new(params).expect("validated");
            let mut others = everyone(&game, Attest::Verify.index());
            others[Attest::Verify.index()] -= 1;
            let echo = game.payoff(Attest::Echo.index(), &others);
            (
                echo - game.payoff(Attest::Stamp.index(), &others),
                echo - game.payoff(Attest::Verify.index(), &others),
            )
        };
        assert!(large.verify_pool() > small.verify_pool());
        assert_eq!(gaps(&small), gaps(&large));
        let cost = Rat::units(small.verify_cost);
        assert_eq!(gaps(&small).1, cost);
        // And neither of the stamper's knobs reaches it.
        for knobbed in [
            NodeParams {
                canary_rate: Rat::rate(1, 5).expect("a valid rate"),
                ..small.clone()
            },
            NodeParams {
                stake: MAX_UNITS,
                slash_rate: Rat::ONE,
                ..small.clone()
            },
        ] {
            assert_eq!(gaps(&knobbed).1, cost);
        }
    }

    #[test]
    fn with_every_paid_claim_sealed_the_four_action_game_is_unchanged() {
        // Echo is not an action when there is nothing to copy, and nothing it
        // added leaks into the other four. Two checks, because they fail
        // differently: the reference game must still *be* the four-action game,
        // and in the five-action game every profile with nobody echoing must pay
        // the four old actions exactly what the four-action game pays them.
        let params = reference();
        assert_eq!(params.blind_sample, Rat::ONE);
        let game = Verification::new(&params).expect("validated");
        assert!(!game.echo_available());
        assert_eq!(game.actions(), Attest::BLIND.len());
        assert_eq!(game.payoff(Attest::Echo.index(), &[99, 0, 0, 0]), Rat::ZERO);

        for base in [
            reference(),
            NodeParams {
                canary_rate: Rat::ZERO,
                ..reference()
            },
            NodeParams {
                stake: 1_000,
                ..reference()
            },
            NodeParams {
                settled_value: 0,
                ..reference()
            },
        ] {
            let small = NodeParams {
                nodes: 12,
                committee: 7,
                threshold: 4,
                ..base
            };
            let sealed = Verification::new(&small).expect("validated");
            for blind_sample in [Rat::ZERO, Rat::rate(1, 2).expect("a valid rate")] {
                let open = NodeParams {
                    blind_sample,
                    ..small.clone()
                };
                let five = Verification::new(&open).expect("validated");
                let four = Verification::blind(&open).expect("validated");
                assert_eq!(five.actions(), 5);
                assert_eq!(
                    symmetric_equilibria(&four).expect("small"),
                    symmetric_equilibria(&sealed).expect("small"),
                    "the blind share moved a four-action result"
                );
                for verifiers in 0..small.nodes {
                    for stampers in 0..small.nodes - verifiers {
                        let rest = small.nodes - 1 - verifiers - stampers;
                        let old = [verifiers, stampers, rest, 0];
                        let new = [verifiers, stampers, rest, 0, 0];
                        for action in Attest::BLIND {
                            assert_eq!(
                                five.payoff(action.index(), &new),
                                sealed.payoff(action.index(), &old),
                                "{} moved with nobody echoing",
                                action.name()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn an_attestor_that_can_see_which_claims_are_sealed_copies_the_rest_at_any_share() {
        // The limit of the five-action game, pinned so nobody reads more into a
        // blind share than it buys. Its `Echo` never checks; a real attestor
        // knows which claims are sealed and can check exactly those. That beats
        // always checking by the shown share times the cost of a check, at every
        // share below one -- including shares where the five-action game's
        // honest profile is strict, because none of its actions is this one.
        let cost = Rat::units(reference().verify_cost);
        for (num, den) in [(0u32, 1u32), (1, 10), (1, 2), (999, 1_000)] {
            let blind_sample = Rat::rate(num, den).expect("a valid rate");
            let params = NodeParams {
                blind_sample,
                ..reference()
            };
            let game = Verification::new(&params).expect("validated");
            assert_eq!(
                game.selective_echo_gain(),
                (Rat::ONE - blind_sample) * cost,
                "at blind share {blind_sample}"
            );
        }
        let mostly_sealed = NodeParams {
            blind_sample: Rat::rate(999, 1_000).expect("a valid rate"),
            ..reference()
        };
        let game = Verification::new(&mostly_sealed).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Attest::Verify.index()))
                .expect("valid counts"),
            Some(Stability::Strict),
            "the game says honest"
        );
        assert!(game.selective_echo_gain().is_positive(), "and it is wrong");
        let all_sealed = reference();
        let sealed = Verification::new(&all_sealed).expect("validated");
        assert_eq!(sealed.selective_echo_gain(), Rat::ZERO);
    }

    // -- availability -------------------------------------------------------

    #[test]
    fn storing_is_strictly_dominant_when_the_audit_rate_clears_the_cost() {
        let params = reference();
        let game = Availability::new(&params).expect("validated");
        let all_store = everyone(&game, Serve::Store.index());
        assert_eq!(
            symmetric_stability(&game, &all_store).expect("valid counts"),
            Some(Stability::Strict)
        );
        // And unlike verification, it needs no canary and no coordination:
        // the payoff does not depend on what anyone else does.
        assert_eq!(
            invasion(
                &game,
                Serve::Store.index(),
                params.nodes,
                Invades::WeaklyBetter
            )
            .expect("valid resident"),
            None
        );
    }

    #[test]
    fn nobody_stores_when_challenges_are_too_rare() {
        let params = NodeParams {
            audit_rate: Rat::ZERO,
            ..reference()
        };
        let game = Availability::new(&params).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Serve::Freeload.index()))
                .expect("valid counts"),
            Some(Stability::Strict)
        );
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Serve::Store.index()))
                .expect("valid counts"),
            None
        );
    }

    // -- custody ------------------------------------------------------------

    #[test]
    fn the_custody_equilibrium_is_weak_and_cannot_be_made_strict() {
        // Not a slack parameter -- a fact about threshold cryptography. A
        // committee member that has agreed to open early but whose cartel has
        // not reached `t` does exactly what an honest member does and is paid
        // exactly what an honest member is paid. There is no observable to
        // punish, so the honest profile is a *weak* equilibrium at every
        // parameter set, and no amount of stake changes it.
        //
        // What the stake buys is the next rung: no group that reaches the
        // threshold profits, which is what `defection` checks.
        let params = reference();
        let game = Custody::new(&params).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Share::Publish.index()))
                .expect("valid counts"),
            Some(Stability::Weak)
        );
        assert_eq!(
            invasion(
                &game,
                Share::Publish.index(),
                params.committee,
                Invades::StrictlyBetter
            )
            .expect("valid resident"),
            None,
            "the reference bond makes both committee attacks unprofitable"
        );
        // Raising the bond tenfold does not promote the equilibrium to strict.
        let fortified = NodeParams {
            stake: params.stake * 10,
            ..params
        };
        let game = Custody::new(&fortified).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Share::Publish.index()))
                .expect("valid counts"),
            Some(Stability::Weak)
        );
    }

    #[test]
    fn a_cartel_of_exactly_the_threshold_is_what_opens_early() {
        // Stake deliberately too small to deter it, so the solver has something
        // to find: V = 2_000_000 against t*d*S' = 11 * 1/2 * 10_000 = 55_000.
        let params = NodeParams {
            stake: 100_000,
            ..reference()
        };
        let game = Custody::new(&params).expect("validated");
        let found = invasion(
            &game,
            Share::Publish.index(),
            params.committee,
            Invades::StrictlyBetter,
        )
        .expect("valid resident")
        .expect("an under-staked committee is corruptible");
        assert_eq!(found.mutant, Share::OpenEarly.index());
        assert_eq!(
            found.mutants, params.threshold,
            "the cartel is exactly threshold-sized: no smaller one gains, and a larger one splits the same loot further"
        );
    }

    #[test]
    fn joining_a_sub_threshold_cartel_is_free_which_is_the_uncomfortable_part() {
        // Below `t`, an early-opening member is indistinguishable from an
        // honest one and earns exactly the same. There is no penalty for
        // standing ready to collude, so the cartel can assemble at zero cost
        // and only becomes profitable, discontinuously, at the threshold.
        let params = NodeParams {
            stake: 100_000,
            ..reference()
        };
        let game = Custody::new(&params).expect("validated");
        let drift = invasion(
            &game,
            Share::Publish.index(),
            params.threshold - 1,
            Invades::WeaklyBetter,
        )
        .expect("valid resident")
        .expect("drift into a cartel is free");
        assert_eq!(drift.mutants, 1);
        assert_eq!(drift.gain, Rat::ZERO);
    }

    #[test]
    fn enough_stake_makes_early_opening_unprofitable_at_every_cartel_size() {
        // t * d * S' > V: 11 * 1/2 * (40_000_000 / 10) = 22_000_000 > 2_000_000.
        let params = NodeParams {
            stake: 40_000_000,
            ..reference()
        };
        let game = Custody::new(&params).expect("validated");
        assert_eq!(
            invasion(
                &game,
                Share::Publish.index(),
                params.committee,
                Invades::StrictlyBetter
            )
            .expect("valid resident"),
            None
        );
    }

    #[test]
    fn withholding_censors_the_submission_when_enough_members_do_it() {
        let params = NodeParams {
            stake: 10_000,
            ..reference()
        };
        let game = Custody::new(&params).expect("validated");
        // n - t + 1 = 21 - 11 + 1 = 11 withholders make reconstruction
        // impossible, and the bounty their rival collects is worth more than
        // the stake they forfeit.
        let blocking = params.committee - params.threshold + 1;
        let others = counts(
            &game,
            &[
                (Share::Publish.index(), params.committee - blocking),
                (Share::Withhold.index(), blocking - 1),
            ],
        );
        assert!(game.payoff(Share::Withhold.index(), &others).is_positive());
        let one_fewer = counts(
            &game,
            &[
                (Share::Publish.index(), params.committee - blocking + 1),
                (Share::Withhold.index(), blocking - 2),
            ],
        );
        assert!(
            game.payoff(Share::Withhold.index(), &one_fewer)
                .is_negative(),
            "a cartel one short of blocking just loses its stake"
        );
    }

    #[test]
    fn raising_the_threshold_trades_one_attack_for_the_other() {
        // The vice, demonstrated: at every stake there is a threshold at which
        // early opening stops paying and a (lower) one above which withholding
        // starts.
        let params = NodeParams {
            stake: 300_000,
            ..reference()
        };
        let corruptible = |threshold: u32| {
            let params = NodeParams {
                threshold,
                ..params.clone()
            };
            let game = Custody::new(&params).expect("validated");
            invasion(
                &game,
                Share::Publish.index(),
                params.committee,
                Invades::StrictlyBetter,
            )
            .expect("valid resident")
            .map(|found| found.mutant)
        };
        assert_eq!(
            corruptible(4),
            Some(Share::OpenEarly.index()),
            "a low threshold is cheap to reach"
        );
        assert_eq!(
            corruptible(20),
            Some(Share::Withhold.index()),
            "a high threshold is cheap to block"
        );
    }

    // -- sybil --------------------------------------------------------------

    #[test]
    fn an_even_pool_split_pays_for_identities_rather_than_for_work() {
        let params = reference();
        let model = SplitIdentities::verification(&params, RewardRule::PerNode).expect("validated");
        let result = sybil_gain(&model, 50);
        assert!(result.best > 1, "splitting pays");
        assert!(result.gain.is_positive());
    }

    #[test]
    fn a_stake_weighted_split_is_exactly_sybil_neutral() {
        let params = reference();
        let model =
            SplitIdentities::verification(&params, RewardRule::PerStake).expect("validated");
        let result = sybil_gain(&model, 50);
        assert_eq!(result.best, 1);
        assert_eq!(result.gain, Rat::ZERO);
        // Neutral on the revenue side and strictly worse on the cost side: each
        // identity is sampled and each sample must be checked.
        assert!(model.payoff_with(2) < model.payoff_with(1));
    }
}
