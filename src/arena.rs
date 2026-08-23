//! Strategies played for money against the real rules engine.
//!
//! # Why this exists, and what it is not
//!
//! Two things in this repository already look like this one and are not:
//!
//! | module | what it varies | what it holds fixed | what it proves |
//! |---|---|---|---|
//! | [`crate::incentive`] | strategies, exactly | **the rules are a model** | honest play is an equilibrium *of that model* |
//! | `tests/simulation.rs` | network timing, seeded | strategies are honest | nodes converge on what settled |
//! | this module | strategies, **against the real `Node`** | timing is simple | whether an attack *pays*, in units the log actually settled |
//!
//! `docs/proving-it.md` names the gap between the first row and the third as
//! the largest hole in the whole argument: *"`src/incentive/` is not a code
//! path"*, so a passing report reads *if the network implemented this
//! mechanism, honest play would be an equilibrium of a model of it.* Both
//! conditionals are load-bearing. This module removes the second one for the
//! attacks it covers — every action below goes through `post_objective`,
//! `commit`, `reveal`, `post_challenge`, `post_undertaking`,
//! `post_availability`, `settle_due`, and the payoff is read out of
//! [`Node::balances`] afterwards.
//!
//! # The discipline that makes it evidence
//!
//! **The arena never grants a strategy anything the rules would refuse.** An
//! attack that the admission rules reject is *reported as rejected* rather
//! than forced through, because "the mechanism refused it" is the strongest
//! possible result and quietly bypassing the refusal to make the simulation
//! interesting would invert the finding.
//!
//! Two attacks genuinely cannot be expressed through admission — a
//! rubber-stamper writes a verdict the verifier disagrees with, and that is
//! not something `reveal` will do. Those go in at the ledger, exactly as a
//! node lying to its own log would, and what catches them is
//! [`crate::canary`] and the audit rather than anything here.
//!
//! # Every attack is run twice
//!
//! With the defence and without it. A single number saying "the attacker
//! earned 4,000" means nothing; the pair *"4,000 with canaries deployed
//! against 34,000 without"* is a measurement of the defence. [`Trial`] carries
//! both, and [`Trial::verdict`] is the difference.
//!
//! # The one number that cannot come from the log
//!
//! **Verification cost.** What it costs an operator to run a checker is an
//! off-log fact about their machine, so it is modelled — [`Costs`] — and it is
//! the only modelled quantity here. Everything else is read back out of
//! records. Where a result depends on it, the result says so.
//!
//! # Scope, stated rather than implied
//!
//! One node, many identities. That is Stage 0's actual trust model, and it is
//! where every money rule in this crate lives. Attacks that need *two
//! disagreeing nodes* — equivocation, a partitioned settlement order — are not
//! here and are not claimed; `tests/simulation.rs` is the harness for those.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::canonical::Value;
use crate::crypto::identity::Identity;
use crate::ledger::Ledger;
use crate::node::{Node, RuleViolation};
use crate::records::{Claim, Commitment, Issuance, Objective, Undertaking};
use crate::verifiers::VerifierRegistry;

/// What running a node costs, per unit of service, in ledger units.
///
/// The only modelled numbers in this module. They are an operator's real
/// expenses, which no log records, and the defaults are the reference network's
/// from `docs/node-incentives.md` so a result here can be read beside a result
/// from [`crate::incentive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Costs {
    /// Running one pinned verifier once.
    pub verify: u128,
    /// Answering one availability sample: reading the log and building a path.
    pub answer: u128,
    /// Minting one canary — a handful of verifier runs, paid once by whoever
    /// polices the network.
    pub mint_canary: u128,
    /// Producing an artifact worth submitting.
    pub solve: u128,
}

impl Default for Costs {
    fn default() -> Costs {
        Costs {
            verify: 100,
            answer: 1,
            mint_canary: 700,
            solve: 1_000,
        }
    }
}

/// What one player did and what it left with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payoff {
    pub player: String,
    /// Units the log says this identity holds at the end.
    pub closed: u128,
    /// Units it held at the start.
    pub opened: u128,
    /// Modelled off-log expenses. See [`Costs`].
    pub spent: u128,
    /// Actions the rules refused. A refusal is a result, not a bug.
    pub refused: Vec<String>,
    /// Whether an audit or a canary docket named this player.
    pub caught: Vec<String>,
    /// Actions the rules admitted. Zero alongside a non-empty `refused` is the
    /// difference between an attack that was priced and one that was declined.
    pub acted: usize,
}

impl Payoff {
    /// What the player is up, after modelled costs. Signed: an attack that
    /// loses money is the point.
    pub fn net(&self) -> i128 {
        let gained = self.closed as i128 - self.opened as i128;
        gained - self.spent as i128
    }
}

impl fmt::Display for Payoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<22} net {:>10}   held {:>10} -> {:>10}   spent {:>8}",
            self.player,
            self.net(),
            self.opened,
            self.closed,
            self.spent
        )?;
        if !self.refused.is_empty() {
            write!(f, "   refused {}", self.refused.len())?;
        }
        if !self.caught.is_empty() {
            write!(f, "   CAUGHT")?;
        }
        Ok(())
    }
}

/// One run of one scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub label: String,
    pub epochs: u64,
    pub payoffs: Vec<Payoff>,
    /// What the audit said at the end. Empty is the honest case.
    pub problems: Vec<String>,
}

impl Run {
    pub fn payoff(&self, player: &str) -> Option<&Payoff> {
        self.payoffs.iter().find(|payoff| payoff.player == player)
    }

    pub fn net(&self, player: &str) -> i128 {
        self.payoff(player).map(Payoff::net).unwrap_or(0)
    }
}

/// The same attack, with the defence and without it.
///
/// The unit of evidence this module deals in. A lone number is unreadable —
/// there is no scale for "the attacker earned 4,000" — and the difference
/// between the two runs is what a defence is *worth*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trial {
    pub attack: String,
    /// What the attacker is protected against.
    pub defence: String,
    pub undefended: Run,
    pub defended: Run,
    /// Which player is the attacker.
    pub attacker: String,
    /// An honest player holding the same resources, if there is one.
    ///
    /// Zero is the wrong bar for several of these attacks. A sybil splitter
    /// that earns 5,952 is not "profitable" in any sense that matters if an
    /// honest operator with the same stake earns 5,994 — the incentive to
    /// split has been *removed*, which is stronger than having been priced.
    /// Comparing to zero reported that as a failure, which is how this field
    /// came to exist.
    pub benchmark: Option<String>,
    /// Who the attack is *against*, when the harm does not show up in the
    /// attacker's own balance.
    ///
    /// Griefing is the case that forced this field. A griefer's profit is not
    /// money it gains, it is time and payout it costs somebody else — and a
    /// trial that scored only the attacker would report a griefing attack as
    /// harmless because the griefer lost its bond.
    pub victim: Option<String>,
}

impl Trial {
    /// The victim's net with the defence, and without, if the trial names one.
    pub fn victim_swing(&self) -> Option<(i128, i128)> {
        let victim = self.victim.as_ref()?;
        Some((self.defended.net(victim), self.undefended.net(victim)))
    }

    /// The attacker's net with the defence, and without.
    pub fn swing(&self) -> (i128, i128) {
        (
            self.defended.net(&self.attacker),
            self.undefended.net(&self.attacker),
        )
    }

    /// Did the defence turn a profitable attack into an unprofitable one?
    ///
    /// The question the whole module exists to answer, and it is deliberately
    /// three-valued rather than a bool: an attack that never paid in the first
    /// place tells you nothing about the defence, and reporting that as
    /// "defence works" would be the most flattering possible reading.
    pub fn verdict(&self) -> Verdict {
        // A refusal outranks a payoff. An attack the rules will not even write
        // down has not been *priced* out of existence, it has been defined out
        // of it, and reporting that as "unprofitable" understates it.
        let refusals = self
            .defended
            .payoff(&self.attacker)
            .map(|payoff| payoff.refused.len())
            .unwrap_or(0);
        if refusals > 0 && self.defended.net(&self.attacker) <= 0 {
            let acted = self
                .defended
                .payoff(&self.attacker)
                .map(|payoff| payoff.acted)
                .unwrap_or(0);
            if acted == 0 {
                return Verdict::Refused { attempts: refusals };
            }
        }
        let (with, without) = self.swing();
        // A benchmark, when there is one, is the right bar: the question is
        // whether attacking beats playing straight with the same resources,
        // not whether it beats doing nothing at all.
        if let Some(benchmark) = &self.benchmark {
            let honest = self.defended.net(benchmark);
            // Losing outright is strictly stronger than merely not beating an
            // honest player, and saying "the incentive is removed, not priced"
            // over an attacker that ended forty-two thousand down would
            // understate the defence. `< 0` rather than `<= 0`: earning
            // *nothing* is neutrality, not a loss, and availability
            // free-riding lands exactly on that line.
            if with < 0 && without > 0 {
                return Verdict::Closed { with, without };
            }
            if with <= honest {
                return Verdict::Neutral {
                    attacker: with,
                    honest,
                    without,
                };
            }
            return Verdict::StillPays { with, without };
        }
        // An attack whose point is somebody else's loss is scored on that
        // loss. Otherwise a griefer that forfeits its bond reads as harmless
        // *because* it lost money, which inverts the finding.
        if let Some(victim) = &self.victim {
            let (victim_with, victim_without) =
                (self.defended.net(victim), self.undefended.net(victim));
            if victim_with > victim_without {
                return Verdict::Protected {
                    victim_with,
                    victim_without,
                    attacker: with,
                };
            }
        }
        if without <= 0 {
            Verdict::NeverPaid { without }
        } else if with <= 0 {
            Verdict::Closed { with, without }
        } else {
            Verdict::StillPays { with, without }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The defence turned a profitable attack into a losing one.
    Closed { with: i128, without: i128 },
    /// The attack pays even with the defence in place.
    StillPays { with: i128, without: i128 },
    /// The attack did not pay undefended either, so this run says nothing
    /// about the defence.
    NeverPaid { without: i128 },
    /// Every attacking action was refused at admission. Stronger than
    /// unprofitable: the mechanism does not price the attack, it declines to
    /// represent it.
    Refused { attempts: usize },
    /// The attacker earns no more than an honest player with the same
    /// resources. The strongest of the outcomes here: the incentive is gone
    /// rather than priced.
    Neutral {
        attacker: i128,
        honest: i128,
        without: i128,
    },
    /// The attack costs the attacker and leaves the victim better off.
    ///
    /// For attacks whose profit was never a balance. A griefer's aim is to
    /// stall somebody else, so scoring only its own units reports the attack as
    /// harmless *because* it lost money — which is the wrong way round.
    Protected {
        victim_with: i128,
        victim_without: i128,
        attacker: i128,
    },
}

impl Verdict {
    /// Did the mechanism hold? `Closed`, `Refused` and `Neutral` all mean yes,
    /// by three different routes.
    pub fn is_closed(&self) -> bool {
        matches!(
            self,
            Verdict::Closed { .. }
                | Verdict::Refused { .. }
                | Verdict::Neutral { .. }
                | Verdict::Protected { .. }
        )
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Closed { with, without } => write!(
                f,
                "CLOSED   attacker nets {without} undefended, {with} defended"
            ),
            Verdict::StillPays { with, without } => write!(
                f,
                "OPEN     attacker nets {without} undefended, {with} defended -- \
                 still profitable"
            ),
            Verdict::NeverPaid { without } => write!(
                f,
                "INERT    the attack nets {without} even undefended, so this run \
                 measures nothing"
            ),
            Verdict::Refused { attempts } => write!(
                f,
                "REFUSED  the rules declined all {attempts} attempt(s); the attack \
                 has no admissible form"
            ),
            Verdict::Protected {
                victim_with,
                victim_without,
                attacker,
            } => write!(
                f,
                "PROTECTED the victim nets {victim_without} undefended and \
                 {victim_with} defended, and the attacker pays {attacker}"
            ),
            Verdict::Neutral {
                attacker,
                honest,
                without,
            } => write!(
                f,
                "NEUTRAL  attacker nets {attacker} where an honest operator with the \
                 same resources nets {honest} ({without} undefended) -- the incentive \
                 is removed, not priced"
            ),
        }
    }
}

impl fmt::Display for Trial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} vs {}", self.attack, self.defence)?;
        write!(f, "  {}", self.verdict())
    }
}

// ---------------------------------------------------------------------------
// The arena
// ---------------------------------------------------------------------------

/// Seconds per epoch inside the arena.
///
/// The real [`crate::partition::EPOCH_SECONDS`]. Timestamps are synthesised
/// rather than slept through — an epoch is arithmetic on a record's own
/// `created_at`, so a scenario advances time by writing later timestamps and
/// every rule sees exactly what it would see on a live network.
const EPOCH: i64 = crate::partition::EPOCH_SECONDS as i64;

/// Where the arena's clock starts. A fixed instant, so a run is reproducible:
/// nothing here reads a wall clock.
const ORIGIN: i64 = 1_785_000_000;

/// A permissive checker. The arena is about *money*, and a checker that
/// rejected honest work would settle the question before an incentive could.
/// The arena's one pinned checker.
///
/// `ok` alone is not enough, and the second clause is not decoration. Every
/// edit `crate::canary::Generator` makes is shape- and length-preserving over
/// *numbers and strings* — it has no move that flips a boolean — so a checker
/// whose verdict turns only on `ok` cannot be made to **reject** by any canary
/// the generator can mint. The first version of this file had exactly that, and
/// the rubber-stamping scenario ran for weeks against a docket with two
/// known-good canaries and zero known-bad ones: a trap with only the half that
/// catches blind *rejection*, pointed at an attacker that blindly accepts.
const CHECKER: &str = r#"
def check(artifact):
    if artifact.get("ok") is not True:
        return False
    return artifact.get("n", 0) % 2 == 0
"#;

/// A step function, so an objective can be *disputed* and a challenge bond has
/// something to bind to. An objective with no stepper cannot be challenged at
/// all, which is a fine property and makes a griefing scenario measure nothing.
const STEPPER: &str = r#"
def step(state):
    n = state.get("n")
    i = state.get("i", 0)
    if isinstance(n, bool) or not isinstance(n, int):
        return {"halted": "n is not an integer", "i": i + 1, "n": 0}
    if n == 1:
        return {"n": 1, "i": i + 1}
    return {"n": n // 2 if n % 2 == 0 else 3 * n + 1, "i": i + 1}
"#;

/// A deterministic byte stream. SHA-256 in counter mode, like
/// [`crate::canary`]'s: a run has to be reproducible from its seed, so the
/// randomness belongs to the repository that pins it.
pub struct Rng {
    key: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
    used: usize,
}

impl Rng {
    pub fn seeded(seed: u64) -> Rng {
        let mut hasher = Sha256::new();
        hasher.update(b"cairn/arena/v1");
        hasher.update(seed.to_be_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize());
        Rng {
            key,
            counter: 0,
            buffer: Vec::new(),
            used: 0,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.used >= self.buffer.len() {
            let mut hasher = Sha256::new();
            hasher.update(self.key);
            hasher.update(self.counter.to_be_bytes());
            self.buffer = hasher.finalize().to_vec();
            self.counter = self.counter.wrapping_add(1);
            self.used = 0;
        }
        let byte = self.buffer[self.used];
        self.used += 1;
        byte
    }

    /// Uniform-enough below `bound`.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        let mut out = 0u64;
        for _ in 0..8 {
            out = (out << 8) | u64::from(self.byte());
        }
        out % bound
    }

    /// True with probability `num/den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        den > 0 && self.below(den) < num
    }
}

/// A working directory that cleans up after itself.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// A directory nothing else is using.
    ///
    /// The label and seed alone are not enough, and the reason is not
    /// hypothetical: two tests running the *same* scenario at the same seed —
    /// which is exactly what a pair of tests measuring the two sides of one
    /// trial does — collided on one directory, and the second one to arrive
    /// wiped the first's log out from under it. The counter and the process id
    /// make the name unique without making a run any less reproducible: nothing
    /// in a scenario reads this path.
    fn new(label: &str, seed: u64) -> Scratch {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cairn-arena-{label}-{seed}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a working directory");
        Scratch { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The board: a real node, a real supply, and a set of identities.
pub struct Arena {
    scratch: Scratch,
    node: Node,
    costs: Costs,
    rng: Rng,
    epoch: u64,
    /// Player name to identity.
    players: BTreeMap<String, Identity>,
    /// Modelled off-log spend, by player.
    spent: BTreeMap<String, u128>,
    refused: BTreeMap<String, Vec<String>>,
    acted: BTreeMap<String, usize>,
    caught: BTreeMap<String, Vec<String>>,
    opened: BTreeMap<String, u128>,
    checker_sha: String,
    stepper_sha: String,
}

impl Arena {
    /// A fresh board with `supply` units issued to `treasury`, and one
    /// identity per named player each issued `stake`.
    pub fn new(label: &str, seed: u64, players: &[&str], stake: u64, supply: u64) -> Arena {
        let stakes: Vec<(&str, u64)> = players.iter().map(|name| (*name, stake)).collect();
        Arena::with_stakes(label, seed, &stakes, supply)
    }

    /// The same, with a stake chosen per player.
    ///
    /// Needed by any comparison that varies *how many keys* an operator uses:
    /// giving every key the same stake would give an eight-way split eight
    /// times the money, and the run would measure the extra money rather than
    /// the extra keys.
    pub fn with_stakes(label: &str, seed: u64, players: &[(&str, u64)], supply: u64) -> Arena {
        let scratch = Scratch::new(label, seed);
        std::fs::write(scratch.path.join("c.py"), CHECKER).expect("writable");
        std::fs::write(scratch.path.join("s.py"), STEPPER).expect("writable");
        let mut hasher = Sha256::new();
        hasher.update(CHECKER.as_bytes());
        let checker_sha = crate::hex::encode(&hasher.finalize());
        let mut hasher = Sha256::new();
        hasher.update(STEPPER.as_bytes());
        let stepper_sha = crate::hex::encode(&hasher.finalize());

        let ledger = Ledger::open(scratch.path.join("log.jsonl")).expect("an empty log");
        let mut node = Node::with_registry(ledger, VerifierRegistry::new(&scratch.path));

        // Identities are derived from the player's name, so two runs of the
        // same scenario use the same keys and a diff between them is a diff in
        // behaviour rather than in who happened to be drawn first.
        let mut identities = BTreeMap::new();
        for (name, _) in players {
            let mut hasher = Sha256::new();
            hasher.update(b"cairn/arena/identity/v1");
            hasher.update(name.as_bytes());
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&hasher.finalize());
            identities.insert((*name).to_string(), Identity::from_secret_bytes(secret));
        }
        // A scarce-supply log requires the identity funding an objective to
        // authenticate the charge. Treasury used to be a nickname, which made
        // every arena objective inadmissible once objective funding became
        // signed and reduced economic scenarios to inert zero-vs-zero runs.
        identities.entry("treasury".to_string()).or_insert_with(|| {
            let mut hasher = Sha256::new();
            hasher.update(b"cairn/arena/identity/v1");
            hasher.update(b"treasury");
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&hasher.finalize());
            Identity::from_secret_bytes(secret)
        });
        let stakes: BTreeMap<String, u64> = players
            .iter()
            .map(|(name, stake)| ((*name).to_string(), *stake))
            .collect();

        let start = stamp(ORIGIN);
        // Genesis first: issuance is admissible only in the opening prefix.
        let treasury = identities
            .get("treasury")
            .expect("treasury identity was inserted")
            .submitter_id();
        node.post_issuance(&Issuance::new(treasury, supply, &start), &start)
            .expect("genesis issuance");
        let mut opened = BTreeMap::new();
        for (name, identity) in &identities {
            let stake = stakes.get(name).copied().unwrap_or(0);
            if stake > 0 {
                node.post_issuance(
                    &Issuance::new(identity.submitter_id(), stake, &start),
                    &start,
                )
                .expect("genesis issuance");
            }
            opened.insert(name.clone(), u128::from(stake));
        }

        Arena {
            scratch,
            node,
            costs: Costs::default(),
            rng: Rng::seeded(seed),
            epoch: 0,
            players: identities,
            spent: BTreeMap::new(),
            refused: BTreeMap::new(),
            acted: BTreeMap::new(),
            caught: BTreeMap::new(),
            opened,
            checker_sha,
            stepper_sha,
        }
    }

    pub fn with_costs(mut self, costs: Costs) -> Arena {
        self.costs = costs;
        self
    }

    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn rng(&mut self) -> &mut Rng {
        &mut self.rng
    }

    pub fn costs(&self) -> Costs {
        self.costs
    }

    pub fn identity(&self, player: &str) -> &Identity {
        self.players.get(player).expect("a registered player")
    }

    pub fn who(&self, player: &str) -> String {
        self.identity(player).submitter_id()
    }

    /// The current epoch's timestamp. Epoch 0 is a fixed instant, so a run is
    /// reproducible: nothing here reads a wall clock.
    pub fn now(&self) -> String {
        stamp(ORIGIN + self.epoch as i64 * EPOCH)
    }

    /// A timestamp `ahead` epochs from now.
    pub fn later(&self, ahead: u64) -> String {
        stamp(ORIGIN + (self.epoch + ahead) as i64 * EPOCH)
    }

    /// Advance to the next epoch, settling anything that has come due.
    ///
    /// Settlement runs through [`Node::settle_due`] rather than being
    /// simulated, so batching, the beacon order, and the finality delay are
    /// the real ones.
    pub fn tick(&mut self) {
        self.epoch += 1;
        let ts = self.now();
        let epoch = crate::partition::epoch_of(
            (ORIGIN + self.epoch as i64 * EPOCH) as u64,
            crate::partition::EPOCH_SECONDS,
        );
        let _ = self.node.settle_due(epoch, &ts);
    }

    /// Charge a player a modelled off-log cost.
    pub fn charge(&mut self, player: &str, units: u128) {
        let slot = self.spent.entry(player.to_string()).or_insert(0);
        *slot = slot.saturating_add(units);
    }

    fn note_acted(&mut self, player: &str) {
        *self.acted.entry(player.to_string()).or_insert(0) += 1;
    }

    fn note_refusal(&mut self, player: &str, what: &str, why: &RuleViolation) {
        self.refused
            .entry(player.to_string())
            .or_default()
            .push(format!("{what}: {why}"));
    }

    fn note_caught(&mut self, player: &str, what: String) {
        self.caught
            .entry(player.to_string())
            .or_default()
            .push(what);
    }

    // -- moves ------------------------------------------------------------

    /// Fund an objective whose computation has a step function, so a claim
    /// against it can be *disputed*.
    pub fn fund_bisectable(&mut self, player: &str, reward: u64, tag: &str) -> Option<String> {
        self.fund_with(player, reward, tag, true)
    }

    /// Fund an objective. Returns its id, or `None` if the rules refused.
    pub fn fund(&mut self, player: &str, reward: u64, tag: &str) -> Option<String> {
        self.fund_with(player, reward, tag, false)
    }

    fn fund_with(
        &mut self,
        player: &str,
        reward: u64,
        tag: &str,
        bisectable: bool,
    ) -> Option<String> {
        let funder = self.who(player);
        let mut verifier = vec![
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(self.checker_sha.clone())),
            ("entrypoint", Value::string("check")),
        ];
        if bisectable {
            verifier.push((
                "stepper",
                Value::object([
                    ("code", Value::string("s.py")),
                    ("code_sha256", Value::string(self.stepper_sha.clone())),
                    ("entrypoint", Value::string("step")),
                ]),
            ));
        }
        let objective = Objective::new(
            "G",
            format!("arena objective {tag}"),
            Value::object(verifier),
            reward,
            funder,
            self.now(),
            None,
            None,
        )
        .expect("a valid objective")
        .funded_by(self.identity(player));
        let ts = self.now();
        match self.node.post_objective(&objective, &ts) {
            Ok(_) => {
                self.note_acted(player);
                Some(objective.id())
            }
            Err(why) => {
                self.note_refusal(player, "fund", &why);
                None
            }
        }
    }

    /// Commit and reveal an artifact. `good` decides whether the pinned
    /// checker will accept it.
    ///
    /// Two epochs, because a reveal must land strictly later than its
    /// commitment — the real rule, not a simplification.
    pub fn submit(
        &mut self,
        player: &str,
        objective: &str,
        good: bool,
        nonce: &str,
    ) -> Option<String> {
        let who = self.who(player);
        let artifact = Value::object([
            ("n", Value::Int(if good { 2 } else { 3 })),
            ("ok", Value::Bool(good)),
            ("tag", Value::string(nonce)),
        ]);
        let at = self.now();
        let commitment = Commitment::new(
            objective,
            &who,
            crate::records::commitment_hash(objective, &who, &artifact, nonce),
            &at,
        )
        .signed_with(self.identity(player));
        if let Err(why) = self.node.commit(&commitment, &at) {
            self.note_refusal(player, "commit", &why);
            return None;
        }
        let reveal_at = self.later(1);
        let claim = Claim::new(objective, &who, artifact, nonce, &reveal_at, Vec::new())
            .expect("a valid claim")
            .signed_with(self.identity(player));
        match self.node.reveal(&claim, &reveal_at) {
            Ok(_) => {
                self.note_acted(player);
                Some(claim.id())
            }
            Err(why) => {
                self.note_refusal(player, "reveal", &why);
                None
            }
        }
    }

    /// Submit an artifact the caller supplies verbatim.
    ///
    /// [`Arena::submit`] builds its own, which is fine for work and wrong for a
    /// canary: a canary *is* a particular artifact, and submitting a
    /// stand-in leaves the docket matching nothing. That was a real bug in the
    /// first rubber-stamping scenario, and it made the defence look like it did
    /// nothing when in fact it had never been pointed at anything.
    pub fn submit_artifact(
        &mut self,
        player: &str,
        objective: &str,
        artifact: &Value,
        nonce: &str,
    ) -> Option<String> {
        let who = self.who(player);
        let at = self.now();
        let commitment = Commitment::new(
            objective,
            &who,
            crate::records::commitment_hash(objective, &who, artifact, nonce),
            &at,
        )
        .signed_with(self.identity(player));
        if let Err(why) = self.node.commit(&commitment, &at) {
            self.note_refusal(player, "commit", &why);
            return None;
        }
        let reveal_at = self.later(1);
        let claim = Claim::new(
            objective,
            &who,
            artifact.clone(),
            nonce,
            &reveal_at,
            Vec::new(),
        )
        .expect("a valid claim")
        .signed_with(self.identity(player));
        match self.node.reveal(&claim, &reveal_at) {
            Ok(_) => {
                self.note_acted(player);
                Some(claim.id())
            }
            Err(why) => {
                self.note_refusal(player, "reveal", &why);
                None
            }
        }
    }

    /// Submit an artifact that also commits to a trace, so the claim can be
    /// disputed. Returns `(claim_id, trace_states)`.
    pub fn submit_traced(
        &mut self,
        player: &str,
        objective: &str,
        nonce: &str,
        states: usize,
    ) -> Option<(String, usize)> {
        let trace = self.trace(states)?;
        let who = self.who(player);
        let artifact = Value::object([
            ("n", Value::Int(2)),
            ("ok", Value::Bool(true)),
            ("tag", Value::string(nonce)),
            ("trace_root", Value::string(trace.root())),
            ("trace_states", Value::Int(trace.len() as i128)),
        ]);
        let at = self.now();
        let commitment = Commitment::new(
            objective,
            &who,
            crate::records::commitment_hash(objective, &who, &artifact, nonce),
            &at,
        )
        .signed_with(self.identity(player));
        if let Err(why) = self.node.commit(&commitment, &at) {
            self.note_refusal(player, "commit", &why);
            return None;
        }
        let reveal_at = self.later(1);
        let claim = Claim::new(objective, &who, artifact, nonce, &reveal_at, Vec::new())
            .expect("a valid claim")
            .signed_with(self.identity(player));
        match self.node.reveal(&claim, &reveal_at) {
            Ok(_) => {
                self.note_acted(player);
                Some((claim.id(), trace.len()))
            }
            Err(why) => {
                self.note_refusal(player, "reveal", &why);
                None
            }
        }
    }

    /// The honest trace of the arena's step function, `states` long.
    pub fn trace(&self, states: usize) -> Option<crate::challenge::Trace> {
        let mut out = vec![Value::object([("i", Value::Int(0)), ("n", Value::Int(27))])];
        let mut current = 27i128;
        for index in 1..states {
            current = if current == 1 {
                1
            } else if current % 2 == 0 {
                current / 2
            } else {
                3 * current + 1
            };
            out.push(Value::object([
                ("i", Value::Int(index as i128)),
                ("n", Value::Int(current)),
            ]));
        }
        crate::challenge::Trace::commit(out).ok()
    }

    /// Promise to hold the log, staking `bond`.
    pub fn undertake(&mut self, player: &str, bond: u64) -> Option<String> {
        let ts = self.now();
        let height = self.node.ledger().len() as u64;
        let root = self
            .node
            .ledger()
            .root()
            .unwrap_or_else(|| String::from("sha256:"));
        let promise = Undertaking::new(self.who(player), root, height, bond, &ts)
            .signed_with(self.identity(player));
        match self.node.post_undertaking(&promise, &ts) {
            Ok(id) => {
                self.note_acted(player);
                Some(id)
            }
            Err(why) => {
                self.note_refusal(player, "undertake", &why);
                None
            }
        }
    }

    /// Answer this epoch's availability sample for every promise this player
    /// made — if it can. A player that did not keep the log cannot.
    pub fn answer(&mut self, player: &str, holds_the_log: bool) -> usize {
        if !holds_the_log {
            // The whole point of the sample: not answering is the *result* of
            // not storing, not a choice made here. A free-rider is modelled by
            // not being able to produce the entry, which is what actually
            // happens to one.
            return 0;
        }
        let who = self.who(player);
        let ts = self.now();
        let epoch = crate::partition::epoch_of(
            (ORIGIN + self.epoch as i64 * EPOCH) as u64,
            crate::partition::EPOCH_SECONDS,
        );
        let mine: Vec<Undertaking> = self
            .node
            .undertakings()
            .into_iter()
            .filter(|promise| promise.identity == who)
            .collect();
        let mut answered = 0;
        for promise in mine {
            let landing = self.node.ledger().len();
            let Ok(index) = self.node.sampled_index(&promise, epoch, landing) else {
                continue;
            };
            let Ok(height) = usize::try_from(promise.height) else {
                continue;
            };
            let built = self.node.ledger().prefix(height).and_then(|prefix| {
                prefix
                    .prove(index)
                    .map(|proof| (proof.entry.body_with_hash(), proof.inclusion.siblings))
            });
            let Some((entry, path)) = built else { continue };
            let record =
                crate::records::Availability::new(&who, promise.id(), epoch, entry, path, &ts)
                    .signed_with(self.identity(player));
            if self.node.post_availability(&record, &ts).is_ok() {
                self.note_acted(player);
                answered += 1;
                self.charge(player, self.costs.answer);
            }
        }
        answered
    }

    /// Run the pinned verifier on a claim, the way an honest operator does.
    ///
    /// `Some(true)` for accept, `Some(false)` for reject, `None` if the checker
    /// could not run — never `Some(false)` for that last case, because an
    /// absent toolchain says nothing about the artifact.
    ///
    /// The arena charges [`Costs::verify`] for this at the caller rather than
    /// here: what a check costs is an off-log fact about somebody's machine,
    /// and burying it inside a move would make it invisible in the payoff.
    pub fn verify(&self, claim_id: &str) -> Option<bool> {
        let claim = self
            .node
            .ledger()
            .entries_of_kind("claim")
            .into_iter()
            .filter_map(|entry| crate::records::Claim::from_value(&entry.payload).ok())
            .find(|claim| claim.id() == claim_id)?;
        let objective = self.node.objectives().get(&claim.objective_id)?.clone();
        let verdict = self
            .node
            .registry()
            .run(&objective.verifier, &claim.artifact);
        verdict.settles().then(|| verdict.accepted())
    }

    /// Stand behind a claim's verdict under bond.
    ///
    /// The move that gives a rubber-stamper something to lose. Nothing is
    /// checked here — that is the design, not a shortcut in the arena — so a
    /// stamper posts exactly the same record an honest verifier does and is
    /// distinguished only by whether it paid to look first.
    pub fn attest(&mut self, who: &str, claim_id: &str, accept: bool) -> Option<String> {
        let ts = self.now();
        let record = crate::records::Attestation::new(
            claim_id,
            self.who(who),
            if accept { "accept" } else { "reject" },
            &ts,
        )
        .signed_with(self.identity(who));
        match self.node.post_attestation(&record, &ts) {
            Ok(id) => {
                self.note_acted(who);
                Some(id)
            }
            Err(why) => {
                self.note_refusal(who, "attestation", &why);
                None
            }
        }
    }

    /// Take the bond of every attestation a docket contradicts.
    ///
    /// The expensive half, and it runs the verifier once per attestation the
    /// cheap half already named. Returns what was taken, in units.
    ///
    /// An attestation the verifier agrees with is *stepped over*, not forced:
    /// a docket names claims, and an honest attestor standing behind a claim
    /// somebody else misjudged must not lose a bond for it.
    pub fn take_bonds(&mut self, catcher: &str, docket: &crate::canary::Docket) -> u128 {
        let verdicts = self.node.recorded_verdicts();
        let targets: Vec<String> = docket
            .contradicted(&verdicts, &self.node.attestations())
            .into_iter()
            .map(|fault| fault.attestation_id)
            .collect();
        let ts = self.now();
        let who = self.who(catcher);
        let mut taken = 0u128;
        for id in targets {
            if let Ok(record) = self.node.slash_attestation(&id, &who, &ts) {
                taken = taken.saturating_add(
                    record
                        .get("units")
                        .and_then(Value::as_i128)
                        .unwrap_or(0)
                        .max(0) as u128,
                );
            }
        }
        if taken > 0 {
            self.note_acted(catcher);
        }
        taken
    }

    /// Point a canary docket at the log and record who it names.
    ///
    /// The defence half of the rubber-stamping trial. Runs no verifier — that
    /// is the whole economic argument for canaries — and the minting cost is
    /// charged to `policed_by` by the caller, once, up front.
    ///
    /// The earlier version took a list of *suspects*, because a docket compared
    /// against verdict records names a claim and no party: a Stage-0 log has
    /// one writer and does not record who ran the checker. Comparing against
    /// bonded attestations removes the guess — the finding is recorded against
    /// whoever signed it.
    pub fn police(&mut self, policed_by: &str, docket: &crate::canary::Docket) {
        let verdicts = self.node.recorded_verdicts();
        let found = docket.contradicted(&verdicts, &self.node.attestations());
        let by_key: BTreeMap<String, String> = self
            .players
            .iter()
            .map(|(name, identity)| (identity.submitter_id(), name.clone()))
            .collect();
        for fault in &found {
            if let Some(name) = by_key.get(&fault.attestor) {
                self.note_caught(&name.clone(), format!("{fault}"));
            }
        }
        let _ = policed_by;
    }

    /// Mutable access to the node, for a scenario that needs a record this
    /// module has no dedicated move for.
    ///
    /// Deliberately narrow in what it is *used* for: every scenario that takes
    /// it still goes through a `post_*` rule, so an attack is never granted
    /// something admission would refuse.
    pub fn node_mut(&mut self) -> &mut Node {
        &mut self.node
    }

    /// Settle the availability pool for the current epoch.
    pub fn settle_availability_now(&mut self) {
        let ts = self.now();
        let epoch = crate::partition::epoch_of(
            (ORIGIN + self.epoch as i64 * EPOCH) as u64,
            crate::partition::EPOCH_SECONDS,
        );
        let _ = self.node.settle_availability(epoch, &ts);
    }

    /// Open a bonded objection to a claim, and then answer nothing.
    ///
    /// The griefer's whole move. Whether it is admissible at all is the
    /// finding: an objective with no stepper cannot be disputed, so the
    /// objection is refused before its bond is even considered — which is a
    /// stronger answer to griefing than pricing it would be.
    pub fn grief(&mut self, claim_id: &str, states: usize, bond: u64) -> Option<String> {
        // A trace that really differs from the defender's, so the objection is
        // well formed and the *bond* is what the run measures rather than a
        // malformed record being refused for some other reason.
        let mut forged: Vec<Value> = Vec::new();
        let honest = self.trace(states)?;
        for index in 0..honest.len() {
            let state = honest.state_at(index)?.clone();
            let n = state.get("n").and_then(Value::as_i128).unwrap_or(0);
            forged.push(Value::object([
                ("i", Value::Int(index as i128)),
                ("n", Value::Int(if index == 0 { n } else { n + 1 })),
            ]));
        }
        let objection = crate::challenge::Trace::commit(forged).ok()?;
        let ts = self.now();
        let record = crate::records::Challenge::new(
            claim_id,
            self.who("griefer"),
            objection.root(),
            objection.len() as u64,
            bond,
            &ts,
        )
        .signed_with(self.identity("griefer"));
        match self.node.post_challenge(&record, &ts) {
            Ok(id) => {
                self.note_acted("griefer");
                Some(id)
            }
            Err(why) => {
                self.note_refusal("griefer", "challenge", &why);
                None
            }
        }
    }

    /// Settle a dispute whose window has shut, or that has narrowed.
    pub fn settle_dispute(&mut self, id: &str) -> Option<Value> {
        let ts = self.now();
        self.node.settle_challenge(id, &ts).ok()
    }

    /// What a player has been caught at so far, without consuming the arena.
    pub fn finish_peek_caught(&self, player: &str) -> Vec<String> {
        self.caught.get(player).cloned().unwrap_or_default()
    }

    /// The log's own verdict on the run.
    pub fn audit(&self, rerun: bool) -> Vec<String> {
        self.node.audit(rerun)
    }

    /// Close the run and read the payoffs out of real balances.
    pub fn finish(self, label: &str, rerun: bool) -> Run {
        // Holdings, not spendable. A bond that is locked behind a live promise
        // is still the promiser's money -- reading `balances`, which subtracts
        // what is committed, scored every honest participant as having *lost*
        // its stake the moment it staked it, and made a free-rider who staked
        // nothing look prudent.
        let mut debits = self.node.challenge_debits();
        // And what a slashed verification bond took. Same reason: a live bond
        // is still the attestor's money, a forfeited one is gone, and holdings
        // alone cannot tell them apart.
        for (who, lost) in self.node.attestation_debits() {
            let slot = debits.entry(who).or_insert(0);
            *slot = slot.saturating_add(lost);
        }
        let held: BTreeMap<String, u128> = self
            .node
            .tiered()
            .into_iter()
            .map(|(who, ledger)| {
                // Holdings minus what a decided dispute took. A *live* bond is
                // still the promiser's money and must not read as a loss; a
                // *forfeited* one is gone and must. Summing holdings alone
                // scored a griefer that forfeited three bonds as having lost
                // nothing.
                let lost = debits.get(&who).copied().unwrap_or(0);
                (who.clone(), ledger.total_held().saturating_sub(lost))
            })
            .collect();
        let problems = self.node.audit(rerun);
        let mut payoffs: Vec<Payoff> = self
            .players
            .iter()
            .map(|(name, identity)| Payoff {
                player: name.clone(),
                closed: held.get(&identity.submitter_id()).copied().unwrap_or(0),
                opened: self.opened.get(name).copied().unwrap_or(0),
                spent: self.spent.get(name).copied().unwrap_or(0),
                refused: self.refused.get(name).cloned().unwrap_or_default(),
                caught: self.caught.get(name).cloned().unwrap_or_default(),
                acted: self.acted.get(name).copied().unwrap_or(0),
            })
            .collect();
        payoffs.sort_by(|a, b| b.net().cmp(&a.net()).then(a.player.cmp(&b.player)));
        // Keep the scratch directory alive until the balances are read.
        drop(self.scratch);
        Run {
            label: label.to_string(),
            epochs: self.epoch,
            payoffs,
            problems,
        }
    }

    /// Path to the arena's working directory, for a scenario that needs to
    /// write a file the node will read.
    pub fn root(&self) -> &Path {
        &self.scratch.path
    }
}

/// An RFC 3339 instant from a unix second. The arena's clock, written out
/// rather than pulled in: a run is reproducible only if its timestamps are.
fn stamp(seconds: i64) -> String {
    // Days since the epoch, then the civil date, by Howard Hinnant's algorithm.
    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        y,
        m,
        d,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

pub mod scenarios;
