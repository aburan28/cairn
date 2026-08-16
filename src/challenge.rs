//! Interactive fraud proofs: settling a disputed computation in `log n` moves
//! and **one** step of execution.
//!
//! # The problem this exists for
//!
//! A `replay` objective pins a command, and verifying it costs a full re-run.
//! That is honest and it does not scale: if every node must re-run every
//! computation to know whether a claim is true, the network's verification bill
//! is the work multiplied by the node count, and
//! [`crate::incentive::design::decomposition_floor`] prices exactly how quickly
//! that stops paying.
//!
//! The standard fix is to stop asking everyone. Let the submitter commit to the
//! *whole trace* of the computation, let anyone who disagrees challenge it, and
//! make the two of them narrow their disagreement by binary search until it is
//! one step wide. Then anybody can settle it by executing that single step.
//!
//! ```text
//!   defender    s0  s1  s2  s3  s4  s5  s6  s7  s8      root_d
//!   challenger  s0  s1  s2  s3  X4  X5  X6  X7  X8      root_c
//!                            ^^^^ first divergence
//!
//!   round 1   both open index 4   differ  -> [0, 4]
//!   round 2   both open index 2   agree   -> [2, 4]
//!   round 3   both open index 3   agree   -> [3, 4]
//!             interval is one step wide: they agree on s3 and differ on s4
//!
//!   adjudicate: run ONE step from s3. Whoever's s4 it produces, wins.
//! ```
//!
//! # What bisection does and does not buy
//!
//! It does **not** remove execution. Somebody still runs the pinned code, and
//! that node is trusted exactly as much as the node running a `certificate`
//! verifier today — no more, no less. What it changes is the *quantity*:
//!
//! | | full re-verification | bisection |
//! |---|---|---|
//! | steps executed to settle a dispute | `n` | **1** |
//! | parties who must execute | everyone | one adjudicator |
//! | records exchanged | 0 | `2·⌈log₂ n⌉` |
//!
//! Claiming more than that would be dishonest, and the asymmetry is measured
//! rather than asserted: see `a_dispute_settles_in_one_step_however_long_the_trace_is`.
//!
//! # Why the game is pure
//!
//! Every move is a record, and the state of a dispute is a **fold over the
//! moves in the log** — no timers, no sockets, no session state on any node.
//! Two auditors reading the same log compute the same live interval, the same
//! whose-turn-it-is, and the same winner. That is the same discipline every
//! other derivation in this crate follows, and it is what lets an interactive
//! protocol live on an append-only log at all.
//!
//! # The one thing that makes a computation bisectable
//!
//! A **stepper**: a pinned entrypoint taking a state and returning the next
//! one. Without it the trace has no steps to search, only an input and an
//! output, and there is nothing between them to disagree about. So
//! bisectability is a property an objective either has or does not, declared in
//! its verifier spec, and [`Stepper`] is how it is declared. Collatz is the
//! natural example — `n ↦ n/2 or 3n+1` is already a step function — and
//! `examples/collatz/steppers/` pins one.
//!
//! # What this module deliberately does not do
//!
//! It moves no money. [`Outcome`] names a winner and a loser; who is bonded,
//! how much, and what happens to it are questions for `node`, because they are
//! consensus rules and this is a game.

use std::collections::BTreeMap;
use std::fmt;

use crate::canonical::{merkle_proof, merkle_root, Inclusion, Value};

/// A committed execution trace: every intermediate state, in order.
///
/// `states[0]` is the pinned starting state and `states[n]` is the final one.
/// A trace of `n` steps therefore has `n + 1` states, and the disagreement
/// interval below is over *state* indices, not step indices — off by one here
/// is the classic way to adjudicate the wrong step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    states: Vec<Value>,
    leaves: Vec<String>,
    root: String,
}

/// Longest trace this module will commit to.
///
/// Not a limit on computation — a limit on one *record*'s worth of it. At
/// 2^24 states a bisection is 24 rounds, 48 records, which is a dispute an
/// append-only log can actually carry. A computation longer than this is
/// decomposed into sub-objectives, which is what
/// [`crate::incentive::design::decomposition_floor`] is for.
pub const MAX_TRACE: usize = 1 << 24;

impl Trace {
    /// Commit to a sequence of states.
    ///
    /// Refuses a trace with fewer than two states: one state is an input with
    /// no computation attached, and there is nothing for two parties to
    /// disagree about within it.
    pub fn commit(states: Vec<Value>) -> Result<Trace, TraceError> {
        if states.len() < 2 {
            return Err(TraceError::TooShort(states.len()));
        }
        if states.len() > MAX_TRACE {
            return Err(TraceError::TooLong(states.len()));
        }
        let leaves: Vec<String> = states.iter().map(Value::digest).collect();
        let root = merkle_root(&leaves).ok_or(TraceError::TooShort(0))?;
        Ok(Trace {
            states,
            leaves,
            root,
        })
    }

    /// Run the stepper from `start` for `steps` steps and commit to what it
    /// produced. This is how an honest submitter builds its commitment, and
    /// how an adjudicator reproduces one.
    pub fn run(stepper: &Stepper<'_>, start: Value, steps: usize) -> Result<Trace, TraceError> {
        let mut states = Vec::with_capacity(steps + 1);
        states.push(start);
        for index in 0..steps {
            let next = stepper
                .step(&states[index])
                .map_err(|why| TraceError::Stepper { index, why })?;
            states.push(next);
        }
        Trace::commit(states)
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    /// Number of *states*, which is one more than the number of steps.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Number of steps the trace claims to have executed.
    pub fn steps(&self) -> usize {
        self.states.len().saturating_sub(1)
    }

    pub fn state_at(&self, index: usize) -> Option<&Value> {
        self.states.get(index)
    }

    pub fn digest_at(&self, index: usize) -> Option<&str> {
        self.leaves.get(index).map(String::as_str)
    }

    /// The move a party makes when the game asks about `index`: the state
    /// itself, plus the path proving it is the one this party committed to.
    ///
    /// The **state**, not just its hash. Carrying the preimage at every round
    /// costs a state per move and removes an entire phase of the protocol — the
    /// one where the parties, having narrowed to a single step, must then be
    /// made to reveal the two states around it, and where a party who prefers
    /// not to has one more thing to stall over. State size is the objective's
    /// choice and it is bounded by [`MAX_STATE_BYTES`].
    pub fn open(&self, challenge: &str, index: usize) -> Option<Move> {
        let state = self.states.get(index)?.clone();
        let path = merkle_proof(&self.leaves, index)?;
        Some(Move {
            challenge: challenge.to_string(),
            index,
            state,
            path,
        })
    }
}

/// Largest state a move may carry.
///
/// A trace whose states are megabytes is not bisectable in practice — the moves
/// are the dispute, and a dispute nobody can afford to transmit is a dispute
/// the liar wins by attrition. 64 KiB is generous for the machine state of a
/// step and small enough that `2·⌈log₂ n⌉` of them stay ordinary records.
pub const MAX_STATE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    /// Fewer than two states: nothing happened, so nothing can be disputed.
    TooShort(usize),
    TooLong(usize),
    Stepper {
        index: usize,
        why: StepError,
    },
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceError::TooShort(len) => {
                write!(f, "a trace of {len} state(s) has no step to disagree about")
            }
            TraceError::TooLong(len) => write!(f, "{len} states exceeds the {MAX_TRACE} cap"),
            TraceError::Stepper { index, why } => write!(f, "stepping state {index}: {why}"),
        }
    }
}

impl std::error::Error for TraceError {}

/// One party's answer to one bisection query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Move {
    /// Which dispute this belongs to.
    pub challenge: String,
    /// Which state index the game asked about.
    pub index: usize,
    /// The state this party committed to at that index.
    pub state: Value,
    /// The path proving it, against this party's own committed root.
    pub path: Inclusion,
}

impl Move {
    pub fn digest(&self) -> String {
        self.state.digest()
    }

    /// Is this move consistent with the root its author published?
    ///
    /// Checked before the move counts for anything. Without it a party losing
    /// the search simply answers with whatever state wins the current round,
    /// and bisection degenerates into "whoever lies last, wins".
    pub fn opens(&self, root: &str) -> bool {
        if self.path.index != self.index {
            return false;
        }
        if self.state.canonical_bytes().len() > MAX_STATE_BYTES {
            return false;
        }
        self.path.verify(&self.digest(), root)
    }
}

/// Which side of a dispute a party is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Side {
    /// The party whose claim is settled or awaiting settlement.
    Defender,
    /// The party who says the defender's trace is wrong, and posted a bond.
    Challenger,
}

impl Side {
    pub fn as_str(&self) -> &'static str {
        match self {
            Side::Defender => "defender",
            Side::Challenger => "challenger",
        }
    }

    pub fn parse(text: &str) -> Option<Side> {
        match text {
            "defender" => Some(Side::Defender),
            "challenger" => Some(Side::Challenger),
            _ => None,
        }
    }

    pub fn other(&self) -> Side {
        match self {
            Side::Defender => Side::Challenger,
            Side::Challenger => Side::Defender,
        }
    }
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a dispute ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// One step of execution decided it. `at` is the state index they agreed
    /// on; the step from there is the one that was run.
    Adjudicated {
        winner: Side,
        at: usize,
        why: String,
    },
    /// A party stopped answering. Silence loses, or a liar simply stops when
    /// the search closes in — which is the whole reason the window exists.
    Forfeited { winner: Side, waiting_on: Side },
}

impl Outcome {
    pub fn winner(&self) -> Side {
        match self {
            Outcome::Adjudicated { winner, .. } => *winner,
            Outcome::Forfeited { winner, .. } => *winner,
        }
    }

    pub fn loser(&self) -> Side {
        self.winner().other()
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Adjudicated { winner, at, why } => {
                write!(f, "{winner} wins on the step from state {at}: {why}")
            }
            Outcome::Forfeited {
                winner,
                waiting_on: silent,
            } => write!(f, "{winner} wins; {silent} stopped answering"),
        }
    }
}

/// What the dispute needs next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Both sides must open this state index. `waiting_on` lists who still
    /// owes a move — a round is not complete until both have answered, and
    /// neither answer is a function of the other, so the order does not matter.
    Open { index: usize, waiting_on: Vec<Side> },
    /// The search is finished. Run one step from `agreed` and compare.
    Adjudicate { agreed: usize },
    /// Already decided.
    Done(Outcome),
}

/// A live dispute, folded from the moves recorded against it.
///
/// Constructed fresh from the log every time rather than kept as session state.
/// A dispute is a claim about what a set of records means, and a node that
/// cached it would eventually disagree with a node that did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispute {
    /// The dispute's identity, used to bind moves to it.
    pub id: String,
    /// The defender's committed trace root, and the challenger's.
    pub defender_root: String,
    pub challenger_root: String,
    /// How many states both sides claim the trace has.
    pub length: usize,
    /// The live interval: agreed at `lo`, disagreed at `hi`.
    lo: usize,
    hi: usize,
    /// States opened so far, per side, for the interval endpoints.
    opened: BTreeMap<(usize, Side), Value>,
    outcome: Option<Outcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisputeError {
    /// The two roots are identical, so there is no disagreement to bisect.
    Agreed,
    /// A trace of fewer than two states has no step.
    TooShort(usize),
    /// The move names an index the game did not ask about. Answering a
    /// different question is how a party stalls while looking cooperative.
    WrongIndex { asked: usize, answered: usize },
    /// The move does not open the root its author committed to.
    NotUnderRoot { side: Side },
    /// This side already answered this round.
    AlreadyMoved { side: Side, index: usize },
    /// The two parties do not start from the same state, so they are not
    /// disputing one computation — they are describing two. No search over
    /// them means anything.
    DifferentStart,
    /// The two traces end on the same state. The challenger has committed to a
    /// different *path* to the same answer, which contradicts nothing the claim
    /// asserts, and the search would terminate on an interval whose endpoints
    /// both agree.
    SameEnd,
    /// Traces of different lengths. The disagreement is already public and
    /// needs no search.
    LengthMismatch { defender: usize, challenger: usize },
    /// The dispute is over.
    Finished,
}

impl fmt::Display for DisputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DisputeError::Agreed => {
                write!(f, "both roots are the same; there is nothing to bisect")
            }
            DisputeError::TooShort(len) => {
                write!(f, "a trace of {len} state(s) has no step to disagree about")
            }
            DisputeError::WrongIndex { asked, answered } => {
                write!(f, "the game asked about state {asked}, not {answered}")
            }
            DisputeError::NotUnderRoot { side } => {
                write!(
                    f,
                    "the {side}'s move does not open the root it committed to"
                )
            }
            DisputeError::AlreadyMoved { side, index } => {
                write!(f, "the {side} already opened state {index}")
            }
            DisputeError::DifferentStart => write!(
                f,
                "the two traces start from different states, so they describe \
                 different computations"
            ),
            DisputeError::SameEnd => write!(
                f,
                "the two traces end on the same state, so the challenge \
                 contradicts nothing the claim asserts"
            ),
            DisputeError::LengthMismatch {
                defender,
                challenger,
            } => write!(
                f,
                "traces of {defender} and {challenger} states disagree in public \
                 already; there is nothing to search for"
            ),
            DisputeError::Finished => write!(f, "this dispute is already decided"),
        }
    }
}

impl std::error::Error for DisputeError {}

/// The four moves a dispute has to be opened with.
///
/// Both parties open the **first** state, which must be the same one, and the
/// **last**, which must differ. Those two facts are the search's invariant —
/// agreed at `lo`, disagreed at `hi` — and until this struct existed they were
/// assumed rather than established. Two consequences, both of which the tests
/// found before a reader did:
///
/// - A lie in the very first step leaves `lo` at 0 forever, and adjudication
///   needs the *state* at `lo` to step from. Nobody ever opened it, so nothing
///   could be adjudicated.
/// - Two traces that diverge and then rejoin have equal final states, so `hi`
///   is not a disagreement at all, and the search terminates on an interval
///   whose endpoints both agree. That dispute has no answer, and refusing it up
///   front is the only correct response: the challenger has not actually
///   contradicted the claim.
pub struct Endpoints {
    pub defender_start: Move,
    pub challenger_start: Move,
    pub defender_final: Move,
    pub challenger_final: Move,
}

impl Dispute {
    /// Open a dispute over two traces of the same length.
    ///
    /// Equal length is required, and that is not a limitation: the *length* is
    /// part of what a trace commitment says, so two parties claiming different
    /// lengths have already stated their disagreement in public and need no
    /// search to find it. Bisection is for the case where the disagreement is
    /// hidden somewhere inside two traces that look alike from outside.
    pub fn open(
        id: impl Into<String>,
        defender_root: impl Into<String>,
        challenger_root: impl Into<String>,
        length: usize,
        ends: Endpoints,
    ) -> Result<Dispute, DisputeError> {
        let defender_root = defender_root.into();
        let challenger_root = challenger_root.into();
        if defender_root == challenger_root {
            return Err(DisputeError::Agreed);
        }
        if length < 2 {
            return Err(DisputeError::TooShort(length));
        }
        let last = length - 1;
        let mut opened = BTreeMap::new();
        for (side, index, mv) in [
            (Side::Defender, 0, &ends.defender_start),
            (Side::Challenger, 0, &ends.challenger_start),
            (Side::Defender, last, &ends.defender_final),
            (Side::Challenger, last, &ends.challenger_final),
        ] {
            if mv.index != index {
                return Err(DisputeError::WrongIndex {
                    asked: index,
                    answered: mv.index,
                });
            }
            let root = match side {
                Side::Defender => &defender_root,
                Side::Challenger => &challenger_root,
            };
            if !mv.opens(root) {
                return Err(DisputeError::NotUnderRoot { side });
            }
            opened.insert((index, side), mv.state.clone());
        }
        if ends.defender_start.state != ends.challenger_start.state {
            return Err(DisputeError::DifferentStart);
        }
        if ends.defender_final.state == ends.challenger_final.state {
            return Err(DisputeError::SameEnd);
        }
        Ok(Dispute {
            id: id.into(),
            defender_root,
            challenger_root,
            length,
            // The invariant the whole search rests on, now *witnessed* by the
            // four moves above rather than taken on trust: agreed at 0,
            // disagreed at the last index. Every round preserves it.
            lo: 0,
            hi: last,
            opened,
            outcome: None,
        })
    }

    /// Open a dispute directly between two traces the caller holds.
    ///
    /// For an adjudicator or a test that has both sides in hand. The wire path
    /// never does — that is what [`Dispute::open`] and its four moves are for.
    pub fn between(
        id: &str,
        defender: &Trace,
        challenger: &Trace,
    ) -> Result<Dispute, DisputeError> {
        if defender.len() != challenger.len() {
            return Err(DisputeError::LengthMismatch {
                defender: defender.len(),
                challenger: challenger.len(),
            });
        }
        let last = defender.len().saturating_sub(1);
        let ends = Endpoints {
            defender_start: defender.open(id, 0).ok_or(DisputeError::TooShort(0))?,
            challenger_start: challenger.open(id, 0).ok_or(DisputeError::TooShort(0))?,
            defender_final: defender.open(id, last).ok_or(DisputeError::TooShort(0))?,
            challenger_final: challenger.open(id, last).ok_or(DisputeError::TooShort(0))?,
        };
        Dispute::open(id, defender.root(), challenger.root(), defender.len(), ends)
    }

    pub fn root_of(&self, side: Side) -> &str {
        match side {
            Side::Defender => &self.defender_root,
            Side::Challenger => &self.challenger_root,
        }
    }

    /// The live interval: agreed at `.0`, disagreed at `.1`.
    pub fn interval(&self) -> (usize, usize) {
        (self.lo, self.hi)
    }

    /// How many rounds a dispute of this length takes, worst case.
    ///
    /// Exactly `⌈log₂(length - 1)⌉`: each round halves the interval, which
    /// starts at `length - 1` steps wide and ends at 1.
    pub fn rounds_needed(length: usize) -> u32 {
        let mut width = length.saturating_sub(1);
        let mut rounds = 0;
        while width > 1 {
            width = width.div_ceil(2);
            rounds += 1;
        }
        rounds
    }

    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    /// What the dispute needs next.
    pub fn next(&self) -> Next {
        if let Some(outcome) = &self.outcome {
            return Next::Done(outcome.clone());
        }
        if self.hi - self.lo <= 1 {
            return Next::Adjudicate { agreed: self.lo };
        }
        let index = self.query();
        let waiting_on = [Side::Defender, Side::Challenger]
            .into_iter()
            .filter(|side| !self.opened.contains_key(&(index, *side)))
            .collect();
        Next::Open { index, waiting_on }
    }

    /// The midpoint the next round asks about.
    ///
    /// `lo + (hi - lo) / 2` rather than `(lo + hi) / 2`: the second overflows on
    /// a large enough interval, and this one is the same value everywhere it
    /// does not.
    fn query(&self) -> usize {
        self.lo + (self.hi - self.lo) / 2
    }

    /// Record one side's answer.
    ///
    /// When both sides have answered the current query, the interval narrows:
    /// equal states mean the divergence is later, unequal means it is earlier.
    /// Either way the invariant `agreed at lo, disagreed at hi` survives, which
    /// is what guarantees the search converges on a real first divergence
    /// rather than on wherever the parties felt like stopping.
    pub fn play(&mut self, side: Side, mv: &Move) -> Result<(), DisputeError> {
        if self.outcome.is_some() {
            return Err(DisputeError::Finished);
        }
        let index = match self.next() {
            Next::Open { index, .. } => index,
            _ => return Err(DisputeError::Finished),
        };
        if mv.index != index {
            return Err(DisputeError::WrongIndex {
                asked: index,
                answered: mv.index,
            });
        }
        if !mv.opens(self.root_of(side)) {
            return Err(DisputeError::NotUnderRoot { side });
        }
        if self.opened.contains_key(&(index, side)) {
            return Err(DisputeError::AlreadyMoved { side, index });
        }
        self.opened.insert((index, side), mv.state.clone());

        let (Some(theirs), Some(mine)) = (
            self.opened.get(&(index, Side::Defender)),
            self.opened.get(&(index, Side::Challenger)),
        ) else {
            return Ok(());
        };
        if theirs == mine {
            self.lo = index;
        } else {
            self.hi = index;
        }
        Ok(())
    }

    /// The state both sides opened at `index`, if they agreed on it.
    pub fn agreed_state(&self, index: usize) -> Option<&Value> {
        let defender = self.opened.get(&(index, Side::Defender))?;
        let challenger = self.opened.get(&(index, Side::Challenger))?;
        (defender == challenger).then_some(defender)
    }

    pub fn opened_state(&self, index: usize, side: Side) -> Option<&Value> {
        self.opened.get(&(index, side))
    }

    /// Settle the narrowed dispute by executing exactly one step.
    ///
    /// The only place in this module that runs anything, and it runs it once,
    /// on a state both parties have already agreed to in writing. A stepper
    /// that cannot run settles **nothing** and returns an error rather than a
    /// winner — the same rule as
    /// [`Status::Unavailable`](crate::verifiers::Status::Unavailable), and for
    /// the same reason: a broken toolchain on the adjudicator's machine is not
    /// evidence about either party, and treating it as one hands a dispute to
    /// whoever can break a machine.
    pub fn adjudicate(&mut self, stepper: &Stepper<'_>) -> Result<&Outcome, AdjudicationError> {
        // Idempotent: adjudicating a decided dispute returns what was decided
        // rather than running the step again. Two adjudicators reaching the
        // same outcome is fine; one dispute having two outcomes is not.
        if self.outcome.is_none() {
            let decided = self.decide(stepper)?;
            self.outcome = Some(decided);
        }
        Ok(self
            .outcome
            .as_ref()
            .expect("set immediately above when it was absent"))
    }

    /// The verdict, computed without touching `self.outcome`.
    ///
    /// Split out so [`Dispute::adjudicate`] has one assignment and one return
    /// rather than two of each. The step runs here.
    fn decide(&self, stepper: &Stepper<'_>) -> Result<Outcome, AdjudicationError> {
        let Next::Adjudicate { agreed } = self.next() else {
            return Err(AdjudicationError::NotNarrowed(self.interval()));
        };
        let disputed = agreed + 1;
        let start = self
            .agreed_state(agreed)
            .ok_or(AdjudicationError::NoAgreedState(agreed))?
            .clone();
        let defender = self
            .opened_state(disputed, Side::Defender)
            .ok_or(AdjudicationError::Unopened {
                side: Side::Defender,
                index: disputed,
            })?
            .clone();
        let challenger = self
            .opened_state(disputed, Side::Challenger)
            .ok_or(AdjudicationError::Unopened {
                side: Side::Challenger,
                index: disputed,
            })?
            .clone();

        let truth = stepper.step(&start).map_err(AdjudicationError::Stepper)?;

        // Order matters only for the message. Both cannot match: the interval
        // narrowed here precisely because the two states differ.
        let outcome = if truth == defender {
            Outcome::Adjudicated {
                winner: Side::Defender,
                at: agreed,
                why: "the step reproduces the defender's state".to_string(),
            }
        } else if truth == challenger {
            Outcome::Adjudicated {
                winner: Side::Challenger,
                at: agreed,
                why: "the step reproduces the challenger's state".to_string(),
            }
        } else {
            // Neither. Both traces are wrong at this step, and the challenger
            // still wins: they were right that the defender's claim does not
            // reproduce, which is the only thing a challenge asserts. Awarding
            // it to the defender because the challenger is also wrong would
            // make a false claim safe as long as nobody could produce a
            // perfectly correct refutation.
            Outcome::Adjudicated {
                winner: Side::Challenger,
                at: agreed,
                why: "the step reproduces neither state, so the defence does not \
                      reproduce either"
                    .to_string(),
            }
        };
        Ok(outcome)
    }

    /// End the dispute against a side that stopped answering.
    ///
    /// The window is enforced by the caller, because "has enough time passed"
    /// is an epoch question and epochs come from records. This only encodes
    /// what silence *means*: the side that owes a move and did not make it
    /// loses. Without it, a liar's dominant strategy is to answer until the
    /// search reaches the step where they lied, and then stop.
    pub fn forfeit(&mut self, silent: Side) -> Result<&Outcome, DisputeError> {
        if self.outcome.is_some() {
            return Err(DisputeError::Finished);
        }
        self.outcome = Some(Outcome::Forfeited {
            winner: silent.other(),
            waiting_on: silent,
        });
        Ok(self.outcome.as_ref().expect("just set"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjudicationError {
    /// The search has not finished; there is more than one step in dispute.
    NotNarrowed((usize, usize)),
    /// The parties never agreed on a state to step from.
    NoAgreedState(usize),
    /// A side never opened the disputed state.
    Unopened { side: Side, index: usize },
    /// The stepper could not run. Settles nothing.
    Stepper(StepError),
}

impl fmt::Display for AdjudicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdjudicationError::NotNarrowed((lo, hi)) => write!(
                f,
                "the dispute still spans states {lo}..{hi}; bisect before adjudicating"
            ),
            AdjudicationError::NoAgreedState(at) => {
                write!(f, "no state both sides opened at {at} to step from")
            }
            AdjudicationError::Unopened { side, index } => {
                write!(f, "the {side} never opened state {index}")
            }
            AdjudicationError::Stepper(why) => write!(f, "the stepper settles nothing: {why}"),
        }
    }
}

impl std::error::Error for AdjudicationError {}

// -- the stepper -----------------------------------------------------------

mod stepper;
pub use stepper::{StepError, Stepper};

#[cfg(test)]
mod tests;
