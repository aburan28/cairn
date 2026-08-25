//! The attacks, each played twice: with its defence and without.
//!
//! Every scenario here returns a [`Trial`], and a `Trial` is a *pair* of runs.
//! That is the whole discipline of the file. "The attacker earned 4,000" has no
//! scale attached to it and can be made to say anything; "the attacker earned
//! 34,000 undefended and −2,300 defended" is a measurement of a defence.
//!
//! A [`crate::arena::Verdict`] is many-valued rather than a bool, and the
//! variants that keep the file honest are the ones that report a *failure to
//! set up*: `NeverPaid` means the attack lost money even
//! *without* the defence, so the run says nothing about whether the defence
//! works. Reporting that as a success would be the most flattering possible
//! reading of a scenario that failed to set itself up.

use crate::arena::{Arena, Costs, Run, Trial};
use crate::canary::{Docket, Generator};
use crate::canonical::Value;
use crate::tier::Tier;

/// Every trial this module knows how to run.
pub fn all(seed: u64) -> Vec<Trial> {
    vec![
        rubber_stamping(seed),
        sybil_split(seed),
        griefing_disputes(seed),
        unbisectable_objectives(seed),
        cheap_tier_standing(seed),
        availability_free_riding(seed),
    ]
}

// ---------------------------------------------------------------------------
// 1. Rubber-stamping
// ---------------------------------------------------------------------------

/// **Attack.** An operator that records `accept` without running the verifier
/// keeps every cycle the honest one spends.
///
/// **Defence.** Two halves, and they only work together. **Canaries** —
/// submissions whose verdict the issuer already knows, mixed in
/// indistinguishably — say *which* verdicts are wrong, for a map lookup rather
/// than a verifier run. A **bonded attestation** says *who is answerable* for
/// each one. The first half without the second names a culprit and takes
/// nothing; the second without the first has evidence nobody can afford to
/// find.
///
/// # What the earlier versions of this scenario got wrong
///
/// The first paid the stamper nothing and reported `INERT`, which was correct
/// and useless. Nothing in the protocol pays for verification *at all*, so a
/// rubber-stamper's gain is not revenue, it is the **cost it does not pay**.
/// Two operators doing the same work, one of which verifies, is the comparison
/// that exists.
///
/// The second got the comparison right and reported `OPEN`: the docket named
/// the stamper and took nothing from it, because nothing was staked on
/// verification. That was the finding, it was pinned as open in
/// `tests/arena.rs`, and `src/records.rs::Attestation` is what closed it.
pub fn rubber_stamping(seed: u64) -> Trial {
    Trial {
        attack: "rubber-stamping".to_string(),
        defence: "a canary docket against bonded attestations".to_string(),
        attacker: "stamper".to_string(),
        // The honest operator does exactly the same work and pays to check it.
        benchmark: Some("honest".to_string()),
        victim: None,
        undefended: rubber_stamp_run(seed, false),
        defended: rubber_stamp_run(seed, true),
    }
}

fn rubber_stamp_run(seed: u64, canaries: bool) -> Run {
    let label = if canaries { "canaried" } else { "bare" };
    // Enough to carry four concurrent verification bonds and still be
    // recognisably in the same economy: the bond is the reference network's
    // catch bounty, which is fifty times an objective's reward here.
    let stake = crate::node::VERIFICATION_BOND * 5;
    let mut arena = Arena::with_stakes(
        &format!("stamp-{label}"),
        seed,
        &[("stamper", stake), ("honest", stake), ("auditor", 10_000)],
        1_000_000,
    );
    let costs = arena.costs();

    // Both operators do the same work and are paid the same for it. The only
    // difference between them is whether they pay to check what they attest to.
    for round in 0..8u64 {
        for who in ["honest", "stamper"] {
            let Some(objective) = arena.fund("treasury", 1_000, &format!("{who}-{round}")) else {
                continue;
            };
            arena.submit(who, &objective, true, &format!("n{round}"));
        }
        // The honest operator verifies every claim in the epoch. The stamper
        // does not, and that saving is the whole of its advantage.
        arena.charge("honest", costs.verify * 2);
        arena.tick();
        arena.tick();
    }

    // The same runway in both arms, so the two differ only in the policing and
    // not in how many settlements had time to land. The first version did not,
    // and the canaried arm scored the stamper *higher* -- one extra epoch of
    // settlement dressed up as an effect of the defence.
    for _ in 0..12 {
        arena.tick();
    }
    if !canaries {
        return arena.finish(&format!("rubber-stamping / {label}"), false);
    }

    // Minting costs verifier runs, once, paid by whoever polices the network.
    // Checking the docket afterwards costs nothing, which is the entire
    // economic argument for canaries.
    arena.charge("auditor", costs.mint_canary);
    let seed_artifact = Value::object([
        ("n", Value::Int(2)),
        ("ok", Value::Bool(true)),
        ("tag", Value::string("seedy")),
    ]);
    let spec = Value::object([
        ("kind", Value::string("certificate")),
        ("checker", Value::string("c.py")),
        ("checker_sha256", Value::string(checker_sha(arena.root()))),
        ("entrypoint", Value::string("check")),
    ]);
    let minted = {
        let generator = Generator::new(arena.node().registry(), &spec);
        let (minted, _failures) = generator.mint_batch(&seed_artifact, 4, 1, 2);
        minted
    };
    let docket = Docket::from_canaries(&minted);
    // Both halves of the trap, or the run measures nothing. A docket with no
    // known-*bad* canary cannot catch a blind accepter however many entries it
    // has, and this scenario spent its first life pointed at one -- see the
    // note on `arena::CHECKER` for why the generator could not mint them.
    let (good, bad) = docket.mix();
    assert!(
        good > 0 && bad > 0,
        "the docket is half a trap ({good} known-good, {bad} known-bad); \
         a rubber-stamper is caught only by a known-bad canary"
    );

    // The canaries go in as ordinary submissions, from an identity that also
    // submits real work — the deployment rule `src/canary.rs` is emphatic
    // about, and the one its own test fixture got wrong first time.
    //
    // One objective each, because an objective with a settled claim refuses
    // further submissions: sharing one meant the first canary landed, the rest
    // were refused at commit, and the docket ended up pointed at half a batch.
    let mut placed: Vec<(String, String)> = Vec::new();
    for (index, canary) in minted.iter().enumerate() {
        let Some(objective) = arena.fund("treasury", 1_000, &format!("canary-{index}")) else {
            continue;
        };
        // The canary's own artifact, not a stand-in. A docket is keyed on the
        // artifact digest, so submitting something else leaves it matching
        // nothing -- which is exactly what the first version of this scenario
        // did, and why the defence appeared to do nothing.
        if let Some(claim) = arena.submit_artifact(
            "auditor",
            &objective,
            &canary.artifact,
            &format!("c{index}"),
        ) {
            placed.push((claim, objective));
        }
        arena.tick();
        arena.tick();
    }

    // Both operators put a bond behind what they say about each canary. The
    // honest one pays to look first and attests what it actually found; the
    // stamper writes `accept` across the board without looking, because it
    // cannot tell a canary from real work — that is the point of the generator.
    // Same record, same stake, differing only in whether it is true.
    for (claim_id, _) in &placed {
        arena.charge("honest", costs.verify);
        let truth = arena.verify(claim_id).unwrap_or(true);
        arena.attest("honest", claim_id, truth);
        arena.attest("stamper", claim_id, true);
    }

    arena.police("auditor", &docket);
    // The taking. One verifier run per attestation the free half already named,
    // and the bond goes to whoever brought the evidence.
    arena.take_bonds("auditor", &docket);

    arena.finish(&format!("rubber-stamping / {label}"), false)
}

// ---------------------------------------------------------------------------
// 2. Sybil splitting
// ---------------------------------------------------------------------------

/// **Attack.** One operator wearing many identities, to take a larger share of
/// a pool.
///
/// **Defence.** Split the pool by *stake* rather than by head count. Stake is
/// conserved when it is divided and a head count is not.
///
/// # The comparison, done carefully
///
/// The operator's **total is held fixed** at 8,000 across both runs: one key
/// holding 8,000, against eight keys holding 1,000 each. The first version of
/// this scenario gave every key the same stake, so the eight-way split started
/// with eight times the money and the run measured the extra money rather than
/// the extra keys.
///
/// The undefended arm is the *same history* scored by head count, computed from
/// the log — the node only ever splits by stake, so a head-count run cannot be
/// played against the real engine. That arithmetic is the one modelled thing
/// here besides [`Costs`], and it is the counterfactual the defence is
/// measured against.
///
/// The result to want is **equality**, not a smaller number. An attack that is
/// exactly neutral has had its incentive removed rather than priced.
pub fn sybil_split(seed: u64) -> Trial {
    let (defended, undefended) = sybil_runs(seed);
    Trial {
        attack: "sybil identity splitting".to_string(),
        defence: "pool split by stake, not by head".to_string(),
        attacker: "splitter (all keys)".to_string(),
        // One key, the same total stake. Equality here is the whole claim.
        benchmark: Some("honest".to_string()),
        victim: None,
        undefended,
        defended,
    }
}

fn sybil_runs(seed: u64) -> (Run, Run) {
    const TOTAL: u64 = 8_000;
    const KEYS: u64 = 8;

    let one = sybil_history(seed, 1, TOTAL);
    let many = sybil_history(seed, KEYS, TOTAL / KEYS);

    // Stake-weighted: what the real engine paid, summed over the operator's
    // keys.
    let mut defended = many.run.clone();
    defended.label = "sybil splitting / stake-weighted (8 keys)".to_string();
    collapse(&mut defended, "splitter", many.earned);

    // Head-counted: the same epochs, the same answers, divided per answering
    // identity instead. Modelled, because the node has no such rule.
    let mut undefended = many.run.clone();
    undefended.label = "sybil splitting / head-counted (8 keys, modelled)".to_string();
    collapse(&mut undefended, "splitter", many.by_head);
    // The honest operator's share moves the other way under a head count, so
    // it is restated too rather than left at the stake-weighted figure.
    if let Some(payoff) = undefended
        .payoffs
        .iter_mut()
        .find(|payoff| payoff.player == "honest")
    {
        payoff.closed = payoff.opened.saturating_add(many.honest_by_head);
    }
    let _ = one;
    (defended, undefended)
}

struct Split {
    run: Run,
    /// What the operator's keys were actually paid, in total.
    earned: u128,
    /// What they would have been paid under an equal split per answering
    /// identity.
    by_head: u128,
    honest_by_head: u128,
}

fn sybil_history(seed: u64, keys: u64, per_key: u64) -> Split {
    let names: Vec<String> = (0..keys)
        .map(|index| {
            if index == 0 {
                "splitter".to_string()
            } else {
                format!("splitter-{index}")
            }
        })
        .collect();
    let mut roster: Vec<(&str, u64)> = names.iter().map(|name| (name.as_str(), per_key)).collect();
    // The honest operator holds the same *total* as the splitter, in one key.
    roster.push(("honest", keys * per_key));

    let mut arena = Arena::with_stakes(&format!("sybil-{keys}"), seed, &roster, 1_000_000);
    for name in &names {
        arena.undertake(name, per_key);
    }
    arena.undertake("honest", keys * per_key);

    let ts = arena.now();
    let epoch = crate::partition::epoch_of(
        crate::time::parse_rfc3339(&ts).unwrap_or(0) as u64,
        crate::partition::EPOCH_SECONDS,
    );
    let first_paid_epoch = epoch + 1;
    let pool = crate::records::AvailabilityPool {
        funder: arena.who("treasury"),
        per_epoch: 2_000,
        from_epoch: first_paid_epoch,
        to_epoch: first_paid_epoch + 16,
        created_at: ts.clone(),
    };
    let _ = arena.node_mut().post_availability_pool(&pool, &ts);
    // Eligibility is fixed at the epoch boundary. Promises and pools created
    // during an epoch start earning only in a later one; otherwise a late,
    // backdated promise could wait to learn that epoch's challenge.
    arena.tick();

    let mut rounds = 0u128;
    for _ in 0..6 {
        let mut answered = 0u128;
        for name in &names {
            answered += arena.answer(name, true) as u128;
        }
        answered += arena.answer("honest", true) as u128;
        if answered > 0 {
            rounds += 1;
        }
        arena.settle_availability_now();
        arena.tick();
    }

    // A head count divides each epoch's pot equally among the answering
    // identities. `keys` of them belong to the operator and one to the honest
    // holder, so the operator takes `keys/(keys+1)` of every epoch.
    let per_epoch = 2_000u128;
    let heads = u128::from(keys) + 1;
    let by_head = rounds * (per_epoch / heads) * u128::from(keys);
    let honest_by_head = rounds * (per_epoch / heads);

    let run = arena.finish(&format!("sybil / {keys} key(s)"), false);
    let earned: u128 = names
        .iter()
        .map(|name| {
            run.payoff(name)
                .map(|payoff| payoff.closed.saturating_sub(payoff.opened))
                .unwrap_or(0)
        })
        .sum();
    Split {
        run,
        earned,
        by_head,
        honest_by_head,
    }
}

/// Fold every `splitter-*` payoff into `splitter`, crediting it `earned`.
///
/// The operator does not care which of its keys holds the money, so a
/// per-key table is the wrong unit for this question.
fn collapse(run: &mut Run, operator: &str, earned: u128) {
    let opened: u128 = run
        .payoffs
        .iter()
        .filter(|payoff| payoff.player.starts_with(operator))
        .map(|payoff| payoff.opened)
        .sum();
    let spent: u128 = run
        .payoffs
        .iter()
        .filter(|payoff| payoff.player.starts_with(operator))
        .map(|payoff| payoff.spent)
        .sum();
    run.payoffs
        .retain(|payoff| !payoff.player.starts_with(operator) || payoff.player == operator);
    if let Some(payoff) = run
        .payoffs
        .iter_mut()
        .find(|payoff| payoff.player == operator)
    {
        payoff.player = format!("{operator} (all keys)");
        payoff.opened = opened;
        payoff.spent = spent;
        payoff.closed = opened.saturating_add(earned);
    }
    run.payoffs
        .sort_by_key(|payoff| std::cmp::Reverse(payoff.net()));
}

// ---------------------------------------------------------------------------
// 3. Griefing disputes
// ---------------------------------------------------------------------------

/// **Attack.** Open bonded objections to honest claims, answer nothing, and let
/// the windows hold up other people's payouts.
///
/// **Defence.** The bond, plus forfeiture on silence. A challenger who stops
/// answering loses, so stalling costs what losing costs.
///
/// # Two defences, and only one of them is being measured
///
/// The first version of this scenario funded objectives with no **stepper**, so
/// every objection was refused before its bond was even considered — a dispute
/// the network could never adjudicate cannot be opened at all. That is a real
/// and stronger property, and it made the run measure nothing about bonds. It
/// is reported separately as [`unbisectable_objectives`].
///
/// Here the objectives *are* bisectable, so the objection is admissible and the
/// bond is what stands between an honest submitter and a free denial of
/// service.
pub fn griefing_disputes(seed: u64) -> Trial {
    Trial {
        attack: "griefing disputes".to_string(),
        defence: "a bond, forfeited on silence".to_string(),
        attacker: "griefer".to_string(),
        benchmark: None,
        // The harm a griefer does lands on the submitter it stalls, not on its
        // own balance, so the trial names both.
        victim: Some("honest".to_string()),
        undefended: grief_run(seed, 0),
        defended: grief_run(seed, 2_000),
    }
}

/// The other half: an objective with no step function cannot be disputed at
/// all, so a griefer has nothing to open.
pub fn unbisectable_objectives(seed: u64) -> Trial {
    Trial {
        attack: "griefing a plain objective".to_string(),
        defence: "an objective with no stepper cannot be disputed".to_string(),
        attacker: "griefer".to_string(),
        benchmark: None,
        victim: Some("honest".to_string()),
        undefended: grief_plain_run(seed),
        defended: grief_plain_run(seed),
    }
}

const TRACE_STATES: usize = 9;

fn grief_run(seed: u64, bond: u64) -> Run {
    let mut arena = Arena::new(
        &format!("grief-{bond}"),
        seed,
        &["griefer", "honest"],
        10_000,
        1_000_000,
    );
    for round in 0..3u64 {
        let Some(objective) = arena.fund_bisectable("treasury", 1_000, &format!("g{round}")) else {
            continue;
        };
        let Some((claim, states)) =
            arena.submit_traced("honest", &objective, &format!("n{round}"), TRACE_STATES)
        else {
            continue;
        };
        // Object, then answer nothing at all. The griefer's whole move.
        let opened = arena.grief(&claim, states, bond);
        arena.tick();
        arena.tick();
        // Long enough for the answer window to shut on the silent party.
        for _ in 0..8 {
            arena.tick();
        }
        if let Some(id) = opened {
            arena.settle_dispute(&id);
        }
    }
    arena.finish(&format!("griefing / bond {bond}"), false)
}

fn grief_plain_run(seed: u64) -> Run {
    let mut arena = Arena::new(
        "grief-plain",
        seed,
        &["griefer", "honest"],
        10_000,
        1_000_000,
    );
    for round in 0..3u64 {
        let Some(objective) = arena.fund("treasury", 1_000, &format!("p{round}")) else {
            continue;
        };
        if let Some(claim) = arena.submit("honest", &objective, true, &format!("n{round}")) {
            arena.grief(&claim, TRACE_STATES, 2_000);
        }
        arena.tick();
        arena.tick();
    }
    arena.finish("griefing a plain objective", false)
}

// ---------------------------------------------------------------------------
// 4. Standing bought on the cheapest tier
// ---------------------------------------------------------------------------

/// **Attack.** Earn on the cheapest verifier tier, then spend the proceeds
/// where expensive work is priced.
///
/// **Defence.** Claim assets typed by tier: a unit minted by settling a claim
/// carries the tier of the objective's verifier and does not convert.
///
/// The undefended run is the same log read with tiers ignored — the balance
/// total, which is what every rule in this crate used before `src/tier.rs`. So
/// the two runs are the *same history* scored two ways, which is the cleanest
/// form this comparison can take: nothing about the attacker's behaviour
/// differs, only what the rules make of it.
pub fn cheap_tier_standing(seed: u64) -> Trial {
    let (defended, undefended) = tier_runs(seed);
    Trial {
        attack: "standing bought on the cheapest tier".to_string(),
        defence: "claim assets typed by verification tier".to_string(),
        attacker: "miller".to_string(),
        benchmark: None,
        victim: None,
        undefended,
        defended,
    }
}

fn tier_runs(seed: u64) -> (Run, Run) {
    let mut arena = Arena::new("tier", seed, &["miller"], 0, 1_000_000);
    for round in 0..6u64 {
        let Some(objective) = arena.fund("treasury", 1_000, &format!("t{round}")) else {
            continue;
        };
        arena.submit("miller", &objective, true, &format!("n{round}"));
        arena.tick();
        arena.tick();
    }

    // What the miller holds, and what it can actually spend where expensive
    // work is priced. Read before `finish` consumes the arena.
    let who = arena.who("miller");
    let positions = arena.node().ledger().len();
    let total = arena.node().balances().get(&who).copied().unwrap_or(0);
    let usable_on_lean =
        arena
            .node()
            .spendable_in(&who, Tier::parse("lean").expect("a known tier"), positions);

    let mut defended = arena.finish("cheap-tier standing / typed", false);
    // The defended run credits the attacker only with what the tier rules let
    // it spend where it wanted to spend it. The undefended run is the same
    // history scored the old way: one fungible total.
    let mut undefended = defended.clone();
    undefended.label = "cheap-tier standing / untyped".to_string();
    for payoff in &mut defended.payoffs {
        if payoff.player == "miller" {
            payoff.closed = usable_on_lean;
        }
    }
    for payoff in &mut undefended.payoffs {
        if payoff.player == "miller" {
            payoff.closed = total;
        }
    }
    (defended, undefended)
}

// ---------------------------------------------------------------------------
// 5. Availability free-riding
// ---------------------------------------------------------------------------

/// **Attack.** Promise to hold the log, hold nothing, collect a share of the
/// storage pool.
///
/// **Defence.** Sample it. The challenge is a pure function of the log, so
/// nobody issues it and nobody can decline to; a node that did not keep the
/// bytes cannot produce the entry, and the settlement pays the answered and
/// names the silent.
///
/// Undefended is modelled by paying every *promise* rather than every answer,
/// which is what a pool split on promises alone would do.
pub fn availability_free_riding(seed: u64) -> Trial {
    Trial {
        attack: "availability free-riding".to_string(),
        defence: "sampling, and paying only the answered".to_string(),
        attacker: "freerider".to_string(),
        // A node that actually kept the log, with the same stake.
        benchmark: Some("holder".to_string()),
        victim: None,
        undefended: availability_run(seed, false),
        defended: availability_run(seed, true),
    }
}

fn availability_run(seed: u64, sampled: bool) -> Run {
    let label = if sampled { "sampled" } else { "unsampled" };
    let mut arena = Arena::new(
        &format!("avail-{label}"),
        seed,
        &["freerider", "holder"],
        8_000,
        1_000_000,
    );
    arena.undertake("freerider", 4_000);
    arena.undertake("holder", 4_000);

    let ts = arena.now();
    let epoch = crate::partition::epoch_of(
        crate::time::parse_rfc3339(&ts).unwrap_or(0) as u64,
        crate::partition::EPOCH_SECONDS,
    );
    let first_paid_epoch = epoch + 1;
    let pool = crate::records::AvailabilityPool {
        funder: arena.who("treasury"),
        per_epoch: 2_000,
        from_epoch: first_paid_epoch,
        to_epoch: first_paid_epoch + 8,
        created_at: ts.clone(),
    };
    let _ = arena.node_mut().post_availability_pool(&pool, &ts);
    arena.tick();

    for _ in 0..6 {
        // The holder keeps the log and can answer. The free-rider did not, and
        // *therefore* cannot — not answering is the consequence of not storing
        // rather than a choice the scenario makes for it.
        arena.answer("holder", true);
        arena.answer("freerider", !sampled);
        arena.settle_availability_now();
        arena.tick();
    }
    arena.finish(&format!("availability free-riding / {label}"), false)
}

// ---------------------------------------------------------------------------

fn checker_sha(root: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(root.join("c.py")).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    crate::hex::encode(&hasher.finalize())
}

/// Print a set of trials the way an operator wants to read them.
pub fn report(trials: &[Trial], costs: Costs) -> String {
    let mut out = String::new();
    out.push_str("cairn arena -- strategies played against the real rules engine\n");
    out.push_str(&format!(
        "modelled costs: verify {} answer {} mint {} solve {}\n",
        costs.verify, costs.answer, costs.mint_canary, costs.solve
    ));
    out.push_str("(every other number below is read out of settled balances)\n\n");
    for trial in trials {
        out.push_str(&format!("== {}\n", trial.attack));
        out.push_str(&format!("   defence: {}\n", trial.defence));
        out.push_str(&format!("   {}\n", trial.verdict()));
        if let (Some(victim), Some((with, without))) = (&trial.victim, trial.victim_swing()) {
            out.push_str(&format!(
                "   victim {victim}: nets {without} undefended, {with} defended\n"
            ));
        }
        for run in [&trial.undefended, &trial.defended] {
            out.push_str(&format!("   -- {} ({} epochs)\n", run.label, run.epochs));
            for payoff in &run.payoffs {
                out.push_str(&format!("      {payoff}\n"));
            }
            if !run.problems.is_empty() {
                out.push_str(&format!("      audit: {} problem(s)\n", run.problems.len()));
                for problem in run.problems.iter().take(3) {
                    out.push_str(&format!("        ! {problem}\n"));
                }
            }
        }
        out.push('\n');
    }
    out
}
