//! Every funded example, checked for the two ways a bounty can be unwinnable.
//!
//! `scripts/check-examples.sh` already proves that every `objective*.json`
//! resolves its pins and passes the published schema. Both are about whether the
//! objective is *well formed*. Neither asks whether it can be **won**, and a
//! bounty that cannot be won is well formed by construction — that is what makes
//! it hard to notice.
//!
//! Two failures are checked here, and the difference between them is the whole
//! point:
//!
//! - **Never pays.** `min_improvement` exceeds the whole baseline-to-target span,
//!   so progress clamps below the gate and no claim at any score ever settles.
//!   [`Ratchet::is_fundable`] answers it, and `cairn post` warns, but nothing
//!   stopped one being committed to the repository.
//! - **Pays once and shuts.** The frontier lands within `min_improvement` of the
//!   target, and from then on nothing settles while money is still in the pool.
//!   This is the one that actually happens, because it needs no mistake in the
//!   arithmetic — only a gate wider than the last stretch of the curve.
//!
//! The second is a judgement call in general: how much of a pool a funder is
//! willing to risk stranding is theirs to decide, and this file does not have an
//! opinion. But there is one case that needs no judgement at all, and it is
//! checkable from what the repository already contains: **an example that ships
//! an artifact which would strand part of its own pool.** That is a bounty whose
//! own directory holds the submission that ends it early. No estimate of the
//! state of the art is required, because the state of the art is checked in next
//! to the objective.
//!
//! # What that misses, exactly
//!
//! The narrowness is the price of needing no judgement, and it is worth being
//! precise about rather than leaving a reader to assume more coverage than
//! exists. The check fires only when a shipped artifact scores strictly *between*
//! the closing score and the target — good enough to enter the dead zone, not
//! good enough to reach the end. So:
//!
//! - An example that ships only a **baseline** cannot trigger it, however coarse
//!   its gate. `faster-algorithms` and `hash-differential` are in that position:
//!   their bounties are open and their artifacts are starting points. (Both
//!   happen to use `min_improvement: 1` and strand nothing, so there is nothing
//!   to catch — but the check is not what establishes that.)
//! - An example whose best artifact **reaches the target** cannot trigger it
//!   either, because reaching the target pays the pool out in full. That covers
//!   `capset_progressive`, `golomb-ruler` and `sorting-network`, each of which
//!   ships its optimum.
//!
//! What is left is the case where the field has already passed the closing score
//! without reaching the target, which is where a real bounty lives and where the
//! live ecdsa-fail objective sits. `cairn post` covers the rest by printing the
//! closing score at funding time, so a funder can make the comparison this file
//! cannot.
//!
//! # Why this is a test and not a line in `check-examples.sh`
//!
//! It needs `Ratchet`'s arithmetic and the verifier registry, and a shell script
//! would have to reimplement the first. Two implementations of the money path
//! that can disagree is the thing this repository is most careful about, and a
//! check that quietly computed payouts differently from the settlement it guards
//! would be worse than no check.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cairn::canonical::Value;
use cairn::frontier::Ratchet;
use cairn::records::Objective;
use cairn::verifiers::{Status, VerifierRegistry};

const REPO_ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Objectives allowed to ship an artifact that strands part of their pool, and
/// why.
///
/// One entry, and it is deliberate rather than tolerated:
/// `examples/ecdsa-fail/objective-live.json` is the *worked example* of this
/// failure. `examples/ecdsa-fail/GAP.md` item 7 uses its real numbers to explain
/// how a ratchet strands its own pool, and `tests/ecdsa_fail.rs` pins the
/// behaviour end to end. Repricing it would delete the illustration, and it is
/// also not this file's call: changing a posted objective's parameters changes
/// its content address, which is the funder's decision and not a test's.
///
/// A new entry here should be very hard to justify. The check exists because
/// nothing caught this one when it landed.
const STRANDING_IS_THE_POINT: &[&str] = &["examples/ecdsa-fail/objective-live.json"];

fn repo_relative(path: &Path) -> String {
    path.strip_prefix(REPO_ROOT)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every `examples/**/objective*.json`, in a stable order.
fn example_objectives() -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk(&Path::new(REPO_ROOT).join("examples"), &mut found);
    found.sort();
    found
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("objective") && name.ends_with(".json"))
        {
            out.push(path);
        }
    }
}

fn load(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    Value::from_json(&text).ok()
}

/// The candidate artifacts shipped beside an objective: `artifact*.json` in the
/// same directory, and everything in an `artifacts/` subdirectory.
///
/// Deliberately not filtered by which objective they were written for. Several
/// examples hold more than one objective over one artifact set, and an artifact
/// meant for a sibling is simply *rejected* by this one — which is the right
/// answer and needs no bookkeeping here.
fn artifacts_beside(objective: &Path) -> Vec<PathBuf> {
    let Some(dir) = objective.parent() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_file() && name.starts_with("artifact") && name.ends_with(".json") {
                found.push(path);
            }
        }
    }
    if let Ok(entries) = fs::read_dir(dir.join("artifacts")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "json")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Every shipped objective that carries a ratchet, decoded.
fn ratcheted() -> Vec<(PathBuf, Objective, Ratchet)> {
    let mut found = Vec::new();
    for path in example_objectives() {
        let Some(value) = load(&path) else { continue };
        let Ok(objective) = Objective::from_value(&value) else {
            // Decoding is `check-examples.sh`'s business, and duplicating the
            // failure here would report one defect twice.
            continue;
        };
        let Some(block) = objective.ratchet.clone() else {
            continue;
        };
        let Ok(ratchet) = Ratchet::from_value(&block) else {
            continue;
        };
        found.push((path, objective, ratchet));
    }
    found
}

#[test]
fn there_are_progressive_examples_to_check() {
    // The guard that keeps every other test in this file honest. If the walk
    // stops finding objectives -- a moved directory, a renamed file -- every
    // assertion below passes over an empty list and this file silently checks
    // nothing.
    let found = ratcheted();
    assert!(
        found.len() >= 10,
        "found only {} progressive examples, so the walk is broken rather than \
         the examples being fine: {:?}",
        found.len(),
        found
            .iter()
            .map(|(p, _, _)| repo_relative(p))
            .collect::<Vec<_>>()
    );
}

#[test]
fn no_funded_example_is_impossible_to_win() {
    // Progress is clamped to the span, so a gate wider than the whole span is a
    // bar no claim clears however good it is, and the reward sits in the log
    // forever. `Ratchet::validate` admits it on purpose -- refusing would change
    // which records a node accepts -- so nothing stops one being committed here
    // except this.
    let mut broken = Vec::new();
    for (path, _, ratchet) in ratcheted() {
        if !ratchet.is_fundable() {
            broken.push(format!(
                "{}: min_improvement {} over a span of {}",
                repo_relative(&path),
                ratchet.min_improvement,
                ratchet.span()
            ));
        }
    }
    assert!(
        broken.is_empty(),
        "these bounties can never pay anybody: {broken:#?}"
    );
}

#[test]
fn every_progressive_example_can_reach_its_target() {
    // Weaker than it sounds, and worth stating: reaching the target must pay the
    // whole pool. If it does not, the curve's endpoints and its reward disagree
    // and the objective would strand money even on the happy path.
    for (path, _, ratchet) in ratcheted() {
        let at_target = ratchet
            .cumulative(ratchet.target)
            .unwrap_or_else(|error| panic!("{}: {error}", repo_relative(&path)));
        assert_eq!(
            at_target,
            ratchet.reward,
            "{}: reaching the target pays {at_target} of a {} pool",
            repo_relative(&path),
            ratchet.reward
        );
        assert_eq!(
            ratchet.stranded_at(ratchet.target).unwrap_or(u64::MAX),
            0,
            "{}: reaching the target still strands money",
            repo_relative(&path)
        );
    }
}

#[test]
fn no_example_ships_an_artifact_that_would_strand_its_own_pool() {
    // THE CHECK. An objective whose own directory holds a submission that shuts
    // it early is unwinnable in the way that matters: the first honest
    // contributor ends the bounty, and the rest of the pool is unreachable by
    // anybody, the funder included.
    //
    // No judgement about the state of the art is needed, which is what makes it
    // a test rather than a review comment -- the state of the art is checked in
    // beside the objective.
    let registry = VerifierRegistry::new(REPO_ROOT);
    let mut findings: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (path, objective, ratchet) in ratcheted() {
        let relative = repo_relative(&path);
        for artifact_path in artifacts_beside(&path) {
            let Some(artifact) = load(&artifact_path) else {
                continue;
            };
            let verdict = registry.run(&objective.verifier, &artifact);
            // Only accepted artifacts can move a frontier. A rejection means the
            // artifact belongs to a sibling objective or is a refusal fixture,
            // and an outage means this host could not check -- neither says
            // anything about the bounty's shape.
            if verdict.status != Status::Accept {
                continue;
            }
            let Some(score) = verdict.score() else {
                continue;
            };
            let stranded = ratchet.stranded_at(score).unwrap_or(0);
            if stranded > 0 {
                findings.entry(relative.clone()).or_default().push(format!(
                    "{} scores {score}, which shuts the objective with {stranded} of {} unpaid \
                     (closes at {}, target {})",
                    repo_relative(&artifact_path),
                    ratchet.reward,
                    ratchet.closes_at(),
                    ratchet.target
                ));
            }
        }
    }

    for exempt in STRANDING_IS_THE_POINT {
        let removed = findings.remove(*exempt);
        // An exemption that stops being needed is an exemption that should be
        // deleted, so it has to keep earning its place.
        assert!(
            removed.is_some(),
            "{exempt} is exempted from this check but no longer strands anything -- \
             remove it from STRANDING_IS_THE_POINT"
        );
    }

    assert!(
        findings.is_empty(),
        "these examples ship an artifact that ends their own bounty early. Either \
         lower min_improvement so the closing score moves toward the target, or \
         say why the objective is meant to be like this in \
         STRANDING_IS_THE_POINT:\n{findings:#?}"
    );
}

#[test]
fn the_exempted_objective_is_exactly_the_one_the_docs_describe() {
    // The exemption is only honest while it points at the case it claims to. If
    // the live ecdsa-fail objective were ever repriced, this fails and says so
    // rather than leaving a stale allowance behind.
    let path = Path::new(REPO_ROOT).join("examples/ecdsa-fail/objective-live.json");
    let objective = Objective::from_value(&load(&path).expect("the live objective is readable"))
        .expect("decodes");
    let ratchet = Ratchet::from_value(&objective.ratchet.expect("progressive")).expect("decodes");

    // The published world best at the time it was written. Its own statement
    // quotes the number.
    const WORLD_BEST: i64 = 1_483_649_332;
    assert!(
        ratchet.closes_at() > WORLD_BEST,
        "the live objective now closes at {}, which the published record does not \
         beat -- it is no longer the worked example of this failure, so the \
         exemption should go",
        ratchet.closes_at()
    );
    assert!(
        ratchet.stranded_at(WORLD_BEST).expect("a live curve") > 0,
        "the live objective no longer strands anything at the world best"
    );
}
