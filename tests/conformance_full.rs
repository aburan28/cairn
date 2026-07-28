//! The rest of the cross-implementation contract.
//!
//! `tests/conformance.rs` pins canonical bytes and merkle roots -- the format
//! layer. This file pins everything built on top of it: record identity, the
//! ratchet payout curve, citation flow, work assignment, and gossip identity,
//! all against `conformance/vectors.json`, which was generated from the Python
//! reference implementation by `scripts/gen_conformance.py`.
//!
//! Why this matters more than an ordinary regression suite: a failure here does
//! not mean "this crate has a bug". It means this crate and the reference
//! implementation would compute *different ids for the same object*, and each
//! would be internally consistent while doing so. Two operators would disagree
//! about which objective was funded, which artifact was accepted, and who was
//! paid -- silently, with no error anywhere. That is the one failure mode the
//! whole design exists to prevent, which is why changing a vector is a
//! migration of every id ever issued rather than an edit.
//!
//! Everything is driven from the vector file rather than from constants copied
//! into the test: hard-coding the expectations here would let the file and the
//! test drift apart, and the file is the artifact CI regenerates.
//!
//! Public API only (`use proofwork::...`), so this also checks that a reader
//! holding nothing but a copy of the log and this crate can re-derive every
//! settled result -- which is the guarantee Stage 0 actually makes.

use std::collections::{BTreeMap, BTreeSet};

use proofwork::attribution::{flow, FlowParams};
use proofwork::canonical::Value;
use proofwork::frontier::Ratchet;
use proofwork::gossip::Candidate;
use proofwork::partition::{assign, assignment_for, beacon};
use proofwork::records::{commitment_hash, Claim, Commitment, Objective};

// -- vector plumbing -------------------------------------------------------
//
// These helpers panic on a malformed vector file. That is correct here and
// nowhere else in the crate: a vector file that does not parse is a broken
// test fixture, not a runtime condition to recover from.

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/vectors.json"
    ))
    .expect("conformance/vectors.json is missing");
    Value::from_json(&text).expect("vectors.json must itself be canonical-parseable")
}

fn section<'a>(vectors: &'a Value, name: &str) -> &'a Value {
    vectors
        .get(name)
        .unwrap_or_else(|| panic!("vectors.json has no {name:?} section"))
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("vector case is missing {key:?}"))
}

fn text_of<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("vector field {key:?} must be a string"))
}

fn i64_of(value: &Value, key: &str) -> i64 {
    field(value, key)
        .as_i64()
        .unwrap_or_else(|| panic!("vector field {key:?} must fit an i64"))
}

fn u64_of(value: &Value, key: &str) -> u64 {
    field(value, key)
        .as_u64()
        .unwrap_or_else(|| panic!("vector field {key:?} must fit a u64"))
}

fn u32_of(value: &Value, key: &str) -> u32 {
    let raw = u64_of(value, key);
    u32::try_from(raw).unwrap_or_else(|_| panic!("vector field {key:?} must fit a u32"))
}

fn list_of<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    field(value, key)
        .as_array()
        .unwrap_or_else(|| panic!("vector field {key:?} must be an array"))
}

fn map_of<'a>(value: &'a Value, key: &str) -> &'a BTreeMap<String, Value> {
    field(value, key)
        .as_object()
        .unwrap_or_else(|| panic!("vector field {key:?} must be an object"))
}

/// Re-encoding a decoded record must reproduce the vector's bytes exactly.
///
/// Id equality alone would not catch a decoder that drops a field the encoder
/// then re-invents from a default: the two errors could cancel on this fixture
/// and diverge on the next record. Comparing canonical text catches it, and
/// gives a readable diff when it fires.
fn assert_reencodes(actual: &Value, expected: &Value, what: &str) {
    assert_eq!(
        actual.canonical_string(),
        expected.canonical_string(),
        "{what}: re-encoded form differs from the vector"
    );
}

#[test]
fn every_section_this_file_covers_is_present_and_populated() {
    // A truncated or half-written vectors.json must fail loudly rather than
    // let every loop below iterate zero times and report success.
    let v = vectors();
    let records = section(&v, "records");
    assert_eq!(list_of(records, "objectives").len(), 3);
    assert_eq!(list_of(records, "claims").len(), 2);
    assert_eq!(list_of(records, "commitments").len(), 1);
    assert_eq!(list_of(records, "commitment_hash_cases").len(), 5);
    assert_eq!(list_of(&v, "ratchet").len(), 5);
    assert_eq!(list_of(section(&v, "attribution"), "cases").len(), 192);
    assert_eq!(list_of(&v, "partition").len(), 8);
    assert_eq!(list_of(&v, "gossip").len(), 12);
}

// -- records ---------------------------------------------------------------

#[test]
fn objective_ids_match_the_reference_implementation() {
    let v = vectors();
    let cases = list_of(section(&v, "records"), "objectives");
    let mut ids: BTreeSet<String> = BTreeSet::new();

    for (i, case) in cases.iter().enumerate() {
        let record = field(case, "record");
        let expected_id = text_of(case, "id");
        let objective = Objective::from_value(record)
            .unwrap_or_else(|e| panic!("objective {i} does not decode: {e}"));

        assert_eq!(objective.id(), expected_id, "objective {i}: id differs");
        assert_reencodes(&objective.to_value(), record, "objective");

        // The same record built through the constructor rather than the
        // decoder. Both paths feed one `to_value`, but only this proves a
        // caller assembling an objective from parts lands on the pinned id.
        let rebuilt = Objective::new(
            objective.goal.clone(),
            objective.statement.clone(),
            objective.verifier.clone(),
            objective.reward,
            objective.funder.clone(),
            objective.created_at.clone(),
            objective.deadline.clone(),
            objective.ratchet.clone(),
        )
        .unwrap_or_else(|e| panic!("objective {i} fails its own validation: {e}"));
        assert_eq!(
            rebuilt.id(),
            expected_id,
            "objective {i}: constructed id differs"
        );

        // A ratchet block is part of the objective's content address, and the
        // pool it names is the objective's own -- there is one pool, not two.
        if let Some(block) = &objective.ratchet {
            let ratchet = Ratchet::from_value(block)
                .unwrap_or_else(|e| panic!("objective {i} carries an invalid ratchet: {e}"));
            assert_eq!(
                ratchet.reward, objective.reward,
                "objective {i}: ratchet pool must be the objective's pool"
            );
        }

        ids.insert(objective.id());
    }

    // The three fixtures differ only in deadline, verifier and ratchet. Equal
    // ids here would mean one of those had fallen out of the identity, which is
    // exactly how "editing an evaluator silently rescores finished work" gets
    // in.
    assert_eq!(
        ids.len(),
        cases.len(),
        "objective identity is not covering every field"
    );
}

#[test]
fn claim_ids_artifact_ids_and_commitment_hashes_match_the_reference_implementation() {
    let v = vectors();
    let cases = list_of(section(&v, "records"), "claims");

    for (i, case) in cases.iter().enumerate() {
        let record = field(case, "record");
        let claim =
            Claim::from_value(record).unwrap_or_else(|e| panic!("claim {i} does not decode: {e}"));

        assert_eq!(claim.id(), text_of(case, "id"), "claim {i}: id differs");
        // Identity of the artifact alone, scoped by objective: this is what
        // makes a copied artifact recognisable as the same work no matter who
        // reveals it, so it is pinned separately from the claim id.
        assert_eq!(
            claim.artifact_id(),
            text_of(case, "artifact_id"),
            "claim {i}: artifact id differs"
        );
        // The commitment this claim opens. Disagreement here means a reveal
        // accepted by one implementation is rejected by the other.
        assert_eq!(
            claim.commitment_hash(),
            text_of(case, "commitment_hash"),
            "claim {i}: commitment hash differs"
        );
        assert_reencodes(&claim.to_value(), record, "claim");

        let rebuilt = Claim::new(
            claim.objective_id.clone(),
            claim.submitter.clone(),
            claim.artifact.clone(),
            claim.nonce.clone(),
            claim.created_at.clone(),
            claim.cites.clone(),
        )
        .unwrap_or_else(|e| panic!("claim {i} fails its own validation: {e}"));
        assert_eq!(
            rebuilt.id(),
            claim.id(),
            "claim {i}: constructed id differs"
        );
    }

    // The second fixture cites the first by id. The citation edge is a hash
    // link, so this also checks the two ids agree across records rather than
    // only against their own vector entry.
    let first = Claim::from_value(field(cases.first().expect("two claim vectors"), "record"))
        .expect("first claim decodes");
    let second = Claim::from_value(field(cases.get(1).expect("two claim vectors"), "record"))
        .expect("second claim decodes");
    assert_eq!(
        second.cites,
        vec![first.id()],
        "the citation DAG in the vectors does not link up"
    );
}

#[test]
fn commitment_ids_match_the_reference_implementation() {
    let v = vectors();
    let records = section(&v, "records");
    let cases = list_of(records, "commitments");

    for (i, case) in cases.iter().enumerate() {
        let record = field(case, "record");
        let commitment = Commitment::from_value(record)
            .unwrap_or_else(|e| panic!("commitment {i} does not decode: {e}"));
        assert_eq!(
            commitment.id(),
            text_of(case, "id"),
            "commitment {i}: id differs"
        );
        assert_reencodes(&commitment.to_value(), record, "commitment");

        let rebuilt = Commitment::new(
            commitment.objective_id.clone(),
            commitment.submitter.clone(),
            commitment.hash.clone(),
            commitment.created_at.clone(),
        );
        assert_eq!(
            rebuilt.id(),
            commitment.id(),
            "commitment {i}: constructed id differs"
        );
    }

    // Commit-then-reveal only works if the two halves meet: the commitment in
    // the vectors is the one the first claim opens. If these two ever disagree,
    // an honest submitter's reveal is refused and their work is unpayable.
    let commitment = Commitment::from_value(field(
        cases.first().expect("one commitment vector"),
        "record",
    ))
    .expect("commitment decodes");
    let claim = Claim::from_value(field(
        list_of(records, "claims")
            .first()
            .expect("two claim vectors"),
        "record",
    ))
    .expect("claim decodes");
    assert_eq!(
        commitment.hash,
        claim.commitment_hash(),
        "the vectors' commitment does not open to the vectors' claim"
    );
    assert_eq!(commitment.submitter, claim.submitter);
    assert_eq!(commitment.objective_id, claim.objective_id);
}

#[test]
fn commitment_hashes_match_the_reference_implementation() {
    let v = vectors();
    let cases = list_of(section(&v, "records"), "commitment_hash_cases");
    let mut hashes: BTreeSet<String> = BTreeSet::new();

    for (i, case) in cases.iter().enumerate() {
        let hash = commitment_hash(
            text_of(case, "objective_id"),
            text_of(case, "submitter"),
            field(case, "artifact"),
            text_of(case, "nonce"),
        );
        assert_eq!(
            hash,
            text_of(case, "hash"),
            "commitment hash case {i} differs"
        );
        hashes.insert(hash);
    }

    // Each fixture differs from the first in exactly one input -- submitter,
    // artifact, nonce -- so distinct hashes are the evidence that all three are
    // actually bound in. If the submitter were not, an observer could replay
    // somebody else's commitment under their own name and steal the work.
    assert_eq!(
        hashes.len(),
        cases.len(),
        "two commitment inputs collide; some input is not bound into the hash"
    );
}

// -- ratchet ---------------------------------------------------------------

#[test]
fn ratchet_progress_and_cumulative_match_the_reference_implementation() {
    let v = vectors();
    let specs = list_of(&v, "ratchet");

    for (i, case) in specs.iter().enumerate() {
        let ratchet = Ratchet::from_value(field(case, "ratchet"))
            .unwrap_or_else(|e| panic!("ratchet spec {i} does not decode: {e}"));

        for (j, point) in list_of(case, "points").iter().enumerate() {
            let score = i64_of(point, "score");
            assert_eq!(
                ratchet.progress(score),
                u64_of(point, "progress"),
                "spec {i} point {j}: progress at score {score} differs"
            );
            assert_eq!(
                ratchet.cumulative(score),
                Ok(u64_of(point, "cumulative")),
                "spec {i} point {j}: cumulative at score {score} differs"
            );
        }
    }
}

#[test]
fn ratchet_payouts_telescope_to_the_pool_over_the_vector_points() {
    // The vectors pin `cumulative`; this derives `payout` from the same points
    // and checks the property the cumulative formula exists to provide -- that
    // paying out along the curve, in whatever steps, totals the pool exactly.
    // A network where chopping an improvement into pieces extracts more than
    // one big step would be farmed within a day.
    let v = vectors();
    let specs = list_of(&v, "ratchet");

    for (i, case) in specs.iter().enumerate() {
        let ratchet = Ratchet::from_value(field(case, "ratchet"))
            .unwrap_or_else(|e| panic!("ratchet spec {i} does not decode: {e}"));
        let points = list_of(case, "points");

        // u128 so a bug that over-pays shows up as a wrong total rather than
        // as an overflow in the test itself: the largest vector pool is 1e18.
        let mut total: u128 = 0;
        let mut previous: Option<i64> = None;
        for point in points {
            let score = i64_of(point, "score");
            let paid = ratchet
                .payout(previous, score)
                .unwrap_or_else(|e| panic!("spec {i}: payout at {score} failed: {e}"));
            total = total.saturating_add(u128::from(paid));
            previous = Some(score);
        }

        let last = points.last().expect("every spec has points");
        assert_eq!(
            total,
            u128::from(u64_of(last, "cumulative")),
            "spec {i}: payouts do not telescope to the final cumulative"
        );
        assert_eq!(
            total,
            u128::from(ratchet.reward),
            "spec {i}: the pool is not exactly exhausted at the target"
        );
        // The final point overshoots the target in every spec; overshooting
        // must not mint progress the pool cannot fund.
        assert!(
            ratchet.exhausted(i64_of(last, "score")),
            "spec {i}: the final vector point should exhaust the ratchet"
        );
    }
}

// -- attribution -----------------------------------------------------------

/// Rebuild the claim DAG the attribution vectors were generated over.
///
/// Keyed by `claim.id()` rather than by any id written in the file: that is how
/// a node indexes claims off its own log, so it also re-checks that the records
/// in the vectors hash to the ids the vectors expect.
fn attribution_claims(attribution: &Value) -> BTreeMap<String, Claim> {
    let mut claims: BTreeMap<String, Claim> = BTreeMap::new();
    for (i, record) in list_of(attribution, "claims").iter().enumerate() {
        let claim = Claim::from_value(record)
            .unwrap_or_else(|e| panic!("attribution claim {i} does not decode: {e}"));
        assert_reencodes(&claim.to_value(), record, "attribution claim");
        claims.insert(claim.id(), claim);
    }
    claims
}

#[test]
fn attribution_dag_reconstructs_with_the_reference_ids() {
    let v = vectors();
    let s = section(&v, "attribution");
    let claims = attribution_claims(s);
    assert_eq!(claims.len(), 4, "the diamond has four distinct claims");

    let by_submitter: BTreeMap<&str, &str> = claims
        .iter()
        .map(|(id, claim)| (claim.submitter.as_str(), id.as_str()))
        .collect();
    for (submitter, expected) in map_of(s, "claim_ids") {
        let expected = expected
            .as_str()
            .unwrap_or_else(|| panic!("claim id for {submitter} must be a string"));
        let actual = by_submitter
            .get(submitter.as_str())
            .copied()
            .unwrap_or_else(|| panic!("no reconstructed claim from {submitter}"));
        assert_eq!(actual, expected, "claim id for {submitter} differs");
    }

    // The settling claim must resolve inside the DAG, and its citations must
    // resolve too. An id that does not resolve is not a payout dispute, it is
    // an edge that silently disappears -- so payouts would still conserve while
    // paying the wrong people.
    let root = text_of(s, "root");
    let dave = claims
        .get(root)
        .unwrap_or_else(|| panic!("the settling claim {root} is not in the DAG"));
    assert_eq!(dave.submitter, "dave");
    for cited in &dave.cites {
        assert!(
            claims.contains_key(cited),
            "citation {cited} does not resolve"
        );
    }
    assert_eq!(dave.cites.len(), 2, "dave cites carol and alice");
}

#[test]
fn attribution_payouts_match_the_reference_implementation() {
    let v = vectors();
    let s = section(&v, "attribution");
    let claims = attribution_claims(s);
    let root = text_of(s, "root");
    let cases = list_of(s, "cases");
    assert_eq!(cases.len(), 192, "the full amount x delta x depth grid");

    for (i, case) in cases.iter().enumerate() {
        let amount = u64_of(case, "amount");
        let num = u64_of(case, "delta_num");
        let den = u64_of(case, "delta_den");
        let depth = u32_of(case, "max_depth");
        let params = FlowParams::new(num, den, depth)
            .unwrap_or_else(|e| panic!("case {i}: vector params are invalid: {e}"));

        let expected: BTreeMap<String, u64> = map_of(case, "payouts")
            .iter()
            .map(|(who, units)| {
                let units = units
                    .as_u64()
                    .unwrap_or_else(|| panic!("case {i}: payout for {who} must be a u64"));
                (who.clone(), units)
            })
            .collect();

        let actual = flow(root, amount, &claims, &params);
        // Exact map equality, not "same totals": a submitter that keeps zero
        // units still appears with a zero value (this happens when delta == 1
        // and the claim passes everything on). Dropping those keys would make
        // the two implementations report different payout maps for the same
        // settlement.
        assert_eq!(
            actual, expected,
            "case {i}: amount {amount}, delta {num}/{den}, depth {depth}"
        );

        // Conservation, checked independently of the expected map. Rounding an
        // uneven split must never leak a unit (money vanishes) or invent one
        // (money is minted), at any amount or any delta.
        let total: u128 = actual.values().map(|units| u128::from(*units)).sum();
        assert_eq!(
            total,
            u128::from(amount),
            "case {i}: payouts do not sum to the amount distributed"
        );
    }
}

// -- partition -------------------------------------------------------------

#[test]
fn partition_beacons_match_the_reference_implementation() {
    let v = vectors();
    let specs = list_of(&v, "partition");

    for (i, spec) in specs.iter().enumerate() {
        let epoch = u64_of(spec, "epoch");
        let anchor = text_of(spec, "anchor");
        let expected = text_of(spec, "beacon");
        assert_eq!(
            beacon(epoch, anchor),
            expected,
            "spec {i}: beacon for epoch {epoch} differs"
        );

        // The beacon is HMAC key material, fed to `assign` as text, so its
        // spelling is part of the wire format: bare lowercase hex with no
        // `sha256:` prefix. Prefixing it would move every assignment in the
        // network, and the change would look like a cosmetic one.
        assert_eq!(
            expected.len(),
            64,
            "spec {i}: beacon is not 32 bytes of hex"
        );
        assert!(
            !expected.starts_with("sha256:"),
            "spec {i}: beacon must not carry the digest prefix"
        );
        assert!(
            expected
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "spec {i}: beacon must be lowercase hex"
        );
    }
}

#[test]
fn partition_assignments_match_the_reference_implementation() {
    let v = vectors();
    let specs = list_of(&v, "partition");
    let mut checked = 0usize;

    for (i, spec) in specs.iter().enumerate() {
        let epoch = u64_of(spec, "epoch");
        let anchor = text_of(spec, "anchor");
        let epoch_beacon = beacon(epoch, anchor);

        for (j, expected) in list_of(spec, "assignments").iter().enumerate() {
            let node_id = text_of(expected, "node_id");
            let objective_id = text_of(expected, "objective_id");
            let partitions = u32_of(expected, "partitions");
            let partition = u32_of(expected, "partition");

            assert_eq!(
                assign(node_id, objective_id, &epoch_beacon, partitions),
                Ok(partition),
                "spec {i} assignment {j}: {node_id} over {partitions} partitions"
            );

            // The packaged path, which derives the beacon itself. It must agree
            // with the manual one: a node computes its own assignment through
            // `assignment_for`, and anyone auditing "did you search your own
            // region?" recomputes it through `assign`. If those two disagreed,
            // the audit would be against a different assignment than the one
            // the node actually used.
            let packaged = assignment_for(node_id, objective_id, epoch, anchor, partitions)
                .unwrap_or_else(|e| panic!("spec {i} assignment {j}: {e}"));
            assert_eq!(packaged.partition, partition);
            assert_eq!(packaged.partitions, partitions);
            assert_eq!(packaged.epoch, epoch);
            assert_eq!(packaged.node_id, node_id);
            assert_eq!(packaged.objective_id, objective_id);
            assert!(
                packaged.partition < packaged.partitions,
                "spec {i} assignment {j}: partition index is out of range"
            );

            checked += 1;
        }
    }

    assert_eq!(checked, 8 * 24, "every pinned assignment must be exercised");
}

// -- gossip ----------------------------------------------------------------

#[test]
fn gossip_candidate_ids_and_islands_match_the_reference_implementation() {
    let v = vectors();
    let cases = list_of(&v, "gossip");

    for (i, case) in cases.iter().enumerate() {
        let record = field(case, "candidate");
        let candidate = Candidate::from_value(record)
            .unwrap_or_else(|e| panic!("candidate {i} does not decode: {e}"));

        // Identity includes the claimed score, deliberately: two peers can
        // gossip the same artifact at different scores, one honestly and one
        // lying, and both entries must be representable side by side.
        assert_eq!(
            candidate.id(),
            text_of(case, "id"),
            "candidate {i}: id differs"
        );
        assert_eq!(
            candidate.artifact_id(),
            text_of(case, "artifact_id"),
            "candidate {i}: artifact id differs"
        );
        assert_reencodes(&candidate.to_value(), record, "candidate");

        let rebuilt = Candidate::new(
            candidate.objective_id.clone(),
            candidate.artifact.clone(),
            candidate.score,
            candidate.origin.clone(),
        );
        assert_eq!(
            rebuilt.id(),
            candidate.id(),
            "candidate {i}: constructed id differs"
        );

        for (count, expected) in map_of(case, "islands") {
            let islands: u32 = count
                .parse()
                .unwrap_or_else(|_| panic!("candidate {i}: island count {count:?} is not a u32"));
            let expected = expected
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or_else(|| panic!("candidate {i}: island index must be a u32"));
            assert_eq!(
                candidate.island(islands),
                expected,
                "candidate {i}: island over {islands} buckets differs"
            );
            assert!(
                candidate.island(islands) < islands,
                "candidate {i}: island index outside 0..{islands}"
            );
        }
    }
}

#[test]
fn gossip_islands_are_keyed_by_artifact_not_by_claimed_score() {
    // Derived from the same vectors: the fixtures are three artifacts at four
    // scores each. Island membership must be a function of the artifact alone,
    // so an artifact's honest and inflated variants land in the same island and
    // compete for one slot. Keying on the full candidate id instead would let a
    // liar occupy a second slot in a bounded population -- a cheap way to evict
    // genuine candidates and starve the search.
    let v = vectors();
    let cases = list_of(&v, "gossip");

    let mut by_artifact: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
    for (i, case) in cases.iter().enumerate() {
        let candidate = Candidate::from_value(field(case, "candidate"))
            .unwrap_or_else(|e| panic!("candidate {i} does not decode: {e}"));
        by_artifact
            .entry(candidate.artifact_id())
            .or_default()
            .push(candidate);
    }
    assert_eq!(
        by_artifact.len(),
        3,
        "three distinct artifacts in the vectors"
    );

    for (artifact_id, group) in &by_artifact {
        assert_eq!(group.len(), 4, "{artifact_id}: four scores per artifact");

        let ids: BTreeSet<String> = group.iter().map(|c| c.id()).collect();
        assert_eq!(
            ids.len(),
            group.len(),
            "{artifact_id}: differing scores must be distinct candidates"
        );

        for islands in [1u32, 2, 4, 8, 64] {
            let buckets: BTreeSet<u32> = group.iter().map(|c| c.island(islands)).collect();
            assert_eq!(
                buckets.len(),
                1,
                "{artifact_id}: one artifact spread across islands at {islands} buckets"
            );
        }
    }
}
