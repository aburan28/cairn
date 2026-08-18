//! Canaries: submissions whose verdict is known before anybody runs the check.
//!
//! `src/incentive/` computes the smallest canary rate at which verifying beats
//! rubber-stamping, and every one of those numbers is downstream of a single
//! engineering assumption: that a node cannot tell a canary from a real
//! submission without doing the work. The parameter is
//! [`NodeParams::canary_leak`](crate::incentive::NodeParams::canary_leak), it is
//! deliberately set nonzero in the reference parameters, and at `canary_leak =
//! 1` the design harness reports that **no canary rate works at all**. So the
//! generator is not a convenience around the mechanism. It *is* the mechanism.
//!
//! # What makes a canary hard to spot
//!
//! The obvious generator — write a deliberately broken artifact — fails
//! immediately, because deliberately broken artifacts look deliberately broken.
//! Hand-authored junk has the wrong shape, the wrong size, the wrong magnitudes,
//! and a node that filters on any of those gets a free canary detector.
//!
//! This generator never authors an artifact. It takes one that a real
//! contributor already submitted and applies a **single edit from a fixed
//! catalogue** ([`Edit`]), where every edit in the catalogue is chosen to be:
//!
//! - **shape preserving** — same key paths, same types, same array lengths, so
//!   a schema check or a structural fingerprint sees nothing; and
//! - **length preserving** — the canonical encoding of the canary is *byte for
//!   byte the same length* as the artifact it came from, so size does not leak
//!   either.
//!
//! Both properties are asserted over the whole catalogue by
//! `every_edit_in_the_catalogue_preserves_shape_and_length`, not
//! promised in prose. That is the strongest indistinguishability claim this
//! module makes, and it is worth stating what it does *not* cover: an adversary
//! who runs the pinned verifier can separate canaries perfectly. That is not a
//! leak, it is the point — running the verifier is the work we are trying to
//! buy.
//!
//! # The label is earned, not asserted
//!
//! A mutation is a guess. The generator does not reason about what its edit did
//! to the artifact's validity; it **runs the objective's own pinned verifier**
//! and keeps the mutant only when the verdict matches what was asked for. So a
//! canary's label is exactly as trustworthy as the verifier the network already
//! agreed to, and the generator needs to know nothing about cap sets, Collatz
//! trajectories, or Lean.
//!
//! This is also where the economics come from. Minting costs a handful of
//! verifier runs, once. [`Docket::discrepancies`] then polices an unbounded
//! number of recorded verdicts and runs **no verifier at all** — it compares
//! what the log says against what the issuer already knows. Pay for
//! verification once, spot-check forever.
//!
//! # Both directions, because there are two ways to attest without looking
//!
//! A node that blindly *rejects* everything catches every known-bad canary and
//! looks like a hero. Only a known-**good** canary catches it, which is why
//! [`Expectation`] has two variants and why
//! [`NodeParams::canary_valid_share`](crate::incentive::NodeParams::canary_valid_share)
//! exists. A docket of only bad canaries is a half-built trap; [`Docket::mix`]
//! reports which half you have.
//!
//! # What this module deliberately does not do
//!
//! It does not submit. A canary submitted from an identity that only ever
//! submits canaries is not a canary — it is a labelled sample, and the leak rate
//! is 1. Getting the artifact into the log under an identity drawn from the same
//! distribution as real contributors is a deployment problem, and pretending a
//! library call solves it would be the most expensive kind of wrong. See
//! `docs/node-incentives.md`.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::canonical::Value;
use crate::verifiers::{Status, Verdict, VerifierRegistry};

/// What the generator has established the pinned verifier will say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Expectation {
    /// A known-good canary. Catches a node that rejects without looking.
    Accepts,
    /// A known-bad canary. Catches a node that accepts without looking.
    Rejects,
}

impl Expectation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Expectation::Accepts => "accept",
            Expectation::Rejects => "reject",
        }
    }

    pub fn parse(text: &str) -> Option<Expectation> {
        match text {
            "accept" | "accepts" => Some(Expectation::Accepts),
            "reject" | "rejects" => Some(Expectation::Rejects),
            _ => None,
        }
    }

    /// The verdict status this expectation is satisfied by.
    ///
    /// Only the two settling statuses appear here. A canary whose verifier came
    /// back `Unavailable` proves nothing about the node and is never minted.
    pub fn status(&self) -> Status {
        match self {
            Expectation::Accepts => Status::Accept,
            Expectation::Rejects => Status::Reject,
        }
    }
}

impl fmt::Display for Expectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One step down into a [`Value`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Key(String),
    Index(usize),
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Key(key) => write!(f, ".{key}"),
            Step::Index(index) => write!(f, "[{index}]"),
        }
    }
}

/// A single edit, applied at one path in the artifact.
///
/// Every variant is shape preserving and canonical-length preserving. Nothing
/// else is allowed in, and adding a variant means extending
/// `every_edit_in_the_catalogue_preserves_shape_and_length` to cover it
/// — the invariant is the whole security argument, so it is enforced over the
/// catalogue rather than argued per variant.
///
/// Notably absent: flipping a boolean. `true` and `false` are four and five
/// bytes, so a flip leaks a byte of length. It would be a fine edit for a
/// generator that did not care about size, and this one does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Add `delta` to an integer, keeping its sign and decimal width.
    Shift { delta: i64 },
    /// Exchange two elements of an array. The multiset of elements — and so the
    /// total encoded length — is unchanged; only the order moves.
    Swap { left: usize, right: usize },
    /// Replace one character of a string with another **from the same character
    /// class**, so hex stays hex and digits stay digits.
    Substitute { index: usize, replacement: char },
}

impl fmt::Display for Edit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Edit::Shift { delta } => write!(f, "shift {delta:+}"),
            Edit::Swap { left, right } => write!(f, "swap {left}<->{right}"),
            Edit::Substitute { index, replacement } => {
                write!(f, "substitute [{index}]='{replacement}'")
            }
        }
    }
}

/// Where an edit landed and what it was. Kept by the issuer, never published:
/// a recipe plus the parent artifact reproduces the canary, and anyone holding
/// both can recognise every canary the same seed will ever produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    pub path: Vec<Step>,
    pub edit: Edit,
}

impl fmt::Display for Recipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "<root> {}", self.edit)
        } else {
            for step in &self.path {
                write!(f, "{step}")?;
            }
            write!(f, " {}", self.edit)
        }
    }
}

/// A minted canary: an artifact, and what the pinned verifier said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canary {
    /// The artifact to submit. Indistinguishable from its parent by shape and
    /// by length; separable only by running the verifier.
    pub artifact: Value,
    /// What the verifier said, established at mint time by actually running it.
    pub expectation: Expectation,
    /// Digest of the artifact this was mutated from. Secret: publishing it
    /// hands over a canary detector for every sibling minted from the same
    /// parent.
    pub parent: String,
    /// How it was made. Secret, for the same reason.
    pub recipe: Recipe,
    /// How many verifier runs it took to find. The mint-time cost, recorded so
    /// a report can price the canary rate it is recommending.
    pub attempts: usize,
    /// The verifier's own words, kept so a discrepancy report can say what the
    /// artifact actually does rather than only that a node was wrong.
    pub detail: String,
}

impl Canary {
    /// The artifact digest — the only field a checker needs, and the only one
    /// safe to hand to anybody else.
    pub fn artifact_id(&self) -> String {
        self.artifact.digest()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryError {
    /// The seed artifact has no site any edit in the catalogue applies to — an
    /// empty object, or one whose only leaves are booleans and nulls.
    NothingToEdit,
    /// The budget ran out before a mutant landed on the wanted side. Raise the
    /// budget, or pick a seed nearer the boundary: mutating a artifact that
    /// clears its threshold by a mile rarely produces a rejection in one edit.
    Exhausted { want: Expectation, attempts: usize },
    /// The verifier never reached a settling verdict on any mutant. This is an
    /// infrastructure fact about the minting machine, not a fact about the
    /// artifact, and it must never be laundered into a canary: a canary minted
    /// against a broken toolchain would accuse honest nodes.
    NeverSettled { attempts: usize, detail: String },
    /// The seed artifact itself does not verify the way the caller said it did.
    SeedDisagrees { expected: Expectation, saw: Status },
}

impl fmt::Display for CanaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanaryError::NothingToEdit => {
                write!(f, "artifact has no integer, string or array to edit")
            }
            CanaryError::Exhausted { want, attempts } => {
                write!(f, "no mutant the verifier would {want} in {attempts} tries")
            }
            CanaryError::NeverSettled { attempts, detail } => write!(
                f,
                "verifier reached no settling verdict in {attempts} tries: {detail}"
            ),
            CanaryError::SeedDisagrees { expected, saw } => write!(
                f,
                "seed artifact was said to {expected} but the verifier said {}",
                saw.as_str()
            ),
        }
    }
}

impl std::error::Error for CanaryError {}

/// Default number of mutants tried before giving up.
///
/// Each attempt is one verifier run, so this is the mint-time budget in units
/// of the thing canaries are trying to make people pay for. Sixty-four is
/// generous for a rejection (most single edits break most artifacts) and is the
/// binding constraint for an *acceptance*, where the search is for an edit the
/// artifact survives.
pub const DEFAULT_BUDGET: usize = 64;

/// Mints canaries against one objective's pinned verifier.
pub struct Generator<'a> {
    registry: &'a VerifierRegistry,
    spec: &'a Value,
    budget: usize,
}

impl<'a> Generator<'a> {
    pub fn new(registry: &'a VerifierRegistry, spec: &'a Value) -> Generator<'a> {
        Generator {
            registry,
            spec,
            budget: DEFAULT_BUDGET,
        }
    }

    pub fn with_budget(mut self, budget: usize) -> Generator<'a> {
        self.budget = budget.max(1);
        self
    }

    /// What the pinned verifier says about an artifact as it stands.
    pub fn verdict(&self, artifact: &Value) -> Verdict {
        self.registry.run(self.spec, artifact)
    }

    /// Mint one canary from `seed`, on the side named by `want`.
    ///
    /// `nonce` separates independent canaries drawn from the same parent: the
    /// whole search is a deterministic function of `(seed, want, nonce)`, so a
    /// docket is reproducible from its recipes and a lost canary can be minted
    /// again without re-running anything.
    pub fn mint(&self, seed: &Value, want: Expectation, nonce: u64) -> Result<Canary, CanaryError> {
        let sites = ranked_sites(seed, want);
        if sites.is_empty() {
            return Err(CanaryError::NothingToEdit);
        }
        let parent = seed.digest();
        let mut unsettled: Option<String> = None;
        let mut settled_any = false;

        for attempt in 0..self.budget {
            let recipe = match draw(seed, &sites, &parent, want, nonce, attempt as u64) {
                Some(recipe) => recipe,
                None => continue,
            };
            let mutant = match apply(seed, &recipe) {
                Some(mutant) => mutant,
                None => continue,
            };
            // An edit that changed nothing is not a canary, it is the parent.
            if mutant == *seed {
                continue;
            }
            let verdict = self.registry.run(self.spec, &mutant);
            if !verdict.settles() {
                unsettled = Some(verdict.detail.clone());
                continue;
            }
            settled_any = true;
            if verdict.status == want.status() {
                return Ok(Canary {
                    artifact: mutant,
                    expectation: want,
                    parent,
                    recipe,
                    attempts: attempt + 1,
                    detail: verdict.detail,
                });
            }
        }

        if !settled_any {
            return Err(CanaryError::NeverSettled {
                attempts: self.budget,
                detail: unsettled.unwrap_or_else(|| "no mutant was even tried".to_string()),
            });
        }
        Err(CanaryError::Exhausted {
            want,
            attempts: self.budget,
        })
    }

    /// Mint `count` canaries from `seed`, splitting them between the two sides.
    ///
    /// `valid_share_num/valid_share_den` is the fraction that should be
    /// known-*good*, mirroring
    /// [`NodeParams::canary_valid_share`](crate::incentive::NodeParams::canary_valid_share).
    /// Half and half is the reference mix, and a docket of only known-bad
    /// canaries is exactly the trap a blind rejecter walks through unharmed.
    ///
    /// Failures are not fatal: a seed near its threshold may yield rejections
    /// readily and acceptances not at all. The caller gets whatever landed,
    /// with [`Docket::mix`] to say what it got.
    pub fn mint_batch(
        &self,
        seed: &Value,
        count: usize,
        valid_share_num: u32,
        valid_share_den: u32,
    ) -> (Vec<Canary>, Vec<CanaryError>) {
        let den = valid_share_den.max(1);
        let mut minted = Vec::new();
        let mut failures = Vec::new();
        for index in 0..count {
            // Deterministic interleave rather than a coin flip: with num/den =
            // 1/2 this alternates, so a caller who asks for two canaries gets
            // one of each rather than whatever the hash felt like.
            let want = if (index as u32 % den) < valid_share_num.min(den) {
                Expectation::Accepts
            } else {
                Expectation::Rejects
            };
            match self.mint(seed, want, index as u64) {
                Ok(canary) => minted.push(canary),
                Err(error) => failures.push(error),
            }
        }
        (minted, failures)
    }
}

/// What a node said about a canary, against what the issuer knew.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discrepancy {
    pub artifact_id: String,
    pub claim_id: String,
    pub expected: Expectation,
    pub recorded: Status,
    /// What the verifier said at mint time, so the report can name the fault
    /// rather than only the disagreement.
    pub detail: String,
}

/// A bonded attestation a docket knows to be false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationFault {
    pub attestation_id: String,
    /// The key that signed it, and therefore the key a slash takes from.
    pub attestor: String,
    pub claim_id: String,
    pub expected: Expectation,
    /// What the attestor said, as the wire spelling of a status.
    pub attested: String,
    /// What the verifier said at mint time.
    pub detail: String,
}

impl fmt::Display for AttestationFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} stood behind {} on claim {}, an artifact the verifier {}s ({})",
            crate::canonical::short(&self.attestor),
            self.attested,
            crate::canonical::short(&self.claim_id),
            self.expected,
            self.detail
        )
    }
}

impl fmt::Display for Discrepancy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "claim {}: recorded {} on an artifact the verifier {}s ({})",
            self.claim_id,
            self.recorded.as_str(),
            self.expected,
            self.detail
        )
    }
}

/// A verdict the log recorded, in the form [`Docket::discrepancies`] reads.
///
/// Deliberately not a `Node`: the checker must be usable against a log fetched
/// from a stranger, a checkpoint, or an HTTP mirror, and none of those hand
/// over a `Node`. It also keeps the dependency pointing this way — `node` may
/// come to know about canaries; canaries must never need a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedVerdict {
    pub claim_id: String,
    pub artifact_id: String,
    pub status: Status,
}

/// The issuer's private record of what it minted.
///
/// Keyed by artifact digest, not by claim id, because the docket is written
/// before anybody knows how the canary will be submitted — which key, which
/// nonce, which epoch. The artifact survives all of that.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Docket {
    entries: BTreeMap<String, (Expectation, String)>,
}

impl Docket {
    pub fn new() -> Docket {
        Docket {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, canary: &Canary) {
        self.entries.insert(
            canary.artifact_id(),
            (canary.expectation, canary.detail.clone()),
        );
    }

    pub fn from_canaries<'c, I: IntoIterator<Item = &'c Canary>>(canaries: I) -> Docket {
        let mut docket = Docket::new();
        for canary in canaries {
            docket.insert(canary);
        }
        docket
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn expectation_of(&self, artifact_id: &str) -> Option<Expectation> {
        self.entries.get(artifact_id).map(|(want, _)| *want)
    }

    /// How many canaries lie on each side: `(known-good, known-bad)`.
    ///
    /// A zero in either slot means half the trap is missing. Zero good canaries
    /// leaves blind rejection unpunished; zero bad ones leaves rubber-stamping
    /// unpunished.
    pub fn mix(&self) -> (usize, usize) {
        let mut good = 0;
        let mut bad = 0;
        for (want, _) in self.entries.values() {
            match want {
                Expectation::Accepts => good += 1,
                Expectation::Rejects => bad += 1,
            }
        }
        (good, bad)
    }

    /// Bonded attestations this docket contradicts.
    ///
    /// The other half of [`Docket::discrepancies`], and the half that names a
    /// party. That one asks what a node's own *verdict record* said, which at
    /// Stage 0 has one writer and therefore names nobody; this one asks who put
    /// a signature and a bond behind a statement the docket already knows is
    /// false. Only the second kind of finding has anything to take.
    ///
    /// `verdicts` supplies the claim-to-artifact mapping and nothing else — the
    /// status it carries is deliberately ignored, so an operator who writes an
    /// honest verdict record and attests the opposite is caught exactly as
    /// readily as one who writes both wrong.
    pub fn contradicted(
        &self,
        verdicts: &[RecordedVerdict],
        attestations: &BTreeMap<String, crate::records::Attestation>,
    ) -> Vec<AttestationFault> {
        let artifacts: BTreeMap<&str, &str> = verdicts
            .iter()
            .map(|verdict| (verdict.claim_id.as_str(), verdict.artifact_id.as_str()))
            .collect();
        let mut out = Vec::new();
        for (id, record) in attestations {
            let Some(artifact_id) = artifacts.get(record.claim_id.as_str()) else {
                continue;
            };
            let Some((expected, detail)) = self.entries.get(*artifact_id) else {
                continue;
            };
            if record.status == expected.status().as_str() {
                continue;
            }
            out.push(AttestationFault {
                attestation_id: id.clone(),
                attestor: record.attestor.clone(),
                claim_id: record.claim_id.clone(),
                expected: *expected,
                attested: record.status.clone(),
                detail: detail.clone(),
            });
        }
        out
    }

    /// The docket as a canonical value, for writing to the issuer's disk.
    ///
    /// Carries the artifact digests and their expected verdicts, and
    /// deliberately **not** the parents or the recipes. A docket is already a
    /// canary detector for anyone who obtains it — that is unavoidable, it is
    /// the list — but a docket carrying recipes is a detector for every canary
    /// the same seeds will *ever* produce, including the ones not yet minted.
    /// Losing a docket should cost one round, not the pipeline.
    pub fn to_value(&self) -> Value {
        let entries: Vec<Value> = self
            .entries
            .iter()
            .map(|(artifact_id, (want, detail))| {
                Value::object([
                    ("artifact", Value::string(artifact_id.clone())),
                    ("detail", Value::string(detail.clone())),
                    ("expect", Value::string(want.as_str())),
                ])
            })
            .collect();
        Value::object([
            ("entries", Value::Array(entries)),
            ("version", Value::Int(1)),
        ])
    }

    pub fn from_value(value: &Value) -> Option<Docket> {
        let entries = value.get("entries")?.as_array()?;
        let mut docket = Docket::new();
        for entry in entries {
            let artifact = entry.get("artifact")?.as_str()?.to_string();
            let want = Expectation::parse(entry.get("expect")?.as_str()?)?;
            let detail = entry
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            docket.entries.insert(artifact, (want, detail));
        }
        Some(docket)
    }

    /// Every recorded verdict that contradicts what the issuer knows.
    ///
    /// Runs no verifier. That asymmetry is the entire economic argument for
    /// canaries: the work was paid for once, at mint time, and this polices an
    /// unbounded number of verdicts for the cost of a map lookup.
    ///
    /// A non-settling recorded verdict is **not** a discrepancy. `Unavailable`
    /// means the node could not run the check and said so, which is the honest
    /// answer and the one the whole verifier interface is built to protect.
    /// Treating it as a lie would punish exactly the behaviour we want.
    pub fn discrepancies<'v, I>(&self, recorded: I) -> Vec<Discrepancy>
    where
        I: IntoIterator<Item = &'v RecordedVerdict>,
    {
        let mut out = Vec::new();
        for verdict in recorded {
            let (expected, detail) = match self.entries.get(&verdict.artifact_id) {
                Some(entry) => entry,
                None => continue,
            };
            if !verdict.status.settles() {
                continue;
            }
            if verdict.status != expected.status() {
                out.push(Discrepancy {
                    artifact_id: verdict.artifact_id.clone(),
                    claim_id: verdict.claim_id.clone(),
                    expected: *expected,
                    recorded: verdict.status,
                    detail: detail.clone(),
                });
            }
        }
        out
    }
}

/// Every place in the artifact an edit could land, in a deterministic order.
///
/// Depth-first, keys in `BTreeMap` order, which is the canonical order — so the
/// site list is a function of the artifact's canonical form and two
/// implementations enumerate it identically.
fn sites(value: &Value) -> Vec<Vec<Step>> {
    let mut out = Vec::new();
    walk(value, &mut Vec::new(), &mut out);
    out
}

/// The same sites, ordered by how likely an edit there is to land on the side
/// the caller asked for.
///
/// This is a **search order, not a label**. Nothing here decides whether a
/// mutant is valid; the verifier does that, every time, and a mis-ranked site
/// costs attempts rather than correctness. Ranking exists because the two
/// sides are not symmetric:
///
/// - Breaking an artifact is easy. Almost any leaf edit does it, so rejections
///   go first to the leaves.
/// - *Not* breaking one is hard, and the reliable way to change an artifact
///   without changing what it means is to **reorder a collection**. So
///   acceptances go first to arrays, shallowest first, because the shallow
///   arrays are the ones that denote sets. Swapping two points in a cap set
///   leaves the same cap set; swapping two coordinates of one point does not.
///
/// An artifact with no array — `{"n": 626331}` — therefore has no cheap
/// known-good canary at all, and [`Generator::mint`] reports
/// [`CanaryError::Exhausted`] rather than inventing one. That is a real
/// property of the objective, not a gap in the generator: when the whole
/// artifact is one number, every edit to it is a different answer.
fn ranked_sites(value: &Value, want: Expectation) -> Vec<Vec<Step>> {
    let mut sites = sites(value);
    let arrays_first = want == Expectation::Accepts;
    sites.sort_by_key(|path| {
        let is_array = matches!(at(value, path), Some(Value::Array(_)));
        let group = u8::from(is_array != arrays_first);
        (group, path.len())
    });
    sites
}

fn walk(value: &Value, path: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    match value {
        Value::Int(_) | Value::String(_) => out.push(path.clone()),
        Value::Array(items) => {
            // An array of two or more is itself a site, for `Swap`.
            if items.len() >= 2 {
                out.push(path.clone());
            }
            for (index, item) in items.iter().enumerate() {
                path.push(Step::Index(index));
                walk(item, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                path.push(Step::Key(key.clone()));
                walk(item, path, out);
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) => {}
    }
}

fn at<'v>(value: &'v Value, path: &[Step]) -> Option<&'v Value> {
    let mut cursor = value;
    for step in path {
        cursor = match (step, cursor) {
            (Step::Key(key), Value::Object(map)) => map.get(key)?,
            (Step::Index(index), Value::Array(items)) => items.get(*index)?,
            _ => return None,
        };
    }
    Some(cursor)
}

/// A deterministic byte stream for one `(seed, want, nonce, attempt)`.
///
/// SHA-256 in counter mode rather than a PRNG crate: the draw is part of how a
/// docket is reproduced, so it belongs to the repository that pins it for the
/// same reason [`crate::hex`] does.
struct Stream {
    key: Vec<u8>,
    counter: u64,
    buffer: Vec<u8>,
    used: usize,
}

impl Stream {
    fn new(parent: &str, want: Expectation, nonce: u64, attempt: u64) -> Stream {
        let mut hasher = Sha256::new();
        hasher.update(b"proofwork/canary/v1");
        hasher.update(parent.as_bytes());
        hasher.update(want.as_str().as_bytes());
        hasher.update(nonce.to_be_bytes());
        hasher.update(attempt.to_be_bytes());
        Stream {
            key: hasher.finalize().to_vec(),
            counter: 0,
            buffer: Vec::new(),
            used: 0,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.used >= self.buffer.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.update(self.counter.to_be_bytes());
            self.buffer = hasher.finalize().to_vec();
            self.counter = self.counter.wrapping_add(1);
            self.used = 0;
        }
        let byte = self.buffer[self.used];
        self.used += 1;
        byte
    }

    fn word(&mut self) -> u64 {
        let mut out = 0u64;
        for _ in 0..8 {
            out = (out << 8) | u64::from(self.byte());
        }
        out
    }

    /// Uniform-enough index below `bound`. Modulo bias over a 64-bit draw into
    /// a bound that is at most an artifact's length is immaterial here: the
    /// draw picks which edit to try, and a slightly uneven search is a slightly
    /// uneven search, not a leak.
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.word() % bound as u64) as usize
        }
    }
}

/// Pick an edit for this attempt: a site, then an edit legal at that site.
fn draw(
    seed: &Value,
    sites: &[Vec<Step>],
    parent: &str,
    want: Expectation,
    nonce: u64,
    attempt: u64,
) -> Option<Recipe> {
    let mut stream = Stream::new(parent, want, nonce, attempt);
    // Widening search: attempt 0 may only use the best-ranked site, attempt 1
    // the best two, and so on. The promising edits are tried first and the
    // whole space stays reachable, which a uniform draw over a hundred sites
    // does not — on a twenty-point cap set the one swap that preserves
    // validity is 1 site in 101, and a budget of 64 uniform draws misses it
    // more often than not.
    let bound = sites.len().min(attempt as usize + 1);
    let path = sites[stream.below(bound)].clone();
    let target = at(seed, &path)?;
    let edit = match target {
        Value::Int(current) => shift(*current, &mut stream)?,
        Value::String(text) => substitute(text, &mut stream)?,
        Value::Array(items) => swap(items.len(), &mut stream)?,
        _ => return None,
    };
    Some(Recipe { path, edit })
}

/// An integer shift that keeps the sign and the decimal width.
///
/// Width is what the canonical encoding costs, so `999 -> 1000` is a canary a
/// node can spot with `len(bytes)`. The rule is stricter than it looks: it also
/// refuses to cross zero, because `0` and `-0` do not both exist but `1` and
/// `-1` differ in width.
fn shift(current: i128, stream: &mut Stream) -> Option<Edit> {
    let width = decimal_width(current);
    // Both signs are in the candidate list rather than an inner loop over
    // `[1, -1]`. With the loop, `-m` was only ever reached when `+m` was
    // illegal, so in practice every shift was upward: six distinct mutants
    // from a one-integer artifact instead of twelve, and a bias an observer
    // could exploit. Small magnitudes come first because a nearly-right
    // artifact is the hard kind to spot.
    let candidates = [1i64, -1, 2, -2, 3, -3, 7, -7, 11, -11, 101, -101];
    let start = stream.below(candidates.len());
    for offset in 0..candidates.len() {
        let delta = candidates[(start + offset) % candidates.len()];
        let moved = current.checked_add(i128::from(delta))?;
        if moved != current
            && decimal_width(moved) == width
            && (moved < 0) == (current < 0)
            && (moved == 0) == (current == 0)
        {
            return Some(Edit::Shift { delta });
        }
    }
    None
}

fn decimal_width(value: i128) -> usize {
    let mut text = value.unsigned_abs();
    let mut width = 1;
    while text >= 10 {
        text /= 10;
        width += 1;
    }
    width
}

/// Replace one character with another of the same class.
///
/// Class, not byte: swapping a hex digit for a `z` turns a digest-shaped field
/// into something a node can reject on sight without ever hashing anything.
/// Restricting the replacement to the alphabet the string already draws from
/// keeps the field looking like what it is.
fn substitute(text: &str, stream: &mut Stream) -> Option<Edit> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return None;
    }
    let start = stream.below(chars.len());
    for offset in 0..chars.len() {
        let index = (start + offset) % chars.len();
        let alphabet = class_of(chars[index])?;
        let pick = stream.below(alphabet.len());
        for step in 0..alphabet.len() {
            let replacement = alphabet[(pick + step) % alphabet.len()];
            if replacement != chars[index] {
                return Some(Edit::Substitute { index, replacement });
            }
        }
    }
    None
}

/// The characters a given character may be exchanged for.
///
/// The classes **partition** the alphabet: every character belongs to exactly
/// one, and a substitution never crosses between them. That is stricter than it
/// first looks, and the strictness was not designed — it was extracted, by
/// [`tests::every_edit_in_the_catalogue_preserves_shape_and_length`] failing.
///
/// The first version let `a`–`f` be exchanged for any hex character, digits
/// included, on the reasoning that a hex field should stay hex. It does stay
/// hex. But `deadbeef` → `2eadbeef` moves a character from the letter class to
/// the digit class, and the class *profile* of the string — which any node can
/// compute in microseconds, without a verifier — changes with it. Overlapping
/// classes leak; a partition cannot.
///
/// So `a`–`f` and `g`–`z` are separate classes even though both are lowercase.
/// A digest keeps exactly the digit positions and letter positions it had, and
/// still looks like a digest.
fn class_of(c: char) -> Option<&'static [char]> {
    const DIGITS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
    const HEX_LOWER: &[char] = &['a', 'b', 'c', 'd', 'e', 'f'];
    const HEX_UPPER: &[char] = &['A', 'B', 'C', 'D', 'E', 'F'];
    const REST_LOWER: &[char] = &[
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
        'y', 'z',
    ];
    const REST_UPPER: &[char] = &[
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z',
    ];
    match c {
        '0'..='9' => Some(DIGITS),
        'a'..='f' => Some(HEX_LOWER),
        'g'..='z' => Some(REST_LOWER),
        'A'..='F' => Some(HEX_UPPER),
        'G'..='Z' => Some(REST_UPPER),
        // Punctuation, whitespace, separators, anything non-ASCII: leave it
        // alone. These carry structure — a `-` in a date, a `/` in a path — and
        // editing one produces a malformed field rather than a wrong one.
        _ => None,
    }
}

fn swap(len: usize, stream: &mut Stream) -> Option<Edit> {
    if len < 2 {
        return None;
    }
    let left = stream.below(len);
    let mut right = stream.below(len - 1);
    if right >= left {
        right += 1;
    }
    Some(Edit::Swap { left, right })
}

/// Apply a recipe, returning `None` if it does not fit the artifact.
pub fn apply(value: &Value, recipe: &Recipe) -> Option<Value> {
    let mut out = value.clone();
    {
        let target = at_mut(&mut out, &recipe.path)?;
        match (&recipe.edit, target) {
            (Edit::Shift { delta }, Value::Int(current)) => {
                *current = current.checked_add(i128::from(*delta))?;
            }
            (Edit::Swap { left, right }, Value::Array(items)) => {
                if *left >= items.len() || *right >= items.len() || left == right {
                    return None;
                }
                items.swap(*left, *right);
            }
            (Edit::Substitute { index, replacement }, Value::String(text)) => {
                let mut chars: Vec<char> = text.chars().collect();
                if *index >= chars.len() {
                    return None;
                }
                chars[*index] = *replacement;
                *text = chars.into_iter().collect();
            }
            _ => return None,
        }
    }
    Some(out)
}

fn at_mut<'v>(value: &'v mut Value, path: &[Step]) -> Option<&'v mut Value> {
    let mut cursor = value;
    for step in path {
        cursor = match (step, cursor) {
            (Step::Key(key), Value::Object(map)) => map.get_mut(key)?,
            (Step::Index(index), Value::Array(items)) => items.get_mut(*index)?,
            _ => return None,
        };
    }
    Some(cursor)
}

/// A cheap structural fingerprint — the thing a node filtering for canaries
/// would compute.
///
/// Deliberately the *attacker's* tool, kept in the library so the claim it
/// tests is falsifiable rather than rhetorical. It records every key path with
/// array indices erased, the type at each leaf, the length of every array, the
/// decimal width of every integer, the length and character classes of every
/// string, and the canonical byte length of the whole artifact. A canary and
/// its parent agreeing on all of that is the indistinguishability this module
/// claims; separating them requires the verifier.
pub fn fingerprint(value: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    describe(value, &mut String::new(), &mut parts);
    parts.sort();
    parts.push(format!("bytes={}", value.canonical_bytes().len()));
    parts.join("|")
}

fn describe(value: &Value, path: &mut String, out: &mut Vec<String>) {
    match value {
        Value::Null => out.push(format!("{path}=null")),
        Value::Bool(_) => out.push(format!("{path}=bool")),
        Value::Int(n) => out.push(format!("{path}=int{}{}", decimal_width(*n), sign(*n))),
        Value::String(text) => {
            let mut classes: Vec<&str> = text.chars().map(class_name).collect();
            classes.dedup();
            out.push(format!(
                "{path}=str{}:{}",
                text.chars().count(),
                classes.join("")
            ));
        }
        Value::Array(items) => {
            out.push(format!("{path}=arr{}", items.len()));
            let mark = path.len();
            path.push_str("[]");
            for item in items {
                describe(item, path, out);
            }
            path.truncate(mark);
        }
        Value::Object(map) => {
            out.push(format!("{path}=obj{}", map.len()));
            let mark = path.len();
            for (key, item) in map {
                path.push('.');
                path.push_str(key);
                describe(item, path, out);
                path.truncate(mark);
            }
        }
    }
}

fn sign(value: i128) -> &'static str {
    if value < 0 {
        "-"
    } else {
        "+"
    }
}

/// The attacker's view of the same partition. One symbol per class, and the
/// classes must be exactly [`class_of`]'s — a fingerprint coarser than the
/// substitution rule would silently stop testing it.
fn class_name(c: char) -> &'static str {
    match c {
        '0'..='9' => "d",
        'a'..='f' => "x",
        'g'..='z' => "l",
        'A'..='F' => "X",
        'G'..='Z' => "L",
        _ => ".",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifiers::VerifierRegistry;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(relative: &str) -> Value {
        let text = std::fs::read_to_string(repo_root().join(relative))
            .unwrap_or_else(|error| panic!("{relative}: {error}"));
        Value::from_json(&text).expect("valid json")
    }

    fn registry() -> VerifierRegistry {
        VerifierRegistry::new(repo_root())
    }

    /// The collatz objective: a certificate verifier over `{"n": <int>}`.
    fn collatz() -> (Value, Value) {
        let objective = read("examples/collatz/objective.json");
        let spec = objective.get("verifier").expect("a verifier").clone();
        (spec, read("examples/collatz/artifact.json"))
    }

    /// The capset objective: an evaluator scoring a set of points.
    fn capset() -> (Value, Value) {
        let objective = read("examples/capset/objective.json");
        let spec = objective.get("verifier").expect("a verifier").clone();
        (spec, read("examples/capset/artifact.json"))
    }

    fn have_python() -> bool {
        std::process::Command::new("python3")
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    // ---- the catalogue's invariant -------------------------------------

    /// The whole indistinguishability claim, over every edit the generator can
    /// draw against a corpus of real artifacts.
    ///
    /// If this fails, the canary rate `src/incentive/` solves for is a fiction:
    /// a node that can separate canaries from submissions by shape or by size
    /// verifies the ones that are watching and rubber-stamps the rest, which is
    /// `canary_leak = 1`, at which the design harness reports that no rate
    /// works.
    #[test]
    fn every_edit_in_the_catalogue_preserves_shape_and_length() {
        let corpus = [
            read("examples/collatz/artifact.json"),
            read("examples/capset/artifact.json"),
            read("examples/permutation/artifact.json"),
            Value::object([
                ("digest", Value::string("deadbeefcafe0123456789ab")),
                ("label", Value::string("Trial-Run")),
                ("count", Value::Int(-42)),
                ("nested", Value::array([Value::Int(7), Value::Int(9)])),
                ("flag", Value::Bool(true)),
                ("nothing", Value::Null),
            ]),
        ];

        let mut applied = 0usize;
        for seed in &corpus {
            let parent = seed.digest();
            let before = fingerprint(seed);
            for nonce in 0..8u64 {
                for attempt in 0..32u64 {
                    for want in [Expectation::Accepts, Expectation::Rejects] {
                        let sites = ranked_sites(seed, want);
                        assert!(!sites.is_empty(), "corpus entry with no editable site");
                        let recipe = match draw(seed, &sites, &parent, want, nonce, attempt) {
                            Some(recipe) => recipe,
                            None => continue,
                        };
                        let mutant = match apply(seed, &recipe) {
                            Some(mutant) => mutant,
                            None => continue,
                        };
                        applied += 1;
                        assert_eq!(
                            fingerprint(&mutant),
                            before,
                            "recipe {recipe} changed the fingerprint"
                        );
                        assert_eq!(
                            mutant.canonical_bytes().len(),
                            seed.canonical_bytes().len(),
                            "recipe {recipe} changed the canonical length"
                        );
                    }
                }
            }
        }
        assert!(applied > 1_000, "only {applied} mutations exercised");
    }

    /// A mutation that changes nothing is not a canary, and the generator's
    /// search must actually move the bytes.
    ///
    /// The distinct-mutant floor is the regression test for a real bias: with
    /// the sign chosen by an inner loop rather than drawn, every shift went
    /// upward and `{"n": 626331}` had six reachable mutants instead of twelve.
    #[test]
    fn a_drawn_edit_always_changes_the_artifact() {
        let seed = read("examples/collatz/artifact.json");
        let sites = ranked_sites(&seed, Expectation::Rejects);
        let parent = seed.digest();
        let mut seen = std::collections::BTreeSet::new();
        let mut down = 0;
        for attempt in 0..64u64 {
            let recipe = draw(&seed, &sites, &parent, Expectation::Rejects, 0, attempt)
                .expect("an editable site");
            if let Edit::Shift { delta } = recipe.edit {
                if delta < 0 {
                    down += 1;
                }
            }
            let mutant = apply(&seed, &recipe).expect("the recipe applies");
            assert_ne!(mutant, seed, "recipe {recipe} was a no-op");
            seen.insert(mutant.digest());
        }
        assert!(seen.len() >= 10, "only {} distinct mutants", seen.len());
        assert!(
            down > 0,
            "every shift went upward: the sign is not being drawn"
        );
    }

    /// Two runs of the same `(seed, want, nonce)` produce the same canary, and
    /// two nonces do not walk the same search.
    ///
    /// Compared as sequences rather than attempt by attempt: a one-field
    /// artifact has twelve reachable edits, so two nonces colliding on a single
    /// attempt is a birthday coincidence, not a broken draw.
    #[test]
    fn the_search_is_a_function_of_its_inputs() {
        let seed = read("examples/collatz/artifact.json");
        let sites = ranked_sites(&seed, Expectation::Rejects);
        let parent = seed.digest();
        let walk = |nonce: u64| -> Vec<Option<Recipe>> {
            (0..16u64)
                .map(|attempt| draw(&seed, &sites, &parent, Expectation::Rejects, nonce, attempt))
                .collect()
        };
        assert_eq!(walk(3), walk(3), "the same inputs drew a different search");
        assert_ne!(walk(3), walk(4), "nonce 3 and 4 walked the same search");
    }

    /// Sign and decimal width are what the encoding costs. A shift that crosses
    /// either is refused, which is the only reason `bytes=` above holds.
    #[test]
    fn a_shift_never_changes_the_width_or_the_sign() {
        for start in [1i128, 9, 10, 99, 100, -1, -9, -100, 0, 626_331] {
            for attempt in 0..16u64 {
                let mut stream = Stream::new("seed", Expectation::Rejects, 0, attempt);
                let Some(Edit::Shift { delta }) = shift(start, &mut stream) else {
                    continue;
                };
                let moved = start + i128::from(delta);
                assert_eq!(
                    decimal_width(moved),
                    decimal_width(start),
                    "{start} -> {moved}"
                );
                assert_eq!(moved < 0, start < 0, "{start} -> {moved} crossed zero");
                assert_ne!(moved, start);
            }
        }
    }

    /// A hex-shaped field stays hex-shaped. Otherwise a digest with a `q` in it
    /// is a canary detector that costs nothing to run.
    #[test]
    fn a_substitution_stays_inside_the_character_class() {
        let cases = ["deadbeef", "0123456789", "Trial", "lowercase"];
        for text in cases {
            for attempt in 0..32u64 {
                let mut stream = Stream::new("seed", Expectation::Accepts, 0, attempt);
                let Some(Edit::Substitute { index, replacement }) = substitute(text, &mut stream)
                else {
                    continue;
                };
                let original: Vec<char> = text.chars().collect();
                assert_ne!(replacement, original[index]);
                assert_eq!(
                    class_name(replacement),
                    class_name(original[index]),
                    "{text}: {} -> {replacement} left its class",
                    original[index]
                );
            }
        }
    }

    // ---- minting -------------------------------------------------------

    /// The label is established by running the objective's own verifier, so a
    /// minted rejection really is rejected — by the same code every node runs.
    #[test]
    fn a_minted_bad_canary_is_one_the_pinned_verifier_rejects() {
        if !have_python() {
            eprintln!("skipping: no python3");
            return;
        }
        let (spec, seed) = collatz();
        let registry = registry();
        let generator = Generator::new(&registry, &spec);
        assert_eq!(
            generator.verdict(&seed).status,
            Status::Accept,
            "the example artifact should verify"
        );

        let canary = generator
            .mint(&seed, Expectation::Rejects, 0)
            .expect("a rejection within budget");
        assert_eq!(canary.expectation, Expectation::Rejects);
        assert_eq!(generator.verdict(&canary.artifact).status, Status::Reject);
        assert_eq!(fingerprint(&canary.artifact), fingerprint(&seed));
        assert_ne!(canary.artifact, seed);
        eprintln!(
            "collatz bad canary in {} verifier runs: {}",
            canary.attempts, canary.recipe
        );
    }

    /// The other half of the trap. A blind rejecter passes every bad canary and
    /// is caught only by this one.
    #[test]
    fn a_minted_good_canary_is_one_the_pinned_verifier_accepts() {
        if !have_python() {
            eprintln!("skipping: no python3");
            return;
        }
        let (spec, seed) = capset();
        let registry = registry();
        let generator = Generator::new(&registry, &spec);
        assert_eq!(generator.verdict(&seed).status, Status::Accept);

        let canary = generator
            .mint(&seed, Expectation::Accepts, 0)
            .expect("an acceptance within budget");
        assert_eq!(generator.verdict(&canary.artifact).status, Status::Accept);
        assert_ne!(
            canary.artifact, seed,
            "a good canary that is byte-identical to a published artifact is \
             recognisable from the log alone"
        );
        assert_eq!(fingerprint(&canary.artifact), fingerprint(&seed));
        eprintln!(
            "capset good canary in {} verifier runs: {}",
            canary.attempts, canary.recipe
        );
    }

    /// Both sides, from one seed, in the reference mix.
    #[test]
    fn a_batch_lands_on_both_sides_of_the_line() {
        if !have_python() {
            eprintln!("skipping: no python3");
            return;
        }
        let (spec, seed) = capset();
        let registry = registry();
        let generator = Generator::new(&registry, &spec);
        let (minted, failures) = generator.mint_batch(&seed, 6, 1, 2);
        assert!(
            failures.len() < minted.len(),
            "more failures than canaries: {failures:?}"
        );
        let docket = Docket::from_canaries(&minted);
        let (good, bad) = docket.mix();
        assert!(good > 0, "no known-good canary: blind rejection goes free");
        assert!(bad > 0, "no known-bad canary: rubber-stamping goes free");
        for canary in &minted {
            assert_eq!(
                generator.verdict(&canary.artifact).status,
                canary.expectation.status()
            );
        }
        eprintln!(
            "capset batch: {good} good, {bad} bad, {} failed",
            failures.len()
        );
    }

    /// Minting is the only place a verifier runs. Checking a thousand verdicts
    /// costs a map lookup each, which is what makes a canary rate affordable.
    #[test]
    fn checking_a_docket_runs_no_verifier() {
        let bad = Canary {
            artifact: Value::object([("n", Value::Int(1))]),
            expectation: Expectation::Rejects,
            parent: "parent".to_string(),
            recipe: Recipe {
                path: vec![Step::Key("n".to_string())],
                edit: Edit::Shift { delta: -1 },
            },
            attempts: 1,
            detail: "trajectory too short".to_string(),
        };
        let good = Canary {
            artifact: Value::object([("n", Value::Int(2))]),
            expectation: Expectation::Accepts,
            ..bad.clone()
        };
        let docket = Docket::from_canaries(&[bad.clone(), good.clone()]);

        let recorded = vec![
            // A rubber-stamper accepting a known-bad artifact.
            RecordedVerdict {
                claim_id: "c-stamp".to_string(),
                artifact_id: bad.artifact_id(),
                status: Status::Accept,
            },
            // A blind rejecter refusing a known-good one.
            RecordedVerdict {
                claim_id: "c-blind".to_string(),
                artifact_id: good.artifact_id(),
                status: Status::Reject,
            },
            // An honest node, on both.
            RecordedVerdict {
                claim_id: "c-honest-1".to_string(),
                artifact_id: bad.artifact_id(),
                status: Status::Reject,
            },
            RecordedVerdict {
                claim_id: "c-honest-2".to_string(),
                artifact_id: good.artifact_id(),
                status: Status::Accept,
            },
            // A node that could not run the check and said so. Not a lie.
            RecordedVerdict {
                claim_id: "c-broken".to_string(),
                artifact_id: bad.artifact_id(),
                status: Status::Unavailable,
            },
            // Somebody else's claim entirely.
            RecordedVerdict {
                claim_id: "c-other".to_string(),
                artifact_id: "not-in-the-docket".to_string(),
                status: Status::Accept,
            },
        ];

        let found = docket.discrepancies(&recorded);
        let named: Vec<&str> = found.iter().map(|d| d.claim_id.as_str()).collect();
        assert_eq!(named, vec!["c-stamp", "c-blind"]);
    }

    /// An honest node that cannot run the toolchain must never be accused.
    /// `Unavailable` is the answer the whole verifier interface exists to
    /// protect, and a canary check that punished it would be an attack on
    /// exactly the operators behaving correctly.
    #[test]
    fn an_unavailable_verdict_is_never_a_discrepancy() {
        let canary = Canary {
            artifact: Value::object([("n", Value::Int(1))]),
            expectation: Expectation::Rejects,
            parent: "parent".to_string(),
            recipe: Recipe {
                path: vec![Step::Key("n".to_string())],
                edit: Edit::Shift { delta: -1 },
            },
            attempts: 1,
            detail: "short".to_string(),
        };
        let docket = Docket::from_canaries(std::slice::from_ref(&canary));
        for status in [Status::Unavailable, Status::InvalidSpec] {
            let recorded = vec![RecordedVerdict {
                claim_id: "c".to_string(),
                artifact_id: canary.artifact_id(),
                status,
            }];
            assert!(
                docket.discrepancies(&recorded).is_empty(),
                "{} was treated as a lie",
                status.as_str()
            );
        }
    }

    /// A verifier that never settles must not produce a canary. Minting one
    /// against a broken toolchain would manufacture accusations of honest
    /// nodes out of a missing interpreter.
    #[test]
    fn a_verifier_that_cannot_run_mints_nothing() {
        let spec = Value::object([
            ("kind", Value::string("certificate")),
            (
                "checker",
                Value::string("examples/collatz/checkers/nope.py"),
            ),
            ("checker_sha256", Value::string("00".repeat(32))),
            ("entrypoint", Value::string("check")),
        ]);
        let registry = registry();
        let generator = Generator::new(&registry, &spec).with_budget(4);
        let seed = read("examples/collatz/artifact.json");
        match generator.mint(&seed, Expectation::Rejects, 0) {
            Err(CanaryError::NeverSettled { .. }) => {}
            other => panic!("expected NeverSettled, got {other:?}"),
        }
    }

    #[test]
    fn an_artifact_with_nothing_to_edit_is_reported_not_mutated() {
        let spec = Value::object([("kind", Value::string("certificate"))]);
        let registry = registry();
        let generator = Generator::new(&registry, &spec);
        let seed = Value::object([("flag", Value::Bool(true)), ("void", Value::Null)]);
        assert_eq!(
            generator.mint(&seed, Expectation::Rejects, 0),
            Err(CanaryError::NothingToEdit)
        );
    }

    #[test]
    fn expectations_round_trip_through_their_wire_spelling() {
        for want in [Expectation::Accepts, Expectation::Rejects] {
            assert_eq!(Expectation::parse(want.as_str()), Some(want));
        }
        assert_eq!(Expectation::parse("unavailable"), None);
    }
}
