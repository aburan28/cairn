//! Adversarial tests for the confidentiality primitives (`docs/censorship.md`).
//!
//! These exercise `cairn::crypto::{shamir, envelope, identity}` through the
//! public API only, from the position of an attacker rather than a user. The
//! happy path is covered because a primitive that does not work cannot defend
//! anything; everything else here is an attempt to break one of the properties
//! §2 and §3 claim:
//!
//! - a sub-threshold set of committee members learns nothing (`shamir`);
//! - a share cannot be lifted between submissions, re-addressed to another
//!   member, or altered without the tag failing (`envelope`);
//! - a pseudonym is stable for its objective, unlinkable across objectives, and
//!   its signature covers every byte of the record (`identity`).
//!
//! Every test names the attack it defends against. Where the design deliberately
//! *cannot* detect something — Shamir cannot report "too few shares" — the test
//! asserts the permissive behaviour on purpose, so that a later "fix" that turns
//! it into an error (and thereby leaks information to a sub-threshold set) fails
//! here loudly.

use std::collections::BTreeMap;

use cairn::canonical::Value;
use cairn::crypto::envelope::{
    CommitteeKey, CommitteeMember, EnvelopeError, SealedEnvelope, SealedShare, Secret32,
};
use cairn::crypto::identity::{
    verify_bytes, verify_value, Identity, IdentityError, MasterSeed, Signature, SignedRecord,
    VerifyingKeyBytes,
};
use cairn::crypto::kem::{Bundle, PublicKey, Suite};
use cairn::crypto::shamir::{combine, split, ShamirError, Share};
use rand_core::{CryptoRng, Error as RngError, OsRng, RngCore};

// -- helpers ---------------------------------------------------------------

/// All `k`-subsets of `0..n`, so "any t of n" can be checked exhaustively
/// rather than sampled. A committee shows up in whatever combination it feels
/// like; a scheme that works for the first `t` indices and not the last is
/// broken in production and passing in a lazy test.
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn walk(start: usize, n: usize, k: usize, current: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if current.len() == k {
            out.push(current.clone());
            return;
        }
        for i in start..n {
            current.push(i);
            walk(i + 1, n, k, current, out);
            current.pop();
        }
    }
    let mut out = Vec::new();
    walk(0, n, k, &mut Vec::new(), &mut out);
    out
}

fn pick(shares: &[Share], indices: &[usize]) -> Vec<Share> {
    indices
        .iter()
        .filter_map(|&i| shares.get(i).cloned())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).expect("hex is ascii");
            u8::from_str_radix(s, 16).expect("hex digits")
        })
        .collect()
}

/// Flip the low bit of one byte of a hex-encoded field. One bit is the smallest
/// tamper an AEAD is obliged to catch.
fn flip_bit_in_hex(text: &str, byte_index: usize) -> String {
    let mut bytes = unhex(text);
    let slot = bytes.get_mut(byte_index).expect("byte index in range");
    *slot ^= 0x01;
    hex(&bytes)
}

/// Replace or insert one field of an encoded record. `Value` is immutable by
/// design, so wire-level tampering has to rebuild the object — which is also
/// exactly what an attacker on the wire does.
fn with_field(value: &Value, key: &str, new: Value) -> Value {
    let mut map: BTreeMap<String, Value> = value.as_object().cloned().unwrap_or_default();
    map.insert(key.to_string(), new);
    Value::Object(map)
}

fn without_field(value: &Value, key: &str) -> Value {
    let mut map: BTreeMap<String, Value> = value.as_object().cloned().unwrap_or_default();
    map.remove(key);
    Value::Object(map)
}

fn field_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .expect("field present and a string")
        .to_string()
}

/// Rewrite the sealed share addressed to `index`, leaving the rest alone.
fn map_sealed_share(envelope: &Value, index: u8, f: impl Fn(&Value) -> Value) -> Value {
    let shares = envelope
        .get("sealed_shares")
        .and_then(Value::as_array)
        .expect("sealed_shares array");
    let rewritten: Vec<Value> = shares
        .iter()
        .map(|share| {
            if share.get("index").and_then(Value::as_i128) == Some(i128::from(index)) {
                f(share)
            } else {
                share.clone()
            }
        })
        .collect();
    with_field(envelope, "sealed_shares", Value::array(rewritten))
}

/// An RNG that returns zeros while asserting `CryptoRng`.
///
/// It exists to demonstrate the caveat in `shamir::split`'s docs: `CryptoRng` is
/// an assertion by the implementor, not a proof, and nothing in the library can
/// detect a bad one. See `predictable_rng_collapses_the_scheme`. Never use this
/// shape outside a test.
struct ZeroRng;

impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ZeroRng {}

// ==========================================================================
// Shamir
// ==========================================================================

/// Attack: **committee absenteeism / cherry-picked quorum.** The reveal must
/// succeed for *whichever* `t` members turn up, not for a privileged subset. A
/// scheme that only interpolates correctly for the first `t` indices hands an
/// attacker a liveness lever: silence the two members it works for and the epoch
/// stalls (§2, "n - t must be large enough to tolerate absentees").
#[test]
fn every_t_of_n_subset_reconstructs() {
    let secret: Vec<u8> = (0u8..=63).collect();
    let shares = split(&secret, 3, 5, OsRng).expect("split");

    for k in 3..=5 {
        for subset in combinations(5, k) {
            let chosen = pick(&shares, &subset);
            let recovered = combine(&chosen).expect("combine");
            assert_eq!(
                recovered, secret,
                "subset {subset:?} of size {k} failed to reconstruct"
            );
        }
    }
}

/// Attack: **`t-1` colluding committee members reading a submission early**
/// (§2, "it cannot read a submission early unless t members collude"). Below the
/// threshold the output must be uncorrelated with the secret.
///
/// Note what is asserted about the *error*: nothing. `combine` returns `Ok` with
/// a wrong answer, and that is the security property, not a defect — an
/// implementation that could say "you are one share short" would be leaking to a
/// sub-threshold set. The check that catches a short reconstruction lives in the
/// AEAD downstream, which is covered in the envelope section.
#[test]
fn sub_threshold_shares_do_not_yield_the_secret() {
    let secret: Vec<u8> = (0u8..=31)
        .map(|b| b.wrapping_mul(7).wrapping_add(3))
        .collect();
    let shares = split(&secret, 3, 5, OsRng).expect("split");

    for k in 1..=2 {
        for subset in combinations(5, k) {
            let chosen = pick(&shares, &subset);
            let recovered = combine(&chosen).expect("combine must not report a short set");
            assert_eq!(recovered.len(), secret.len());
            assert_ne!(
                recovered, secret,
                "subset {subset:?} of size {k} recovered the secret below threshold"
            );
        }
    }
}

/// Attack: **one member submitting their share twice to fake a quorum.** The
/// Lagrange denominator for two equal indices is `x ^ x == 0`; without the check
/// the interpolation is undefined and a single member could appear to be `t` of
/// them.
#[test]
fn duplicate_indices_are_rejected() {
    let shares = split(b"content key stand-in", 2, 3, OsRng).expect("split");
    let one = shares.first().cloned().expect("a share");
    let two = shares.get(1).cloned().expect("a share");

    assert_eq!(
        combine(&[one.clone(), one.clone()]),
        Err(ShamirError::DuplicateIndex { index: one.index })
    );
    // Also when hidden among legitimate shares rather than offered alone.
    assert_eq!(
        combine(&[one.clone(), two, one.clone()]),
        Err(ShamirError::DuplicateIndex { index: one.index })
    );
}

/// Attack: **passing off the plaintext secret as a "share".** `x = 0` is where
/// the secret lives, so accepting a point at index 0 silently converts a
/// threshold scheme into a plaintext handoff — and would let a caller who holds
/// the secret manufacture a quorum out of it.
#[test]
fn index_zero_is_rejected_everywhere() {
    let forged = Share {
        index: 0,
        data: b"the secret itself".to_vec(),
    };
    assert_eq!(combine(&[forged]), Err(ShamirError::IndexZero));

    // The same refusal on the decode path, so it cannot be smuggled in from the
    // wire instead of constructed in memory.
    let encoded = Value::object([
        ("index", Value::Int(0)),
        ("data", Value::string("00112233")),
    ]);
    assert_eq!(Share::from_value(&encoded), Err(ShamirError::IndexZero));
}

/// Attack: **a truncated or padded share.** Shares of different lengths cannot
/// have come from one split; accepting them would interpolate over ragged data
/// and produce a key that is wrong in a way nobody can attribute.
#[test]
fn mismatched_share_lengths_are_rejected() {
    let shares = split(b"thirty-two bytes of key material", 2, 3, OsRng).expect("split");
    let full = shares.first().cloned().expect("a share");
    let mut truncated = shares.get(1).cloned().expect("a share");
    truncated.data.truncate(4);

    let expected = ShamirError::LengthMismatch {
        expected: full.data.len(),
        found: 4,
    };
    assert_eq!(combine(&[full, truncated]), Err(expected));
}

/// Attack: **a caller who believes `t = 1` is "just a low threshold".** It is
/// replication: every share *is* the secret, so one committee member reads the
/// submission alone. The behaviour is supported, and this test pins it so the
/// cost is visible in the test suite rather than discovered in an incident.
#[test]
fn threshold_one_is_replication_not_sharing() {
    let secret = b"one member sees everything".to_vec();
    let shares = split(&secret, 1, 4, OsRng).expect("split");

    for share in &shares {
        assert_eq!(share.data, secret, "t=1 shares are the secret verbatim");
        assert_eq!(combine(std::slice::from_ref(share)), Ok(secret.clone()));
    }
}

/// Attack: **losing one member stalls the epoch when `t == n`.** Unanimity works
/// cryptographically and is a liveness trap (§2); both halves are asserted so
/// the tradeoff is explicit.
#[test]
fn threshold_equal_to_n_works_and_tolerates_no_absentees() {
    let secret: Vec<u8> = (100u8..132).collect();
    let shares = split(&secret, 4, 4, OsRng).expect("split");

    assert_eq!(combine(&shares), Ok(secret.clone()));
    for subset in combinations(4, 3) {
        let recovered = combine(&pick(&shares, &subset)).expect("combine");
        assert_ne!(
            recovered, secret,
            "subset {subset:?} recovered without all n"
        );
    }
}

/// Attack: **a size-dependent bug that only bites at scale.** Artifacts are not
/// 32 bytes, and per-byte polynomial evaluation is exactly the shape of code
/// where an off-by-one appears only past the first block.
#[test]
fn large_secrets_round_trip() {
    let secret: Vec<u8> = (0..65_536u32).map(|i| (i ^ (i >> 8)) as u8).collect();
    let shares = split(&secret, 3, 5, OsRng).expect("split");

    for share in &shares {
        assert_eq!(
            share.data.len(),
            secret.len(),
            "a share is as long as the secret"
        );
    }
    let recovered = combine(&pick(&shares, &[4, 1, 0])).expect("combine");
    assert_eq!(recovered, secret);
}

/// Attack: **two spellings of one share.** Identities in this system are hashes
/// of canonical bytes, so a share that accepts both `AB` and `ab` gives one
/// committee action two digests and lets a member equivocate about what they
/// published.
#[test]
fn share_wire_form_round_trips_and_refuses_ambiguity() {
    let shares = split(b"key material", 2, 3, OsRng).expect("split");
    let from_split = shares.first().cloned().expect("a share");
    let decoded = Share::from_value(&from_split.to_value()).expect("round trip");
    assert_eq!(decoded.index, from_split.index);
    assert_eq!(decoded.data, from_split.data);

    // A fixed share from here on: the hex must be known to contain letters, or
    // the uppercase check below would silently pass on an all-digit encoding.
    let share = Share {
        index: 3,
        data: vec![0xab, 0xcd, 0xef, 0x01],
    };
    let good = share.to_value();
    assert_eq!(field_str(&good, "data"), "abcdef01");
    assert_eq!(
        Share::from_value(&good).expect("round trip").data,
        share.data
    );

    assert_eq!(
        Share::from_value(&with_field(&good, "data", Value::string("ABCDEF01"))),
        Err(ShamirError::InvalidField {
            field: "data",
            expected: "an even-length lowercase hex string",
        })
    );
    assert!(Share::from_value(&with_field(&good, "data", Value::string("abc"))).is_err());
    assert!(Share::from_value(&with_field(&good, "data", Value::string(""))).is_err());
    assert!(Share::from_value(&without_field(&good, "index")).is_err());
    assert!(Share::from_value(&without_field(&good, "data")).is_err());
    assert!(Share::from_value(&Value::string("not an object")).is_err());

    // `true` is not index 1: a JSON bool must not be coerced into a coordinate.
    assert!(Share::from_value(&with_field(&good, "index", Value::Bool(true))).is_err());
    // 256 is not a u8 x-coordinate.
    assert!(Share::from_value(&with_field(&good, "index", Value::Int(256))).is_err());
}

/// Attack: **parameters that destroy the submission rather than protect it.** A
/// `0`-of-n scheme protects nothing and a `t > n` scheme is unrecoverable; both
/// must fail at split time, while the submitter still has the plaintext.
#[test]
fn degenerate_split_parameters_are_refused() {
    assert_eq!(split(b"", 2, 3, OsRng), Err(ShamirError::EmptySecret));
    assert_eq!(split(b"x", 0, 3, OsRng), Err(ShamirError::ThresholdZero));
    assert_eq!(
        split(b"x", 4, 3, OsRng),
        Err(ShamirError::ThresholdExceedsShares {
            threshold: 4,
            shares: 3
        })
    );
    assert_eq!(
        split(b"x", 1, 0, OsRng),
        Err(ShamirError::ThresholdExceedsShares {
            threshold: 1,
            shares: 0
        })
    );
    assert_eq!(combine(&[]), Err(ShamirError::NoShares));
    assert_eq!(
        combine(&[Share {
            index: 1,
            data: Vec::new()
        }]),
        Err(ShamirError::EmptyShare)
    );
}

/// Attack: **a submitter with a predictable RNG.** With deterministic
/// coefficients the polynomial is not random and a single share reconstructs the
/// secret regardless of `t`. Nothing in the library can detect this — the shares
/// look identical either way — so it is asserted here to keep the documented
/// caveat honest and to prove the coefficients really do come from the RNG.
#[test]
fn predictable_rng_collapses_the_scheme() {
    let secret = b"a content key that should not be guessable".to_vec();
    let shares = split(&secret, 3, 5, ZeroRng).expect("split");

    for share in &shares {
        assert_eq!(
            share.data, secret,
            "with a zero RNG every share is the plaintext secret"
        );
    }
    // One share, threshold three: the confidentiality claim is gone.
    let single = pick(&shares, &[2]);
    assert_eq!(combine(&single), Ok(secret));
}

/// Attack: **a member replaying a share from a different split** (a previous
/// epoch, or another submission that reused the committee). Shamir alone cannot
/// notice: mixing splits yields `Ok` and a wrong key. This is precisely why the
/// AEAD tag downstream is load-bearing rather than decorative.
#[test]
fn shares_from_two_splits_mix_silently() {
    let secret = b"thirty-two bytes of key materiel".to_vec();
    let first = split(&secret, 3, 5, OsRng).expect("split");
    let second = split(&secret, 3, 5, OsRng).expect("split");

    // Two genuine shares plus one from the other split, all distinct indices.
    let mut mixed = pick(&first, &[0, 1]);
    mixed.extend(pick(&second, &[2]));
    let recovered = combine(&mixed).expect("combine cannot detect a mixed set");
    assert_ne!(recovered, secret);
}

/// Attack: **a share leaking through a log line.** In the `t = 1` case that line
/// *is* the secret, and in every case it is a share an attacker did not have.
#[test]
fn share_debug_redacts_its_data() {
    let share = Share {
        index: 9,
        data: vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67],
    };
    let rendered = format!("{share:?}");
    assert!(
        !rendered.contains(&hex(&share.data)),
        "share data appeared in Debug output: {rendered}"
    );
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(rendered.contains('9'), "the public index is fine to print");
}

// ==========================================================================
// Envelope
// ==========================================================================

const AAD_A: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const AAD_B: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

struct Committee {
    keys: Vec<CommitteeKey>,
    members: Vec<CommitteeMember>,
}

/// Routing indices are deliberately not `1..=n`. `CommitteeMember::index`
/// addresses a member within the envelope and is not the Shamir x-coordinate;
/// using sparse, non-sequential indices means a test cannot accidentally pass by
/// conflating the two.
fn committee(size: usize) -> Committee {
    let indices: [u8; 6] = [7, 11, 13, 42, 200, 255];
    let mut keys = Vec::new();
    let mut members = Vec::new();
    for slot in 0..size {
        let key = CommitteeKey::generate(&mut OsRng);
        let index = indices.get(slot).copied().unwrap_or(slot as u8);
        members.push(key.member(index));
        keys.push(key);
    }
    Committee { keys, members }
}

/// Open each member's share the way the epoch boundary does: member `i` uses
/// their own private key on their own routing index.
fn open_shares(committee: &Committee, envelope: &SealedEnvelope, who: &[usize]) -> Vec<Share> {
    who.iter()
        .map(|&i| {
            let key = committee.keys.get(i).expect("member key");
            let member = committee.members.get(i).expect("member");
            key.open_share(envelope, member.index)
                .expect("a member can open their own share")
        })
        .collect()
}

/// The property §2 exists for: the reveal happens **without the submitter**.
/// Exactly `t` members suffice, and so does the whole committee.
#[test]
fn threshold_reveal_works_with_exactly_t_and_with_n() {
    let committee = committee(5);
    let payload = b"artifact bytes that must not be visible before the epoch ends";
    let envelope =
        SealedEnvelope::seal(payload, AAD_A, &committee.members, 3, &mut OsRng).expect("seal");

    for subset in combinations(5, 3) {
        let shares = open_shares(&committee, &envelope, &subset);
        assert_eq!(
            envelope.open_with_shares(&shares).expect("open"),
            payload.to_vec(),
            "subset {subset:?} failed to open"
        );
    }

    let all: Vec<usize> = (0..5).collect();
    let shares = open_shares(&committee, &envelope, &all);
    assert_eq!(envelope.open_with_shares(&shares).expect("open"), payload);
}

/// Attack: **`t-1` members opening early.** Shamir hands back a well-formed
/// 32-byte key that is simply wrong; the AEAD tag is the only thing that can
/// tell. The requirement is an `Err` — not garbage plaintext, and not a panic in
/// the reveal path, which would take down the whole epoch rather than one
/// submission.
#[test]
fn sub_threshold_shares_fail_with_an_error_not_garbage() {
    let committee = committee(5);
    let payload = b"still sealed";
    let envelope =
        SealedEnvelope::seal(payload, AAD_A, &committee.members, 3, &mut OsRng).expect("seal");

    for k in 1..=2 {
        for subset in combinations(5, k) {
            let shares = open_shares(&committee, &envelope, &subset);
            assert_eq!(
                envelope.open_with_shares(&shares),
                Err(EnvelopeError::Authentication { context: "payload" }),
                "subset {subset:?} of size {k}"
            );
        }
    }

    // Zero shares is the one sub-threshold case with its own name, because there
    // is nothing to interpolate at all.
    assert_eq!(envelope.open_with_shares(&[]), Err(EnvelopeError::NoShares));
}

/// Attack: **a sequencer or storage node quietly corrupting one bit** of a
/// sealed artifact — enough to destroy a submission if it went unnoticed, and
/// enough to be blamed on the submitter ("they sealed garbage"). Every single-bit
/// change anywhere in the payload ciphertext, including the tag, must fail
/// authentication.
#[test]
fn a_flipped_bit_anywhere_in_the_ciphertext_fails_authentication() {
    let committee = committee(4);
    let payload = b"forty bytes of artifact, give or take..";
    let envelope =
        SealedEnvelope::seal(payload, AAD_A, &committee.members, 2, &mut OsRng).expect("seal");
    let shares = open_shares(&committee, &envelope, &[0, 1]);

    let encoded = envelope.to_value();
    let ciphertext = field_str(&encoded, "ciphertext");
    let byte_len = ciphertext.len() / 2;
    assert!(byte_len > payload.len(), "ciphertext carries a tag");

    for i in 0..byte_len {
        let tampered = with_field(
            &encoded,
            "ciphertext",
            Value::string(flip_bit_in_hex(&ciphertext, i)),
        );
        let envelope = SealedEnvelope::from_value(&tampered).expect("still decodes");
        assert_eq!(
            envelope.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { context: "payload" }),
            "flipping byte {i} of the ciphertext was not detected"
        );
    }

    // The nonce is not covered by the tag as a *field*, but changing it changes
    // the keystream, so it fails just the same.
    let nonce = field_str(&encoded, "nonce");
    for i in 0..(nonce.len() / 2) {
        let tampered = with_field(&encoded, "nonce", Value::string(flip_bit_in_hex(&nonce, i)));
        let envelope = SealedEnvelope::from_value(&tampered).expect("still decodes");
        assert_eq!(
            envelope.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { context: "payload" }),
            "flipping byte {i} of the nonce was not detected"
        );
    }
}

/// Attack: **re-labelling an envelope to a different submission.** The `aad` is
/// the commitment hash; it binds the ciphertext and every share key to one
/// submission. Rewriting it must break both, otherwise a sealed artifact could be
/// lifted under someone else's commitment.
#[test]
fn a_rewritten_aad_breaks_the_payload_and_every_share() {
    let committee = committee(4);
    let envelope = SealedEnvelope::seal(
        b"bound to one commitment",
        AAD_A,
        &committee.members,
        2,
        &mut OsRng,
    )
    .expect("seal");
    let shares = open_shares(&committee, &envelope, &[0, 1]);

    let relabelled = SealedEnvelope::from_value(&with_field(
        &envelope.to_value(),
        "aad",
        Value::string(AAD_B),
    ))
    .expect("decodes");
    assert_eq!(relabelled.aad(), AAD_B);

    // The payload AEAD refuses, even with the correct content key shares.
    assert_eq!(
        relabelled.open_with_shares(&shares),
        Err(EnvelopeError::Authentication { context: "payload" })
    );
    // And no member can even recover their share, because the aad is absorbed
    // into the share key derivation too.
    for (i, key) in committee.keys.iter().enumerate() {
        let member = committee.members.get(i).expect("member");
        assert_eq!(
            key.open_share(&relabelled, member.index),
            Err(EnvelopeError::Authentication {
                context: "sealed share"
            })
        );
    }
}

/// Attack: **replaying a sealed share into another submission.** A member's
/// share for submission A, dropped into submission B, must not decrypt: the
/// derived key absorbs the aad, so a share is welded to the envelope it was
/// issued for.
#[test]
fn a_sealed_share_from_another_envelope_does_not_decrypt() {
    let committee = committee(4);
    let envelope_a =
        SealedEnvelope::seal(b"submission A", AAD_A, &committee.members, 2, &mut OsRng)
            .expect("seal a");
    let envelope_b =
        SealedEnvelope::seal(b"submission B", AAD_B, &committee.members, 2, &mut OsRng)
            .expect("seal b");

    let victim = committee.members.first().cloned().expect("a member");
    let key = committee.keys.first().expect("a key");
    let lifted = envelope_a
        .sealed_share(victim.index)
        .expect("share exists")
        .to_value();

    let spliced = SealedEnvelope::from_value(&map_sealed_share(
        &envelope_b.to_value(),
        victim.index,
        |_: &Value| lifted.clone(),
    ))
    .expect("decodes");

    assert_eq!(
        key.open_share(&spliced, victim.index),
        Err(EnvelopeError::Authentication {
            context: "sealed share"
        })
    );
}

/// Attack: **cross-submission share reuse when the aad happens to match.** Two
/// envelopes sealed under the same context still have independent content keys,
/// so a full quorum's worth of shares from one must not open the other. Here the
/// shares *do* decrypt (same aad, same committee) and the defence is the payload
/// tag — the layered check the design relies on.
#[test]
fn shares_from_another_envelope_do_not_open_this_payload() {
    let committee = committee(4);
    let envelope_a =
        SealedEnvelope::seal(b"payload A", AAD_A, &committee.members, 2, &mut OsRng).expect("seal");
    let envelope_b =
        SealedEnvelope::seal(b"payload B", AAD_A, &committee.members, 2, &mut OsRng).expect("seal");

    let shares_a = open_shares(&committee, &envelope_a, &[0, 1]);
    assert_eq!(
        envelope_b.open_with_shares(&shares_a),
        Err(EnvelopeError::Authentication { context: "payload" })
    );
}

/// Attack: **a committee member opening a colleague's share** to reach the
/// threshold alone. Each share is sealed to one X25519 key; holding a different
/// one must not help.
#[test]
fn a_member_cannot_open_another_members_share() {
    let committee = committee(4);
    let envelope =
        SealedEnvelope::seal(b"one share each", AAD_A, &committee.members, 3, &mut OsRng)
            .expect("seal");

    for (i, key) in committee.keys.iter().enumerate() {
        for (j, member) in committee.members.iter().enumerate() {
            if i == j {
                continue;
            }
            assert_eq!(
                key.open_share(&envelope, member.index),
                Err(EnvelopeError::Authentication {
                    context: "sealed share"
                }),
                "member {i} opened member {j}'s share"
            );
        }
    }

    // An index nobody holds is a distinct, non-cryptographic failure.
    assert_eq!(
        committee
            .keys
            .first()
            .expect("a key")
            .open_share(&envelope, 3),
        Err(EnvelopeError::UnknownShare { index: 3 })
    );
}

/// Attack: **tampering with a sealed share in transit** — corrupting the share
/// ciphertext, its nonce, or a KEM ciphertext it was sealed under. All of these
/// must fail rather than yield a subtly wrong Shamir point, which would surface
/// as an unattributable reveal failure.
#[test]
fn a_tampered_sealed_share_fails_to_open() {
    let committee = committee(3);
    let envelope =
        SealedEnvelope::seal(b"share integrity", AAD_A, &committee.members, 2, &mut OsRng)
            .expect("seal");
    let victim = committee.members.first().cloned().expect("a member");
    let key = committee.keys.first().expect("a key");
    let encoded = envelope.to_value();

    for field in ["ciphertext", "nonce"] {
        let tampered = map_sealed_share(&encoded, victim.index, |share: &Value| {
            let text = field_str(share, field);
            with_field(share, field, Value::string(flip_bit_in_hex(&text, 0)))
        });
        let envelope = SealedEnvelope::from_value(&tampered).expect("decodes");
        let result = key.open_share(&envelope, victim.index);
        assert!(
            matches!(result, Err(EnvelopeError::Authentication { .. })),
            "tampering with {field} produced {result:?}"
        );
    }

    // Every KEM leg, one at a time. A flipped bit in *any* of them must fail:
    // the combiner absorbs all of them, so tampering with the cheapest one is
    // as fatal as tampering with McEliece. That is the property that makes
    // adding a suite safe, and it would be quietly untrue if a leg were
    // absorbed into the transcript but not into the shared secret.
    let legs = encoded
        .get("sealed_shares")
        .and_then(Value::as_array)
        .expect("shares")
        .iter()
        .find(|share| share.get("index").and_then(Value::as_i128) == Some(i128::from(victim.index)))
        .and_then(|share| share.get("kem"))
        .and_then(Value::as_array)
        .expect("kem legs")
        .len();
    assert!(legs >= 1, "a share must carry at least the McEliece leg");

    for leg in 0..legs {
        let tampered = map_sealed_share(&encoded, victim.index, |share: &Value| {
            let mut items = share
                .get("kem")
                .and_then(Value::as_array)
                .expect("kem legs")
                .to_vec();
            let target = items.get(leg).cloned().expect("leg in range");
            let text = field_str(&target, "ciphertext");
            items[leg] = with_field(
                &target,
                "ciphertext",
                Value::string(flip_bit_in_hex(&text, 0)),
            );
            with_field(share, "kem", Value::array(items))
        });
        let envelope = SealedEnvelope::from_value(&tampered).expect("decodes");
        let result = key.open_share(&envelope, victim.index);
        assert!(
            matches!(result, Err(EnvelopeError::Authentication { .. })),
            "tampering with KEM leg {leg} produced {result:?}"
        );
    }
}

/// Attack: **shares that reconstruct something that is not a 32-byte key**, and
/// **a duplicate share smuggled into the reveal**. Both must be refused before
/// the AEAD sees them, since neither can be the result of an honest split.
#[test]
fn malformed_share_sets_are_refused_before_decryption() {
    let committee = committee(4);
    let envelope =
        SealedEnvelope::seal(b"payload", AAD_A, &committee.members, 2, &mut OsRng).expect("seal");

    let mut shares = open_shares(&committee, &envelope, &[0, 1]);
    for share in shares.iter_mut() {
        share.data.truncate(16);
    }
    assert_eq!(
        envelope.open_with_shares(&shares),
        Err(EnvelopeError::ContentKeyLength { actual: 16 })
    );

    let one = open_shares(&committee, &envelope, &[0]);
    let doubled = [
        one.first().cloned().expect("share"),
        one.first().cloned().expect("share"),
    ];
    assert!(
        matches!(
            envelope.open_with_shares(&doubled),
            Err(EnvelopeError::Shamir(_))
        ),
        "a duplicated share must be refused by the sharing layer"
    );
}

/// The §2 liveness fallback: a committee that will not publish must not lose the
/// submission. The retained content key opens the envelope without any shares —
/// and, being a key that can be seized, is exactly why this is the fallback and
/// not the path. A *different* key must not work.
#[test]
fn the_retained_content_key_is_a_fallback_and_only_the_right_one_works() {
    let committee = committee(3);
    let payload = b"the committee went dark";
    let (envelope, content_key) =
        SealedEnvelope::seal_retaining_key(payload, AAD_A, &committee.members, 2, &mut OsRng)
            .expect("seal");

    assert_eq!(
        envelope.open_with_content_key(&content_key).expect("open"),
        payload.to_vec()
    );

    // An unrelated 32-byte secret must not open it.
    let wrong = Secret32::new([0x5au8; 32]);
    assert_eq!(
        envelope.open_with_content_key(&wrong),
        Err(EnvelopeError::Authentication { context: "payload" })
    );
}

/// Attack: **a committee that is not what it claims to be.** A duplicate routing
/// index makes a share unaddressable; a duplicate public key means one entity
/// silently holds two shares, so the effective threshold is lower than the number
/// everyone is relying on (§2, "the threshold set high enough that collusion is
/// expensive").
#[test]
fn dishonest_committee_shapes_are_refused_at_seal_time() {
    let committee = committee(3);
    let payload = b"x";

    assert_eq!(
        SealedEnvelope::seal(payload, AAD_A, &[], 1, &mut OsRng),
        Err(EnvelopeError::EmptyCommittee)
    );
    assert_eq!(
        SealedEnvelope::seal(payload, AAD_A, &committee.members, 0, &mut OsRng),
        Err(EnvelopeError::InvalidThreshold {
            threshold: 0,
            committee: 3
        })
    );
    assert_eq!(
        SealedEnvelope::seal(payload, AAD_A, &committee.members, 4, &mut OsRng),
        Err(EnvelopeError::InvalidThreshold {
            threshold: 4,
            committee: 3
        })
    );

    let key = CommitteeKey::generate(&mut OsRng);
    let same_index = [key.member(5), CommitteeKey::generate(&mut OsRng).member(5)];
    assert_eq!(
        SealedEnvelope::seal(payload, AAD_A, &same_index, 2, &mut OsRng),
        Err(EnvelopeError::DuplicateMemberIndex { index: 5 })
    );

    let same_key = [key.member(1), key.member(2)];
    assert_eq!(
        SealedEnvelope::seal(payload, AAD_A, &same_key, 2, &mut OsRng),
        Err(EnvelopeError::DuplicateMemberKey { index: 2 })
    );

    // More members than there are Shamir x-coordinates. One bundle cloned 256
    // times rather than 256 keygens: the size check runs before any key is
    // touched, so what this exercises is the ceiling and not the cryptography.
    let oversized: Vec<CommitteeMember> = (0..256usize)
        .map(|i| CommitteeMember {
            index: i as u8,
            keys: key.public(),
        })
        .collect();
    assert_eq!(
        SealedEnvelope::seal(payload, AAD_A, &oversized, 2, &mut OsRng),
        Err(EnvelopeError::CommitteeTooLarge { size: 256 })
    );
}

/// Attack: **a member who publishes a key nobody holds the secret to.**
///
/// This test used to be `a_non_contributory_committee_key_is_refused`, and the
/// change is in the threat model rather than in the code under test. Under
/// X25519 a low-order public key forced the shared secret to the identity
/// point, which every observer can compute — that member's share became
/// world-readable and the real threshold was one lower than advertised, so
/// sealing had to refuse.
///
/// A KEM has no low-order key. Every bit string of the right length is *a*
/// public key, and encapsulating to a random one yields a secret nobody can
/// recover — least of all whoever planted it. The planted member forfeits their
/// own share and learns nothing, so there is nothing to refuse, and the
/// mechanism that absorbs the loss is `n - t` rather than a validity check.
///
/// The assertion that matters is the second one: the *other* members still
/// reach the threshold, so a planted key cannot stall a reveal.
#[test]
fn a_committee_key_nobody_holds_costs_only_its_own_share() {
    let honest = CommitteeKey::generate(&mut OsRng);
    let second = CommitteeKey::generate(&mut OsRng);

    let mut junk = vec![0u8; Suite::McEliece.public_key_len()];
    OsRng.fill_bytes(&mut junk);
    let planted = CommitteeMember {
        index: 3,
        keys: Bundle::mceliece_only(
            PublicKey::from_bytes(Suite::McEliece, &junk).expect("right length"),
        )
        .expect("mandatory leg"),
    };
    let members = [honest.member(1), second.member(2), planted];

    // Sealing succeeds: there is no longer anything to detect.
    let envelope = SealedEnvelope::seal(b"payload", AAD_A, &members, 2, &mut OsRng).expect("seals");

    // Two honest members still reach the threshold.
    let shares = vec![
        honest.open_share(&envelope, 1).expect("opens"),
        second.open_share(&envelope, 2).expect("opens"),
    ];
    assert_eq!(
        envelope.open_with_shares(&shares).expect("opens"),
        b"payload".to_vec()
    );
}

/// A sealed envelope is public ciphertext that every node must agree on. The
/// encoding must round-trip exactly and the digest must be stable, or two honest
/// nodes disagree about what was even submitted.
#[test]
fn envelope_wire_form_round_trips_exactly() {
    let committee = committee(4);
    let envelope = SealedEnvelope::seal(b"round trip me", AAD_A, &committee.members, 2, &mut OsRng)
        .expect("seal");

    let decoded = SealedEnvelope::from_value(&envelope.to_value()).expect("round trip");
    assert_eq!(decoded, envelope);
    assert_eq!(decoded.digest(), envelope.digest());
    assert_eq!(decoded.threshold(), 2);
    assert_eq!(decoded.aad(), AAD_A);
    assert_eq!(decoded.ciphertext(), envelope.ciphertext());
    assert_eq!(decoded.nonce(), envelope.nonce());
    assert_eq!(decoded.sealed_shares().len(), 4);

    // And it still opens after the trip through the wire.
    let shares = open_shares(&committee, &decoded, &[2, 3]);
    assert_eq!(
        decoded.open_with_shares(&shares).expect("open"),
        b"round trip me"
    );

    let sealed_share = envelope.sealed_shares().first().cloned().expect("a share");
    assert_eq!(
        SealedShare::from_value(&sealed_share.to_value()).expect("round trip"),
        sealed_share
    );
}

/// Attack: **a hand-crafted envelope the sealer could never have produced** —
/// two shares claiming one index, an impossible threshold, an empty committee, or
/// a version this build cannot interpret. Accepting any of them hands the rest of
/// the system a shape it has no code to handle.
#[test]
fn hostile_envelope_encodings_are_refused() {
    let committee = committee(3);
    let envelope =
        SealedEnvelope::seal(b"payload", AAD_A, &committee.members, 2, &mut OsRng).expect("seal");
    let encoded = envelope.to_value();

    assert_eq!(
        SealedEnvelope::from_value(&with_field(&encoded, "threshold", Value::Int(0))),
        Err(EnvelopeError::InvalidThreshold {
            threshold: 0,
            committee: 3
        })
    );
    assert_eq!(
        SealedEnvelope::from_value(&with_field(&encoded, "threshold", Value::Int(4))),
        Err(EnvelopeError::InvalidThreshold {
            threshold: 4,
            committee: 3
        })
    );
    assert_eq!(
        SealedEnvelope::from_value(&with_field(
            &encoded,
            "sealed_shares",
            Value::Array(Vec::new())
        )),
        Err(EnvelopeError::EmptyCommittee)
    );
    assert_eq!(
        SealedEnvelope::from_value(&with_field(&encoded, "version", Value::Int(99))),
        Err(EnvelopeError::UnsupportedVersion { version: 99 })
    );
    assert!(
        SealedEnvelope::from_value(&with_field(&encoded, "type", Value::string("commitment")))
            .is_err()
    );
    assert!(SealedEnvelope::from_value(&without_field(&encoded, "aad")).is_err());
    assert!(SealedEnvelope::from_value(&Value::Array(Vec::new())).is_err());

    // Uppercase hex is a second spelling of one envelope, and therefore a second
    // digest for one submission. A fixed 12-byte nonce with letters in it, so the
    // case check is actually exercised rather than passing on all-digit hex.
    assert_eq!(
        SealedEnvelope::from_value(&with_field(
            &encoded,
            "nonce",
            Value::string("AABBCCDDEEFF001122334455")
        )),
        Err(EnvelopeError::InvalidHex { field: "nonce" })
    );

    // Two shares addressed to one member.
    let shares = encoded
        .get("sealed_shares")
        .and_then(Value::as_array)
        .expect("array");
    let first = shares.first().cloned().expect("a share");
    let duplicated = Value::array([first.clone(), first.clone()]);
    let index = first
        .get("index")
        .and_then(Value::as_i128)
        .and_then(|i| u8::try_from(i).ok())
        .expect("index");
    assert_eq!(
        SealedEnvelope::from_value(&with_field(&encoded, "sealed_shares", duplicated)),
        Err(EnvelopeError::DuplicateShareIndex { index })
    );
}

// ==========================================================================
// Identity
// ==========================================================================

/// Attack: **losing a per-objective key and therefore the payout.** Derivation
/// must be deterministic, so a submitter who kept only the seed can always speak
/// for a pseudonym again — including for objectives they have forgotten.
#[test]
fn pseudonyms_are_stable_for_one_objective() {
    let seed = MasterSeed::generate(&mut OsRng);
    let first = seed.pseudonym("RQ-ECDLP-001");
    let second = seed.pseudonym("RQ-ECDLP-001");

    assert_eq!(first.public(), second.public());
    assert_eq!(first.submitter_id(), second.submitter_id());

    // And the same after a backup/restore cycle through the seed bytes.
    let restored = MasterSeed::from_bytes(*seed.to_bytes());
    assert_eq!(restored.pseudonym("RQ-ECDLP-001").public(), first.public());
}

/// Attack: **a state correlating one participant's work across objectives**
/// (§3, layer 1). Distinct objectives must yield unrelated keys, including for
/// objective ids that differ only by a suffix, where a sloppy `H(seed || id)`
/// transcript could collide.
#[test]
fn pseudonyms_differ_across_objectives() {
    let seed = MasterSeed::generate(&mut OsRng);
    let ids = [
        "RQ-ECDLP-001",
        "RQ-ECDLP-002",
        "RQ-ECDLP-0011",
        "RQ-ECDLP-001 ",
        "",
        "RQ",
        "rq-ecdlp-001",
    ];

    let keys: Vec<VerifyingKeyBytes> = ids.iter().map(|id| seed.pseudonym(id).public()).collect();
    for (i, a) in keys.iter().enumerate() {
        for (j, b) in keys.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "ids {:?} and {:?} share a pseudonym", ids[i], ids[j]);
            }
        }
    }
}

/// Attack: **guessing the seed.** Two seeds must give unrelated pseudonyms for
/// the same objective; if they did not, a published pseudonym would be evidence
/// about the seed behind it.
#[test]
fn pseudonyms_differ_across_seeds() {
    let a = MasterSeed::generate(&mut OsRng);
    let b = MasterSeed::generate(&mut OsRng);
    assert_ne!(a.pseudonym("RQ-1").public(), b.pseudonym("RQ-1").public());

    // Adjacent seeds too: a one-bit difference must not produce a related key.
    let mut bytes = [0u8; 32];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    let one = MasterSeed::from_bytes(bytes);
    let mut nudged = bytes;
    let first = nudged.first_mut().expect("non-empty");
    *first ^= 0x01;
    let other = MasterSeed::from_bytes(nudged);
    assert_ne!(
        one.pseudonym("RQ-1").public(),
        other.pseudonym("RQ-1").public()
    );
}

/// The baseline: a pseudonym can sign, and its signature verifies against the
/// public key alone — which is all a validator ever has.
#[test]
fn sign_and_verify_round_trip() {
    let identity = MasterSeed::generate(&mut OsRng).pseudonym("RQ-1");
    let record = Value::object([
        ("type", Value::string("claim")),
        ("objective", Value::string("RQ-1")),
        ("commitment", Value::string("sha256:abcd")),
    ]);

    let signature = identity.sign_value(&record);
    assert!(verify_value(&identity.public().to_bytes(), &record, &signature).is_ok());

    let message = b"detached bytes";
    let over_bytes = identity.sign_bytes(message);
    assert!(verify_bytes(&identity.public().to_bytes(), message, &over_bytes).is_ok());

    let signed = SignedRecord::sign(&identity, record.clone());
    assert!(signed.verify().is_ok());
    assert!(signed
        .verify_signed_by(&identity.public().to_bytes())
        .is_ok());
    assert_eq!(signed.submitter_id(), identity.submitter_id());
    assert_eq!(signed.public(), identity.public());
}

/// Attack: **editing a signed record after the fact** — changing the objective,
/// the commitment, the amount, adding a field, or deleting one. The signature is
/// over the canonical encoding, so every one of these must break it.
#[test]
fn tampering_with_any_field_breaks_verification() {
    let identity = MasterSeed::generate(&mut OsRng).pseudonym("RQ-1");
    let record = Value::object([
        ("type", Value::string("claim")),
        ("objective", Value::string("RQ-1")),
        ("submitter", Value::string(identity.submitter_id())),
        ("amount", Value::Int(1_000)),
        ("cites", Value::array([Value::string("EV-1")])),
        (
            "meta",
            Value::object([("epoch", Value::Int(7)), ("class", Value::string("public"))]),
        ),
    ]);
    let signed = SignedRecord::sign(&identity, record.clone());

    let keys: Vec<String> = record
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect();

    for key in &keys {
        // Replace the field with something structurally valid but different.
        let mut tampered = signed.clone();
        tampered.record = with_field(&record, key, Value::string("tampered"));
        assert_eq!(
            tampered.verify(),
            Err(IdentityError::BadSignature),
            "replacing field {key:?} was not detected"
        );

        // Remove it entirely.
        let mut removed = signed.clone();
        removed.record = without_field(&record, key);
        assert_eq!(
            removed.verify(),
            Err(IdentityError::BadSignature),
            "removing field {key:?} was not detected"
        );
    }

    // Adding a field the signer never saw.
    let mut extended = signed.clone();
    extended.record = with_field(&record, "bonus", Value::Int(1));
    assert_eq!(extended.verify(), Err(IdentityError::BadSignature));

    // A nested edit, one level down.
    let mut nested = signed.clone();
    let meta = record.get("meta").cloned().expect("meta");
    nested.record = with_field(&record, "meta", with_field(&meta, "epoch", Value::Int(8)));
    assert_eq!(nested.verify(), Err(IdentityError::BadSignature));

    // A one-bit change in the signature itself, at every byte position.
    for i in 0..64 {
        let mut bytes = signed.signature.to_bytes();
        let slot = bytes.get_mut(i).expect("in range");
        *slot ^= 0x01;
        let mut forged = signed.clone();
        forged.signature = Signature::from_bytes(bytes);
        assert!(
            forged.verify().is_err(),
            "flipping signature byte {i} still verified"
        );
    }

    // Untouched, it still verifies -- otherwise the assertions above prove nothing.
    assert!(signed.verify().is_ok());
}

/// Attack: **claiming someone else's work by swapping the key on a valid
/// record.** A signature from key A must not verify under key B, and asking for a
/// specific signer must report the authorization failure distinctly from a
/// forgery, because the remedies differ.
#[test]
fn cross_key_verification_fails() {
    let seed = MasterSeed::generate(&mut OsRng);
    let mine = seed.pseudonym("RQ-1");
    let theirs = seed.pseudonym("RQ-2");
    let stranger = Identity::generate(&mut OsRng);

    let record = Value::object([("claim", Value::string("mine"))]);
    let signed = SignedRecord::sign(&mine, record.clone());

    // Substituting another key into an otherwise valid record.
    let mut swapped = signed.clone();
    swapped.public_key = theirs.public().to_bytes();
    assert_eq!(swapped.verify(), Err(IdentityError::BadSignature));

    assert_eq!(
        verify_value(&stranger.public().to_bytes(), &record, &signed.signature),
        Err(IdentityError::BadSignature)
    );

    // Authentic, but not from the pseudonym the caller required.
    match signed.verify_signed_by(&theirs.public().to_bytes()) {
        Err(IdentityError::WrongSigner { expected, actual }) => {
            assert_eq!(expected, theirs.submitter_id());
            assert_eq!(actual, mine.submitter_id());
        }
        other => panic!("expected WrongSigner, got {other:?}"),
    }
}

/// Attack: **an authentication bypass through a small-order public key**, which
/// verifies signatures nobody needed a secret to produce, and through the
/// all-zero signature that `sign_bytes` returns on its documented impossible
/// path. Neither may ever verify.
#[test]
fn weak_keys_and_null_signatures_never_verify() {
    let identity = Identity::generate(&mut OsRng);
    let message = b"anything";

    assert_eq!(
        verify_bytes(&[0u8; 32], message, &identity.sign_bytes(message)),
        Err(IdentityError::InvalidPublicKey)
    );
    assert!(
        !VerifyingKeyBytes::from_bytes([0u8; 32]).is_usable(),
        "a small-order key must not be reported as usable"
    );
    assert!(identity.public().is_usable(), "a real key is usable");

    assert_eq!(
        verify_bytes(
            &identity.public().to_bytes(),
            message,
            &Signature::from_bytes([0u8; 64])
        ),
        Err(IdentityError::BadSignature)
    );
}

/// A trap for the unwary caller, pinned as behaviour: `verify` is
/// **authentication, not authorization**. A record whose own `submitter` field
/// names someone else still verifies, because a validator co-signing another
/// party's record is legitimate. Callers binding a record to its author must
/// compare `submitter_id` themselves.
#[test]
fn verification_is_authentication_not_authorization() {
    let seed = MasterSeed::generate(&mut OsRng);
    let signer = seed.pseudonym("RQ-1");
    let victim = seed.pseudonym("RQ-2");

    let record = Value::object([
        ("type", Value::string("claim")),
        ("submitter", Value::string(victim.submitter_id())),
    ]);
    let signed = SignedRecord::sign(&signer, record);

    assert!(signed.verify().is_ok(), "the bytes are authentic");
    assert_ne!(
        signed.submitter_id(),
        victim.submitter_id(),
        "but the signer is not who the record names"
    );
    assert_eq!(
        signed.verify_signed_by(&victim.public().to_bytes()),
        Err(IdentityError::WrongSigner {
            expected: victim.submitter_id(),
            actual: signer.submitter_id(),
        })
    );
}

/// The wire form must round-trip exactly, and must refuse encodings that could
/// give one signed record two spellings — the disagreement `canonical.rs` exists
/// to prevent.
#[test]
fn signed_record_wire_form_round_trips_and_refuses_ambiguity() {
    let identity = Identity::generate(&mut OsRng);
    let record = Value::object([
        ("type", Value::string("claim")),
        ("n", Value::Int(-5)),
        ("null", Value::Null),
        ("flag", Value::Bool(false)),
    ]);
    let signed = SignedRecord::sign(&identity, record);
    let encoded = signed.to_value();

    let decoded = SignedRecord::from_value(&encoded).expect("round trip");
    assert_eq!(decoded, signed);
    assert!(decoded.verify().is_ok());

    assert_eq!(
        SignedRecord::from_value(&with_field(&encoded, "version", Value::Int(2))),
        Err(IdentityError::UnsupportedVersion { version: 2 })
    );
    assert!(SignedRecord::from_value(&with_field(
        &encoded,
        "type",
        Value::string("sealed_envelope")
    ))
    .is_err());
    assert!(SignedRecord::from_value(&without_field(&encoded, "record")).is_err());
    assert!(SignedRecord::from_value(&without_field(&encoded, "signature")).is_err());
    assert!(SignedRecord::from_value(&Value::string("nope")).is_err());

    // A fixed uppercase signature of the right length: the length check passes, so
    // it is genuinely the case rule doing the rejecting.
    assert_eq!(
        SignedRecord::from_value(&with_field(
            &encoded,
            "signature",
            Value::string("AB".repeat(64))
        )),
        Err(IdentityError::InvalidHex { field: "signature" })
    );
    assert!(SignedRecord::from_value(&with_field(
        &encoded,
        "public_key",
        Value::string("00112233")
    ))
    .is_err());

    // Signature and key wrappers round-trip on their own too.
    assert_eq!(
        Signature::from_value(&signed.signature.to_value()).expect("round trip"),
        signed.signature
    );
    assert_eq!(
        VerifyingKeyBytes::from_value(&identity.public().to_value()).expect("round trip"),
        identity.public()
    );
    assert_eq!(
        VerifyingKeyBytes::from_hex(&"AB".repeat(32)),
        Err(IdentityError::InvalidHex {
            field: "public_key"
        })
    );
}

/// Attack: **a secret harvested from a log file.** Debug output is the most
/// common way key material escapes a process, and it escapes to whoever reads
/// logs, which is a much larger set than whoever can read memory. Nothing that
/// holds key material may print it.
#[test]
fn debug_output_contains_no_secret_material() {
    let mut seed_bytes = [0u8; 32];
    for (i, slot) in seed_bytes.iter_mut().enumerate() {
        *slot = (i as u8).wrapping_mul(11).wrapping_add(29);
    }
    let seed_hex = hex(&seed_bytes);
    let seed = MasterSeed::from_bytes(seed_bytes);

    let rendered = format!("{seed:?}");
    assert!(
        !rendered.contains(&seed_hex),
        "seed hex in Debug: {rendered}"
    );
    assert!(
        !rendered.contains(seed_hex.get(..16).expect("prefix")),
        "seed prefix in Debug: {rendered}"
    );
    assert!(rendered.contains("redacted"), "{rendered}");

    // A per-objective identity: the public half may print, the secret half must not.
    let identity = seed.pseudonym("RQ-1");
    let secret_hex = hex(identity.to_secret_bytes().as_slice());
    let rendered = format!("{identity:?}");
    assert!(
        !rendered.contains(&secret_hex),
        "signing key in Debug: {rendered}"
    );
    assert!(
        !rendered.contains(secret_hex.get(..16).expect("prefix")),
        "signing key prefix in Debug: {rendered}"
    );
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(
        rendered.contains(&identity.public().to_hex()),
        "the public key is what a log line is for"
    );

    // A committee member's KEM secrets, one per suite, and the Secret32
    // wrapper. Every leg is checked, not just the first: a Debug impl that
    // redacted McEliece and printed the ML-KEM seed would leak a whole leg.
    let committee_key = CommitteeKey::generate(&mut OsRng);
    let rendered = format!("{committee_key:?}");
    for secret in committee_key.secrets().keys() {
        let stored_hex = hex(secret.expose());
        assert!(
            !rendered.contains(&stored_hex),
            "committee {} secret in Debug: {rendered}",
            secret.suite()
        );
    }
    assert!(rendered.contains("redacted"), "{rendered}");

    let exported = Secret32::new([0x11u8; 32]);
    let rendered = format!("{exported:?}");
    assert!(
        !rendered.contains(&hex(exported.expose())),
        "Secret32 leaked: {rendered}"
    );
    assert!(rendered.contains("redacted"), "{rendered}");
}

/// A throwaway `Identity::generate` must be unlinkable to any seed-derived
/// pseudonym — that is the "maximal anonymity, no citation income" option in §3,
/// and it would be worthless if the two constructors landed in the same keyspace.
#[test]
fn independently_generated_identities_are_unrelated_to_any_seed() {
    let seed = MasterSeed::generate(&mut OsRng);
    let throwaway = Identity::generate(&mut OsRng);

    for id in ["RQ-1", "RQ-2", ""] {
        assert_ne!(throwaway.public(), seed.pseudonym(id).public());
    }

    // And it survives a store/reload cycle, since nothing can recompute it.
    let reloaded = Identity::from_secret_bytes(*throwaway.to_secret_bytes());
    assert_eq!(reloaded.public(), throwaway.public());
}

/// Regenerate `conformance/signatures.json`, which the reference
/// implementation verifies against via `cairn-reference signatures`.
///
/// The other conformance vectors flow Python -> Rust. These flow the other
/// way, and they have to: Python verifies signatures with a hand-written
/// ed25519 and deliberately cannot sign, so "both implementations agree" can
/// only be shown against signatures this one actually produced. Passing the
/// same RFC vectors would not establish it -- two implementations can both
/// satisfy RFC 8032 and still disagree on the strictness rules where honest
/// implementations differ, which is exactly where a consensus split would
/// live.
///
/// Set `CAIRN_WRITE_VECTORS=1` to rewrite the file; otherwise this
/// asserts the committed vectors still verify, so a change to signing or to
/// canonical encoding fails here rather than in a peer's log.
#[test]
fn signature_vectors_match_the_committed_file() {
    use cairn::canonical::Value;
    use cairn::crypto::identity::{verify_value, Identity, Signature, VerifyingKeyBytes};

    let mut vectors = Vec::new();
    for seed in 0u8..6 {
        let identity = Identity::from_secret_bytes([seed.wrapping_mul(37).wrapping_add(1); 32]);
        let record = Value::object([
            ("type", Value::string("claim")),
            ("submitter", Value::string(identity.submitter_id())),
            ("n", Value::Int(i128::from(seed))),
        ]);
        let signature = identity.sign_value(&record);
        vectors.push(Value::object([
            ("public_key", Value::string(identity.submitter_id())),
            (
                "message_hex",
                Value::string(
                    record
                        .canonical_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                ),
            ),
            ("signature", Value::string(signature.to_hex())),
        ]));
    }
    let produced = Value::Array(vectors).canonical_string();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/signatures.json");

    if std::env::var("CAIRN_WRITE_VECTORS").is_ok() {
        std::fs::write(path, format!("{produced}\n")).expect("write vectors");
        return;
    }

    let committed = std::fs::read_to_string(path).expect("conformance/signatures.json is missing");
    assert_eq!(
        committed.trim(),
        produced,
        "signature vectors moved -- signing or canonical encoding changed"
    );

    // And every committed vector must verify here, so the file cannot rot
    // into something only the generator agrees with.
    let parsed = Value::from_json(committed.trim()).expect("vectors parse");
    for vector in parsed.as_array().expect("an array") {
        let key = VerifyingKeyBytes::from_hex(
            vector
                .get("public_key")
                .and_then(Value::as_str)
                .expect("key"),
        )
        .expect("valid key");
        let message: Vec<u8> = {
            let hex = vector
                .get("message_hex")
                .and_then(Value::as_str)
                .expect("message");
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect()
        };
        let signature = Signature::from_hex(
            vector
                .get("signature")
                .and_then(Value::as_str)
                .expect("sig"),
        )
        .expect("valid signature");
        let value = Value::from_json(&String::from_utf8(message).expect("utf8")).expect("record");
        verify_value(key.as_bytes(), &value, &signature).expect("committed vector verifies");
    }
}
