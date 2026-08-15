//! A negative claim about verification, checked instead of asserted.
//!
//! > Every verifier kind re-executes. Soundness here is *reproducibility*, not
//! > the soundness of an argument system, and there is no Fiat–Shamir transform
//! > anywhere in the settlement path.
//!
//! That sentence is why this repository is not exposed to
//! [Khovratovich–Rothblum–Soukhanov](https://eprint.iacr.org/2025/118), which
//! builds circuits where a GKR-based succinct argument, made non-interactive by
//! Fiat–Shamir, proves **false statements**. The immunity is a property of the
//! ladder rather than a law, and it ends the moment somebody adds a kind that
//! checks a proof instead of re-running a computation.
//!
//! Nobody would add an unsound verifier on purpose. What happens instead is that
//! a sixth kind arrives for a good reason — zkML, a succinct proof over the
//! checker's execution, `sealed` finally getting its zero-knowledge path — and
//! the constraints in `docs/verification.md` are three years old and nobody
//! reads a document they do not know exists. A negative property with no test is
//! a negative property with an expiry date, which is the same argument
//! `cipher_policy.rs` makes about AES.
//!
//! So this pins the set. Adding a kind fails here, and the failure says where to
//! read before deciding the kind is safe. It cannot tell a sound construction
//! from an unsound one — no test can — so it does the one thing a test can do:
//! guarantee the question gets asked.

use proofwork::canonical::Value;
use proofwork::records::{Confidentiality, Objective};
use proofwork::verifiers::Kind;

/// Every kind this build dispatches, and every one of them re-executes.
///
/// Written out rather than derived from `Kind::ALL`, because a list that
/// updates itself pins nothing.
const RE_EXECUTING: [&str; 5] = ["certificate", "evaluator", "lean", "replay", "statistical"];

#[test]
fn every_verifier_kind_re_executes_and_none_checks_a_proof() {
    let live: Vec<&str> = Kind::ALL.iter().map(|kind| kind.as_str()).collect();
    assert_eq!(
        live, RE_EXECUTING,
        "The verifier ladder changed.\n\n\
         Every kind above re-executes: it runs the pinned code and compares, and \
         `audit --rerun` does it again from the artifacts. That is why soundness \
         here is reproducibility rather than the soundness of an argument system, \
         and why no Fiat-Shamir transform exists in the settlement path to attack.\n\n\
         If the new kind also re-executes, add it to RE_EXECUTING and carry on.\n\n\
         If it checks a *proof*, read `docs/verification.md`, section \"The rule \
         for any proof-system verifier\", first. The short version: do not \
         Fiat-Shamir an argument over a circuit the prover chose; a derived \
         challenge is only as unpredictable as the part of its input the \
         adversary cannot choose; and verifiers here are funder-authored, so a \
         proof-system kind must pin the circuit family in the protocol rather \
         than in the objective."
    );
}

#[test]
fn the_sealed_refusal_routes_a_would_be_implementer_to_the_constraint() {
    // `records.rs` already tests *that* sealed is refused. This tests what the
    // refusal **says**, which is the part that has to survive: the person who
    // eventually builds zero-knowledge settlement reads this string, not the
    // threat model, and an error that names only the missing feature sends them
    // off to add it without the constraint attached.
    //
    // If this fails because `sealed` was implemented, the test that replaces it
    // is not "does it round-trip". It is "what pins the circuit family, and what
    // stops the challenge being ground".
    let error = Objective::new(
        "GOAL-x",
        "do the thing",
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string("aa".repeat(32))),
            ("entrypoint", Value::string("check")),
        ]),
        1000,
        "treasury",
        "2026-07-28T00:00:00+00:00",
        None,
        None,
    )
    .expect("valid objective")
    .with_confidentiality(Confidentiality::Sealed)
    .expect_err("sealed must still be refused");

    let message = error.to_string();
    for expected in [
        "zero-knowledge",
        "embargoed",
        "verification.md",
        "Fiat-Shamir",
    ] {
        assert!(
            message.contains(expected),
            "the sealed refusal must mention {expected:?} -- it is the only place a \
             would-be implementer is guaranteed to look. Got: {message}"
        );
    }
}
