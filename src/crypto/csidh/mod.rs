//! Vendored: CSIDH-512, from the `csidh` crate v0.5.0.
//!
//! Upstream <https://github.com/TitouanReal/csidh>, Apache-2.0 OR MIT; both
//! licence texts sit beside this file. Vendored rather than depended on for
//! exactly one reason: **the published API cannot serialise a public key or a
//! shared secret.** `PublicKey::key` and `SharedSecret::shared_secret` are
//! `pub(crate)`, and a `Bundle` has to publish key bytes, hash them into an id,
//! and feed the shared secret to the combiner. There is no way to do any of
//! that from outside the crate, and no newer release that adds one.
//!
//! # What was changed
//!
//! Two accessors, and nothing else. The isogeny arithmetic is byte-for-byte
//! upstream\'s, deliberately -- a local edit to a group-action implementation
//! nobody here is qualified to review would be worse than the vendoring.
//!
//! * `PublicKey::to_bytes` / `PublicKey::from_bytes` -- canonical little-endian
//!   of the Montgomery coefficient `A`, retrieved *out* of Montgomery form so
//!   the bytes are the curve parameter rather than an internal representation.
//!   The read path goes through upstream\'s own `PublicKey::new`, so a decoded
//!   key is still supersingularity-checked.
//! * `SharedSecret::to_bytes` -- the same retrieval, for the combiner.
//! * **CSIDH-1024 and CSIDH-1792 removed**, with their tests. `Suite::Csidh512`
//!   is the only parameter set this crate exposes, and vendoring two more meant
//!   carrying cryptography nobody here uses and cannot review -- plus their
//!   tests, which are far slower than the 512 ones and were minutes of every
//!   `cargo test`. Restoring them is a copy from upstream if a caller ever
//!   needs one.
//! * The vendored tests draw from `rand_core::OsRng` rather than
//!   `rand::thread_rng()`, which is an API this crate's `rand` version does not
//!   have. They are kept rather than deleted: they exercise the isogeny
//!   arithmetic, which the vendoring made this repository's responsibility.
//!
//! # What it does not fix
//!
//! Upstream says it plainly and so does this: **not constant-time.** The group
//! action branches on the private key, so a local attacker who can time it
//! recovers that key. That is why `Suite::Csidh512` carries
//! `Assurance::Contested`, is never in the default suite set, and can never be
//! a bundle\'s mandatory leg -- see [`crate::crypto::kem`]. In a bundle whose
//! McEliece leg is sound, a fully recovered CSIDH secret still opens nothing.

// Upstream's file layout, kept rather than tidied. Renaming `csidh.rs` would
// mean a diff against the released crate in a file full of isogeny arithmetic,
// which is the one thing this vendoring is trying not to have -- the two added
// accessors are the whole intended delta, and every other line should stay
// greppable against upstream.
#[allow(clippy::module_inception)]
mod csidh;
pub mod csidh_params;
mod montgomery_curve;
mod montgomery_point;
mod private_key;
mod public_key;
mod shared_secret;

#[doc(no_inline)]
pub use crypto_bigint::{impl_modulus, modular::ConstMontyForm, Uint};

pub use csidh_params::CsidhParams;
pub use private_key::{PrivateKey, PrivateKeyCsidh512};
pub use public_key::PublicKey;
pub use shared_secret::SharedSecret;
