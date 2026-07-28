//! The confidentiality layer: sealed submissions, threshold reveal, and
//! pseudonymous identity.
//!
//! The design this implements is `docs/censorship.md`. Read it before changing
//! anything here; the reasoning is the part that is hard to reconstruct.
//!
//! # The problem, in one paragraph
//!
//! Plain commit–reveal requires the submitter to act **twice**: commit, then
//! reveal (§1). An adversary who can neither forge nor steal your work can still
//! take it by stopping the second action — a targeted DoS, a network block, a
//! detention, a seized laptop, or a sequencer that drops your reveal until the
//! deadline passes. Your commitment sits on the log proving you had the answer
//! first, and you cannot collect. The attack costs almost nothing and breaks no
//! cryptography.
//!
//! # The fix
//!
//! Submit the artifact **encrypted, at commit time**, and let a threshold
//! committee open it at the epoch boundary, so the reveal happens **without the
//! submitter** (§2):
//!
//! ```text
//! commit    commitment = H(artifact ‖ submitter ‖ nonce)      (unchanged)
//!           envelope   = ChaCha20-Poly1305(K, {artifact, nonce})
//!           shares     = Shamir(K, t of n), share_i sealed to member i
//!                        via X25519 + AEAD
//!             ↓
//! epoch end ≥ t members publish their shares
//!             ↓
//! reveal    anyone reconstructs K, decrypts, and checks the plaintext against
//!           the commitment. Mismatch ⇒ invalid submission.
//! ```
//!
//! Three properties fall out at once. Reveal-window censorship dies, because
//! nothing is required of the submitter after commit. In-flight front-running
//! dies, because nobody — sequencer included — sees the artifact while they could
//! still act on it. And selective censorship becomes *visible*: a sequencer that
//! cannot see what it is dropping must include everything or censor
//! indiscriminately, and indiscriminate censorship is detectable by everyone at
//! once. Forcing an attacker from targeted to indiscriminate is most of the win.
//!
//! # Binding, not secrecy, is what makes this safe
//!
//! Encryption is the mechanism; **binding** is the security argument, and it is
//! free. The commitment is already a hash of the plaintext
//! ([`crate::records::commitment_hash`]), so a submitter who seals garbage is
//! caught the moment the committee opens it. No new trust is introduced on that
//! axis, which is why [`crate::sealed::open`] re-derives the commitment and why
//! that check is not optional.
//!
//! Sealing moves **when** an artifact becomes public. It never moves **whether**.
//! Once opened, the artifact is public and anyone re-runs the pinned verifier
//! exactly as before — the guarantee the whole project exists for is untouched.
//!
//! # Layout
//!
//! - [`shamir`] — `t`-of-`n` secret sharing over GF(2^8). The reconstruction path
//!   for the content key. Note its central caveat: `combine` **cannot** report
//!   "too few shares", and that is the security property, not a defect.
//! - [`envelope`] — one AEAD over the payload, with the content key split across
//!   the committee and each share sealed to a member's X25519 key. Binds
//!   everything to the submission's commitment via the AEAD associated data.
//! - [`identity`] — per-objective pseudonyms derived from one seed, and detached
//!   signatures over canonical bytes (§3, layer 1).
//!
//! The submission flow that ties the three together is [`crate::sealed`].
//!
//! # What this layer does NOT provide
//!
//! Stated plainly, because a confidentiality layer that is oversold is worse than
//! none: people rely on the parts that do not exist.
//!
//! - **It does not stop a sequencer that includes nothing.** Blind inclusion
//!   defeats *targeted* censorship — the sequencer cannot tell which submission to
//!   drop — and does nothing about total refusal. That needs forced inclusion on a
//!   base layer, and it remains the primary unresolved threat at Stage 0 (§7, §8).
//! - **It does not hide the citation graph.** If your claim cites mine and value
//!   flows to me, the edge between us is public *by construction* — that graph is
//!   the attribution mechanism. Pseudonyms hide the mapping from a name to a
//!   person; nothing hides the graph, because paying people for being built upon
//!   is what the graph is for. A participant who wants maximal anonymity should
//!   expect to forfeit citation income and should choose that explicitly (§3).
//! - **It does not defeat a global traffic-analysis observer.** The log still
//!   shows which objectives received submissions, how many, roughly how large, and
//!   when. Fixed-size envelopes and batch-boundary publication narrow that; only
//!   **cover traffic** defeats a global observer, it is not implemented here, and
//!   it is the mitigation nobody wants to pay for (§4).
//! - **It does not survive `t` colluding committee members.** They can read early
//!   and front-run. Rotation, diversity, and a high threshold make collusion
//!   expensive; nothing here makes it impossible (§2, §8).
//! - **It does not reach the network layer.** Encrypted content over a blocked
//!   network is still blocked; that needs pluggable transports, and no single
//!   submission endpoint (§5).
//! - **It does not answer a legal order against the operator.** Stage 0 has one
//!   operator. Encryption does not change who can be served a subpoena; only
//!   decentralized inclusion does (§7).

pub mod envelope;
pub mod identity;
pub mod shamir;

pub use envelope::{
    CommitteeKey, CommitteeMember, EnvelopeError, SealedEnvelope, SealedShare, Secret32,
};
pub use identity::{
    verify_bytes, verify_value, Identity, IdentityError, MasterSeed, Signature, SignedRecord,
    VerifyingKeyBytes,
};
pub use shamir::{combine, split, ShamirError, Share};
