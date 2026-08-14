//! Post-quantum peer handshake: Classic McEliece KEM to a long-term key.
//!
//! # Why the key sizes decide the protocol
//!
//! Measured on this machine, `mceliece348864`:
//!
//! | operation | cost | size |
//! |---|---|---|
//! | keygen | 243 ms | public key **261,120 bytes** |
//! | encapsulate | 22 µs | ciphertext **96 bytes** |
//! | decapsulate | 12 ms | shared secret 32 bytes |
//!
//! A 255 KB public key cannot travel in every handshake, and a 243 ms keygen
//! cannot happen per connection. So the public key is a peer's **long-term
//! identity**: published once, fetched once, cached by id thereafter. After
//! that a handshake costs 96 bytes on the wire — smaller than an X25519
//! exchange plus a certificate, which is a genuinely good trade for gossip.
//!
//! # What this does and does not give you
//!
//! * **Confidentiality against a quantum adversary.** Classic McEliece is the
//!   most conservative KEM available: the underlying problem has resisted
//!   attack since 1978, which is the reason to accept the key size.
//! * **Responder authentication, implicitly.** Only the holder of the secret
//!   key can decapsulate, so a session that decrypts proves you are talking to
//!   the owner of that public key.
//! * **No initiator authentication.** The KEM says nothing about who
//!   encapsulated. Peers that must prove who they are sign the transcript with
//!   the ed25519 identity in [`crate::crypto::identity`] — that layer already
//!   exists and this one deliberately does not duplicate it.
//! * **No forward secrecy.** This is the real cost of a static key, and it is
//!   stated rather than buried: if a peer's McEliece secret leaks, every past
//!   session it accepted becomes decryptable to whoever recorded the traffic.
//!   Ephemeral keypairs would fix it and cost 243 ms plus 255 KB per
//!   connection, which no gossip protocol can pay. The mitigation available
//!   here is key rotation, and a peer's id changes when it rotates.
//!
//! # The amplification a deployment must handle
//!
//! Encapsulation costs 22 µs; decapsulation costs 12 ms. A 96-byte message
//! therefore buys about **125,000× its cost in CPU** from the responder. That
//! is a denial-of-service asymmetry, not a cryptographic weakness, and it is
//! the responder's problem to price: rate-limit per source, or require
//! something cheap-to-verify and expensive-to-produce before decapsulating.
//! Nothing in this module does that for you.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use classic_mceliece_rust::{CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

use crate::crypto::kem::{
    Bundle, Encapsulated, Leg, PublicKey as KemPublicKey, SecretBundle, SecretKey as KemSecretKey,
    Suite,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;

/// A peer's identity: the SHA-256 of its public key.
///
/// 32 bytes rather than 255 KB, so peer references stay small everywhere. It
/// commits to the key, so citing an id and fetching the key later is safe.
pub type PeerId = [u8; 32];

/// Domain separation. Changing any of these changes every derived key.
const KDF_DOMAIN: &str = "proofwork/p2p/mceliece/v1";
const LABEL_I2R: &str = "initiator-to-responder";
const LABEL_R2I: &str = "responder-to-initiator";

/// Errors from the handshake or the channel it produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// A public key blob was not exactly `CRYPTO_PUBLICKEYBYTES` long.
    BadPublicKeyLength { got: usize },
    /// A secret key blob was not exactly `CRYPTO_SECRETKEYBYTES` long.
    BadSecretKeyLength { got: usize },
    /// A ciphertext was not exactly `CRYPTO_CIPHERTEXTBYTES` long.
    BadCiphertextLength { got: usize },
    /// The frame did not authenticate: wrong key, wrong transcript, or
    /// tampering. Deliberately one variant — telling an attacker *which* is
    /// free help.
    NotAuthentic,
    /// A frame arrived with a counter at or below one already accepted.
    Replay { counter: u64, expected_above: u64 },
    /// The send counter is exhausted. Rekey rather than wrap.
    CounterExhausted,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::BadPublicKeyLength { got } => write!(
                f,
                "public key must be {CRYPTO_PUBLICKEYBYTES} bytes, got {got}"
            ),
            HandshakeError::BadSecretKeyLength { got } => write!(
                f,
                "secret key must be {CRYPTO_SECRETKEYBYTES} bytes, got {got}"
            ),
            HandshakeError::BadCiphertextLength { got } => write!(
                f,
                "ciphertext must be {CRYPTO_CIPHERTEXTBYTES} bytes, got {got}"
            ),
            HandshakeError::NotAuthentic => f.write_str("frame did not authenticate"),
            HandshakeError::Replay {
                counter,
                expected_above,
            } => write!(
                f,
                "replayed or reordered frame: counter {counter}, expected above {expected_above}"
            ),
            HandshakeError::CounterExhausted => {
                f.write_str("send counter exhausted; rekey rather than reuse a nonce")
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

/// A peer's long-term keypair.
///
/// Generating one costs ~243 ms, so generate it once and persist it. Not
/// `Clone`: two copies of a secret key are two things to lose.
///
/// # Why this is a bundle and not a McEliece keypair
///
/// It was a bare `mceliece348864` keypair, so a session key rested on one
/// hardness family with no combiner in front of it — while a *committee share*
/// travelling over that session was sealed to a whole bundle. Protecting the
/// cargo and not the road. The 2026 cryptanalysis of binary Goppa codes made
/// the asymmetry worth closing: see `crypto::kem::Family`.
///
/// The id is unchanged, and that is the whole reason this was affordable.
/// [`peer_id_of`] delegates to [`crate::crypto::kem::key_id`], which hashes the
/// **McEliece leg only**, so an identity that grows legs keeps its
/// [`PeerId`] — it stays in the DHT, its bootstrap files stay valid, and its
/// `PeerRecord` still names it. Nothing about this change reaches the log.
pub struct PeerIdentity {
    secrets: SecretBundle,
    public: Bundle,
    id: PeerId,
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the secret, and never the 255 KB public key.
        write!(f, "PeerIdentity({})", short(&self.id))
    }
}

impl PeerIdentity {
    /// Generate a fresh long-term identity over every suite this build has.
    ///
    /// ~243 ms, which is McEliece's keygen and unchanged: the other legs cost
    /// microseconds. A new identity is hedged by default, because an option
    /// nobody turns on protects nobody.
    pub fn generate() -> PeerIdentity {
        // What to publish comes from the policy, not from `SUITES`. Deprecating
        // a suite then stops new identities carrying it with no change here --
        // which is the difference between a registry and a comment.
        let (public, secrets) = SecretBundle::generate(
            &crate::crypto::policy::Policy::current().suites_to_publish(),
            &mut OsRng,
        );
        let id = public.id();
        PeerIdentity {
            secrets,
            public,
            id,
        }
    }

    /// Restore a **McEliece-only** identity from persisted key material.
    ///
    /// The shape an identity file written before bundles existed has, so it is
    /// kept and behaves exactly as it did. Such a node still accepts hedged
    /// handshakes it cannot benefit from — it simply has no extra legs to
    /// decapsulate — and its own sessions rest on one family until it is
    /// regenerated. [`PeerIdentity::from_secrets`] is the hedged constructor.
    pub fn from_bytes(public: &[u8], secret: &[u8]) -> Result<PeerIdentity, HandshakeError> {
        if public.len() != CRYPTO_PUBLICKEYBYTES {
            return Err(HandshakeError::BadPublicKeyLength { got: public.len() });
        }
        if secret.len() != CRYPTO_SECRETKEYBYTES {
            return Err(HandshakeError::BadSecretKeyLength { got: secret.len() });
        }
        let key = KemSecretKey::from_bytes(Suite::McEliece, secret, public)
            .map_err(|_| HandshakeError::BadSecretKeyLength { got: secret.len() })?;
        let secrets = SecretBundle::new([key])
            .map_err(|_| HandshakeError::BadSecretKeyLength { got: secret.len() })?;
        Ok(PeerIdentity::from_secrets(secrets))
    }

    /// Adopt a full secret bundle. The hedged path.
    pub fn from_secrets(secrets: SecretBundle) -> PeerIdentity {
        let public = secrets.public_bundle();
        let id = public.id();
        PeerIdentity {
            secrets,
            public,
            id,
        }
    }

    pub fn id(&self) -> PeerId {
        self.id
    }

    /// The 255 KB McEliece public key. Publish once; peers cache it by id.
    ///
    /// Still only the McEliece leg, because this is what the id is derived
    /// from and what every existing bootstrap file carries. A peer that wants
    /// the hedged handshake needs [`PeerIdentity::bundle`] as well.
    pub fn public_key(&self) -> &[u8] {
        self.mceliece_public()
    }

    /// The whole published bundle: what a peer must hold to hedge a session to
    /// this one.
    pub fn bundle(&self) -> &Bundle {
        &self.public
    }

    fn mceliece_public(&self) -> &[u8] {
        self.public
            .key_for(Suite::McEliece)
            .expect("a bundle always carries the mandatory leg")
            .as_bytes()
    }

    /// Secret key material for an explicitly persisted node identity.
    /// Callers must protect the returned bytes like any other private key.
    ///
    /// The McEliece leg only, matching the legacy identity-file shape.
    /// [`PeerIdentity::secrets`] is what persists a hedged identity whole.
    pub fn secret_key(&self) -> &[u8] {
        self.secrets
            .keys()
            .iter()
            .find(|key| key.suite() == Suite::McEliece)
            .expect("a bundle always carries the mandatory leg")
            .expose()
    }

    /// The whole secret bundle, for persisting a hedged identity.
    pub fn secrets(&self) -> &SecretBundle {
        &self.secrets
    }

    /// What other peers hold about this one.
    pub fn to_public(&self) -> PeerPublic {
        PeerPublic {
            bundle: self.public.clone(),
            id: self.id,
        }
    }

    /// Accept an incoming handshake, hedged or legacy.
    ///
    /// Costs ~12 ms. See the module docs on amplification before exposing this
    /// to unauthenticated traffic.
    ///
    /// # Which path, and why length is enough to tell
    ///
    /// There is no version byte and none is needed. A legacy handshake is
    /// exactly [`CRYPTO_CIPHERTEXTBYTES`]; a hedged one is the sum of this
    /// identity's own legs. The responder knows both numbers without asking, so
    /// it can serve old and new initiators at once — which is what lets
    /// responders upgrade unilaterally, with no flag day and no negotiation.
    ///
    /// Negotiation is what is being avoided. A protocol that *asked* which
    /// suites to use would be as strong as the weakest set an attacker could
    /// force, which is the downgrade attack `crypto::kem` refuses by only ever
    /// combining.
    ///
    /// # Truncation is a liveness attack, not a downgrade
    ///
    /// McEliece sorts first, so the first 96 bytes of a hedged ciphertext *are*
    /// a valid McEliece ciphertext, and an attacker can cut a hedged handshake
    /// down to the legacy path. It gains them nothing: the initiator derived
    /// its keys through the combiner over every leg, the responder would derive
    /// from the McEliece secret alone, the two disagree, and every frame fails
    /// to authenticate. The session dies and nothing is read — which an
    /// attacker who can truncate could achieve by dropping the packet anyway.
    pub fn accept(&self, initiator: PeerId, ciphertext: &[u8]) -> Result<Channel, HandshakeError> {
        let hedged_len: usize = self
            .public
            .suites()
            .iter()
            .map(|suite| suite.ciphertext_len())
            .sum();

        // Legacy first: for a McEliece-only identity the two lengths coincide,
        // and the legacy derivation is the one an old peer will agree with.
        let shared = if ciphertext.len() == CRYPTO_CIPHERTEXTBYTES {
            self.secrets
                .keys()
                .iter()
                .find(|key| key.suite() == Suite::McEliece)
                .expect("a bundle always carries the mandatory leg")
                .decapsulate(ciphertext)
                .map_err(|_| HandshakeError::BadCiphertextLength {
                    got: ciphertext.len(),
                })?
        } else if ciphertext.len() == hedged_len {
            let sealed = split_legs(&self.public, ciphertext)?;
            self.secrets
                .decapsulate(&sealed)
                .map_err(|_| HandshakeError::BadCiphertextLength {
                    got: ciphertext.len(),
                })?
        } else {
            return Err(HandshakeError::BadCiphertextLength {
                got: ciphertext.len(),
            });
        };

        // Classic McEliece is IND-CCA2: a malformed ciphertext yields a
        // pseudorandom shared secret rather than an error, so there is nothing
        // to check here. The mismatch surfaces at the first frame that fails to
        // authenticate, which is exactly where it should.
        Ok(Channel::new(
            derive(shared.expose(), initiator, self.id, ciphertext),
            Role::Responder,
        ))
    }
}

/// Split a concatenated handshake ciphertext into its legs.
///
/// Concatenation in suite order rather than a length-prefixed framing: both
/// ends already know the suite set — the responder from its own bundle, the
/// initiator from the bundle it encapsulated to — and every suite's ciphertext
/// is fixed-length, so the split is unambiguous. A framing would add bytes an
/// attacker could vary while changing nothing either side is allowed to
/// disagree about.
fn split_legs(bundle: &Bundle, ciphertext: &[u8]) -> Result<Encapsulated, HandshakeError> {
    let mut legs = Vec::with_capacity(bundle.keys().len());
    let mut rest = ciphertext;
    for suite in bundle.suites() {
        let want = suite.ciphertext_len();
        if rest.len() < want {
            return Err(HandshakeError::BadCiphertextLength {
                got: ciphertext.len(),
            });
        }
        let (head, tail) = rest.split_at(want);
        legs.push(Leg {
            suite,
            ciphertext: head.to_vec(),
        });
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(HandshakeError::BadCiphertextLength {
            got: ciphertext.len(),
        });
    }
    Encapsulated::new(legs).map_err(|_| HandshakeError::BadCiphertextLength {
        got: ciphertext.len(),
    })
}

/// What a peer caches about another peer.
///
/// Carries a whole [`Bundle`], which may be one leg. A peer learned from a
/// source that only conveys the McEliece key — a pre-bundle bootstrap file, the
/// DHT's key-learning round — arrives as a one-leg bundle and gets exactly the
/// handshake it always got. Hedging engages when the source carried more.
#[derive(Clone)]
pub struct PeerPublic {
    bundle: Bundle,
    id: PeerId,
}

impl fmt::Debug for PeerPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerPublic({})", short(&self.id))
    }
}

impl PeerPublic {
    /// Adopt a public key blob, deriving its id.
    ///
    /// The id is computed here rather than taken on trust, so a peer cannot
    /// hand you a key under someone else's name.
    pub fn from_bytes(public: &[u8]) -> Result<PeerPublic, HandshakeError> {
        if public.len() != CRYPTO_PUBLICKEYBYTES {
            return Err(HandshakeError::BadPublicKeyLength { got: public.len() });
        }
        let key = KemPublicKey::from_bytes(Suite::McEliece, public)
            .map_err(|_| HandshakeError::BadPublicKeyLength { got: public.len() })?;
        let bundle = Bundle::new([key])
            .map_err(|_| HandshakeError::BadPublicKeyLength { got: public.len() })?;
        Ok(PeerPublic::from_bundle(bundle))
    }

    /// Adopt a whole bundle. The hedged path.
    ///
    /// The id comes from the bundle rather than being taken on trust, exactly
    /// as [`PeerPublic::from_bytes`] derives it — and it is the same id, since
    /// [`Bundle::id`] hashes the McEliece leg alone.
    pub fn from_bundle(bundle: Bundle) -> PeerPublic {
        let id = bundle.id();
        PeerPublic { bundle, id }
    }

    pub fn id(&self) -> PeerId {
        self.id
    }

    /// The McEliece leg, which is what the id commits to and what pre-bundle
    /// readers expect.
    pub fn as_bytes(&self) -> &[u8] {
        self.bundle
            .key_for(Suite::McEliece)
            .expect("a bundle always carries the mandatory leg")
            .as_bytes()
    }

    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    /// Does a session to this peer survive a break of any one hardness family?
    pub fn is_hedged(&self) -> bool {
        self.bundle.is_hedged()
    }

    /// Open a session to this peer.
    ///
    /// 96 bytes to a peer known only by its McEliece key; 5,617 to one whose
    /// whole bundle is known. **Every leg the peer published is encapsulated
    /// to, never a subset.** Choosing a subset would be negotiation by another
    /// name, and a session would then be as strong as the fewest legs an
    /// attacker could talk either side into — the downgrade `crypto::kem`
    /// exists to refuse. The wire cost is the honest price of that refusal, and
    /// it is paid per dial, not per frame.
    pub fn initiate(&self, initiator: PeerId) -> (Vec<u8>, Channel) {
        // A one-leg bundle takes the **raw** McEliece secret, not the combiner
        // over a single leg. Not an optimisation: a peer running the pre-bundle
        // build decapsulates and uses the shared secret directly, so combining
        // here would derive a different key and every session with an old node
        // would fail to authenticate. The single-leg case must stay byte- and
        // key-identical to what it always was, and `accept`'s legacy branch is
        // the other half of that promise.
        let (wire, shared) = if self.bundle.keys().len() == 1 {
            let key = self
                .bundle
                .key_for(Suite::McEliece)
                .expect("a bundle always carries the mandatory leg");
            let (ciphertext, secret) = key.encapsulate(&mut OsRng);
            (ciphertext, secret)
        } else {
            let (sealed, secret) = self.bundle.encapsulate(&mut OsRng);
            let wire: Vec<u8> = sealed
                .legs()
                .iter()
                .flat_map(|leg| leg.ciphertext.iter().copied())
                .collect();
            (wire, secret)
        };
        let channel = Channel::new(
            derive(shared.expose(), initiator, self.id, &wire),
            Role::Initiator,
        );
        (wire, channel)
    }
}

/// Which end of the handshake this side is. Decides which derived key sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

/// The two directional keys a handshake produces.
struct SessionKeys {
    i2r: [u8; 32],
    r2i: [u8; 32],
}

/// Derive directional keys, binding the whole transcript.
///
/// Both peer ids and the ciphertext go into the KDF, so a shared secret is
/// useless outside the exact handshake that produced it: a ciphertext replayed
/// against a different claimed initiator derives different keys and every frame
/// fails to authenticate.
///
/// Separate keys per direction because the nonce is a counter starting at zero
/// on both sides. One key would mean both peers using nonce 0 under the same
/// key, which is the catastrophic failure mode for ChaCha20-Poly1305.
fn derive(
    shared: &[u8; 32],
    initiator: PeerId,
    responder: PeerId,
    ciphertext: &[u8],
) -> SessionKeys {
    let leg = |label: &str| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update((KDF_DOMAIN.len() as u64).to_be_bytes());
        h.update(KDF_DOMAIN.as_bytes());
        h.update((label.len() as u64).to_be_bytes());
        h.update(label.as_bytes());
        h.update(shared);
        h.update(initiator);
        h.update(responder);
        h.update(ciphertext);
        h.finalize().into()
    };
    SessionKeys {
        i2r: leg(LABEL_I2R),
        r2i: leg(LABEL_R2I),
    }
}

/// An authenticated, encrypted session.
///
/// Nonces are the frame counter, never random: a counter cannot repeat by
/// accident, and repetition is the one thing this construction cannot survive.
pub struct Channel {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    /// Highest counter accepted so far. Frames must strictly increase, which
    /// rejects both replays and reordering.
    recv_high: Option<u64>,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("sent", &self.send_counter)
            .field("recv_high", &self.recv_high)
            .finish()
    }
}

/// Seal one frame under `key` at `counter`.
///
/// A free function rather than a method so both [`Channel`] and [`Sealer`] can
/// reach it **without copying the key to get there**. The first version of the
/// split built a temporary `Channel` per call, which meant a fresh copy of the
/// session key on the stack for every frame instead of one for the session --
/// the same objection [`crate::store::atrest::Cipher`] makes about deriving
/// `Clone`, and it applies to a session key at least as much.
fn seal_frame(
    key: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    if counter == u64::MAX {
        return Err(HandshakeError::CounterExhausted);
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &nonce_for(counter),
            Payload {
                msg: plaintext,
                aad: &aad(counter, context),
            },
        )
        .map_err(|_| HandshakeError::NotAuthentic)
}

/// Open one frame under `key` at `counter`. Replay is the caller's business:
/// this is the cryptography, and the window lives with whoever owns it.
fn open_frame(
    key: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &nonce_for(counter),
            Payload {
                msg: ciphertext,
                aad: &aad(counter, context),
            },
        )
        .map_err(|_| HandshakeError::NotAuthentic)
}

impl Channel {
    fn new(keys: SessionKeys, role: Role) -> Channel {
        let (send_key, recv_key) = match role {
            Role::Initiator => (keys.i2r, keys.r2i),
            Role::Responder => (keys.r2i, keys.i2r),
        };
        Channel {
            send_key,
            recv_key,
            send_counter: 0,
            recv_high: None,
        }
    }

    /// Encrypt a frame. Returns its counter and ciphertext.
    ///
    /// `context` is authenticated but not transmitted — bind whatever the
    /// caller must agree on out of band.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        context: &[u8],
    ) -> Result<(u64, Vec<u8>), HandshakeError> {
        let counter = self.send_counter;
        let ciphertext = seal_frame(&self.send_key, counter, plaintext, context)?;
        self.send_counter += 1;
        Ok((counter, ciphertext))
    }

    /// Decrypt a frame, refusing replays and reordering.
    pub fn open(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if let Some(high) = self.recv_high {
            if counter <= high {
                return Err(HandshakeError::Replay {
                    counter,
                    expected_above: high,
                });
            }
        }
        let plaintext = open_frame(&self.recv_key, counter, ciphertext, context)?;
        // Only advance on success, so a forged frame cannot burn counter space
        // and lock out the honest peer.
        self.recv_high = Some(counter);
        Ok(plaintext)
    }

    /// Frames sent so far. Rekey well before this approaches `u64::MAX`.
    pub fn frames_sent(&self) -> u64 {
        self.send_counter
    }

    /// Split into the two halves, so sending and receiving can happen on
    /// different threads.
    ///
    /// Safe because the two directions share nothing. A session derives *four*
    /// values — a key and a counter each way — and [`Channel::seal`] touches
    /// only the send pair while [`Channel::open`] touches only the receive pair.
    /// There is no state to race over, so the split needs no lock, and a lock
    /// would be actively wrong: a reader blocked in `recv` holding it would
    /// starve the writer forever.
    ///
    /// That is not a general property of AEAD sessions and is worth stating.
    /// A construction with one counter for both directions, or one key, could
    /// not do this — the halves would have to agree on every increment. The
    /// separation is what `SessionKeys`'s two labels buy.
    pub fn split(self) -> (Sealer, Opener) {
        (
            Sealer {
                key: self.send_key,
                counter: self.send_counter,
            },
            Opener {
                key: self.recv_key,
                high: self.recv_high,
            },
        )
    }
}

/// The sending half of a split [`Channel`].
pub struct Sealer {
    key: [u8; 32],
    counter: u64,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("sent", &self.counter)
            .finish()
    }
}

impl Sealer {
    /// As [`Channel::seal`].
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        context: &[u8],
    ) -> Result<(u64, Vec<u8>), HandshakeError> {
        let counter = self.counter;
        let ciphertext = seal_frame(&self.key, counter, plaintext, context)?;
        self.counter += 1;
        Ok((counter, ciphertext))
    }

    pub fn frames_sent(&self) -> u64 {
        self.counter
    }
}

/// The receiving half of a split [`Channel`].
pub struct Opener {
    key: [u8; 32],
    high: Option<u64>,
}

impl fmt::Debug for Opener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opener")
            .field("recv_high", &self.high)
            .finish()
    }
}

impl Opener {
    /// As [`Channel::open`], including the replay and reordering refusal.
    pub fn open(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if let Some(high) = self.high {
            if counter <= high {
                return Err(HandshakeError::Replay {
                    counter,
                    expected_above: high,
                });
            }
        }
        let plaintext = open_frame(&self.key, counter, ciphertext, context)?;
        // As `Channel::open`: only advance on success, so a forged frame cannot
        // burn counter space and lock out the honest peer.
        self.high = Some(counter);
        Ok(plaintext)
    }
}

/// The counter as a 12-byte little-endian nonce, zero-padded.
fn nonce_for(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&counter.to_le_bytes());
    bytes.into()
}

/// The counter is authenticated as well as used as the nonce, so a frame
/// cannot be renumbered without breaking the tag.
fn aad(counter: u64, context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len());
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(context);
    out
}

/// A peer's id from its public key.
///
/// Delegated to [`crate::crypto::kem::key_id`] rather than hashed here, because
/// [`crate::crypto::kem::Bundle::id`] must produce the identical 32 bytes: a
/// node's transport id, its Kademlia node id, its `PeerRecord::transport` and
/// the committee identity its shares are sealed under are all the same value,
/// and two copies of the derivation are two chances for that to stop being
/// true. Public so the committee layer can name a member without importing the
/// transport.
pub fn peer_id_of(public: &[u8; CRYPTO_PUBLICKEYBYTES]) -> PeerId {
    crate::crypto::kem::key_id(public)
}

fn short(id: &PeerId) -> String {
    id.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex of a peer id, for logs and config.
pub fn peer_id_hex(id: &PeerId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Identity is by id, not by key blob: deriving `PartialEq` on the public key
/// would compare 255 KB every time, and the id already commits to it.
impl PartialEq for PeerPublic {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PeerPublic {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generating a McEliece keypair costs ~243 ms, so the suite shares two.
    fn pair() -> &'static (PeerIdentity, PeerIdentity) {
        use std::sync::OnceLock;
        static PAIR: OnceLock<(PeerIdentity, PeerIdentity)> = OnceLock::new();
        PAIR.get_or_init(|| (PeerIdentity::generate(), PeerIdentity::generate()))
    }

    fn session() -> (Channel, Channel) {
        let (alice, bob) = pair();
        let (ct, a_chan) = bob.to_public().initiate(alice.id());
        let b_chan = bob.accept(alice.id(), &ct).expect("accept");
        (a_chan, b_chan)
    }

    #[test]
    fn a_session_round_trips_in_both_directions() {
        let (mut a, mut b) = session();
        let (n, ct) = a.seal(b"objectives 1..9", b"sync").unwrap();
        assert_eq!(b.open(n, &ct, b"sync").unwrap(), b"objectives 1..9");

        let (n, ct) = b.seal(b"want 3,7", b"sync").unwrap();
        assert_eq!(a.open(n, &ct, b"sync").unwrap(), b"want 3,7");
    }

    #[test]
    fn the_wire_cost_is_a_ciphertext_not_a_key() {
        // The whole reason the public key is a cached long-term identity: even
        // hedged across every leg, the handshake is three orders of magnitude
        // smaller than the key it opens a session to.
        let (alice, bob) = pair();
        let (ct, _) = bob.to_public().initiate(alice.id());
        assert_eq!(bob.public_key().len(), 261_120);

        let legacy = PeerPublic::from_bytes(bob.public_key()).unwrap();
        let (short, _) = legacy.initiate(alice.id());
        assert_eq!(short.len(), 96, "a McEliece-only peer costs what it did");

        // Hedged: 96 + 1,088 + 4,433. HQC's ciphertext dominates, which is the
        // number to look at first if this ever needs to come down.
        assert_eq!(ct.len(), 5_617);
        assert!(ct.len() * 46 < bob.public_key().len());
    }

    #[test]
    fn peer_ids_commit_to_the_key_and_are_derived_not_trusted() {
        let (alice, bob) = pair();
        assert_ne!(alice.id(), bob.id());
        // Adopting a key recomputes the id, so a peer cannot present someone
        // else's key under its own name.
        let adopted = PeerPublic::from_bytes(bob.public_key()).unwrap();
        assert_eq!(adopted.id(), bob.id());
        assert_eq!(peer_id_hex(&adopted.id()).len(), 64);
    }

    #[test]
    fn only_the_holder_of_the_secret_can_open_the_session() {
        let (alice, bob) = pair();
        let (ct, mut a_chan) = bob.to_public().initiate(alice.id());
        // Alice is not the intended responder, so her decapsulation yields a
        // different secret -- IND-CCA2 means no error, just useless keys.
        let mut wrong = alice
            .accept(alice.id(), &ct)
            .expect("decapsulation never errors");
        let (n, frame) = a_chan.seal(b"secret", b"ctx").unwrap();
        assert_eq!(
            wrong.open(n, &frame, b"ctx"),
            Err(HandshakeError::NotAuthentic)
        );
    }

    #[test]
    fn the_transcript_is_bound_into_the_keys() {
        // A ciphertext replayed under a different claimed initiator must not
        // produce a working session.
        let (alice, bob) = pair();
        let (ct, mut a_chan) = bob.to_public().initiate(alice.id());
        let mut mallory = bob.accept([0xAA; 32], &ct).unwrap();
        let (n, frame) = a_chan.seal(b"hello", b"ctx").unwrap();
        assert_eq!(
            mallory.open(n, &frame, b"ctx"),
            Err(HandshakeError::NotAuthentic)
        );
    }

    #[test]
    fn directions_use_different_keys() {
        // Otherwise both peers would send counter 0 under one key, which is the
        // failure ChaCha20-Poly1305 cannot survive. Reflecting a frame back at
        // its sender must not decrypt.
        let (mut a, _b) = session();
        let (n, frame) = a.seal(b"mine", b"ctx").unwrap();
        assert_eq!(a.open(n, &frame, b"ctx"), Err(HandshakeError::NotAuthentic));
    }

    #[test]
    fn replayed_and_reordered_frames_are_refused() {
        let (mut a, mut b) = session();
        let (n1, f1) = a.seal(b"one", b"ctx").unwrap();
        let (n2, f2) = a.seal(b"two", b"ctx").unwrap();
        assert_eq!(b.open(n2, &f2, b"ctx").unwrap(), b"two");
        // n1 < n2: arrives late, or is replayed. Either way, refused.
        assert_eq!(
            b.open(n1, &f1, b"ctx"),
            Err(HandshakeError::Replay {
                counter: n1,
                expected_above: n2
            })
        );
    }

    #[test]
    fn a_forged_frame_does_not_advance_the_window() {
        // Otherwise an attacker sends garbage at a high counter and locks the
        // honest peer out of every counter below it.
        let (mut a, mut b) = session();
        assert!(b.open(9_000, b"garbage", b"ctx").is_err());
        let (n, f) = a.seal(b"still fine", b"ctx").unwrap();
        assert_eq!(b.open(n, &f, b"ctx").unwrap(), b"still fine");
    }

    #[test]
    fn nonces_never_repeat_within_a_session() {
        let (mut a, _) = session();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let (n, _) = a.seal(b"x", b"ctx").unwrap();
            assert!(seen.insert(n), "counter {n} reused");
        }
        assert_eq!(a.frames_sent(), 256);
    }

    #[test]
    fn tampering_with_ciphertext_counter_or_context_is_detected() {
        let (mut a, mut b) = session();
        let (n, f) = a.seal(b"payload", b"sync").unwrap();

        let mut bad = f.clone();
        bad[0] ^= 0xff;
        assert_eq!(b.open(n, &bad, b"sync"), Err(HandshakeError::NotAuthentic));
        // Renumbering: the counter is authenticated, not just used as a nonce.
        assert_eq!(
            b.open(n + 1, &f, b"sync"),
            Err(HandshakeError::NotAuthentic)
        );
        // Context is bound even though it never travels.
        assert_eq!(b.open(n, &f, b"other"), Err(HandshakeError::NotAuthentic));
        // ... and the good frame still opens, so none of the above consumed it.
        assert_eq!(b.open(n, &f, b"sync").unwrap(), b"payload");
    }

    #[test]
    fn two_handshakes_to_one_peer_get_independent_sessions() {
        // Encapsulation is randomised, so a static responder key still gives a
        // fresh session per connection.
        let (alice, bob) = pair();
        let (ct1, mut a1) = bob.to_public().initiate(alice.id());
        let (ct2, _a2) = bob.to_public().initiate(alice.id());
        assert_ne!(ct1, ct2);
        let mut b2 = bob.accept(alice.id(), &ct2).unwrap();
        let (n, f) = a1.seal(b"session one", b"ctx").unwrap();
        assert_eq!(b2.open(n, &f, b"ctx"), Err(HandshakeError::NotAuthentic));
    }

    #[test]
    fn identities_persist_and_restore() {
        let (alice, _) = pair();
        // The legacy identity-file shape: the McEliece leg alone. It restores
        // to a one-leg identity with the *same id*, which is the property that
        // let bundles be added without reissuing anybody's name.
        let restored = PeerIdentity::from_bytes(alice.public_key(), alice.secret_key()).unwrap();
        assert_eq!(restored.id(), alice.id());
        assert!(!restored.bundle().is_hedged());
        // And a restored identity can still accept.
        let (ct, mut chan) = restored.to_public().initiate([1u8; 32]);
        assert_eq!(
            ct.len(),
            CRYPTO_CIPHERTEXTBYTES,
            "one leg, legacy wire size"
        );
        let mut theirs = restored.accept([1u8; 32], &ct).unwrap();
        let (n, f) = chan.seal(b"ok", b"c").unwrap();
        assert_eq!(theirs.open(n, &f, b"c").unwrap(), b"ok");
    }

    #[test]
    fn a_hedged_identity_keeps_the_id_its_mceliece_leg_gave_it() {
        let hedged = PeerIdentity::generate();
        assert!(hedged.bundle().is_hedged());
        // The id is the hash of the McEliece leg and nothing else, so the DHT,
        // every bootstrap file and every `PeerRecord` naming this peer stay
        // valid. This is the whole reason the change needed no migration.
        let leg: &[u8; CRYPTO_PUBLICKEYBYTES] =
            hedged.public_key().try_into().expect("mceliece leg length");
        assert_eq!(hedged.id(), peer_id_of(leg));

        let legacy = PeerIdentity::from_bytes(hedged.public_key(), hedged.secret_key()).unwrap();
        assert_eq!(
            legacy.id(),
            hedged.id(),
            "dropping the extra legs must not rename the peer"
        );
    }

    #[test]
    fn a_hedged_session_is_bigger_on_the_wire_and_still_opens() {
        let alice = PeerIdentity::generate();
        let bob = PeerIdentity::generate();
        let (ct, mut chan) = bob.to_public().initiate(alice.id());
        // Every leg, never a subset -- see `PeerPublic::initiate`.
        let expected: usize = crate::crypto::kem::SUITES
            .iter()
            .map(|s| s.ciphertext_len())
            .sum();
        assert_eq!(ct.len(), expected);
        assert!(ct.len() > CRYPTO_CIPHERTEXTBYTES);

        let mut theirs = bob.accept(alice.id(), &ct).unwrap();
        let (n, f) = chan.seal(b"hedged", b"c").unwrap();
        assert_eq!(theirs.open(n, &f, b"c").unwrap(), b"hedged");
    }

    #[test]
    fn a_hedged_responder_still_serves_a_legacy_initiator() {
        // The rollout property: responders upgrade unilaterally. A node that
        // has grown legs must keep talking to one that has not, or nobody can
        // upgrade first.
        let hedged = PeerIdentity::generate();
        let legacy_view = PeerPublic::from_bytes(hedged.public_key()).unwrap();
        assert!(!legacy_view.is_hedged());

        let (ct, mut chan) = legacy_view.initiate([9u8; 32]);
        assert_eq!(ct.len(), CRYPTO_CIPHERTEXTBYTES);
        let mut theirs = hedged.accept([9u8; 32], &ct).unwrap();
        let (n, f) = chan.seal(b"old client", b"c").unwrap();
        assert_eq!(theirs.open(n, &f, b"c").unwrap(), b"old client");
    }

    #[test]
    fn truncating_a_hedged_handshake_kills_the_session_rather_than_downgrading_it() {
        // McEliece sorts first, so the first 96 bytes of a hedged ciphertext
        // are a valid McEliece ciphertext and an attacker can cut one down.
        // They gain nothing: the two sides derive different keys and every
        // frame fails. A liveness attack already available by dropping packets.
        let alice = PeerIdentity::generate();
        let bob = PeerIdentity::generate();
        let (ct, mut chan) = bob.to_public().initiate(alice.id());

        let truncated = &ct[..CRYPTO_CIPHERTEXTBYTES];
        let mut theirs = bob
            .accept(alice.id(), truncated)
            .expect("a truncated handshake still decapsulates -- that is the point");
        let (n, f) = chan.seal(b"secret", b"c").unwrap();
        assert_eq!(
            theirs.open(n, &f, b"c"),
            Err(HandshakeError::NotAuthentic),
            "a downgraded session must not carry data"
        );
    }

    #[test]
    fn malformed_blobs_are_refused_by_length() {
        assert_eq!(
            PeerPublic::from_bytes(&[0u8; 10]),
            Err(HandshakeError::BadPublicKeyLength { got: 10 })
        );
        let (_, bob) = pair();
        assert_eq!(
            bob.accept([0u8; 32], &[0u8; 10]).err(),
            Some(HandshakeError::BadCiphertextLength { got: 10 })
        );
    }

    #[test]
    fn debug_output_never_leaks_key_material() {
        let (alice, _) = pair();
        let rendered = format!("{:?} {:?}", alice, alice.to_public());
        assert!(rendered.len() < 100, "debug is far too large: {rendered}");
        assert!(!rendered.contains("["), "looks like raw bytes: {rendered}");
    }

    // -- splitting a channel ----------------------------------------------

    fn paired() -> (Channel, Channel) {
        let responder = PeerIdentity::generate();
        let initiator = PeerIdentity::generate();
        let (ciphertext, initiator_channel) = responder.to_public().initiate(initiator.id());
        let responder_channel = responder
            .accept(initiator.id(), &ciphertext)
            .expect("the responder decapsulates");
        (initiator_channel, responder_channel)
    }

    #[test]
    fn a_split_channel_still_talks_to_an_unsplit_one() {
        // The split must be invisible on the wire, or a node that splits could
        // not talk to a node that does not.
        let (initiator, mut responder) = paired();
        let (mut sealer, _opener) = initiator.split();
        let (counter, ciphertext) = sealer.seal(b"hello", b"ctx").expect("seals");
        assert_eq!(
            responder.open(counter, &ciphertext, b"ctx").expect("opens"),
            b"hello"
        );
    }

    #[test]
    fn both_halves_of_a_split_work_in_both_directions() {
        let (initiator, responder) = paired();
        let (mut i_send, mut i_recv) = initiator.split();
        let (mut r_send, mut r_recv) = responder.split();

        let (counter, ct) = i_send.seal(b"ping", b"ctx").expect("seals");
        assert_eq!(r_recv.open(counter, &ct, b"ctx").expect("opens"), b"ping");
        let (counter, ct) = r_send.seal(b"pong", b"ctx").expect("seals");
        assert_eq!(i_recv.open(counter, &ct, b"ctx").expect("opens"), b"pong");
    }

    #[test]
    fn a_split_opener_still_refuses_replays_and_reordering() {
        // The property that makes the counter worth having. Losing it in the
        // split would be a silent downgrade -- everything would still work,
        // and a recorded frame would replay.
        let (initiator, responder) = paired();
        let (mut sealer, _) = initiator.split();
        let (_, mut opener) = responder.split();

        let (c0, f0) = sealer.seal(b"first", b"ctx").expect("seals");
        let (c1, f1) = sealer.seal(b"second", b"ctx").expect("seals");
        assert_eq!(opener.open(c1, &f1, b"ctx").expect("opens"), b"second");
        // The earlier frame is now in the past: refused, not accepted late.
        assert!(
            matches!(
                opener.open(c0, &f0, b"ctx"),
                Err(HandshakeError::Replay { .. })
            ),
            "a split opener accepted a reordered frame"
        );
        // And the one it did accept cannot be replayed either.
        assert!(matches!(
            opener.open(c1, &f1, b"ctx"),
            Err(HandshakeError::Replay { .. })
        ));
    }

    #[test]
    fn a_split_sealer_does_not_reuse_a_counter() {
        // Nonce reuse is the one thing this construction cannot survive, and
        // the counter is the nonce. A split that reset it would be fatal.
        let (initiator, _) = paired();
        let sent_before = initiator.frames_sent();
        let (mut sealer, _) = initiator.split();
        assert_eq!(sealer.frames_sent(), sent_before);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..16 {
            let (counter, _) = sealer.seal(b"x", b"ctx").expect("seals");
            assert!(seen.insert(counter), "counter {counter} was reused");
        }
    }

    #[test]
    fn a_split_preserves_a_counter_already_advanced() {
        // Splitting mid-session must not rewind either side. A sealer that
        // restarted at zero would reuse nonces against a peer that had already
        // seen them, and an opener that forgot its high-water mark would accept
        // every frame it had already accepted.
        let (mut initiator, mut responder) = paired();
        let (c, f) = initiator.seal(b"before", b"ctx").expect("seals");
        assert_eq!(responder.open(c, &f, b"ctx").expect("opens"), b"before");
        let (r_c, r_f) = responder.seal(b"reply", b"ctx").expect("seals");
        assert_eq!(initiator.open(r_c, &r_f, b"ctx").expect("opens"), b"reply");

        let (mut sealer, mut opener) = initiator.split();
        let (next, _) = sealer.seal(b"after", b"ctx").expect("seals");
        assert!(next > c, "the split rewound the send counter");
        assert!(
            matches!(
                opener.open(r_c, &r_f, b"ctx"),
                Err(HandshakeError::Replay { .. })
            ),
            "the split forgot what it had already received"
        );
    }

    #[test]
    fn a_split_half_still_binds_its_context() {
        // Frames sealed for one subsystem must not open as another's; that is
        // what the context string is for and the split must not lose it.
        let (initiator, responder) = paired();
        let (mut sealer, _) = initiator.split();
        let (_, mut opener) = responder.split();
        let (counter, frame) = sealer.seal(b"payload", b"proofwork/a").expect("seals");
        assert!(matches!(
            opener.open(counter, &frame, b"proofwork/b"),
            Err(HandshakeError::NotAuthentic)
        ));
    }

    #[test]
    fn a_split_sealer_refuses_to_wrap_its_counter() {
        // The counter is the nonce, and nonce reuse is the one failure
        // ChaCha20-Poly1305 does not survive -- it exposes the XOR of two
        // messages and permits forgery. `Channel::seal` has always refused to
        // wrap; the split half has to refuse too, and would not if it reached
        // the cipher by a path that skipped the check.
        let (initiator, _) = paired();
        let (mut sealer, _) = initiator.split();
        sealer.counter = u64::MAX;
        assert_eq!(
            sealer.seal(b"one frame too many", b"ctx"),
            Err(HandshakeError::CounterExhausted)
        );
        // And it did not advance past the end while failing.
        assert_eq!(sealer.frames_sent(), u64::MAX);
    }
}
