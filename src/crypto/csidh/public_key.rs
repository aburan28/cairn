use crypto_bigint::{
    modular::{BernsteinYangInverter, ConstMontyForm, ConstMontyParams},
    rand_core::CryptoRngCore,
    Odd, PrecomputeInverter, Uint,
};

use super::{
    csidh::csidh, csidh_params::CsidhParams, montgomery_curve::MontgomeryCurve,
    private_key::PrivateKey,
};

/// A public key for the CSIDH key exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> {
    key: ConstMontyForm<MOD, LIMBS>,
}

impl<const SAT_LIMBS: usize, MOD: ConstMontyParams<SAT_LIMBS>, const UNSAT_LIMBS: usize>
    PublicKey<SAT_LIMBS, MOD>
where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
        Inverter = BernsteinYangInverter<SAT_LIMBS, UNSAT_LIMBS>,
        Output = Uint<SAT_LIMBS>,
    >,
{
    /// Computes the public key associated with the given private key.
    #[must_use]
    pub fn from<const N: usize>(
        private_key: PrivateKey<SAT_LIMBS, N, MOD>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        Self {
            key: csidh(
                private_key.params(),
                private_key.key(),
                ConstMontyForm::ZERO,
                rng,
            ),
        }
    }

    /// Constructs a `PublicKey` from the foreign public key, if the key is valid.
    #[must_use]
    pub fn new<const N: usize>(
        params: CsidhParams<SAT_LIMBS, N, MOD>,
        key: Uint<SAT_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self> {
        let key = ConstMontyForm::new(&key);
        if MontgomeryCurve::new(params, key).is_supersingular(rng) {
            Some(Self { key })
        } else {
            None
        }
    }

    pub(crate) const fn key(&self) -> ConstMontyForm<MOD, SAT_LIMBS> {
        self.key
    }

    // -- added by the vendoring; see the module docs ------------------------

    /// The Montgomery coefficient `A`, little-endian.
    ///
    /// `retrieve()` first: the stored value is in Montgomery form, which is an
    /// internal representation that depends on the modulus and is *not* the
    /// curve parameter. Publishing that instead would produce bytes no other
    /// implementation could read and a key id that means nothing outside this
    /// build.
    /// Written limb by limb rather than with `Uint::to_le_bytes`, which the
    /// upstream crate only implements for concrete widths and not for a generic
    /// `LIMBS`. A `Word` is `u64` on 64-bit targets and `u32` on 32-bit ones, so
    /// the loop uses `Limb::BYTES` and the encoding is the same on both --
    /// hard-coding 8 would silently produce different bytes on a 32-bit build,
    /// which is a different key id for the same key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let value = self.key.retrieve();
        let mut out = Vec::with_capacity(Uint::<SAT_LIMBS>::BYTES);
        for word in value.as_words() {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Read a public key back, checking it is a supersingular curve.
    ///
    /// Through upstream's own `new`, so the validation is theirs rather than a
    /// second opinion of mine. `None` for the wrong length or a curve that is
    /// not supersingular -- and the check matters: the group action on an
    /// ordinary curve leaks the private key, so an unvalidated peer key is an
    /// invalid-curve attack.
    pub fn from_bytes<const N: usize>(
        params: CsidhParams<SAT_LIMBS, N, MOD>,
        bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self> {
        let width = Uint::<SAT_LIMBS>::BYTES;
        if bytes.len() != width {
            return None;
        }
        let mut buf = vec![0u8; width];
        buf.copy_from_slice(bytes);
        PublicKey::new(params, Uint::<SAT_LIMBS>::from_le_slice(&buf), rng)
    }
}
