use crypto_bigint::{
    modular::{BernsteinYangInverter, ConstMontyForm, ConstMontyParams},
    rand_core::CryptoRngCore,
    Odd, PrecomputeInverter, Uint,
};

use super::{csidh::csidh, private_key::PrivateKey, public_key::PublicKey};

/// A shared secret created with the CSIDH key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedSecret<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> {
    shared_secret: ConstMontyForm<MOD, LIMBS>,
}

impl<const SAT_LIMBS: usize, MOD: ConstMontyParams<SAT_LIMBS>, const UNSAT_LIMBS: usize>
    SharedSecret<SAT_LIMBS, MOD>
where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
        Inverter = BernsteinYangInverter<SAT_LIMBS, UNSAT_LIMBS>,
        Output = Uint<SAT_LIMBS>,
    >,
{
    /// Computes a shared secret from a foreign public key and a private key.
    #[must_use]
    pub fn from<const N: usize>(
        foreign_public_key: PublicKey<SAT_LIMBS, MOD>,
        private_key: PrivateKey<SAT_LIMBS, N, MOD>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        Self {
            shared_secret: csidh(
                private_key.params(),
                private_key.key(),
                foreign_public_key.key(),
                rng,
            ),
        }
    }

    // -- added by the vendoring; see the module docs ------------------------

    /// The shared curve coefficient, little-endian.
    ///
    /// Fed to the combiner in [`crate::crypto::kem`], which hashes it with a
    /// domain separator and every other leg. Handing it out raw is safe only
    /// because of that: the group action's output is a curve parameter with
    /// structure, not a uniform string, so it is a KDF input and never a key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let value = self.shared_secret.retrieve();
        let mut out = Vec::with_capacity(Uint::<SAT_LIMBS>::BYTES);
        for word in value.as_words() {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}
