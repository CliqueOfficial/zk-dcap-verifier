pub use halo2_base::halo2_proofs;
pub use halo2_proofs::halo2curves;
pub use snark_verifier::halo2_base;
pub use snark_verifier::halo2_ecc;
pub use snark_verifier_sdk::snark_verifier;

pub mod circuit;

use halo2_ecc::fields::FpStrategy;
use halo2curves::secp256r1::{Fp, Fq};

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

impl Default for CircuitParams {
    fn default() -> Self {
        Self {
            strategy: FpStrategy::Simple,
            degree: 18,
            num_advice: 2,
            num_lookup_advice: 1,
            num_fixed: 1,
            lookup_bits: 17,
            limb_bits: 88,
            num_limbs: 3,
        }
    }
}

// Fq < Fp
#[derive(Clone, Copy, Debug, Default)]
pub struct ECDSAInput {
    pub r: Fq,
    pub s: Fq,
    pub msghash: Fq,
    pub x: Fp,
    pub y: Fp,
}

