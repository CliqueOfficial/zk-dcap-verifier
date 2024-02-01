use anyhow::anyhow;
use anyhow::Result;
pub use halo2_base::halo2_proofs;
pub use halo2_proofs::halo2curves;
pub use snark_verifier::halo2_base;
pub use snark_verifier::halo2_ecc;
pub use snark_verifier_sdk::snark_verifier;

pub mod base;
pub mod circuit;

use halo2_ecc::fields::FpStrategy;
use halo2curves::secp256r1::{Fp, Fq};
use snark_verifier_sdk::snark_verifier::halo2_base::gates::circuit::BaseCircuitParams;

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

impl From<CircuitParams> for BaseCircuitParams {
    fn from(params: CircuitParams) -> Self {
        Self {
            k: params.degree as usize,
            num_fixed: params.num_fixed,
            lookup_bits: Some(params.lookup_bits),
            num_instance_columns: 1,
            ..Default::default()
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

impl ECDSAInput {
    pub fn new(msghash: &[u8], r: &[u8], s: &[u8], x: &[u8], y: &[u8]) -> Result<Self> {
        assert_eq!(msghash.len(), 32);
        assert_eq!(r.len(), 32);
        assert_eq!(s.len(), 32);
        assert_eq!(x.len(), 32);

        macro_rules! ensure_some {
            ($o: expr) => {
                if $o.is_some().into() {
                    $o.unwrap()
                } else {
                    return Err(anyhow!("Invalid input"));
                }
            };
        }

        let msghash = ensure_some!(Fq::from_bytes(msghash.try_into()?));
        let r = ensure_some!(Fq::from_bytes(r.try_into()?));
        let s = ensure_some!(Fq::from_bytes(s.try_into()?));
        let x = ensure_some!(Fp::from_bytes(x.try_into()?));
        let y = ensure_some!(Fp::from_bytes(y.try_into()?));

        Ok(Self {
            msghash,
            r,
            s,
            x,
            y,
        })
    }
}
