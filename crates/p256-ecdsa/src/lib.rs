use std::fs::File;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Result;
pub use halo2_base::halo2_proofs;
pub use halo2_proofs::halo2curves;
pub use snark_verifier::halo2_base;
pub use snark_verifier::halo2_ecc;
pub use snark_verifier_sdk::snark_verifier;

pub mod base;
pub mod circuit;

use halo2curves::secp256r1::{Fp, Fq};
use snark_verifier_sdk::snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::snark_verifier::halo2_base::utils::decompose_biguint;
use snark_verifier_sdk::snark_verifier::halo2_base::utils::fe_to_biguint;
use snark_verifier_sdk::snark_verifier::halo2_base::utils::ScalarField;

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

    pub fn as_instances(&self) -> Vec<Fr> {
        const LIMB_BITS: usize = 88;
        const NUM_LIMBS: usize = 3;

        fn f(x: impl ScalarField) -> Vec<Fr> {
            let x = fe_to_biguint(&x);
            decompose_biguint::<Fr>(&x, NUM_LIMBS, LIMB_BITS)
        }

        [f(self.msghash), f(self.r), f(self.s), f(self.x), f(self.y)].concat()
    }
}
