pub mod base;
pub mod circuit;

pub use base::ECDSAProver;

use anyhow::{anyhow, Result};

use common::{
    halo2_base::utils::{decompose_biguint, fe_to_biguint, ScalarField},
    halo2curves::{
        bn256::Fr,
        secp256r1::{Fp, Fq},
    },
};

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
        assert_eq!(y.len(), 32);

        macro_rules! from_bytes {
            ($TT: ty, $o: expr) => {{
                let mut a: Vec<_> = $o.into();
                a.reverse();
                let f = <$TT>::from_bytes(a.as_slice().try_into()?);
                if f.is_some().into() {
                    f.unwrap()
                } else {
                    return Err(anyhow!("Invalid input"));
                }
            }};
        }

        let msghash = from_bytes!(Fq, msghash);
        let r = from_bytes!(Fq, r);
        let s = from_bytes!(Fq, s);
        let x = from_bytes!(Fp, x);
        let y = from_bytes!(Fp, y);

        Ok(Self {
            msghash,
            r,
            s,
            x,
            y,
        })
    }

    pub fn try_from_hex(msghash: &str, signature: &str, pubkey: &str) -> Result<Self> {
        let msghash = hex::decode(msghash)?;
        let signature = hex::decode(signature)?;
        let pubkey = hex::decode(pubkey)?;

        let (r, s) = (signature.len() == 64)
            .then(|| signature.split_at(32))
            .ok_or(anyhow!("signature should be 64 bytes"))?;

        let (x, y) = (pubkey.len() == 65)
            .then(|| &pubkey[1..])
            .map(|v| v.split_at(32))
            .ok_or(anyhow!("Pubkey should be uncompressed format"))?;

        ECDSAInput::new(&msghash, r, s, x, y)
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
