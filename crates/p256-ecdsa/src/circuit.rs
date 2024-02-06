use anyhow::Result;
use common::{
    halo2_base::{
        gates::{circuit::builder::BaseCircuitBuilder, GateChip, GateInstructions, RangeChip},
        AssignedValue,
    },
    halo2_ecc::{
        ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
        fields::FieldChip,
        secp256r1::{FpChip, FqChip},
    },
    halo2curves::{
        bn256::Fr,
        secp256r1::{Fp, Fq, Secp256r1Affine as Affine},
    },
};

use crate::ECDSAInput;

pub fn ecdsa_verify(
    builder: &mut BaseCircuitBuilder<Fr>,
    input: ECDSAInput,
    make_public: &mut Vec<AssignedValue<Fr>>,
) -> Result<()> {
    const LOOKUP_BITS: usize = 17;
    const LIMB_BITS: usize = 88;
    const NUM_LIMBS: usize = 3;

    let range = RangeChip::new(LOOKUP_BITS, builder.lookup_manager().clone());

    let ctx = builder.main(0);

    let res = {
        let range = &range;
        let fp_chip = FpChip::new(range, LIMB_BITS, NUM_LIMBS);
        let fq_chip = FqChip::new(range, LIMB_BITS, NUM_LIMBS);

        let [m, r, s] = [input.msghash, input.r, input.s].map(|x| fq_chip.load_private(ctx, x));

        make_public.extend(m.limbs());
        make_public.extend(r.limbs());
        make_public.extend(s.limbs());

        let ecc_chip = EccChip::new(&fp_chip);
        let pk = ecc_chip.load_private_unchecked(ctx, (input.x, input.y));

        make_public.extend(pk.x().limbs());
        make_public.extend(pk.y().limbs());

        // test ECDSA
        ecdsa_verify_no_pubkey_check::<_, Fp, Fq, Affine>(&ecc_chip, ctx, pk, r, s, m, 4, 4)
    };

    let gate = GateChip::new();
    gate.assert_is_const(ctx, &res, &Fr::one());

    Ok(())
}
