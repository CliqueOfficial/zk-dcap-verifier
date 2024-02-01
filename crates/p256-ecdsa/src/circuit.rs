use std::path::{Path, PathBuf};

use anyhow::Result;
use snark_verifier_sdk::{
    halo2::{gen_proof, gen_proof_shplonk},
    snark_verifier::{
        halo2_base::{
            gates::{circuit::builder::BaseCircuitBuilder, GateChip, GateInstructions, RangeChip},
            halo2_proofs::{
                halo2curves::{
                    bn256::{Bn256, Fr},
                    secp256r1::{Fp, Fq, Secp256r1Affine as Affine},
                },
                plonk::{keygen_pk, keygen_vk},
                poly::kzg::{
                    commitment::ParamsKZG,
                    multiopen::{ProverSHPLONK, VerifierSHPLONK},
                },
            },
            utils::{fs::gen_srs, BigPrimeField, ScalarField},
            AssignedValue, Context,
        },
        halo2_ecc::{
            ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
            fields::FieldChip,
            secp256r1::{FpChip, FqChip},
        },
    },
};

use crate::{CircuitParams, ECDSAInput};

pub fn ecdsa_verify(
    builder: &mut BaseCircuitBuilder<Fr>,
    input: ECDSAInput,
    make_public: &mut Vec<AssignedValue<Fr>>,
) -> Result<()> {
    let params = CircuitParams::default();
    let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());

    let ctx = builder.main(0);

    let res = {
        let range = &range;
        let fp_chip = FpChip::new(range, params.limb_bits, params.num_limbs);
        let fq_chip = FqChip::new(range, params.limb_bits, params.num_limbs);

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

    // builder.calculate_params(Some(9));
    // let kzg_params = gen_srs(params.degree);
    // let vk = keygen_vk(&kzg_params, builder)?;
    // let pk = keygen_pk(&kzg_params, vk, builder)?;
    // gen_proof_shplonk(
    //     &kzg_params,
    //     &pk,
    //     *builder,
    //     vec![],
    //     Some((&PathBuf::from("instance.bin"), &PathBuf::from("proof.bin"))),
    // );
    Ok(())
}
