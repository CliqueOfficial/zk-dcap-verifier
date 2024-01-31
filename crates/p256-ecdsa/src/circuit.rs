#[cfg(test)]
mod tests {
    use snark_verifier_sdk::snark_verifier::{
        halo2_base::{
            gates::{circuit::builder::BaseCircuitBuilder, GateChip, GateInstructions, RangeChip},
            halo2_proofs::{
                dev::MockProver,
                halo2curves::{
                    bn256::Fr,
                    secp256r1::{Fp, Fq},
                },
            },
            utils::{biguint_to_fe, fe_to_biguint, modulus, BigPrimeField},
            Context,
        },
        halo2_ecc::{
            ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
            fields::FieldChip,
            secp256r1::{FpChip, FqChip},
        },
        util::arithmetic::PrimeField,
    };

    use crate::{halo2_proofs::arithmetic::CurveAffine, ECDSAInput};
    use crate::{halo2curves::secp256r1::Secp256r1Affine as Affine, CircuitParams};

    fn custom_parameters_ecdsa(sk: u64, msg_hash: u64, k: u64) -> ECDSAInput {
        let sk = <Affine as CurveAffine>::ScalarExt::from(sk);
        let pubkey = Affine::from(Affine::generator() * sk);
        let msg_hash = <Affine as CurveAffine>::ScalarExt::from(msg_hash);

        let k = <Affine as CurveAffine>::ScalarExt::from(k);
        let k_inv = k.invert().unwrap();

        let r_point = Affine::from(Affine::generator() * k).coordinates().unwrap();
        let x = r_point.x();
        let x_bigint = fe_to_biguint(x);

        let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
        let s = k_inv * (msg_hash + (r * sk));

        {
            let s_inv = s.invert().unwrap();
            let u1 = s_inv;
            let u2 = r * s_inv;
            let p1 = Affine::from(Affine::generator() * u1 + pubkey * u2);
            let p = p1.coordinates().unwrap();
            assert_eq!(p.x().to_repr(), r.to_repr());
        }

        ECDSAInput {
            r,
            s,
            msghash: msg_hash,
            x: pubkey.x,
            y: pubkey.y,
        }
    }

    fn ecdsa_test<F: BigPrimeField>(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        params: CircuitParams,
        input: ECDSAInput,
    ) -> snark_verifier_sdk::snark_verifier::halo2_base::AssignedValue<F> {
        let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
        let fq_chip = FqChip::<F>::new(range, params.limb_bits, params.num_limbs);

        let [m, r, s] = [input.msghash, input.r, input.s].map(|x| fq_chip.load_private(ctx, x));

        let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
        let pk = ecc_chip.load_private_unchecked(ctx, (input.x, input.y));
        // test ECDSA
        ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Affine>(&ecc_chip, ctx, pk, r, s, m, 4, 4)
    }

    #[test]
    fn test_p256_ecdsa() {
        let params = CircuitParams::default();
        let input = custom_parameters_ecdsa(1, 1, 1);

        let mut builder = BaseCircuitBuilder::<Fr>::default()
            .use_k(params.degree as usize)
            .use_lookup_bits(params.lookup_bits);

        let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());

        let ctx = builder.main(0);
        // run the function, mutating `builder`
        let res = ecdsa_test(ctx, &range, params, input);

        let gate = GateChip::new();
        gate.assert_is_const(ctx, &res, &Fr::one());

        // configure the circuit shape, 9 blinding rows seems enough
        builder.calculate_params(Some(9));
        MockProver::run(params.degree, &builder, vec![])
            .unwrap()
            .assert_satisfied();

        assert_eq!(*res.value(), Fr::one());
    }
}
