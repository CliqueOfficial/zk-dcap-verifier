use anyhow::{anyhow, Result};
use snark_verifier_sdk::{
    halo2::gen_proof_shplonk,
    snark_verifier::halo2_base::{
        gates::{
            circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
            flex_gate::MultiPhaseThreadBreakPoints,
        },
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::{Bn256, Fr},
            plonk::{keygen_pk, keygen_vk},
            poly::{commitment::Params, kzg::commitment::ParamsKZG},
        },
        utils::fs::gen_srs,
        AssignedValue,
    },
};

use crate::{circuit::ecdsa_verify, CircuitParams, ECDSAInput};

pub struct PreCircuit<T, Fn> {
    private_inputs: T,
    f: Fn,
}

impl<T, Fn> PreCircuit<T, Fn>
where
    Fn: FnOnce(&mut BaseCircuitBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>) -> Result<()>,
{
    /// Creates a Halo2 circuit from the given function.
    pub fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<(BaseCircuitParams, MultiPhaseThreadBreakPoints)>,
        params: &ParamsKZG<Bn256>,
    ) -> Result<BaseCircuitBuilder<Fr>> {
        let mut builder = BaseCircuitBuilder::from_stage(stage);
        if let Some((params, break_points)) = pinning {
            builder.set_params(params);
            builder.set_break_points(break_points);
        } else {
            let k = params.k() as usize;
            builder.set_k(k);
            builder.set_lookup_bits(17);
            builder.set_instance_columns(1);
        };

        // builder.main(phase) gets a default "main" thread for the given phase. For most purposes we only need to think about phase 0
        // we need a 64-bit number as input in this case
        // while `some_algorithm_in_zk` was written generically for any field `F`, in practice we use the scalar field of the BN254 curve because that's what the proving system backend uses
        let mut assigned_instances = vec![];
        (self.f)(&mut builder, self.private_inputs, &mut assigned_instances)?;
        if !assigned_instances.is_empty() {
            assert_eq!(
                builder.assigned_instances.len(),
                1,
                "num_instance_columns != 1"
            );
            builder.assigned_instances[0] = assigned_instances;
        }

        if !stage.witness_gen_only() {
            builder.calculate_params(Some(20));
        }

        Ok(builder)
    }
}

pub fn create_proof(input: ECDSAInput) -> Result<Vec<u8>> {
    let params = CircuitParams::default();

    let pre_circuit = PreCircuit {
        private_inputs: input,
        f: ecdsa_verify,
    };

    // let builder = pre_circuit.create_circuit(CircuitBuilderStage::Keygen)?;

    // let kzg_params = gen_srs(params.degree);
    // let vk = keygen_vk(&kzg_params, &builder)?;
    // let pk = keygen_pk(&kzg_params, vk, &builder)?;

    // MockProver::run(params.degree, &builder, vec![])
    //     .unwrap()
    //     .assert_satisfied();
    // gen_proof_shplonk(kzg_params, pk, circuit, instances, path)
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use snark_verifier_sdk::{
        snark_verifier::{
            halo2_base::{
                halo2_proofs::halo2curves::secp256r1::Fq,
                utils::{biguint_to_fe, fe_to_biguint, modulus},
            },
            util::arithmetic::PrimeField,
        },
        CircuitExt,
    };

    use super::*;

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

    #[test]
    fn test_p256_ecdsa() {
        macro_rules! fr {
            ($x: literal) => {{
                let mut s = hex_literal::hex!($x);
                s.reverse();
                Fr::from_bytes(&s).unwrap()
            }};
        }

        let input = custom_parameters_ecdsa(1, 1, 1);

        let params = gen_srs(18);

        let pre_circuit = PreCircuit {
            private_inputs: input,
            f: ecdsa_verify,
        };

        let builder = pre_circuit
            .create_circuit(CircuitBuilderStage::Mock, None, &params)
            .unwrap();

        let mut instances = builder.instances();

        MockProver::run(18, &builder, instances)
            .unwrap()
            .assert_satisfied();
    }
}
