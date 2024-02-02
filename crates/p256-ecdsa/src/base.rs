use std::path::PathBuf;

use anyhow::{anyhow, Result};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{gen_proof_shplonk, gen_snark_shplonk, PoseidonTranscript},
    snark_verifier::halo2_base::{
        gates::{
            circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
            flex_gate::MultiPhaseThreadBreakPoints,
        },
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::{Bn256, Fr},
            plonk::{keygen_pk, keygen_vk, verify_proof, Circuit},
            poly::{
                commitment::{Params, ParamsProver},
                kzg::{
                    commitment::{KZGCommitmentScheme, ParamsKZG},
                    multiopen::VerifierSHPLONK,
                    strategy::SingleStrategy,
                },
            },
        },
        utils::fs::gen_srs,
        AssignedValue,
    },
    NativeLoader,
};

use crate::{circuit::ecdsa_verify, CircuitParams, ECDSAInput};

#[derive(Clone)]
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
    let pre_circuit = PreCircuit {
        private_inputs: input,
        f: ecdsa_verify,
    };

    let circuit_params = CircuitParams::default();

    let params = gen_srs(circuit_params.degree);

    let circuit = pre_circuit
        .clone()
        .create_circuit(CircuitBuilderStage::Keygen, None, &params)?;

    let pk = gen_pk(&params, &circuit, None);

    let c_params = circuit.params();
    let break_points = circuit.break_points();
    dbg!(&break_points);

    let vk = pk.get_vk();

    let circuit = pre_circuit.clone().create_circuit(
        CircuitBuilderStage::Prover,
        Some((c_params, break_points)),
        &params,
    )?;
    let snark = gen_snark_shplonk(&params, &pk, circuit, Some(&PathBuf::from("snark.bin")));

    let mut circuit =
        pre_circuit
            .clone()
            .create_circuit(CircuitBuilderStage::Keygen, None, &params)?;

    let mut transcript =
        PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(snark.proof.as_slice());
    let instances = snark.instances[0].as_slice();

    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);

    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        verifier_params,
        vk,
        strategy,
        &[&[instances]],
        &mut transcript,
    )?;

    circuit.clear();

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
        let input = custom_parameters_ecdsa(1, 1, 1);
        create_proof(input).unwrap();

        // let params = gen_srs(18);
        //
        // let pre_circuit = PreCircuit {
        //     private_inputs: input,
        //     f: ecdsa_verify,
        // };
        //
        // let builder = pre_circuit
        //     .create_circuit(CircuitBuilderStage::Prover, None, &params)
        //     .unwrap();
        //
        // let instances = builder.instances();
        //
        // MockProver::run(18, &builder, instances)
        //     .unwrap()
        //     .assert_satisfied();
    }
}
