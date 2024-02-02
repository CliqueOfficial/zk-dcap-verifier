use std::path::PathBuf;

use anyhow::{anyhow, Result};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{gen_proof_shplonk, gen_snark_shplonk, PoseidonTranscript},
    read_pk,
    snark_verifier::halo2_base::{
        gates::{
            circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
            flex_gate::MultiPhaseThreadBreakPoints,
        },
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::{Bn256, Fr, G1Affine},
            plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey},
            poly::{
                commitment::{Params, ParamsProver},
                kzg::{
                    commitment::{KZGCommitmentScheme, ParamsKZG},
                    multiopen::VerifierSHPLONK,
                    strategy::SingleStrategy,
                },
                VerificationStrategy,
            },
            SerdeFormat,
        },
        utils::fs::gen_srs,
        AssignedValue,
    },
    NativeLoader,
};

use crate::{circuit::ecdsa_verify, ECDSAInput};

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

pub struct ECDSAProver {
    pk: ProvingKey<G1Affine>,
    params: ParamsKZG<Bn256>,
    pinning: (BaseCircuitParams, MultiPhaseThreadBreakPoints),
}

impl ECDSAProver {
    fn read_pinning() -> Option<(BaseCircuitParams, MultiPhaseThreadBreakPoints)> {
        if let Ok(f) = std::fs::File::open("params/pinning.json") {
            if let Ok(c) =
                serde_json::from_reader::<_, (BaseCircuitParams, MultiPhaseThreadBreakPoints)>(f)
            {
                return Some(c);
            } else {
                // remove invalid file
                let _ = std::fs::remove_file(PathBuf::from("params/pinning.json"));
            }
        }
        None
    }

    fn from_files() -> Option<Self> {
        if let Some(pinning) = Self::read_pinning() {
            let params = gen_srs(pinning.0.k as u32);
            if let Ok(pk) = read_pk::<BaseCircuitBuilder<Fr>>(
                &PathBuf::from("params/pk.bin"),
                pinning.0.clone(),
            ) {
                return Some(Self {
                    pk,
                    params,
                    pinning,
                });
            }
        }
        None
    }

    pub fn new() -> Self {
        if let Some(v) = Self::from_files() {
            return v;
        }

        let params = gen_srs(18);
        let input = ECDSAInput::default();
        let pre_circuit = PreCircuit {
            private_inputs: input,
            f: ecdsa_verify,
        };
        let circuit = pre_circuit
            .create_circuit(CircuitBuilderStage::Keygen, None, &params)
            .expect("pre-built circuit cannot failed");

        let pk = gen_pk(&params, &circuit, Some(&PathBuf::from("params/pk.bin")));
        let pinning = {
            let path = PathBuf::from("params/pinning.json");
            let pinning = (circuit.params(), circuit.break_points());
            let mut file = std::fs::File::create(path).unwrap();
            serde_json::to_writer_pretty(&mut file, &pinning).unwrap();
            pinning
        };

        Self {
            params,
            pk,
            pinning,
        }
    }

    pub fn create_proof(&self, input: ECDSAInput) -> Result<Vec<u8>> {
        let pre_circuit = PreCircuit {
            private_inputs: input,
            f: ecdsa_verify,
        };

        let circuit = pre_circuit.clone().create_circuit(
            CircuitBuilderStage::Prover,
            Some(self.pinning.clone()),
            &self.params,
        )?;

        let snark = gen_snark_shplonk(&self.params, &self.pk, circuit, Option::<&PathBuf>::None);
        let accept = {
            let vk = self.pk.get_vk();
            let mut circuit =
                pre_circuit.create_circuit(CircuitBuilderStage::Keygen, None, &self.params)?;

            let mut transcript =
                PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(snark.proof.as_slice());
            let instances = snark.instances[0].as_slice();

            circuit.clear();
            snark_verifier_sdk::snark_verifier::halo2_base::halo2_proofs::plonk::verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                _,
                _,
                _,
            >(
                self.params.verifier_params(),
                vk,
                SingleStrategy::new(&self.params),
                &[&[instances]],
                &mut transcript,
            )
            .is_ok()
        };
        assert!(accept);
        Ok(snark.proof)
    }
}

impl Default for ECDSAProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use snark_verifier_sdk::snark_verifier::{
        halo2_base::{
            halo2_proofs::halo2curves::secp256r1::Fq,
            utils::{biguint_to_fe, fe_to_biguint, modulus},
        },
        util::arithmetic::PrimeField,
    };

    use super::*;

    use crate::halo2curves::secp256r1::Secp256r1Affine as Affine;
    use crate::{halo2_proofs::arithmetic::CurveAffine, ECDSAInput};

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
        let prover = ECDSAProver::new();
        prover.create_proof(input).unwrap();
    }
}
