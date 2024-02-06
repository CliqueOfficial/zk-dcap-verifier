use std::{path::PathBuf, rc::Rc};

use anyhow::Result;
use common::{
    halo2_base::{
        gates::{
            circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
            flex_gate::MultiPhaseThreadBreakPoints,
        },
        utils::fs::gen_srs,
        AssignedValue,
    },
    halo2_proofs::{
        plonk::{Circuit, ProvingKey},
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        SerdeFormat,
    },
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    snark_verifier::{
        loader::evm::{compile_solidity, EvmLoader},
        system::halo2::{compile, transcript::evm::EvmTranscript, Config},
        verifier::SnarkVerifier,
    },
    snark_verifier_sdk::{
        self, evm::encode_calldata, gen_pk, halo2::PoseidonTranscript, read_pk, NativeLoader,
        PlonkVerifier, SHPLONK,
    },
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
    const INSTANCES_LEN: usize = 15;
    const DEGREE: u32 = 21u32;
    const BATCH_SIZE: usize = 4usize;

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

    pub fn keygen() -> Result<()> {
        let params = gen_srs(Self::DEGREE);
        let input = vec![ECDSAInput::default(); Self::BATCH_SIZE];
        let pre_circuit = PreCircuit {
            private_inputs: input,
            f: ecdsa_verify,
        };
        let circuit = pre_circuit
            .create_circuit(CircuitBuilderStage::Keygen, None, &params)
            .expect("pre-built circuit cannot failed");

        {
            let pk = gen_pk(&params, &circuit, Some(&PathBuf::from("params/pk.bin")));
            let vk = pk.get_vk();

            let vk_path = PathBuf::from("params/vk.bin");
            if vk_path.exists() {
                std::fs::remove_file(&vk_path).unwrap();
            }
            let mut file = std::fs::File::create(vk_path).unwrap();
            vk.write(&mut file, SerdeFormat::RawBytesUnchecked).unwrap();
        };

        {
            let path = PathBuf::from("params/pinning.json");
            if path.exists() {
                std::fs::remove_file(&path).unwrap();
            }
            let pinning = (circuit.params(), circuit.break_points());
            let mut file = std::fs::File::create(path).unwrap();
            serde_json::to_writer_pretty(&mut file, &pinning).unwrap();
        };
        Ok(())
    }

    pub fn new(
        pk: ProvingKey<G1Affine>,
        params: ParamsKZG<Bn256>,
        pinning: (BaseCircuitParams, MultiPhaseThreadBreakPoints),
    ) -> Self {
        Self {
            pk,
            params,
            pinning,
        }
    }

    pub fn create_proof(&self, input: Vec<ECDSAInput>, evm: bool) -> Result<Vec<u8>> {
        // Extend `input` to BATCH_SIZE
        let input = [input, vec![ECDSAInput::default(); 4]].concat();
        let input = input[..4].to_vec();

        let pre_circuit = PreCircuit {
            private_inputs: input.clone(),
            f: ecdsa_verify,
        };

        let circuit = pre_circuit.clone().create_circuit(
            CircuitBuilderStage::Prover,
            Some(self.pinning.clone()),
            &self.params,
        )?;
        let instances = input
            .iter()
            .flat_map(|input| input.as_instances())
            .collect::<Vec<_>>();

        let proof = if evm {
            snark_verifier_sdk::evm::gen_evm_proof_shplonk(
                &self.params,
                &self.pk,
                circuit,
                vec![instances.clone()],
            )
        } else {
            snark_verifier_sdk::halo2::gen_proof::<
                _,
                ProverSHPLONK<'_, _>,
                VerifierSHPLONK<'_, Bn256>,
            >(
                &self.params,
                &self.pk,
                circuit,
                vec![instances.clone()],
                None,
            )
        };

        #[cfg(debug_assertions)]
        {
            let accept = if evm {
                let sol = self.gen_evm_verifier().unwrap();
                let bytecode = compile_solidity(&sol);
                let calldata = encode_calldata(&[instances], &proof);
                snark_verifier_sdk::snark_verifier::loader::evm::deploy_and_call(bytecode, calldata)
                    .is_ok()
            } else {
                let vk = self.pk.get_vk();
                let mut circuit =
                    pre_circuit.create_circuit(CircuitBuilderStage::Keygen, None, &self.params)?;

                let mut transcript =
                    PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(proof.as_slice());

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
                    &[&[&instances]],
                    &mut transcript,
                )
                .is_ok()
            };
            assert!(accept);
        }
        Ok(proof)
    }

    pub fn gen_evm_verifier(&self) -> Result<String> {
        let protocol = compile(
            &self.params,
            self.pk.get_vk(),
            Config::kzg().with_num_instance(vec![Self::INSTANCES_LEN * Self::BATCH_SIZE]),
        );

        let vk = (self.params.get_g()[0], self.params.g2(), self.params.s_g2()).into();

        let loader = EvmLoader::new::<Fq, Fr>();
        let protocol = protocol.loaded(&loader);
        let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

        let instances = transcript.load_instances(vec![Self::INSTANCES_LEN * Self::BATCH_SIZE]);
        let proof =
            PlonkVerifier::<SHPLONK>::read_proof(&vk, &protocol, &instances, &mut transcript)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        assert!(PlonkVerifier::<SHPLONK>::verify(&vk, &protocol, &instances, &proof).is_ok());
        Ok(loader.solidity_code())
    }
}

impl Default for ECDSAProver {
    fn default() -> Self {
        if let Some(v) = Self::from_files() {
            return v;
        }

        Self::keygen().unwrap();
        Self::from_files().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    use super::*;

    use crate::ECDSAInput;

    #[test]
    fn test_p256_ecdsa() {
        let msghash = "0x9c8adb93585642008f6defe84b014d3db86e65ec158f32c1fe8b78974123c264";
        let signature = "0x89e7242b7a0be99f7c668a8bdbc1fcaf6fa7562dd28538dbab4b059e9d6955c2c434593d3ccb0e7e5825effb14e251e6e5efb738d6042647ed2e2faac9191718";
        let pubkey = "0x04cd8fdae57e9fcc6638b7e0bdf1cfe6eb4783c29ed13916f10c121c70b7173dd61291422f9ef68a1b6a7e9cccbe7cc2c0738f81a996f7e62e9094c1f80bc0d788";

        {
            let pubkey = hex::decode(pubkey).unwrap();
            let signature = hex::decode(signature).unwrap();
            let msghash = hex::decode(msghash).unwrap();
            let vk = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
            let signature = Signature::from_slice(&signature).unwrap();
            vk.verify_prehash(&msghash, &signature).unwrap();
        }

        let input = ECDSAInput::try_from_hex(msghash, signature, pubkey).unwrap();
        let prover = ECDSAProver::default();
        prover
            .create_proof(vec![input, input, input, input], false)
            .unwrap();
        prover
            .create_proof(vec![input, input, input, input], true)
            .unwrap();
    }
}
