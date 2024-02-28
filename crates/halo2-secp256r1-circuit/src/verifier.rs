use std::any::type_name;
use std::env::var;
use std::path::Path;

#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, Error};
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use halo2_base::utils::fs::gen_srs;
use rand::rngs::OsRng;
use snark_verifier::loader::evm::ExecutorBuilder;
use snark_verifier_sdk::{gen_pk, AggregationCircuit, CircuitExt, Snark, LIMBS};

use crate::{cal_row_size, Secp256r1Circuit};

pub type Secp256r1Verifier<const N: usize> = EvmProver<Secp256r1Circuit<Fr, N>>;

pub struct EvmProver<C> {
    pub keygen_circuit: C,
    pub params: ParamsKZG<Bn256>,
    pub pk: ProvingKey<G1Affine>,
}

#[derive(Debug)]
pub struct EvmProverVerifyResult {
    pub success: bool,
    pub gas_used: u64,
}

pub(crate) fn params_path(tag: &str, params: &ParamsKZG<Bn256>) -> String {
    let dir = var("PARAMS_DIR").unwrap_or_else(|_| "./params".to_string());
    format!("{dir}/{tag}_kzg_bn254_{}.srs", params.k)
}

impl<C: CircuitExt<Fr>> EvmProver<C> {
    pub fn new(tag: &str, params: ParamsKZG<Bn256>, circuit: C) -> Result<Self, Error> {
        #[cfg(feature = "display")]
        let pt = start_timer!(|| "EvmProver: keygen_vk");

        let path = params_path(tag, &params);

        let pk = gen_pk(&params, &circuit, Some(&Path::new(&path)));

        Ok(Self {
            keygen_circuit: circuit,
            params,
            pk,
        })
    }

    pub fn deployment_code(&self, path: Option<&str>) -> Vec<u8> {
        #[cfg(feature = "display")]
        let pt = start_timer!(|| "EvmProver: create deployment code");

        let path = path.map(|n| Path::new(n));

        let deployment_code = snark_verifier_sdk::gen_evm_verifier_shplonk::<C>(
            &self.params,
            self.pk.get_vk(),
            self.keygen_circuit.num_instance(),
            path,
        );

        #[cfg(feature = "display")]
        end_timer!(pt);
        deployment_code
    }

    pub fn gen_params(k: u32) -> ParamsKZG<Bn256> {
        #[cfg(feature = "display")]
        let pt = start_timer!(|| "EvmProver: setup params");

        let params = ParamsKZG::<Bn256>::setup(k, OsRng);

        #[cfg(feature = "display")]
        end_timer!(pt);

        params
    }

    pub fn evm_verify(&self, instances: &[Vec<Fr>], proof: &[u8], deployment_code: Vec<u8>) -> EvmProverVerifyResult {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();
        let caller = Default::default();
        let contract = evm
            .deploy(caller, deployment_code.into(), 0.into())
            .address
            .unwrap();

        let calldata = self.generate_calldata(instances, proof);
        let result = evm.call_raw(caller, contract, calldata.into(), 0.into());
        EvmProverVerifyResult {
            success: !result.reverted,
            gas_used: result.gas_used,
        }
    }

    pub fn from_bytes(mut buf: &[u8], circuit: C, format: SerdeFormat) -> Option<Self> {
        let r = &mut buf;
        let params = ParamsKZG::read_custom(r, format).ok()?;
        let pk = ProvingKey::read::<_, C>(r, format).ok()?;
        Some(Self {
            keygen_circuit: circuit,
            params,
            pk,
        })
    }

    pub fn to_bytes(&self, format: SerdeFormat) -> Vec<u8> {
        let mut buf = vec![];
        self.params.write_custom(&mut buf, format).unwrap();
        buf.extend(self.pk.to_bytes(format));
        buf
    }

    pub fn generate_proof(&self, circuit: C) -> Vec<u8> {
        #[cfg(feature = "display")]
        let pt = start_timer!(|| "EvmProver: generate proof");

        let instances = circuit.instances();

        let proof = snark_verifier_sdk::gen_evm_proof_shplonk(
            &self.params,
            &self.pk,
            circuit,
            instances,
            &mut OsRng,
        );

        #[cfg(feature = "display")]
        end_timer!(pt);

        proof
    }

    pub fn generate_calldata(&self, instances: &[Vec<Fr>], proof: &[u8]) -> Vec<u8> {
        snark_verifier_sdk::encode_calldata(&instances, &proof)
    }
}
