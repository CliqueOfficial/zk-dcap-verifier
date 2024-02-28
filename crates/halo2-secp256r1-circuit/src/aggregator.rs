use std::any::type_name;

#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};

use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, Error};
use halo2_base::halo2_proofs::plonk::{Circuit, ProvingKey};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::fs::gen_srs;
use rand::rngs::OsRng;
use snark_verifier::system::halo2::{self, Config};
use snark_verifier_sdk::{
    gen_pk, gen_proof, gen_snark_shplonk, load_verify_circuit_degree, AggregationCircuit,
    CircuitExt, Snark,
};

use crate::{EvmProver, EvmProverVerifyResult};

pub struct EvmAggregator<const N: usize, C: CircuitExt<Fr>> {
    circuit: C,
    pk: ProvingKey<G1Affine>,
    prover: EvmProver<AggregationCircuit>,
}

impl<C: CircuitExt<Fr>, const N: usize> EvmAggregator<N, C> {
    pub fn new(params: &ParamsKZG<Bn256>, circuit: C) -> Result<Self, Error> {
        let agg_params = gen_srs(load_verify_circuit_degree());
        let pk = gen_pk(&params, &circuit.without_witnesses(), None);
        let snarks = vec![Self::generate_snark(circuit.without_witnesses(), &pk, params); N];
        let agg_keygen_circuit = AggregationCircuit::new(&params, snarks, OsRng);
        let tag = format!("aggregator_{}", type_name::<C>());
        let prover = EvmProver::new(&tag, agg_params, agg_keygen_circuit.without_witnesses())?;
        Ok(Self {
            circuit,
            pk,
            prover,
        })
    }

    pub fn deployment_code(&self, path: Option<&str>) -> Vec<u8> {
        self.prover.deployment_code(path)
    }

    pub fn generate_circuit(
        &self,
        params: &ParamsKZG<Bn256>,
        circuits: [C; N],
    ) -> AggregationCircuit {
        #[cfg(feature = "display")]
        let pt = start_timer!(|| "agg: generate circuit");

        let mut snarks = Vec::with_capacity(circuits.len());
        for circuit in circuits {
            snarks.push(Self::generate_snark(circuit, &self.pk, params));
        }
        let circuit = AggregationCircuit::new(params, snarks, OsRng);

        #[cfg(feature = "display")]
        end_timer!(pt);

        circuit
    }

    pub fn generate_proof(&self, agg_circuit: AggregationCircuit) -> Vec<u8> {
        self.prover.generate_proof(agg_circuit)
    }

    pub fn generate_calldata(&self, instances: &[Vec<Fr>], proof: &[u8]) -> Vec<u8> {
        snark_verifier_sdk::encode_calldata(&instances, &proof)
    }

    pub fn evm_verify(
        &self,
        instances: &[Vec<Fr>],
        proof: &[u8],
        deployment_code: Vec<u8>,
    ) -> EvmProverVerifyResult {
        self.prover.evm_verify(instances, proof, deployment_code)
    }

    pub fn to_bytes(&self, format: SerdeFormat) -> Vec<u8> {
        self.prover.to_bytes(format)
    }

    //
    // let deployment_code = verifier.deployment_code();

    // let deployment_code_len = deployment_code.len();

    // let result = verifier.evm_verify(agg_circuit, deployment_code);
    // println!("result: {:?}", result);
    // println!("deployment_code: {}", deployment_code_len);

    // let proof = prover.generate_proof(agg_circuit, agg_circuit.instances());
    // prover.evm_verify(instances, proof);
    // }

    fn generate_snark(circuit: C, pk: &ProvingKey<G1Affine>, params: &ParamsKZG<Bn256>) -> Snark {
        gen_snark_shplonk(params, pk, circuit, &mut OsRng, None::<&str>)
    }
}

const N: usize = 1;

#[cfg(test)]
mod test {
    use super::*;
    use crate::{circuit, ecdsa_params, EvmAggregator, Secp256r1Circuit, K};

    #[test]
    fn test_aggregator() {
        use std::convert::TryInto;
        // N=1: col: 8, size: 20768, gas: 495576; col: 4, size:16684, gas: 410563; col: 2, size: 14350, gas: 356584
        // N=2: size: -, gas: -
        // N=3: size: -, gas: -
        // N=4: col:8, size: 21610, gas: 530560
        // N=5: size: , gas:
        // N=6: size: , gas:
        const N: usize = 2;

        let mut input = ecdsa_params()[..1].to_vec();
        // let mut msg = input[2].msg.to_vec();
        // msg[3] += 1;
        // input[2].msg = &msg;
        // let mut pubkey = params.pubkey.to_owned();
        let circuits = input
            .chunks(N)
            .map(<Secp256r1Circuit<Fr, N>>::new)
            .collect::<Vec<_>>();
        let params = gen_srs(K);
        let aggregator = <EvmAggregator<1, _>>::new(&params, Default::default()).unwrap();
        let deployment_code = aggregator.deployment_code();
        let circuit = aggregator.generate_circuit(&params, circuits.try_into().unwrap());
        let result = aggregator.evm_verify(circuit, deployment_code);
        println!("result: {:?}", result);
    }
}
