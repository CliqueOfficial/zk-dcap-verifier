use std::io::BufReader;

use anyhow::{anyhow, Result};
use p256_ecdsa::{
    halo2_base::gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
        flex_gate::MultiPhaseThreadBreakPoints,
    },
    halo2_proofs::{
        plonk::{verify_proof, VerifyingKey},
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::VerifierSHPLONK,
                strategy::SingleStrategy,
            },
        },
        SerdeFormat,
    },
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    snark_verifier::loader::native::NativeLoader,
    snark_verifier_sdk::halo2::PoseidonTranscript,
    ECDSAInput,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "zk-clique", about = "Clique zk tools")]
enum Cli {
    Verify {
        msghash: String,
        signature: String,
        pubkey: String,
        proof: String,
    },
}

impl Cli {
    fn run(self) -> Result<()> {
        match self {
            Self::Verify {
                msghash,
                signature,
                pubkey,
                proof,
            } => {
                let [msghash, signature, pubkey, proof] =
                    [msghash, signature, pubkey, proof].map(Self::read_bytes);

                let (r, s) = (signature.len() == 64)
                    .then(|| signature.split_at(32))
                    .ok_or(anyhow!("signature should be 64 bytes"))?;

                let (x, y) = (pubkey.len() == 65)
                    .then(|| &pubkey[1..])
                    .map(|v| v.split_at(32))
                    .ok_or(anyhow!("Pubkey should be uncompressed format"))?;

                let input = ECDSAInput::new(&msghash, r, s, x, y)?;

                Self::inner_verify_proof(&proof, input)
                    .then_some(())
                    .ok_or(anyhow!("Invalid signature"))
            }
        }
    }

    fn read_bytes(raw: String) -> Vec<u8> {
        let raw = raw.trim();
        let is_literal = raw.starts_with("0x");
        if is_literal {
            hex::decode(&raw[2..]).unwrap()
        } else {
            vec![]
        }
    }

    fn inner_verify_proof(proof: &[u8], input: ECDSAInput) -> bool {
        let vk = {
            let circuit_params = {
                let raw_pinning = include_str!("../params/pinning.json");
                let (p, _): (BaseCircuitParams, MultiPhaseThreadBreakPoints) =
                    serde_json::from_str(raw_pinning).unwrap();
                p
            };
            let raw_vk = include_bytes!("../params/vk.bin");
            VerifyingKey::<G1Affine>::from_bytes::<BaseCircuitBuilder<Fr>>(
                raw_vk,
                SerdeFormat::RawBytesUnchecked,
                circuit_params,
            )
            .unwrap()
        };

        let params = {
            let bytes = include_bytes!("../params/kzg_bn254_18.srs");
            let mut reader = BufReader::new(bytes.as_ref());
            ParamsKZG::<Bn256>::read(&mut reader).unwrap()
        };

        let mut transcript = PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(proof);

        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            params.verifier_params(),
            &vk,
            SingleStrategy::new(&params),
            &[&[input.as_instances().as_slice()]],
            &mut transcript,
        )
        .is_ok()
    }
}

fn main() -> Result<()> {
    let cli = Cli::from_args();
    cli.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_verify() -> Result<()> {
        let cli = Cli::Verify {
            msghash: "0x9c8adb93585642008f6defe84b014d3db86e65ec158f32c1fe8b78974123c264".into(), 
            signature: "0x89e7242b7a0be99f7c668a8bdbc1fcaf6fa7562dd28538dbab4b059e9d6955c2c434593d3ccb0e7e5825effb14e251e6e5efb738d6042647ed2e2faac9191718".into(), 
            pubkey: "0x04cd8fdae57e9fcc6638b7e0bdf1cfe6eb4783c29ed13916f10c121c70b7173dd61291422f9ef68a1b6a7e9cccbe7cc2c0738f81a996f7e62e9094c1f80bc0d788".into(), 
            proof: include_str!("../assets/proof.bin").into(),
        };
        cli.run()
    }
}
