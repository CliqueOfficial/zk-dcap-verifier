use std::{io::BufReader, path::PathBuf};

use anyhow::{anyhow, Result};
use common::{
    halo2_base::gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
        flex_gate::MultiPhaseThreadBreakPoints,
    },
    halo2_proofs::{
        plonk::{verify_proof, ProvingKey, VerifyingKey},
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
    snark_verifier::{
        self,
        loader::{evm::compile_solidity, native::NativeLoader},
    },
    snark_verifier_sdk::{evm::encode_calldata, halo2::PoseidonTranscript},
};
use p256_ecdsa::{ECDSAInput, ECDSAProver};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "zk-clique", about = "ZK-Clique commands")]
enum Cli {
    #[structopt(about = "p256-ecdsa commands")]
    P256Ecdsa(P256Ecdsa),
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self {
            Self::P256Ecdsa(cmd) => cmd.run(),
        }
    }
}

#[derive(Debug, StructOpt)]
enum P256Ecdsa {
    #[structopt(about = "Verify a hex-encoded proof with 0x prefix based on given input")]
    Verify {
        #[structopt(long)]
        msghash: String,
        #[structopt(long)]
        signature: String,
        #[structopt(long)]
        pubkey: String,
        #[structopt(long)]
        evm: bool,
        #[structopt(long)]
        proof: String,
    },
    #[structopt(about = "Create a hex-encoded proof with 0x prefix based on given input")]
    Prove {
        #[structopt(long)]
        msghash: String,
        #[structopt(long)]
        signature: String,
        #[structopt(long)]
        pubkey: String,
        #[structopt(long)]
        evm: bool,
        #[structopt(
            short,
            long,
            parse(from_os_str),
            about = "Optional, by default it prints to stdout"
        )]
        output: Option<PathBuf>,
    },
    #[structopt(about = "Generate solidity verifier for p256-ecdsa circuit")]
    GenSolidity {
        #[structopt(
            short,
            long,
            parse(from_os_str),
            about = "Optional, by default it prints to stdout"
        )]
        output: Option<PathBuf>,
    },
    #[structopt(about = "Encode instances and proof as evm calldata")]
    GenCalldata {
        #[structopt(long)]
        msghash: String,
        #[structopt(long)]
        signature: String,
        #[structopt(long)]
        pubkey: String,
        #[structopt(long)]
        proof: String,
        #[structopt(
            short,
            long,
            parse(from_os_str),
            about = "Optional, by default it prints to stdout"
        )]
        output: Option<PathBuf>,
    },
    Setup,
}

impl P256Ecdsa {
    fn read_raw_or_file(raw: String) -> String {
        let raw = raw.trim();
        let is_literal = raw.starts_with("0x");
        if is_literal {
            raw[2..].into()
        } else {
            let p = PathBuf::from(&raw);
            std::fs::read_to_string(p).unwrap()
        }
    }
    fn run(self) -> Result<()> {
        match self {
            Self::Verify {
                msghash,
                signature,
                pubkey,
                proof,
                evm,
            } => {
                let [msghash, signature, pubkey, proof] =
                    [msghash, signature, pubkey, proof].map(Self::read_raw_or_file);

                let input = ECDSAInput::try_from_hex(&msghash, &signature, &pubkey)?;

                println!(
                    "{}",
                    Self::inner_verify_proof(&hex::decode(&proof)?, input, evm)
                );
                Ok(())
            }

            Self::Prove {
                msghash,
                signature,
                pubkey,
                output,
                evm,
            } => {
                let [msghash, signature, pubkey] =
                    [msghash, signature, pubkey].map(Self::read_raw_or_file);
                let input = ECDSAInput::try_from_hex(&msghash, &signature, &pubkey)?;
                let prover = ECDSAProver::new(Self::pk(), Self::params(), Self::pinning());
                let proof = ["0x", &hex::encode(prover.create_proof(input, evm)?)].concat();
                if let Some(output) = output {
                    std::fs::write(output, proof.as_bytes())?;
                } else {
                    println!("{}", proof);
                }
                Ok(())
            }
            Self::GenCalldata {
                msghash,
                signature,
                pubkey,
                output,
                proof,
            } => {
                let [msghash, signature, pubkey, proof] =
                    [msghash, signature, pubkey, proof].map(Self::read_raw_or_file);
                let input = ECDSAInput::try_from_hex(&msghash, &signature, &pubkey)?;
                let calldata = encode_calldata(&[input.as_instances()], &hex::decode(&proof)?);
                let calldata = ["0x", &hex::encode(calldata)].concat();
                if let Some(output) = output {
                    std::fs::write(output, calldata.as_bytes())?;
                } else {
                    println!("{}", calldata);
                }
                Ok(())
            }

            Self::GenSolidity { output } => {
                let code = Self::gen_evm_verifier()?;
                if let Some(output) = output {
                    std::fs::write(output, code.as_bytes())?;
                } else {
                    println!("{}", code);
                }
                Ok(())
            }

            Self::Setup => ECDSAProver::keygen(),
        }
    }

    fn pinning() -> (BaseCircuitParams, MultiPhaseThreadBreakPoints) {
        let raw_pinning = std::fs::read_to_string("./params/pinning.json").unwrap();
        serde_json::from_str(&raw_pinning).unwrap()
    }

    fn gen_evm_verifier() -> Result<String> {
        let prover = ECDSAProver::new(Self::pk(), Self::params(), Self::pinning());
        prover.gen_evm_verifier()
    }

    fn pk() -> ProvingKey<G1Affine> {
        let (params, _) = Self::pinning();
        let raw_pk = std::fs::read("./params/pk.bin").unwrap();
        ProvingKey::<_>::from_bytes::<BaseCircuitBuilder<Fr>>(
            &raw_pk,
            SerdeFormat::RawBytesUnchecked,
            params,
        )
        .unwrap()
    }

    fn vk() -> VerifyingKey<G1Affine> {
        let (params, _) = Self::pinning();
        let raw_vk = std::fs::read("./params/vk.bin").unwrap();
        VerifyingKey::<_>::from_bytes::<BaseCircuitBuilder<Fr>>(
            &raw_vk,
            SerdeFormat::RawBytesUnchecked,
            params,
        )
        .unwrap()
    }

    fn params() -> ParamsKZG<Bn256> {
        let raw = std::fs::read("./params/kzg_bn254_18.srs").unwrap();
        let mut reader = BufReader::new(raw.as_slice());
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    }

    fn inner_verify_proof(proof: &[u8], input: ECDSAInput, evm: bool) -> bool {
        if evm {
            let sol = Self::gen_evm_verifier().unwrap();
            let bytecode = compile_solidity(&sol);
            let calldata = encode_calldata(&[input.as_instances()], proof);
            snark_verifier::loader::evm::deploy_and_call(bytecode, calldata).is_ok()
        } else {
            let vk = Self::vk();
            let params = Self::params();
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
}

fn main() -> Result<()> {
    let cli = Cli::from_args();
    let params = std::path::PathBuf::from("./params");
    if !params.exists() {
        return Err(anyhow!("You may forget to download params or run `setup` first. If it doesn't work, please remove `params` directory and try again."));
    }
    cli.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_verify() -> Result<()> {
        let cli = P256Ecdsa::Verify {
            msghash: "0x9c8adb93585642008f6defe84b014d3db86e65ec158f32c1fe8b78974123c264".into(), 
            signature: "0x89e7242b7a0be99f7c668a8bdbc1fcaf6fa7562dd28538dbab4b059e9d6955c2c434593d3ccb0e7e5825effb14e251e6e5efb738d6042647ed2e2faac9191718".into(), 
            pubkey: "0x04cd8fdae57e9fcc6638b7e0bdf1cfe6eb4783c29ed13916f10c121c70b7173dd61291422f9ef68a1b6a7e9cccbe7cc2c0738f81a996f7e62e9094c1f80bc0d788".into(), 
            proof: include_str!("../assets/proof.bin").into(),
            evm: false,
        };
        cli.run()
    }
}
