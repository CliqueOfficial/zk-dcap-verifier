mod types;

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
use types::ECDSAInputPayload;

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
        params: String,
        #[structopt(long)]
        evm: bool,
        #[structopt(long)]
        proof: String,
    },
    #[structopt(about = "Create a hex-encoded proof with 0x prefix based on given input")]
    Prove {
        #[structopt(long)]
        params: String,
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
        params: String,
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
    fn read_proof(raw: String) -> String {
        let raw = raw.trim();
        match raw.starts_with("0x") {
            true => raw[2..].into(),
            false => {
                let p = PathBuf::from(&raw);
                let raw = std::fs::read_to_string(p).unwrap();
                raw[2..].into()
            }
        }
    }

    fn read_params(raw: String) -> Vec<ECDSAInput> {
        if let Ok(r) = serde_json::from_str::<Vec<ECDSAInputPayload>>(&raw) {
            return r.into_iter().map(Into::into).collect::<Vec<_>>();
        }

        let p = PathBuf::from(&raw);
        let raw = std::fs::read_to_string(p).unwrap();
        let r: Vec<ECDSAInputPayload> = serde_json::from_str(&raw).unwrap();
        r.into_iter().map(Into::into).collect::<Vec<_>>()
    }

    fn run(self) -> Result<()> {
        match self {
            Self::Verify { params, proof, evm } => {
                let params = Self::read_params(params);
                let proof = Self::read_proof(proof);

                println!(
                    "{}",
                    Self::inner_verify_proof(&hex::decode(&proof)?, params, evm)
                );
                Ok(())
            }

            Self::Prove {
                params,
                output,
                evm,
            } => {
                let params = Self::read_params(params);

                let prover = ECDSAProver::new(Self::pk(), Self::params(), Self::pinning());
                let proof = ["0x", &hex::encode(prover.create_proof(params, evm)?)].concat();
                if let Some(output) = output {
                    std::fs::write(output, proof.as_bytes())?;
                } else {
                    println!("{}", proof);
                }
                Ok(())
            }
            Self::GenCalldata {
                params,
                output,
                proof,
            } => {
                let params = Self::read_params(params);
                let proof = Self::read_proof(proof);
                let instances: Vec<_> = params.iter().flat_map(|v| v.as_instances()).collect();

                let calldata = encode_calldata(&[instances], &hex::decode(&proof)?);
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
        let (params, _) = Self::pinning();
        let raw = std::fs::read(format!("./params/kzg_bn254_{}.srs", params.k)).unwrap();
        let mut reader = BufReader::new(raw.as_slice());
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    }

    fn inner_verify_proof(proof: &[u8], input: Vec<ECDSAInput>, evm: bool) -> bool {
        let instances: Vec<_> = input.iter().flat_map(|v| v.as_instances()).collect();
        if evm {
            let sol = Self::gen_evm_verifier().unwrap();
            let bytecode = compile_solidity(&sol);
            let calldata = encode_calldata(&[instances], proof);
            snark_verifier::loader::evm::deploy_and_call(bytecode, calldata).is_ok()
        } else {
            let vk = Self::vk();
            let params = Self::params();
            let mut transcript = PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(proof);

            verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
                params.verifier_params(),
                &vk,
                SingleStrategy::new(&params),
                &[&[instances.as_slice()]],
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

    const PARAMS: &str = include_str!("../assets/params.json");

    #[test]
    fn test_cli_prove() -> Result<()> {
        let cli = P256Ecdsa::Prove {
            params: PARAMS.into(),
            evm: true,
            output: None,
        };
        cli.run()
    }

    #[test]
    fn test_cli_verify_native() -> Result<()> {
        let cli = P256Ecdsa::Verify {
            params: PARAMS.into(),
            proof: include_str!("../assets/proof_native.bin").into(),
            evm: false,
        };
        cli.run()
    }

    #[test]
    fn test_cli_verify_evm() -> Result<()> {
        let cli = P256Ecdsa::Verify {
            params: PARAMS.into(),
            proof: include_str!("../assets/proof_evm.bin").into(),
            evm: true,
        };
        cli.run()
    }
}
