use dcap_quote::{SgxQuote, parse_quote};
use halo2_secp256r1_circuit::{Fr, EvmAggregator, Secp256r1Circuit, CircuitExt, Secp256r1Instance};
use structopt::StructOpt;

use crate::utils::{read_file_or_hex, debug, read_file};
use ethers::prelude::*;
use std::fs;

#[derive(StructOpt, Debug)]
pub enum Dcap {
    ExtractCerts(ExtractCerts),
    GenerateVerifier(GenerateVerifier),
    VerifyQuoteCerts(VerifyQuoteCerts),
}

impl Dcap {
    pub async fn run(&self) -> Result<(), String> {
        match self {
            Self::ExtractCerts(cmd) => cmd.run(),
            Self::GenerateVerifier(cmd) => cmd.run().await,
            Self::VerifyQuoteCerts(cmd) => cmd.run(),
        }
    }
}

#[derive(Debug, StructOpt)]
pub struct ExtractCerts {
    quote: String,
}

impl ExtractCerts {
    pub fn run(&self) -> Result<(), String> {
        let quote_bytes = read_file_or_hex(&self.quote)?;
        let quote = dcap_quote::parse_quote(&quote_bytes).unwrap();
        for (idx, cert) in quote.certs.iter().enumerate() {
            let issuer = if idx == quote.certs.len() - 1 {
                cert
            } else {
                &quote.certs[idx + 1]
            };

            let issue_pubkey_hash = keccak_hash::keccak(&issuer.pub_key);

            println!("{}", "=".repeat(80));
            if let Some(pck) = &cert.pck {
                println!("pck: \n{:?}\n", pck);
            }
            println!("serial_number: \n0x{}\n", hex::encode(&cert.serial_number));
            println!(
                "tbs_certificate: \n0x{}\n",
                hex::encode(&cert.tbs_certificate)
            );
            println!("signature: \n0x{}\n", hex::encode(&cert.signature));
            println!("issuer_pubkey_hash: \n{:?}\n", issue_pubkey_hash);
        }
        Ok(())
    }
}


#[derive(Debug, StructOpt)]
pub struct GenerateVerifier {
    #[structopt(default_value = "target/release/ZkVerifier.bin")]
    bytecode: String,
    #[structopt(long)]
    deploy: bool,
}

impl GenerateVerifier {
    pub async fn run(&self) -> Result<(), String> {
        let k: u32 = halo2_secp256r1_circuit::K;
        let params = Secp256r1Circuit::<Fr, 2>::params();
        let circuit = Secp256r1Circuit::<Fr, 2>::default();

        let agg = EvmAggregator::<2, _>::new(&params, circuit).map_err(debug)?;
        let code = agg.deployment_code(None);

        fs::write(&self.bytecode, code.clone()).map_err(debug)?;

        if self.deploy {
            let rpc_url = std::env::var("RPC_URL").unwrap();
            let private_key = std::env::var("PRIVATE_KEY").unwrap();

            let provider = Provider::<Http>::try_from(rpc_url).unwrap();
            let chain_id = provider.get_chainid().await.unwrap().as_u64();
            let wallet: LocalWallet = private_key.parse().unwrap();
            let wallet = wallet.with_chain_id(chain_id);
            let client = SignerMiddleware::new(provider, wallet);

            let abi = Default::default();
            let contract = ContractFactory::new(abi, code.into(), client.into());
            let result = contract.deploy(()).unwrap();

            let data = result.send().await.unwrap();
            println!("[LOG] Deployed ZkVerifier to: {:?}", data.address());
        }

        Ok(())
    }
}

#[derive(StructOpt, Debug)]
pub struct VerifyQuoteCerts {
    #[structopt(long)]
    quote: String,
    #[structopt(long, default_value = "target/release/ZkVerifier.bin")]
    verifier: String,
}

impl VerifyQuoteCerts {
    pub fn run(&self) -> Result<(), String> {
        const N: usize = 2;
        let quote = read_file_or_hex(&self.quote)?;
        let verifier = read_file(&self.verifier)?;
        let quote = parse_quote(&quote).map_err(debug)?;
        let instances = self.generate_instances(&quote);


        let circuits = instances
            .chunks(N)
            .map(<Secp256r1Circuit<Fr, N>>::new)
            .collect::<Vec<_>>();
        let params = Secp256r1Circuit::<Fr, 2>::params();
        let aggregator = <EvmAggregator<2, _>>::new(&params, Default::default()).unwrap();
        let agg_circuit = aggregator.generate_circuit(&params, circuits.try_into().unwrap());
        let proof = aggregator.generate_proof(agg_circuit.clone());
        let calldata = aggregator.generate_calldata(&agg_circuit.instances(), &proof);
        // let instance_bytes: Vec<u8> = agg_circuit
        //     .instances()
        //     .iter()
        //     .flatten()
        //     .flat_map(|value| value.to_repr().as_ref().iter().rev().cloned().collect::<Vec<_>>())
        //     .collect();
        // std::fs::write("target/release/ZkVerifierProof", proof.clone()).unwrap();
        // std::fs::write("target/release/ZkVerifierProof.calldata", calldata).unwrap();
        let result = aggregator.evm_verify(&agg_circuit.instances(), &proof, verifier);
        println!("result: {:?}", result);
        // std::fs::write("target/release/ZkVerifierProof.instances", hex::encode(instance_bytes)).unwrap();

        // println!("{:?}", agg_circuit.instances());
        // println!("{:?}", hex::encode(instance_bytes));

        Ok(())
    }

    fn generate_instances<'a>(&self, quote: &'a SgxQuote) -> Vec<Secp256r1Instance<'a>> {
        let mut instances = vec![];
        for (idx, cert) in quote.certs.iter().enumerate() {
            let issuer = if idx == quote.certs.len() - 1 {
                cert
            } else {
                &quote.certs[idx + 1]
            };

            instances.push(Secp256r1Instance {
                pubkey: &issuer.pub_key,
                sig: &cert.signature,
                msg: &cert.tbs_certificate,
            });
        }
        instances
    }
}
