use halo2_base::halo2_proofs::halo2curves::group::GroupEncoding;
use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_base::halo2_proofs::plonk::{VerifyingKey, verify_proof};
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_base::{utils::PrimeField, SKIP_FIRST_PASS};

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::PathBuf;

use halo2_ecc::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::{fp::{FpStrategy, FpConfig}, FieldChip},
};


fn main() {
    # TODO
}

#[cfg(test)]
#[test]
fn test_dcap_attestation_verifier() {
    # TODO
}