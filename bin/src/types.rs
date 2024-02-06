use std::str::FromStr;

use anyhow::Result;
use p256_ecdsa::ECDSAInput;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ECDSAInputPayload {
    msghash: String,
    pubkey: String,
    signature: String,
}

impl From<ECDSAInputPayload> for ECDSAInput {
    fn from(value: ECDSAInputPayload) -> Self {
        Self::try_from_hex(&value.msghash, &value.signature, &value.pubkey).unwrap()
    }
}
