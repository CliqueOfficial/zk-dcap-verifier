use std::{convert::TryInto, fs::File, path::PathBuf};

use anyhow::{anyhow, Result};
use serde_json::Value;

#[derive(PartialEq, Eq)]
pub enum EnclaveIdStatus {
    OK,
    #[allow(non_camel_case_types)]
    SGX_ENCLAVE_REPORT_ISVSVN_REVOKED,
}

pub struct TcbLevel {
    pub isvsvn: u16,
    pub tcb_status: EnclaveIdStatus,
}

pub struct EnclaveId {
    pub miscselect: u32,
    pub miscselect_mask: u32,
    pub isvprodid: u16,
    pub attributes: [u8; 16],
    pub attributes_mask: [u8; 16],
    pub mrsigner: [u8; 32],
    pub tcb_levels: Vec<TcbLevel>,
}

impl EnclaveId {
    pub fn get() -> &'static Self {
        use std::sync::OnceLock;
        static READ_ONLY: OnceLock<EnclaveId> = OnceLock::new();
        READ_ONLY.get_or_init(|| Self::load().unwrap())
    }

    fn load() -> Result<Self> {
        let raw = include_str!("../assets/identity.json");
        let value: Value = serde_json::from_str(raw)?;
        let value = value
            .get("enclaveIdentity")
            .ok_or(anyhow!("Invalid format"))?;

        macro_rules! load_hex {
            ($name: expr) => {
                value
                    .get($name)
                    .and_then(|v| v.as_str())
                    .and_then(|v| hex::decode(v.as_bytes()).ok())
                    .and_then(|v| TryInto::try_into(v.as_slice()).ok())
                    .ok_or(anyhow!("{} doesn't exist or cannot be parsed", $name))
            };
        }

        let miscselect = load_hex!("miscselect").and_then(|v| Ok(u32::from_le_bytes(v)))?;
        let miscselect_mask =
            load_hex!("miscselectMask").and_then(|v| Ok(u32::from_le_bytes(v)))?;
        let attributes = load_hex!("attributes")?;
        let attributes_mask = load_hex!("attributesMask")?;
        let isvprodid = value
            .get("isvprodid")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16)
            .ok_or(anyhow!("isvprodid doesn't exist or cannot be parsed",))?;

        let mrsigner = load_hex!("mrsigner").and_then(|bytes: Vec<u8>| {
            if bytes.len() != 32 {
                Err(anyhow!(
                    "Invalid mrsigner bytes length. MrSigner should be 32-bytes",
                ))
            } else {
                Ok(bytes.as_slice().try_into().unwrap())
            }
        })?;

        let tcb_levels = value
            .get("tcbLevels")
            .and_then(|v| v.as_array())
            .and_then(|tcb_levels| {
                tcb_levels
                    .iter()
                    .map(|tcb_level| {
                        Some(TcbLevel {
                            isvsvn: tcb_level
                                .get("tcb")
                                .and_then(|v| v.get("isvsvn"))
                                .and_then(|v| v.as_u64())
                                .map(|v| v as u16)?,
                            tcb_status: tcb_level.get("tcbStatus").and_then(|v| v.as_str()).map(
                                |v| {
                                    if v == "UpToDate" {
                                        EnclaveIdStatus::OK
                                    } else {
                                        EnclaveIdStatus::SGX_ENCLAVE_REPORT_ISVSVN_REVOKED
                                    }
                                },
                            )?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(anyhow!("tcbLevels don't exist or cannot be parsed",))?;

        Ok(Self {
            miscselect,
            miscselect_mask,
            isvprodid,
            attributes,
            attributes_mask,
            mrsigner,
            tcb_levels,
        })
    }
}
