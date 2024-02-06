use std::{convert::TryInto, fs::File, path::PathBuf, str::FromStr};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;

pub struct TcbInfo {
    pub version: u8,
    pub issue_data: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub fmspc: [u8; 6],
    pub pce_id: [u8; 2],
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u8,
    pub tcb_levels: Vec<TcbLevelInfo>,
}

pub struct TcbLevelInfo {
    pub tcb: Tcb,
    pub tcb_date: DateTime<Utc>,
    pub tcb_statue: String,
}

pub struct Tcb {
    pub sgxtcbcompsvn: [u8; 16],
    pub pcesvn: u16,
}

impl TcbInfo {
    pub fn get() -> &'static Self {
        use std::sync::OnceLock;
        static TCB_INFO: OnceLock<TcbInfo> = OnceLock::new();
        TCB_INFO.get_or_init(|| TcbInfo::load().unwrap())
    }

    fn load() -> Result<Self> {
        let raw = include_str!("../assets/tcbinfo.json");
        let value: Value = serde_json::from_str(raw)?;
        let value = value.get("tcbInfo").unwrap();

        let load_datetime = |key: &str| {
            let raw = value.get(key).unwrap().as_str().unwrap();
            DateTime::<Utc>::from_str(raw).unwrap()
        };
        let load_number = |key: &str| value.get(key).unwrap().as_u64().unwrap();

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

        let version = load_number("version") as u8;
        let issue_data = load_datetime("issueDate");
        let next_update = load_datetime("nextUpdate");
        let fmspc = load_hex!("fmspc")?;
        let pce_id = load_hex!("pceId")?;
        let tcb_type = load_number("tcbType") as u8;
        let tcb_evaluation_data_number = load_number("tcbEvaluationDataNumber") as u8;

        let tcb_levels = value
            .get("tcbLevels")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                let load_u16 = |key: &str| {
                    let value = value.get("tcb").unwrap();
                    value.get(key).unwrap().as_u64().unwrap() as u16
                };

                let tcb = Tcb {
                    sgxtcbcompsvn: (1..=16)
                        .map(|idx| load_u16(&format!("sgxtcbcomp{:02}svn", idx)) as u8)
                        .collect::<Vec<_>>()
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    pcesvn: load_u16("pcesvn"),
                };
                let tcb_date = value
                    .get("tcbDate")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                let tcb_statue = value
                    .get("tcbStatus")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();

                TcbLevelInfo {
                    tcb,
                    tcb_date,
                    tcb_statue,
                }
            })
            .collect();

        Ok(Self {
            version,
            issue_data,
            next_update,
            fmspc,
            pce_id,
            tcb_type,
            tcb_evaluation_data_number,
            tcb_levels,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcb_info_json() {
        TcbInfo::get();
    }
}
