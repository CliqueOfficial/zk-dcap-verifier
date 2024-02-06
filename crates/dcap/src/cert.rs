use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
};

use der::{
    asn1::{ObjectIdentifier, OctetString},
    Decode,
};
use x509_cert::{
    der::{self, Any, Sequence},
    Certificate,
};

macro_rules! oid {
    ($h: expr) => {
        der::asn1::ObjectIdentifier::new_unwrap($h)
    };
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, Default)]
pub struct Tcb {
    pub pce_svn: u16,
    pub comp_svn_array: [u8; 16],
}

#[allow(clippy::upper_case_acronyms)]
pub struct PCK {
    inner: Certificate,
    pub fmspc: [u8; 6],
    pub pce_id: [u8; 2],
    pub tcb: Tcb,
}

impl std::ops::Deref for PCK {
    type Target = Certificate;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl PCK {
    pub fn new(cert: Certificate) -> Self {
        const SGX_EXTENSION_OID: ObjectIdentifier = oid!("1.2.840.113741.1.13.1");

        const TCB_OID: ObjectIdentifier = oid!("1.2.840.113741.1.13.1.2");
        const TCB_COMPSVN_OID: [ObjectIdentifier; 16] = [
            oid!("1.2.840.113741.1.13.1.2.1"),
            oid!("1.2.840.113741.1.13.1.2.2"),
            oid!("1.2.840.113741.1.13.1.2.3"),
            oid!("1.2.840.113741.1.13.1.2.4"),
            oid!("1.2.840.113741.1.13.1.2.5"),
            oid!("1.2.840.113741.1.13.1.2.6"),
            oid!("1.2.840.113741.1.13.1.2.7"),
            oid!("1.2.840.113741.1.13.1.2.8"),
            oid!("1.2.840.113741.1.13.1.2.9"),
            oid!("1.2.840.113741.1.13.1.2.10"),
            oid!("1.2.840.113741.1.13.1.2.11"),
            oid!("1.2.840.113741.1.13.1.2.12"),
            oid!("1.2.840.113741.1.13.1.2.13"),
            oid!("1.2.840.113741.1.13.1.2.14"),
            oid!("1.2.840.113741.1.13.1.2.15"),
            oid!("1.2.840.113741.1.13.1.2.16"),
        ];
        const TCB_PCESVN_OID: ObjectIdentifier = oid!("1.2.840.113741.1.13.1.2.17");

        const PCEID_OID: ObjectIdentifier = oid!("1.2.840.113741.1.13.1.3");
        const FMSPC_OID: ObjectIdentifier = oid!("1.2.840.113741.1.13.1.4");

        #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
        struct Ext {
            pub key: ObjectIdentifier,
            pub value: Any,
        }

        let raw_ext = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|exts| {
                exts.iter()
                    .find(|ext| ext.extn_id == SGX_EXTENSION_OID)
                    .cloned()
            })
            .unwrap();

        let sgx_exts = Vec::<Ext>::from_der(raw_ext.extn_value.as_bytes())
            .unwrap()
            .into_iter()
            .map(|ext| (ext.key, ext.value))
            .collect::<HashMap<ObjectIdentifier, Any>>();

        let fmspc = OctetString::try_from(&sgx_exts[&FMSPC_OID])
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();
        let pce_id = OctetString::try_from(&sgx_exts[&PCEID_OID])
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();

        let tcb = sgx_exts[&TCB_OID].decode_as::<Vec<Ext>>().unwrap();
        let tcb = tcb
            .into_iter()
            .map(|ext| (ext.key, ext.value))
            .collect::<HashMap<_, _>>();

        let pce_svn = tcb[&TCB_PCESVN_OID].decode_as::<u16>().unwrap();

        let comp_svn_array = TCB_COMPSVN_OID
            .iter()
            .map(|oid| tcb[oid].decode_as::<u8>().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
            .unwrap();

        Self {
            inner: cert,
            fmspc,
            pce_id,
            tcb: Tcb {
                pce_svn,
                comp_svn_array,
            },
        }
    }
}
