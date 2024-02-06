use anyhow::{anyhow, Result};
use p256::EncodedPoint;
use sha2::{digest::Digest, Sha256};
use signature::hazmat::PrehashVerifier;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

pub(crate) fn verify_signature<R, N>(vk: &VerifyingKey, sig: R, message: N) -> Result<()>
where
    R: AsRef<[u8]>,
    N: AsRef<[u8]>,
{
    let message = Sha256::digest(message.as_ref());
    let message = message.as_slice();

    vk.verify_prehash(message.as_ref(), sig.as_ref()).unwrap();
    {
        let _m = hex::encode(message);
        let _s = hex::encode(sig.as_ref());
        let _p = hex::encode(vk.0.to_encoded_point(false).as_bytes());
    }
    Ok(())
}

pub struct VerifyingKey(pub p256::ecdsa::VerifyingKey);

impl VerifyingKey {
    pub fn verify_prehash(&self, msg: impl AsRef<[u8]>, sig: impl AsRef<[u8]>) -> Result<()> {
        self.0
            .verify_prehash(
                msg.as_ref(),
                &p256::ecdsa::Signature::from_slice(sig.as_ref()).unwrap(),
            )
            .map_err(|_| anyhow!("Invalid signature"))
    }

    pub fn from_untagged_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let len = bytes.as_ref().len();
        if len != 64 {
            return Err(anyhow!("Expect 64 bytes but found {}", len));
        }

        let point = EncodedPoint::from_untagged_bytes(bytes.as_ref().into());
        let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .map_err(|_| anyhow!("Invalid public key"))?;
        Ok(Self(vk))
    }

    pub fn from_sec1_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let len = bytes.as_ref().len();
        if len != 65 {
            return Err(anyhow!("Expect 65 bytes but found {}", len));
        }

        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes.as_ref())
            .map_err(|_| anyhow!("Invalid public key"))?;
        Ok(Self(vk))
    }

    pub fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        Self::from_sec1_bytes(spki.subject_public_key.raw_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn test_verify_signature() {
        let sig = general_purpose::STANDARD.decode("ieckK3oL6Z98ZoqL28H8r2+nVi3ShTjbq0sFnp1pVcLENFk9PMsOflgl7/sU4lHm5e+3ONYEJkftLi+qyRkXGA==").unwrap();
        let public_key = general_purpose::STANDARD.decode("zY/a5X6fzGY4t+C98c/m60eDwp7RORbxDBIccLcXPdYSkUIvnvaKG2p+nMy+fMLAc4+BqZb35i6QlMH4C8DXiA==").unwrap();
        let message = general_purpose::STANDARD.decode("AwACAAAAAAAJAA4Ak5pyM/ecTKmUCg2zlX8GB58v1eFSi0gAaM+d5aI7bOgAAAAADAwQD///AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAADnAAAAAAAAAIDIDmlGKK7n/RSYZe+/CUN2f7i1mn9geBRujaQ/DuCcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD3qZTlRpxL2bFOOSxHx+5xQ2RZXsc8AJVR6ASCh+1pIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU35qIoBd1R7of7n6YauZYZvq3Pbz8zV6CrDg2pf3twptTNQBJFgiN7ltTFPLQQDuECHomN3HoW3ougA49Y7Ud").unwrap();
        assert!(verify_signature(
            &VerifyingKey::from_untagged_bytes(public_key).unwrap(),
            sig,
            message
        )
        .is_ok());
    }
}
