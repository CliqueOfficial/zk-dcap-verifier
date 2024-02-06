use anyhow::Result;

pub trait BinRepr: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    fn to_bytes(&self) -> Result<Vec<u8>>;
}

pub trait Verifiable {
    type Payload;
    type Output;

    fn verify(&self, payload: Option<&Self::Payload>) -> Result<Self::Output>;
}
