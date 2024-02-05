use std::path::PathBuf;

use p256_ecdsa::ECDSAProver;

fn main() {
    let p = PathBuf::from("./params");
    if !p.exists() && ECDSAProver::keygen().is_err() {
        std::fs::remove_dir_all(p).unwrap();
        panic!("Failed to generate params");
    }
}
