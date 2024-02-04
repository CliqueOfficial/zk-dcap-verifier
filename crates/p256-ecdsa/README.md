# p256-ecdsa

This crate includes a circuit to prove p256 ecdsa signature.

## Usage

** Generate Proof **

```rust
let input = ECDSAInput { ... };
let proof = ECDSAProver::default().create_proof(input).unwrap();
```

** Generate Solidity Verifier Contract **


```rust
ECDSAProver::default().gen_evm_verifier();
```


