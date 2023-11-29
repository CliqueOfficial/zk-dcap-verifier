# zk-dcap-verifier
A halo2 implementation of on-chain DCAP attestation verification

## Roadmap

**Checking the signature**

* get certificate chain, signatures, and the data we want to check its sign from SGX Attestation
* base64 decode certificate from PEM format into bytes
* get public key and signature from certificate bytes
* transform keys, signatures from Big Endian into Litter Endian
* convert AssignedValue into CRTInteger as we need to use ECDSA chip
* get sha256 of the data to be checked using sha256chip
* the output of sha256chip is bytes of the hash, convert the bytes to crtinteger values
* verify secp256r1 signatures using ecdsa chip

**Checking certificate chain is issued by Intel**

* Store the Intel's Root CA's public key in ZK circuit as constant values
* Check the intermediate certificate is issued by Root CA
* Check the leaf certificate is issued by intermediate certificate

**Verifying MRENCLAVE, MRSIGNER, and enclave identity**

* simply get these values from Quote
* compare them with expected ones

**Checking PCK and TCB**

* get Fmspc and pceid from PCK certificate
* compare them with expected ones

**Verifying TCB Level**

* compare TCB level with a update-to-date TCB info

**Checking QE3 report signature and isv_report_signature**

* verifying QE3 report signature with leaf certificate
* verifying `isv_report_signature` with `attestation_key`


**(Optional) checking results and report_data**

* check if the `report_data` is expected by given results. For example, `report_data` is hash of results.
