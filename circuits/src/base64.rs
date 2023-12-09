// use halo2::halo2curves::bn256::G1Affine;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use halo2_base::{halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Assigned, Circuit, Column, ConstraintSystem, Constraints, Error, Expression,
        Instance, Selector,
    },
    poly::Rotation, halo2curves::{secp256r1::{Fp, Secp256r1Affine, Fq}, CurveAffine},
}, gates::{range::RangeStrategy::Vertical, flex_gate::{FlexGateConfig, GateStrategy}}, SKIP_FIRST_PASS, AssignedValue, gates::{GateInstructions, range::RangeConfig}, Context, ContextParams, utils::{bigint_to_fe, biguint_to_fe, fe_to_bigint, fe_to_biguint, value_to_option}, QuantumCell};
use halo2_ecc::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::{fp::{FpStrategy, FpConfig}, FieldChip},
};
use halo2_base::utils::modulus;
use num_bigint::BigUint;
use std::{fs::File, collections::hash_map, hash};
use serde::{Deserialize, Serialize};
use std::env::var;
use halo2_base::utils::PrimeField;
use std::{marker::PhantomData, vec};
use halo2_dynamic_sha256::*;

use crate::table::BitDecompositionTableConfig;
// use snark_verifier_sdk::CircuitExt;

// Checks a regex of string len
const SHAHASH_BASE64_STRING_LEN: usize = 1696;
const BIT_DECOMPOSITION_ADVICE_COL_COUNT: usize = 12;

#[derive(Debug, Clone)]
pub struct AssignedBase64Result<F: PrimeField> {
    pub encoded: Vec<AssignedCell<F, F>>,
    pub decoded: Vec<AssignedCell<F, F>>,
}

#[derive(Serialize, Deserialize)]
struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

type FpChip<F> = FpConfig<F, Fp>;

// Here we decompose a transition into 3-value lookups.
#[derive(Debug, Clone)]
pub struct Base64Config<F: PrimeField> {
    encoded_chars: Column<Advice>, // This is the raw ASCII character value -- like 'a' would be 97
    bit_decompositions: [Column<Advice>; BIT_DECOMPOSITION_ADVICE_COL_COUNT],
    decoded_chars: Column<Advice>, // This has a 1 char gap between each group of 3 chars
    decoded_chars_without_gap: Column<Advice>,
    bit_decomposition_table: BitDecompositionTableConfig<F>,
    q_decode_selector: Selector,
    fp_config: FpConfig<F, Fp>,
    sha256_config: Sha256DynamicConfig<F>,
    flex_config: FlexGateConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Base64Config<F> {
    const MAX_BYTE_SIZE1: usize = 128;
    const MAX_BYTE_SIZE2: usize = 128;
    const NUM_ADVICE: usize = 3;
    const NUM_FIXED: usize = 1;
    const NUM_LOOKUP_ADVICE: usize = 1;
    const LOOKUP_BITS: usize = 16;

    #[inline]
    pub fn create_bit_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        encoded_or_decoded_index_offset: usize,
        encoded_if_true_and_decoded_if_false: bool,
        bit_query_cols: Vec<usize>,
        bit_lookup_cols: Vec<usize>,
        selector_col: Selector,
    ) -> Option<bool> {
        meta.lookup("lookup base64 encode/decode", |meta| {
            assert!(bit_query_cols.len() == bit_lookup_cols.len());
            let q = meta.query_selector(selector_col);

            // One minus q defaults to the 'a' value and '0' bit values
            let one_minus_q = Expression::Constant(F::from(1)) - q.clone();
            let zero = Expression::Constant(F::from(0));
            let zero_char = Expression::Constant(F::from(65));

            let mut lookup_vec = vec![];
            if encoded_if_true_and_decoded_if_false {
                let encoded_char = meta.query_advice(
                    self.encoded_chars,
                    Rotation(encoded_or_decoded_index_offset as i32),
                );
                lookup_vec.push((
                    q.clone() * encoded_char + one_minus_q.clone() * zero_char.clone(),
                    self.bit_decomposition_table.character,
                ));
            } else {
                let decoded_char = meta.query_advice(
                    self.decoded_chars,
                    Rotation(encoded_or_decoded_index_offset as i32),
                );
                // println!("decoded_char: {:?}", decoded_char);
                lookup_vec.push((
                    q.clone() * decoded_char + one_minus_q.clone() * zero.clone(),
                    self.bit_decomposition_table.value_decoded,
                ));
            }
            for i in 0..bit_query_cols.len() {
                let bit =
                    meta.query_advice(self.bit_decompositions[bit_query_cols[i]], Rotation::cur());
                // println!("bit: {:?}", bit);
                lookup_vec.push((
                    q.clone() * bit + one_minus_q.clone() * zero.clone(),
                    self.bit_decomposition_table.bit_decompositions[bit_lookup_cols[i]],
                ));
            }
            lookup_vec
        });
        None
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let mut bit_decompositions = vec![];
        for _ in 0..BIT_DECOMPOSITION_ADVICE_COL_COUNT {
            bit_decompositions.push(meta.advice_column());
        }
        let encoded_chars = meta.advice_column();
        let decoded_chars = meta.advice_column();
        // let characters = meta.advice_column();
        let decoded_chars_without_gap = meta.advice_column();
        let bit_decomposition_table = BitDecompositionTableConfig::configure(meta);
        let q_decode_selector = meta.complex_selector();

        meta.enable_equality(encoded_chars);
        meta.enable_equality(decoded_chars);
        meta.enable_equality(decoded_chars_without_gap);

        // Create bit lookup for each bit
        const ENCODED_LOOKUP_COLS: [usize; 4] = [0, 1, 2, 3];
        const ENCODED_BIT_LOOKUP_COLS: [[usize; 3]; 4] =
            [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9, 10, 11]];
        const DECODED_LOOKUP_COLS: [usize; 3] = [0, 1, 2];
        const DECODED_BIT_LOOKUP_COLS: [[usize; 4]; 3] =
            [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11]];

        let path = var("ECDSA_CONFIG")
            .unwrap_or_else(|_| "./src/configs/ecdsa_circuit.config".to_string());
        let params: CircuitParams = serde_json::from_reader(
            File::open(&path).unwrap_or_else(|_| panic!("{path:?} file should exist")),
        )
        .unwrap();
        let fp_config = FpConfig::<F, Fp>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            modulus::<Fp>(),
            0,
            params.degree as usize,
        );

        let range_config = RangeConfig::configure(
            meta,
            Vertical,
            &[Self::NUM_ADVICE],
            &[Self::NUM_LOOKUP_ADVICE],
            Self::NUM_FIXED,
            Self::LOOKUP_BITS,
            0,
            19,
        );
        // let hash_column = meta.instance_column();
        // meta.enable_equality(hash_column);
        let sha256_config: Sha256DynamicConfig<F> = Sha256DynamicConfig::configure(
            meta,
            vec![Self::MAX_BYTE_SIZE1, Self::MAX_BYTE_SIZE2],
            range_config,
            8,
            2,
            true,
        );

        let flex_config = FlexGateConfig::configure(
            meta,
            GateStrategy::Vertical,
            &[Self::NUM_ADVICE],
            Self::NUM_FIXED,
            0,
            19
        );

        let config = Self {
            encoded_chars,
            bit_decompositions: bit_decompositions.try_into().unwrap(),
            decoded_chars,
            decoded_chars_without_gap,
            bit_decomposition_table,
            q_decode_selector,
            fp_config,
            sha256_config,
            flex_config,
            _marker: PhantomData,
        };
        // Create bit lookup for each 6-bit encoded value
        for i in 0..ENCODED_LOOKUP_COLS.len() {
            config.create_bit_lookup(
                meta,
                i,
                true,
                ENCODED_BIT_LOOKUP_COLS[i].to_vec(),
                [2, 1, 0].to_vec(),
                config.q_decode_selector,
            );
        }
        // Create bit lookup for each 8-bit decoded value
        for i in 0..DECODED_LOOKUP_COLS.len() {
            config.create_bit_lookup(
                meta,
                i,
                false,
                DECODED_BIT_LOOKUP_COLS[i].to_vec(),
                [3, 2, 1, 0].to_vec(),
                config.q_decode_selector,
            );
        }
        config
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.bit_decomposition_table.load(layouter)
    }
}
#[derive(Default, Clone)]
pub struct Base64Circuit<F: PrimeField> {
    // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
    pub base64_encoded_string: Vec<u8>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Base64Circuit<F> {
    // Note that the two types of region.assign_advice calls happen together so that it is the same region
    fn base64_assign_values(
        &self,
        region: &mut Region<F>,
        characters: &[u8],
        encoded_chars: Column<Advice>,
        bit_decompositions: [Column<Advice>; BIT_DECOMPOSITION_ADVICE_COL_COUNT],
        decoded_chars: Column<Advice>,
        decoded_chars_without_gap: Column<Advice>,
        bit_decomposition_table: BitDecompositionTableConfig<F>,
        q_decode_selector: Selector
    ) -> Result<AssignedBase64Result<F>, Error> {
        let mut assigned_encoded_values = Vec::new();
        let mut assigned_decoded_values = Vec::new();

        // Set the decoded values and enable permutation checks with offset
        let res_decoded_chars: Vec<u8> = general_purpose::STANDARD
            .decode(characters)
            .expect(&format!(
                "{:?} is an invalid base64 string bytes",
                characters
            ));
        for i in 0..res_decoded_chars.len() {
            let offset_value = region.assign_advice(
                || format!("decoded character"),
                decoded_chars_without_gap,
                i,
                || Value::known(F::from_u128(res_decoded_chars[i].into())),
            )?;
            offset_value.copy_advice(
                || "copying to add offset",
                region,
                decoded_chars,
                i + (i / 3),
            )?;
            assigned_decoded_values.push(offset_value);
        }

        // Set the character values as encoded chars
        for i in 0..SHAHASH_BASE64_STRING_LEN {
            let bit_val: u8 = bit_decomposition_table
                .map_character_to_encoded_value(characters[i] as char);
            let assigned_encoded = region.assign_advice(
                || format!("encoded character"),
                encoded_chars,
                i,
                || Value::known(F::from(characters[i] as u64)),
            )?;
            assigned_encoded_values.push(assigned_encoded);

            // Set bit values by decomposing the encoded character
            for j in 0..3 {
                region.assign_advice(
                    || format!("bit assignment"),
                    bit_decompositions[(i % 4) * 3 + j],
                    i - (i % 4),
                    || Value::known(F::from_u128(((bit_val >> ((2 - j) * 2)) % 4) as u128)),
                )?;
            }
        }

        // Enable q_decomposed on every 4 rows
        for i in (0..SHAHASH_BASE64_STRING_LEN).step_by(4) {
            q_decode_selector.enable(region, i)?;
        }
        // println!("Decoded chars: {:?}", decoded_chars);
        let result = AssignedBase64Result {
            encoded: assigned_encoded_values,
            decoded: assigned_decoded_values,
        };
        Ok(result)
    }
}

impl<F: PrimeField> Circuit<F> for Base64Circuit<F> {
    type Config = Base64Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    // Circuit without witnesses, called only during key generation
    fn without_witnesses(&self) -> Self {
        Self {
            base64_encoded_string: vec![],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // let encoded_chars = meta.advice_column();
        // TODO Set an offset to encoded_chars
        let config = Base64Config::configure(meta);
        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // println!("Assigning table in synthesize...");
        let fp_chip = config.fp_config;
        fp_chip.range.load_lookup_table(&mut layouter)?;

        let limb_bits = fp_chip.limb_bits;
        let num_limbs = fp_chip.num_limbs;
        let _num_fixed = fp_chip.range.gate.constants.len();
        let _lookup_bits = fp_chip.range.lookup_bits;
        let _num_advice = fp_chip.range.gate.num_advice;

        config.bit_decomposition_table.load(&mut layouter)?;

        let mut sha256 = config.sha256_config.clone();
        sha256.range().load_lookup_table(&mut layouter)?;
        sha256.load(&mut layouter)?;

        let flex_config = config.flex_config;

        let base64_result = layouter.assign_region(
            || "Assign all values",
            |mut region| self.base64_assign_values(
                &mut region, &self.base64_encoded_string,
                config.encoded_chars,
                config.bit_decompositions,
                config.decoded_chars,
                config.decoded_chars_without_gap,
                config.bit_decomposition_table,
                config.q_decode_selector
            ),
        )?;
        let mut first_pass = SKIP_FIRST_PASS;
        // println!("based64: {:?}", &base64_result.decoded[323..323+12]);
        let pubkey_x = &base64_result.decoded[335..335+32];
        let pubkey_y = &base64_result.decoded[335+32..335+64];
        // println!("pubkey_x: {:?}", pubkey_x);

        // let mut assigned_hash_cells = vec![];
        let range = sha256.range().clone();
        let qe_report: Vec<u8> = vec![8, 9, 14, 13, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 231, 0, 0, 0, 0, 0, 0, 0, 206, 29, 168, 154, 193, 245, 74, 128, 114, 87, 196, 229, 124, 120, 20, 12, 188, 102, 82, 212, 213, 135, 214, 15, 5, 131, 18, 90, 39, 146, 190, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 79, 87, 117, 215, 150, 80, 62, 150, 19, 127, 119, 198, 138, 130, 154, 0, 86, 172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144, 197, 123, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 188, 124, 79, 211, 205, 227, 97, 238, 49, 224, 32, 91, 56, 220, 72, 241, 138, 165, 234, 97, 86, 191, 147, 42, 38, 34, 143, 92, 197, 56, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
 
        // NOTE (xiaowentao) All the values must be Little-Endian
        let pubkey_x_base = Fp::from_bytes(&[25, 122, 102, 10, 107, 161, 208, 37, 40, 103, 230, 212, 217, 201, 219, 37, 243, 21, 148, 231, 81, 156, 37, 255, 173, 53, 17, 65, 57, 1, 131, 41]).unwrap();
        let pubkey_y_base = Fp::from_bytes(&[61, 92, 233, 152, 97, 160, 133, 116, 50, 175, 252, 245, 58, 47, 19, 241, 229, 38, 133, 160, 239, 55, 223, 203, 39, 166, 219, 23, 138, 241, 140, 84]).unwrap();
        let pubkey_point: Option<Secp256r1Affine> = Secp256r1Affine::from_xy(pubkey_x_base, pubkey_y_base).into();
        // sha256 result of qeReport (attestation[436+128:436+512])
        let msghash_tmp: Option<Fq> = <Secp256r1Affine as CurveAffine>::ScalarExt::from_bytes(&[213, 190, 114, 4, 209, 8, 253, 177, 115, 233, 78, 182, 125, 86, 180, 111, 229, 1, 180, 87, 87, 165, 247, 28, 227, 115, 150, 79, 183, 175, 176, 217]).into();
        // qeReportSig (attestation[436+512:436+576])
        let r_point: Option<Fq> = <Secp256r1Affine as CurveAffine>::ScalarExt::from_bytes(&[85, 11, 117, 70, 141, 121, 224, 181, 11, 22, 189, 36, 53, 164, 196, 215, 128, 241, 3, 3, 78, 217, 25, 34, 39, 31, 169, 113, 138, 231, 85, 42]).into();
        let s_point: Option<Fq> = <Secp256r1Affine as CurveAffine>::ScalarExt::from_bytes(&[41, 142, 197, 233, 154, 110, 18, 217, 14, 60, 22, 79, 26, 131, 37, 102, 35, 30, 143, 208, 8, 164, 25, 160, 36, 86, 192, 101, 211, 255, 243, 6]).into();
        println!("msghash_tmp: {:?}", msghash_tmp.unwrap());

        layouter.assign_region(
            || "ECDSA",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = fp_chip.new_context(region);
                let ctx = &mut aux;

                let result0 = sha256.digest(
                    ctx,
                    &qe_report,
                    Some(384),
                )?;
                let hash_bytes: Vec<QuantumCell<'_, '_, F>> = result0.output_bytes.into_iter().map(
                    |v| QuantumCell::ExistingOwned(v)).collect();
                range.finalize(ctx);

                // big-endian
                // load constants from [2^248, 2^240, ..., 2^8, 2^0]
                let coffes = (0..32).map(|i| QuantumCell::Constant(
                    biguint_to_fe(&BigUint::from(2u32).pow(248 - 8 * i)))).collect::<Vec<_>>();
                println!("hash_bytes: {:?}\n{:?}\n", &hash_bytes[..], hash_bytes.len());
                println!("coffs: {:?}\n{:?}\n", &coffes[..], coffes.len());

                let (inter, msghash) = flex_config.inner_product_simple_with_assignments(
                    ctx, coffes, hash_bytes);
                println!("inter: {:?}\n{:?}\n", inter, inter.len());
                println!("msghash: {:?}", msghash);

                let msghash_bigint = fe_to_bigint(value_to_option(msghash.value()).unwrap());

                let (r_assigned, s_assigned, m_assigned) = {
                    let fq_chip = FpConfig::<F, Fq>::construct(
                        fp_chip.range.clone(),
                        limb_bits,
                        num_limbs,
                        modulus::<Fq>(),
                    );

                    let m_assigned = fq_chip.load_private(
                        ctx,
                        FpConfig::<F, Fq>::fe_to_witness(
                            &msghash_tmp.map_or(Value::unknown(), Value::known),
                        ),
                    );
                    println!("true m_assigned: {:?} {:?}", m_assigned.native, m_assigned.truncation);

                    let m_assigned = fq_chip.load_private(
                        ctx, Some(msghash_bigint).map_or(Value::unknown(), Value::known)
                    );

                    let r_assigned = fq_chip.load_private(
                        ctx,
                        FpConfig::<F, Fq>::fe_to_witness(
                            &r_point.map_or(Value::unknown(), Value::known),
                        ),
                    );
                    let s_assigned = fq_chip.load_private(
                        ctx,
                        FpConfig::<F, Fq>::fe_to_witness(
                            &s_point.map_or(Value::unknown(), Value::known),
                        ),
                    );
                    (r_assigned, s_assigned, m_assigned)
                };

                let ecc_chip = EccChip::<F, FpChip<F>>::construct(fp_chip.clone());
                let pk_assigned = ecc_chip.load_private(
                    ctx,
                    (
                        pubkey_point.map_or(Value::unknown(), |pt| Value::known(pt.x)),
                        pubkey_point.map_or(Value::unknown(), |pt| Value::known(pt.y)),
                    ),
                );
                // test ECDSA
                let ecdsa = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256r1Affine>(
                    &ecc_chip.field_chip,
                    ctx,
                    &pk_assigned,
                    &r_assigned,
                    &s_assigned,
                    &m_assigned,
                    4,
                    4,
                );
                
                fp_chip.gate().assert_is_const(ctx, &ecdsa, F::one());

                // IMPORTANT: this copies cells to the lookup advice column to perform range check lookups
                // This is not optional.
                fp_chip.finalize(ctx);

                #[cfg(feature = "display")]
                if self.r.is_some() {
                    println!("ECDSA res {ecdsa:?}");

                    ctx.print_stats(&["Range"]);
                }

                Ok(())
            },
        )?;
        // println!("Done assigning values in synthesize");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit},
    };

    use super::*;

    // TODO: set an offset in the email for the bh= and see what happens
    #[test]
    fn test_base64_decode_pass() {
        let k = 20; // 8, 128, etc

        // Convert query string to u128s
        // "R0g=""
        let characters: Vec<u8> = "MIIE8zCCBJmgAwIBAgIVANnqQ+J6On8k9DBBJWcJx3reEJy4MAoGCCqGSM49BAMCMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTIyMTEyODIyMDIxMFoXDTI5MTEyODIyMDIxMFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQpgwE5QRE1rf8lnFHnlBXzJdvJ2dTmZygl0KFrCmZ6GVSM8YoX26Yny98376CFJuXxEy869fyvMnSFoGGY6Vw9o4IDDjCCAwowHwYDVR0jBBgwFoAUlW9dzb0b4elAScnU9DPOAVcL3lQwawYDVR0fBGQwYjBgoF6gXIZaaHR0cHM6Ly9hcGkudHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw/Y2E9cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBQAE57yu4XMyfNOmuKqnPmlWDwjETAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADCCAjsGCSqGSIb4TQENAQSCAiwwggIoMB4GCiqGSIb4TQENAQEEEEQrDHfHzNZ3gmSih7cpm9swggFlBgoqhkiG+E0BDQECMIIBVTAQBgsqhkiG+E0BDQECAQIBBzAQBgsqhkiG+E0BDQECAgIBCTAQBgsqhkiG+E0BDQECAwIBAzAQBgsqhkiG+E0BDQECBAIBAzARBgsqhkiG+E0BDQECBQICAP8wEQYLKoZIhvhNAQ0BAgYCAgD/MBAGCyqGSIb4TQENAQIHAgEBMBAGCyqGSIb4TQENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAGCyqGSIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAGCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqGSIb4TQENAQIRAgENMB8GCyqGSIb4TQENAQISBBAHCQMD//8BAAAAAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQENAQQEBgBgagAAADAPBgoqhkiG+E0BDQEFCgEBMB4GCiqGSIb4TQENAQYEEHGGXU24gBumawNX8L7XcfEwRAYKKoZIhvhNAQ0BBzA2MBAGCyqGSIb4TQENAQcBAQH/MBAGCyqGSIb4TQENAQcCAQEAMBAGCyqGSIb4TQENAQcDAQEAMAoGCCqGSM49BAMCA0gAMEUCIQC5Jc5Gr9eeJKD9ZkN2l/AHeqDKuog01EOSL6obVJTPowIgbJ8WKzefyUxwbaRQVruhFvo6T9TJzwk4JokWgGnDybI="
            .chars()
            .map(|c| c as u32 as u8)
            .collect();

        // Decode characters
        assert_eq!(characters.len(), SHAHASH_BASE64_STRING_LEN);
        #[allow(deprecated)]
        let chars: Vec<char> = base64::decode(characters.clone())
            .unwrap()
            .iter()
            .map(|&b| b as char)
            .collect();
        // print!("Decoded chars: {:?}", chars);

        // Successful cases
        let circuit = Base64Circuit::<Fr> {
            base64_encoded_string: characters,
            _marker: PhantomData,
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("Error: {:?}", e),
        };
        prover.assert_satisfied();
        CircuitCost::<G1, Base64Circuit<Fr>>::measure((k as u128).try_into().unwrap(), &circuit);
        // .proof_size(2);

        // Assert the 33rd pos is 0
    }

    // #[test]
    // fn test_base64_decode_fail() {
    //     let k = 10;

    //     // Convert query string to u128s
    //     let characters: Vec<u128> = "charcount+not+div+by+4"
    //         .chars()
    //         .map(|c| c as u32 as u128)
    //         .collect();

    //     assert_eq!(characters.len(), SHAHASH_BASE64_STRING_LEN);

    //     // Out-of-range `value = 8`
    //     let circuit = Base64Circuit::<Fp> {
    //         characters: characters,
    //         _marker: PhantomData,
    //     };
    //     let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    //     match prover.verify() {
    //         Err(e) => {
    //             println!("Error successfully achieved!");
    //         }
    //         _ => assert_eq!(1, 0),
    //     }
    // }
}
