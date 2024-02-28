use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::halo2_proofs::circuit::{Region, Value};
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::halo2curves::secp256r1::{Fp, Fq, Secp256r1Affine};
use halo2_base::halo2_proofs::plonk::Advice;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::poly::Rotation;
use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::{modulus, ScalarField};
use halo2_base::{Context, QuantumCell, SKIP_FIRST_PASS};
use halo2_ecc::bigint::CRTInteger;
use halo2_ecc::ecc::ecdsa::ecdsa_verify_no_pubkey_check;
use halo2_ecc::ecc::EccChip;
use halo2_ecc::fields::FieldChip;
use halo2_ecc::fields::{
    fp::{FpConfig, FpStrategy},
    PrimeField,
};
use snark_verifier::util::arithmetic::fe_to_limbs;
use snark_verifier_sdk::CircuitExt;

pub const K: u32 = 17;

#[derive(Debug, Default, Clone)]
pub struct EcdsaParams<Fp: PrimeField, Fq: PrimeField> {
    pub msg_hash: Fq,
    pub x: Fp,
    pub y: Fp,
    pub r: Fq,
    pub s: Fq,
}

impl<Fp: PrimeField, Fq: PrimeField> EcdsaParams<Fp, Fq> {
    pub fn keygen() -> Self {
        // avoid panic for F.invert().unwrap()
        let mut params = Self::default();
        params.x = Fp::ONE;
        params.y = Fp::ONE;
        params.r = Fq::ONE;
        params.s = Fq::ONE;
        params.msg_hash = Fq::ONE;
        params
    }
}

impl<Fp: PrimeField, Fq: PrimeField> EcdsaParams<Fp, Fq> {
    pub fn parse(msg: &[u8]) -> Option<Self> {
        let mut param = Self::default();
        fn from_bytes<F: PrimeField>(msg: &[u8]) -> F {
            let mut tmp = [0_u8; 32];
            tmp.copy_from_slice(msg);
            tmp.reverse();
            F::from_bytes_le(&tmp)
        }
        param.msg_hash = from_bytes(&msg[..32]);
        param.x = from_bytes(&msg[32..64]);
        param.y = from_bytes(&msg[64..96]);
        param.r = from_bytes(&msg[96..128]);
        param.s = from_bytes(&msg[128..160]);
        Some(param)
    }
}

#[derive(Clone)]
pub struct Secp256r1Config<F: PrimeField> {
    pub fp_config: FpConfig<F, Fp>,
    pub ecdsa_params: Column<Instance>,
    pub min_pass: Column<Instance>,
    pub current_pass: Column<Advice>,
}

impl<F: PrimeField> Secp256r1Config<F> {
    fn configure(meta: &mut ConstraintSystem<F>, n: usize) -> Self {
        let fp_config = FpConfig::configure(
            meta,
            FpStrategy::Simple,
            &[4 * n],
            &[n],
            1,
            16,
            88,
            3,
            modulus::<Fp>(),
            0,
            K as _,
        );
        let ecdsa_params = meta.instance_column();
        let min_pass = meta.instance_column();
        let current_pass = meta.advice_column();

        Self {
            fp_config,
            ecdsa_params,
            min_pass,
            current_pass,
        }
    }

    fn load_private<Fp: PrimeField>(
        chip: &FpConfig<F, Fp>,
        ctx: &mut Context<F>,
        val: &Value<Fp>,
    ) -> CRTInteger<F> {
        chip.load_private(ctx, <FpConfig<F, Fp>>::fe_to_witness(&val))
    }

    fn construct_chip<Fp: PrimeField, Fq: PrimeField>(
        fp_chip: &FpConfig<F, Fp>,
    ) -> FpConfig<F, Fq> {
        <FpConfig<F, Fq>>::construct(
            fp_chip.range.clone(),
            fp_chip.limb_bits,
            fp_chip.num_limbs,
            modulus::<Fq>(),
        )
    }

    fn assign(
        &self,
        fp_chip: &FpConfig<F, Fp>,
        region: Region<F>,
        ecdsa_params_list: Vec<EcdsaParams<Fp, Fq>>,
        min_pass: Value<F>,
    ) -> Result<(), Error> {
        let mut aux = fp_chip.new_context(region);
        let ctx = &mut aux;

        let fq_chip = Self::construct_chip(fp_chip);

        let ecdsa_params_list_len = ecdsa_params_list.len();

        let mut vals = vec![];
        for (idx, params) in ecdsa_params_list.into_iter().enumerate() {
            let msg_hash = Value::known(params.msg_hash);
            let x = Value::known(params.x);
            let y = Value::known(params.y);
            let r_point = Value::known(params.r);
            let s_point = Value::known(params.s);

            let msg_assigned = Self::load_private::<Fq>(&fq_chip, ctx, &msg_hash);
            let r_assigned = Self::load_private::<Fq>(&fq_chip, ctx, &r_point);
            let s_assigned = Self::load_private::<Fq>(&fq_chip, ctx, &s_point);

            let ecc_chip = EccChip::<F, _>::construct(fp_chip.clone());
            let pk_assigned = ecc_chip.load_private(ctx, (x, y));

            let ecdsa = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256r1Affine>(
                &ecc_chip.field_chip,
                ctx,
                &pk_assigned,
                &r_assigned,
                &s_assigned,
                &msg_assigned,
                4,
                4,
            );
            vals.push(QuantumCell::Existing(ecdsa));
            // ctx.region
            //     .assign_advice(|| "result", self.current_pass, idx, || ecdsa.value)?;
            // fq_chip.range.gate().add(ctx, ecdsa, b)
            // ecdsa.cell();
            // fq_chip.range.gate().add(ctx, a, b)
            // fq_chip.range.gate().assert_is_const(ctx, &ecdsa, F::ONE);
        }

        println!("ecdsa: {:?}", vals);
        let sum = fq_chip.range.gate().sum(ctx, vals);
        fq_chip.range.gate().assert_equal(
            ctx,
            QuantumCell::Existing(sum),
            QuantumCell::Witness(min_pass),
        );
        // println!("sum: {:?}", sum);

        // for n in 0..ecdsa_params_list_len {
        //     let val = ctx.region.query_advice(self.current_pass, n)?;
        //     println!("value: {:?}", val);
        // }

        // fq_chip.range.gate().assert_is_const(ctx, a, min_pass);

        fp_chip.finalize(ctx);
        Ok(())
    }
}

pub fn verify(msg: &[u8], sig: &[u8], pubkey: &[u8]) {
    use ring::signature::{VerificationAlgorithm, ECDSA_P256_SHA256_FIXED};

    let mut uncompress_key = vec![4];
    uncompress_key.extend(pubkey);
    ECDSA_P256_SHA256_FIXED
        .verify(uncompress_key.as_slice().into(), msg.into(), sig.into())
        .unwrap()
}

#[derive(Clone, Debug)]
pub struct Secp256r1Circuit<F, const N: usize> {
    instances: Vec<F>,
    min_pass: F,
}

impl<F: PrimeField, const N: usize> Default for Secp256r1Circuit<F, N> {
    fn default() -> Self {
        let params_size = cal_row_size(160, F::NUM_BITS as usize / 8) + 1;
        let instances = vec![F::default(); N * params_size];
        Self {
            instances,
            min_pass: F::ZERO,
        }
    }
}

impl<F: PrimeField, const N: usize> Secp256r1Circuit<F, N> {
    pub fn new(instances: &[Secp256r1Instance]) -> Self {
        assert!(instances.len() <= N);
        let mut out = vec![];
        for i in instances {
            out.extend(pack::<F>(&i.payload()));
        }
        let placeholder = Secp256r1Instance::default().payload();
        for i in instances.len()..N {
            out.extend(pack::<F>(&placeholder));
        }
        Self {
            instances: out,
            min_pass: F::from(instances.len() as u64),
        }
    }

    pub fn params() -> ParamsKZG<Bn256> {
        gen_srs(K)
    }
}

impl<F: PrimeField, const N: usize> CircuitExt<F> for Secp256r1Circuit<F, N> {
    fn num_instance(&self) -> Vec<usize> {
        let params_size = cal_row_size(160, F::NUM_BITS as usize / 8) + 1;
        vec![self.instances.len(), 1]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.instances.clone(), vec![self.min_pass]]
    }
}

impl<F: PrimeField, const N: usize> Circuit<F> for Secp256r1Circuit<F, N> {
    type Config = Secp256r1Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Secp256r1Config::configure(meta, N)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let fp_chip = config.fp_config.clone();
        fp_chip.range.load_lookup_table(&mut layouter)?;

        let mut first_pass = SKIP_FIRST_PASS;

        layouter.assign_region(
            || "ECDSA",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let params_size = cal_row_size(160, F::NUM_BITS as usize / 8) + 1;
                let min_pass = region.instance_value(config.min_pass, 0)?;
                let mut ecdsa_params_list = vec![];
                for row in 0..N {
                    let raw = read_unpack(&mut region, config.ecdsa_params, row * params_size)?;
                    let params = if raw.len() == 0 {
                        EcdsaParams::keygen()
                    } else {
                        EcdsaParams::parse(&raw).unwrap()
                    };
                    ecdsa_params_list.push(params);
                }
                config.assign(&fp_chip, region, ecdsa_params_list, min_pass)?;
                Ok(())
            },
        )?;
        Ok(())
    }

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
}

fn pack<F: PrimeField>(mut msg: &[u8]) -> Vec<F> {
    use std::io::Read;
    let fr_bytes = (F::NUM_BITS / 8) as usize;

    let mut tmp = vec![0_u8; fr_bytes];
    let msg_len = msg.len();
    let reader = &mut msg;
    let mut output = Vec::with_capacity(msg_len / fr_bytes + 2);
    output.push(F::from(msg_len as u64));

    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(_) => output.push(F::from_bytes_le(&tmp)),
            Err(err) => unreachable!("{:?}", err),
        }
    }
    output
}

pub(crate) fn cal_row_size(total: usize, single: usize) -> usize {
    if total % single == 0 {
        total / single
    } else {
        (total / single) + 1
    }
}

fn read_unpack<F: PrimeField>(
    region: &mut Region<F>,
    instance: Column<Instance>,
    start_row: usize,
) -> Result<Vec<u8>, Error> {
    let mut msg_len = 0;
    region
        .instance_value(instance, start_row)?
        .map(|n| msg_len = n.get_lower_64() as usize);
    let mut msg = Vec::with_capacity(msg_len);
    let fr_bytes = (F::NUM_BITS / 8) as usize;
    let instance_size = cal_row_size(msg_len, fr_bytes);
    for i in 0..instance_size {
        region
            .instance_value(instance, start_row + i + 1)?
            .map(|f| msg.extend(&f.to_bytes_le()[..fr_bytes]));
    }
    msg.truncate(msg_len);
    Ok(msg)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Secp256r1Circuit, Secp256r1Verifier};
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::fs::gen_srs;

    #[test]
    pub fn test_ecdsa() {
        let k = K;
        const N: usize = 2;
        // N=1: size: 14810, gas: 384620
        // N=2: size: 21135, gas: 507341
        // N=3: size: 28040, gas: 642653
        // N=4: size: 33875, gas: 749759
        // N=5: size: 41251, gas: 886244
        // N=6: size: 48255, gas: 1004665

        let test_params = &ecdsa_params()[..N];

        // let instances = Secp256r1Instance::build_instances::<Fr>(test_params);
        let params = gen_srs(k);
        let circuit = Secp256r1Circuit::<Fr, N>::new(test_params);

        let prover = MockProver::run(k, &circuit, circuit.instances()).unwrap();
        prover.assert_satisfied();

        let verifier = Secp256r1Verifier::new(params, circuit.clone()).unwrap();
        let deployment_code = verifier.deployment_code();
        let result = verifier.evm_verify(circuit, deployment_code);
        println!("evm_verify: {:?}", result);
    }
}

#[derive(Clone, Default)]
pub struct Secp256r1Instance<'a> {
    pub pubkey: &'a [u8],
    pub sig: &'a [u8],
    pub msg: &'a [u8],
}

impl<'a> Secp256r1Instance<'a> {
    pub fn msg_hash(&self) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(self.msg).to_vec()
    }

    pub fn payload(&self) -> Vec<u8> {
        let mut p = self.msg_hash().to_vec();
        p.extend(self.pubkey);
        p.extend(self.sig);
        if p.len() == 32 && self.msg.len() == 0 {
            return vec![1_u8; 160];
        }
        return p;
    }

    pub fn to_fq(&self) -> [Fq; 5] {
        let payload = self.payload();
        assert_eq!(payload.len(), 160);
        let mut buf = [0_u8; 32];
        use std::io::Read;
        let payload = &mut payload.as_slice();
        [Fq::zero(); 5].map(|_| {
            payload.read(&mut buf).unwrap();
            Fq::from_bytes_le(&buf)
        })
    }

    pub fn to_limbs(&self) {}

    pub fn build_instances<F: PrimeField>(params: &[Self]) -> Vec<F> {
        let mut ins_vec = vec![];
        for param in params {
            let p = param.payload();
            ins_vec.extend(pack::<F>(&p));
        }
        ins_vec
    }
}

#[allow(dead_code)]
pub(crate) fn ecdsa_params() -> &'static [Secp256r1Instance<'static>] {
    &[
        Secp256r1Instance {
            msg: &[
                48, 130, 4, 152, 160, 3, 2, 1, 2, 2, 20, 42, 125, 78, 251, 229, 208, 173, 209, 26,
                104, 46, 121, 112, 146, 244, 182, 145, 71, 131, 121, 48, 10, 6, 8, 42, 134, 72,
                206, 61, 4, 3, 2, 48, 112, 49, 34, 48, 32, 6, 3, 85, 4, 3, 12, 25, 73, 110, 116,
                101, 108, 32, 83, 71, 88, 32, 80, 67, 75, 32, 80, 108, 97, 116, 102, 111, 114, 109,
                32, 67, 65, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32,
                67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 20, 48, 18, 6, 3, 85, 4,
                7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 11, 48, 9, 6, 3, 85,
                4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 48, 30, 23, 13,
                50, 51, 48, 56, 50, 52, 50, 49, 52, 48, 51, 48, 90, 23, 13, 51, 48, 48, 56, 50, 52,
                50, 49, 52, 48, 51, 48, 90, 48, 112, 49, 34, 48, 32, 6, 3, 85, 4, 3, 12, 25, 73,
                110, 116, 101, 108, 32, 83, 71, 88, 32, 80, 67, 75, 32, 67, 101, 114, 116, 105,
                102, 105, 99, 97, 116, 101, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116,
                101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 20, 48, 18,
                6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 11, 48,
                9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 48,
                89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7,
                3, 66, 0, 4, 209, 145, 175, 58, 165, 2, 98, 95, 107, 5, 118, 42, 7, 163, 245, 105,
                240, 38, 199, 223, 19, 24, 67, 87, 91, 161, 27, 217, 230, 91, 187, 116, 61, 151,
                103, 110, 251, 63, 150, 12, 107, 92, 21, 27, 85, 96, 166, 60, 33, 40, 56, 133, 240,
                133, 94, 172, 178, 105, 228, 144, 113, 126, 90, 100, 163, 130, 3, 14, 48, 130, 3,
                10, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 149, 111, 93, 205, 189, 27,
                225, 233, 64, 73, 201, 212, 244, 51, 206, 1, 87, 11, 222, 84, 48, 107, 6, 3, 85,
                29, 31, 4, 100, 48, 98, 48, 96, 160, 94, 160, 92, 134, 90, 104, 116, 116, 112, 115,
                58, 47, 47, 97, 112, 105, 46, 116, 114, 117, 115, 116, 101, 100, 115, 101, 114,
                118, 105, 99, 101, 115, 46, 105, 110, 116, 101, 108, 46, 99, 111, 109, 47, 115,
                103, 120, 47, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 105, 111, 110, 47,
                118, 51, 47, 112, 99, 107, 99, 114, 108, 63, 99, 97, 61, 112, 108, 97, 116, 102,
                111, 114, 109, 38, 101, 110, 99, 111, 100, 105, 110, 103, 61, 100, 101, 114, 48,
                29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 13, 235, 225, 18, 155, 26, 116, 245, 157, 114,
                240, 101, 154, 235, 65, 70, 0, 38, 76, 37, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4,
                4, 3, 2, 6, 192, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 130, 2, 59,
                6, 9, 42, 134, 72, 134, 248, 77, 1, 13, 1, 4, 130, 2, 44, 48, 130, 2, 40, 48, 30,
                6, 10, 42, 134, 72, 134, 248, 77, 1, 13, 1, 1, 4, 16, 202, 237, 236, 4, 217, 175,
                217, 87, 194, 223, 45, 176, 252, 52, 131, 111, 48, 130, 1, 101, 6, 10, 42, 134, 72,
                134, 248, 77, 1, 13, 1, 2, 48, 130, 1, 85, 48, 16, 6, 11, 42, 134, 72, 134, 248,
                77, 1, 13, 1, 2, 1, 2, 1, 12, 48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1,
                2, 2, 2, 1, 12, 48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 3, 2, 1, 3,
                48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 4, 2, 1, 3, 48, 17, 6, 11,
                42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 5, 2, 2, 0, 255, 48, 17, 6, 11, 42, 134,
                72, 134, 248, 77, 1, 13, 1, 2, 6, 2, 2, 0, 255, 48, 16, 6, 11, 42, 134, 72, 134,
                248, 77, 1, 13, 1, 2, 7, 2, 1, 1, 48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13,
                1, 2, 8, 2, 1, 0, 48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 9, 2, 1,
                0, 48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 10, 2, 1, 0, 48, 16, 6,
                11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 11, 2, 1, 0, 48, 16, 6, 11, 42, 134,
                72, 134, 248, 77, 1, 13, 1, 2, 12, 2, 1, 0, 48, 16, 6, 11, 42, 134, 72, 134, 248,
                77, 1, 13, 1, 2, 13, 2, 1, 0, 48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1,
                2, 14, 2, 1, 0, 48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 15, 2, 1, 0,
                48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 16, 2, 1, 0, 48, 16, 6, 11,
                42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 17, 2, 1, 13, 48, 31, 6, 11, 42, 134, 72,
                134, 248, 77, 1, 13, 1, 2, 18, 4, 16, 12, 12, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 48, 16, 6, 10, 42, 134, 72, 134, 248, 77, 1, 13, 1, 3, 4, 2, 0, 0, 48, 20,
                6, 10, 42, 134, 72, 134, 248, 77, 1, 13, 1, 4, 4, 6, 0, 96, 106, 0, 0, 0, 48, 15,
                6, 10, 42, 134, 72, 134, 248, 77, 1, 13, 1, 5, 10, 1, 1, 48, 30, 6, 10, 42, 134,
                72, 134, 248, 77, 1, 13, 1, 6, 4, 16, 233, 235, 196, 218, 128, 114, 162, 19, 122,
                255, 74, 240, 3, 137, 157, 250, 48, 68, 6, 10, 42, 134, 72, 134, 248, 77, 1, 13, 1,
                7, 48, 54, 48, 16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 7, 1, 1, 1, 255, 48,
                16, 6, 11, 42, 134, 72, 134, 248, 77, 1, 13, 1, 7, 2, 1, 1, 0, 48, 16, 6, 11, 42,
                134, 72, 134, 248, 77, 1, 13, 1, 7, 3, 1, 1, 0,
            ],
            sig: &[
                71, 238, 2, 195, 135, 123, 26, 59, 33, 28, 112, 165, 207, 210, 219, 139, 22, 73,
                17, 207, 245, 126, 92, 236, 12, 131, 204, 77, 0, 179, 248, 45, 244, 66, 121, 144,
                47, 227, 100, 55, 178, 115, 121, 151, 229, 63, 23, 70, 226, 28, 251, 41, 239, 184,
                9, 132, 159, 180, 160, 35, 29, 54, 110, 244,
            ],
            pubkey: &[
                53, 32, 127, 238, 221, 181, 149, 116, 142, 216, 43, 179, 167, 28, 59, 225, 226, 65,
                239, 97, 50, 12, 104, 22, 230, 181, 194, 183, 29, 173, 85, 50, 234, 234, 18, 164,
                235, 63, 148, 137, 22, 66, 158, 164, 123, 166, 195, 175, 130, 161, 94, 75, 25, 102,
                78, 82, 101, 121, 57, 162, 217, 102, 51, 222,
            ],
        },
        Secp256r1Instance {
            msg: &[
                48, 130, 2, 61, 160, 3, 2, 1, 2, 2, 21, 0, 149, 111, 93, 205, 189, 27, 225, 233,
                64, 73, 201, 212, 244, 51, 206, 1, 87, 11, 222, 84, 48, 10, 6, 8, 42, 134, 72, 206,
                61, 4, 3, 2, 48, 104, 49, 26, 48, 24, 6, 3, 85, 4, 3, 12, 17, 73, 110, 116, 101,
                108, 32, 83, 71, 88, 32, 82, 111, 111, 116, 32, 67, 65, 49, 26, 48, 24, 6, 3, 85,
                4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116,
                105, 111, 110, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32,
                67, 108, 97, 114, 97, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 11, 48, 9,
                6, 3, 85, 4, 6, 19, 2, 85, 83, 48, 30, 23, 13, 49, 56, 48, 53, 50, 49, 49, 48, 53,
                48, 49, 48, 90, 23, 13, 51, 51, 48, 53, 50, 49, 49, 48, 53, 48, 49, 48, 90, 48,
                112, 49, 34, 48, 32, 6, 3, 85, 4, 3, 12, 25, 73, 110, 116, 101, 108, 32, 83, 71,
                88, 32, 80, 67, 75, 32, 80, 108, 97, 116, 102, 111, 114, 109, 32, 67, 65, 49, 26,
                48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112,
                111, 114, 97, 116, 105, 111, 110, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97,
                110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67,
                65, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 48, 89, 48, 19, 6, 7, 42, 134,
                72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 53, 32, 127,
                238, 221, 181, 149, 116, 142, 216, 43, 179, 167, 28, 59, 225, 226, 65, 239, 97, 50,
                12, 104, 22, 230, 181, 194, 183, 29, 173, 85, 50, 234, 234, 18, 164, 235, 63, 148,
                137, 22, 66, 158, 164, 123, 166, 195, 175, 130, 161, 94, 75, 25, 102, 78, 82, 101,
                121, 57, 162, 217, 102, 51, 222, 163, 129, 187, 48, 129, 184, 48, 31, 6, 3, 85, 29,
                35, 4, 24, 48, 22, 128, 20, 34, 101, 12, 214, 90, 157, 52, 137, 243, 131, 180, 149,
                82, 191, 80, 27, 57, 39, 6, 172, 48, 82, 6, 3, 85, 29, 31, 4, 75, 48, 73, 48, 71,
                160, 69, 160, 67, 134, 65, 104, 116, 116, 112, 115, 58, 47, 47, 99, 101, 114, 116,
                105, 102, 105, 99, 97, 116, 101, 115, 46, 116, 114, 117, 115, 116, 101, 100, 115,
                101, 114, 118, 105, 99, 101, 115, 46, 105, 110, 116, 101, 108, 46, 99, 111, 109,
                47, 73, 110, 116, 101, 108, 83, 71, 88, 82, 111, 111, 116, 67, 65, 46, 100, 101,
                114, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 149, 111, 93, 205, 189, 27, 225, 233,
                64, 73, 201, 212, 244, 51, 206, 1, 87, 11, 222, 84, 48, 14, 6, 3, 85, 29, 15, 1, 1,
                255, 4, 4, 3, 2, 1, 6, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1, 255,
                2, 1, 0,
            ],
            sig: &[
                94, 197, 100, 139, 76, 62, 139, 165, 88, 25, 109, 212, 23, 253, 182, 185, 165, 222,
                209, 130, 67, 143, 85, 30, 156, 15, 147, 140, 61, 90, 139, 151, 38, 27, 213, 32,
                38, 15, 156, 100, 125, 53, 105, 190, 142, 20, 163, 40, 146, 99, 26, 195, 88, 185,
                148, 71, 128, 136, 244, 210, 178, 124, 243, 126,
            ],
            pubkey: &[
                11, 169, 196, 192, 192, 200, 97, 147, 163, 254, 35, 214, 176, 44, 218, 16, 168,
                187, 212, 232, 142, 72, 180, 69, 133, 97, 163, 110, 112, 85, 37, 245, 103, 145,
                142, 46, 220, 136, 228, 13, 134, 11, 208, 204, 78, 226, 106, 172, 201, 136, 229, 5,
                169, 83, 85, 140, 69, 63, 107, 9, 4, 174, 115, 148,
            ],
        },
        Secp256r1Instance {
            msg: &[
                48, 130, 2, 52, 160, 3, 2, 1, 2, 2, 20, 34, 101, 12, 214, 90, 157, 52, 137, 243,
                131, 180, 149, 82, 191, 80, 27, 57, 39, 6, 172, 48, 10, 6, 8, 42, 134, 72, 206, 61,
                4, 3, 2, 48, 104, 49, 26, 48, 24, 6, 3, 85, 4, 3, 12, 17, 73, 110, 116, 101, 108,
                32, 83, 71, 88, 32, 82, 111, 111, 116, 32, 67, 65, 49, 26, 48, 24, 6, 3, 85, 4, 10,
                12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111,
                110, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97,
                114, 97, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4,
                6, 19, 2, 85, 83, 48, 30, 23, 13, 49, 56, 48, 53, 50, 49, 49, 48, 52, 53, 49, 48,
                90, 23, 13, 52, 57, 49, 50, 51, 49, 50, 51, 53, 57, 53, 57, 90, 48, 104, 49, 26,
                48, 24, 6, 3, 85, 4, 3, 12, 17, 73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 82,
                111, 111, 116, 32, 67, 65, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116,
                101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 20, 48, 18,
                6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 11, 48,
                9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 48,
                89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7,
                3, 66, 0, 4, 11, 169, 196, 192, 192, 200, 97, 147, 163, 254, 35, 214, 176, 44, 218,
                16, 168, 187, 212, 232, 142, 72, 180, 69, 133, 97, 163, 110, 112, 85, 37, 245, 103,
                145, 142, 46, 220, 136, 228, 13, 134, 11, 208, 204, 78, 226, 106, 172, 201, 136,
                229, 5, 169, 83, 85, 140, 69, 63, 107, 9, 4, 174, 115, 148, 163, 129, 187, 48, 129,
                184, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 34, 101, 12, 214, 90, 157,
                52, 137, 243, 131, 180, 149, 82, 191, 80, 27, 57, 39, 6, 172, 48, 82, 6, 3, 85, 29,
                31, 4, 75, 48, 73, 48, 71, 160, 69, 160, 67, 134, 65, 104, 116, 116, 112, 115, 58,
                47, 47, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 115, 46, 116, 114, 117,
                115, 116, 101, 100, 115, 101, 114, 118, 105, 99, 101, 115, 46, 105, 110, 116, 101,
                108, 46, 99, 111, 109, 47, 73, 110, 116, 101, 108, 83, 71, 88, 82, 111, 111, 116,
                67, 65, 46, 100, 101, 114, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 34, 101, 12,
                214, 90, 157, 52, 137, 243, 131, 180, 149, 82, 191, 80, 27, 57, 39, 6, 172, 48, 14,
                6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 6, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255,
                4, 8, 48, 6, 1, 1, 255, 2, 1, 1,
            ],
            sig: &[
                229, 191, 229, 9, 17, 249, 47, 66, 137, 32, 220, 54, 138, 48, 46, 227, 209, 46,
                197, 134, 127, 246, 34, 236, 100, 151, 247, 128, 96, 193, 60, 32, 224, 157, 37,
                172, 122, 12, 179, 229, 232, 230, 143, 236, 95, 163, 189, 65, 108, 71, 68, 11, 217,
                80, 99, 157, 69, 14, 220, 190, 164, 87, 106, 162,
            ],
            pubkey: &[
                11, 169, 196, 192, 192, 200, 97, 147, 163, 254, 35, 214, 176, 44, 218, 16, 168,
                187, 212, 232, 142, 72, 180, 69, 133, 97, 163, 110, 112, 85, 37, 245, 103, 145,
                142, 46, 220, 136, 228, 13, 134, 11, 208, 204, 78, 226, 106, 172, 201, 136, 229, 5,
                169, 83, 85, 140, 69, 63, 107, 9, 4, 174, 115, 148,
            ],
        },
        Secp256r1Instance {
            msg: &[
                12, 12, 16, 15, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0,
                0, 0, 0, 0, 231, 0, 0, 0, 0, 0, 0, 0, 25, 42, 165, 12, 225, 192, 206, 240, 60, 207,
                137, 231, 181, 177, 107, 13, 121, 120, 245, 194, 177, 237, 207, 119, 77, 135, 112,
                46, 129, 84, 216, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 79, 87, 117, 215, 150, 80, 62, 150, 19,
                127, 119, 198, 138, 130, 154, 0, 86, 172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144,
                197, 123, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 84,
                188, 215, 143, 250, 165, 207, 200, 136, 252, 144, 203, 194, 79, 183, 246, 225, 155,
                200, 102, 22, 113, 241, 227, 178, 204, 148, 125, 179, 182, 52, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            sig: &[
                131, 154, 220, 233, 4, 210, 174, 193, 252, 2, 26, 208, 236, 55, 12, 113, 118, 148,
                45, 75, 100, 147, 155, 149, 162, 225, 225, 211, 224, 155, 242, 229, 112, 147, 35,
                31, 67, 8, 182, 78, 143, 83, 184, 28, 214, 174, 54, 252, 82, 242, 2, 230, 106, 199,
                123, 147, 177, 51, 7, 238, 87, 123, 227, 107,
            ],
            pubkey: &[
                209, 145, 175, 58, 165, 2, 98, 95, 107, 5, 118, 42, 7, 163, 245, 105, 240, 38, 199,
                223, 19, 24, 67, 87, 91, 161, 27, 217, 230, 91, 187, 116, 61, 151, 103, 110, 251,
                63, 150, 12, 107, 92, 21, 27, 85, 96, 166, 60, 33, 40, 56, 133, 240, 133, 94, 172,
                178, 105, 228, 144, 113, 126, 90, 100,
            ],
        },
        Secp256r1Instance {
            msg: &[
                12, 12, 16, 15, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0,
                0, 0, 0, 0, 231, 0, 0, 0, 0, 0, 0, 0, 25, 42, 165, 12, 225, 192, 206, 240, 60, 207,
                137, 231, 181, 177, 107, 13, 121, 120, 245, 194, 177, 237, 207, 119, 77, 135, 112,
                46, 129, 84, 216, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 79, 87, 117, 215, 150, 80, 62, 150, 19,
                127, 119, 198, 138, 130, 154, 0, 86, 172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144,
                197, 123, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 84,
                188, 215, 143, 250, 165, 207, 200, 136, 252, 144, 203, 194, 79, 183, 246, 225, 155,
                200, 102, 22, 113, 241, 227, 178, 204, 148, 125, 179, 182, 52, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            sig: &[
                131, 154, 220, 233, 4, 210, 174, 193, 252, 2, 26, 208, 236, 55, 12, 113, 118, 148,
                45, 75, 100, 147, 155, 149, 162, 225, 225, 211, 224, 155, 242, 229, 112, 147, 35,
                31, 67, 8, 182, 78, 143, 83, 184, 28, 214, 174, 54, 252, 82, 242, 2, 230, 106, 199,
                123, 147, 177, 51, 7, 238, 87, 123, 227, 107,
            ],
            pubkey: &[
                209, 145, 175, 58, 165, 2, 98, 95, 107, 5, 118, 42, 7, 163, 245, 105, 240, 38, 199,
                223, 19, 24, 67, 87, 91, 161, 27, 217, 230, 91, 187, 116, 61, 151, 103, 110, 251,
                63, 150, 12, 107, 92, 21, 27, 85, 96, 166, 60, 33, 40, 56, 133, 240, 133, 94, 172,
                178, 105, 228, 144, 113, 126, 90, 100,
            ],
        },
        Secp256r1Instance {
            msg: &[
                12, 12, 16, 15, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0,
                0, 0, 0, 0, 231, 0, 0, 0, 0, 0, 0, 0, 25, 42, 165, 12, 225, 192, 206, 240, 60, 207,
                137, 231, 181, 177, 107, 13, 121, 120, 245, 194, 177, 237, 207, 119, 77, 135, 112,
                46, 129, 84, 216, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 79, 87, 117, 215, 150, 80, 62, 150, 19,
                127, 119, 198, 138, 130, 154, 0, 86, 172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144,
                197, 123, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 84,
                188, 215, 143, 250, 165, 207, 200, 136, 252, 144, 203, 194, 79, 183, 246, 225, 155,
                200, 102, 22, 113, 241, 227, 178, 204, 148, 125, 179, 182, 52, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            sig: &[
                131, 154, 220, 233, 4, 210, 174, 193, 252, 2, 26, 208, 236, 55, 12, 113, 118, 148,
                45, 75, 100, 147, 155, 149, 162, 225, 225, 211, 224, 155, 242, 229, 112, 147, 35,
                31, 67, 8, 182, 78, 143, 83, 184, 28, 214, 174, 54, 252, 82, 242, 2, 230, 106, 199,
                123, 147, 177, 51, 7, 238, 87, 123, 227, 107,
            ],
            pubkey: &[
                209, 145, 175, 58, 165, 2, 98, 95, 107, 5, 118, 42, 7, 163, 245, 105, 240, 38, 199,
                223, 19, 24, 67, 87, 91, 161, 27, 217, 230, 91, 187, 116, 61, 151, 103, 110, 251,
                63, 150, 12, 107, 92, 21, 27, 85, 96, 166, 60, 33, 40, 56, 133, 240, 133, 94, 172,
                178, 105, 228, 144, 113, 126, 90, 100,
            ],
        },
    ]
}