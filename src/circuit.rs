use halo2_gadgets::ecc::chip::constants::*;
use halo2_proofs::pasta::group::{Curve, Group};
use lazy_static::lazy_static;
use ff::{Field, PrimeField};
use halo2_gadgets::ecc::{FixedPointBaseField, FixedPoints};
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::pasta::{pallas, EpAffine, EqAffine, Fp, Fq};
use halo2_proofs::plonk::{
    self, create_proof, keygen_pk, keygen_vk, verify_proof, BatchVerifier,
    Circuit, ConstraintSystem, Error, SingleVerifier,
};
use halo2_gadgets::ecc::{
        chip::{EccChip, EccConfig},
        NonIdentityPoint, Point, ScalarFixed, ScalarFixedShort, ScalarVar, EccInstructions
        
};
use halo2_gadgets::ecc::FixedPoint as FPoint;
use halo2_gadgets::ecc::chip::{BaseFieldElem, EccPoint, FixedPoint, FullScalar, ShortScalar};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2_proofs::{circuit::*, plonk::*};
use rand_core::OsRng;
use std::time::Instant;
// use pasta_curves::{arithmetic::CurveAffine, pallas};

// use halo2_proofs::dev::MockProver;

mod permissible;
mod select;

use permissible::*;
use select::*;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct TestFixedBases;
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct FullWidth(pallas::Affine, &'static [(u64, [pallas::Base; H])]);
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct BaseField;
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct Short;

lazy_static! {
    static ref BASE: pallas::Affine = pallas::Point::generator().to_affine();
    static ref ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS).unwrap();
    static ref ZS_AND_US_SHORT: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS_SHORT).unwrap();
}

impl FullWidth {
    pub(crate) fn from_pallas_generator() -> Self {
        FullWidth(*BASE, &ZS_AND_US)
    }

    pub(crate) fn from_parts(
        base: pallas::Affine,
        zs_and_us: &'static [(u64, [pallas::Base; H])],
    ) -> Self {
        FullWidth(base, zs_and_us)
    }
}

impl FixedPoint<pallas::Affine> for FullWidth {
    type FixedScalarKind = FullScalar;

    fn generator(&self) -> pallas::Affine {
        self.0
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        self.1
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        self.1.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoint<pallas::Affine> for BaseField {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoint<pallas::Affine> for Short {
    type FixedScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US_SHORT
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US_SHORT.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoints<pallas::Affine> for TestFixedBases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}

/// This represents an advice column at a certain row in the ConstraintSystem
#[derive(Debug, Clone)]
struct MyConfig {
    pub select: SelectConfig,
    pub permisable: PrmsConfig,
    ecc_config: EccConfig<TestFixedBases>,
}

#[derive(Default, Clone, Debug)]
struct MyCircuit {
    pub commits_x: Vec<Value<Fp>>,
    pub commits_y: Vec<Value<Fp>>,
    pub witness: Value<Fp>,
    pub w_sqrt: Value<Fp>,
    pub k: usize,
    pub index: usize,
}

impl Circuit<Fp> for MyCircuit {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        MyChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let config_clone = config.clone();
        let chip = MyChip::construct(config_clone.select, config_clone.permisable);
        chip.assign_select(
            layouter.namespace(|| "select"),
            &self.commits_x,
            &self.witness,
            self.k,
        );

        chip.assign_perm(
            layouter.namespace(|| "permissible"),
            &self.commits_x,
            &self.commits_y,
            &self.w_sqrt,
            self.index,
        );

        let ecc_chip = EccChip::construct(config.ecc_config.clone());
        chip.assign_rerand(layouter, ecc_chip.clone());

        Ok(())
    }
}

struct MyChip {
    select: SelectChip,
    permisable: PrmsChip,
}

impl MyChip {
    fn construct(s_config: SelectConfig, p_config: PrmsConfig) -> Self {
        Self {
            select: SelectChip::construct(s_config),
            permisable: PrmsChip::construct(p_config),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fp>) -> MyConfig {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();
        let select_config = SelectChip::configure(meta, vec![col_a, col_b, col_c]);
        let prms_config = PrmsChip::configure(meta, vec![col_a, col_b, col_d]);

        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        meta.enable_constant(lagrange_coeffs[0]);

        let table_idx = meta.lookup_table_column();
        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        let ecc_config =
        EccChip::<TestFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        MyConfig {
            select: select_config,
            permisable: prms_config,
            ecc_config
        }
    }

    pub fn assign_select(
        &self,
        layouter: impl Layouter<Fp>,
        x: &Vec<Value<Fp>>,
        witness: &Value<Fp>,
        num_rows: usize,
    ) {
        SelectChip::assign(&self.select, layouter, x, witness, num_rows).expect("Select assignment Error");
    }

    pub fn assign_perm(
        &self,
        layouter: impl Layouter<Fp>,
        x: &Vec<Value<Fp>>,
        y: &Vec<Value<Fp>>,
        y_sqrt: &Value<Fp>,
        index: usize,
    ) {
        PrmsChip::assign(&self.permisable, layouter, &x[index], &y[index], y_sqrt).expect("Permisiible assignment Error");
    }

    pub fn assign_rerand<EccChip: EccInstructions<pallas::Affine, Point = EccPoint> + Clone + Eq + std::fmt::Debug>(
        &self,
        mut layouter: impl Layouter<Fp>,
        ecc_chip: EccChip,
    )
    {
        let alpha = ScalarVar::new(
            ecc_chip.clone(), 
            layouter.namespace(|| "alpha"), 
            Value::known(Fq::from(0))
            ).expect("M1");
        let p_val = pallas::Point::random(OsRng).to_affine(); // P
        let p = NonIdentityPoint::new(
            ecc_chip.clone(),
            layouter.namespace(|| "P"),
            Value::known(p_val),
        ).expect("M2");

        let res = p.mul(
            layouter.namespace(|| "mul fixed"), 
            alpha
            ).expect("M3");

        // let fpoint = FPoint::from_inner(ecc_chip.clone(), );
        // let base_point = FixedPointBaseField::from_inner(ecc_chip.clone(), BaseField);
    }
}

fn keygen(k: u32, empty_circuit: MyCircuit) -> (Params<EqAffine>, ProvingKey<EqAffine>) {
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    (params, pk)
}

fn prover(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: MyCircuit,
) -> Vec<u8> {
    let rng = OsRng;
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(params, pk, &[circuit], &[&[]], rng, &mut transcript)
        .expect("proof generation should not fail");
    transcript.finalize()
}

fn verifier(params: &Params<EqAffine>, vk: &VerifyingKey<EqAffine>, proof: &[u8]) {
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    assert!(verify_proof(params, vk, strategy, &[&[]], &mut transcript).is_ok());
}

fn main() {
    let k = 4;
    println!("k = {k}");
    let index = 2;

    let iterations = 1 << k - 1;
    let mut commitments_x: Vec<Value<Fp>> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        // let element = i as u64;
        commitments_x.push(Value::known(Fp::from(5)));
    }

    let mut commitments_y: Vec<Value<Fp>> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let tmp = commitments_x[i].map(|x| {
            let y = (x.square() * x + pallas::Affine::b()).sqrt().unwrap_or(Fp::default());
            // if bool::from(y.is_odd() ^ y_lsb.is_odd()) {
            //     y = -y;
            // }
            y
        });

        commitments_y.push(tmp);
    }

    let witness = commitments_x[index].clone();
    let witness_y = commitments_y[index].clone();
    let w_sqrt: Value<Option<Fp>> = witness_y.map(|v| v.sqrt().into());
    let w_sqrt = w_sqrt.map(|opt_fp| opt_fp.unwrap_or_default());

    let circuit = MyCircuit {
        commits_x: commitments_x,
        commits_y: commitments_y,
        witness: witness,
        w_sqrt: w_sqrt,
        k: iterations,
        index,
    };

    let mut commitments_x: Vec<Value<Fp>> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        commitments_x.push(Value::unknown());
    }

    let mut commitments_y: Vec<Value<Fp>> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        commitments_y.push(Value::unknown());
    }

    let witness = Value::unknown();

    let empty_circuit = MyCircuit {
        commits_x: commitments_x,
        commits_y: commitments_y,
        witness: witness,
        w_sqrt: witness,
        k: iterations,
        index,
    };

    // let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    // prover.assert_satisfied();

    let start_time = Instant::now();
    let (params, pk) = keygen(k, empty_circuit.clone());
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    println!("Elapsed keygen time: {:?}ms", elapsed_time.as_millis());

    let start_time = Instant::now();
    let proof = prover(&params, &pk, circuit);
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    println!("Elapsed prover time: {:?}ms", elapsed_time.as_millis());

    let start_time = Instant::now();
    verifier(&params, pk.get_vk(), &proof);
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    println!("Elapsed verifier time: {:?}ms", elapsed_time.as_millis());

    let mut batch: BatchVerifier<EqAffine> = BatchVerifier::new();
    for _ in 0..8 {
        batch.add_proof(vec![vec![]], proof.clone());
    }

    let start_time = Instant::now();
    assert!(batch.finalize(&params, pk.get_vk()));
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    println!(
        "Elapsed batch verifier time: {:?}ms",
        elapsed_time.as_millis()
    );
}
