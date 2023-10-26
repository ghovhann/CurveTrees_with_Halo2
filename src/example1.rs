// use std::marker::PhantomData;
// use halo2_proofs::{arithmetic::{FieldExt, Field}, circuit::*, plonk::*, poly::Rotation, dev::MockProver, pasta::Fp};
// use std::time::{Instant};

// #[derive(Debug, Clone)]
// struct MyConfig{
//     pub advice: [Column<Advice>; 3],
//     pub selector: [Selector; 2],
//     pub instance: Column<Instance>,
// }

// struct MyChip<F:FieldExt> {
//     config: MyConfig,
//     _marker: PhantomData<F>,
// }

// impl<F:FieldExt> MyChip<F> {
//     fn construct(config: MyConfig) -> Self {
//         Self{config, _marker: PhantomData}
//     }

//     fn configure(meta: &mut ConstraintSystem<F>, instance: Column<Instance>) -> MyConfig {

//         let col_a = meta.advice_column();
//         let col_b = meta.advice_column();
//         let col_c = meta.advice_column();
//         let selector_1 = meta.selector();
//         let selector_2 = meta.selector();

//         meta.enable_equality(col_c);
//         meta.enable_equality(instance);

//         meta.create_gate("subtract", |meta|{
//             let s = meta.query_selector(selector_1);
//             let a = meta.query_advice(col_a, Rotation::cur());
//             let b = meta.query_advice(col_b, Rotation::cur());
//             let c = meta.query_advice(col_c, Rotation::cur());
//             vec![s*(a - b - c)]
//         });

//         meta.create_gate("running product", |meta|{
//             let s = meta.query_selector(selector_2);
//             let a = meta.query_advice(col_a, Rotation::cur());
//             let b = meta.query_advice(col_b, Rotation::cur());
//             let c = meta.query_advice(col_c, Rotation::cur());
//             let c_prev = meta.query_advice(col_c, Rotation::prev());
//             let sub = a - b;
//             vec![s*(c_prev*sub - c)]
//         });

//         meta.create_gate("constant column", |meta|{
//             let s = meta.query_selector(selector_2);
//             let b = meta.query_advice(col_b, Rotation::cur());
//             let b_prev = meta.query_advice(col_b, Rotation::prev());
//             vec![s*(b_prev - b)]
//         });

//         MyConfig { advice: ([col_a, col_b, col_c]), selector: ([selector_1, selector_2]), instance }
//     }

//     fn assign(&self, mut layouter: impl Layouter<F>, commit: &Vec<Option<F>>, witness: &Option<F>, num_rows: usize)
//     -> Result<AssignedCell<F, F>, Error> {
//         layouter.assign_region(
//             || "select",
//             |mut region| {

//                 let mut c_cell: AssignedCell<F, F>;

//                 self.config.selector[0].enable(&mut region, 0)?;

//                 region.assign_advice(
//                     || "a",
//                     self.config.advice[0],
//                     0,
//                     || commit[0].ok_or(Error::Synthesis)
//                 )?;

//                 region.assign_advice(
//                     || "b",
//                     self.config.advice[1],
//                     0,
//                     || witness.ok_or(Error::Synthesis),
//                 )?;
//                 let c_val = commit[0].and_then(|commit| witness.map(|witness| commit - witness));
//                 c_cell = region.assign_advice(
//                     || "a-b",
//                     self.config.advice[2],
//                     0,
//                     || c_val.ok_or(Error::Synthesis),
//                 )?;

//                 for row in 1..num_rows
//                 {
//                     self.config.selector[1].enable(&mut region, row)?;

//                     region.assign_advice(
//                         || "a",
//                         self.config.advice[0],
//                         row,
//                         || commit[row].ok_or(Error::Synthesis),
//                     )?;

//                     region.assign_advice(
//                         || "b",
//                         self.config.advice[1],
//                         row,
//                         || witness.ok_or(Error::Synthesis),
//                     )?;

//                     let sub = commit[row].and_then(|c| witness.map(|w| c - w));

//                     let c_val = c_cell.value().and_then(|d| sub.map(|c| *d * c));

//                     c_cell = region.assign_advice(
//                         || "product",
//                         self.config.advice[2],
//                         row,
//                         || c_val.ok_or(Error::Synthesis),
//                     )?;
//                 }

//                 Ok(c_cell)
//             },
//         )
//     }

//     pub fn expose_public(
//         &self,
//         mut layouter: impl Layouter<F>,
//         cell: AssignedCell<F, F>,
//         row: usize,
//     ) -> Result<(), Error> {
//         layouter.constrain_instance(cell.cell(), self.config.instance, row)
//     }
// }

// #[derive(Default)]
// struct MyCircuit<F> {
//     pub commits: Vec<Option<F>>,
//     pub witness: Option<F>,
// }

// impl<F:FieldExt> Circuit<F> for MyCircuit<F> {
//     type Config = MyConfig;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         Self::default()
//     }

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         let instance = meta.instance_column();
//         MyChip::configure(meta, instance)
//     }

//     fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
//         let chip = MyChip::construct(config);
//         let iterations = 1 << 20;
//         let c_cell = chip.assign(layouter.namespace(|| "select"), &self.commits, &self.witness, iterations)?;

//         chip.expose_public(layouter.namespace(|| "zero check"), c_cell, 0)?;

//         Ok(())
//     }
// }
// fn main() {
//     let k = 21;

//     let iterations = 1 << k-1;
//     let mut commitments: Vec<Option<Fp>> = Vec::with_capacity(iterations);

//     for i in 0..iterations {
//         // Your loop body code here
//         let element = i as u64;
//         commitments.push(Some(Fp::from(element)));

//     }

//     let witness = commitments[30].clone();

//     let circuit = MyCircuit{
//         commits: commitments,
//         witness: witness,
//     };

//     let public_input = vec![Fp::from(0)];

//     let start_time = Instant::now();
//     let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
//     let end_time = Instant::now();
//     let elapsed_time = end_time.duration_since(start_time);
//     println!("Elapsed prover time: {:?}ms", elapsed_time.as_millis());

//     let start_time = Instant::now();
//     prover.assert_satisfied();
//     let end_time = Instant::now();
//     let elapsed_time = end_time.duration_since(start_time);
//     println!("Elapsed verifier time: {:?}ms", elapsed_time.as_millis());
// }

#[macro_use]
extern crate criterion;

use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::poly::{commitment::Params, Rotation};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::*,
    plonk::*,
};
use rand_core::OsRng;
use std::marker::PhantomData;

use criterion::{BenchmarkId, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    /// This represents an advice column at a certain row in the ConstraintSystem
    #[derive(Debug, Clone)]
    struct MyConfig {
        pub advice: [Column<Advice>; 3],
        pub selector: [Selector; 2],
        pub instance: Column<Instance>,
    }

    #[derive(Default, Clone, Debug)]
    struct MyCircuit<F> {
        pub commits: Vec<Option<F>>,
        pub witness: Option<F>,
        pub k: usize,
    }

    struct MyChip<F: FieldExt> {
        config: MyConfig,
        _marker: PhantomData<F>,
    }

    impl<F: FieldExt> MyChip<F> {
        fn construct(config: MyConfig) -> Self {
            Self {
                config,
                _marker: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>, instance: Column<Instance>) -> MyConfig {
            let col_a = meta.advice_column();
            let col_b = meta.advice_column();
            let col_c = meta.advice_column();
            let selector_1 = meta.selector();
            let selector_2 = meta.selector();

            meta.enable_equality(col_c);
            meta.enable_equality(instance);

            meta.create_gate("subtract", |meta| {
                let s = meta.query_selector(selector_1);
                let a = meta.query_advice(col_a, Rotation::cur());
                let b = meta.query_advice(col_b, Rotation::cur());
                let c = meta.query_advice(col_c, Rotation::cur());
                vec![s * (a - b - c)]
            });

            meta.create_gate("running product", |meta| {
                let s = meta.query_selector(selector_2);
                let a = meta.query_advice(col_a, Rotation::cur());
                let b = meta.query_advice(col_b, Rotation::cur());
                let c = meta.query_advice(col_c, Rotation::cur());
                let c_prev = meta.query_advice(col_c, Rotation::prev());
                let sub = a - b;
                vec![s * (c_prev * sub - c)]
            });

            meta.create_gate("constant column", |meta| {
                let s = meta.query_selector(selector_2);
                let b = meta.query_advice(col_b, Rotation::cur());
                let b_prev = meta.query_advice(col_b, Rotation::prev());
                vec![s * (b_prev - b)]
            });

            MyConfig {
                advice: ([col_a, col_b, col_c]),
                selector: ([selector_1, selector_2]),
                instance,
            }
        }

        fn assign(
            &self,
            mut layouter: impl Layouter<F>,
            commit: &Vec<Option<F>>,
            witness: &Option<F>,
            num_rows: usize,
        ) -> Result<AssignedCell<F, F>, Error> {
            layouter.assign_region(
                || "select",
                |mut region| {
                    println!("Inside select assignment\n");

                    let mut c_cell: AssignedCell<F, F>;

                    self.config.selector[0].enable(&mut region, 0)?;

                    region.assign_advice(
                        || "a",
                        self.config.advice[0],
                        0,
                        || commit[0].ok_or(Error::Synthesis),
                    )?;

                    region.assign_advice(
                        || "b",
                        self.config.advice[1],
                        0,
                        || witness.ok_or(Error::Synthesis),
                    )?;
                    let c_val =
                        commit[0].and_then(|commit| witness.map(|witness| commit - witness));
                    c_cell = region.assign_advice(
                        || "a-b",
                        self.config.advice[2],
                        0,
                        || c_val.ok_or(Error::Synthesis),
                    )?;

                    for row in 1..num_rows {
                        self.config.selector[1].enable(&mut region, row)?;

                        region.assign_advice(
                            || "a",
                            self.config.advice[0],
                            row,
                            || commit[row].ok_or(Error::Synthesis),
                        )?;

                        region.assign_advice(
                            || "b",
                            self.config.advice[1],
                            row,
                            || witness.ok_or(Error::Synthesis),
                        )?;

                        let sub = commit[row].and_then(|c| witness.map(|w| c - w));

                        let c_val = c_cell.value().and_then(|d| sub.map(|c| *d * c));

                        c_cell = region.assign_advice(
                            || "product",
                            self.config.advice[2],
                            row,
                            || c_val.ok_or(Error::Synthesis),
                        )?;
                    }

                    return Ok(c_cell);
                },
            )
        }

        pub fn expose_public(
            &self,
            mut layouter: impl Layouter<F>,
            cell: AssignedCell<F, F>,
            row: usize,
        ) -> Result<(), Error> {
            layouter.constrain_instance(cell.cell(), self.config.instance, row)
        }
    }

    impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
        type Config = MyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                commits: vec![None],
                witness: None,
                k: 0,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let instance = meta.instance_column();
            MyChip::configure(meta, instance)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = MyChip::construct(config);
            let c_cell = chip.assign(
                layouter.namespace(|| "select"),
                &self.commits,
                &self.witness,
                self.k,
            )?;

            chip.expose_public(layouter.namespace(|| "zero check"), c_cell, 0)?;

            Ok(())
        }
    }

    fn keygen(k: u32) -> (Params<EqAffine>, ProvingKey<EqAffine>) {
        let params: Params<EqAffine> = Params::new(k);
        let empty_circuit: MyCircuit<Fp> = MyCircuit {
            commits: vec![None],
            witness: None,
            k: 0,
        };
        println!("Before keygen");
        println!("empty circuit {:?}", empty_circuit);
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
        (params, pk)
    }

    fn prover(k: u32, params: &Params<EqAffine>, pk: &ProvingKey<EqAffine>) -> Vec<u8> {
        let rng = OsRng;

        let k = 21;

        let iterations = 1 << k - 1;
        let mut commitments: Vec<Option<Fp>> = Vec::with_capacity(iterations);

        for i in 0..iterations {
            // Your loop body code here
            let element = i as u64;
            commitments.push(Some(Fp::from(element)));
        }

        let witness = commitments[30].clone();

        let rows: usize = 1 << k - 1;
        let circuit = MyCircuit {
            commits: commitments,
            witness: witness,
            k: rows,
        };

        // let public_input = vec![Fp::from(0)];
        // let public_input = vec![public_input.clone()];
        // let data_ref: &[&[&[Fp]]] = public_input.iter().map(|row| row.iter().map(|item| item).collect()).collect();
        let value: Fp = Fp::from(0);

        // Create a reference with a slice of a single value
        let data_ref: &[&[&[Fp]]] = &[&[&[value]]];

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(params, pk, &[circuit], data_ref, rng, &mut transcript)
            .expect("proof generation should not fail");
        transcript.finalize()
    }

    fn verifier(params: &Params<EqAffine>, vk: &VerifyingKey<EqAffine>, proof: &[u8]) {
        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
        assert!(verify_proof(params, vk, strategy, &[&[]], &mut transcript).is_ok());
    }

    let k_range = 8..=16;

    let mut keygen_group = c.benchmark_group("plonk-keygen");
    keygen_group.sample_size(10);
    for k in k_range.clone() {
        keygen_group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, &k| {
            b.iter(|| keygen(k));
        });
    }
    keygen_group.finish();

    let mut prover_group = c.benchmark_group("plonk-prover");
    prover_group.sample_size(10);
    for k in k_range.clone() {
        let (params, pk) = keygen(k);

        prover_group.bench_with_input(
            BenchmarkId::from_parameter(k),
            &(k, &params, &pk),
            |b, &(k, params, pk)| {
                b.iter(|| prover(k, params, pk));
            },
        );
    }
    prover_group.finish();

    let mut verifier_group = c.benchmark_group("plonk-verifier");
    for k in k_range {
        let (params, pk) = keygen(k);
        let proof = prover(k, &params, &pk);

        verifier_group.bench_with_input(
            BenchmarkId::from_parameter(k),
            &(&params, pk.get_vk(), &proof[..]),
            |b, &(params, vk, proof)| {
                b.iter(|| verifier(params, vk, proof));
            },
        );
    }
    verifier_group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
