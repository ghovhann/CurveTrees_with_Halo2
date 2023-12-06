use ff::Field;
//use halo2_gadgets::utilities::FieldValue;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned, BatchVerifier, Circuit,
    Column, ConstraintSystem, Error, Fixed, SingleVerifier, TableColumn, VerificationStrategy,
};
use halo2_proofs::poly::{commitment::Params, Rotation};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2_proofs::{circuit::*, plonk::*};
use rand_core::OsRng;
use std::marker::PhantomData;
use std::time::Instant;

mod permissible;
mod select;

use permissible::*;
use select::*;

/// This represents an advice column at a certain row in the ConstraintSystem
#[derive(Debug, Clone)]
struct MyConfig {
    pub select: SelectConfig,
    pub permisable: PrmsConfig,
}

#[derive(Default, Clone, Debug)]
struct MyCircuit<F> {
    pub commits: Vec<Value<F>>,
    pub witness: Value<F>,
    pub w_sqrt: Value<F>,
    pub k: usize,
}

impl<F: Field> Circuit<F> for MyCircuit<F> {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MyChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = MyChip::construct(config);
        chip.assign(
            layouter.namespace(|| "select"),
            &self.commits,
            &self.witness,
            &self.w_sqrt,
            self.k,
        )?;

        Ok(())
    }
}

struct MyChip<F: Field> {
    config: MyConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> MyChip<F> {
    fn construct(config: MyConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> MyConfig {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();
        let select_config = SelectChip::configure(meta, col_a, col_b, col_c);
        let prms_config = PrmsChip::configure(meta, col_a, col_b, col_d);

        MyConfig {
            select: select_config,
            permisable: prms_config,
        }
    }
}

fn keygen(k: u32, empty_circuit: MyCircuit<Fp>) -> (Params<EqAffine>, ProvingKey<EqAffine>) {
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    (params, pk)
}

fn prover(
    k: u32,
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: MyCircuit<Fp>,
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
    // match verify_proof(params, vk, strategy, &[&[]], &mut transcript) {
    //     Ok(_) => {
    //         println!("Verification passed");
    //     }
    //     Err(err) => {
    //         println!(" {:?} ", err);
    //     }
    // }
}

fn main() {
    let k = 9;
    println!("k = {k}");

    let iterations = 1 << k - 1;
    let mut commitments: Vec<Value<Fp>> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let element = i as u64;
        commitments.push(Value::known(Fp::from(element)));
    }

    let witness = commitments[2].clone();
    let w_sqrt: Value<Option<Fp>> = witness.map(|v| v.sqrt().into());
    let w_sqrt = w_sqrt.map(|opt_fp| opt_fp.unwrap_or_default());
    // let w_sqrt = Value::known(Fp::from(5));

    let circuit = MyCircuit {
        commits: commitments,
        witness: witness,
        w_sqrt: w_sqrt,
        k: iterations,
    };

    let mut commitments: Vec<Value<Fp>> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        commitments.push(Value::unknown());
    }

    let witness = Value::unknown();

    let empty_circuit = MyCircuit {
        commits: commitments,
        witness: witness,
        w_sqrt: witness,
        k: iterations,
    };

    let start_time = Instant::now();
    let (params, pk) = keygen(k, empty_circuit.clone());
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);
    println!("Elapsed keygen time: {:?}ms", elapsed_time.as_millis());

    let start_time = Instant::now();
    let proof = prover(k, &params, &pk, circuit);
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
