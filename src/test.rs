use std::marker::PhantomData;
use halo2_proofs::{circuit::*, plonk::*};
use halo2_proofs::poly::{commitment::Params, Rotation};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand_core::OsRng;
use std::time::{Instant};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned, BatchVerifier, Circuit,
    Column, ConstraintSystem, Error, Fixed, SingleVerifier, TableColumn, VerificationStrategy,
};
use ff::Field;


/// This represents an advice column at a certain row in the ConstraintSystem
#[derive(Debug, Clone)]
struct MyConfig{
    pub advice: [Column<Advice>; 3],
    pub selector: [Selector; 2],
    // pub constant: Column<Fixed>
}

#[derive(Default, Clone, Debug)]
struct MyCircuit<F> {
    pub commits: Vec<Value<F>>,
    pub witness: Value<F>,
    pub k: usize
}

struct MyChip<F:Field> {
    config: MyConfig,
    _marker: PhantomData<F>,
}

impl<F:Field> MyChip<F> {
    fn construct(config: MyConfig) -> Self {
        Self{config, _marker: PhantomData}
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> MyConfig {

        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let selector_1 = meta.selector();
        let selector_2 = meta.selector();
        let constant = meta.fixed_column();

        meta.enable_equality(col_c);
        meta.enable_constant(constant);

        meta.create_gate("subtract", |meta|{
            let s = meta.query_selector(selector_1);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s*(a - b - c)]
        });

        meta.create_gate("running product", |meta|{
            let s = meta.query_selector(selector_2);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let c_prev = meta.query_advice(col_c, Rotation::prev());
            let sub = a - b;
            vec![s*(c_prev*sub - c)]
        });

        meta.create_gate("constant column", |meta|{
            let s = meta.query_selector(selector_2);
            let b = meta.query_advice(col_b, Rotation::cur());
            let b_prev = meta.query_advice(col_b, Rotation::prev());
            vec![s*(b_prev - b)]
        });

        MyConfig { advice: ([col_a, col_b, col_c]), selector: ([selector_1, selector_2])}
    }

    fn assign(&self, mut layouter: impl Layouter<F>, commit: &Vec<Value<F>>, witness: &Value<F>, num_rows: usize) 
    -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "select",
            |mut region| {

                    let mut c_cell: AssignedCell<F, F>; 

                    self.config.selector[0].enable(&mut region, 0)?;

                    region.assign_advice(
                        || "a",
                        self.config.advice[0],
                        0,
                        || commit[0]
                    )?;

                    region.assign_advice(
                        || "b",
                        self.config.advice[1],
                        0,
                        || *witness
                    )?;
                    let c_val = commit[0].and_then(|commit| witness.map(|witness| commit - witness));
                    c_cell = region.assign_advice(
                        || "a-b",
                        self.config.advice[2],
                        0,
                        || c_val
                    )?;

                    for row in 1..num_rows
                    {
                        self.config.selector[1].enable(&mut region, row)?;

                        region.assign_advice(
                            || "a",
                            self.config.advice[0],
                            row,
                            || commit[row]
                        )?;

                        region.assign_advice(
                            || "b",
                            self.config.advice[1],
                            row,
                            || *witness
                        )?;

                        let sub = commit[row].and_then(|c| witness.map(|w| c - w));
                        
                        let c_val = c_cell.value().and_then(|d| sub.map(|c| *d * c));

                        c_cell = region.assign_advice(
                            || "product",
                            self.config.advice[2],
                            row,
                            || c_val,
                        )?;
                    }
                    
                    region.constrain_constant (c_cell.cell(), F::ZERO)?;

                    return Ok(c_cell)
            },
        )
    }

}

impl<F:Field> Circuit<F> for MyCircuit<F> {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MyChip::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = MyChip::construct(config);
        chip.assign(layouter.namespace(|| "select"), &self.commits, &self.witness, self.k)?;

        Ok(())
    }
}

fn keygen(k: u32, empty_circuit: MyCircuit<Fp>) -> (Params<EqAffine>, ProvingKey<EqAffine>) {
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    (params, pk)
}

fn prover(k: u32, params: &Params<EqAffine>, pk: &ProvingKey<EqAffine>, circuit: MyCircuit<Fp>) -> Vec<u8> {
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

fn main()
{
    let k = 9;
    println!("k = {k}");

    let iterations = 1 << k-1; 
    let mut commitments: Vec<Value<Fp>> = Vec::with_capacity(iterations);


    for i in 0..iterations {
        let element = i as u64;
        commitments.push(Value::known(Fp::from(element)));

    }

    let witness = commitments[2].clone();

    let circuit = MyCircuit{
        commits: commitments,
        witness,
        k: iterations
    };

    let mut commitments: Vec<Value<Fp>> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        commitments.push(Value::unknown());

    }

    let witness = Value::unknown();

    let empty_circuit = MyCircuit{
        commits: commitments,
        witness,
        k: iterations
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
}