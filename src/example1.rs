use std::marker::PhantomData;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation, dev::MockProver, pasta::Fp};


#[derive(Debug, Clone)]
struct MyConfig{
    pub advice: [Column<Advice>; 3],
    pub selector: [Selector; 2],
}

struct MyChip<F:FieldExt> {
    config: MyConfig,
    _marker: PhantomData<F>,
}

impl<F:FieldExt> MyChip<F> {
    fn construct(config: MyConfig) -> Self {
        Self{config, _marker: PhantomData}
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> MyConfig {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let selector_1 = meta.selector();
        let selector_2 = meta.selector();

        meta.enable_equality(col_c);

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

        MyConfig { advice: ([col_a, col_b, col_c]), selector: ([selector_1, selector_2]) }
    }

    fn assign_first_row(&self, mut layouter: impl Layouter<F>, commit: &Option<F>, witness: &Option<F>) 
    -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "select first row",
            |mut region| {
                self.config.selector[0].enable(&mut region, 0)?;

                region.assign_advice(
                    || "a",
                    self.config.advice[0],
                    0,
                    || commit.ok_or(Error::Synthesis)
                )?;

                region.assign_advice(
                    || "b",
                    self.config.advice[1],
                    0,
                    || witness.ok_or(Error::Synthesis),
                )?;
                let c_val = commit.and_then(|commit| witness.map(|witness| commit - witness));
                let c_cell = region.assign_advice(
                    || "a-b",
                    self.config.advice[2],
                    0,
                    || c_val.ok_or(Error::Synthesis),
                )?;

                Ok(c_cell)
            },
        )
    }

    fn assign_next_row(&self, mut layouter: impl Layouter<F>, commit: &Vec<Option<F>>, witness: &Option<F>, prev_d: &AssignedCell<F, F>) 
    -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "select other rows",
            |mut region| {
                // self.config.selector[0].enable(&mut region, 0)?;
                let mut c_cell: AssignedCell<F, F> = prev_d.clone(); 
                for row in 1..8
                {
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
                    
                    let c_val = prev_d.value().and_then(|d| sub.map(|c| *d * c));

                    c_cell = region.assign_advice(
                        || "product",
                        self.config.advice[2],
                        row,
                        || c_val.ok_or(Error::Synthesis),
                    )?;
                }

                Ok(c_cell)
            },
        )
    }

    // pub fn expose_public(
    //     &self,
    //     mut layouter: impl Layouter<F>,
    //     cell: &AssignedCell<F, F>,
    //     row: usize,
    // ) -> Result<(), Error> {
    //     layouter.constrain_constant(cell.cell(), F::ZERO)
    // }
}

#[derive(Default)]
struct MyCircuit<F> {
    pub commits: Vec<Option<F>>,
    pub witness: Option<F>,
}

impl<F:FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MyChip::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = MyChip::construct(config);
        let prev_c = chip.assign_first_row(layouter.namespace(|| "select first row"), &self.commits[0], &self.witness)?;

        let c_cell = chip.assign_next_row(layouter.namespace(|| "select next rows"), &self.commits, &self.witness, &prev_c)?;

        // chip.expose_public(layouter.namespace(|| "out"), &prev_d, 8)?;
    
        Ok(())
    }
}
fn main() {
    let k = 4;

    let commitments: Vec<Option<Fp>> = vec![Some(Fp::from(1)), Some(Fp::from(2)), Some(Fp::from(3)), Some(Fp::from(4)), Some(Fp::from(5)), Some(Fp::from(6)), Some(Fp::from(7)), Some(Fp::from(8))];
    let witness = Some(Fp::from(5));
    let circuit = MyCircuit{
        commits: commitments,
        witness: witness,
    };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();

    // let _prover = MockProver::run(k, &circuit, vec![]).unwrap();
}
