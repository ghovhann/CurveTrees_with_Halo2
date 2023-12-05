use ff::Field;
//use halo2_gadgets::utilities::FieldValue;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::pasta::{pallas, EqAffine, Fp};
use halo2_proofs::plonk::{
    Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Fixed, TableColumn,
};
use halo2_proofs::poly::{commitment::Params, Rotation};
use halo2_proofs::{circuit::*, plonk::*};
use std::marker::PhantomData;

/// This represents an advice column at a certain row in the ConstraintSystem
#[derive(Debug, Clone)]
pub struct PrmsConfig {
    pub advice: [Column<Advice>; 3], // add y column for (x,y) and check point on curve, alpha beta from transcript
    pub selector: Selector,
}
pub struct PrmsChip<F: Field> {
    config: PrmsConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> PrmsChip<F> {
    pub fn construct(config: PrmsConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> PrmsConfig {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let selector_1 = meta.selector();

        meta.create_gate("is permissible", |meta| {
            //add alpha beta random numbers
            let s = meta.query_selector(selector_1);
            let c = meta.query_advice(col_c, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            vec![s * (c.clone() * c.clone() - b)]
        });

        meta.create_gate("is point on curve", |meta| {
            let s = meta.query_selector(selector_1);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());

            let on_curve =
                b.square() - a.clone().square() * a - Expression::Constant(pallas::Affine::b());

            vec![s * on_curve]
        });

        PrmsConfig {
            advice: ([col_a, col_b, col_c]),
            selector: (selector_1),
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        x: &Value<F>,
        y: &Value<F>,
        y_sqrt: &Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "permissible",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                region.assign_advice(|| "a", self.config.advice[0], 0, || *x)?;

                region.assign_advice(|| "b", self.config.advice[1], 0, || *y)?;

                let y_sqrt: Value<Option<F>> = y.map(|v| v.sqrt().into());
                let mut c_val: Value<F>;

                if let Some(sqrt_value) = y_sqrt.into() {
                    c_val = Value::from(sqrt_value);
                } else {
                    Err(Error::Synthesis);
                }

                let c_cell =
                    region.assign_advice(|| "sqrt(y)", self.config.advice[2], 0, || c_val)?;

                return Ok(c_cell);
            },
        )
    }
}
