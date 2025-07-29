use halo2::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
   
};
use halo2curves::ff::{Field, PrimeField};
use halo2::poly::Rotation;
use integer::IntegerInstructions;

#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    pub value: Column<Advice>,
    pub min: Column<Advice>,
    pub max: Column<Advice>,
    pub selector: Selector,
}

pub struct RangeCheckChip<F: Field> {
    config: RangeCheckConfig,
    _marker: std::marker::PhantomData<F>,
}


impl<F: Field> RangeCheckChip<F> {
    pub fn construct(config: RangeCheckConfig) -> Self {
        Self { config, _marker: std::marker::PhantomData }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> RangeCheckConfig {
        let value = meta.advice_column();
        let min = meta.advice_column();
        let max = meta.advice_column();
        let selector = meta.selector();

        meta.create_gate("range check", |meta| {
            let s = meta.query_selector(selector);
            let value = meta.query_advice(value, Rotation::cur());
            let min = meta.query_advice(min, Rotation::cur());
            let max = meta.query_advice(max, Rotation::cur());

            vec![
                s.clone() * (value.clone() - min.clone()), // value >= min
                s * (max - value),                         // value <= max
            ]
        });

        RangeCheckConfig { value, min, max, selector }
    }

    pub fn range_check(
        &self,
        layouter: &mut impl Layouter<F>,
        value: F,
        min: F,
        max: F,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "range check",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "value", self.config.value, 0, || Value::known(value))?;
                region.assign_advice(|| "min", self.config.min, 0, || Value::known(min))?;
                region.assign_advice(|| "max", self.config.max, 0, || Value::known(max))?;
                Ok(())
            },
        )
    }
}