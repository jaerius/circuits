use halo2_axiom as halo2_proofs;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    arithmetic::FieldExt,
};

#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    pub value: Column<Advice>,
    pub min: Column<Advice>,
    pub max: Column<Advice>,
    pub selector: Selector,
}

pub struct RangeCheckChip<F: FieldExt> {
    config: RangeCheckConfig,
    _marker: std::marker::PhantomData<F>,
}


impl<F: FieldExt> RangeCheckChip<F> {
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
            let value = meta.query_advice(value, halo2_proofs::plonk::Rotation::cur());
            let min = meta.query_advice(min, halo2_proofs::plonk::Rotation::cur());
            let max = meta.query_advice(max, halo2_proofs::plonk::Rotation::cur());

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