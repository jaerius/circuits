use halo2_axiom as halo2_proofs;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    arithmetic::FieldExt,
};

#[derive(Clone, Debug)]
pub struct SignatureConfig {
    pub msg: Column<Advice>,
    pub sig: Column<Advice>,
    pub pk: Column<Advice>,
    pub selector: Selector,
}

pub struct SignatureChip<F: FieldExt> {
    config: SignatureConfig,
    _marker: std::marker::PhantomData<F>,
}

impl<F: FieldExt> SignatureChip<F> {
    pub fn construct(config: SignatureConfig) -> Self {
        Self { config, _marker: std::marker::PhantomData }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> SignatureConfig {
        let msg = meta.advice_column();
        let sig = meta.advice_column();
        let pk = meta.advice_column();
        let selector = meta.selector();

        // 실제 signature 검증 constraint는 구현체에 따라 다름(예: ECDSA, Schnorr 등)
        // 아래는 placeholder
        meta.create_gate("signature check", |meta| {
            let s = meta.query_selector(selector);
            let msg = meta.query_advice(msg, halo2_proofs::plonk::Rotation::cur());
            let sig = meta.query_advice(sig, halo2_proofs::plonk::Rotation::cur());
            let pk = meta.query_advice(pk, halo2_proofs::plonk::Rotation::cur());

            // 실제 검증 로직은 별도 gadget에서 구현 필요
            vec![s * (msg + sig + pk)] // placeholder
        });

        SignatureConfig { msg, sig, pk, selector }
    }

    pub fn verify(
        &self,
        layouter: &mut impl Layouter<F>,
        msg: F,
        sig: F,
        pk: F,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "signature verify",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "msg", self.config.msg, 0, || Value::known(msg))?;
                region.assign_advice(|| "sig", self.config.sig, 0, || Value::known(sig))?;
                region.assign_advice(|| "pk", self.config.pk, 0, || Value::known(pk))?;
                Ok(())
            },
        )
    }
}