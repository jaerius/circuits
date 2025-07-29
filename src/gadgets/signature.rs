use halo2curves::ff::PrimeField;
use halo2::plonk::{ConstraintSystem, Error};
use halo2::circuit::{Layouter, Value};
use ecdsa::ecdsa::{
    EcdsaChip, EcdsaConfig, AssignedEcdsaSig, AssignedPublicKey,
};
use ecc::{GeneralEccChip, EccConfig};
use integer::rns::Integer;
use integer::{AssignedInteger, IntegerConfig, IntegerInstructions};
use maingate::{MainGate, RangeChip};
use ecc::maingate::RegionCtx;
use integer::Range;
use integer::UnassignedInteger;



/// SignatureConfig: ECDSA gadget의 config를 그대로 사용
pub type SignatureConfig = EcdsaConfig;

/// SignatureChip: 내부적으로 halo2wrong의 EcdsaChip을 래핑
pub struct SignatureChip<E: halo2curves::CurveAffine, F: PrimeField, const LIMBS: usize, const BITS: usize> {
    chip: EcdsaChip<E, F, LIMBS, BITS>,
}

impl<E: halo2curves::CurveAffine, F: PrimeField, const LIMBS: usize, const BITS: usize> SignatureChip<E, F, LIMBS, BITS> {
    pub fn new(chip: EcdsaChip<E, F, LIMBS, BITS>) -> Self {
        Self { chip }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> SignatureConfig {
        // MainGateConfig, RangeConfig 등은 회로에서 생성해서 넘겨줘야 함
        let main_gate_config = MainGate::configure(meta);
        let range_config = RangeChip::configure(meta, &main_gate_config, vec![BITS / LIMBS], vec![]);
        SignatureConfig::new(range_config, main_gate_config)
    }

     // Proxy methods for assignment
     pub fn assign_signature(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        sig: (E::Scalar, E::Scalar),
    ) -> Result<AssignedEcdsaSig<E::Scalar, F, LIMBS, BITS>, Error> {
        let scalar_chip = self.chip.scalar_field_chip();
        let rns = scalar_chip.rns(); // 또는 self.chip.range(), config.range 등 회로 구조에 맞게
        let r = scalar_chip.assign_integer(ctx,  UnassignedInteger::from(Value::known(Integer::from_fe(sig.0, rns.clone()))), Range::Operand)?;
        let s = scalar_chip.assign_integer(ctx,  UnassignedInteger::from(Value::known(Integer::from_fe(sig.1, rns.clone()))), Range::Operand)?;
        Ok(AssignedEcdsaSig { r, s })
    }

    pub fn assign_public_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        pk: (E::Base, E::Base),
    ) -> Result<AssignedPublicKey<E::Base, F, LIMBS, BITS>, Error> {
        let base_chip = self.chip.0.ecc_chip().base_field_chip();
        let rns = base_chip.rns();
        let x = base_chip.assign_integer(ctx, Value::known(Integer::from_fe(pk.0, rns.clone())))?;
        let y = base_chip.assign_integer(ctx, Value::known(Integer::from_fe(pk.1, rns.clone())))?;
        let point = self.chip.0.ecc_chip().assign_point_from_coords(ctx, x, y)?;
        Ok(AssignedPublicKey { point })
    }

    pub fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        value: F,
    ) -> Result<AssignedInteger<E::Scalar, F, LIMBS, BITS>, Error> {
        let scalar_chip = self.chip.scalar_field_chip();
        let range = scalar_chip.range_chip(); // 또는 self.chip.range(), config.range 등
        scalar_chip.assign_integer(ctx, UnassignedInteger::from(value), Range::Operand)
    }

    pub fn verify(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        sig: &AssignedEcdsaSig<E::Scalar, F, LIMBS, BITS>,
        pk: &AssignedPublicKey<E::Base, F, LIMBS, BITS>,
        msg_hash: &AssignedInteger<E::Scalar, F, LIMBS, BITS>,
    ) -> Result<(), Error> {
        self.chip.verify(ctx, sig, pk, msg_hash)
    }
}


// use halo2_proofs::{
//     circuit::{Layouter, Value},
//     plonk::{Advice, Column, ConstraintSystem, Error, Selector},
// };
// use halo2curves::ff::{Field, PrimeField};
// use halo2_proofs::poly::Rotation;

// #[derive(Clone, Debug)]
// pub struct SignatureConfig {
//     pub msg: Column<Advice>,
//     pub sig: Column<Advice>,
//     pub pk: Column<Advice>,
//     pub selector: Selector,
// }

// pub struct SignatureChip<F: Field> {
//     config: SignatureConfig,
//     _marker: std::marker::PhantomData<F>,
// }

// impl<F: Field> SignatureChip<F> {
//     pub fn construct(config: SignatureConfig) -> Self {
//         Self { config, _marker: std::marker::PhantomData }
//     }

//     pub fn configure(meta: &mut ConstraintSystem<F>) -> SignatureConfig {
//         let msg = meta.advice_column();
//         let sig = meta.advice_column();
//         let pk = meta.advice_column();
//         let selector = meta.selector();

//         // 실제 signature 검증 constraint는 구현체에 따라 다름(예: ECDSA, Schnorr 등)
//         // 아래는 placeholder
//         meta.create_gate("signature check", |meta| {
//             let s = meta.query_selector(selector);
//             let msg = meta.query_advice(msg, Rotation::cur());
//             let sig = meta.query_advice(sig, Rotation::cur());
//             let pk = meta.query_advice(pk, Rotation::cur());

//             // 실제 검증 로직은 별도 gadget에서 구현 필요
//             vec![s * (msg + sig + pk)] // placeholder
//         });

//         SignatureConfig { msg, sig, pk, selector }
//     }

//     pub fn verify(
//         &self,
//         layouter: &mut impl Layouter<F>,
//         msg: F,
//         sig: F,
//         pk: F,
//     ) -> Result<(), Error> {
//         layouter.assign_region(
//             || "signature verify",
//             |mut region| {
//                 self.config.selector.enable(&mut region, 0)?;
//                 region.assign_advice(self.config.msg, 0, Value::known(msg));
//                 region.assign_advice(self.config.sig, 0, Value::known(sig));
//                 region.assign_advice(self.config.pk, 0, Value::known(pk));
//                 Ok(())
//             },
//         )
//     }
// }