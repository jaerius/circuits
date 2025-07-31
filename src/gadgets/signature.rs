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
use ecc::AssignedPoint;



/// SignatureConfig: ECDSA gadget의 config를 그대로 사용
pub type SignatureConfig = EcdsaConfig;

/// SignatureChip: 내부적으로 ecdsa의 EcdsaChip을 래핑
pub struct SignatureChip<E: halo2curves::CurveAffine, F: PrimeField, const LIMBS: usize, const BITS: usize> {
    chip: EcdsaChip<E, F, LIMBS, BITS>,
}

impl<E: halo2curves::CurveAffine<ScalarExt = F>, F: PrimeField, const LIMBS: usize, const BITS: usize> SignatureChip<E, F, LIMBS, BITS> {
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
        let rns = scalar_chip.rns();
        let r = scalar_chip.assign_integer(ctx,  UnassignedInteger::from(Value::known(Integer::from_fe(sig.0, rns.clone()))), Range::Operand)?;
        // field element를 RNS 기반 limb 구조로 변환
        let s = scalar_chip.assign_integer(ctx,  UnassignedInteger::from(Value::known(Integer::from_fe(sig.1, rns.clone()))), Range::Operand)?;
        Ok(AssignedEcdsaSig { r, s })
    }

    pub fn assign_public_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        pk: (E::Base, E::Base),
    ) -> Result<AssignedPublicKey<E::Base, F, LIMBS, BITS>, Error> {
        let base_chip = self.chip.ecc_chip().base_field_chip();
        let rns = base_chip.rns();
        let x = base_chip.assign_integer(
            ctx,
            Value::known(Integer::from_fe(pk.0, rns.clone())).into(),
            Range::Remainder,
        )?;
        let y = base_chip.assign_integer(
            ctx,
            Value::known(Integer::from_fe(pk.1, rns.clone())).into(),
            Range::Remainder,
        )?;
        let point = AssignedPoint::new(x, y);
        Ok(AssignedPublicKey { point })
    }

    pub fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        value: F,
    ) -> Result<AssignedInteger<E::Scalar, F, LIMBS, BITS>, Error> {
        let scalar_chip = self.chip.scalar_field_chip();
        let rns = scalar_chip.rns(); // 또는 self.chip.range(), config.range 등
        scalar_chip.assign_integer(ctx, UnassignedInteger::from(Value::known(Integer::from_fe(value, rns.clone()))), Range::Operand)
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

// ECDSA 검증은 아래 수학적 검증을 회로로 표현
// Given:
//   Signature: (r, s)
//   Public key: P = (x, y)
//   Message hash: z
// Verify:
//   w = s⁻¹ mod n
//   u1 = z * w mod n
//   u2 = r * w mod n
//   R = u1 * G + u2 * P
//   R.x mod n == r ?


// assign_signature:
//   - r, s 값 -> RNS limb 구조로 변환 (AssignedInteger)
// assign_public_key:
//   - (x, y) -> RNS limb 구조로 변환 → AssignedPoint
// assign_integer:
//   - 메시지 해시 z → RNS limb로 변환

// verify:
//   - 내부적으로 EcdsaChip.verify(ctx, sig, pk, msg_hash) 호출
//     └→ 실제 흐름:
//         1. w = s⁻¹ mod n (modular inverse using RNS)
//         2. u₁ = z · w
//         3. u₂ = r · w
//         4. [Scalar mult]: u₁·G + u₂·P
//         5. 결과점의 x좌표 mod n == r 검증

//   - 모든 연산은 RNS 기반 limb 연산
//   - scalar 연산은 IntegerConfig / IntegerInstructions trait 기반
//   - ECC 연산은 EccChip 기반 (일반적으로 elliptic curve group addition, scalar mul 포함)
