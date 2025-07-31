use halo2curves::bn256::Fr;
use poseidon::{Pow5Chip, Pow5Config, Spec, ConstantLength, Hash, P128Pow5T3};
use halo2::plonk::{Circuit, ConstraintSystem, Error};
use halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
use crate::gadgets::poseidon::PoseidonGadget;
use crate::gadgets::merkle::MerkleGadget;
use crate::gadgets::range_check::{RangeCheckChip, RangeCheckConfig};
use crate::gadgets::signature::{SignatureChip, SignatureConfig};
use ecc::{GeneralEccChip, EccConfig};
use ecdsa::ecdsa::{EcdsaChip, AssignedEcdsaSig, AssignedPublicKey};
use integer::rns::Integer;
use integer::AssignedInteger;
use maingate::RegionCtx;
use halo2curves::bn256::G1Affine;
use halo2curves::bn256::Fq;
use halo2curves::ff::PrimeField;
use halo2::circuit::AssignedCell;



#[derive(Clone, Debug)]
pub struct IdentityClaimCircuit {
    pub claim_hash: Fr,
    pub merkle_root: Fr,
    pub merkle_proof: Vec<Fr>,
    pub leaf_index: usize,
    pub value: Fr,
    pub min: Fr,
    pub max: Fr,
    pub signature_hash: Fr,
    pub sig_r: Fr,
    pub sig_s: Fr,
    pub pk_x: Fr,
    pub pk_y: Fr,
}

#[derive(Clone, Debug)]
pub struct IdentityClaimConfig {
    pub range: RangeCheckConfig,
    pub signature: SignatureConfig,
    pub poseidon: Pow5Config<Fr, 3, 2>, // 추가!
}

impl Circuit<Fr> for IdentityClaimCircuit {
    type Config = IdentityClaimConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            claim_hash: Fr::zero(),
            merkle_root: Fr::zero(),
            merkle_proof: vec![],
            leaf_index: 0,
            value: Fr::zero(),
            min: Fr::zero(),
            max: Fr::zero(),
            signature_hash: Fr::zero(),
            sig_r: Fr::zero(),
            sig_s: Fr::zero(),
            pk_x: Fr::zero(),
            pk_y: Fr::zero(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let range = RangeCheckChip::configure(meta);
        let signature = SignatureChip::<halo2curves::bn256::G1Affine, Fr, 4, 68>::configure(meta);
        // Poseidon용 컬럼 선언
        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];

        let poseidon = Pow5Chip::<Fr, 3, 2>::configure::<P128Pow5T3>(
            meta,
            state,
            partial_sbox,
            rc_a,
            rc_b,
        );

        IdentityClaimConfig { range, signature, poseidon }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // 1. 값 할당만 region에서
        let (assigned_value, assigned_min, assigned_max, assigned_path) =
            layouter.assign_region(
                || "identity claim main",
                |mut region| {
                    let assigned_value = region.assign_advice(
                        || "value", config.range.value, 0, || Value::known(self.value)
                    )?;
                    let assigned_min = region.assign_advice(
                        || "min", config.range.min, 0, || Value::known(self.min)
                    )?;
                    let assigned_max = region.assign_advice(
                        || "max", config.range.max, 0, || Value::known(self.max)
                    )?;
                    let assigned_path: Vec<AssignedCell<Fr, Fr>> = self.merkle_proof.iter()
                        .enumerate()
                        .map(|(i, v)| region.assign_advice(
                            || format!("merkle_path_{i}"), config.range.value, i + 1, || Value::known(*v)
                        ).unwrap())
                        .collect();
                    Ok((assigned_value, assigned_min, assigned_max, assigned_path))
                }
            )?;

       // 2. Poseidon 해시 (in-circuit, layouter 기반)
        let chip = Pow5Chip::<Fr, 3, 2>::construct(config.poseidon.clone());
        let calc_claim_hash = PoseidonGadget::hash::<3>(
            &chip,
            layouter.namespace(|| "poseidon hash"),
            [assigned_value.clone(), assigned_min.clone(), assigned_max.clone()],
        )?;

        // 3. Merkle root 계산 (layouter 기반)
        let indicies: Vec<bool> = (0..self.merkle_proof.len())
            .map(|i| (self.leaf_index >> i) & 1 == 1)
            .collect();
        let _merkle_root = MerkleGadget::compute_root(
            &chip,
            &mut layouter,
            calc_claim_hash.clone(),
            &assigned_path,
            &indicies,
        )?;

        // 4. Range check (in-circuit, layouter 기반)
        let range_chip = RangeCheckChip::<Fr>::construct(config.range.clone());
        range_chip.range_check(
            &mut layouter,
            &assigned_value,
            self.min,
            self.max
        )?;
    
        // 5. Signature 검증 (in-circuit, 별도 region)
        layouter.assign_region(
            || "ecdsa verify",
            |mut region| {
                let mut ctx = RegionCtx::new(region, 0);

                let ecc_chip = GeneralEccChip::<G1Affine, Fr, 4, 68>::new(config.signature.ecc_chip_config());
                let ecdsa_chip = EcdsaChip::new(ecc_chip);
                let signature_chip = SignatureChip::new(ecdsa_chip);

                let pk_x_fq = Fq::from_repr_vartime(self.pk_x.to_repr()).unwrap();
                let pk_y_fq = Fq::from_repr_vartime(self.pk_y.to_repr()).unwrap();
                let assigned_pk = signature_chip.assign_public_key(&mut ctx, (pk_x_fq, pk_y_fq))?;
                let assigned_sig = signature_chip.assign_signature(&mut ctx, (self.sig_r, self.sig_s))?;
                let assigned_msg_hash = signature_chip.assign_integer(&mut ctx, self.signature_hash)?;
                signature_chip.verify(&mut ctx, &assigned_sig, &assigned_pk, &assigned_msg_hash)?;
                Ok(())
            }
        )?;

        Ok(())
    }
}
