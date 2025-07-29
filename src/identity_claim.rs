use halo2curves::bn256::Fr;
use crate::gadgets::{poseidon, merkle, range_check, signature};
use halo2::plonk::{Circuit, ConstraintSystem, Error};
use halo2::circuit::{Layouter, SimpleFloorPlanner};
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
        IdentityClaimConfig { range, signature }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // 1. Poseidon 해시 (off-circuit 예시)
        let calc_claim_hash = PoseidonGadget::hash(&[self.value, self.min, self.max]);

        // 2. Merkle proof (off-circuit 예시)
        let _merkle_root = MerkleGadget::compute_root(calc_claim_hash, &self.merkle_proof, &vec![]);

        // 3. Range check (in-circuit)
        let range_chip = RangeCheckChip::<Fr>::construct(config.range.clone());
        range_chip.range_check(&mut layouter, self.value, self.min, self.max)?;

        // 4. Signature 검증 (in-circuit)
         // 4. Signature 검증 (in-circuit)
         layouter.assign_region(
            || "ecdsa verify",
            |mut region| {
                let mut ctx = RegionCtx::new(region, 0);

                // EccChip 생성 (EccConfig는 SignatureConfig 내부에서 가져오거나 별도 생성)
                let ecc_chip = GeneralEccChip::<G1Affine, Fr, 4, 68>::new(config.signature.ecc_chip_config());

                // EcdsaChip 생성
                let ecdsa_chip = EcdsaChip::new(ecc_chip);

                // SignatureChip 생성
                let signature_chip = SignatureChip::new(ecdsa_chip);
                
                let pk_x_fq = Fq::from_repr_vartime(self.pk_x.to_repr()).unwrap();
                let pk_y_fq = Fq::from_repr_vartime(self.pk_y.to_repr()).unwrap();
                let assigned_pk = signature_chip.assign_public_key(&mut ctx, (pk_x_fq, pk_y_fq))?;

                let assigned_sig = signature_chip.assign_signature(&mut ctx, (self.sig_r, self.sig_s))?;
                
                let assigned_msg_hash = signature_chip.assign_integer(&mut ctx, self.signature_hash)?;
                signature_chip.verify(&mut ctx, &assigned_sig, &assigned_pk, &assigned_msg_hash)?;
                Ok(())
                },
        )?;

        Ok(())
    }
}
