use halo2wrong::curves::bn256::Fr;
use halo2_axiom as halo2_proofs;
use crate::gadgets::{poseidon, merkle, range_check, signature};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use crate::gadgets::poseidon::PoseidonGadget;

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
}

impl Circuit<Fr> for IdentityClaimCircuit {
    type Config = ();
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

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
        }
    }

    fn configure(_meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // TODO: Poseidon, Merkle, Range check, Signature 제약조건 추가
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // 1. Poseidon 해시
        //let _calc_claim_hash = poseidon::poseidon_hash(vec![self.value, self.min, self.max]);
        // 2. Merkle proof
        // 3. Range check
        // 4. Signature 검증
        Ok(())
    }
}
