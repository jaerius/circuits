use halo2curves::bn256::Fr;
use halo2::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

#[derive(Clone, Debug)]
pub struct PostProofCircuit {
    pub claim_hash: Fr,
    pub post_hash: Fr,
    pub merkle_root: Fr,
    pub merkle_proof: Vec<Fr>,
    pub leaf_index: usize,
}

impl Circuit<Fr> for PostProofCircuit {
    type Config = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            claim_hash: Fr::zero(),
            post_hash: Fr::zero(),
            merkle_root: Fr::zero(),
            merkle_proof: vec![],
            leaf_index: 0,
        }
    }

    fn configure(_meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // TODO: Claim, 상태, Merkle proof 등 제약조건
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Claim, 상태, Merkle proof 등 증명 로직
        Ok(())
    }
}
