use halo2::{
    circuit::{AssignedCell, Region, Value, Layouter},
    plonk::Error,
};
use halo2curves::bn256::Fr;
use crate::gadgets::poseidon::PoseidonGadget;
use poseidon::Pow5Chip;


pub struct MerkleGadget;

impl MerkleGadget {
    /// in-circuit Merkle root 계산
    /// leaf: AssignedCell<Fr, Fr>
    /// path: Vec<AssignedCell<Fr, Fr>>
    /// indices: &[bool]
    pub fn compute_root(
        chip: &Pow5Chip<Fr, 3, 2>,
        layouter: &mut impl Layouter<Fr>,
        mut hash: AssignedCell<Fr, Fr>,
        path: &[AssignedCell<Fr, Fr>],
        indices: &[bool],
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        
        for (i, sibling) in path.iter().enumerate() {
           let (left, right) = if indices[i] {
            (sibling.clone(), hash)
           } else {
                (hash, sibling.clone())
           };
           // PoseidonGadget의 in-circuit 해시 API 사용
           hash = PoseidonGadget::hash::<2>(
            chip,
            layouter.namespace(|| format!("merkle_hash_{i}")),
            [left, right],
        )?;
    }
    Ok(hash)
    }
}
