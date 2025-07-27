use halo2curves::bn256::Fr;
use crate::gadgets::poseidon::PoseidonGadget;

pub struct MerkleGadget;

impl MerkleGadget {
    /// leaf: 리프 값
    /// path: 머클 경로 값들
    /// indices: 각 경로가 왼쪽/오른쪽인지 (false: left, true: right)
    pub fn compute_root(leaf: Fr, path: &[Fr], indices: &[bool]) -> Fr {
        let mut hash = leaf;
        for (i, sibling) in path.iter().enumerate() {
            let inputs = if indices[i] {
                // 오른쪽에 sibling
                vec![sibling.clone(), hash]
            } else {
                // 왼쪽에 sibling
                vec![hash, sibling.clone()]
            };
            hash = PoseidonGadget::hash(&inputs);
        }
        hash
    }
}
