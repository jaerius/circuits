use halo2curves::bn256::Fr;
use poseidon::Poseidon;

const R_F: usize = 8;
const R_P: usize = 57;
const T: usize = 3;
const RATE: usize = 2;

pub struct PoseidonGadget;

impl PoseidonGadget {
    pub fn hash(inputs: &[Fr]) -> Fr {
        let mut poseidon = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
        poseidon.update(inputs);
        poseidon.squeeze()
    }
}