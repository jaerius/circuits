use halo2curves::bn256::Fr;
use halo2::{
    circuit::{AssignedCell, Region, Value, Layouter},
    plonk::Error,
};
use poseidon::{Pow5Chip, Spec, ConstantLength, Hash};

const WIDTH: usize = 3;
const RATE: usize = 2;

pub struct PoseidonGadget;

impl PoseidonGadget {
    pub fn hash<const L: usize>(
        chip: &Pow5Chip<Fr, WIDTH, RATE>,
        layouter: impl Layouter<Fr>,
        inputs: [AssignedCell<Fr, Fr>; L],
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let hasher = Hash::<
            Fr,
            Pow5Chip<Fr, WIDTH, RATE>,
            Spec<Fr, WIDTH, RATE>,
            ConstantLength<L>,
            WIDTH,
            RATE,
        >::init(chip, layouter.namespace(|| "init"))?;
        hasher.hash(layouter, inputs)
    }
}