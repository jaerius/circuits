use halo2wrong::curves::bn256::Fr;
use halo2_axiom as halo2_proofs;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value, Region},
    plonk::{Circuit, ConstraintSystem, Error, Advice, Column, Instance, Selector},
};
use halo2_solidity_verifier::SolidityGenerator;

/// Merkle proof 회로의 Config 구조체
#[derive(Clone, Debug)]
pub struct GroupAccessConfig {
    pub leaf: Column<Advice>,
    pub path_elements: Vec<Column<Advice>>,
    pub path_indices: Vec<Column<Advice>>,
    pub root: Column<Instance>,
    pub selector: Selector,
}

#[derive(Clone, Debug)]
pub struct GroupAccessCircuit {
    pub leaf: Fr,
    pub path_elements: Vec<Fr>,
    pub path_indices: Vec<bool>, // 0: left, 1: right
    pub root: Fr,
}

impl Circuit<Fr> for GroupAccessCircuit {
    type Config = GroupAccessConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            leaf: Fr::zero(),
            path_elements: vec![Fr::zero(); self.path_elements.len()],
            path_indices: vec![false; self.path_indices.len()],
            root: Fr::zero(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // Merkle proof depth (예: 20)
        let depth = 20;
        let leaf = meta.advice_column();
        let mut path_elements = Vec::new();
        let mut path_indices = Vec::new();
        for _ in 0..depth {
            path_elements.push(meta.advice_column());
            path_indices.push(meta.advice_column());
        }
        let root = meta.instance_column();
        let selector = meta.selector();

        GroupAccessConfig {
            leaf,
            path_elements,
            path_indices,
            root,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let cell = layouter.assign_region(
            || "Merkle proof traversal",
            |mut region| {
                let mut current_hash = self.leaf;
                let mut offset = 0;
                for (i, (pe, pi)) in self.path_elements.iter().zip(self.path_indices.iter()).enumerate() {
                    let (left, right) = if *pi { (pe.clone(), current_hash) } else { (current_hash, pe.clone()) };
                    // 실제로는 Poseidon hash를 써야 하지만, 예시로 left+right 사용
                    let hash = left + right;
                    region.assign_advice(
                       
                        config.leaf,
                        offset,
                        Value::known(current_hash),
                    );
                    region.assign_advice(
                        
                        config.path_elements[i],
                        offset,
                        Value::known(*pe),
                    );
                    region.assign_advice(
                        
                        config.path_indices[i],
                        offset,
                        Value::known(Fr::from(*pi as u64)),
                    );
                    current_hash = hash;
                    offset += 1;
                }
                let cell = region.assign_advice(
                    
                    config.leaf,
                    offset,
                    (|| Value::known(current_hash))(),
                );
                Ok(cell)
            },
        )?;
        layouter.constrain_instance(cell.cell(), config.root, 0);
        Ok(())
    }
}

/*
====================[ Halo2 Prover/Verifier & Solidity 연동 흐름 ]====================

1. Rust(Halo2)에서 회로 정의 및 proving/verification key 생성
   - let circuit = GroupAccessCircuit { ... };
   - let params = ...; // KZG 등
   - let pk = keygen_pk(&params, &circuit, ...);
   - let vk = keygen_vk(&params, &circuit, ...);

2. proof 생성
   - let proof = create_proof(&params, &pk, &circuit, ...);
   - let public_inputs = vec![root];
   - proof, public_inputs를 export (JSON, calldata 등)

3. halo2-solidity-verifier로 Solidity Verifier 컨트랙트 생성
   - let generator = SolidityGenerator::new(&params, &vk, Bdfg21, num_instances);
   - let verifier_solidity = generator.render().unwrap();
   - 생성된 Solidity 코드를 contracts/에 배치

4. Solidity 컨트랙트에 proof, public input 제출 → on-chain 검증
   - verifyProof(proof, publicInputs) 호출
   - 컨트랙트에서 on-chain으로 proof 검증

5. 실제 동작 테스트
   - Rust에서 proof 생성 → Solidity 컨트랙트에 제출 → 검증 결과 확인

참고: https://github.com/privacy-scaling-explorations/halo2-solidity-verifier
====================================================================================
*/
