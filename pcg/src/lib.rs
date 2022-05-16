pub mod codes;
pub mod sparse_vole;
use codes::EACode;
use fields::GF128;
use pprf::PuncturedKey;

pub struct SparseVolePcgEvaluatorKey<const KEY_SIZE: usize, const WEIGHT: usize> {
    code: EACode,
    prf_keys: [[u8; KEY_SIZE]; WEIGHT],
    scalar: GF128,
}

pub struct SparseVolePcgEvaluatedKey<
    const KEY_SIZE: usize,
    const INPUT_BITLEN: usize,
    const WEIGHT: usize,
> {
    code: EACode,
    pprf_keys: [PuncturedKey<KEY_SIZE, INPUT_BITLEN>; WEIGHT],
    punctured_values: [GF128; WEIGHT],
    puncturing_points: [[bool; INPUT_BITLEN]; WEIGHT],
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
