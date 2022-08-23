use rayon::iter::{IndexedParallelIterator, ParallelIterator};

use crate::pprf::usize_to_bits;
use std::simd::{u8x16, u8x64};

use super::{DpfKey, DPF_KEY_SIZE};
const BITS_IN_BYTE: usize = 8;
const LOG_BITS_IN_BYTE: usize = 3;
pub fn gen_query<const DEPTH: usize>(
    index: usize,
    dpf_root_0: [u8; DPF_KEY_SIZE],
    dpf_root_1: [u8; DPF_KEY_SIZE],
) -> (DpfKey<DEPTH>, DpfKey<DEPTH>) {
    let point = usize_to_bits(index / (DPF_KEY_SIZE * BITS_IN_BYTE));
    let arr_index = (index & ((DPF_KEY_SIZE * BITS_IN_BYTE) - 1)) >> LOG_BITS_IN_BYTE;
    let cell_index = index & (BITS_IN_BYTE - 1);
    let mut hiding_value = [0u8; DPF_KEY_SIZE];
    hiding_value[arr_index] = 1 << cell_index;
    DpfKey::gen(&point, &hiding_value, dpf_root_0, dpf_root_1)
}

pub fn dpf_to_simd_vec_helpers<const DPF_DEPTH: usize, const BATCH: usize>(
    dpf_keys: &[DpfKey<DPF_DEPTH>; BATCH],
    output: &mut [[u8x64; BATCH]],
    mut helper: &mut [u8x64],
    helper_toggle: &mut [bool],
) {
    let helper_len = helper.len();
    let helper_transmuted_len = helper_len * (std::mem::size_of::<u8x64>() / DPF_KEY_SIZE);
    assert_eq!(
        (DPF_KEY_SIZE << DPF_DEPTH),
        output.len() * std::mem::size_of::<u8x64>()
    );
    let mut helper_transmuted: &mut [[u8; DPF_KEY_SIZE]] = unsafe {
        std::slice::from_raw_parts_mut(helper.as_mut_ptr().cast(), helper_transmuted_len)
    };
    assert_eq!(helper_transmuted.len(), helper_toggle.len());
    for i in 0..BATCH {
        dpf_keys[i].eval_all_into(helper_transmuted, helper_toggle);
        helper = unsafe {
            std::slice::from_raw_parts_mut(helper_transmuted.as_mut_ptr().cast(), helper.len())
        };
        for j in 0..helper.len() {
            output[j][i] = helper[j];
        }
        helper_transmuted = unsafe {
            std::slice::from_raw_parts_mut(helper.as_mut_ptr().cast(), helper_transmuted_len)
        };
    }
}

pub fn dpf_to_simd_vec<const DPF_DEPTH: usize, const BATCH: usize>(
    dpf_keys: &[DpfKey<DPF_DEPTH>; BATCH],
) -> Vec<[u8x64; BATCH]> {
    let mut output =
        vec![[u8x64::default(); BATCH]; (DPF_KEY_SIZE << DPF_DEPTH) / std::mem::size_of::<u8x64>()];
    let mut helper = vec![u8x64::default(); output.len()];
    let mut helper_toggle = vec![false; 1 << DPF_DEPTH];
    dpf_to_simd_vec_helpers(dpf_keys, &mut output, &mut helper, &mut helper_toggle);
    output
}
pub fn answer_query_batched<const BATCH: usize>(
    query: &[[u8x64; BATCH]],
    db: &[u8x64],
    output: &mut [[u8x64; BATCH]],
) {
    assert_eq!(query.len() * output.len(), db.len());
    for i in 0..output.len() {
        output[i] = inner_prod_simd(query, &db[i * query.len()..(i + 1) * query.len()]);
    }
}
pub fn inner_prod_simd<const BATCH: usize>(a: &[[u8x64; BATCH]], b: &[u8x64]) -> [u8x64; BATCH] {
    let mut o = [u8x64::default(); BATCH];
    for i in 0..b.len() {
        for j in 0..BATCH {
            o[j] ^= a[i][j] & b[i]
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use std::simd::{u8x16, u8x64};

    use crate::dpf::dpf_pir::{answer_query_batched, dpf_to_simd_vec, gen_query};
    use crate::dpf::{DpfKey, DPF_KEY_SIZE};
    use crate::pprf::usize_to_bits;

    #[test]
    pub fn test_pir() {
        const BATCH: usize = 1;
        const LOG_DB_SZ: usize = 33;
        const DB_SZ: usize = 1 << LOG_DB_SZ;
        const DPF_DEPTH: usize = 17;
        const QUERY_INDEX: usize = 512;
        let array_index = QUERY_INDEX / (8 * std::mem::size_of::<u8x64>());
        let cell_index = (QUERY_INDEX % (8 * std::mem::size_of::<u8x64>())) / 8;
        let bit_index = QUERY_INDEX % 8;
        let db: Vec<_> = (0..(DB_SZ / (std::mem::size_of::<u8x64>() * 8)))
            .map(|i| {
                u8x64::from_array(unsafe { std::mem::transmute([u64::try_from(i).unwrap(); 8]) })
            })
            .collect();
        let dpf_root_0 = [1u8; DPF_KEY_SIZE];
        let dpf_root_1 = [2u8; DPF_KEY_SIZE];
        let (k_0, k_1) = gen_query::<DPF_DEPTH>(QUERY_INDEX, dpf_root_0, dpf_root_1);
        let dpf_merged_evals_util = dpf_to_simd_vec(&[k_0]);
        let mut output_0 = vec![[u8x64::default(); BATCH]; db.len() / dpf_merged_evals_util.len()];
        answer_query_batched(&dpf_merged_evals_util, &db, &mut output_0);
        let dpf_merged_evals_util = dpf_to_simd_vec(&[k_1]);
        let mut output_1 = vec![[u8x64::default(); BATCH]; db.len() / dpf_merged_evals_util.len()];
        answer_query_batched(&dpf_merged_evals_util, &db, &mut output_1);

        assert_eq!(
            ((output_0[array_index][0] ^ output_1[array_index][0])[cell_index] >> bit_index) & 1,
            (db[array_index][cell_index] >> bit_index) & 1
        );
        // for i in 0..output_0.len() {
        //     let entry: [u8; DPF_KEY_SIZE] = unsafe {
        //         std::mem::transmute(
        //             u8x16::from_array(output_0[i][0]) ^ u8x16::from_array(output_1[i][0]),
        //         )
        //     };
        //     if i != QUERY_OUTPUT_INDEX {
        //         assert_eq!(entry, [0u8; DPF_KEY_SIZE]);
        //     } else {
        //         let mut expected_output = [0u8; DPF_KEY_SIZE];
        //         expected_output[QUERY_OUTPUT_IN_CELL] = 1 << QUERY_OUTPUT_BIT;
        //         assert_eq!(entry, expected_output);
        //     }
        // }
    }
}
