use crate::xor_arrays;
use crate::KEY_SIZE;
use pprf::{bits_to_usize, prf_eval_all, prf_eval_all_into_slice, PuncturedKey};
use rayon::prelude::*;

pub trait PprfAggregator {
    fn aggregate(prf_keys: &[[u8; KEY_SIZE]], pprf_input_bitlen: usize) -> Vec<[u8; KEY_SIZE]>;
    fn aggregate_punctured<const INPUT_BITLEN: usize>(
        pprf_keys: &[PuncturedKey<INPUT_BITLEN>],
        punctured_points: &[[bool; INPUT_BITLEN]],
        punctured_values_plus_leaves_sum: &[[u8; KEY_SIZE]],
    ) -> (Vec<[u8; KEY_SIZE]>, Vec<usize>);
}

pub struct RandomErrorPprfAggregator {}
impl PprfAggregator for RandomErrorPprfAggregator {
    fn aggregate(prf_keys: &[[u8; KEY_SIZE]], pprf_input_bitlen: usize) -> Vec<[u8; KEY_SIZE]> {
        let mut accumulated_vector = prf_eval_all(&prf_keys[0], pprf_input_bitlen);
        prf_keys[1..].iter().for_each(|k| {
            prf_eval_all(k, pprf_input_bitlen)
                .iter()
                .zip(accumulated_vector.iter_mut())
                .for_each(|(tmp_vec, acc_vec)| {
                    xor_arrays(acc_vec, tmp_vec);
                })
        });
        accumulated_vector
    }
    fn aggregate_punctured<const INPUT_BITLEN: usize>(
        pprf_keys: &[PuncturedKey<INPUT_BITLEN>],
        punctured_points: &[[bool; INPUT_BITLEN]],
        punctured_values_plus_leaves_sum: &[[u8; KEY_SIZE]],
    ) -> (Vec<[u8; KEY_SIZE]>, Vec<usize>) {
        let mut accumulated_vector = vec![[0u8; KEY_SIZE]; 1 << INPUT_BITLEN];
        for idx in 0..pprf_keys.len() {
            let next_scalar_vector = pprf_keys[idx]
                .full_eval_with_punctured_point(&punctured_values_plus_leaves_sum[idx]);
            next_scalar_vector
                .into_iter()
                .zip(accumulated_vector.iter_mut())
                .for_each(|(newkey, aggregated_key)| {
                    xor_arrays(aggregated_key, &newkey);
                });
        }
        let mut numeric_punctured_points = vec![0usize; pprf_keys.len()];
        for (i, punctuerd_point) in punctured_points.iter().enumerate() {
            numeric_punctured_points[i] = bits_to_usize(punctuerd_point);
        }
        (accumulated_vector, numeric_punctured_points)
    }
}

pub struct RegularErrorPprfAggregator {}
impl PprfAggregator for RegularErrorPprfAggregator {
    fn aggregate(prf_keys: &[[u8; KEY_SIZE]], pprf_input_bitlen: usize) -> Vec<[u8; KEY_SIZE]> {
        let mut accumulated_vector = vec![[0u8; KEY_SIZE]; prf_keys.len() << pprf_input_bitlen];
        let pprf_domain_size = 1 << pprf_input_bitlen;
        prf_keys
            .par_iter()
            .zip(accumulated_vector.par_chunks_mut(pprf_domain_size))
            .for_each(|(key, acc_vector_chunk)| {
                prf_eval_all_into_slice(
                    key,
                    pprf_input_bitlen,
                    acc_vector_chunk, // &mut accumulated_vector[pprf_domain_size * idx..pprf_domain_size * (idx + 1)],
                )
            });
        accumulated_vector
    }
    fn aggregate_punctured<const INPUT_BITLEN: usize>(
        pprf_keys: &[PuncturedKey<INPUT_BITLEN>],
        punctured_points: &[[bool; INPUT_BITLEN]],
        punctured_values_plus_leaves_sums: &[[u8; KEY_SIZE]],
    ) -> (Vec<[u8; KEY_SIZE]>, Vec<usize>) {
        let mut output = vec![[0u8; KEY_SIZE]; pprf_keys.len() * (1 << INPUT_BITLEN)];
        pprf_keys
            .par_iter()
            .zip(punctured_values_plus_leaves_sums.par_iter())
            .zip(output.par_chunks_mut(1 << INPUT_BITLEN))
            .for_each(
                |((punctured_key, punctured_value_plus_leaf_sum), output_chunk)| {
                    punctured_key.full_eval_with_punctured_point_into_slice(
                        punctured_value_plus_leaf_sum,
                        output_chunk,
                    )
                },
            );
        let mut numeric_punctured_points = vec![0usize; pprf_keys.len()];
        for (i, punctuerd_point) in punctured_points.iter().enumerate() {
            numeric_punctured_points[i] = bits_to_usize(punctuerd_point) + (1 << INPUT_BITLEN) * i;
        }
        (output, numeric_punctured_points)
    }
}
