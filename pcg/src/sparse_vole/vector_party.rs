use super::scalar_party::{ScalarFirstMessage, ScalarSecondMessage};
use crate::codes::EACode;
use crate::{xor_arrays, KEY_SIZE};
use fields::{FieldElement, GF128, GF2};
use pprf::distributed_generation::{Puncturee, ReceiverFirstMessage};
use pprf::{bits_to_usize, PuncturedKey};
pub struct SparseVolePcgVectorKeyGenStateInitial<const INPUT_BITLEN: usize, const WEIGHT: usize> {
    puncturing_points: [[bool; INPUT_BITLEN]; WEIGHT],
    puncturees: [Puncturee<KEY_SIZE, INPUT_BITLEN>; WEIGHT],
}
pub struct SparseVolePcgVectorKeyGenStateFinal<const INPUT_BITLEN: usize, const WEIGHT: usize> {
    pprf_keys: [PuncturedKey<KEY_SIZE, INPUT_BITLEN>; WEIGHT],
    punctured_values: [GF128; WEIGHT],
    puncturing_points: [[bool; INPUT_BITLEN]; WEIGHT],
}

pub type VectorFirstMessage<const WEIGHT: usize, const INPUT_BITLEN: usize> =
    [[ReceiverFirstMessage; INPUT_BITLEN]; WEIGHT];

pub struct OfflineSparseVoleKey {
    accumulated_scalar_vector: Vec<GF128>,
    accumulated_sparse_subfield_vector: Vec<GF2>,
}

pub struct OnlineSparseVoleKey<const CODE_WEIGHT: usize> {
    accumulated_scalar_vector: Vec<GF128>,
    accumulated_sparse_subfield_vector: Vec<GF2>,
    code: EACode<CODE_WEIGHT>,
}

impl<const INPUT_BITLEN: usize, const WEIGHT: usize>
    SparseVolePcgVectorKeyGenStateInitial<INPUT_BITLEN, WEIGHT>
{
    pub fn new(puncturing_points: [[bool; INPUT_BITLEN]; WEIGHT]) -> Self {
        Self {
            puncturing_points,
            puncturees: [0; WEIGHT].map(|_| Puncturee::<KEY_SIZE, INPUT_BITLEN>::new()),
        }
    }

    pub fn create_first_message(
        &mut self,
        scalar_first_message: &ScalarFirstMessage<WEIGHT, INPUT_BITLEN>,
    ) -> VectorFirstMessage<WEIGHT, INPUT_BITLEN> {
        let mut i = 0;
        [0; WEIGHT].map(|_| {
            i += 1;
            self.puncturees[i - 1]
                .make_first_msg(scalar_first_message[i - 1], self.puncturing_points[i - 1])
        })
    }
    pub fn handle_second_message(
        mut self,
        scalar_second_message: ScalarSecondMessage<WEIGHT, INPUT_BITLEN>,
    ) -> SparseVolePcgVectorKeyGenStateFinal<INPUT_BITLEN, WEIGHT> {
        SparseVolePcgVectorKeyGenStateFinal {
            pprf_keys: {
                let mut i = 0;
                [0; WEIGHT].map(|_| {
                    i += 1;
                    self.puncturees[i - 1]
                        .obtain_pprf(scalar_second_message[i - 1].0)
                        .expect("Failed to create PPRF key!")
                })
            },
            punctured_values: {
                let mut i = 0;
                [0; WEIGHT].map(|_| {
                    i += 1;
                    scalar_second_message[i - 1].1
                })
            },
            puncturing_points: self.puncturing_points,
        }
    }
}

impl<const INPUT_BITLEN: usize, const WEIGHT: usize>
    SparseVolePcgVectorKeyGenStateFinal<INPUT_BITLEN, WEIGHT>
{
    pub fn keygen_offline(&self) -> OfflineSparseVoleKey {
        let mut accumulated_scalar_vector = vec![[0u8; KEY_SIZE]; 1 << INPUT_BITLEN];
        for (idx, pprf_key) in self.pprf_keys.iter().enumerate() {
            let mut next_scalar_vector = pprf_key.full_eval_with_punctured_point(&[0; KEY_SIZE]);
            let mut full_sum: [u8; KEY_SIZE] = self.punctured_values[idx].into();
            for v in next_scalar_vector.iter() {
                xor_arrays(&mut full_sum, v)
            }
            next_scalar_vector[bits_to_usize(&self.puncturing_points[idx])] = full_sum;
            next_scalar_vector
                .into_iter()
                .zip(accumulated_scalar_vector.iter_mut())
                .for_each(|(newkey, aggregated_key)| {
                    xor_arrays(aggregated_key, &newkey);
                });
        }

        let mut numeric_puncturing_points = {
            let mut i = 0;
            [0; WEIGHT].map(|_| {
                i += 1;
                bits_to_usize(&self.puncturing_points[i - 1])
            })
        };
        numeric_puncturing_points.sort_unstable();
        let mut accumulated_sparse_subfield_vector = vec![GF2::zero(); 1 << INPUT_BITLEN];
        (0..numeric_puncturing_points.len())
            .step_by(2)
            .for_each(|i| {
                let starting_index = numeric_puncturing_points[i];
                let end_index = *numeric_puncturing_points
                    .get(i + 1)
                    .unwrap_or(&(1 << INPUT_BITLEN));
                for j in starting_index..end_index {
                    accumulated_sparse_subfield_vector[j] = GF2::one();
                }
            });
        let mut sum = GF128::zero();
        OfflineSparseVoleKey {
            accumulated_scalar_vector: accumulated_scalar_vector
                .into_iter()
                .map(|e| {
                    sum += GF128::from(e);
                    sum
                })
                .collect(),
            accumulated_sparse_subfield_vector,
        }
    }
}

impl OfflineSparseVoleKey {
    pub fn provide_online_key<const CODE_WEIGHT: usize>(
        self,
        code: EACode<CODE_WEIGHT>,
    ) -> OnlineSparseVoleKey<CODE_WEIGHT> {
        OnlineSparseVoleKey {
            accumulated_scalar_vector: self.accumulated_scalar_vector,
            accumulated_sparse_subfield_vector: self.accumulated_sparse_subfield_vector,
            code,
        }
    }
}

impl<const CODE_WEIGHT: usize> Iterator for OnlineSparseVoleKey<CODE_WEIGHT> {
    type Item = (GF2, GF128);
    fn next(&mut self) -> Option<Self::Item> {
        match self.code.next() {
            None => None,
            Some(v) => Some((
                v.iter()
                    .map(|idx| self.accumulated_sparse_subfield_vector[*idx])
                    .sum(),
                v.iter()
                    .map(|idx| self.accumulated_scalar_vector[*idx])
                    .sum(),
            )),
        }
    }
}
