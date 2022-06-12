use super::scalar_party::{ScalarFirstMessage, ScalarSecondMessage};
use crate::codes::EACode;
use crate::pprf_aggregator::PprfAggregator;
use crate::{xor_arrays, KEY_SIZE};
use fields::{FieldElement, GF128, GF2};
use pprf::distributed_generation::{Puncturee, ReceiverFirstMessage};
use pprf::{bits_to_usize, PuncturedKey};
pub struct SparseVolePcgVectorKeyGenStateInitial<const INPUT_BITLEN: usize> {
    puncturing_points: Vec<[bool; INPUT_BITLEN]>,
    puncturees: Vec<Puncturee<KEY_SIZE, INPUT_BITLEN>>,
}
pub struct SparseVolePcgVectorKeyGenStateFinal<const INPUT_BITLEN: usize> {
    pprf_keys: Vec<PuncturedKey<KEY_SIZE, INPUT_BITLEN>>,
    punctured_values: Vec<[u8; KEY_SIZE]>,
    puncturing_points: Vec<[bool; INPUT_BITLEN]>,
}

pub type VectorFirstMessage<const INPUT_BITLEN: usize> = Vec<[ReceiverFirstMessage; INPUT_BITLEN]>;

pub struct OfflineSparseVoleKey {
    accumulated_scalar_vector: Vec<GF128>,
    accumulated_sparse_subfield_vector: Vec<GF2>,
}

pub struct OnlineSparseVoleKey<const CODE_WEIGHT: usize> {
    accumulated_scalar_vector: Vec<GF128>,
    accumulated_sparse_subfield_vector: Vec<GF2>,
    code: EACode<CODE_WEIGHT>,
}

impl<const INPUT_BITLEN: usize> SparseVolePcgVectorKeyGenStateInitial<INPUT_BITLEN> {
    pub fn new(puncturing_points: Vec<[bool; INPUT_BITLEN]>) -> Self {
        Self {
            puncturees: (0..puncturing_points.len())
                .map(|_| Puncturee::<KEY_SIZE, INPUT_BITLEN>::new())
                .collect(),
            puncturing_points,
        }
    }

    pub fn create_first_message(
        &mut self,
        scalar_first_message: &ScalarFirstMessage<INPUT_BITLEN>,
    ) -> VectorFirstMessage<INPUT_BITLEN> {
        self.puncturees
            .iter_mut()
            .enumerate()
            .map(|(i, puncturee)| {
                puncturee.make_first_msg(scalar_first_message[i], self.puncturing_points[i])
            })
            .collect()
    }
    pub fn handle_second_message(
        mut self,
        scalar_second_message: ScalarSecondMessage<INPUT_BITLEN>,
    ) -> SparseVolePcgVectorKeyGenStateFinal<INPUT_BITLEN> {
        SparseVolePcgVectorKeyGenStateFinal {
            pprf_keys: {
                self.puncturees
                    .iter_mut()
                    .zip(scalar_second_message.iter())
                    .map(|(puncturee, scalar_second_message_element)| {
                        puncturee
                            .obtain_pprf(scalar_second_message_element.0)
                            .expect("Failed to create PPRF key!")
                    })
                    .collect()
            },
            punctured_values: scalar_second_message.iter().map(|m| m.1).collect(),
            puncturing_points: self.puncturing_points,
        }
    }
}

impl<const INPUT_BITLEN: usize> SparseVolePcgVectorKeyGenStateFinal<INPUT_BITLEN> {
    pub fn keygen_offline<T: PprfAggregator<KEY_SIZE>>(&self) -> OfflineSparseVoleKey {
        let (accumulated_scalar_vector, mut numeric_puncturing_points) = T::aggregate_punctured(
            &self.pprf_keys,
            &self.puncturing_points,
            &self.punctured_values,
        );

        numeric_puncturing_points.sort_unstable();
        let mut accumulated_sparse_subfield_vector =
            vec![GF2::zero(); accumulated_scalar_vector.len()];
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
    pub fn vector_length(&self) -> usize {
        self.accumulated_scalar_vector.len()
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
