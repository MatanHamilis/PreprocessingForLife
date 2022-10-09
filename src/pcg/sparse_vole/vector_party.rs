use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use super::super::pprf_aggregator::PprfAggregator;
use super::super::KEY_SIZE;
use super::scalar_party::{ScalarFirstMessage, ScalarSecondMessage};
use super::FirstMessageItem;
use crate::communicator::Communicator;
use crate::fields::{FieldElement, GF128, GF2};
use crate::pcg::pprf_aggregator::RegularErrorPprfAggregator;
use crate::pprf::distributed_generation::Puncturee;
use crate::pprf::PuncturedKey;
use crate::pseudorandom::prf::PrfInput;
pub type PcgItem = (GF2, GF128);

pub struct SparseVolePcgVectorKeyGenStateInitial<const INPUT_BITLEN: usize> {
    puncturing_points: Vec<PrfInput<INPUT_BITLEN>>,
    puncturees: Vec<Puncturee<KEY_SIZE, INPUT_BITLEN>>,
}
#[derive(Serialize, Deserialize)]
pub struct SparseVolePcgVectorKeyGenStateFinal<const INPUT_BITLEN: usize> {
    pprf_keys: Vec<PuncturedKey<INPUT_BITLEN>>,
    punctured_values: Vec<[u8; KEY_SIZE]>,
    puncturing_points: Vec<PrfInput<INPUT_BITLEN>>,
}

pub type VectorFirstMessage<const INPUT_BITLEN: usize> = Vec<FirstMessageItem<INPUT_BITLEN>>;

#[derive(Clone)]
pub struct OfflineSparseVoleKey {
    pub(super) accumulated_scalar_vector: Vec<(GF2, GF128)>,
}

#[derive(Debug)]
pub struct OnlineSparseVoleKey<const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>> {
    accumulated_scalar_vector: Vec<(GF2, GF128)>,
    code: S,
}

impl<const INPUT_BITLEN: usize> SparseVolePcgVectorKeyGenStateInitial<INPUT_BITLEN> {
    pub fn new(puncturing_points: Vec<PrfInput<INPUT_BITLEN>>) -> Self {
        Self {
            puncturees: (0..puncturing_points.len())
                .map(|_| Puncturee::<KEY_SIZE, INPUT_BITLEN>::default())
                .collect(),
            puncturing_points,
        }
    }

    pub fn create_first_message(
        &mut self,
        scalar_first_message: ScalarFirstMessage<INPUT_BITLEN>,
    ) -> VectorFirstMessage<INPUT_BITLEN> {
        self.puncturees
            .iter_mut()
            .zip(scalar_first_message.into_iter())
            .enumerate()
            .map(|(i, (puncturee, scalar_first_message_item))| {
                puncturee
                    .make_first_msg(scalar_first_message_item.into(), self.puncturing_points[i])
                    .into()
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
                            .obtain_pprf(scalar_second_message_element.ots)
                            .expect("Failed to create PPRF key!")
                    })
                    .collect()
            },
            punctured_values: scalar_second_message.iter().map(|m| m.sums).collect(),
            puncturing_points: self.puncturing_points,
        }
    }
}

impl<const INPUT_BITLEN: usize> SparseVolePcgVectorKeyGenStateFinal<INPUT_BITLEN> {
    pub fn keygen_offline<T: PprfAggregator>(&self) -> OfflineSparseVoleKey {
        let (accumulated_scalar_vector, mut numeric_puncturing_points) = T::aggregate_punctured(
            &self.pprf_keys,
            &self.puncturing_points,
            &self.punctured_values,
        );

        let mut accumulated_scalar_vector: Vec<(GF2, GF128)> = accumulated_scalar_vector
            .into_iter()
            .map(|i| (GF2::zero(), i))
            .collect();
        numeric_puncturing_points.sort_unstable();
        (0..numeric_puncturing_points.len())
            .step_by(2)
            .for_each(|i| {
                let starting_index = numeric_puncturing_points[i];
                let end_index = *numeric_puncturing_points
                    .get(i + 1)
                    .unwrap_or(&(1 << INPUT_BITLEN));
                for item in accumulated_scalar_vector
                    .iter_mut()
                    .take(end_index)
                    .skip(starting_index)
                {
                    item.0 = GF2::one();
                }
            });
        OfflineSparseVoleKey {
            accumulated_scalar_vector,
            // accumulated_sparse_subfield_vector,
        }
    }
}

impl OfflineSparseVoleKey {
    pub fn provide_online_key<const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>>(
        self,
        code: S,
    ) -> OnlineSparseVoleKey<CODE_WEIGHT, S> {
        OnlineSparseVoleKey {
            accumulated_scalar_vector: self.accumulated_scalar_vector,
            // accumulated_sparse_subfield_vector: self.accumulated_sparse_subfield_vector,
            code,
        }
    }
    pub fn vector_length(&self) -> usize {
        self.accumulated_scalar_vector.len()
    }
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>> Iterator
    for OnlineSparseVoleKey<CODE_WEIGHT, S>
{
    type Item = PcgItem;
    fn next(&mut self) -> Option<Self::Item> {
        self.code.next().map(|v| {
            v.into_iter()
                .map(|idx| self.accumulated_scalar_vector[idx as usize])
                .fold((GF2::zero(), GF128::zero()), |acc, cur| {
                    (acc.0 + cur.0, acc.1 + cur.1)
                })
        })
    }
}

pub fn distributed_generation<const PRF_INPUT_BITLEN: usize, T: Write + Read>(
    puncturing_points: Vec<PrfInput<PRF_INPUT_BITLEN>>,
    prf_keys: Vec<[u8; KEY_SIZE]>,
    comm: &mut Communicator<T>,
) -> Option<OfflineSparseVoleKey> {
    // Define Gen State
    let mut vector_keygen_state_init =
        SparseVolePcgVectorKeyGenStateInitial::new(puncturing_points);

    // Run Gen Algorithm
    comm.send(prf_keys)?;
    let scalar_first_message = comm.receive()?;
    let vector_msg = vector_keygen_state_init.create_first_message(scalar_first_message);
    comm.send(vector_msg)?;
    let scalar_second_message = comm.receive()?;
    let vector_keygen_state_final =
        vector_keygen_state_init.handle_second_message(scalar_second_message);

    // Create Offline Keys
    Some(vector_keygen_state_final.keygen_offline::<RegularErrorPprfAggregator>())
}
