use super::super::pprf_aggregator::PprfAggregator;
use super::super::{xor_arrays, KEY_SIZE};
use super::vector_party::VectorFirstMessage;
use crate::fields::{FieldElement, GF128};
use crate::pprf::distributed_generation::{Puncturer, SenderFirstMessage, SenderSecondMessage};

pub type PcgItem = (GF128, GF128);

pub struct SparseVolePcgScalarKeyGenState<const INPUT_BITLEN: usize> {
    prf_keys: Vec<[u8; KEY_SIZE]>,
    scalar: GF128,
    puncturers: Vec<Puncturer<KEY_SIZE, INPUT_BITLEN>>,
}

pub struct OfflineSparseVoleKey {
    pub scalar: GF128,
    pub accumulated_vector: Vec<GF128>,
}

#[derive(Debug)]
pub struct OnlineSparseVoleKey<const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>> {
    pub(super) accumulated_vector: Vec<GF128>,
    code: S,
    index: usize,
    pub scalar: GF128,
}

pub type ScalarFirstMessage<const INPUT_BITLEN: usize> = Vec<[SenderFirstMessage; INPUT_BITLEN]>;

pub type ScalarSecondMessage<const INPUT_BITLEN: usize> = Vec<(
    [SenderSecondMessage<KEY_SIZE>; INPUT_BITLEN],
    [u8; KEY_SIZE],
)>;

impl<const INPUT_BITLEN: usize> SparseVolePcgScalarKeyGenState<INPUT_BITLEN> {
    /// Generates the first message of the Scalar party
    pub fn new(scalar: GF128, prf_keys: Vec<[u8; KEY_SIZE]>) -> Self {
        let puncturers = prf_keys
            .iter()
            .map(Puncturer::<KEY_SIZE, INPUT_BITLEN>::new)
            .collect();
        Self {
            prf_keys,
            scalar,
            puncturers,
        }
    }

    pub fn create_first_message(&mut self) -> ScalarFirstMessage<INPUT_BITLEN> {
        self.puncturers
            .iter_mut()
            .map(|puncturer| puncturer.make_first_msg())
            .collect()
    }

    pub fn create_second_message(
        &mut self,
        vector_msg: &VectorFirstMessage<INPUT_BITLEN>,
    ) -> ScalarSecondMessage<INPUT_BITLEN> {
        self.puncturers
            .iter_mut()
            .enumerate()
            .map(|(i, puncturer)| {
                let mut s = puncturer.get_full_sum();
                xor_arrays(&mut s, &self.scalar.into());
                (puncturer.make_second_msg(vector_msg[i]), s)
            })
            .collect()
    }

    pub fn keygen_offline<T: PprfAggregator>(&self) -> OfflineSparseVoleKey {
        let accumulated_vector = T::aggregate(&self.prf_keys, INPUT_BITLEN);
        let mut sum = GF128::zero();
        OfflineSparseVoleKey {
            scalar: self.scalar,
            accumulated_vector,
        }
    }
}

impl OfflineSparseVoleKey {
    pub fn provide_online_key<const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>>(
        self,
        code: S,
    ) -> OnlineSparseVoleKey<CODE_WEIGHT, S> {
        OnlineSparseVoleKey {
            accumulated_vector: self.accumulated_vector,
            code,
            index: 0,
            scalar: self.scalar,
        }
    }
    pub fn vector_length(&self) -> usize {
        self.accumulated_vector.len()
    }
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>> Iterator
    for OnlineSparseVoleKey<CODE_WEIGHT, S>
{
    type Item = PcgItem;
    fn next(&mut self) -> Option<Self::Item> {
        match self.code.next() {
            None => None,
            Some(v) => {
                self.index += 1;
                Some((
                    v.into_iter()
                        .map(|idx| self.accumulated_vector[idx as usize])
                        .sum(),
                    self.scalar,
                ))
            }
        }
    }
}
