use super::vector_party::VectorFirstMessage;
use crate::pprf_aggregator::PprfAggregator;
use crate::{codes::EACode, xor_arrays, KEY_SIZE};
use fields::{FieldElement, GF128};
use pprf::{
    distributed_generation::{Puncturer, SenderFirstMessage, SenderSecondMessage},
    prf_eval_all,
};

pub struct SparseVolePcgScalarKeyGenState<const INPUT_BITLEN: usize> {
    prf_keys: Vec<[u8; KEY_SIZE]>,
    scalar: GF128,
    puncturers: Vec<Puncturer<KEY_SIZE, INPUT_BITLEN>>,
}

pub struct OfflineSparseVoleKey {
    pub scalar: GF128,
    pub accumulated_vector: Vec<GF128>,
}

pub struct OnlineSparseVoleKey<const CODE_WEIGHT: usize> {
    accumulated_vector: Vec<GF128>,
    code: EACode<CODE_WEIGHT>,
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
            .map(|prf_key| Puncturer::<KEY_SIZE, INPUT_BITLEN>::new(&prf_key))
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

    pub fn keygen_offline<T: PprfAggregator<KEY_SIZE>>(&self) -> OfflineSparseVoleKey {
        let accumulated_vector = T::aggregate(&self.prf_keys, INPUT_BITLEN);
        let mut sum = GF128::zero();
        OfflineSparseVoleKey {
            scalar: self.scalar.clone(),
            accumulated_vector: accumulated_vector
                .into_iter()
                .map(|v| {
                    sum += GF128::from(v);
                    sum
                })
                .collect(),
        }
    }
}

impl OfflineSparseVoleKey {
    pub fn provide_online_key<const CODE_WEIGHT: usize>(
        self,
        code: EACode<CODE_WEIGHT>,
    ) -> OnlineSparseVoleKey<CODE_WEIGHT> {
        OnlineSparseVoleKey {
            accumulated_vector: self.accumulated_vector,
            code,
        }
    }
    pub fn vector_length(&self) -> usize {
        self.accumulated_vector.len()
    }
}

impl<const CODE_WEIGHT: usize> Iterator for OnlineSparseVoleKey<CODE_WEIGHT> {
    type Item = GF128;
    fn next(&mut self) -> Option<Self::Item> {
        match self.code.next() {
            None => None,
            Some(v) => Some(v.iter().map(|idx| self.accumulated_vector[*idx]).sum()),
        }
    }
}
