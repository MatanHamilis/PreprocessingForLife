use super::vector_party::VectorFirstMessage;
use crate::{codes::EACode, xor_arrays, KEY_SIZE};
use fields::{FieldElement, GF128};
use pprf::{
    distributed_generation::{Puncturer, SenderFirstMessage, SenderSecondMessage},
    prf_eval_all,
};

pub struct SparseVolePcgScalarKeyGenState<const INPUT_BITLEN: usize, const WEIGHT: usize> {
    prf_keys: [[u8; KEY_SIZE]; WEIGHT],
    scalar: GF128,
    puncturers: [Puncturer<KEY_SIZE, INPUT_BITLEN>; WEIGHT],
}

pub struct OfflineSparseVoleKey {
    pub scalar: GF128,
    pub accumulated_vector: Vec<GF128>,
}

pub struct OnlineSparseVoleKey<const CODE_WEIGHT: usize> {
    accumulated_vector: Vec<GF128>,
    code: EACode<CODE_WEIGHT>,
}

pub type ScalarFirstMessage<const WEIGHT: usize, const INPUT_BITLEN: usize> =
    [[SenderFirstMessage; INPUT_BITLEN]; WEIGHT];

pub type ScalarSecondMessage<const WEIGHT: usize, const INPUT_BITLEN: usize> =
    [([SenderSecondMessage<KEY_SIZE>; INPUT_BITLEN], GF128); WEIGHT];

impl<const INPUT_BITLEN: usize, const WEIGHT: usize>
    SparseVolePcgScalarKeyGenState<INPUT_BITLEN, WEIGHT>
{
    /// Generates the first message of the Scalar party
    pub fn new(scalar: GF128, prf_keys: [[u8; KEY_SIZE]; WEIGHT]) -> Self {
        let mut i = 0;
        Self {
            prf_keys,
            scalar,
            puncturers: [0; WEIGHT].map(|_| {
                i += 1;
                Puncturer::<KEY_SIZE, INPUT_BITLEN>::new(&prf_keys[i - 1])
            }),
        }
    }

    pub fn create_first_message(&mut self) -> ScalarFirstMessage<WEIGHT, INPUT_BITLEN> {
        let mut i = 0;
        [0; WEIGHT].map(|_| {
            i += 1;
            self.puncturers[i - 1].make_first_msg()
        })
    }

    pub fn create_second_message(
        &mut self,
        vector_msg: &VectorFirstMessage<WEIGHT, INPUT_BITLEN>,
    ) -> ScalarSecondMessage<WEIGHT, INPUT_BITLEN> {
        let mut i = 0;
        [0; WEIGHT].map(|_| {
            i += 1;
            (
                self.puncturers[i - 1].make_second_msg(vector_msg[i - 1]),
                GF128::from(self.puncturers[i - 1].get_full_sum()) + self.scalar,
            )
        })
    }

    pub fn keygen_offline(&self) -> OfflineSparseVoleKey {
        let mut accumulated_vector = prf_eval_all(&self.prf_keys[0], INPUT_BITLEN);
        self.prf_keys[1..].iter().for_each(|k| {
            prf_eval_all(k, INPUT_BITLEN)
                .iter()
                .zip(accumulated_vector.iter_mut())
                .for_each(|(tmp_vec, acc_vec)| {
                    xor_arrays(acc_vec, tmp_vec);
                })
        });
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
