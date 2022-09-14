use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};

use super::super::pprf_aggregator::PprfAggregator;
use super::super::{xor_arrays, KEY_SIZE};
use super::vector_party::VectorFirstMessage;
use super::FirstMessageItem;
use crate::communicator::Communicator;
use crate::fields::GF128;
use crate::pcg::pprf_aggregator::RegularErrorPprfAggregator;
use crate::pprf::distributed_generation::{Puncturer, SenderSecondMessage};
use serde_big_array::BigArray;

pub type PcgItem = (GF128, GF128);

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

pub type ScalarFirstMessage<const INPUT_BITLEN: usize> = Vec<FirstMessageItem<INPUT_BITLEN>>;

#[derive(Serialize, Deserialize)]
pub struct ScalarSecondMessageItem<const INPUT_BITLEN: usize> {
    #[serde(with = "BigArray")]
    pub(super) ots: [SenderSecondMessage<KEY_SIZE>; INPUT_BITLEN],
    #[serde(with = "BigArray")]
    pub(super) sums: [u8; KEY_SIZE],
}

impl<const INPUT_BITLEN: usize>
    From<(
        [SenderSecondMessage<KEY_SIZE>; INPUT_BITLEN],
        [u8; KEY_SIZE],
    )> for ScalarSecondMessageItem<INPUT_BITLEN>
{
    fn from(
        v: (
            [SenderSecondMessage<KEY_SIZE>; INPUT_BITLEN],
            [u8; KEY_SIZE],
        ),
    ) -> Self {
        Self {
            ots: v.0,
            sums: v.1,
        }
    }
}

pub type ScalarSecondMessage<const INPUT_BITLEN: usize> =
    Vec<ScalarSecondMessageItem<INPUT_BITLEN>>;

pub struct SparseVolePcgScalarKeyGenState<const INPUT_BITLEN: usize> {
    prf_keys: Vec<[u8; KEY_SIZE]>,
    scalar: GF128,
    puncturers: Vec<Puncturer<KEY_SIZE, INPUT_BITLEN>>,
}

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
            .map(|puncturer| puncturer.make_first_msg().into())
            .collect()
    }

    pub fn create_second_message(
        &mut self,
        vector_msg: VectorFirstMessage<INPUT_BITLEN>,
    ) -> ScalarSecondMessage<INPUT_BITLEN> {
        self.puncturers
            .iter_mut()
            .zip(vector_msg.into_iter())
            .map(|(puncturer, vector_msg_item)| {
                let mut s = puncturer.get_full_sum();
                xor_arrays(&mut s, &self.scalar.into());
                &s;
                (puncturer.make_second_msg(vector_msg_item.into()), s).into()
            })
            .collect()
    }

    pub fn keygen_offline<T: PprfAggregator>(&self) -> OfflineSparseVoleKey {
        let accumulated_vector = T::aggregate(&self.prf_keys, INPUT_BITLEN);
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

pub fn distributed_generation<const PRF_INPUT_BITLEN: usize, T: Write + Read>(
    scalar: &GF128,
    comm: &mut Communicator<T>,
) -> Option<OfflineSparseVoleKey> {
    // Define Gen State
    let prf_keys: Vec<[u8; KEY_SIZE]> = match comm.receive() {
        Some(v) => v,
        None => {
            return None;
        }
    };
    let mut scalar_keygen_state =
        SparseVolePcgScalarKeyGenState::<PRF_INPUT_BITLEN>::new(*scalar, prf_keys);

    let scalar_first_message = scalar_keygen_state.create_first_message();
    comm.send(scalar_first_message);
    let vector_msg: VectorFirstMessage<PRF_INPUT_BITLEN> = comm.receive()?;
    let scalar_second_message = scalar_keygen_state.create_second_message(vector_msg);
    comm.send(scalar_second_message);

    // Create Offline Keys
    let scalar_offline_key = scalar_keygen_state.keygen_offline::<RegularErrorPprfAggregator>();
    Some(scalar_offline_key)
}
