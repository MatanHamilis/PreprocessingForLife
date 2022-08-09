use super::sparse_vole::scalar_party::OnlineSparseVoleKey as ScalarSparseVoleOnlineKey;
use super::sparse_vole::vector_party::OnlineSparseVoleKey as VectorSparseVoleOnlineKey;
use crate::fields::{GF128, GF2};
use crate::pseudorandom::hash::correlation_robust_hash_block_field;
use std::iter::Iterator;

#[derive(Debug)]
pub struct RandomOTSenderOnlinePCGKey<
    const CODE_WEIGHT: usize,
    S: Iterator<Item = [usize; CODE_WEIGHT]>,
> {
    vole_online_key: ScalarSparseVoleOnlineKey<CODE_WEIGHT, S>,
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>>
    From<ScalarSparseVoleOnlineKey<CODE_WEIGHT, S>> for RandomOTSenderOnlinePCGKey<CODE_WEIGHT, S>
{
    fn from(vole_online_key: ScalarSparseVoleOnlineKey<CODE_WEIGHT, S>) -> Self {
        Self { vole_online_key }
    }
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>> Iterator
    for RandomOTSenderOnlinePCGKey<CODE_WEIGHT, S>
{
    type Item = (GF128, GF128);
    fn next(&mut self) -> Option<Self::Item> {
        match self.vole_online_key.next() {
            None => None,
            Some(v) => Some((
                correlation_robust_hash_block_field(v),
                correlation_robust_hash_block_field(v + self.vole_online_key.scalar),
            )),
        }
    }
}

#[derive(Debug)]
pub struct RandomOTReceiverOnlinePCGKey<
    const CODE_WEIGHT: usize,
    S: Iterator<Item = [usize; CODE_WEIGHT]>,
> {
    vole_online_key: VectorSparseVoleOnlineKey<CODE_WEIGHT, S>,
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>>
    From<VectorSparseVoleOnlineKey<CODE_WEIGHT, S>>
    for RandomOTReceiverOnlinePCGKey<CODE_WEIGHT, S>
{
    fn from(vole_online_key: VectorSparseVoleOnlineKey<CODE_WEIGHT, S>) -> Self {
        Self { vole_online_key }
    }
}
impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>> Iterator
    for RandomOTReceiverOnlinePCGKey<CODE_WEIGHT, S>
{
    type Item = (GF2, GF128);
    fn next(&mut self) -> Option<Self::Item> {
        self.vole_online_key
            .next()
            .map(|(bit, field_element)| (bit, correlation_robust_hash_block_field(field_element)))
    }
}
