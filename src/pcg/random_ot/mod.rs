use super::sparse_vole::scalar_party::PcgItem as ScalarPcgItem;
use super::sparse_vole::vector_party::PcgItem as VectorPcgItem;
use crate::fields::{GF128, GF2};
use crate::pseudorandom::hash::correlation_robust_hash_block_field;
use std::iter::Iterator;

pub type SenderRandomOtPcgItem = (GF128, GF128);
pub type ReceiverRandomOtPcgItem = (GF2, GF128);

#[derive(Debug)]
pub struct RandomOTSenderOnlinePCGKey<T: Iterator<Item = ScalarPcgItem>> {
    vole_online_key: T,
}

impl<T: Iterator<Item = ScalarPcgItem>> From<T> for RandomOTSenderOnlinePCGKey<T> {
    fn from(vole_online_key: T) -> Self {
        Self { vole_online_key }
    }
}

impl<T: Iterator<Item = ScalarPcgItem>> Iterator for RandomOTSenderOnlinePCGKey<T> {
    type Item = SenderRandomOtPcgItem;
    fn next(&mut self) -> Option<Self::Item> {
        self.vole_online_key.next().map(|(v, scalar)| {
            (
                correlation_robust_hash_block_field(v),
                correlation_robust_hash_block_field(v + scalar),
            )
        })
    }
}

#[derive(Debug)]
pub struct RandomOTReceiverOnlinePCGKey<T: Iterator<Item = VectorPcgItem>> {
    vole_online_key: T,
}

impl<T: Iterator<Item = VectorPcgItem>> From<T> for RandomOTReceiverOnlinePCGKey<T> {
    fn from(vole_online_key: T) -> Self {
        Self { vole_online_key }
    }
}
impl<T: Iterator<Item = VectorPcgItem>> Iterator for RandomOTReceiverOnlinePCGKey<T> {
    type Item = ReceiverRandomOtPcgItem;
    fn next(&mut self) -> Option<Self::Item> {
        self.vole_online_key
            .next()
            .map(|(bit, field_element)| (bit, correlation_robust_hash_block_field(field_element)))
    }
}
