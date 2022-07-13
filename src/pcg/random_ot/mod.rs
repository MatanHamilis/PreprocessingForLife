use super::sparse_vole::scalar_party::OnlineSparseVoleKey as ScalarSparseVoleOnlineKey;
use super::sparse_vole::vector_party::OnlineSparseVoleKey as VectorSparseVoleOnlineKey;
use crate::fields::{GF128, GF2};
use crate::pseudorandom::hash::correlation_robust_hash_block_field;
use std::iter::Iterator;

const CODE_WEIGHT: usize = 7;

pub struct RandomOTSenderOnlinePCGKey {
    vole_online_key: ScalarSparseVoleOnlineKey<CODE_WEIGHT>,
}
impl Iterator for RandomOTSenderOnlinePCGKey {
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

pub struct RandomOTReceiverOnlinePCGKey {
    vole_online_key: VectorSparseVoleOnlineKey<CODE_WEIGHT>,
}
impl Iterator for RandomOTReceiverOnlinePCGKey {
    type Item = (GF2, GF128);
    fn next(&mut self) -> Option<Self::Item> {
        match self.vole_online_key.next() {
            None => None,
            Some((bit, field_element)) => {
                Some((bit, correlation_robust_hash_block_field(field_element)))
            }
        }
    }
}
