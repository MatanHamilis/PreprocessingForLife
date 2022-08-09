use crate::fields::GF2;

use super::random_ot::{RandomOTReceiverOnlinePCGKey, RandomOTSenderOnlinePCGKey};
use super::sparse_vole::scalar_party::OnlineSparseVoleKey as OnlineSparseVoleKeyScalar;
use super::sparse_vole::vector_party::OnlineSparseVoleKey as OnlineSparseVoleKeyVector;
#[derive(Debug)]
pub struct RandomBitOTSenderOnlinePCGKey<
    const CODE_WEIGHT: usize,
    S: Iterator<Item = [usize; CODE_WEIGHT]>,
> {
    random_ot_pcg_key: RandomOTSenderOnlinePCGKey<CODE_WEIGHT, S>,
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>>
    From<RandomOTSenderOnlinePCGKey<CODE_WEIGHT, S>>
    for RandomBitOTSenderOnlinePCGKey<CODE_WEIGHT, S>
{
    fn from(random_ot_pcg_key: RandomOTSenderOnlinePCGKey<CODE_WEIGHT, S>) -> Self {
        Self { random_ot_pcg_key }
    }
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>>
    From<OnlineSparseVoleKeyScalar<CODE_WEIGHT, S>>
    for RandomBitOTSenderOnlinePCGKey<CODE_WEIGHT, S>
{
    fn from(key: OnlineSparseVoleKeyScalar<CODE_WEIGHT, S>) -> Self {
        Self {
            random_ot_pcg_key: key.into(),
        }
    }
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>> Iterator
    for RandomBitOTSenderOnlinePCGKey<CODE_WEIGHT, S>
{
    type Item = (GF2, GF2);
    fn next(&mut self) -> Option<Self::Item> {
        let (m_1, m_2) = self.random_ot_pcg_key.next()?;
        Some((m_1.get_bit(0).into(), m_2.get_bit(0).into()))
    }
}
#[derive(Debug)]
pub struct RandomBitOTReceiverOnlinePCGKey<
    const CODE_WEIGHT: usize,
    S: Iterator<Item = [usize; CODE_WEIGHT]>,
> {
    random_ot_pcg_key: RandomOTReceiverOnlinePCGKey<CODE_WEIGHT, S>,
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>>
    From<RandomOTReceiverOnlinePCGKey<CODE_WEIGHT, S>>
    for RandomBitOTReceiverOnlinePCGKey<CODE_WEIGHT, S>
{
    fn from(random_ot_pcg_key: RandomOTReceiverOnlinePCGKey<CODE_WEIGHT, S>) -> Self {
        Self { random_ot_pcg_key }
    }
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>>
    From<OnlineSparseVoleKeyVector<CODE_WEIGHT, S>>
    for RandomBitOTReceiverOnlinePCGKey<CODE_WEIGHT, S>
{
    fn from(key: OnlineSparseVoleKeyVector<CODE_WEIGHT, S>) -> Self {
        Self {
            random_ot_pcg_key: key.into(),
        }
    }
}

impl<const CODE_WEIGHT: usize, S: Iterator<Item = [usize; CODE_WEIGHT]>> Iterator
    for RandomBitOTReceiverOnlinePCGKey<CODE_WEIGHT, S>
{
    type Item = (GF2, GF2);
    fn next(&mut self) -> Option<Self::Item> {
        let (b, mb) = self.random_ot_pcg_key.next()?;
        Some((b, mb.get_bit(0).into()))
    }
}
