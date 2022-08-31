use super::random_ot::{
    RandomOTReceiverOnlinePCGKey, RandomOTSenderOnlinePCGKey, ReceiverRandomOtPcgItem,
    SenderRandomOtPcgItem,
};
use super::sparse_vole::scalar_party::{
    OnlineSparseVoleKey as OnlineSparseVoleKeyScalar, PcgItem as PcgItemScalar,
};
use super::sparse_vole::vector_party::{
    OnlineSparseVoleKey as OnlineSparseVoleKeyVector, PcgItem as PcgItemVector,
};
use crate::fields::GF2;

pub type SenderRandomBitOtPcgItem = (GF2, GF2);
pub type ReceiverRandomBitOtPcgItem = (GF2, GF2);

#[derive(Debug)]
pub struct RandomBitOTSenderOnlinePCGKey<T: Iterator<Item = SenderRandomOtPcgItem>> {
    random_ot_pcg_key: T,
}

impl<T: Iterator<Item = SenderRandomOtPcgItem>> From<T> for RandomBitOTSenderOnlinePCGKey<T> {
    fn from(random_ot_pcg_key: T) -> Self {
        Self { random_ot_pcg_key }
    }
}

impl<T: Iterator<Item = PcgItemScalar>> From<T>
    for RandomBitOTSenderOnlinePCGKey<RandomOTSenderOnlinePCGKey<T>>
{
    fn from(key: T) -> Self {
        Self {
            random_ot_pcg_key: key.into(),
        }
    }
}

impl<T: Iterator<Item = SenderRandomOtPcgItem>> Iterator for RandomBitOTSenderOnlinePCGKey<T> {
    type Item = (GF2, GF2);
    fn next(&mut self) -> Option<Self::Item> {
        let (m_1, m_2) = self.random_ot_pcg_key.next()?;
        Some((m_1.get_bit(0).into(), m_2.get_bit(0).into()))
    }
}
#[derive(Debug)]
pub struct RandomBitOTReceiverOnlinePCGKey<T: Iterator<Item = ReceiverRandomOtPcgItem>> {
    random_ot_pcg_key: T,
}

impl<T: Iterator<Item = ReceiverRandomOtPcgItem>> From<T> for RandomBitOTReceiverOnlinePCGKey<T> {
    fn from(random_ot_pcg_key: T) -> Self {
        Self { random_ot_pcg_key }
    }
}

impl<T: Iterator<Item = PcgItemVector>> From<T>
    for RandomBitOTReceiverOnlinePCGKey<RandomOTReceiverOnlinePCGKey<T>>
{
    fn from(key: T) -> Self {
        Self {
            random_ot_pcg_key: key.into(),
        }
    }
}

impl<T: Iterator<Item = ReceiverRandomOtPcgItem>> Iterator for RandomBitOTReceiverOnlinePCGKey<T> {
    type Item = (GF2, GF2);
    fn next(&mut self) -> Option<Self::Item> {
        let (b, mb) = self.random_ot_pcg_key.next()?;
        Some((b, mb.get_bit(0).into()))
    }
}
