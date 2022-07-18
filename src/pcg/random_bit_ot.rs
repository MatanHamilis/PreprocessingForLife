use crate::fields::{FieldElement, GF128, GF2};

use super::random_ot::{RandomOTReceiverOnlinePCGKey, RandomOTSenderOnlinePCGKey};
#[derive(Debug)]
pub struct RandomBitOTSenderOnlinePCGKey<const CODE_WEIGHT: usize> {
    random_ot_pcg_key: RandomOTSenderOnlinePCGKey<CODE_WEIGHT>,
}

impl<const CODE_WEIGHT: usize> From<RandomOTSenderOnlinePCGKey<CODE_WEIGHT>>
    for RandomBitOTSenderOnlinePCGKey<CODE_WEIGHT>
{
    fn from(random_ot_pcg_key: RandomOTSenderOnlinePCGKey<CODE_WEIGHT>) -> Self {
        Self { random_ot_pcg_key }
    }
}

impl<const CODE_WEIGHT: usize> Iterator for RandomBitOTSenderOnlinePCGKey<CODE_WEIGHT> {
    type Item = (GF2, GF2);
    fn next(&mut self) -> Option<Self::Item> {
        let (m_1, m_2) = self.random_ot_pcg_key.next()?;
        Some((m_1.get_bit(0).into(), m_2.get_bit(0).into()))
    }
}
#[derive(Debug)]
pub struct RandomBitOTReceiverOnlinePCGKey<const CODE_WEIGHT: usize> {
    random_ot_pcg_key: RandomOTReceiverOnlinePCGKey<CODE_WEIGHT>,
}

impl<const CODE_WEIGHT: usize> From<RandomOTReceiverOnlinePCGKey<CODE_WEIGHT>>
    for RandomBitOTReceiverOnlinePCGKey<CODE_WEIGHT>
{
    fn from(random_ot_pcg_key: RandomOTReceiverOnlinePCGKey<CODE_WEIGHT>) -> Self {
        Self { random_ot_pcg_key }
    }
}

impl<const CODE_WEIGHT: usize> Iterator for RandomBitOTReceiverOnlinePCGKey<CODE_WEIGHT> {
    type Item = (GF2, GF2);
    fn next(&mut self) -> Option<Self::Item> {
        let (b, mb) = self.random_ot_pcg_key.next()?;
        Some((b, mb.get_bit(0).into()))
    }
}
