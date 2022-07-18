use crate::fields::{FieldElement, GF2};

use super::{
    random_bit_ot::{RandomBitOTReceiverOnlinePCGKey, RandomBitOTSenderOnlinePCGKey},
    random_ot::RandomOTReceiverOnlinePCGKey,
};

#[derive(Debug)]
pub struct BeaverTripletShare<T: FieldElement> {
    pub a_share: T,
    pub b_share: T,
    pub ab_share: T,
}

#[derive(Debug)]
pub struct BeaverTripletBitPartyOnlinePCGKey<const CODE_WEIGHT: usize> {
    ot_receiver_pcg_key: RandomBitOTReceiverOnlinePCGKey<CODE_WEIGHT>,
}

impl<const CODE_WEIGHT: usize> From<RandomBitOTReceiverOnlinePCGKey<CODE_WEIGHT>>
    for BeaverTripletBitPartyOnlinePCGKey<CODE_WEIGHT>
{
    fn from(ot_receiver_pcg_key: RandomBitOTReceiverOnlinePCGKey<CODE_WEIGHT>) -> Self {
        Self {
            ot_receiver_pcg_key,
        }
    }
}

impl<const CODE_WEIGHT: usize> Iterator for BeaverTripletBitPartyOnlinePCGKey<CODE_WEIGHT> {
    type Item = BeaverTripletShare<GF2>;
    fn next(&mut self) -> Option<Self::Item> {
        let (b0, m_b0) = self.ot_receiver_pcg_key.next()?;
        let (b1, m_b1) = self.ot_receiver_pcg_key.next()?;
        Some(BeaverTripletShare {
            a_share: b0.into(),
            b_share: b1.into(),
            ab_share: b0 * b1 + m_b0 + m_b1,
        })
    }
}

#[derive(Debug)]
pub struct BeaverTriplerScalarPartyOnlinePCGKey<const CODE_WEIGHT: usize> {
    ot_sender_pcg_key: RandomBitOTSenderOnlinePCGKey<CODE_WEIGHT>,
}

impl<const CODE_WEIGHT: usize> From<RandomBitOTSenderOnlinePCGKey<CODE_WEIGHT>>
    for BeaverTriplerScalarPartyOnlinePCGKey<CODE_WEIGHT>
{
    fn from(ot_sender_pcg_key: RandomBitOTSenderOnlinePCGKey<CODE_WEIGHT>) -> Self {
        Self { ot_sender_pcg_key }
    }
}

impl<const CODE_WEIGHT: usize> Iterator for BeaverTriplerScalarPartyOnlinePCGKey<CODE_WEIGHT> {
    type Item = BeaverTripletShare<GF2>;
    fn next(&mut self) -> Option<Self::Item> {
        let (x_0, mut y_0) = self.ot_sender_pcg_key.next()?;
        let (x_1, mut y_1) = self.ot_sender_pcg_key.next()?;
        y_0 -= x_0;
        y_1 -= x_1;
        Some(BeaverTripletShare {
            a_share: y_1,
            b_share: y_0,
            ab_share: y_1 * y_0 - x_0 - x_1,
        })
    }
}
