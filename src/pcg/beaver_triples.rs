use crate::fields::GF128;

use super::random_ot::{RandomOTReceiverOnlinePCGKey, RandomOTSenderOnlinePCGKey};

pub struct BeaverTripletShare {
    a_share: GF128,
    b_share: GF128,
    ab_share: GF128,
}

pub struct BeaverTripletBitPartyOnlinePCGKey {
    ot_receiver_pcg_key: RandomOTReceiverOnlinePCGKey,
}

impl Iterator for BeaverTripletBitPartyOnlinePCGKey {
    type Item = BeaverTripletShare;
    fn next(&mut self) -> Option<Self::Item> {
        let (b0, m_b0) = self.ot_receiver_pcg_key.next()?;
        let (b1, m_b1) = self.ot_receiver_pcg_key.next()?;
        Some(BeaverTripletShare {
            a_share: b0.into(),
            b_share: b1.into(),
            ab_share: GF128::from(b0 * b1) + m_b0 + m_b1,
        })
    }
}

pub struct BeaverTriplerScalarPartyOnlinePCGKey {
    ot_receiver_pcg_key: RandomOTSenderOnlinePCGKey,
}

impl Iterator for BeaverTriplerScalarPartyOnlinePCGKey {
    type Item = BeaverTripletShare;
    fn next(&mut self) -> Option<Self::Item> {
        let (x_0, mut y_0) = self.ot_receiver_pcg_key.next()?;
        let (x_1, mut y_1) = self.ot_receiver_pcg_key.next()?;
        y_0 -= x_0;
        y_1 -= x_1;
        Some(BeaverTripletShare {
            a_share: y_1,
            b_share: y_0,
            ab_share: y_1 * y_0 - x_0 - x_1,
        })
    }
}
