use crate::fields::{FieldElement, GF128, GF2};

#[derive(Debug, Clone, Copy)]
pub struct BeaverTripletShare<T: FieldElement> {
    pub a_share: T,
    pub b_share: T,
    pub ab_share: T,
}

pub struct WideBitBeaverTripletShare {
    pub a_share: GF2,
    pub b_shares: GF128,
    pub ab_shares: GF128,
}

#[derive(Debug)]
pub struct WideBeaverTripletShare<T: FieldElement> {
    pub a_share: T,
    pub b_shares: [T; 128],
    pub ab_shares: [T; 128],
}
