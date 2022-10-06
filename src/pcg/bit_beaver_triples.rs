use std::marker::PhantomData;

use super::packed_random_bit_ot::{PackedRandomBitOtReceiverPcgKey, PackedRandomBitOtSenderPcgKey};
use super::random_bit_ot::{RandomBitOTReceiverOnlinePCGKey, RandomBitOTSenderOnlinePCGKey};
use super::random_ot::{RandomOTReceiverOnlinePCGKey, RandomOTSenderOnlinePCGKey};
use super::sparse_vole::scalar_party::OnlineSparseVoleKey as ScalarPartySparseVoleOnlinePCGKey;
use super::sparse_vole::vector_party::OnlineSparseVoleKey as VectorPartySparseVoleOnlinePCGKey;
use crate::fields::{FieldElement, GF2};

#[derive(Debug, Clone, Copy)]
pub struct BeaverTripletShare<T: FieldElement> {
    pub a_share: T,
    pub b_share: T,
    pub ab_share: T,
}

#[derive(Debug)]
pub struct BeaverTripletBitPartyOnlinePCGKey<S: FieldElement, T: Iterator<Item = (S, S)>> {
    ot_receiver_pcg_key: T,
    phantom_data: PhantomData<S>,
}

impl<S: FieldElement, T: Iterator<Item = (S, S)>> From<T>
    for BeaverTripletBitPartyOnlinePCGKey<S, T>
{
    fn from(ot_receiver_pcg_key: T) -> Self {
        Self {
            ot_receiver_pcg_key,
            phantom_data: PhantomData,
        }
    }
}

impl<const CODE_WEIGHT: usize, F: FieldElement, S: Iterator<Item = [u32; CODE_WEIGHT]>>
    From<VectorPartySparseVoleOnlinePCGKey<CODE_WEIGHT, S>>
    for BeaverTripletBitPartyOnlinePCGKey<
        F,
        PackedRandomBitOtReceiverPcgKey<
            F,
            RandomBitOTReceiverOnlinePCGKey<
                RandomOTReceiverOnlinePCGKey<VectorPartySparseVoleOnlinePCGKey<CODE_WEIGHT, S>>,
            >,
        >,
    >
{
    fn from(key: VectorPartySparseVoleOnlinePCGKey<CODE_WEIGHT, S>) -> Self {
        Self {
            ot_receiver_pcg_key: key.into(),
            phantom_data: PhantomData,
        }
    }
}

impl<S: FieldElement, T: Iterator<Item = (S, S)>> Iterator
    for BeaverTripletBitPartyOnlinePCGKey<S, T>
{
    type Item = BeaverTripletShare<S>;
    fn next(&mut self) -> Option<Self::Item> {
        let (b0, m_b0) = self.ot_receiver_pcg_key.next()?;
        let (b1, m_b1) = self.ot_receiver_pcg_key.next()?;
        Some(BeaverTripletShare {
            a_share: b0,
            b_share: b1,
            ab_share: b0 * b1 + m_b0 + m_b1,
        })
    }
}

#[derive(Debug)]
pub struct BeaverTripletScalarPartyOnlinePCGKey<S, T: Iterator<Item = (S, S)>> {
    ot_sender_pcg_key: T,
}

impl<S: FieldElement, T: Iterator<Item = (S, S)>> From<T>
    for BeaverTripletScalarPartyOnlinePCGKey<S, T>
{
    fn from(ot_sender_pcg_key: T) -> Self {
        Self { ot_sender_pcg_key }
    }
}

impl<const CODE_WEIGHT: usize, F: FieldElement, S: Iterator<Item = [u32; CODE_WEIGHT]>>
    From<ScalarPartySparseVoleOnlinePCGKey<CODE_WEIGHT, S>>
    for BeaverTripletScalarPartyOnlinePCGKey<
        F,
        PackedRandomBitOtSenderPcgKey<
            F,
            RandomBitOTSenderOnlinePCGKey<
                RandomOTSenderOnlinePCGKey<ScalarPartySparseVoleOnlinePCGKey<CODE_WEIGHT, S>>,
            >,
        >,
    >
{
    fn from(key: ScalarPartySparseVoleOnlinePCGKey<CODE_WEIGHT, S>) -> Self {
        Self {
            ot_sender_pcg_key: key.into(),
        }
    }
}

impl<S: FieldElement, T: Iterator<Item = (S, S)>> Iterator
    for BeaverTripletScalarPartyOnlinePCGKey<S, T>
{
    type Item = BeaverTripletShare<S>;
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

#[cfg(test)]
mod tests {
    use crate::fields::{GF128, GF2};

    use super::{BeaverTripletBitPartyOnlinePCGKey, BeaverTripletScalarPartyOnlinePCGKey};
    #[test]
    fn get_correlation() {
        let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let (scalar_sparse_vole_key, vector_sparse_vole_key) =
            super::super::sparse_vole::tests::get_correlation(&scalar);
        let scalar_bit_beaver_triplet_online_key: BeaverTripletScalarPartyOnlinePCGKey<GF2, _> =
            scalar_sparse_vole_key.into();
        let vector_bit_beaver_triplet_online_key: BeaverTripletBitPartyOnlinePCGKey<GF2, _> =
            vector_sparse_vole_key.into();

        scalar_bit_beaver_triplet_online_key
            .zip(vector_bit_beaver_triplet_online_key)
            .take(30000)
            .for_each(|(u, v)| {
                assert_eq!(
                    (u.a_share + v.a_share) * (u.b_share + v.b_share),
                    (u.ab_share + v.ab_share)
                );
            })
    }
}
