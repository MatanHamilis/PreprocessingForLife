use std::marker::PhantomData;

use super::bit_beaver_triples::BeaverTripletShare;
use super::sparse_vole::scalar_party;
use crate::fields::{FieldElement, GF128, GF2};
use crate::pseudorandom::hash::correlation_robust_hash_block_field;
pub struct PcgKeySender<T: Iterator<Item = scalar_party::PcgItem>> {
    vole_pcg: T,
}

impl<T: Iterator<Item = scalar_party::PcgItem>> From<T> for PcgKeySender<T> {
    fn from(value: T) -> Self {
        Self { vole_pcg: value }
    }
}
impl<T: Iterator<Item = scalar_party::PcgItem>> PcgKeySender<T> {
    pub fn next_random_string_ot_sender(&mut self) -> Option<(GF128, GF128)> {
        let (v, scalar) = self.vole_pcg.next()?;
        Some((
            correlation_robust_hash_block_field(v),
            correlation_robust_hash_block_field(v + scalar),
        ))
    }

    pub fn iter_random_string_ot_sender(&mut self) -> RandomStringOTSenderKey<'_, T> {
        RandomStringOTSenderKey { key: self }
    }

    pub fn next_random_bit_ot_sender(&mut self) -> Option<(GF2, GF2)> {
        let (m_0, m_1) = self.next_random_string_ot_sender()?;
        Some((m_0.get_bit(0).into(), m_1.get_bit(0).into()))
    }

    pub fn iter_random_bit_ot_sender(&mut self) -> RandomBitOTSenderKey<'_, T> {
        RandomBitOTSenderKey { key: self }
    }

    pub fn next_packed_random_bit_ot_sender<S: FieldElement>(&mut self) -> Option<(S, S)> {
        let mut output_first = S::zero();
        let mut output_second = S::zero();
        for bit_idx in 0..S::BITS {
            let (m_0, m_1) = self.next_random_bit_ot_sender()?;
            output_first.set_bit(m_0.into(), bit_idx);
            output_second.set_bit(m_1.into(), bit_idx);
        }
        Some((output_first, output_second))
    }

    pub fn iter_packed_random_bit_ot_sender<S: FieldElement>(
        &mut self,
    ) -> RandomPackedBitOTSenderKey<'_, T, S> {
        RandomPackedBitOTSenderKey {
            key: self,
            phantom: PhantomData,
        }
    }

    pub fn next_bit_beaver_triple(&mut self) -> Option<BeaverTripletShare<GF2>> {
        let (mut y_0, x_0) = self.next_random_bit_ot_sender()?;
        let (mut y_1, x_1) = self.next_random_bit_ot_sender()?;
        y_0 -= x_0;
        y_1 -= x_1;
        Some(BeaverTripletShare {
            a_share: y_1,
            b_share: y_0,
            ab_share: y_1 * y_0 - x_0 - x_1,
        })
    }

    pub fn iter_bit_beaver_triple(&mut self) -> BitBeaverTripletKey<'_, T> {
        BitBeaverTripletKey { key: self }
    }

    pub fn next_beaver_triple<S: FieldElement>(&mut self) -> Option<BeaverTripletShare<S>> {
        let (mut y_0, x_0) = self.next_packed_random_bit_ot_sender()?;
        let (mut y_1, x_1) = self.next_packed_random_bit_ot_sender()?;
        y_0 -= x_0;
        y_1 -= x_1;
        Some(BeaverTripletShare {
            a_share: y_1,
            b_share: y_0,
            ab_share: y_1 * y_0 - x_0 - x_1,
        })
    }

    pub fn iter_beaver_triple<S: FieldElement>(&mut self) -> BeaverTripletKey<'_, T, S> {
        BeaverTripletKey {
            key: self,
            phantom: PhantomData,
        }
    }
}

pub struct RandomStringOTSenderKey<'a, T: Iterator<Item = scalar_party::PcgItem>> {
    key: &'a mut PcgKeySender<T>,
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>> RandomStringOTSenderKey<'a, T> {
    pub fn new(key: &'a mut PcgKeySender<T>) -> Self {
        Self { key }
    }
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>> Iterator for RandomStringOTSenderKey<'a, T> {
    type Item = (GF128, GF128);
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_random_string_ot_sender()
    }
}

pub struct RandomBitOTSenderKey<'a, T: Iterator<Item = scalar_party::PcgItem>> {
    key: &'a mut PcgKeySender<T>,
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>> RandomBitOTSenderKey<'a, T> {
    pub fn new(key: &'a mut PcgKeySender<T>) -> Self {
        Self { key }
    }
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>> Iterator for RandomBitOTSenderKey<'a, T> {
    type Item = (GF2, GF2);
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_random_bit_ot_sender()
    }
}

pub struct RandomPackedBitOTSenderKey<
    'a,
    T: Iterator<Item = scalar_party::PcgItem>,
    S: FieldElement,
> {
    key: &'a mut PcgKeySender<T>,
    phantom: PhantomData<S>,
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>, S: FieldElement>
    RandomPackedBitOTSenderKey<'a, T, S>
{
    pub fn new(key: &'a mut PcgKeySender<T>) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>, S: FieldElement> Iterator
    for RandomPackedBitOTSenderKey<'a, T, S>
{
    type Item = (S, S);
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_packed_random_bit_ot_sender()
    }
}

pub struct BitBeaverTripletKey<'a, T: Iterator<Item = scalar_party::PcgItem>> {
    key: &'a mut PcgKeySender<T>,
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>> BitBeaverTripletKey<'a, T> {
    pub fn new(key: &'a mut PcgKeySender<T>) -> Self {
        Self { key }
    }
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>> Iterator for BitBeaverTripletKey<'a, T> {
    type Item = BeaverTripletShare<GF2>;
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_bit_beaver_triple()
    }
}

pub struct BeaverTripletKey<'a, T: Iterator<Item = scalar_party::PcgItem>, S: FieldElement> {
    key: &'a mut PcgKeySender<T>,
    phantom: PhantomData<S>,
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>, S: FieldElement> BeaverTripletKey<'a, T, S> {
    pub fn new(key: &'a mut PcgKeySender<T>) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }
}
impl<'a, T: Iterator<Item = scalar_party::PcgItem>, S: FieldElement> Iterator
    for BeaverTripletKey<'a, T, S>
{
    type Item = BeaverTripletShare<S>;
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_beaver_triple()
    }
}
