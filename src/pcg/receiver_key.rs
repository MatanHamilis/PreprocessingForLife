use std::marker::PhantomData;

use super::bit_beaver_triples::BeaverTripletShare;
use super::sparse_vole::vector_party;
use crate::fields::{FieldElement, GF128, GF2};
use crate::pseudorandom::hash::correlation_robust_hash_block_field;

pub struct PcgKeyReceiver<T: Iterator<Item = vector_party::PcgItem>> {
    vole_pcg: T,
}

impl<T: Iterator<Item = vector_party::PcgItem>> From<T> for PcgKeyReceiver<T> {
    fn from(value: T) -> Self {
        Self { vole_pcg: value }
    }
}
impl<T: Iterator<Item = vector_party::PcgItem>> PcgKeyReceiver<T> {
    pub fn next_random_string_ot_receiver(&mut self) -> Option<(GF2, GF128)> {
        let (bit, v) = self.vole_pcg.next()?;
        Some((bit, correlation_robust_hash_block_field(v)))
    }

    pub fn iter_random_string_ot_receiver(&mut self) -> RandomStringOTReceiverKey<'_, T> {
        RandomStringOTReceiverKey { key: self }
    }

    pub fn next_random_bit_ot_receiver(&mut self) -> Option<(GF2, GF2)> {
        let (b, m_b) = self.next_random_string_ot_receiver()?;
        Some((b, m_b.get_bit(0).into()))
    }

    pub fn iter_random_bit_ot_receiver(&mut self) -> RandomBitOTReceiverKey<'_, T> {
        RandomBitOTReceiverKey { key: self }
    }

    pub fn next_packed_random_bit_ot_receiver<S: FieldElement>(&mut self) -> Option<(S, S)> {
        let mut output_first = S::zero();
        let mut output_second = S::zero();
        for bit_idx in 0..S::BITS {
            let (m_0, m_1) = self.next_random_bit_ot_receiver()?;
            output_first.set_bit(m_0.into(), bit_idx);
            output_second.set_bit(m_1.into(), bit_idx);
        }
        Some((output_first, output_second))
    }

    pub fn iter_packed_random_bit_ot_receiver<S: FieldElement>(
        &mut self,
    ) -> RandomPackedBitOTReceiverKey<'_, T, S> {
        RandomPackedBitOTReceiverKey {
            key: self,
            phantom: PhantomData,
        }
    }

    pub fn next_bit_beaver_triple(&mut self) -> Option<BeaverTripletShare<GF2>> {
        let (b0, m_b0) = self.next_random_bit_ot_receiver()?;
        let (b1, m_b1) = self.next_random_bit_ot_receiver()?;
        Some(BeaverTripletShare {
            a_share: b0,
            b_share: b1,
            ab_share: b0 * b1 + m_b0 + m_b1,
        })
    }

    pub fn iter_bit_beaver_triple(&mut self) -> BitBeaverTripletKey<'_, T> {
        BitBeaverTripletKey { key: self }
    }

    pub fn next_beaver_triple<S: FieldElement>(&mut self) -> Option<BeaverTripletShare<S>> {
        let (b0, m_b0) = self.next_packed_random_bit_ot_receiver()?;
        let (b1, m_b1) = self.next_packed_random_bit_ot_receiver()?;
        Some(BeaverTripletShare {
            a_share: b0,
            b_share: b1,
            ab_share: b0 * b1 + m_b0 + m_b1,
        })
    }

    pub fn iter_beaver_triple<S: FieldElement>(&mut self) -> BeaverTripletKey<'_, T, S> {
        BeaverTripletKey {
            key: self,
            phantom: PhantomData,
        }
    }
}

pub struct RandomStringOTReceiverKey<'a, T: Iterator<Item = vector_party::PcgItem>> {
    key: &'a mut PcgKeyReceiver<T>,
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>> RandomStringOTReceiverKey<'a, T> {
    pub fn new(key: &'a mut PcgKeyReceiver<T>) -> Self {
        Self { key }
    }
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>> Iterator for RandomStringOTReceiverKey<'a, T> {
    type Item = (GF2, GF128);
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_random_string_ot_receiver()
    }
}

pub struct RandomBitOTReceiverKey<'a, T: Iterator<Item = vector_party::PcgItem>> {
    key: &'a mut PcgKeyReceiver<T>,
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>> RandomBitOTReceiverKey<'a, T> {
    pub fn new(key: &'a mut PcgKeyReceiver<T>) -> Self {
        Self { key }
    }
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>> Iterator for RandomBitOTReceiverKey<'a, T> {
    type Item = (GF2, GF2);
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_random_bit_ot_receiver()
    }
}

pub struct RandomPackedBitOTReceiverKey<
    'a,
    T: Iterator<Item = vector_party::PcgItem>,
    S: FieldElement,
> {
    key: &'a mut PcgKeyReceiver<T>,
    phantom: PhantomData<S>,
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>, S: FieldElement>
    RandomPackedBitOTReceiverKey<'a, T, S>
{
    pub fn new(key: &'a mut PcgKeyReceiver<T>) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>, S: FieldElement> Iterator
    for RandomPackedBitOTReceiverKey<'a, T, S>
{
    type Item = (S, S);
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_packed_random_bit_ot_receiver()
    }
}

pub struct BitBeaverTripletKey<'a, T: Iterator<Item = vector_party::PcgItem>> {
    key: &'a mut PcgKeyReceiver<T>,
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>> BitBeaverTripletKey<'a, T> {
    pub fn new(key: &'a mut PcgKeyReceiver<T>) -> Self {
        Self { key }
    }
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>> Iterator for BitBeaverTripletKey<'a, T> {
    type Item = BeaverTripletShare<GF2>;
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_bit_beaver_triple()
    }
}

pub struct BeaverTripletKey<'a, T: Iterator<Item = vector_party::PcgItem>, S: FieldElement> {
    key: &'a mut PcgKeyReceiver<T>,
    phantom: PhantomData<S>,
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>, S: FieldElement> BeaverTripletKey<'a, T, S> {
    pub fn new(key: &'a mut PcgKeyReceiver<T>) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }
}
impl<'a, T: Iterator<Item = vector_party::PcgItem>, S: FieldElement> Iterator
    for BeaverTripletKey<'a, T, S>
{
    type Item = BeaverTripletShare<S>;
    fn next(&mut self) -> Option<Self::Item> {
        self.key.next_beaver_triple()
    }
}
