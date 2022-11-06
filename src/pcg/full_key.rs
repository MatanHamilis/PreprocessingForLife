use std::marker::PhantomData;

use crate::fields::FieldElement;
use crate::fields::GF2;

use super::bit_beaver_triples::BeaverTripletShare;
use super::bit_beaver_triples::WideBeaverTripletShare;
use super::bit_beaver_triples::WideBitBeaverTripletShare;
use super::receiver_key::PcgKeyReceiver;
use super::sender_key::PcgKeySender;
use super::sparse_vole::scalar_party;
use super::sparse_vole::vector_party;

pub trait CorrelationGenerator {
    fn next_beaver_triple<S: FieldElement>(&mut self) -> Option<BeaverTripletShare<S>>;
    fn next_wide_beaver_triple<S: FieldElement>(&mut self) -> Option<WideBeaverTripletShare<S>>;
}
pub enum Role {
    Sender,
    Receiver,
}
pub struct FullPcgKey<
    T: Iterator<Item = vector_party::PcgItem>,
    S: Iterator<Item = scalar_party::PcgItem>,
> {
    receiver_key: PcgKeyReceiver<T>,
    sender_key: PcgKeySender<S>,
    main_role: Role,
}
impl<T: Iterator<Item = vector_party::PcgItem>, S: Iterator<Item = scalar_party::PcgItem>>
    CorrelationGenerator for FullPcgKey<T, S>
{
    fn next_wide_beaver_triple<F: FieldElement>(&mut self) -> Option<WideBeaverTripletShare<F>> {
        let mut a_share = F::zero();
        let mut b_shares = [F::zero(); 128];
        let mut ab_shares = [F::zero(); 128];
        for i in 0..F::BITS {
            let next_bit_beaver_triple = self.next_wide_bit_beaver_triple()?;
            a_share.set_bit(next_bit_beaver_triple.a_share.into(), i);
            for wide_idx in 0..128 {
                b_shares[wide_idx].set_bit(next_bit_beaver_triple.b_shares.get_bit(wide_idx), i);
                ab_shares[wide_idx].set_bit(next_bit_beaver_triple.ab_shares.get_bit(wide_idx), i);
            }
        }
        Some(WideBeaverTripletShare {
            a_share,
            b_shares,
            ab_shares,
        })
    }
    fn next_beaver_triple<F: FieldElement>(&mut self) -> Option<BeaverTripletShare<F>> {
        Some(match self.main_role {
            Role::Sender => self.sender_key.next_beaver_triple()?,
            Role::Receiver => self.receiver_key.next_beaver_triple()?,
        })
    }
}

impl<T: Iterator<Item = vector_party::PcgItem>, S: Iterator<Item = scalar_party::PcgItem>>
    FullPcgKey<T, S>
{
    pub fn new(sender_key: PcgKeySender<S>, receiver_key: PcgKeyReceiver<T>, role: Role) -> Self {
        Self {
            receiver_key,
            sender_key,
            main_role: role,
        }
    }

    pub fn next_wide_bit_beaver_triple(&mut self) -> Option<WideBitBeaverTripletShare> {
        let (b, m_b) = self.receiver_key.next_random_string_ot_receiver()?;
        let (m_0, mut m_1) = self.sender_key.next_random_string_ot_sender()?;
        m_1 -= m_0;
        Some(WideBitBeaverTripletShare {
            a_share: b,
            b_shares: m_1,
            ab_shares: m_1 * b + m_b + m_0,
        })
    }

    pub fn next_bit_beaver_triple(&mut self) -> Option<BeaverTripletShare<GF2>> {
        Some(match self.main_role {
            Role::Sender => self.sender_key.next_bit_beaver_triple()?,
            Role::Receiver => self.receiver_key.next_bit_beaver_triple()?,
        })
    }
}
impl<T: Iterator<Item = vector_party::PcgItem>, S: Iterator<Item = scalar_party::PcgItem>>
    AsMut<PcgKeyReceiver<T>> for FullPcgKey<T, S>
{
    fn as_mut(&mut self) -> &mut PcgKeyReceiver<T> {
        &mut self.receiver_key
    }
}

impl<T: Iterator<Item = vector_party::PcgItem>, S: Iterator<Item = scalar_party::PcgItem>>
    AsRef<PcgKeyReceiver<T>> for FullPcgKey<T, S>
{
    fn as_ref(&self) -> &PcgKeyReceiver<T> {
        &self.receiver_key
    }
}

impl<T: Iterator<Item = vector_party::PcgItem>, S: Iterator<Item = scalar_party::PcgItem>>
    AsMut<PcgKeySender<S>> for FullPcgKey<T, S>
{
    fn as_mut(&mut self) -> &mut PcgKeySender<S> {
        &mut self.sender_key
    }
}

impl<T: Iterator<Item = vector_party::PcgItem>, S: Iterator<Item = scalar_party::PcgItem>>
    AsRef<PcgKeySender<S>> for FullPcgKey<T, S>
{
    fn as_ref(&self) -> &PcgKeySender<S> {
        &self.sender_key
    }
}

pub struct BitBeaverTripletKey<
    'a,
    IT: Iterator<Item = vector_party::PcgItem>,
    IS: Iterator<Item = scalar_party::PcgItem>,
> {
    full_pcg_key: &'a mut FullPcgKey<IT, IS>,
}

impl<
        'a,
        IT: Iterator<Item = vector_party::PcgItem>,
        IS: Iterator<Item = scalar_party::PcgItem>,
    > Iterator for BitBeaverTripletKey<'a, IT, IS>
{
    type Item = BeaverTripletShare<GF2>;
    fn next(&mut self) -> Option<Self::Item> {
        self.full_pcg_key.next_beaver_triple()
    }
}
pub struct BeaverTripletKey<
    'a,
    S: FieldElement,
    IT: Iterator<Item = vector_party::PcgItem>,
    IS: Iterator<Item = scalar_party::PcgItem>,
> {
    full_pcg_key: &'a mut FullPcgKey<IT, IS>,
    phantom: PhantomData<S>,
}

impl<
        'a,
        S: FieldElement,
        IT: Iterator<Item = vector_party::PcgItem>,
        IS: Iterator<Item = scalar_party::PcgItem>,
    > Iterator for BeaverTripletKey<'a, S, IT, IS>
{
    type Item = BeaverTripletShare<S>;
    fn next(&mut self) -> Option<Self::Item> {
        self.full_pcg_key.next_beaver_triple()
    }
}

pub struct WideBitBeaverTripletKey<
    'a,
    IT: Iterator<Item = vector_party::PcgItem>,
    IS: Iterator<Item = scalar_party::PcgItem>,
> {
    full_pcg_key: &'a mut FullPcgKey<IT, IS>,
}

impl<
        'a,
        IT: Iterator<Item = vector_party::PcgItem>,
        IS: Iterator<Item = scalar_party::PcgItem>,
    > Iterator for WideBitBeaverTripletKey<'a, IT, IS>
{
    type Item = WideBitBeaverTripletShare;
    fn next(&mut self) -> Option<Self::Item> {
        self.full_pcg_key.next_wide_bit_beaver_triple()
    }
}

pub struct WideBeaverTripletKey<
    'a,
    F: FieldElement,
    IT: Iterator<Item = vector_party::PcgItem>,
    IS: Iterator<Item = scalar_party::PcgItem>,
> {
    full_pcg_key: &'a mut FullPcgKey<IT, IS>,
    phantom: PhantomData<F>,
}

impl<
        'a,
        F: FieldElement,
        IT: Iterator<Item = vector_party::PcgItem>,
        IS: Iterator<Item = scalar_party::PcgItem>,
    > Iterator for WideBeaverTripletKey<'a, F, IT, IS>
{
    type Item = WideBeaverTripletShare<F>;
    fn next(&mut self) -> Option<Self::Item> {
        self.full_pcg_key.next_wide_beaver_triple()
    }
}
