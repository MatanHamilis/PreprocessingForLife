use std::marker::PhantomData;

use super::{
    random_bit_ot::{
        RandomBitOTReceiverOnlinePCGKey, RandomBitOTSenderOnlinePCGKey, ReceiverRandomBitOtPcgItem,
        SenderRandomBitOtPcgItem,
    },
    random_ot::{RandomOTReceiverOnlinePCGKey, RandomOTSenderOnlinePCGKey},
    sparse_vole::{scalar_party, vector_party},
};
use crate::fields::FieldElement;

pub struct PackedRandomBitOtReceiverPcgKey<
    S: FieldElement,
    T: Iterator<Item = ReceiverRandomBitOtPcgItem>,
> {
    iter: T,
    phantom_data: PhantomData<S>,
    buffer_one: Vec<bool>,
    buffer_two: Vec<bool>,
}

impl<S: FieldElement, T: Iterator<Item = ReceiverRandomBitOtPcgItem>> From<T>
    for PackedRandomBitOtReceiverPcgKey<S, T>
{
    fn from(iter: T) -> Self {
        Self {
            iter,
            phantom_data: PhantomData,
            buffer_one: vec![false; S::BITS],
            buffer_two: vec![false; S::BITS],
        }
    }
}

impl<S: FieldElement, T: Iterator<Item = vector_party::PcgItem>> From<T>
    for PackedRandomBitOtReceiverPcgKey<
        S,
        RandomBitOTReceiverOnlinePCGKey<RandomOTReceiverOnlinePCGKey<T>>,
    >
{
    fn from(iter: T) -> Self {
        Self {
            iter: iter.into(),
            phantom_data: PhantomData,
            buffer_one: vec![false; S::BITS],
            buffer_two: vec![false; S::BITS],
        }
    }
}

impl<S: FieldElement, T: Iterator<Item = ReceiverRandomBitOtPcgItem>> Iterator
    for PackedRandomBitOtReceiverPcgKey<S, T>
{
    type Item = (S, S);
    fn next(&mut self) -> Option<Self::Item> {
        for idx in 0..S::BITS {
            let (b0, b1) = self.iter.next()?;
            self.buffer_one[idx] = b0.into();
            self.buffer_two[idx] = b1.into();
        }
        Some((
            S::from_bits(&self.buffer_one)?,
            S::from_bits(&self.buffer_two)?,
        ))
    }
}

pub struct PackedRandomBitOtSenderPcgKey<
    S: FieldElement,
    T: Iterator<Item = SenderRandomBitOtPcgItem>,
> {
    iter: T,
    phantom_data: PhantomData<S>,
    buffer_one: Vec<bool>,
    buffer_two: Vec<bool>,
}

impl<S: FieldElement, T: Iterator<Item = SenderRandomBitOtPcgItem>> From<T>
    for PackedRandomBitOtSenderPcgKey<S, T>
{
    fn from(iter: T) -> Self {
        Self {
            iter,
            phantom_data: PhantomData,
            buffer_one: vec![false; S::BITS],
            buffer_two: vec![false; S::BITS],
        }
    }
}

impl<S: FieldElement, T: Iterator<Item = scalar_party::PcgItem>> From<T>
    for PackedRandomBitOtSenderPcgKey<
        S,
        RandomBitOTSenderOnlinePCGKey<RandomOTSenderOnlinePCGKey<T>>,
    >
{
    fn from(iter: T) -> Self {
        Self {
            iter: iter.into(),
            phantom_data: PhantomData,
            buffer_one: vec![false; S::BITS],
            buffer_two: vec![false; S::BITS],
        }
    }
}

impl<S: FieldElement, T: Iterator<Item = SenderRandomBitOtPcgItem>> Iterator
    for PackedRandomBitOtSenderPcgKey<S, T>
{
    type Item = (S, S);
    fn next(&mut self) -> Option<Self::Item> {
        for idx in 0..S::BITS {
            let (b0, b1) = self.iter.next()?;
            self.buffer_one[idx] = b0.into();
            self.buffer_two[idx] = b1.into();
        }
        Some((
            S::from_bits(&self.buffer_one)?,
            S::from_bits(&self.buffer_two)?,
        ))
    }
}
