use super::{
    random_bit_ot::{
        RandomBitOTReceiverOnlinePCGKey, RandomBitOTSenderOnlinePCGKey, ReceiverRandomBitOtPcgItem,
        SenderRandomBitOtPcgItem,
    },
    random_ot::{RandomOTReceiverOnlinePCGKey, RandomOTSenderOnlinePCGKey},
    sparse_vole::{scalar_party, vector_party},
};
use crate::fields::PackedGF2U64;

pub struct PackedRandomBitOtReceiverU64<T: Iterator<Item = ReceiverRandomBitOtPcgItem>> {
    iter: T,
}

impl<T: Iterator<Item = ReceiverRandomBitOtPcgItem>> From<T> for PackedRandomBitOtReceiverU64<T> {
    fn from(iter: T) -> Self {
        Self { iter }
    }
}

impl<T: Iterator<Item = vector_party::PcgItem>> From<T>
    for PackedRandomBitOtReceiverU64<
        RandomBitOTReceiverOnlinePCGKey<RandomOTReceiverOnlinePCGKey<T>>,
    >
{
    fn from(iter: T) -> Self {
        Self { iter: iter.into() }
    }
}

impl<T: Iterator<Item = ReceiverRandomBitOtPcgItem>> PackedRandomBitOtReceiverU64<T> {
    const BIT_LEN: usize = 64;
}

impl<T: Iterator<Item = ReceiverRandomBitOtPcgItem>> Iterator for PackedRandomBitOtReceiverU64<T> {
    type Item = (PackedGF2U64, PackedGF2U64);
    fn next(&mut self) -> Option<Self::Item> {
        let out = (0..Self::BIT_LEN).map_while(|_| self.iter.next()).fold(
            (0u64, 0u64),
            |(acc0, acc1), (cur0, cur1)| {
                (
                    (acc0 << 1) ^ u64::from(u8::from(cur0)),
                    (acc1 << 1) ^ u64::from(u8::from(cur1)),
                )
            },
        );
        Some((out.0.into(), out.1.into()))
    }
}

pub struct PackedRandomBitOtSenderU64<T: Iterator<Item = SenderRandomBitOtPcgItem>> {
    iter: T,
}

impl<T: Iterator<Item = SenderRandomBitOtPcgItem>> From<T> for PackedRandomBitOtSenderU64<T> {
    fn from(iter: T) -> Self {
        Self { iter }
    }
}

impl<T: Iterator<Item = scalar_party::PcgItem>> From<T>
    for PackedRandomBitOtSenderU64<RandomBitOTSenderOnlinePCGKey<RandomOTSenderOnlinePCGKey<T>>>
{
    fn from(iter: T) -> Self {
        Self { iter: iter.into() }
    }
}

impl<T: Iterator<Item = SenderRandomBitOtPcgItem>> PackedRandomBitOtSenderU64<T> {
    const BIT_LEN: usize = 64;
}

impl<T: Iterator<Item = SenderRandomBitOtPcgItem>> Iterator for PackedRandomBitOtSenderU64<T> {
    type Item = (PackedGF2U64, PackedGF2U64);
    fn next(&mut self) -> Option<Self::Item> {
        let out = (0..Self::BIT_LEN).map_while(|_| self.iter.next()).fold(
            (0u64, 0u64),
            |(acc0, acc1), (cur0, cur1)| {
                (
                    (acc0 << 1) ^ u64::from(u8::from(cur0)),
                    (acc1 << 1) ^ u64::from(u8::from(cur1)),
                )
            },
        );
        Some((out.0.into(), out.1.into()))
    }
}
