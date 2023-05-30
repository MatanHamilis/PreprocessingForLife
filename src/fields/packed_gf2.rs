// use std::{
//     iter::Sum,
//     ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
// };

// use serde::{Deserialize, Serialize};
// use serde_big_array::BigArray;

// use super::FieldElement;
// #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
// pub struct PackedGF2U64(u64);
// impl From<u64> for PackedGF2U64 {
//     fn from(e: u64) -> Self {
//         Self(e)
//     }
// }

// impl FieldElement for PackedGF2U64 {
//     const BITS: usize = 64;
//     fn is_one(&self) -> bool {
//         self.0 == u64::MAX
//     }
//     fn is_zero(&self) -> bool {
//         self.0 == 0u64
//     }
//     fn one() -> Self {
//         Self(u64::MAX)
//     }
//     fn zero() -> Self {
//         Self(0u64)
//     }

//     fn set_bit(&mut self, bit: bool, idx: usize) {
//         let mask = u64::MAX ^ (1 << idx);
//         let masked_val = self.0 & mask;
//         self.0 = u64::from(bit) << idx | masked_val;
//     }
//     // fn from_bits(bits: &[bool]) -> Option<Self> {
//     //     if bits.len() != Self::BITS {
//     //         return None;
//     //     }
//     //     let mut output = 0u64;
//     //     for (idx, bit) in bits.iter().enumerate() {
//     //         if *bit {
//     //             output ^= 1 << idx;
//     //         }
//     //     }
//     //     Some(PackedGF2U64(output))
//     // }
//     fn random(mut rng: impl rand::CryptoRng + rand::RngCore) -> Self {
//         Self(rng.next_u64())
//     }
// }
// impl Sum for PackedGF2U64 {
//     fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
//         iter.fold(Self::zero(), |acc, v| acc + v)
//     }
// }

// impl Neg for PackedGF2U64 {
//     type Output = Self;
//     fn neg(self) -> Self::Output {
//         self + Self::one()
//     }
// }
// impl Add for PackedGF2U64 {
//     type Output = Self;
//     #[allow(clippy::suspicious_arithmetic_impl)]
//     fn add(self, rhs: Self) -> Self::Output {
//         Self(self.0 ^ rhs.0)
//     }
// }

// impl Default for PackedGF2U64 {
//     fn default() -> Self {
//         Self::zero()
//     }
// }

// impl AddAssign for PackedGF2U64 {
//     #[allow(clippy::suspicious_op_assign_impl)]
//     fn add_assign(&mut self, rhs: Self) {
//         self.0 ^= rhs.0;
//     }
// }

// impl Mul for PackedGF2U64 {
//     type Output = Self;
//     #[allow(clippy::suspicious_arithmetic_impl)]
//     fn mul(self, rhs: Self) -> Self::Output {
//         Self(self.0 & rhs.0)
//     }
// }

// impl MulAssign for PackedGF2U64 {
//     #[allow(clippy::suspicious_op_assign_impl)]
//     fn mul_assign(&mut self, rhs: Self) {
//         self.0 &= rhs.0;
//     }
// }

// impl Div for PackedGF2U64 {
//     type Output = Self;
//     #[allow(clippy::suspicious_arithmetic_impl)]
//     fn div(self, rhs: Self) -> Self::Output {
//         if rhs != Self::one() {
//             panic!("Dividing by zero!");
//         }
//         self
//     }
// }
// impl DivAssign for PackedGF2U64 {
//     #[allow(clippy::suspicious_op_assign_impl)]
//     fn div_assign(&mut self, rhs: Self) {
//         if rhs != Self::one() {
//             panic!("Dividing by zero!");
//         }
//     }
// }

// impl Sub for PackedGF2U64 {
//     type Output = Self;
//     #[allow(clippy::suspicious_arithmetic_impl)]
//     fn sub(self, rhs: Self) -> Self::Output {
//         self + rhs
//     }
// }
// impl SubAssign for PackedGF2U64 {
//     #[allow(clippy::suspicious_op_assign_impl)]
//     fn sub_assign(&mut self, rhs: Self) {
//         *self += rhs;
//     }
// }

// #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
// pub struct PackedGF2Array<const SIZE: usize>(#[serde(with = "BigArray")] [PackedGF2U64; SIZE]);
// impl<const SIZE: usize> Div for PackedGF2Array<SIZE> {
//     type Output = Self;
//     fn div(mut self, rhs: Self) -> Self::Output {
//         self /= rhs;
//         self
//     }
// }
// impl<const SIZE: usize> DivAssign for PackedGF2Array<SIZE> {
//     fn div_assign(&mut self, rhs: Self) {
//         for i in 0..SIZE {
//             self.0[i] /= rhs.0[i];
//         }
//     }
// }
// impl<const SIZE: usize> Mul for PackedGF2Array<SIZE> {
//     type Output = Self;
//     fn mul(mut self, rhs: Self) -> Self::Output {
//         self *= rhs;
//         self
//     }
// }
// impl<const SIZE: usize> MulAssign for PackedGF2Array<SIZE> {
//     fn mul_assign(&mut self, rhs: Self) {
//         for i in 0..SIZE {
//             self.0[i] *= rhs.0[i];
//         }
//     }
// }
// impl<const SIZE: usize> Sub for PackedGF2Array<SIZE> {
//     type Output = Self;
//     fn sub(mut self, rhs: Self) -> Self::Output {
//         self -= rhs;
//         self
//     }
// }
// impl<const SIZE: usize> SubAssign for PackedGF2Array<SIZE> {
//     fn sub_assign(&mut self, rhs: Self) {
//         for i in 0..SIZE {
//             self.0[i] -= rhs.0[i];
//         }
//     }
// }
// impl<const SIZE: usize> Add for PackedGF2Array<SIZE> {
//     type Output = Self;
//     fn add(mut self, rhs: Self) -> Self::Output {
//         self += rhs;
//         self
//     }
// }
// impl<const SIZE: usize> AddAssign for PackedGF2Array<SIZE> {
//     fn add_assign(&mut self, rhs: Self) {
//         for i in 0..SIZE {
//             self.0[i] += rhs.0[i];
//         }
//     }
// }

// impl<const SIZE: usize> FieldElement for PackedGF2Array<SIZE> {
//     const BITS: usize = SIZE * 64;
//     fn is_one(&self) -> bool {
//         *self == Self::one()
//     }
//     fn is_zero(&self) -> bool {
//         *self == Self::zero()
//     }
//     fn one() -> Self {
//         Self([PackedGF2U64::one(); SIZE])
//     }
//     fn zero() -> Self {
//         Self([PackedGF2U64::zero(); SIZE])
//     }

//     fn set_bit(&mut self, bit: bool, idx: usize) {
//         let entry = idx / PackedGF2U64::BITS;
//         let offset = idx & (PackedGF2U64::BITS - 1);
//         self.0[entry].set_bit(bit, offset)
//     }
//     fn random(mut rng: impl rand::CryptoRng + rand::RngCore) -> Self {
//         Self(core::array::from_fn(|_| PackedGF2U64::random(&mut rng)))
//     }
// }

// impl<const SIZE: usize> Default for PackedGF2Array<SIZE> {
//     fn default() -> Self {
//         Self::zero()
//     }
// }

// impl<const SIZE: usize> Neg for PackedGF2Array<SIZE> {
//     type Output = Self;
//     fn neg(self) -> Self::Output {
//         self + Self::one()
//     }
// }

// impl<const SIZE: usize> Sum for PackedGF2Array<SIZE> {
//     fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
//         iter.fold(Self::zero(), |acc, v| acc + v)
//     }
// }
