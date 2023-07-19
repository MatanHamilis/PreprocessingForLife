use super::{FieldElement, PackedField, GF128, GF64};
use bitvec::prelude::*;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    iter::Sum,
    mem::size_of,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitXor, BitXorAssign, Div, DivAssign, Mul, MulAssign,
        Neg, Sub, SubAssign,
    },
};

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct GF2 {
    v: u8,
}

impl GF2 {
    pub fn flip(&mut self) {
        self.v ^= 1;
    }

    pub fn random_not_cryptographic<T: RngCore>(rng: &mut T) -> Self {
        GF2::from(rng.next_u32() & 1 == 0)
    }
}

impl Mul<GF128> for GF2 {
    type Output = GF128;
    fn mul(self, rhs: GF128) -> Self::Output {
        if self.is_zero() {
            GF128::zero()
        } else {
            rhs
        }
    }
}
impl Mul<GF64> for GF2 {
    type Output = GF64;
    fn mul(self, rhs: GF64) -> Self::Output {
        if self.is_zero() {
            GF64::zero()
        } else {
            rhs
        }
    }
}

impl BitAnd for GF2 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn bitand(self, rhs: Self) -> Self::Output {
        self * rhs
    }
}

impl BitAndAssign for GF2 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn bitand_assign(&mut self, rhs: Self) {
        *self *= rhs;
    }
}

impl BitXor for GF2 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl BitXorAssign for GF2 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl From<GF2> for bool {
    fn from(v: GF2) -> Self {
        v.is_one()
    }
}
impl Sum for GF2 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(GF2::zero(), |acc, elem| acc + elem)
    }
}
impl FieldElement for GF2 {
    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        GF2::from(rng.next_u32() & 1 == 0)
    }
    const BITS: usize = 1;
    fn one() -> Self {
        Self { v: 1u8 }
    }
    fn as_bytes(&self) -> &[u8] {
        std::slice::from_ref(&self.v)
    }

    fn hash(&self, hasher: &mut blake3::Hasher) {
        hasher.update(&[self.v]);
    }

    fn is_one(&self) -> bool {
        self.v == 1u8
    }

    fn zero() -> Self {
        Self { v: 0u8 }
    }

    fn is_zero(&self) -> bool {
        self.v == 0
    }

    fn set_bit(&mut self, bit: bool, idx: usize) {
        assert_eq!(idx, 0);
        self.v = bit.into();
    }
}

impl Neg for GF2 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self
    }
}

impl From<bool> for GF2 {
    fn from(v: bool) -> Self {
        match v {
            true => GF2::one(),
            _ => GF2::zero(),
        }
    }
}

impl Sub for GF2 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl SubAssign for GF2 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

impl Mul for GF2 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self { v: self.v & rhs.v }
    }
}

impl MulAssign for GF2 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn mul_assign(&mut self, rhs: Self) {
        self.v &= rhs.v;
    }
}

impl Add for GF2 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self { v: self.v ^ rhs.v }
    }
}

impl AddAssign for GF2 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.v ^= rhs.v;
    }
}
impl AddAssign<&GF2> for GF2 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: &GF2) {
        self.v ^= rhs.v;
    }
}

impl Div for GF2 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        assert!(rhs.v != 0);
        self
    }
}

impl DivAssign for GF2 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn div_assign(&mut self, rhs: Self) {
        assert!(rhs.v != 0);
    }
}

impl TryFrom<u8> for GF2 {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 1 {
            Err(())
        } else {
            Ok(Self { v: value })
        }
    }
}

impl From<GF2> for u8 {
    fn from(v: GF2) -> Self {
        v.v
    }
}

impl Display for GF2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.v)
    }
}

const PACKING: usize = 1 << 10;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackedGF2 {
    pub bits: BitArr!(for PACKING, in usize),
}
impl FieldElement for PackedGF2 {
    const BITS: usize = PACKING;
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                std::mem::transmute(self.bits.as_raw_slice().as_ptr()),
                self.bits.as_raw_slice().len() * std::mem::size_of::<usize>(),
            )
        }
    }
    fn from_bit(bit: bool) -> Self {
        let mut b = Self::zero();
        b.bits.fill(bit);
        b
    }
    fn is_one(&self) -> bool {
        self.bits.as_raw_slice().iter().all(|i| !i == 0)
    }
    fn is_zero(&self) -> bool {
        self.bits.as_raw_slice().iter().all(|i| i == &0)
    }
    fn hash(&self, hasher: &mut blake3::Hasher) {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self.bits.as_raw_slice().as_ptr() as *const u8,
                self.bits.as_raw_slice().len() * size_of::<usize>(),
            )
        };
        hasher.update(bytes);
    }
    fn one() -> Self {
        Self::from_bit(true)
    }
    fn zero() -> Self {
        Self {
            bits: bitarr![0 as usize;PACKING],
        }
    }
    fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        let mut v = Self::zero();
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                v.bits.as_raw_mut_slice().as_mut_ptr() as *mut u8,
                PACKING / u8::BITS as usize,
            )
        };
        rng.fill(bytes);
        v
    }
    fn set_bit(&mut self, bit: bool, idx: usize) {
        *self.bits.get_mut(idx).unwrap() = bit;
    }
}

impl AddAssign for PackedGF2 {
    fn add_assign(&mut self, rhs: Self) {
        self.bits
            .as_raw_mut_slice()
            .iter_mut()
            .zip(rhs.bits.as_raw_slice().iter())
            .for_each(|(d, s)| *d ^= s);
    }
}
impl Add for PackedGF2 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut o = self.clone();
        o += rhs;
        o
    }
}
impl Sum for PackedGF2 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut sum = Self::zero();
        for i in iter {
            sum += i;
        }
        sum
    }
}
impl Neg for PackedGF2 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self
    }
}
impl Default for PackedGF2 {
    fn default() -> Self {
        Self::zero()
    }
}

impl DivAssign for PackedGF2 {
    fn div_assign(&mut self, rhs: Self) {
        if !rhs.is_one() {
            panic!();
        }
    }
}
impl Div for PackedGF2 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        let mut v = self.clone();
        v /= rhs;
        v
    }
}

impl MulAssign for PackedGF2 {
    fn mul_assign(&mut self, rhs: Self) {
        self.bits
            .as_raw_mut_slice()
            .iter_mut()
            .zip(rhs.bits.as_raw_slice().iter())
            .for_each(|(d, s)| *d &= s);
    }
}

impl Mul for PackedGF2 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut v = self.clone();
        v *= rhs;
        v
    }
}

impl SubAssign for PackedGF2 {
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs
    }
}

impl Sub for PackedGF2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut v = self.clone();
        v -= rhs;
        v
    }
}

impl PackedField<GF2, PACKING> for PackedGF2 {
    fn get_element(&self, i: usize) -> GF2 {
        GF2::from(*self.bits.get(i).unwrap())
    }
    fn set_element(&mut self, i: usize, value: &GF2) {
        self.bits.set(i, value.is_one())
    }
}

impl PackedField<GF2, 1> for GF2 {
    fn get_element(&self, _: usize) -> GF2 {
        self.clone()
    }
    fn set_element(&mut self, i: usize, value: &GF2) {
        assert_eq!(i, 0);
        *self = *value;
    }
}
