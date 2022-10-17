use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use super::FieldElement;
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PackedGF2U64(u64);
impl From<u64> for PackedGF2U64 {
    fn from(e: u64) -> Self {
        Self(e)
    }
}

impl FieldElement for PackedGF2U64 {
    const BITS: usize = 64;
    fn is_one(&self) -> bool {
        self.0 == u64::MAX
    }
    fn is_zero(&self) -> bool {
        self.0 == 0u64
    }
    fn one() -> Self {
        Self(u64::MAX)
    }
    fn zero() -> Self {
        Self(0u64)
    }
    fn from_bits(bits: &[bool]) -> Option<Self> {
        if bits.len() != Self::BITS {
            return None;
        }
        let mut output = 0u64;
        for (idx, bit) in bits.iter().enumerate() {
            if *bit {
                output ^= 1 << idx;
            }
        }
        Some(PackedGF2U64(output))
    }
}

impl Add for PackedGF2U64 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Default for PackedGF2U64 {
    fn default() -> Self {
        Self::zero()
    }
}

impl AddAssign for PackedGF2U64 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Mul for PackedGF2U64 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl MulAssign for PackedGF2U64 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Div for PackedGF2U64 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        if rhs != Self::one() {
            panic!("Dividing by zero!");
        }
        self
    }
}
impl DivAssign for PackedGF2U64 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn div_assign(&mut self, rhs: Self) {
        if rhs != Self::one() {
            panic!("Dividing by zero!");
        }
    }
}

impl Sub for PackedGF2U64 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}
impl SubAssign for PackedGF2U64 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PackedGF2Array<const SIZE: usize>(#[serde(with = "BigArray")] [PackedGF2U64; SIZE]);
impl<const SIZE: usize> Div for PackedGF2Array<SIZE> {
    type Output = Self;
    fn div(mut self, rhs: Self) -> Self::Output {
        self /= rhs;
        self
    }
}
impl<const SIZE: usize> DivAssign for PackedGF2Array<SIZE> {
    fn div_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.0[i] /= rhs.0[i];
        }
    }
}
impl<const SIZE: usize> Mul for PackedGF2Array<SIZE> {
    type Output = Self;
    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}
impl<const SIZE: usize> MulAssign for PackedGF2Array<SIZE> {
    fn mul_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.0[i] *= rhs.0[i];
        }
    }
}
impl<const SIZE: usize> Sub for PackedGF2Array<SIZE> {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}
impl<const SIZE: usize> SubAssign for PackedGF2Array<SIZE> {
    fn sub_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.0[i] -= rhs.0[i];
        }
    }
}
impl<const SIZE: usize> Add for PackedGF2Array<SIZE> {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}
impl<const SIZE: usize> AddAssign for PackedGF2Array<SIZE> {
    fn add_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.0[i] += rhs.0[i];
        }
    }
}

impl<const SIZE: usize> FieldElement for PackedGF2Array<SIZE> {
    const BITS: usize = SIZE * 64;
    fn is_one(&self) -> bool {
        *self == Self::one()
    }
    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
    fn one() -> Self {
        Self([PackedGF2U64::one(); SIZE])
    }
    fn zero() -> Self {
        Self([PackedGF2U64::zero(); SIZE])
    }
    fn from_bits(bits: &[bool]) -> Option<Self> {
        if bits.len() != Self::BITS {
            return None;
        }
        let mut output = Self::zero();
        for i in 0..SIZE {
            let chunk = &bits[PackedGF2U64::BITS * i..PackedGF2U64::BITS * (i + 1)];
            output.0[i] = PackedGF2U64::from_bits(chunk)?;
        }
        Some(output)
    }
}

impl<const SIZE: usize> Default for PackedGF2Array<SIZE> {
    fn default() -> Self {
        Self::zero()
    }
}
