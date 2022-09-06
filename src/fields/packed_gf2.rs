use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

use super::FieldElement;
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PackedGF2U64 {
    e: u64,
}
impl From<u64> for PackedGF2U64 {
    fn from(e: u64) -> Self {
        Self { e }
    }
}

impl FieldElement for PackedGF2U64 {
    fn is_one(&self) -> bool {
        self.e == u64::MAX
    }
    fn is_zero(&self) -> bool {
        self.e == 0u64
    }
    fn one() -> Self {
        Self { e: u64::MAX }
    }
    fn zero() -> Self {
        Self { e: 0u64 }
    }
}

impl Add for PackedGF2U64 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self { e: self.e ^ rhs.e }
    }
}

impl AddAssign for PackedGF2U64 {
    fn add_assign(&mut self, rhs: Self) {
        self.e ^= rhs.e;
    }
}

impl Mul for PackedGF2U64 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self { e: self.e & rhs.e }
    }
}

impl MulAssign for PackedGF2U64 {
    fn mul_assign(&mut self, rhs: Self) {
        self.e &= rhs.e;
    }
}

impl Div for PackedGF2U64 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        if rhs != Self::one() {
            panic!("Dividing by zero!");
        }
        self
    }
}
impl DivAssign for PackedGF2U64 {
    fn div_assign(&mut self, rhs: Self) {
        if rhs != Self::one() {
            panic!("Dividing by zero!");
        }
    }
}

impl Sub for PackedGF2U64 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}
impl SubAssign for PackedGF2U64 {
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}
