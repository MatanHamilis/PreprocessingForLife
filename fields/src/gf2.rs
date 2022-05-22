use crate::FieldElement;
use std::{
    iter::Sum,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct GF2 {
    v: bool,
}

impl GF2 {}

impl Sum for GF2 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(GF2::zero(), |acc, elem| acc + elem)
    }
}
impl FieldElement for GF2 {
    fn one() -> Self {
        GF2::from(true)
    }

    fn is_one(&self) -> bool {
        self.v
    }

    fn zero() -> Self {
        GF2::from(false)
    }

    fn is_zero(&self) -> bool {
        !self.v
    }
}

impl Neg for GF2 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        GF2::from(!self.v)
    }
}

impl From<bool> for GF2 {
    fn from(v: bool) -> Self {
        Self { v }
    }
}

impl Sub for GF2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl SubAssign for GF2 {
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

impl Mul for GF2 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        GF2::from(self.v && rhs.v)
    }
}

impl MulAssign for GF2 {
    fn mul_assign(&mut self, rhs: Self) {
        self.v &= rhs.v;
    }
}

impl Add for GF2 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        GF2::from(self.v ^ rhs.v)
    }
}

impl AddAssign for GF2 {
    fn add_assign(&mut self, rhs: Self) {
        self.v ^= rhs.v;
    }
}

impl Div for GF2 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        assert!(rhs.v);
        self
    }
}

impl DivAssign for GF2 {
    fn div_assign(&mut self, rhs: Self) {
        assert!(rhs.v);
    }
}
