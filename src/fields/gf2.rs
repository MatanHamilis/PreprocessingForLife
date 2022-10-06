use super::FieldElement;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    iter::Sum,
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
    pub fn random<T: CryptoRng + RngCore>(rng: &mut T) -> Self {
        GF2::from(rng.next_u32() & 1 == 0)
    }

    pub fn random_not_cryptographic<T: RngCore>(rng: &mut T) -> Self {
        GF2::from(rng.next_u32() & 1 == 0)
    }
}

impl BitAnd for GF2 {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        self * rhs
    }
}

impl BitAndAssign for GF2 {
    fn bitand_assign(&mut self, rhs: Self) {
        *self *= rhs;
    }
}

impl BitXor for GF2 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl BitXorAssign for GF2 {
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
    const BITS: usize = 1;
    fn one() -> Self {
        Self { v: 1u8 }
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

    fn from_bits(bits: &[bool]) -> Option<Self> {
        if bits.len() != Self::BITS {
            None
        } else {
            Some(GF2::from(bits[0]))
        }
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
        Self { v: self.v & rhs.v }
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
        Self { v: self.v ^ rhs.v }
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
        assert!(rhs.v != 0);
        self
    }
}

impl DivAssign for GF2 {
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
