use serde::Deserialize;
use serde::Serialize;
use std::iter::Sum;
use std::ops::DivAssign;
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

use super::FieldElement;

pub const PR: u64 = 2305843009213693951;
pub const PRIME_EXP: u64 = 61;
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct GFMersenne(u64);
impl AddAssign for GFMersenne {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
        if self.0 >= PR {
            self.0 -= PR;
        }
    }
}
impl Add for GFMersenne {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}
impl MulAssign for GFMersenne {
    fn mul_assign(&mut self, rhs: Self) {
        let r: u128 = (self.0 as u128) * (rhs.0 as u128);
        self.0 = (r >> PRIME_EXP) as u64;
        let lower: Self = Self((r as u64) & PR);
        self.add_assign(lower);
    }
}
impl Mul for GFMersenne {
    type Output = Self;
    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}
impl Sum for GFMersenne {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, cur| acc + cur)
    }
}
impl Neg for GFMersenne {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(PR - self.0)
    }
}
impl Default for GFMersenne {
    fn default() -> Self {
        Self::zero()
    }
}
impl DivAssign for GFMersenne {
    fn div_assign(&mut self, rhs: Self) {
        *self *= Self(inverse(rhs.0));
    }
}
impl Div for GFMersenne {
    type Output = Self;
    fn div(mut self, rhs: Self) -> Self::Output {
        self /= rhs;
        self
    }
}
fn inverse(a: u64) -> u64 {
    // inline uint64_t Mersenne::inverse(uint64_t a) {
    let mut left = a;
    let mut right = PR;
    let (mut x, mut y, mut u, mut v): (u64, u64, u64, u64) = (1, 0, 0, 1);
    let gcd = a;
    let (mut w, mut z) = (0, 0);
    while (left != 0) {
        w = right / left;
        z = right % left;
        right = left;
        left = z;
        z = u - w * x;
        u = x;
        x = z;

        z = v - w * y;
        v = y;
        y = z;
    }
    if (u >= PR) {
        u += PR;
    }
    return u;
}
impl SubAssign for GFMersenne {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = if self.0 >= rhs.0 {
            self.0 - rhs.0
        } else {
            PR - rhs.0 + self.0
        };
    }
}
impl Sub for GFMersenne {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}
impl FieldElement for GFMersenne {
    const BITS: usize = PRIME_EXP as usize;
    fn zero() -> Self {
        Self(0)
    }
    fn one() -> Self {
        Self(1)
    }
    fn is_one(&self) -> bool {
        self.0 == 1
    }
    fn is_zero(&self) -> bool {
        self.0 == 0
    }
    fn as_bytes(&self) -> &[u8] {
        let output =
            unsafe { std::slice::from_raw_parts(std::mem::transmute::<_, *const u8>(&self.0), 8) };
        output
    }
    fn hash(&self, hasher: &mut blake3::Hasher) {
        hasher.update(self.as_bytes());
    }
    fn from_bit(bit: bool) -> Self {
        if bit {
            Self::one()
        } else {
            Self::zero()
        }
    }
    fn number(mut number: u32) -> Self {
        Self(number as u64)
    }
    fn random(mut rng: impl rand_core::CryptoRng + rand_core::RngCore) -> Self {
        Self(rng.next_u64())
    }
    fn set_bit(&mut self, bit: bool, idx: usize) {
        if (idx as u64) >= PRIME_EXP {
            panic!();
        }
    }
    fn switch(&self, bit: bool) -> Self {
        if bit {
            self.clone()
        } else {
            Self::zero()
        }
    }
}
