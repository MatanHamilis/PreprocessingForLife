use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_xor_si128};
use core::simd::{u64x2, Simd};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::arch::x86_64::_lzcnt_u64;
use std::fmt::Display;
use std::iter::Sum;
use std::mem::transmute;
use std::ops::Not;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use super::gf2::GF2;
use super::{FieldElement, IntermediateMulField, MulResidue};

/// This is the irreducible polynomial $x^64 + x^4 + x^3 + x + 1$.
const IRREDUCIBLE_POLYNOMIAL: u64 = (1 << 4) + (1 << 3) + (1 << 1) + (1 << 0);
// const IRREDUCIBLE_POLYNOMIAL: u64x2 = u64x2::from_array([IRREDUCIBLE_POLYNOMIAL_U64, 0]);

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct GF64(pub u64);

// impl Serialize for GF64 {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         let mut seq = serializer.serialize_tuple(2)?;
//         seq.serialize_element(&self.0[0])?;
//         seq.serialize_element(&self.0[1])?;
//         seq.end()
//     }
// }

// struct GF64Visitor;
// impl<'de> Visitor<'de> for GF64Visitor {
//     type Value = GF64;u64x2::from_array([0, 1])D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         Ok(deserializer.deserialize_tuple(2, GF64Visitor)?)
//     }
// }
impl From<GF2> for GF64 {
    fn from(v: GF2) -> Self {
        if v.is_one() {
            GF64::one()
        } else {
            GF64::zero()
        }
    }
}

impl Sum for GF64 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, v| acc + v)
    }
}
impl Neg for GF64 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self
    }
}

impl Add for GF64 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        GF64(self.0 ^ rhs.0)
    }
}

impl AddAssign for GF64 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl AddAssign<&GF64> for GF64 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: &GF64) {
        self.0 ^= rhs.0
    }
}

impl Sub for GF64 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl SubAssign for GF64 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs
    }
}

impl Mul<GF2> for GF64 {
    type Output = Self;
    fn mul(self, rhs: GF2) -> Self::Output {
        if rhs.is_one() {
            self
        } else {
            GF64::zero()
        }
    }
}

impl MulAssign<GF2> for GF64 {
    fn mul_assign(&mut self, rhs: GF2) {
        if rhs.is_zero() {
            *self = GF64::zero();
        }
    }
}

const LOWER_LOWER: i32 = 0;
const UPPER_LOWER: i32 = 1;
// const LOWER_UPPER: i32 = 16;
// const UPPER_UPPER: i32 = 17;
impl Mul for GF64 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self::mul_inner(&self, &rhs)
    }
}

impl MulAssign for GF64 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self::mul_inner(self, &rhs);
    }
}

impl Div for GF64 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inv()
    }
}

impl DivAssign for GF64 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn div_assign(&mut self, rhs: Self) {
        *self *= rhs.inv();
    }
}

impl From<u64> for GF64 {
    fn from(v: u64) -> Self {
        GF64(v)
    }
}

impl From<[u8; 8]> for GF64 {
    fn from(v: [u8; 8]) -> Self {
        GF64(u64::from_le_bytes(v))
    }
}

impl From<GF64> for [u8; 8] {
    fn from(value: GF64) -> Self {
        unsafe { transmute(value.0) }
    }
}

impl FieldElement for GF64 {
    const BITS: usize = 64;
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                std::mem::transmute::<_, *const u8>((&self.0) as *const u64),
                8,
            )
        }
    }
    fn one() -> Self {
        GF64(1u64)
    }

    fn hash(&self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.0.to_le_bytes());
    }
    fn is_one(&self) -> bool {
        self.0 == 1u64
    }

    fn zero() -> Self {
        GF64(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
    fn set_bit(&mut self, bit: bool, idx: usize) {
        assert!(idx < Self::BITS);
        self.0 |= (bit as u64) << idx;
    }
    /// Returns a random field element
    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        GF64(rng.next_u64())
    }

    // fn from_bits(bits: &[bool]) -> Option<Self> {
    //     if bits.len() != Self::BITS {
    //         return None;
    //     }
    //     let mut output = u64x2::default();
    //     for (idx, bit) in bits.iter().enumerate() {
    //         if *bit {
    //             GF64::toggle_bit(&mut output, idx as u32);
    //         }
    //     }
    //     Some(GF64(output))
    // }
}

impl GF64 {
    // #[inline]
    pub fn get_deg(v: &u64) -> u32 {
        let lzcnt: u32 = unsafe { _lzcnt_u64(*v) } as u32;
        63 - lzcnt
    }
    #[inline]
    fn toggle_bit(v: &mut u64, offset: u32) {
        *v ^= 1u64 << (offset & 63);
    }
    pub fn get_bit(&self, offset: usize) -> bool {
        (self.0 >> (offset & 63)) & 1 != 0
    }

    /// Divides IRREDUCIBLE_POLYNOMIAL by v.
    /// This requires a special function since IRREDUCIBLE_POLYNOMIAL can't be represented
    /// using GF64 since it has 129 coefficients.
    fn irred_div_by(v: &u64) -> (u64, u64) {
        let self_deg = GF64::get_deg(v);
        let mut q = 0;
        // The &63 is for the special case in which v is 1.
        GF64::toggle_bit(&mut q, (64 - self_deg) & 63);
        let nom = GF64::shl(v, 64 - self_deg) ^ IRREDUCIBLE_POLYNOMIAL;
        let (q_prime, r_prime) = GF64::div_rem(&nom, v);
        (q ^ q_prime, r_prime)
    }
    /// Assumes deg(nom) >= deg(denom), otherwise - undefined behavior.
    fn div_rem(nom: &u64, denom: &u64) -> (u64, u64) {
        let mut nom = *nom;
        let mut deg_nom = Self::get_deg(&nom);
        let deg_denom = Self::get_deg(denom);
        let mut q = 0;
        while deg_nom >= deg_denom {
            let q_deg = deg_nom - deg_denom;
            nom ^= Self::shl(denom, q_deg);
            GF64::toggle_bit(&mut q, q_deg);
            if nom == 0 {
                break;
            }
            deg_nom = Self::get_deg(&nom);
        }
        (q, nom)
    }

    #[inline]
    #[allow(dead_code)]
    fn shl_assign(a: &mut u64, b: u32) {
        *a <<= b;
    }
    #[inline]
    fn shl(a: &u64, b: u32) -> u64 {
        a << b
    }
    // fn mul_inner(a: &GF64, b: &GF64) -> GF64 {
    //     let (mut lower, upper) = Self::mul_no_reduce(&a.0, &b.0);

    //     lower ^= Self::mod_reduce(upper);
    //     GF64(lower)
    // }
    fn mul_no_reduce(a: &u64, b: &u64) -> (u64, u64) {
        let a: __m128i = Simd::from_array([*a, 0]).into();
        let b: __m128i = Simd::from_array([*b, 0]).into();
        let output: u64x2 = unsafe { _mm_clmulepi64_si128::<LOWER_LOWER>(a, b) }.into();
        (output.as_array()[0], output.as_array()[1])
    }

    #[inline]
    fn reduce(output: __m128i) -> u64 {
        let rr: __m128i = Simd::from_array([IRREDUCIBLE_POLYNOMIAL, 0]).into();
        let output_red = unsafe { _mm_clmulepi64_si128::<UPPER_LOWER>(output, rr) };
        let output_red_2 = unsafe { _mm_clmulepi64_si128::<UPPER_LOWER>(output_red, rr) };
        let output = unsafe {
            u64x2::from(_mm_xor_si128(
                _mm_xor_si128(output, output_red),
                output_red_2,
            ))
        };
        output.as_array()[0]
    }
    fn mul_inner(a: &GF64, b: &GF64) -> GF64 {
        let a: __m128i = Simd::from_array([a.0, 0]).into();
        let b: __m128i = Simd::from_array([b.0, 0]).into();
        let output = unsafe { _mm_clmulepi64_si128::<LOWER_LOWER>(a, b) };

        GF64(Self::reduce(output))
    }

    pub fn random_not_cryptographic(mut rng: impl RngCore) -> Self {
        GF64(rng.next_u64())
    }

    pub fn checked_div(&self, v: &Self) -> Option<Self> {
        if v.is_zero() {
            return None;
        }
        Some(*self / *v)
    }

    pub fn inv(&self) -> Self {
        if self.is_zero() {
            panic!("Inversion of 0 is undefined!");
        }
        if self.is_one() {
            return *self;
        }
        // Initiazlie the bezout coefficients
        // For each iteration in the EGCD algorithm we have:
        // IRREDUCIBLE_POLYNOMIAL*s + self*t = r
        // Eventually, r_i = 1 so we're done (return t_i).
        let (mut t_old, mut t) = (0, 1);

        // Since we don't represent the upper bit of the irreducible polynomial, we "bootstrap"
        // the division.
        let (mut q, mut r) = GF64::irred_div_by(&self.0);
        let mut r_old = self.0;
        (t_old, t) = (t, t_old ^ GF64::mul_no_reduce(&t, &q).0);
        while r != 1 {
            ((q, r), r_old) = (GF64::div_rem(&r_old, &r), r);
            (t_old, t) = (t, t_old ^ GF64::mul_no_reduce(&t, &q).0);
        }
        t.into()
    }

    pub fn flip(&mut self) {
        self.0 = !self.0.not()
    }
}

impl Display for GF64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..GF64::BITS {
            write!(f, "{}", self.get_bit(i) as u8)?;
        }
        Ok(())
    }
}

impl IntermediateMulField for GF64 {
    type MulRes = MulResidue64;
    fn intermediate_mul(&self, rhs: &Self) -> Self::MulRes {
        let v = GF64::mul_no_reduce(&self.0, &rhs.0);
        MulResidue64 {
            v: u64x2::from_array([v.0, v.1]),
        }
    }
}

#[derive(Clone, Copy)]
pub struct MulResidue64 {
    v: u64x2,
}
impl MulResidue<GF64> for MulResidue64 {
    fn reduce(&self) -> GF64 {
        GF64(GF64::reduce(self.v.into()))
    }
}
impl From<GF64> for MulResidue64 {
    fn from(value: GF64) -> Self {
        Self {
            v: Simd::from_array([value.0, 0]),
        }
    }
}

impl AddAssign for MulResidue64 {
    fn add_assign(&mut self, rhs: Self) {
        self.v ^= rhs.v;
    }
}

impl Add for MulResidue64 {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}
impl Sum for MulResidue64 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(
            Self {
                v: u64x2::from_array([0; 2]),
            },
            |cur, acc| cur + acc,
        )
    }
}
impl SubAssign for MulResidue64 {
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}
impl Sub for MulResidue64 {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{IntermediateMulField, MulResidue};

    use super::FieldElement;

    use super::{GF64, IRREDUCIBLE_POLYNOMIAL};

    #[test]
    pub fn test_bit_manipulation() {
        let mut a = GF64::zero();
        for i in 0..GF64::BITS {
            assert!(!a.get_bit(i))
        }
        for i in (0..GF64::BITS).step_by(2) {
            a.set_bit(true, i);
        }
        for i in 0..GF64::BITS {
            if i & 1 == 0 {
                assert!(a.get_bit(i));
            } else {
                assert!(!a.get_bit(i));
            }
        }
    }
    #[test]
    pub fn test_mul() {
        let a = GF64(1 << 32);
        let b = GF64(1 << 32);
        let c = a * b;
        assert_eq!(c.0, IRREDUCIBLE_POLYNOMIAL);
    }
    #[test]
    pub fn test_dev_rem() {
        let a = 1 << 32;
        let b = 1u64 << 28;
        let (q, r) = GF64::div_rem(&a, &b);
        assert_eq!(q, 1 << 4);
        assert_eq!(r, 0);
    }

    #[test]
    pub fn test_irred_dib() {
        let a = 2;
        let (q, r) = GF64::irred_div_by(&a);
        assert_eq!(q, (1 << 63) + IRREDUCIBLE_POLYNOMIAL / 2);
        assert_eq!(r, 1);
    }

    #[test]
    pub fn test_inv_one() {
        assert_eq!(GF64::one().inv(), GF64::one());
    }
    #[test]
    #[should_panic]
    pub fn test_inv_zero() {
        GF64::zero().inv();
    }
    #[test]
    pub fn test_inv() {
        let x = GF64((1 << 3) + (1 << 2) + 1 + (1u64 << 63)).inv();
        assert_eq!(x, GF64(2));

        for i in 0u64..1000 {
            let x = GF64(i + (i + 1) << 32);
            assert_eq!(x.inv().inv(), x);
        }
    }
    #[test]
    pub fn test_inv_with_mul() {
        for i in 0u64..1000 {
            let x = GF64(i + (i + 1) << 32);
            let x_inv = x.inv();
            let y = x * x_inv;
            assert!(y.is_one());
        }
    }

    #[test]
    pub fn test_from_into() {
        let element = [1, 2, 3, 4, 5, 6, 7, 8];
        let e = GF64::from(element);
        let new_element: [u8; 8] = e.into();
        assert_eq!(element, new_element);
    }
    #[test]
    pub fn test_intermediate() {
        let a = GF64(10);
        let b = GF64((1 << 63) + 12);
        let c = GF64((1 << 30) + 12);
        let d = GF64((1 << 60) + 12);
        let f = (a.intermediate_mul(&b) + c.intermediate_mul(&d)).reduce();
        let e = a * b + c * d;
        assert_eq!(e, f);
    }
}
