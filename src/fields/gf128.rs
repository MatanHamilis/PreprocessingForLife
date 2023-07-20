use aes::Block;
use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_lzcnt_epi64, _mm_xor_si128};
use core::simd::u64x2;
use rand_core::{CryptoRng, RngCore};
use serde::de::Visitor;
use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::iter::Sum;
use std::mem::transmute;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, ShlAssign, Sub, SubAssign};
use std::ops::{Not, Shl};

use super::gf2::GF2;
use super::{FieldElement, IntermediateMulField, MulResidue};

/// This is the irreducible polynomial $x^128 + x^7 + x^2 + x + 1$.
const IRREDUCIBLE_POLYNOMIAL_U64: u64 = (1 << 7) + (1 << 2) + (1 << 1) + (1 << 0);
const IRREDUCIBLE_POLYNOMIAL: u64x2 = u64x2::from_array([IRREDUCIBLE_POLYNOMIAL_U64, 0]);

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct GF128(pub u64x2);

impl Serialize for GF128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(2)?;
        seq.serialize_element(&self.0[0])?;
        seq.serialize_element(&self.0[1])?;
        seq.end()
    }
}

struct GF128Visitor;
impl<'de> Visitor<'de> for GF128Visitor {
    type Value = GF128;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A [u64;2] value")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let a = seq.next_element()?.unwrap_or(u64::default());
        let b = seq.next_element()?.unwrap_or(u64::default());
        Ok(GF128(u64x2::from_array([a, b])))
    }
}
impl<'de> Deserialize<'de> for GF128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(deserializer.deserialize_tuple(2, GF128Visitor)?)
    }
}
impl From<GF2> for GF128 {
    fn from(v: GF2) -> Self {
        if v.is_one() {
            GF128::one()
        } else {
            GF128::zero()
        }
    }
}

impl From<GF128> for Block {
    fn from(value: GF128) -> Self {
        unsafe { transmute(value.0) }
    }
}

impl From<Block> for GF128 {
    fn from(b: Block) -> Self {
        unsafe { std::mem::transmute(b) }
    }
}

impl Sum for GF128 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, v| acc + v)
    }
}
impl Neg for GF128 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self
    }
}

impl Add for GF128 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        GF128(self.0 ^ rhs.0)
    }
}

impl AddAssign for GF128 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl AddAssign<&GF128> for GF128 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: &GF128) {
        self.0 ^= rhs.0
    }
}

impl Sub for GF128 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl SubAssign for GF128 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs
    }
}

impl Mul<GF2> for GF128 {
    type Output = Self;
    fn mul(self, rhs: GF2) -> Self::Output {
        if rhs.is_one() {
            self
        } else {
            GF128::zero()
        }
    }
}

impl MulAssign<GF2> for GF128 {
    fn mul_assign(&mut self, rhs: GF2) {
        if rhs.is_zero() {
            *self = GF128::zero();
        }
    }
}

const LOWER_LOWER: i32 = 0;
const UPPER_LOWER: i32 = 1;
const LOWER_UPPER: i32 = 16;
const UPPER_UPPER: i32 = 17;
impl Mul for GF128 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self::mul_inner(&self, &rhs)
    }
}

impl MulAssign for GF128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self::mul_inner(self, &rhs);
    }
}

impl Div for GF128 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inv()
    }
}

impl DivAssign for GF128 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn div_assign(&mut self, rhs: Self) {
        *self *= rhs.inv();
    }
}

impl From<u64x2> for GF128 {
    fn from(v: u64x2) -> Self {
        GF128(v)
    }
}

impl From<[u8; 16]> for GF128 {
    fn from(v: [u8; 16]) -> Self {
        GF128(u64x2::from([
            u64::from_le_bytes(v[0..8].try_into().expect("Shouldn't fail")),
            u64::from_le_bytes(v[8..16].try_into().expect("Shouldn't fail")),
        ]))
    }
}

impl From<GF128> for [u8; 16] {
    fn from(value: GF128) -> Self {
        unsafe { transmute(value.0) }
    }
}

impl FieldElement for GF128 {
    const BITS: usize = 128;
    fn one() -> Self {
        GF128(GF128::U64X2_ONE)
    }
    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.as_array().as_ptr() as *const u8, 16) }
    }
    fn hash(&self, hasher: &mut blake3::Hasher) {
        let bytes = unsafe {
            (self.0.as_array().as_ptr() as *const [u8; 16])
                .as_ref()
                .unwrap()
        };
        hasher.update(bytes);
    }

    fn is_one(&self) -> bool {
        self.0 == GF128::U64X2_ONE
    }

    fn zero() -> Self {
        GF128(GF128::U64X2_ZERO)
    }

    fn is_zero(&self) -> bool {
        self.0 == GF128::U64X2_ZERO
    }
    fn set_bit(&mut self, bit: bool, idx: usize) {
        assert!(idx < Self::BITS);
        if GF128::get_bit(&self, idx) != bit {
            GF128::toggle_bit(
                &mut self.0,
                u32::try_from(idx).expect("This should not happen"),
            );
        }
    }
    /// Returns a random field element
    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        GF128(u64x2::from_array([rng.next_u64(), rng.next_u64()]))
    }

    // fn from_bits(bits: &[bool]) -> Option<Self> {
    //     if bits.len() != Self::BITS {
    //         return None;
    //     }
    //     let mut output = u64x2::default();
    //     for (idx, bit) in bits.iter().enumerate() {
    //         if *bit {
    //             GF128::toggle_bit(&mut output, idx as u32);
    //         }
    //     }
    //     Some(GF128(output))
    // }
}

impl GF128 {
    const U64X2_ZERO: u64x2 = u64x2::from_array([0u64, 0u64]);
    const U64X2_ONE: u64x2 = u64x2::from_array([1u64, 0u64]);

    // #[inline]
    pub fn get_deg(v: &u64x2) -> u32 {
        let lzcnt: u64x2 = unsafe { _mm_lzcnt_epi64((*v).into()) }.into();
        (127 - lzcnt[1] - u64::from(lzcnt[1] == 64) * (lzcnt[0])) as u32
    }
    #[inline]
    fn toggle_bit(v: &mut u64x2, offset: u32) {
        v[(offset / 64) as usize] ^= 1u64 << (offset % 64);
    }
    pub fn get_bit(&self, offset: usize) -> bool {
        (self.0[offset / 64] >> (offset % 64)) & 1 != 0
    }

    /// Divides IRREDUCIBLE_POLYNOMIAL by v.
    /// This requires a special function since IRREDUCIBLE_POLYNOMIAL can't be represented
    /// using GF128 since it has 129 coefficients.
    fn irred_div_by(v: &u64x2) -> (u64x2, u64x2) {
        let self_deg = GF128::get_deg(v);
        let mut q = u64x2::from_array([0, 0]);
        // The &127 is for the special case in which v is 1.
        GF128::toggle_bit(&mut q, (128 - self_deg) & 127);
        let nom = GF128::shl(v, 128 - self_deg) ^ IRREDUCIBLE_POLYNOMIAL;
        let (q_prime, r_prime) = GF128::div_rem(&nom, v);
        (q ^ q_prime, r_prime)
    }
    /// Assumes deg(nom) >= deg(denom), otherwise - undefined behavior.
    fn div_rem(nom: &u64x2, denom: &u64x2) -> (u64x2, u64x2) {
        let mut nom = *nom;
        let mut deg_nom = Self::get_deg(&nom);
        let deg_denom = Self::get_deg(denom);
        let mut q = u64x2::from_array([0; 2]);
        while deg_nom >= deg_denom {
            let q_deg = deg_nom - deg_denom;
            nom ^= Self::shl(denom, q_deg);
            GF128::toggle_bit(&mut q, q_deg);
            if nom == GF128::U64X2_ZERO {
                break;
            }
            deg_nom = Self::get_deg(&nom);
        }
        (q, nom)
    }

    #[inline]
    #[allow(dead_code)]
    fn shl_assign(a: &mut u64x2, b: u32) {
        unsafe { transmute::<&mut u64x2, &mut u128>(a).shl_assign(b) };
    }
    #[inline]
    fn shl(a: &u64x2, b: u32) -> u64x2 {
        unsafe { transmute::<u128, u64x2>(transmute::<&u64x2, &u128>(a).shl(b)) }
    }
    fn mul_inner(a: &GF128, b: &GF128) -> GF128 {
        let (mut lower, upper) = Self::mul_no_reduce(&a.0, &b.0);

        lower ^= Self::mod_reduce(upper);
        GF128(lower)
    }
    fn mul_no_reduce(a: &u64x2, b: &u64x2) -> (u64x2, u64x2) {
        let a: __m128i = (*a).into();
        let b: __m128i = (*b).into();
        let mut output: u64x2 = unsafe { _mm_clmulepi64_si128::<LOWER_LOWER>(a, b) }.into();
        let mut upper: u64x2 = unsafe { _mm_clmulepi64_si128::<UPPER_UPPER>(a, b) }.into();
        let middle: u64x2 = unsafe {
            _mm_xor_si128(
                _mm_clmulepi64_si128::<UPPER_LOWER>(a, b),
                _mm_clmulepi64_si128::<LOWER_UPPER>(a, b),
            )
        }
        .into();
        output.as_mut_array()[1] ^= middle.as_array()[0];
        upper.as_mut_array()[0] ^= middle.as_array()[1];
        (output, upper)
    }
    /// Reduces the polynomials to_reduce*x^128.
    #[inline]
    fn mod_reduce(to_reduce: u64x2) -> u64x2 {
        let mut output: u64x2 = unsafe {
            _mm_clmulepi64_si128::<LOWER_LOWER>(to_reduce.into(), IRREDUCIBLE_POLYNOMIAL.into())
        }
        .into();
        let upper: u64x2 = unsafe {
            _mm_clmulepi64_si128::<UPPER_LOWER>(to_reduce.into(), IRREDUCIBLE_POLYNOMIAL.into())
        }
        .into();
        output.as_mut_array()[1] ^= upper.as_array()[0];
        let reduced_half: u64x2 = unsafe {
            _mm_clmulepi64_si128::<UPPER_LOWER>(upper.into(), IRREDUCIBLE_POLYNOMIAL.into())
        }
        .into();
        output ^ reduced_half
    }

    pub fn random_not_cryptographic(mut rng: impl RngCore) -> Self {
        GF128(u64x2::from_array([rng.next_u64(), rng.next_u64()]))
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
        let (mut t_old, mut t) = (GF128::U64X2_ZERO, GF128::U64X2_ONE);

        // Since we don't represent the upper bit of the irreducible polynomial, we "bootstrap"
        // the division.
        let (mut q, mut r) = GF128::irred_div_by(&self.0);
        let mut r_old = self.0;
        (t_old, t) = (t, t_old ^ GF128::mul_no_reduce(&t, &q).0);
        while r != GF128::U64X2_ONE {
            ((q, r), r_old) = (GF128::div_rem(&r_old, &r), r);
            (t_old, t) = (t, t_old ^ GF128::mul_no_reduce(&t, &q).0);
        }
        t.into()
    }

    pub fn flip(&mut self) {
        self.0 = !self.0.not()
    }
}

impl Display for GF128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..128 {
            write!(f, "{}", self.get_bit(i) as u8)?;
        }
        Ok(())
    }
}

impl IntermediateMulField for GF128 {
    type MulRes = MulResidue128;
    fn intermediate_mul(&self, rhs: &Self) -> Self::MulRes {
        let v = GF128::mul_no_reduce(&self.0, &rhs.0);
        MulResidue128 {
            base: v.0,
            carry: v.1,
        }
    }
}

#[derive(Clone, Copy)]
pub struct MulResidue128 {
    base: u64x2,
    carry: u64x2,
}
impl MulResidue<GF128> for MulResidue128 {
    fn reduce(&self) -> GF128 {
        let v = GF128::mod_reduce(self.carry);
        GF128(v ^ self.base)
    }
}
impl From<GF128> for MulResidue128 {
    fn from(value: GF128) -> Self {
        Self {
            base: value.0,
            carry: u64x2::default(),
        }
    }
}

impl AddAssign for MulResidue128 {
    fn add_assign(&mut self, rhs: Self) {
        self.base ^= rhs.base;
        self.carry ^= rhs.carry;
    }
}

impl Add for MulResidue128 {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}
impl Sum for MulResidue128 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(
            Self {
                base: u64x2::default(),
                carry: u64x2::default(),
            },
            |cur, acc| cur + acc,
        )
    }
}
impl SubAssign for MulResidue128 {
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}
impl Sub for MulResidue128 {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use std::simd::u64x2;

    use super::{GF128, IRREDUCIBLE_POLYNOMIAL, IRREDUCIBLE_POLYNOMIAL_U64};

    #[test]
    pub fn test_bit_manipulation() {
        let mut a = GF128::zero();
        for i in 0..128 {
            assert!(!a.get_bit(i))
        }
        for i in (0..128).step_by(2) {
            a.set_bit(true, i);
        }
        for i in 0..128 {
            if i & 1 == 0 {
                assert!(a.get_bit(i));
            } else {
                assert!(!a.get_bit(i));
            }
        }
    }
    #[test]
    pub fn test_mul() {
        let a = GF128(u64x2::from_array([0, 1]));
        let b = GF128(u64x2::from_array([0, 1]));
        let c = a * b;
        assert_eq!(c.0, IRREDUCIBLE_POLYNOMIAL);
    }
    #[test]
    pub fn test_dev_rem() {
        let a = u64x2::from_array([0, 1]);
        let b = u64x2::from_array([1u64 << 60, 0]);
        let (q, r) = GF128::div_rem(&a, &b);
        assert_eq!(q, u64x2::from_array([1 << 4, 0]));
        assert_eq!(r, u64x2::splat(0));
    }

    #[test]
    pub fn test_irred_dib() {
        let a = u64x2::from_array([2, 0]);
        let (q, r) = GF128::irred_div_by(&a);
        assert_eq!(
            q,
            u64x2::from_array([IRREDUCIBLE_POLYNOMIAL_U64 / 2, 1u64 << 63])
        );
        assert_eq!(r, u64x2::from_array([1, 0]));
    }

    #[test]
    pub fn test_inv_one() {
        assert_eq!(GF128::one().inv(), GF128::one());
    }
    #[test]
    #[should_panic]
    pub fn test_inv_zero() {
        GF128::zero().inv();
    }
    #[test]
    pub fn test_inv() {
        let x = GF128(u64x2::from_array([(1 << 6) + (1 << 1) + 1, 1u64 << 63])).inv();
        assert_eq!(x, GF128(u64x2::from_array([2, 0])));

        for i in 0u64..1000 {
            let x = GF128(u64x2::from_array([i, i + 1]));
            assert_eq!(x.inv().inv(), x);
        }
    }
    #[test]
    pub fn test_inv_with_mul() {
        for i in 0u64..1000 {
            let x = GF128(u64x2::from_array([i, i + 1]));
            let x_inv = x.inv();
            let y = x * x_inv;
            assert!(y.is_one());
        }
    }

    #[test]
    pub fn test_from_into() {
        let element = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let e = GF128::from(element);
        let new_element: [u8; 16] = e.into();
        assert_eq!(element, new_element);
    }
}
