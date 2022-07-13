use aes::Block;
use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_lzcnt_epi64, _mm_xor_si128};
use core::simd::u64x2;
use rand_core::{CryptoRng, RngCore};
use std::iter::Sum;
use std::mem::transmute;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, ShlAssign, Sub, SubAssign};
use std::ops::{Not, Shl};

use super::gf2::GF2;
use super::FieldElement;

/// This is the irreducible polynomial $x^128 + x^7 + x^2 + x + 1$.
const IRREDUCIBLE_POLYNOMIAL_U64: u64 = (1 << 7) + (1 << 2) + (1 << 1) + (1 << 0);
const IRREDUCIBLE_POLYNOMIAL: u64x2 = u64x2::from_array([IRREDUCIBLE_POLYNOMIAL_U64, 0]);

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct GF128(u64x2);

impl Into<Block> for GF128 {
    fn into(self) -> Block {
        unsafe { std::mem::transmute(self) }
    }
}

impl Sum for GF128 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(GF128::zero(), |acc, v| acc + v)
    }
}
impl Neg for GF128 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        GF128(self.0.not())
    }
}

impl Add for GF128 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        GF128(self.0 ^ rhs.0)
    }
}

impl AddAssign for GF128 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl Sub for GF128 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl SubAssign for GF128 {
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
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inv()
    }
}

impl DivAssign for GF128 {
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

impl Into<[u8; 16]> for GF128 {
    fn into(self) -> [u8; 16] {
        unsafe { transmute(self.0.to_array()) }
    }
}

impl FieldElement for GF128 {
    fn one() -> Self {
        GF128(GF128::U64X2_ONE)
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
    fn set_bit(v: &mut u64x2, offset: u32) {
        v[(offset / 64) as usize] ^= 1u64 << (offset % 64);
    }
    /// Divides IRREDUCIBLE_POLYNOMIAL by v.
    /// This requires a special function since IRREDUCIBLE_POLYNOMIAL can't be represented
    /// using GF128 since it has 129 coefficients.
    fn irred_div_by(v: &u64x2) -> (u64x2, u64x2) {
        let self_deg = GF128::get_deg(v);
        let mut q = u64x2::from_array([0, 0]);
        // The &127 is for the special case in which v is 1.
        GF128::set_bit(&mut q, (128 - self_deg) & 127);
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
            GF128::set_bit(&mut q, q_deg);
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

    /// Returns a random field element
    pub fn random<T: CryptoRng + RngCore>(rng: &mut T) -> Self {
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
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use std::simd::u64x2;

    use super::{GF128, IRREDUCIBLE_POLYNOMIAL, IRREDUCIBLE_POLYNOMIAL_U64};
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
