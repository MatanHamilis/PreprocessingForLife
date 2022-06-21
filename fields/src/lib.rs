#![feature(portable_simd, stdsimd)]
mod gf128;
mod gf2;
pub use gf128::GF128;
pub use gf2::GF2;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
pub trait FieldElement:
    Add + Sub + Mul + Div + AddAssign + SubAssign + MulAssign + DivAssign + Neg + Sized + Eq
{
    fn one() -> Self;
    fn is_one(&self) -> bool;

    fn zero() -> Self;
    fn is_zero(&self) -> bool;
}
