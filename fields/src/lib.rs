#![feature(portable_simd, stdsimd)]
mod gf128;
pub use gf128::GF128;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Not, Sub, SubAssign};
pub trait FieldElement:
    Add + Sub + Mul + Div + AddAssign + SubAssign + MulAssign + DivAssign + Neg + Sized + Eq
{
}
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
