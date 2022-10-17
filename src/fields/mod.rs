mod gf128;
mod gf2;
mod packed_gf2;
pub use gf128::GF128;
pub use gf2::GF2;
pub use packed_gf2::PackedGF2Array;
pub use packed_gf2::PackedGF2U64;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};
pub trait FieldElement:
    Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + DivAssign
    + Sized
    + Eq
    + Copy
    + Default
{
    fn one() -> Self;
    fn is_one(&self) -> bool;

    fn zero() -> Self;
    fn is_zero(&self) -> bool;

    const BITS: usize;
    fn from_bits(bits: &[bool]) -> Option<Self>;
}
