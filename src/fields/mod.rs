mod gf128;
mod gf2;
mod packed_gf2;
pub use gf128::GF128;
pub use gf2::GF2;
pub use packed_gf2::PackedGF2Array;
pub use packed_gf2::PackedGF2U64;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::ops::Neg;
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
    + Neg<Output = Self>
    + DeserializeOwned
    + Serialize
    + Debug
{
    fn one() -> Self;
    fn is_one(&self) -> bool;

    fn zero() -> Self;
    fn is_zero(&self) -> bool;

    const BITS: usize;
    fn set_bit(&mut self, bit: bool, idx: usize);
}
