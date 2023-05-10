mod gf128;
mod gf2;
mod gf64;
mod packed_gf2;
pub use gf128::GF128;
pub use gf2::PackedGF2;
pub use gf2::GF2;
pub use gf64::GF64;
pub use packed_gf2::PackedGF2Array;
pub use packed_gf2::PackedGF2U64;
use rand::CryptoRng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::iter::Sum;
use std::ops::Neg;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};
trait MulResidue<F: FieldElement>:
    Add<Output = Self> + AddAssign + Sub<Output = Self> + SubAssign + Copy + Clone + Send + Sync + Sum
{
    fn reduce(self) -> F;
}
trait IntermediateMulField: FieldElement {
    type MulRes: MulResidue<Self>;
    fn intermediate_mul(&self, rhs: &Self) -> Self::MulRes;
}

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
    + Send
    + Sync
    + Sum
    + 'static
{
    fn one() -> Self;
    fn is_one(&self) -> bool;

    fn zero() -> Self;
    fn is_zero(&self) -> bool;

    const BITS: usize;
    fn set_bit(&mut self, bit: bool, idx: usize);
    fn random(rng: impl CryptoRng + RngCore) -> Self;
    fn from_bit(bit: bool) -> Self {
        if bit {
            Self::one()
        } else {
            Self::zero()
        }
    }
    fn switch(&self, bit: bool) -> Self {
        if bit {
            *self
        } else {
            Self::zero()
        }
    }
}

pub trait PackedField<F: FieldElement, const PACKING: usize>: FieldElement {
    fn get_element(&self, i: usize) -> F;
    fn set_element(&mut self, i: usize, value: &F);
}
