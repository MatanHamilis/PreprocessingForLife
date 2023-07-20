mod gf128;
mod gf2;
mod gf64;
mod packed_gf2;
use blake3::Hasher;
pub use gf128::GF128;
pub use gf2::PackedGF2;
pub use gf2::GF2;
pub use gf64::GF64;
pub use gf_mersenne::GFMersenne;
use rand::CryptoRng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::iter::Sum;
use std::ops::Neg;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};
mod gf_mersenne;
pub trait MulResidue<F: FieldElement>:
    Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Copy
    + Clone
    + Send
    + Sync
    + Sum
    + From<F>
{
    fn reduce(&self) -> F;
}
pub trait IntermediateMulField: FieldElement {
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

    fn hash(&self, hasher: &mut Hasher);
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
    fn as_bytes(&self) -> &[u8];
    fn number(mut number: u32) -> Self {
        let mut pow = Self::one();
        let mut two = Self::one();
        two.set_bit(true, 1);
        let mut output = Self::zero();
        while number != 0 {
            if number & 1 == 1 {
                output += pow;
            }
            pow *= two;
            number >>= 1;
        }
        output
    }
}

pub trait PackedField<F: FieldElement, const PACKING: usize>: FieldElement {
    fn get_element(&self, i: usize) -> F;
    fn set_element(&mut self, i: usize, value: &F);
}
