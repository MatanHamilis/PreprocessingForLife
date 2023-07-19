#![feature(option_get_or_insert_default)]
#![feature(portable_simd, stdsimd)]
#![feature(maybe_uninit_uninit_array)]
#![feature(split_array)]
#![feature(maybe_uninit_array_assume_init)]
#![feature(generic_const_exprs)]

pub mod circuit_eval;
pub mod commitment;
pub mod engine;
pub mod fields;
pub mod ot;
pub mod pcg;
pub mod pprf;
pub mod pseudorandom;
mod uc_tags;
pub mod zkfliop;

pub use engine::PartyId;
pub use uc_tags::UCTag;

pub(crate) fn xor_arrays<const LENGTH: usize>(a: &mut [u8; LENGTH], b: &[u8; LENGTH]) {
    for i in 0..LENGTH {
        a[i] ^= b[i];
    }
}

pub(crate) fn diff_arrays<const LENGTH: usize, F: std::ops::Sub<F, Output = F> + Copy>(
    a: &[F; LENGTH],
    b: &[F; LENGTH],
) -> [F; LENGTH] {
    core::array::from_fn(|i| a[i] - b[i])
}
pub(crate) fn diff_assign_arrays<F: std::ops::SubAssign<F> + Copy>(a: &mut [F], b: &[F]) {
    a.iter_mut().zip(b.iter()).for_each(|(ai, bi)| *ai -= *bi);
}

pub(crate) fn add_assign_arrays<const LENGTH: usize, F: std::ops::AddAssign<F> + Copy>(
    a: &mut [F; LENGTH],
    b: &[F; LENGTH],
) {
    a.iter_mut().zip(b.iter()).for_each(|(ai, bi)| *ai += *bi);
}
