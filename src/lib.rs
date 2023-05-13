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
