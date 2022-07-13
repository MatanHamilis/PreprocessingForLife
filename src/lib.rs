#![feature(option_get_or_insert_default)]
#![feature(portable_simd, stdsimd)]

pub mod fields;
pub mod non_committing_encryption;
pub mod ot;
pub mod pcg;
pub mod pprf;
pub mod pseudorandom;

pub(crate) fn xor_arrays<const LENGTH: usize>(a: &mut [u8; LENGTH], b: &[u8; LENGTH]) {
    for i in 0..LENGTH {
        a[i] ^= b[i];
    }
}
