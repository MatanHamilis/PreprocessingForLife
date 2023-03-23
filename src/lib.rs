#![feature(option_get_or_insert_default)]
#![feature(portable_simd, stdsimd)]
#![feature(maybe_uninit_uninit_array)]
#![feature(split_array)]

use fields::GF128;
// use pcg::{
//     codes::EACode,
//     full_key::{FullPcgKey, Role},
//     receiver_key::PcgKeyReceiver,
//     sender_key::PcgKeySender,
//     sparse_vole::{scalar_party, vector_party},
//     KEY_SIZE,
// };
// use pseudorandom::prf::PrfInput;

pub mod circuit_eval;
mod engine;
pub mod fields;
pub mod ot;
pub mod pcg;
pub mod pprf;
pub mod pseudorandom;
mod uc_tags;
mod zkfliop;

pub(crate) fn xor_arrays<const LENGTH: usize>(a: &mut [u8; LENGTH], b: &[u8; LENGTH]) {
    for i in 0..LENGTH {
        a[i] ^= b[i];
    }
}
