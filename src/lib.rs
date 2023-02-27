#![feature(option_get_or_insert_default)]
#![feature(portable_simd, stdsimd)]
#![feature(maybe_uninit_uninit_array)]
#![feature(split_array)]

use std::io::{Read, Write};

use communicator::Communicator;
use fields::GF128;
use pcg::{
    codes::EACode,
    full_key::{FullPcgKey, Role},
    receiver_key::PcgKeyReceiver,
    sender_key::PcgKeySender,
    sparse_vole::{scalar_party, vector_party},
    KEY_SIZE,
};
use pseudorandom::prf::PrfInput;

pub mod circuit_eval;
pub mod communicator;
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

fn scalar_key_gen<T: Write + Read, const CODE_WEIGHT: usize, const INPUT_BITLEN: usize>(
    scalar: GF128,
    code_seed: [u8; KEY_SIZE],
    communicator: &mut Communicator<T>,
) -> scalar_party::OnlineSparseVoleKey<CODE_WEIGHT, EACode<CODE_WEIGHT>> {
    let pcg_offline_key_scalar =
        scalar_party::distributed_generation::<INPUT_BITLEN, _>(&scalar, communicator).unwrap();
    let ea_code_scalar =
        EACode::<CODE_WEIGHT>::new(pcg_offline_key_scalar.vector_length(), code_seed);
    pcg_offline_key_scalar.provide_online_key(ea_code_scalar)
}

fn vector_key_gen<
    T: Write + Read,
    const PUNCTURING_POINTS_NO: usize,
    const CODE_WEIGHT: usize,
    const INPUT_BITLEN: usize,
>(
    prf_keys: [[u8; KEY_SIZE]; PUNCTURING_POINTS_NO],
    puncturing_points: [PrfInput<INPUT_BITLEN>; PUNCTURING_POINTS_NO],
    communicator: &mut Communicator<T>,
    code_seed: [u8; KEY_SIZE],
) -> vector_party::OnlineSparseVoleKey<CODE_WEIGHT, EACode<CODE_WEIGHT>> {
    let pcg_offline_key_vector = vector_party::distributed_generation(
        Vec::from_iter(puncturing_points.into_iter()),
        Vec::from_iter(prf_keys.into_iter()),
        communicator,
    )
    .unwrap();
    let ea_code_vector =
        EACode::<CODE_WEIGHT>::new(pcg_offline_key_vector.vector_length(), code_seed);
    pcg_offline_key_vector.provide_online_key(ea_code_vector)
}
pub fn pcg_key_gen<
    T: Write + Read,
    const PUNCTURING_POINTS_NO: usize,
    const INPUT_BITLEN: usize,
    const CODE_WEIGHT: usize,
>(
    prf_keys: [[u8; KEY_SIZE]; PUNCTURING_POINTS_NO],
    puncturing_points: [PrfInput<INPUT_BITLEN>; PUNCTURING_POINTS_NO],
    scalar: GF128,
    code_seed_first: [u8; KEY_SIZE],
    code_seed_second: [u8; KEY_SIZE],
    role: Role,
    communicator: &mut Communicator<T>,
) -> FullPcgKey<
    vector_party::OnlineSparseVoleKey<CODE_WEIGHT, EACode<CODE_WEIGHT>>,
    scalar_party::OnlineSparseVoleKey<CODE_WEIGHT, EACode<CODE_WEIGHT>>,
> {
    let (scalar_key, vector_key) = match role {
        Role::Receiver => {
            let scalar_key = scalar_key_gen::<T, CODE_WEIGHT, INPUT_BITLEN>(
                scalar,
                code_seed_first,
                communicator,
            );
            let vector_key =
                vector_key_gen(prf_keys, puncturing_points, communicator, code_seed_second);
            (scalar_key, vector_key)
        }
        Role::Sender => {
            let vector_key =
                vector_key_gen(prf_keys, puncturing_points, communicator, code_seed_first);
            let scalar_key = scalar_key_gen::<T, CODE_WEIGHT, INPUT_BITLEN>(
                scalar,
                code_seed_second,
                communicator,
            );
            (scalar_key, vector_key)
        }
    };
    FullPcgKey::new(
        PcgKeySender::from(scalar_key),
        PcgKeyReceiver::from(vector_key),
        role,
    )
}
