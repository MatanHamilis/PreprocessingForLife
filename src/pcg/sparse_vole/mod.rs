//! For a sparse-VOLE correlation we need one party (called the "ScalarParty") to hold some scalar in a large field $x\in \mathbb{F}_2^128$.
//! The second party (called the "VectorParty") holds a sparse vector $v$ of weight $t$.
//! We view $v$ as the sum of $t$ unit vectors $v=v_1+...+v_t$.
//! For each unit vector $v_i$ we split the unit vector using PPRF.
//! The full PRF-key remains with the ScalarParty.
//! The PPRF key is obtained by the VectorParty (using Ds17 protocol).
//! After it is obtained, the ScalarParty sends the sum of *all* points of the PPRF to the VectorParty plus the scalar $x$.
//! In other words, the ScalarParty sums $PRF(i)$ for all $i$ in the input domain of the PRF in a value $s$ and sends $(s+x)\in \mathbb{F}_{2^128}$ to the VectorParty$.
//! By subtracting from the value it received the sum of all points in the PPRF, the VectorParty can obtain the $p+x$ where $p$ is the value of the PRF at the puncturing point.

use self::packed::{SparseVoleScalarPartyPackedOfflineKey, SparseVoleVectorPartyPackedOfflineKey};
use self::scalar_party::{
    OfflineSparseVoleKey as ScalarSparseVoleOfflineKey, SparseVolePcgScalarKeyGenState,
};
use self::vector_party::{
    OfflineSparseVoleKey as VectorSparseVoleOfflineKey, SparseVolePcgVectorKeyGenStateInitial,
};
use self::{
    scalar_party::OnlineSparseVoleKey as OnlineSparseVoleKeyScalar,
    vector_party::OnlineSparseVoleKey as OnlineSparseVoleKeyVector,
};
use super::codes::EACode;
use super::pprf_aggregator::RegularErrorPprfAggregator;
use crate::fields::GF128;
use crate::pseudorandom::KEY_SIZE;

pub mod packed;
pub mod scalar_party;
pub mod vector_party;

pub fn trusted_deal<const PRF_INPUT_BITLEN: usize, const CODE_WEIGHT: usize>(
    scalar: &GF128,
    puncturing_points: Vec<[bool; PRF_INPUT_BITLEN]>,
    prf_keys: Vec<[u8; KEY_SIZE]>,
) -> (
    OnlineSparseVoleKeyScalar<CODE_WEIGHT, EACode<CODE_WEIGHT>>,
    OnlineSparseVoleKeyVector<CODE_WEIGHT, EACode<CODE_WEIGHT>>,
) {
    // Define Gen State
    let mut scalar_keygen_state =
        SparseVolePcgScalarKeyGenState::<PRF_INPUT_BITLEN>::new(*scalar, prf_keys);

    let mut vector_keygen_state_init =
        SparseVolePcgVectorKeyGenStateInitial::new(puncturing_points);

    // Run Gen Algorithm
    let scalar_first_message = scalar_keygen_state.create_first_message();
    let vector_msg = vector_keygen_state_init.create_first_message(&scalar_first_message);
    let scalar_second_message = scalar_keygen_state.create_second_message(&vector_msg);
    let vector_keygen_state_final =
        vector_keygen_state_init.handle_second_message(scalar_second_message);

    // Create Offline Keys
    let scalar_offline_key = scalar_keygen_state.keygen_offline::<RegularErrorPprfAggregator>();
    let vector_offline_key =
        vector_keygen_state_final.keygen_offline::<RegularErrorPprfAggregator>();

    // Create code
    let code_seed = [0; 16];
    let scalar_code = EACode::<CODE_WEIGHT>::new(scalar_offline_key.vector_length(), code_seed);
    let vector_code = EACode::<CODE_WEIGHT>::new(vector_offline_key.vector_length(), code_seed);

    // Create online keys
    let scalar_online_key = scalar_offline_key.provide_online_key(scalar_code);
    let vector_online_key = vector_offline_key.provide_online_key(vector_code);
    (scalar_online_key, vector_online_key)
}

pub fn trusted_deal_packed_offline_keys<const PACK: usize, const PRF_INPUT_BITLEN: usize>(
    scalar: &[GF128; PACK],
    puncturing_points: [Vec<[bool; PRF_INPUT_BITLEN]>; PACK],
    prf_keys: [Vec<[u8; KEY_SIZE]>; PACK],
) -> (
    SparseVoleScalarPartyPackedOfflineKey<PACK>,
    SparseVoleVectorPartyPackedOfflineKey<PACK>,
) {
    let mut scalar_keys: [std::mem::MaybeUninit<ScalarSparseVoleOfflineKey>; PACK] =
        std::mem::MaybeUninit::uninit_array();
    let mut vector_keys: [std::mem::MaybeUninit<VectorSparseVoleOfflineKey>; PACK] =
        std::mem::MaybeUninit::uninit_array();
    prf_keys
        .into_iter()
        .zip(scalar.into_iter())
        .zip(puncturing_points.into_iter())
        .zip(scalar_keys.iter_mut())
        .zip(vector_keys.iter_mut())
        .for_each(
            |((((prf_key, scalar), puncturing_points), scalar_key), vector_key)| {
                // Define Gen State
                let mut scalar_keygen_state =
                    SparseVolePcgScalarKeyGenState::<PRF_INPUT_BITLEN>::new(*scalar, prf_key);

                let mut vector_keygen_state_init =
                    SparseVolePcgVectorKeyGenStateInitial::new(puncturing_points);

                // Run Gen Algorithm
                let scalar_first_message = scalar_keygen_state.create_first_message();
                let vector_msg =
                    vector_keygen_state_init.create_first_message(&scalar_first_message);
                let scalar_second_message = scalar_keygen_state.create_second_message(&vector_msg);
                let vector_keygen_state_final =
                    vector_keygen_state_init.handle_second_message(scalar_second_message);

                // Create Offline Keys
                let scalar_offline_key =
                    scalar_keygen_state.keygen_offline::<RegularErrorPprfAggregator>();
                let vector_offline_key =
                    vector_keygen_state_final.keygen_offline::<RegularErrorPprfAggregator>();
                scalar_key.write(scalar_offline_key);
                vector_key.write(vector_offline_key);
            },
        );

    (
        SparseVoleScalarPartyPackedOfflineKey::new(unsafe {
            scalar_keys
                .as_ptr()
                .cast::<[ScalarSparseVoleOfflineKey; PACK]>()
                .read()
        }),
        SparseVoleVectorPartyPackedOfflineKey::new(unsafe {
            vector_keys
                .as_ptr()
                .cast::<[VectorSparseVoleOfflineKey; PACK]>()
                .read()
        }),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use self::{
        super::scalar_party::OnlineSparseVoleKey as OnlineSparseVoleKeyScalar,
        super::vector_party::OnlineSparseVoleKey as OnlineSparseVoleKeyVector,
    };
    use super::super::preprocessor::Preprocessor;
    use super::super::KEY_SIZE;
    use super::packed::{
        SparseVoleScalarPartyPackedOnlineKey, SparseVoleVectorPartyPackedOnlineKey,
    };
    use crate::pcg::codes::EACode;
    use crate::pprf::usize_to_bits;
    use crate::{
        fields::{FieldElement, GF128},
        pcg::sparse_vole::{trusted_deal, trusted_deal_packed_offline_keys},
    };

    pub(crate) fn get_correlation(
        scalar: &GF128,
    ) -> (
        OnlineSparseVoleKeyScalar<2, EACode<2>>,
        OnlineSparseVoleKeyVector<2, EACode<2>>,
    ) {
        // Define constants
        const WEIGHT: usize = 128;
        const CODE_WEIGHT: usize = 2;
        const INPUT_BITLEN: usize = 10;
        let prf_keys = (0..WEIGHT)
            .map(|num| {
                let mut output = [0u8; KEY_SIZE];
                let bits = usize_to_bits::<KEY_SIZE>(num);
                for (i, b) in bits.iter().enumerate() {
                    if *b {
                        output[i] = 1;
                    }
                }
                output
            })
            .collect();
        let puncturing_points = (0..WEIGHT)
            .map(|i| usize_to_bits::<INPUT_BITLEN>(i * 100))
            .collect();

        // Create online keys
        trusted_deal::<INPUT_BITLEN, CODE_WEIGHT>(&scalar, puncturing_points, prf_keys)
    }

    pub(crate) fn get_packed_correlation<const PACK: usize>(
        scalars: &[GF128; PACK],
    ) -> (
        SparseVoleScalarPartyPackedOnlineKey<PACK, 8, EACode<8>>,
        SparseVoleVectorPartyPackedOnlineKey<PACK, 8, EACode<8>>,
    ) {
        // Define constants
        const WEIGHT: usize = 128;
        const INPUT_BITLEN: usize = 10;
        let prf_keys: [Vec<[u8; KEY_SIZE]>; PACK] = core::array::from_fn(|idx| {
            (0..WEIGHT)
                .map(|num| {
                    let mut output = [0u8; KEY_SIZE];
                    let bits = usize_to_bits::<KEY_SIZE>((num + idx) * idx);
                    for (i, b) in bits.iter().enumerate() {
                        if *b {
                            output[i] = 1;
                        }
                    }
                    output
                })
                .collect()
        });
        let puncturing_points: [Vec<[bool; INPUT_BITLEN]>; PACK] = core::array::from_fn(|idx| {
            (0..WEIGHT)
                .map(|i| usize_to_bits::<INPUT_BITLEN>(i * (100 + idx)))
                .collect()
        });

        // Create offline keys
        let (scalar_offline_key, vector_offline_key) = trusted_deal_packed_offline_keys::<
            PACK,
            INPUT_BITLEN,
        >(
            scalars, puncturing_points, prf_keys
        );

        const CODE_SEED: [u8; 16] = [0; 16];
        let code_scalar = EACode::new(scalar_offline_key.len(), CODE_SEED);
        let code_vector = EACode::new(scalar_offline_key.len(), CODE_SEED);
        // Create online keys
        (
            SparseVoleScalarPartyPackedOnlineKey::new(code_scalar, scalar_offline_key),
            SparseVoleVectorPartyPackedOnlineKey::new(code_vector, vector_offline_key),
        )
    }
    #[test]
    fn test_full_correlation() {
        let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let (scalar_online_key, vector_online_key) = get_correlation(&scalar);
        // Expand the online keys
        let mut i = 0;
        for ((scalar_gf, scalar_pcg), (vector_bit, vector_gf)) in
            scalar_online_key.zip(vector_online_key).take(3000)
        {
            i = dbg!(i) + 1;
            assert_eq!(scalar_pcg, scalar);
            if vector_bit.is_one() {
                assert_eq!((scalar_gf + vector_gf), scalar);
            } else {
                assert_eq!((scalar_gf + vector_gf), GF128::zero());
            }
        }
    }
    #[test]
    fn test_full_correlation_packed() {
        const PACK: usize = 10;
        const TESTS: usize = 3000;
        let scalar = [GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]); PACK];
        let (scalar_online_key, vector_online_key) = get_packed_correlation(&scalar);
        let mut i = 0;
        // Expand the online keys
        for ((scalar_gf, scalar_pcg), (vector_bit, vector_gf)) in
            scalar_online_key.zip(vector_online_key).take(TESTS)
        {
            i += 1;
            if vector_bit.is_one() {
                assert_eq!((scalar_gf + vector_gf), scalar_pcg);
            } else {
                assert_eq!((scalar_gf + vector_gf), GF128::zero());
            }
        }
        assert_eq!(i, TESTS);
    }
}
