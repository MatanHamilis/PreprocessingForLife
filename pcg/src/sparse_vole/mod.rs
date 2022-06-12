//! For a sparse-VOLE correlation we need one party (called the "ScalarParty") to hold some scalar in a large field $x\in \mathbb{F}_2^128$.
//! The second party (called the "VectorParty") holds a sparse vector $v$ of weight $t$.
//! We view $v$ as the sum of $t$ unit vectors $v=v_1+...+v_t$.
//! For each unit vector $v_i$ we split the unit vector using PPRF.
//! The full PRF-key remains with the ScalarParty.
//! The PPRF key is obtained by the VectorParty (using Ds17 protocol).
//! After it is obtained, the ScalarParty sends the sum of *all* points of the PPRF to the VectorParty plus the scalar $x$.
//! In other words, the ScalarParty sums $PRF(i)$ for all $i$ in the input domain of the PRF in a value $s$ and sends $(s+x)\in \mathbb{F}_{2^128}$ to the VectorParty$.
//! By subtracting from the value it received the sum of all points in the PPRF, the VectorParty can obtain the $p+x$ where $p$ is the value of the PRF at the puncturing point.

pub mod scalar_party;
pub mod vector_party;

#[cfg(test)]
mod tests {

    use crate::{
        codes::EACode,
        pprf_aggregator::{RandomErrorPprfAggregator, RegularErrorPprfAggregator},
        sparse_vole::{
            scalar_party::SparseVolePcgScalarKeyGenState,
            vector_party::SparseVolePcgVectorKeyGenStateInitial,
        },
        KEY_SIZE,
    };

    use fields::{FieldElement, GF128};
    use pprf::usize_to_bits;

    #[test]
    fn test_full_correlation() {
        // Define constants
        const WEIGHT: usize = 128;
        const CODE_WEIGHT: usize = 10;
        const INPUT_BITLEN: usize = 10;
        let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
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

        // Define Gen State
        let mut scalar_keygen_state =
            SparseVolePcgScalarKeyGenState::<INPUT_BITLEN>::new(scalar.clone(), prf_keys);

        let puncturing_points = (0..WEIGHT).map(|i| usize_to_bits(i * 100)).collect();

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
        let code_seed = [0; 32];
        let scalar_code =
            EACode::<CODE_WEIGHT>::new(scalar_offline_key.vector_length(), 100, code_seed);
        let vector_code =
            EACode::<CODE_WEIGHT>::new(vector_offline_key.vector_length(), 100, code_seed);

        // Create online keys
        let scalar_online_key = scalar_offline_key.provide_online_key(scalar_code);
        let vector_online_key = vector_offline_key.provide_online_key(vector_code);

        // Expand the online keys
        for (scalar_gf, (vector_bit, vector_gf)) in scalar_online_key.zip(vector_online_key) {
            if vector_bit.is_one() {
                assert_eq!((scalar_gf + vector_gf), scalar);
            } else {
                assert_eq!((scalar_gf + vector_gf), GF128::zero());
            }
        }
    }
}
