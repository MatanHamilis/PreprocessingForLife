use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fields::GF128;
use pcg::codes::EACode;
use pcg::pprf_aggregator::RegularErrorPprfAggregator;
use pcg::sparse_vole::scalar_party::SparseVolePcgScalarKeyGenState;
use pcg::sparse_vole::vector_party::SparseVolePcgVectorKeyGenStateInitial;
use pprf::usize_to_bits;
use std::time::Instant;

pub fn full_pcg_bench(c: &mut Criterion) {
    c.bench_function("full_pcg_bench", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for i in 0..iters as usize {
                const PRF_KEYS_NUM: usize = 128;
                const CODE_WEIGHT: usize = 10;
                const INPUT_BITLEN: usize = 13;
                const KEY_SIZE: usize = 16;
                let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
                let mut i = 0;
                let prf_keys = (0..PRF_KEYS_NUM)
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

                let puncturing_points = (0..PRF_KEYS_NUM).map(|i| usize_to_bits(i * 100)).collect();

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
                for (scalar_gf, (vector_bit, vector_gf)) in scalar_online_key.zip(vector_online_key)
                {
                    black_box(scalar_gf);
                    black_box(vector_gf);
                    black_box(vector_bit);
                }
            }
            start.elapsed()
        })
    });
}
pub fn offline_pcg(c: &mut Criterion) {
    c.bench_function("offline_pcg", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for i in 0..iters as usize {
                const PRF_KEYS_NUM: usize = 128;
                const INPUT_BITLEN: usize = 13;
                const KEY_SIZE: usize = 16;
                let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
                let mut i = 0;
                let prf_keys = (0..PRF_KEYS_NUM)
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

                let puncturing_points = (0..PRF_KEYS_NUM).map(|i| usize_to_bits(i * 100)).collect();

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
                black_box(scalar_offline_key);
                black_box(vector_offline_key);
            }
            start.elapsed()
        })
    });
}

criterion_group!(benches, offline_pcg, full_pcg_bench);
criterion_main!(benches);
