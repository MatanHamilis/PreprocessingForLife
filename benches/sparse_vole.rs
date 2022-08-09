use criterion::{black_box, criterion_group, criterion_main, Criterion};
use silent_party::fields::GF128;
use silent_party::pcg::codes::EACode;
use silent_party::pcg::pprf_aggregator::RegularErrorPprfAggregator;
use silent_party::pcg::preprocessor::Preprocessor;
use silent_party::pcg::sparse_vole::scalar_party::OfflineSparseVoleKey as ScalarOfflineSparseVoleKey;
use silent_party::pcg::sparse_vole::scalar_party::SparseVolePcgScalarKeyGenState;
use silent_party::pcg::sparse_vole::vector_party::OfflineSparseVoleKey as VectorOfflineSparseVoleKey;
use silent_party::pcg::sparse_vole::vector_party::SparseVolePcgVectorKeyGenStateInitial;
use silent_party::pprf::usize_to_bits;

pub fn get_offline_keys() -> (ScalarOfflineSparseVoleKey, VectorOfflineSparseVoleKey) {
    const PRF_KEYS_NUM: usize = 128;
    const INPUT_BITLEN: usize = 19;
    const KEY_SIZE: usize = 16;
    let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
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
    let vector_msg = vector_keygen_state_init.create_first_message(&scalar_first_message);
    let scalar_second_message = scalar_keygen_state.create_second_message(&vector_msg);
    let vector_keygen_state_final =
        vector_keygen_state_init.handle_second_message(scalar_second_message);

    // Create Offline Keys
    let scalar_offline_key = scalar_keygen_state.keygen_offline::<RegularErrorPprfAggregator>();
    let vector_offline_key =
        vector_keygen_state_final.keygen_offline::<RegularErrorPprfAggregator>();
    (scalar_offline_key, vector_offline_key)
}
pub fn online_pcg(c: &mut Criterion) {
    const CODE_WEIGHT: usize = 8;
    // Create Offline Keys
    let (scalar_offline_key, vector_offline_key) = get_offline_keys();

    // Create code
    let code_seed = [0; 32];
    let scalar_code = EACode::<CODE_WEIGHT>::new(scalar_offline_key.vector_length(), code_seed);
    let vector_code = EACode::<CODE_WEIGHT>::new(vector_offline_key.vector_length(), code_seed);
    let scalar_code = Preprocessor::new(10_000_000usize, scalar_code);
    let vector_code = Preprocessor::new(10_000_000usize, vector_code);

    // Create online keys
    let mut scalar_online_key = scalar_offline_key.provide_online_key(scalar_code);
    let mut vector_online_key = vector_offline_key.provide_online_key(vector_code);
    c.bench_function("online_pcg_scalar_with_preprocessing", |b| {
        b.iter(|| scalar_online_key.next())
    });
    c.bench_function("online_pcg_vector_with_preprocessing", |b| {
        b.iter(|| vector_online_key.next())
    });

    let (scalar_offline_key, vector_offline_key) = get_offline_keys();
    let code_seed = [0; 32];
    let scalar_code = EACode::<CODE_WEIGHT>::new(scalar_offline_key.vector_length(), code_seed);
    let vector_code = EACode::<CODE_WEIGHT>::new(vector_offline_key.vector_length(), code_seed);
    let mut scalar_online_key = scalar_offline_key.provide_online_key(scalar_code);
    let mut vector_online_key = vector_offline_key.provide_online_key(vector_code);
    c.bench_function("online_pcg_scalar", |b| {
        b.iter(|| black_box(scalar_online_key.next().unwrap()))
    });
    c.bench_function("online_pcg_vector", |b| {
        b.iter(|| vector_online_key.next().unwrap())
    });
}
pub fn offline_pcg(c: &mut Criterion) {
    const PRF_KEYS_NUM: usize = 50;
    const INPUT_BITLEN: usize = 20;
    const KEY_SIZE: usize = 16;
    let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
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
    let vector_msg = vector_keygen_state_init.create_first_message(&scalar_first_message);
    let scalar_second_message = scalar_keygen_state.create_second_message(&vector_msg);
    let vector_keygen_state_final =
        vector_keygen_state_init.handle_second_message(scalar_second_message);

    // Create Offline Keys
    c.bench_function("offline_pcg_scalar", |b| {
        b.iter_with_large_drop(|| {
            scalar_keygen_state.keygen_offline::<RegularErrorPprfAggregator>();
        });
    });
    c.bench_function("offline_pcg_vector", |b| {
        b.iter_with_large_drop(|| {
            vector_keygen_state_final.keygen_offline::<RegularErrorPprfAggregator>();
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = offline_pcg, online_pcg
}
criterion_main!(benches);
