use criterion::measurement::WallTime;
use criterion::{
    black_box, criterion_group, criterion_main, AxisScale, Criterion, PlotConfiguration,
};
use criterion::{BenchmarkGroup, BenchmarkId};
use silent_party::fields::GF128;
use silent_party::pcg::codes::EACode;
use silent_party::pcg::pprf_aggregator::RegularErrorPprfAggregator;
use silent_party::pcg::preprocessor::Preprocessor;
use silent_party::pcg::sparse_vole::packed::SparseVoleScalarPartyPackedOfflineKey;
use silent_party::pcg::sparse_vole::packed::SparseVoleScalarPartyPackedOnlineKey;
use silent_party::pcg::sparse_vole::packed::SparseVoleVectorPartyPackedOfflineKey;
use silent_party::pcg::sparse_vole::packed::SparseVoleVectorPartyPackedOnlineKey;
use silent_party::pcg::sparse_vole::scalar_party::OfflineSparseVoleKey as ScalarOfflineSparseVoleKey;
use silent_party::pcg::sparse_vole::scalar_party::SparseVolePcgScalarKeyGenState;
use silent_party::pcg::sparse_vole::trusted_deal_packed_offline_keys;
use silent_party::pcg::sparse_vole::vector_party::SparseVolePcgVectorKeyGenStateInitial;
use silent_party::pcg::sparse_vole::vector_party::{
    OfflineSparseVoleKey as VectorOfflineSparseVoleKey, SparseVolePcgVectorKeyGenStateFinal,
};
use silent_party::pprf::usize_to_bits;
use silent_party::pseudorandom::prf::PrfInput;
use silent_party::pseudorandom::{prf, KEY_SIZE};

macro_rules! pack_test {
    ($group:ident,$pack:literal,$codeseed:ident) => {
        let p = $pack;
        $group.bench_with_input(BenchmarkId::from_parameter($pack), &p, |b, p| {
            let (scalar_offline_key, vector_offline_key) =
                get_packed_offline_keys::<$pack, 128, 14>();
            let code_scalar = EACode::<CODE_WEIGHT>::new(scalar_offline_key.len(), $codeseed);
            let code_vector = EACode::<CODE_WEIGHT>::new(scalar_offline_key.len(), $codeseed);
            let mut scalar_online_key =
                SparseVoleScalarPartyPackedOnlineKey::new(code_scalar, scalar_offline_key);
            b.iter(|| scalar_online_key.next().unwrap());
            // let mut vector_online_key =
            //     SparseVoleVectorPartyPackedOnlineKey::new(code_vector, vector_offline_key);
            // b.iter(|| vector_online_key.next().unwrap());
        });
    };
}
pub fn get_packed_offline_keys<
    const PACK: usize,
    const PRF_KEYS_NUM: usize,
    const INPUT_BITLEN: usize,
>() -> (
    SparseVoleScalarPartyPackedOfflineKey<PACK>,
    SparseVoleVectorPartyPackedOfflineKey<PACK>,
) {
    let scalars = core::array::from_fn(|i| {
        GF128::from([
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            u8::try_from(i).unwrap(),
        ])
    });
    let puncturing_points: [Vec<PrfInput<INPUT_BITLEN>>; PACK] = core::array::from_fn(|idx| {
        (0..PRF_KEYS_NUM)
            .map(|i| usize_to_bits((i + idx) * (100 + idx)).into())
            .collect()
    });
    let prf_keys = core::array::from_fn(|idx| {
        (0..PRF_KEYS_NUM)
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
            .collect()
    });
    trusted_deal_packed_offline_keys(&scalars, puncturing_points, prf_keys)
}

pub fn gen_material_for_offline_keys<const INPUT_BITLEN: usize>(
    prf_keys_num: usize,
) -> (
    SparseVolePcgScalarKeyGenState<INPUT_BITLEN>,
    SparseVolePcgVectorKeyGenStateFinal<INPUT_BITLEN>,
) {
    let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    let prf_keys = (0..prf_keys_num)
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

    let puncturing_points = (0..prf_keys_num).map(|i| PrfInput::from(i * 100)).collect();

    let mut vector_keygen_state_init =
        SparseVolePcgVectorKeyGenStateInitial::new(puncturing_points);

    // Run Gen Algorithm
    let scalar_first_message = scalar_keygen_state.create_first_message();
    let vector_msg = vector_keygen_state_init.create_first_message(scalar_first_message);
    let scalar_second_message = scalar_keygen_state.create_second_message(vector_msg);
    let vector_keygen_state_final =
        vector_keygen_state_init.handle_second_message(scalar_second_message);
    (scalar_keygen_state, vector_keygen_state_final)
}

pub fn bench_offline_key_single_scalar<const DEPTH: usize>(group: &mut BenchmarkGroup<WallTime>) {
    let (scalar_state, _) = gen_material_for_offline_keys::<DEPTH>(128);
    let depth = DEPTH;
    group.bench_with_input(
        BenchmarkId::new("offline_depth_scalar", 1 << DEPTH),
        &depth,
        |b, _| b.iter(|| scalar_state.keygen_offline::<RegularErrorPprfAggregator>()),
    );
}
pub fn bench_offline_key_single_vector<const DEPTH: usize>(group: &mut BenchmarkGroup<WallTime>) {
    let (_, vector_state) = gen_material_for_offline_keys::<DEPTH>(128);
    let depth = DEPTH;
    group.bench_with_input(
        BenchmarkId::new("offline_depth_scalar", 1 << DEPTH),
        &depth,
        |b, _| b.iter(|| vector_state.keygen_offline::<RegularErrorPprfAggregator>()),
    );
}
pub fn bench_offline_keys(c: &mut Criterion) {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut g = c.benchmark_group("offline_phase_as_function_of_ggm_depth_sender");
    g.plot_config(plot_config.clone());
    bench_offline_key_single_scalar::<4>(&mut g);
    bench_offline_key_single_scalar::<6>(&mut g);
    bench_offline_key_single_scalar::<8>(&mut g);
    bench_offline_key_single_scalar::<10>(&mut g);
    bench_offline_key_single_scalar::<12>(&mut g);
    bench_offline_key_single_scalar::<14>(&mut g);
    bench_offline_key_single_scalar::<16>(&mut g);
    bench_offline_key_single_scalar::<18>(&mut g);
    g.finish();
    let mut g = c.benchmark_group("offline_phase_as_function_of_ggm_depth_receiver");
    g.plot_config(plot_config);
    bench_offline_key_single_vector::<4>(&mut g);
    bench_offline_key_single_vector::<6>(&mut g);
    bench_offline_key_single_vector::<8>(&mut g);
    bench_offline_key_single_vector::<10>(&mut g);
    bench_offline_key_single_vector::<12>(&mut g);
    bench_offline_key_single_vector::<14>(&mut g);
    bench_offline_key_single_vector::<16>(&mut g);
    bench_offline_key_single_vector::<18>(&mut g);
    g.finish();
}
pub fn get_offline_keys<const INPUT_BITLEN: usize>(
    prf_keys_num: usize,
) -> (ScalarOfflineSparseVoleKey, VectorOfflineSparseVoleKey) {
    let (scalar_keygen_state, vector_keygen_state) =
        gen_material_for_offline_keys::<INPUT_BITLEN>(prf_keys_num);
    // Create Offline Keys
    let scalar_offline_key = scalar_keygen_state.keygen_offline::<RegularErrorPprfAggregator>();
    let vector_offline_key = vector_keygen_state.keygen_offline::<RegularErrorPprfAggregator>();
    (scalar_offline_key, vector_offline_key)
}
pub fn packing_pcg(c: &mut Criterion) {
    let CODE_SEED: [u8; 16] = [0u8; 16];
    const CODE_WEIGHT: usize = 8;
    let mut group = c.benchmark_group("packing_pcg");
    pack_test!(group, 1, CODE_SEED);
    pack_test!(group, 2, CODE_SEED);
    pack_test!(group, 4, CODE_SEED);
    pack_test!(group, 8, CODE_SEED);
    pack_test!(group, 12, CODE_SEED);
    pack_test!(group, 16, CODE_SEED);
    pack_test!(group, 20, CODE_SEED);
    pack_test!(group, 24, CODE_SEED);
    pack_test!(group, 28, CODE_SEED);
    pack_test!(group, 32, CODE_SEED);
}

pub fn online_pcg(c: &mut Criterion) {
    const CODE_WEIGHT: usize = 8;
    // Create Offline Keys
    let (scalar_offline_key, vector_offline_key) = get_offline_keys::<19>(128);

    // Create code
    let code_seed = [0; 16];
    let scalar_code = EACode::<CODE_WEIGHT>::new(scalar_offline_key.vector_length(), code_seed);
    let vector_code = EACode::<CODE_WEIGHT>::new(vector_offline_key.vector_length(), code_seed);
    let scalar_code: Vec<[u32; CODE_WEIGHT]> =
        Preprocessor::new(10_000_000usize, scalar_code).collect();
    let vector_code: Vec<[u32; CODE_WEIGHT]> =
        Preprocessor::new(10_000_000usize, vector_code).collect();

    // Create online keys
    let mut scalar_online_key =
        scalar_offline_key.provide_online_key(scalar_code.into_iter().cycle());
    let mut vector_online_key =
        vector_offline_key.provide_online_key(vector_code.into_iter().cycle());
    c.bench_function("scalar_online_preprocessing", |b| {
        b.iter(|| black_box(scalar_online_key.next().unwrap()))
    });
    c.bench_function("vector_online_preprocessing", |b| {
        b.iter(|| black_box(vector_online_key.next().unwrap()))
    });

    let (scalar_offline_key, vector_offline_key) = get_offline_keys::<19>(128);
    let code_seed = [0; 16];
    let scalar_code = EACode::<CODE_WEIGHT>::new(scalar_offline_key.vector_length(), code_seed);
    let vector_code = EACode::<CODE_WEIGHT>::new(vector_offline_key.vector_length(), code_seed);
    let mut scalar_online_key = scalar_offline_key.provide_online_key(scalar_code);
    let mut vector_online_key = vector_offline_key.provide_online_key(vector_code);
    c.bench_function("scalar_online_no_preprocessing", |b| {
        b.iter(|| black_box(scalar_online_key.next().unwrap()))
    });
    c.bench_function("vector_online_no_preprocessing", |b| {
        b.iter(|| black_box(vector_online_key.next().unwrap()))
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

    let puncturing_points = (0..PRF_KEYS_NUM).map(|i| PrfInput::from(i * 100)).collect();

    let mut vector_keygen_state_init =
        SparseVolePcgVectorKeyGenStateInitial::new(puncturing_points);

    // Run Gen Algorithm
    let scalar_first_message = scalar_keygen_state.create_first_message();
    let vector_msg = vector_keygen_state_init.create_first_message(scalar_first_message);
    let scalar_second_message = scalar_keygen_state.create_second_message(vector_msg);
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
    targets = offline_pcg, online_pcg, packing_pcg, bench_offline_keys
}
criterion_main!(benches);
