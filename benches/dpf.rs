#![feature(maybe_uninit_uninit_array)]
#![feature(portable_simd)]
use std::{
    mem::MaybeUninit,
    simd::{u8x32, u8x64},
};

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
    PlotConfiguration, Throughput,
};
use silent_party::dpf::{
    dpf_pir::{answer_query_batched, dpf_to_simd_vec, gen_query},
    DpfKey, DPF_KEY_SIZE,
};

fn dpf_gen<const DEPTH: usize>() -> (DpfKey<DEPTH>, DpfKey<DEPTH>) {
    let hiding_point = [false; DEPTH];
    let mut point_val = [0u8; DPF_KEY_SIZE];
    point_val[0] = 1;
    let dpf_root_0 = [1u8; DPF_KEY_SIZE];
    let dpf_root_1 = [2u8; DPF_KEY_SIZE];
    DpfKey::gen(&hiding_point, &point_val, dpf_root_0, dpf_root_1)
}

fn dpf_gen_bench<const DEPTH: usize>(c: &mut Criterion) {
    let i = DEPTH;
    c.bench_with_input(BenchmarkId::new("dpf_keygen", DEPTH), &i, |b, &s| {
        let hiding_point = [false; DEPTH];
        let mut point_val = [0u8; DPF_KEY_SIZE];
        point_val[0] = 1;
        let dpf_root_0 = [1u8; DPF_KEY_SIZE];
        let dpf_root_1 = [2u8; DPF_KEY_SIZE];
        b.iter(|| DpfKey::gen(&hiding_point, &point_val, dpf_root_0, dpf_root_1));
    });
}

fn dpf_evalall_bench<const DEPTH: usize>(c: &mut Criterion) {
    let i = DEPTH;
    c.bench_with_input(BenchmarkId::new("dpf_evalall", DEPTH), &i, |b, &s| {
        let (k_0, k_1) = dpf_gen::<DEPTH>();
        let mut output = vec![[0u8; DPF_KEY_SIZE]; 1 << DEPTH];
        let mut aux = vec![false; 1 << DEPTH];
        b.iter(|| k_0.eval_all_into(&mut output, &mut aux));
    });
}

pub fn bench_dpf_gen(g: &mut Criterion) {
    dpf_gen_bench::<3>(g);
    dpf_gen_bench::<4>(g);
    dpf_gen_bench::<5>(g);
    dpf_gen_bench::<6>(g);
    dpf_gen_bench::<7>(g);
    dpf_gen_bench::<8>(g);
    dpf_gen_bench::<9>(g);
    dpf_gen_bench::<10>(g);
    dpf_gen_bench::<11>(g);
    dpf_gen_bench::<12>(g);
    dpf_gen_bench::<13>(g);
    dpf_gen_bench::<14>(g);
    dpf_gen_bench::<15>(g);
    dpf_gen_bench::<16>(g);
    dpf_gen_bench::<17>(g);
    dpf_gen_bench::<18>(g);
    dpf_gen_bench::<19>(g);
    dpf_gen_bench::<20>(g);
}
pub fn bench_dpf_evalall(g: &mut Criterion) {
    dpf_evalall_bench::<18>(g);
    dpf_evalall_bench::<3>(g);
    dpf_evalall_bench::<4>(g);
    dpf_evalall_bench::<5>(g);
    dpf_evalall_bench::<6>(g);
    dpf_evalall_bench::<7>(g);
    dpf_evalall_bench::<8>(g);
    dpf_evalall_bench::<9>(g);
    dpf_evalall_bench::<10>(g);
    dpf_evalall_bench::<11>(g);
    dpf_evalall_bench::<12>(g);
    dpf_evalall_bench::<13>(g);
    dpf_evalall_bench::<14>(g);
    dpf_evalall_bench::<15>(g);
    dpf_evalall_bench::<16>(g);
    dpf_evalall_bench::<17>(g);
    dpf_evalall_bench::<18>(g);
    dpf_evalall_bench::<19>(g);
    dpf_evalall_bench::<20>(g);
}
pub fn bench_pir_single<const DPF_DEPTH: usize, const BATCH: usize>(
    c: &mut BenchmarkGroup<WallTime>,
    db: &[u8x64],
    query_index: usize,
) {
    let dpf_root_0 = [1u8; DPF_KEY_SIZE];
    let dpf_root_1 = [2u8; DPF_KEY_SIZE];
    let mut keys_0: [MaybeUninit<DpfKey<DPF_DEPTH>>; BATCH] =
        std::mem::MaybeUninit::<DpfKey<DPF_DEPTH>>::uninit_array();
    let mut keys_1: [MaybeUninit<DpfKey<DPF_DEPTH>>; BATCH] =
        std::mem::MaybeUninit::<DpfKey<DPF_DEPTH>>::uninit_array();
    for i in 0..BATCH {
        let (k_0, k_1) = gen_query::<DPF_DEPTH>(query_index, dpf_root_0, dpf_root_1);
        keys_0[i].write(k_0);
        keys_1[i].write(k_1);
    }
    let keys_0 = unsafe { keys_0.as_ptr().cast::<[DpfKey<DPF_DEPTH>; BATCH]>().read() };
    let keys_1 = unsafe { keys_1.as_ptr().cast::<[DpfKey<DPF_DEPTH>; BATCH]>().read() };

    let mut output_0 = vec![
        [u8x64::default(); BATCH];
        (db.len() >> DPF_DEPTH) * std::mem::size_of::<u8x64>() / DPF_KEY_SIZE
    ];
    let mut output_1 = vec![
        [u8x64::default(); BATCH];
        (db.len() >> DPF_DEPTH) * std::mem::size_of::<u8x64>() / DPF_KEY_SIZE
    ];
    let dpf_eval_0 = dpf_to_simd_vec(&keys_0);
    let dpf_eval_1 = dpf_to_simd_vec(&keys_1);
    let batch = BATCH;
    c.throughput(Throughput::Bytes(
        u64::try_from(db.len() * std::mem::size_of::<u8x64>() * BATCH).unwrap(),
    ));
    c.bench_with_input(BenchmarkId::new("pir_batch", BATCH), &batch, |b, param| {
        b.iter(|| {
            answer_query_batched(&dpf_eval_0, &db[..], &mut output_0[..]);
            answer_query_batched(&dpf_eval_1, &db[..], &mut output_1[..]);
        });
    });
}
pub fn bench_pir(c: &mut Criterion) {
    const LOG_DB_SZ: usize = 33;
    const DB_SZ: usize = 1 << LOG_DB_SZ;
    const DPF_DEPTH: usize = 12;
    const QUERY_INDEX: usize = 257;
    let mut g = c.benchmark_group("pir_batch");
    let db: Vec<_> = (0..(DB_SZ / (std::mem::size_of::<u8x64>() * 8)))
        .map(|i| u8x64::from_array(unsafe { std::mem::transmute([u64::try_from(i).unwrap(); 8]) }))
        .collect();
    bench_pir_single::<DPF_DEPTH, 1>(&mut g, &db, QUERY_INDEX);
    bench_pir_single::<DPF_DEPTH, 2>(&mut g, &db, QUERY_INDEX);
    // bench_pir_single::<DPF_DEPTH, 3>(&mut g, &db, QUERY_INDEX);
    bench_pir_single::<DPF_DEPTH, 4>(&mut g, &db, QUERY_INDEX);
    // bench_pir_single::<DPF_DEPTH, 5>(&mut g, &db, QUERY_INDEX);
    // bench_pir_single::<DPF_DEPTH, 6>(&mut g, &db, QUERY_INDEX);
    // bench_pir_single::<DPF_DEPTH, 7>(&mut g, &db, QUERY_INDEX);
    bench_pir_single::<DPF_DEPTH, 8>(&mut g, &db, QUERY_INDEX);
    // bench_pir_single::<DPF_DEPTH, 9>(&mut g, &db, QUERY_INDEX);
    // bench_pir_single::<DPF_DEPTH, 10>(&mut g, &db, QUERY_INDEX);
    bench_pir_single::<DPF_DEPTH, 16>(&mut g, &db, QUERY_INDEX);
    bench_pir_single::<DPF_DEPTH, 32>(&mut g, &db, QUERY_INDEX);
    // bench_pir_single::<DPF_DEPTH, 64>(&mut g, &db, QUERY_INDEX);
    g.finish();
}

pub fn bench_mem_xor(c: &mut Criterion) {
    let mut g = c.benchmark_group("mem_xor");
    const LOG_DB_SZ: usize = 30;
    const DB_SZ: usize = 1 << LOG_DB_SZ;
    let db = vec![u8x64::default(); DB_SZ / std::mem::size_of::<u8x64>()];
    g.throughput(Throughput::Bytes(u64::try_from(DB_SZ).unwrap()));
    g.bench_function("mem_xor", |b| {
        b.iter(|| {
            let mut sum = u8x64::default();
            for i in 0..db.len() / 8 {
                let a = db[8 * i] ^ db[8 * i + 1];
                let b = db[8 * i + 2] ^ db[8 * i + 3];
                let c = db[8 * i + 4] ^ db[8 * i + 5];
                let d = db[8 * i + 6] ^ db[8 * i + 7];
                sum ^= a ^ b ^ c ^ d;
            }
        })
    });
}
criterion_group!(
    benches,
    bench_dpf_gen,
    bench_dpf_evalall,
    bench_pir,
    bench_mem_xor
);
criterion_main!(benches);
