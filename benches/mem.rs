use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{thread_rng, RngCore};

pub fn bench_mem_random(c: &mut Criterion) {
    c.bench_function("mem_random", |b| {
        const VEC_SIZE: usize = 1 << 18;
        let mut v = vec![0u128; VEC_SIZE];
        for i in 0..v.len() {
            v[i] = u128::from(i as u64);
        }
        b.iter(|| black_box(v[(thread_rng().next_u32() as usize) & (VEC_SIZE - 1)]));
    });
}
criterion_group!(benches, bench_mem_random);
criterion_main!(benches);
