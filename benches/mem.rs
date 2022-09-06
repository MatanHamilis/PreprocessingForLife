use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{random, thread_rng, RngCore};

pub fn bench_mem_random(c: &mut Criterion) {
    c.bench_function("mem_random", |b| {
        const VEC_SIZE: usize = 1 << 26;
        let mut v = vec![0u128; VEC_SIZE];
        for i in 0..v.len() {
            v[i] = u128::from(i as u64);
        }
        let mut i = 1usize;
        let mut rng = thread_rng();
        b.iter(|| {
            let indices: [u32; 8] = random();
            black_box(
                v[indices[0] as usize & (VEC_SIZE - 1)]
                    + v[indices[1] as usize & (VEC_SIZE - 1)]
                    + v[indices[2] as usize & (VEC_SIZE - 1)]
                    + v[indices[3] as usize & (VEC_SIZE - 1)]
                    + v[indices[4] as usize & (VEC_SIZE - 1)]
                    + v[indices[5] as usize & (VEC_SIZE - 1)]
                    + v[indices[6] as usize & (VEC_SIZE - 1)]
                    + v[indices[7] as usize & (VEC_SIZE - 1)],
            )
        });
    });

    c.bench_function("bench_rng", |b| {
        const VEC_SIZE: usize = 1 << 26;
        let mut v = vec![0u128; VEC_SIZE];
        for i in 0..v.len() {
            v[i] = u128::from(i as u64);
        }
        b.iter(|| black_box((thread_rng().next_u32() as usize) & (VEC_SIZE - 1)));
    });
}
criterion_group!(benches, bench_mem_random);
criterion_main!(benches);
