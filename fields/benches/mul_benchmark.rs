use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use fields::GF128;
use rand_core::OsRng;
use std::time::Instant;

pub fn mul_benchmark(c: &mut Criterion) {
    c.bench_function("mul_bench", |b| {
        b.iter_custom(|iters| {
            let rng = &mut OsRng;
            let a: Vec<_> = (0..iters).map(|_| GF128::random(rng)).collect();
            let b: Vec<_> = (0..iters).map(|_| GF128::random(rng)).collect();
            let start = Instant::now();
            for i in 0..iters as usize {
                black_box(a[i] * b[i]);
            }
            start.elapsed()
        })
    });
}
pub fn mul_benchmark_with_mem(c: &mut Criterion) {
    c.bench_function("mul_bench_with_mem", |bench| {
        let mut rng = &mut OsRng;
        bench.iter_batched(
            || (GF128::random(rng), GF128::random(rng)),
            |(a, b)| (a * b),
            BatchSize::SmallInput,
        );
    });
}

pub fn inv_benchmark(c: &mut Criterion) {
    c.bench_function("inv_bench", |b| {
        b.iter_custom(|iters| {
            let rng = &mut OsRng;
            let a = GF128::random(rng);

            let start = Instant::now();
            for _ in 0..iters {
                black_box(a.inv());
            }
            start.elapsed()
        })
    });
}

criterion_group!(
    benches,
    // mul_benchmark_with_mem,
    // mul_benchmark,
    inv_benchmark,
);
criterion_main!(benches);
