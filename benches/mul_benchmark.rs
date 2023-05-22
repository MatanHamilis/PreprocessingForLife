use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand_core::OsRng;
use silent_party::fields::FieldElement;
use silent_party::fields::GF128;
use silent_party::fields::GF64;
use std::time::Instant;

pub fn mul_benchmark(c: &mut Criterion) {
    c.bench_function("mul_bench", |b| {
        b.iter_custom(|iters| {
            let mut rng = &mut OsRng;
            let a: Vec<_> = (0..iters).map(|_| GF128::random(&mut rng)).collect();
            let b: Vec<_> = (0..iters).map(|_| GF128::random(&mut rng)).collect();
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
            || (GF128::random(&mut rng), GF128::random(&mut rng)),
            |(a, b)| (a * b),
            BatchSize::SmallInput,
        );
    });
    c.bench_function("mul_bench_with_mem_gf64", |bench| {
        let mut rng = &mut OsRng;
        let a = GF64::random(&mut rng);
        let b = GF64::random(&mut rng);
        bench.iter(|| black_box(a * b));
    });
}
pub fn mul_benchmark_with_vec(c: &mut Criterion) {
    c.bench_function("mul_bench_with_vec", |bench| {
        let mut rng = &mut OsRng;
        bench.iter_batched(
            || {
                (
                    vec![GF128::random(&mut rng); 1 << 20],
                    vec![GF128::random(&mut rng); 1 << 20],
                )
            },
            |(mut a, b)| {
                black_box(a.iter_mut().zip(b.iter()).for_each(|(a, b)| {
                    (*a *= *b);
                }));
                black_box(a);
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("mul_bench_with_vec_gf64", |bench| {
        let mut rng = &mut OsRng;
        bench.iter_batched(
            || {
                (
                    vec![GF64::random(&mut rng); 1 << 20],
                    vec![GF64::random(&mut rng); 1 << 20],
                )
            },
            |(mut a, b)| {
                black_box(a.iter_mut().zip(b.iter()).for_each(|(a, b)| {
                    (*a *= *b);
                }));
                black_box(a);
            },
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
    mul_benchmark_with_mem,
    mul_benchmark_with_vec,
    mul_benchmark,
    inv_benchmark,
);
criterion_main!(benches);
