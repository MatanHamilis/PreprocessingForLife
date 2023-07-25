use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand_core::OsRng;
use silent_party::fields::FieldElement;
use silent_party::fields::GF128;
use silent_party::fields::GF64;
use silent_party::zkfliop::PowersIterator;
use std::time::Instant;

pub fn mul_benchmark(c: &mut Criterion) {
    c.bench_function("mul_bench_custom", |b| {
        b.iter_custom(|iters| {
            let mut rng = &mut OsRng;
            let mut a: Vec<_> = (0..iters).map(|_| GF64::random(&mut rng)).collect();
            let b: Vec<_> = (0..iters).map(|_| GF64::random(&mut rng)).collect();
            let start = Instant::now();
            for i in 0..iters as usize {
                a[i] = a[i] * b[i];
            }
            let end = start.elapsed();
            black_box(a);
            black_box(b);
            end
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
                    vec![GF64::random(&mut rng); 1 << 25],
                    vec![GF64::random(&mut rng); 1 << 25],
                )
            },
            |(mut a, b)| {
                let time = Instant::now();
                black_box(a.iter_mut().zip(b.iter()).for_each(|(a, b)| {
                    (*a *= *b);
                }));
                black_box(a);
                println!("Time: {}", time.elapsed().as_millis());
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

const CHUNK_SIZE: usize = 1 << 4;
pub struct NaivePowersIterator<F: FieldElement> {
    alpha: F,
    cur: F,
}
impl<F: FieldElement> NaivePowersIterator<F> {
    pub fn new(alpha: F) -> Self {
        Self {
            alpha,
            cur: F::one(),
        }
    }
}
impl<F: FieldElement> Iterator for NaivePowersIterator<F> {
    type Item = F;
    fn next(&mut self) -> Option<Self::Item> {
        let output = Some(self.cur);
        self.cur *= self.alpha;
        output
    }
}
pub fn power_benchmark(c: &mut Criterion) {
    c.bench_function("powers naive", |b| {
        let rng = &mut OsRng;
        let a = GF128::random(rng);
        let mut powers = NaivePowersIterator::new(a);
        b.iter(|| {
            black_box((0..10_000_000).for_each(|_| {
                powers.next().unwrap();
            }))
        });
    });
    c.bench_function("powers optimized", |b| {
        let rng = &mut OsRng;
        let a = GF128::random(rng);
        let mut powers = PowersIterator::new(a);
        b.iter(|| {
            black_box((0..10_000_000).for_each(|_| {
                powers.next().unwrap();
            }))
        });
    });
}

criterion_group!(
    benches,
    mul_benchmark_with_mem,
    mul_benchmark_with_vec,
    mul_benchmark,
    inv_benchmark,
    power_benchmark
);
criterion_main!(benches);
