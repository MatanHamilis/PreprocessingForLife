use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use silent_party::fields::{FieldElement, GF128, GF64};
fn bench_parallel(c: &mut Criterion) {
    let mut g = c.benchmark_group("parallel");

    for threads in [1, 2, 4, 8] {
        g.bench_with_input(
            format!("vec_mul/{}", threads),
            &threads,
            |bencher, threads| {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(*threads)
                    .build()
                    .unwrap();
                let a = vec![GF64::one(); 1 << 23];
                let b = vec![GF64::one(); 1 << 23];
                pool.install(|| {
                    bencher.iter(|| {
                        a.par_iter()
                            .zip(b.par_iter())
                            .map(|(&ai, &bi)| ai * bi)
                            .sum::<GF64>();
                    })
                })
            },
        );
    }
}
fn bench_std_thread(c: &mut Criterion) {
    let mut g = c.benchmark_group("std_thread");

    println!(
        "available: {}",
        std::thread::available_parallelism().unwrap()
    );
    for threads in [1, 2, 4, 8] {
        g.bench_with_input(
            format!("vec_mul/{}", threads),
            &threads,
            |bencher, &threads| {
                let a = vec![GF64::one(); 1 << 23];
                let b = vec![GF64::one(); 1 << 23];
                bencher.iter(|| {
                    let mut handles = Vec::with_capacity(threads);
                    for i in 0..threads {
                        let start = a.len() * i / threads;
                        let end = a.len() * (i + 1) / threads;
                        let a = unsafe {
                            std::slice::from_raw_parts(a[start..end].as_ptr(), end - start)
                        };
                        let b = unsafe {
                            std::slice::from_raw_parts(b[start..end].as_ptr(), end - start)
                        };
                        handles.push(std::thread::spawn(|| {
                            a.iter()
                                .zip(b.iter())
                                .map(|(&ai, &bi)| ai * bi)
                                .sum::<GF64>()
                        }));
                    }
                    let sum: GF64 = handles.into_iter().map(|i| i.join().unwrap()).sum();
                })
            },
        );
    }
}
criterion_group!(benches, bench_parallel, bench_std_thread);
criterion_main!(benches);
