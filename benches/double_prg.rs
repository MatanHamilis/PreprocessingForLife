use aes::Block;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_party::pseudorandom::double_prg_many;
pub fn double_prg_many_bench(c: &mut Criterion) {
    const MAX_DEPTH: usize = 26;
    let mut blocks_a = vec![Block::default(); 1 << MAX_DEPTH];
    let mut blocks_b = vec![Block::default(); 1 << MAX_DEPTH];
    for i in 20..MAX_DEPTH {
        if i & 1 == 0 {
            c.bench_with_input(BenchmarkId::new("double_prg_many", i), &i, |b, &s| {
                b.iter(|| double_prg_many(&blocks_a[0..(1 << s)], &mut blocks_b[0..(1 << (s + 1))]))
            });
        } else {
            c.bench_with_input(BenchmarkId::new("double_prg_many", i), &i, |b, &s| {
                b.iter(|| double_prg_many(&blocks_b[0..(1 << s)], &mut blocks_a[0..(1 << (s + 1))]))
            });
        }
    }

    c.bench_function("double_prg_small_array", |b| {
        b.iter(|| double_prg_many(&blocks_a[0..8], &mut blocks_b[0..16]))
    });
}

criterion_group!(benches, double_prg_many_bench);
criterion_main!(benches);
