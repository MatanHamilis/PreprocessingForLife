use aes::Block;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_party::pseudorandom::hash;

pub fn bench_hash(c: &mut Criterion) {
    let mut block = Block::default();
    c.bench_function("hash", |b| {
        b.iter(|| hash::correlation_robust_hash_block(&mut block));
    });
}
criterion_group!(benches, bench_hash);
criterion_main!(benches);
