use aes::{cipher::BlockEncrypt, cipher::KeyInit, Aes128, Aes128Enc, Block};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_party::pseudorandom::hash;

pub fn bench_hash(c: &mut Criterion) {
    let key = [0u8; 16];
    let mut blocks = [Block::default(); 8];
    let mut aes = Aes128Enc::new_from_slice(&key[..]).unwrap();
    c.bench_function("hash", |b| {
        b.iter(|| aes.encrypt_blocks(&mut blocks));
    });
}
criterion_group!(benches, bench_hash);
criterion_main!(benches);
