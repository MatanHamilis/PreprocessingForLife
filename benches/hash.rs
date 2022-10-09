use aes::{cipher::BlockEncrypt, cipher::KeyInit, Aes128Enc, Block};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn bench_hash(c: &mut Criterion) {
    let key = [0u8; 16];
    let mut blocks = [Block::default(); 8];
    let aes = Aes128Enc::new_from_slice(&key[..]).unwrap();
    c.bench_function("hash", |b| {
        b.iter(|| aes.encrypt_blocks(&mut blocks));
    });
}
criterion_group!(benches, bench_hash);
criterion_main!(benches);
