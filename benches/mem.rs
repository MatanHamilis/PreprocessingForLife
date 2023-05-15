use std::{mem::size_of, println};

use aes_prng::AesRng;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{random, thread_rng, RngCore};
use silent_party::fields::GF128;

pub fn bench_mem_random(c: &mut Criterion) {
    c.bench_function("mem_random", |b| {
        const VEC_SIZE: usize = 1 << 26;
        let mut v = vec![0u128; VEC_SIZE];
        for (i, v_item) in v.iter_mut().enumerate() {
            *v_item = u128::from(i as u64);
        }
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
        for (i, v_item) in v.iter_mut().enumerate() {
            *v_item = u128::from(i as u64);
        }
        b.iter(|| black_box((thread_rng().next_u32() as usize) & (VEC_SIZE - 1)));
    });
}
pub fn bench_mem_strides(c: &mut Criterion) {
    c.bench_function("mem_strides_64", |b| {
        const VEC_SIZE: usize = 1 << 22;
        let mut v = vec![[0u64; 8]; VEC_SIZE];
        for (i, v_item) in v.iter_mut().enumerate() {
            for j in 0..v_item.len() {
                v_item[j] = j as u64;
            }
        }
        let mut rng = AesRng::from_random_seed();
        b.iter(|| {
            let a = v[rng.next_u32() as usize & (VEC_SIZE - 1)];
            let b = v[rng.next_u32() as usize & (VEC_SIZE - 1)];
            black_box(a);
            black_box(b);
        });
    });
    c.bench_function("mem_strides_128", |b| {
        const VEC_SIZE: usize = 1 << 21;
        let mut v = vec![[0u64; 16]; VEC_SIZE];
        for (i, v_item) in v.iter_mut().enumerate() {
            for j in 0..v_item.len() {
                v_item[j] = j as u64;
            }
        }
        let mut rng = AesRng::from_random_seed();
        b.iter(|| {
            let a = v[rng.next_u32() as usize & (VEC_SIZE - 1)];
            black_box(a);
        });
    });

    c.bench_function("bench_rng", |b| {
        const VEC_SIZE: usize = 1 << 26;
        let mut v = vec![0u128; VEC_SIZE];
        for (i, v_item) in v.iter_mut().enumerate() {
            *v_item = u128::from(i as u64);
        }
        b.iter(|| black_box((thread_rng().next_u64() as usize) & (VEC_SIZE - 1)));
    });
}
criterion_group!(benches, bench_mem_random, bench_mem_strides);
criterion_main!(benches);
