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
#[derive(Clone, Copy)]
struct UnsafePtr<T> {
    ptr: *mut T,
}
unsafe impl<T> Send for UnsafePtr<T> {}

pub fn bench_mem_strides(c: &mut Criterion) {
    const STRIDE: usize = 1024;
    const ITERS: usize = (1 << 30) / (STRIDE * 8 * 2);
    c.bench_function("mem_strides_64", |b| {
        const VEC_SIZE: usize = 1 << 19;
        let mut v = vec![[0u64; STRIDE]; VEC_SIZE];
        for (i, v_item) in v.iter_mut().enumerate() {
            for j in 0..v_item.len() {
                v_item[j] = j as u64;
            }
        }
        let v_ptr = UnsafePtr {
            ptr: unsafe { v.as_mut_ptr() },
        };
        let v_len = v.len();
        b.iter(|| {
            rayon::join(
                move || {
                    let mut buf = [0u64; STRIDE];
                    let c = 113usize;
                    let d = 291;
                    let mut idx = 1usize;
                    let ptr = v_ptr;
                    let v_slice = unsafe { std::slice::from_raw_parts_mut(ptr.ptr, v_len) };
                    for _ in 0..ITERS {
                        {
                            for i in 0..STRIDE {
                                let a = v_slice[idx & (VEC_SIZE - 1)][i];
                                black_box(a);
                                // buf[i] ^= a;
                            }
                            idx = idx * c + d;
                        }
                    }
                    black_box(buf);
                },
                move || {
                    let mut buf = [0u64; STRIDE];
                    let c = 118usize;
                    let d = 295;
                    let mut idx = 1usize;
                    let ptr = v_ptr;
                    let v_slice = unsafe { std::slice::from_raw_parts_mut(ptr.ptr, v_len) };
                    for _ in 0..ITERS {
                        {
                            for i in 0..STRIDE {
                                let a = v_slice[idx & (VEC_SIZE - 1)][i];
                                black_box(a);
                                // buf[i] ^= a;
                            }
                            idx = idx * c + d;
                        };
                    }
                    black_box(buf);
                },
            );
        });
    });
    c.bench_function("mem_strides_128", |b| {
        const VEC_SIZE: usize = 1 << 19;
        let mut v = vec![[0u64; STRIDE]; VEC_SIZE];
        for (i, v_item) in v.iter_mut().enumerate() {
            for j in 0..v_item.len() {
                v_item[j] = j as u64;
            }
        }
        let d = 5;
        let c = 312;
        let mut last = 1usize;
        b.iter(|| {
            for _ in 0..ITERS * 2 {
                last = d * last + c;
                for i in 0..STRIDE {
                    let a = v[last & (VEC_SIZE - 1)][i];
                    black_box(a);
                }
            }
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
fn bench_xor(c: &mut Criterion) {
    c.bench_function("xor_local", |bencher| {
        let a = 1234u64;
        let b = 5667u64;
        let iters = 1 << 30;
        bencher.iter(|| {
            for i in 0..iters / (8 * 16) {
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
                black_box(a ^ b);
            }
        })
    });
}
criterion_group!(benches, bench_mem_random, bench_mem_strides, bench_xor);
criterion_main!(benches);
