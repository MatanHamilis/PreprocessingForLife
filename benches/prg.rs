use std::alloc::Layout;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{thread_rng, Rng};
use silent_party::{
    fields::{FieldElement, GF128},
    pseudorandom::prg::{fill_prg, fill_prg_cache_friendly, ALIGN},
};

pub fn bench(c: &mut Criterion) {
    let v = GF128::random(thread_rng());
    const LEN: usize = 1 << 23;
    let layout = Layout::array::<GF128>(LEN)
        .unwrap()
        .align_to(ALIGN)
        .unwrap();
    let buf1 = unsafe { std::alloc::alloc(layout) as *mut GF128 };
    let buf2 = unsafe { std::alloc::alloc(layout) as *mut GF128 };
    let buf3 = unsafe { std::alloc::alloc(layout) as *mut GF128 };
    let mut v1 = unsafe { Vec::from_raw_parts(buf1, LEN, LEN) };
    let mut v2 = unsafe { Vec::from_raw_parts(buf2, LEN, LEN) };
    let mut v3 = unsafe { Vec::from_raw_parts(buf3, LEN, LEN) };
    c.bench_function("fill_prg", |b| {
        b.iter(|| {
            fill_prg(&v, &mut v1);
        })
    });
    let mut g = c.benchmark_group("prg_cache_friendly");
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &1),
        &1,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<1>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &2),
        &2,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<2>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &3),
        &3,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<3>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &4),
        &4,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<4>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &5),
        &5,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<5>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &6),
        &6,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<6>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &7),
        &7,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<7>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &8),
        &8,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<8>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &9),
        &9,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<9>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &10),
        &10,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<10>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &11),
        &11,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<11>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &12),
        &12,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<12>(&v, &mut v2, &mut v3);
            })
        },
    );
    g.bench_with_input(
        BenchmarkId::new("fill_prg_cache_friendly", &16),
        &16,
        |b, i| {
            b.iter(|| {
                fill_prg_cache_friendly::<16>(&v, &mut v2, &mut v3);
            })
        },
    );
}
criterion_group!(benches, bench);
criterion_main!(benches);
