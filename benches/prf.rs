use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_party::pseudorandom::prf;
use silent_party::pseudorandom::prg::PrgValue;

pub fn bench_prf(c: &mut Criterion) {
    let prf_key = PrgValue::default();

    const MAX_RANGE: usize = 20;
    const MIN_RANGE: usize = 19;
    let mut output = vec![PrgValue::default(); 1 << MAX_RANGE];
    for i in MIN_RANGE..=MAX_RANGE {
        c.bench_with_input(BenchmarkId::new("prf_eval", i), &i, |b, &_| {
            b.iter(|| prf::prf_eval_all_into_slice(&prf_key, i, &mut output[..1 << i]))
        });
    }
}
criterion_group!(benches, bench_prf);
criterion_main!(benches);
