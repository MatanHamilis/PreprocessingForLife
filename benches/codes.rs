use criterion::{black_box, criterion_group, criterion_main, Criterion};
use silent_party::pcg::codes::EACode;
pub fn bench_codes(c: &mut Criterion) {
    let mut code = EACode::<8>::new(1 << 17, [0u8; 16]);
    c.bench_function("bench_codes", |b| {
        b.iter(|| black_box(code.next().unwrap()))
    });
}

criterion_group!(benches, bench_codes);
criterion_main!(benches);
