use aes_prng::AesRng;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use silent_party::fields::{FieldElement, GFMersenne, GF64};

pub fn do_bench<F: FieldElement>(c: &mut Criterion, name: &str) {
    const WINDOW: usize = 16;
    let mut aes_rng = AesRng::from_random_seed();
    let mut nums: Vec<_> = (0..WINDOW).map(|_| F::random(&mut aes_rng)).collect();
    let num = F::random(&mut aes_rng);
    c.bench_function(format!("{} / {}", name, WINDOW).as_str(), |b| {
        b.iter(|| {
            nums[0] *= num;
            nums[1] *= num;
            nums[2] *= num;
            nums[3] *= num;
            nums[4] *= num;
            nums[5] *= num;
            nums[6] *= num;
            nums[7] *= num;
            nums[8] *= num;
            nums[9] *= num;
            nums[10] *= num;
            nums[11] *= num;
            nums[12] *= num;
            nums[13] *= num;
            nums[14] *= num;
            nums[15] *= num;
        })
    });
}
pub fn bench(c: &mut Criterion) {
    do_bench::<GF64>(c, "gf64");
    do_bench::<GFMersenne>(c, "mersenne");
}
criterion_group!(benches, bench);
criterion_main!(benches);
