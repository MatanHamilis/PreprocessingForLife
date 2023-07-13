use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;
use silent_party::fields::{FieldElement, GF64};
use silent_party::zkfliop::dealer;
use silent_party::zkfliop::ni::prove;

fn do_zkfliop_bench<F: FieldElement>(c: &mut Criterion, statement_len: usize) {
    let statement = get_statement(statement_len);
    let mut last_vec = statement.to_vec();
    let mut rng = AesRng::from_random_seed();
    let parties = 3;
    let mut shares: Vec<Vec<F>> = (0..parties - 1)
        .map(|_| {
            last_vec
                .iter_mut()
                .map(|v| {
                    let random = F::random(&mut rng);
                    *v -= random;
                    random
                })
                .collect()
        })
        .collect();
    shares.push(last_vec);
    c.bench_with_input(
        BenchmarkId::new("zkfliop_prover", statement_len),
        &statement_len,
        |b, statement_len| {
            b.iter(|| {
                criterion::black_box(prove(
                    shares.iter(),
                    statement.to_vec(),
                    F::two(),
                    F::three(),
                    F::four(),
                ));
            })
        },
    );
}
pub fn zkfliop_bench(c: &mut Criterion) {
    do_zkfliop_bench::<GF64>(c, 1 << 17);
}
fn get_statement<F: FieldElement>(len: usize) -> Vec<F> {
    let mut output = Vec::with_capacity(2 * len + 1);
    output.push(F::zero());
    let mut sum = F::zero();
    for _ in 0..len {
        let x = F::random(thread_rng());
        let y = F::random(thread_rng());
        sum += x * y;
        output.push(x);
        output.push(y);
    }
    output[0] = sum;
    output
}
criterion_group!(benches, zkfliop_bench);
criterion_main!(benches);
