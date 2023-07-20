use std::fmt::format;

use aes_prng::AesRng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;
use silent_party::fields::{FieldElement, IntermediateMulField, GF64};
use silent_party::zkfliop::ni::{obtain_check_value, prove};
use silent_party::zkfliop::{dealer, ProverCtx, VerifierCtx};

fn do_zkfliop_bench<F: IntermediateMulField>(
    c: &mut Criterion,
    statement_len: usize,
    log_folding_factor: usize,
) {
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
        BenchmarkId::new(
            format!("zkfliop_prover {}", log_folding_factor),
            statement_len,
        ),
        &statement_len,
        |b, statement_len| {
            let mut prover_ctx = ProverCtx::<F>::new(log_folding_factor);
            b.iter(|| {
                criterion::black_box(prove(shares.iter(), statement.to_vec(), &mut prover_ctx));
            })
        },
    );
}
fn do_zkfliop_bench_verify<F: IntermediateMulField>(
    c: &mut Criterion,
    statement_len: usize,
    log_folding_factor: usize,
) {
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
    let mut prover_ctx = ProverCtx::<F>::new(log_folding_factor);
    let proof = prove(shares.iter(), statement.to_vec(), &mut prover_ctx);
    let share = shares[0].clone();
    c.bench_with_input(
        BenchmarkId::new(
            format!("zkfliop_verifier {}", log_folding_factor),
            statement_len,
        ),
        &statement_len,
        |b, statement_len| {
            let share = share.clone();
            let mut verifier_ctx = VerifierCtx::<F>::new(log_folding_factor);
            b.iter_batched(
                || share.clone(),
                |(share)| {
                    criterion::black_box(obtain_check_value(share, &proof[0], &mut verifier_ctx));
                },
                criterion::BatchSize::PerIteration,
            )
        },
    );
}
pub fn zkfliop_bench(c: &mut Criterion) {
    let statement_len = 10_000;
    do_zkfliop_bench_verify::<GF64>(c, statement_len, 1);
    do_zkfliop_bench::<GF64>(c, statement_len, 1);
    do_zkfliop_bench_verify::<GF64>(c, statement_len, 2);
    do_zkfliop_bench::<GF64>(c, statement_len, 2);
    do_zkfliop_bench_verify::<GF64>(c, statement_len, 3);
    do_zkfliop_bench::<GF64>(c, statement_len, 3);
    do_zkfliop_bench_verify::<GF64>(c, statement_len, 4);
    do_zkfliop_bench::<GF64>(c, statement_len, 4);
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
