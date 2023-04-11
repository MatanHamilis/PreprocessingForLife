use std::collections::HashSet;

use criterion::{criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};
use futures::future::try_join_all;
use rand::thread_rng;
use silent_party::{
    engine::{LocalRouter, MultiPartyEngine},
    fields::{FieldElement, GF128},
    zkfliop::{dealer, g, prover, verifier},
    PartyId, UCTag,
};
use tokio::{join, time::Instant};

async fn bench_routine<F: FieldElement>(
    prover_id: PartyId,
    dealer_id: PartyId,
    prover_engine: impl MultiPartyEngine,
    dealer_engine: impl MultiPartyEngine,
    verifier_engines: Vec<impl MultiPartyEngine>,
    prover_input: Vec<F>,
    dealer_input: Vec<F>,
    verifier_input: Vec<Vec<F>>,
    two: F,
    three: F,
    four: F,
) {
    let prover_future = tokio::spawn(async move {
        let mut prover_input = prover_input;
        prover(
            prover_engine,
            &mut prover_input,
            dealer_id,
            two.clone(),
            three.clone(),
            four.clone(),
        )
        .await
    });
    let dealer_future = tokio::spawn(async move {
        let mut dealer_input = dealer_input;
        dealer(
            dealer_engine,
            &mut dealer_input,
            prover_id,
            two,
            three,
            four,
        )
        .await
    });
    let verfiers_futures: Vec<_> = verifier_engines
        .into_iter()
        .zip(verifier_input.into_iter())
        .map(|(e, input)| {
            tokio::spawn(async move {
                let mut input = input;
                verifier(e, &mut input, prover_id, dealer_id, two, three, four).await;
                Result::<(), ()>::Ok(())
            })
        })
        .collect();
    let v = try_join_all(verfiers_futures);
    let (_, _, v) = join!(prover_future, dealer_future, v);
    v.unwrap();
}
fn bench_single(log_length: usize, parties: usize, b: &mut Bencher) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let z_len: usize = (1 << log_length) + 1;
    let party_ids: Vec<_> = (1..=parties).map(|i| i as u64).collect();
    let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
    let prover_id = party_ids[0];
    let dealer_id = party_ids[1];
    let mut two = GF128::zero();
    two.set_bit(true, 1);
    let three = two + GF128::one();
    let four = two * two;

    let mut rng = thread_rng();
    let (router, engines) = LocalRouter::new(UCTag::new(&"root"), &party_ids_set);

    let router_handle = runtime.spawn(router.launch());
    let mut prover_input = vec![GF128::zero(); z_len];
    for i in 1..prover_input.len() {
        prover_input[i] = GF128::random(&mut rng);
    }
    prover_input[0] = g(&prover_input[1..]);

    let mut verifier_input: Vec<_> = prover_input
        .iter()
        .enumerate()
        .map(|(idx, v)| if idx % 2 != 0 { *v } else { GF128::zero() })
        .collect();
    verifier_input[0] -= GF128::random(&mut rng);
    let dealer_input: Vec<_> = prover_input
        .iter()
        .zip(verifier_input.iter())
        .map(|(a, b)| *a - *b)
        .collect();
    b.to_async(&runtime).iter_batched(
        || {
            (
                prover_id,
                dealer_id,
                engines.get(&prover_id).unwrap().sub_protocol("A"),
                engines.get(&dealer_id).unwrap().sub_protocol("A"),
                engines
                    .iter()
                    .filter_map(|(id, e)| {
                        if *id == prover_id || *id == dealer_id {
                            return None;
                        }
                        Some(e.sub_protocol("A"))
                    })
                    .collect(),
                prover_input.clone(),
                dealer_input.clone(),
                vec![verifier_input.clone(); parties - 2],
                two,
                three,
                four,
            )
        },
        |(
            prover_id,
            dealer_id,
            prover_engine,
            dealer_engine,
            verifier_engines,
            prover_input,
            dealer_input,
            verifier_input,
            two,
            three,
            four,
        )| {
            bench_routine(
                prover_id,
                dealer_id,
                prover_engine,
                dealer_engine,
                verifier_engines,
                prover_input,
                dealer_input,
                verifier_input,
                two,
                three,
                four,
            )
        },
        criterion::BatchSize::PerIteration,
    );
    drop(engines);
    runtime.block_on(async { router_handle.await.unwrap().unwrap() })
}
pub fn bench_zkfliop(c: &mut Criterion) {
    const PARTIES_START: usize = 3;
    const PARTIES_END: usize = 3;
    const LOG_Z_START: usize = 10;
    const LOG_Z_END: usize = 24;

    for parties in PARTIES_START..=PARTIES_END {
        let mut g = c.benchmark_group(format!("parties {}", parties).as_str());
        for log_z in LOG_Z_START..=LOG_Z_END {
            g.bench_with_input(
                BenchmarkId::new(format!("zkfliop {}", parties), log_z),
                &(parties, log_z),
                |b, &(parties, log_z)| bench_single(log_z, parties, b),
            );
        }
    }
}

criterion_group!(benches, bench_zkfliop);
criterion_main!(benches);
