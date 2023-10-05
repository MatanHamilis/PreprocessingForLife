use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    println,
    sync::Arc,
};

use aes_prng::AesRng;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use futures::future::try_join_all;
use log::info;
use silent_party::{
    circuit_eval::{
        spdz::{offline_spdz_verify, online_spdz, spdz_deal},
        FieldContainer, PackedGF2Container, ParsedCircuit,
    },
    engine::{MultiPartyEngine, NetworkRouter},
    fields::{FieldElement, PackedField, PackedGF2, GF2, GF64},
    zkfliop::{ProverCtx, VerifierCtx},
    PartyId, UCTag,
};
use tokio::{join, time::Instant};
const ROOT_TAG: &str = "ROOT_TAG";
async fn set_up_routers_for_parties(
    party_ids: &HashSet<PartyId>,
    base_port: u16,
) -> (
    HashMap<PartyId, NetworkRouter>,
    HashMap<PartyId, impl MultiPartyEngine>,
) {
    let mut routers = vec![];
    let parties_count = party_ids.len();
    for &id in party_ids {
        let addresses = HashMap::from_iter(party_ids.iter().filter(|i| *i > &id).map(|i| {
            (
                *i,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, base_port + *i as u16),
            )
        }));
        routers.push(async move {
            let personal_port = base_port + id as u16;
            let personal_peers = addresses;
            NetworkRouter::new(
                id,
                &personal_peers,
                UCTag::new(&ROOT_TAG),
                parties_count,
                personal_port,
            )
            .await
            .ok_or(())
            .map(|v| (id, v))
        })
    }
    try_join_all(routers)
        .await
        .unwrap()
        .into_iter()
        .map(|v| ((v.0, v.1 .0), (v.0, v.1 .1)))
        .unzip()
}

fn bench_spdz_dealer<const N: usize, PF: PackedField<GF2, N>>(
    c: &mut Criterion,
    circuit: ParsedCircuit,
    input: Vec<PF>,
    log_folding_factor: usize,
) {
    let circuit = Arc::new(circuit);
    c.bench_function("aes packed spdz deal", |b| {
        b.iter_custom(|_| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let party_ids: [PartyId; 2] = [1, 2];
            let input_pos: HashMap<PartyId, (usize, usize)> = HashMap::from([
                (1, (0, circuit.input_wire_count / 2)),
                (
                    2,
                    (
                        circuit.input_wire_count / 2,
                        circuit.input_wire_count - circuit.input_wire_count / 2,
                    ),
                ),
            ]);
            //CTXs
            let mut prover_ctx = ProverCtx::<GF64>::new(log_folding_factor);
            let mut first_ctx = VerifierCtx::<GF64>::new(log_folding_factor);
            let mut second_ctx = VerifierCtx::<GF64>::new(log_folding_factor);
            let first_pos = input_pos[&party_ids[0]];
            let input_first: Vec<_> = input[first_pos.0..first_pos.0 + first_pos.1].to_vec();
            let second_pos = input_pos[&party_ids[1]];
            let input_second: Vec<_> = input[second_pos.0..second_pos.0 + second_pos.1].to_vec();
            let time = Instant::now();
            let mut corr = spdz_deal::<N, PF, GF64>(circuit.as_ref(), &input_pos, &mut prover_ctx);
            time.elapsed()
        });
    });
}
fn bench_spdz_circuit<const N: usize, PF: PackedField<GF2, N>, CF: FieldContainer<PF>>(
    c: &mut Criterion,
    circuit: ParsedCircuit,
    input: Vec<PF>,
    log_folding_factor: usize,
) {
    let circuit = Arc::new(circuit);
    c.bench_function("aes packed spdz online", |b| {
        b.iter_batched(
            || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let party_ids: [PartyId; 2] = [1, 2];
                let input_pos: HashMap<PartyId, (usize, usize)> = HashMap::from([
                    (1, (0, circuit.input_wire_count / 2)),
                    (
                        2,
                        (
                            circuit.input_wire_count / 2,
                            circuit.input_wire_count - circuit.input_wire_count / 2,
                        ),
                    ),
                ]);
                //CTXs
                let mut prover_ctx = ProverCtx::<GF64>::new(log_folding_factor);
                let mut first_ctx = VerifierCtx::<GF64>::new(log_folding_factor);
                let mut second_ctx = VerifierCtx::<GF64>::new(log_folding_factor);
                let first_pos = input_pos[&party_ids[0]];
                let input_first: Vec<_> = input[first_pos.0..first_pos.0 + first_pos.1].to_vec();
                let second_pos = input_pos[&party_ids[1]];
                let input_second: Vec<_> =
                    input[second_pos.0..second_pos.0 + second_pos.1].to_vec();
                let mut corr =
                    spdz_deal::<N, PF, GF64>(circuit.as_ref(), &input_pos, &mut prover_ctx);
                let parties_set = HashSet::from_iter(party_ids);
                let (mut routers, mut engines) =
                    runtime.block_on(set_up_routers_for_parties(&parties_set, 3000));

                let router_handle = runtime.spawn(try_join_all(routers.drain().map(|r| async {
                    let bytes = r.1.launch().await;
                    Ok::<_, ()>(bytes)
                })));
                let first_party = engines.remove(&party_ids[0]).unwrap();
                let second_party = engines.remove(&party_ids[1]).unwrap();
                let mut corr_first = corr.remove(&party_ids[0]).unwrap();
                let mut corr_second = corr.remove(&party_ids[1]).unwrap();
                // Verify Correlations
                let mut first_verify_engine = first_party.sub_protocol("verify");
                let mut second_verify_engine = second_party.sub_protocol("verify");
                let first_verify = runtime.spawn(async move {
                    offline_spdz_verify(&mut first_verify_engine, &corr_first, &mut first_ctx).await;
                    corr_first
                });
                let second_verify = runtime.spawn(async move {
                    offline_spdz_verify(&mut second_verify_engine, &corr_second, &mut second_ctx).await;
                    corr_second
                });
                let v = runtime.block_on(async { join!(first_verify, second_verify) });
                corr_first = v.0.unwrap();
                corr_second = v.1.unwrap();

                let first_party_circuit = circuit.clone();
                let second_party_circuit = circuit.clone();
                let input_pos_first = Arc::new(input_pos);
                let input_pos_second = input_pos_first.clone();
                (
                    router_handle,
                    runtime,
                    first_party,
                    first_party_circuit,
                    input_first,
                    corr_first,
                    input_pos_first,
                    second_party,
                    second_party_circuit,
                    input_second,
                    corr_second,
                    input_pos_second,
                )
            },
            |(
                router_handle,
                runtime,
                first_party,
                first_party_circuit,
                input_first,
                corr_first,
                input_pos_first,
                second_party,
                second_party_circuit,
                input_second,
                corr_second,
                input_pos_second,
            )| {
                let time = Instant::now();
                let first_party_handle = runtime.spawn(async move {
                    let mut first_party = first_party;
                    online_spdz::<N, _, _, CF>(
                        &mut first_party,
                        &first_party_circuit,
                        &input_first,
                        corr_first,
                        input_pos_first,
                    )
                    .await
                });
                let second_party_handle = runtime.spawn(async move {
                    let mut second_party = second_party;
                    online_spdz::<N, _, _, CF>(
                        &mut second_party,
                        &second_party_circuit,
                        &input_second,
                        corr_second,
                        input_pos_second,
                    )
                    .await
                });
                let (first, second, router) = runtime.block_on(async move {
                    join!(first_party_handle, second_party_handle, router_handle)
                });
                let t = time.elapsed();
                let bytes = router.unwrap().unwrap()[0];
                println!("Time: {}ms", t.as_millis());
                println!("Online bytes: {}", bytes);

                let (first, second) = (first.unwrap(), second.unwrap());
                t
            },
            criterion::BatchSize::PerIteration,
        );
    });
}
fn bench_spdz_circuit_offline_party<const N: usize, PF: PackedField<GF2, N>>(
    c: &mut Criterion,
    circuit: ParsedCircuit,
    input: Vec<PF>,
    log_folding_factor: usize,
) {
    let circuit = Arc::new(circuit);
    c.bench_function("aes packed spdz offline party", |b| {
        b.iter_custom(|_| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let party_ids: [PartyId; 2] = [1, 2];
            let input_pos: HashMap<PartyId, (usize, usize)> = HashMap::from([
                (1, (0, circuit.input_wire_count / 2)),
                (
                    2,
                    (
                        circuit.input_wire_count / 2,
                        circuit.input_wire_count - circuit.input_wire_count / 2,
                    ),
                ),
            ]);
            //CTXs
            let mut prover_ctx = ProverCtx::<GF64>::new(log_folding_factor);
            let mut first_ctx = VerifierCtx::<GF64>::new(log_folding_factor);
            let mut second_ctx = VerifierCtx::<GF64>::new(log_folding_factor);
            let first_pos = input_pos[&party_ids[0]];
            let input_first: Vec<_> = input[first_pos.0..first_pos.0 + first_pos.1].to_vec();
            let second_pos = input_pos[&party_ids[1]];
            let input_second: Vec<_> = input[second_pos.0..second_pos.0 + second_pos.1].to_vec();
            let mut corr = spdz_deal::<N, PF, GF64>(circuit.as_ref(), &input_pos, &mut prover_ctx);
            let parties_set = HashSet::from_iter(party_ids);
            let (mut routers, mut engines) =
                runtime.block_on(set_up_routers_for_parties(&parties_set, 3000));

            let router_handle = runtime.spawn(try_join_all(routers.drain().map(|r| async {
                let bytes = r.1.launch().await;
                Ok::<_, ()>(bytes)
            })));
            let first_party = engines.remove(&party_ids[0]).unwrap();
            let second_party = engines.remove(&party_ids[1]).unwrap();
            let corr_first = corr.remove(&party_ids[0]).unwrap();
            let corr_second = corr.remove(&party_ids[1]).unwrap();
            // Verify Correlations
            let mut first_verify_engine = first_party;
            let mut second_verify_engine = second_party;
            let first_verify = runtime.spawn(async move {
                offline_spdz_verify(&mut first_verify_engine, &corr_first, &mut first_ctx).await;
                corr_first
            });
            let second_verify = runtime.spawn(async move {
                offline_spdz_verify(&mut second_verify_engine, &corr_second, &mut second_ctx).await;
                corr_second
            });
            let time = Instant::now();
            let v = runtime.block_on(async { join!(first_verify, second_verify) });
            black_box(v.0.unwrap());
            let t = time.elapsed();
            let r = runtime.block_on(router_handle);
            info!("Total bytes: {}", r.unwrap().unwrap()[0]);
            t
        });
    });
}
pub fn bench_spdz(c: &mut Criterion) {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let path = Path::new("circuits/aes_128.txt");
    let parsed_circuit = silent_party::circuit_eval::circuit_from_file(path).unwrap();
    bench_spdz_circuit::<{ PackedGF2::BITS }, _, PackedGF2Container>(
        c,
        parsed_circuit.clone(),
        vec![PackedGF2::one(); 256],
        2,
    );
    bench_spdz_dealer(c, parsed_circuit.clone(), vec![PackedGF2::one(); 256], 2);
    bench_spdz_circuit_offline_party(c, parsed_circuit, vec![PackedGF2::one(); 256], 2);
}
criterion_group!(benches, bench_spdz);
criterion_main!(benches);
