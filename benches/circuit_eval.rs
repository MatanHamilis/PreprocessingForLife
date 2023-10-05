#![feature(generic_const_exprs)]
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    sync::Arc,
    time::Instant,
};

const PPRF_COUNT: usize = 75;
const PPRF_DEPTH: usize = 20;
use aes_prng::AesRng;
use core_affinity::CoreId;
use criterion::{criterion_group, criterion_main, Criterion};
use futures::future::try_join_all;
use log::info;
use pretty_env_logger::env_logger::Logger;
use rand::thread_rng;
use rayon::prelude::*;
use silent_party::{
    circuit_eval::{
        circuit_from_file, multi_party_semi_honest_eval_circuit, DealerCtx, FieldContainer,
        FliopCtx, GF2Container, MaliciousSecurityOffline, OfflineSemiHonestCorrelation,
        PackedGF2Container, ParsedCircuit, PcgBasedPairwiseBooleanCorrelation, PreOnlineMaterial,
    },
    engine::{self, MultiPartyEngine, NetworkRouter},
    fields::{FieldElement, PackedField, PackedGF2, GF2, GF64},
    pcg::{
        PackedKeysDealer, PackedOfflineReceiverPcgKey, PackedSenderCorrelationGenerator,
        StandardDealer,
    },
    PartyId, UCTag,
};
use tokio::join;

const ROOT_TAG: &str = "ROOT_TAG";

async fn set_up_router_for_party(
    id: PartyId,
    party_ids: &HashSet<PartyId>,
    base_port: u16,
) -> (NetworkRouter, impl MultiPartyEngine) {
    let parties_count = party_ids.len();
    let addresses = HashMap::from_iter(party_ids.iter().filter(|i| *i > &id).map(|i| {
        (
            *i,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, base_port + *i as u16),
        )
    }));
    async move {
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
    }
    .await
    .unwrap()
}
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
fn bench_boolean_circuit_semi_honest<
    const N: usize,
    F: PackedField<GF2, N>,
    FC: FieldContainer<F>,
    PS: PackedSenderCorrelationGenerator + 'static,
    D: PackedKeysDealer<PS> + 'static,
>(
    c: &mut Criterion,
    id: &str,
    circuit: ParsedCircuit,
    input: &[F],
    party_count: usize,
    base_port: u16,
    pcg_dealer: Arc<D>,
) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(16)
        .build()
        .unwrap();
    c.bench_function(format!("{} semi honest online", id).as_str(), |b| {
        b.to_async(&runtime).iter_custom(|_| async {
            const CODE_SEED: [u8; 16] = [1u8; 16];
            assert_eq!(input.len(), circuit.input_wire_count);
            let mut party_ids: Vec<_> = (1..=party_count).map(|i| i as u64).collect();
            party_ids.sort();
            let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
            let (routers, mut engines) =
                set_up_routers_for_parties(&party_ids_set, base_port).await;
            let router_handles: Vec<_> = routers
                .into_iter()
                .map(|(_, r)| tokio::spawn(r.launch()))
                .collect();
            let mut rng = AesRng::from_random_seed();
            let addition_threshold = circuit.input_wire_count % party_count;
            let mut total_input_previous = 0;
            let parties_input_lengths: HashMap<_, _> = party_ids
                .iter()
                .enumerate()
                .map(|(i, pid)| {
                    let addition = (i < addition_threshold) as usize;
                    let my_input_length = circuit.input_wire_count / party_count + addition;
                    let my_input_start = total_input_previous;
                    total_input_previous += my_input_length;
                    (*pid, (my_input_start, my_input_length))
                })
                .collect();
            let (_, _, offline_correlations) =
                PcgBasedPairwiseBooleanCorrelation::<N, F, PS, D>::deal(
                    &mut rng,
                    &parties_input_lengths,
                    &circuit,
                    pcg_dealer.as_ref(),
                );

            let parties_input_lengths = Arc::new(parties_input_lengths);
            let mut inputs: HashMap<_, _> = parties_input_lengths
                .iter()
                .map(|(&pid, &(input_start, input_len))| {
                    let my_input = input[input_start..input_start + input_len].to_vec();
                    (pid, my_input)
                })
                .collect();
            let engine_futures =
                offline_correlations
                    .into_iter()
                    .map(|(id, mut offline_correlation)| {
                        let circuit = circuit.clone();
                        let mut engine =
                            engines.get(&id).unwrap().sub_protocol("MULTIPARTY BEAVER");
                        tokio::spawn(async move {
                            let timer = Instant::now();
                            let bts = offline_correlation
                                .get_multiparty_beaver_triples(&mut engine, &circuit)
                                .await;
                            info!(
                                "\t\tSemi Honest - Opening Beaver triples: {}ms",
                                timer.elapsed().as_millis()
                            );
                            Result::<_, ()>::Ok((id, offline_correlation))
                        })
                    });

            let exec_results = try_join_all(engine_futures).await.unwrap();
            let engine_futures =
                exec_results
                    .into_iter()
                    .map(|v| v.unwrap())
                    .map(|(id, offline_corerlation)| {
                        let mut engine = engines.remove(&id).unwrap();
                        let circuit = circuit.clone();
                        let input = inputs.remove(&id).unwrap();
                        let output_wire_masks: Vec<_> =
                            offline_corerlation.get_circuit_output_wires_masks_shares(&circuit);
                        let input_wire_masks: Vec<_> =
                            offline_corerlation.get_circuit_input_wires_masks_shares(&circuit);
                        let my_input_mask = offline_corerlation
                            .get_personal_circuit_input_wires_masks()
                            .to_vec();
                        let parties_input_lengths = parties_input_lengths.clone();
                        tokio::spawn(async move {
                            let (n_party_correlation, wide_n_party_correlation) =
                                offline_corerlation.get_prepared_multiparty_beaver_triples();
                            let time = Instant::now();
                            let o = multi_party_semi_honest_eval_circuit::<N, _, _, _, FC>(
                                &mut engine,
                                &circuit,
                                &input,
                                &my_input_mask,
                                input_wire_masks,
                                &n_party_correlation,
                                &wide_n_party_correlation,
                                &output_wire_masks,
                                &parties_input_lengths,
                            )
                            .await
                            .map(
                                |(
                                    masked_input_wires,
                                    masked_gate_inputs,
                                    wide_masked_gate_inputs,
                                    masked_outputs,
                                )| {
                                    (
                                        masked_gate_inputs,
                                        wide_masked_gate_inputs,
                                        masked_outputs,
                                        output_wire_masks,
                                        masked_input_wires,
                                    )
                                },
                            );
                            let time = time.elapsed();
                            info!("semi honest: {}", time.as_millis());
                            (time, o)
                        })
                    });

            let e = try_join_all(engine_futures).await.unwrap();
            let output = e[0].0;
            let v: usize = try_join_all(router_handles)
                .await
                .unwrap()
                .into_iter()
                .sum();
            info!("Total bytes sent: {}", v);
            output
        })
    });
}

fn bench_malicious_circuit<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    FC: FieldContainer<PF>,
    PS: PackedSenderCorrelationGenerator + 'static,
    D: PackedKeysDealer<PS> + 'static,
>(
    c: &mut Criterion,
    id: &str,
    circuit: ParsedCircuit,
    input: &[PF],
    parties: usize,
    base_port: u16,
    pcg_dealer: Arc<D>,
    is_authenticated: bool,
    log_folding_factor: usize,
) {
    let input = input.clone();
    let dealer = pcg_dealer.clone();
    let input = Arc::new(input);
    // Make CTXs
    let mut dealer_ctx = DealerCtx::<GF64>::new(log_folding_factor);
    let mut parties_ctx: Vec<_> = (0..parties)
        .map(|_| FliopCtx::<GF64>::new(log_folding_factor, parties - 1))
        .collect();

    // Offline
    let online_party_ids: Vec<_> = (0..parties).map(|i| (i + 1) as PartyId).collect();
    let default_input_length = input.len() / parties;
    let addition_threshold = input.len() % parties;
    let mut inputs = HashMap::with_capacity(parties);
    let mut used_input = 0;
    let input_lengths: HashMap<_, _> = online_party_ids
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, i)| {
            let my_input_len = default_input_length + (idx < addition_threshold) as usize;
            let my_input = input[used_input..used_input + my_input_len].to_vec();
            inputs.insert(i, my_input);
            used_input += my_input_len;
            (i, (used_input - my_input_len, my_input_len))
        })
        .collect();
    let time = Instant::now();
    let mut parties_offline_material = MaliciousSecurityOffline::<
        PACKING,
        PF,
        GF64,
        PcgBasedPairwiseBooleanCorrelation<PACKING, PF, PS, D>,
    >::malicious_security_offline_dealer(
        &circuit,
        &input_lengths,
        dealer.as_ref(),
        is_authenticated,
        &mut dealer_ctx,
    );
    info!("Dealer:\t took: {}ms", time.elapsed().as_millis());
    let online_party_ids: Vec<_> = (0..parties).map(|i| (i + 1) as PartyId).collect();
    let online_parties_set = Arc::new(HashSet::from_iter(online_party_ids.iter().copied()));

    let circuit = Arc::new(circuit);
    let mut inputs = inputs;
    let input_lengths = Arc::new(input_lengths);
    let mut handles = Vec::with_capacity(parties);
    for (pid, mut ctx) in online_party_ids
        .iter()
        .copied()
        .zip(parties_ctx.into_iter())
    {
        let circuit = circuit.clone();
        let input = inputs.remove(&pid).unwrap();
        let input_lengths = input_lengths.clone();
        let offline_material = parties_offline_material.remove(&pid).unwrap();
        let is_authenticated = is_authenticated.clone();
        let online_parties_set = online_parties_set.clone();
        handles.push(std::thread::spawn(move || {
            core_affinity::set_for_current(CoreId {
                id: pid as usize + 1,
            });
            let offline_material = offline_material;
            party_run::<PACKING, _, FC, _, _>(
                pid,
                online_parties_set,
                circuit,
                input,
                input_lengths,
                is_authenticated,
                &offline_material,
                base_port,
                &mut ctx,
            )
        }));
    }
    let (_, mut start, mut end) = handles.pop().unwrap().join().unwrap().unwrap();
    let (start, end) = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .fold(
            (start, end),
            |(acc_start, acc_end), (_, cur_start, cur_end)| {
                let start = acc_start.max(cur_start);
                let end = acc_end.min(cur_end);
                (start, end)
            },
        );
    println!("Duration: {}", end.duration_since(start).as_millis());
    info!("Done!");
    // c.bench_function(format!("{} semi malicious online", id).as_str(), |b| {
    //     let runtime = tokio::runtime::Builder::new_multi_thread()
    //         .worker_threads(4)
    //         .enable_all()
    //         .thread_stack_size(32 * 1024 * 1024)
    //         .build()
    //         .unwrap();
    //     b.iter_custom(|_| {
    //         let input_lengths = input_lengths.clone();
    //         let circuit = circuit.clone();
    //         let inputs = inputs.clone();
    //         let parties_offline_material = parties_offline_material.clone();
    //     })
    // });
}
pub fn party_run<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    FC: FieldContainer<PF>,
    PS: PackedSenderCorrelationGenerator + 'static,
    D: PackedKeysDealer<PS> + 'static,
>(
    party_id: PartyId,
    party_ids: Arc<HashSet<PartyId>>,
    circuit: impl AsRef<ParsedCircuit>,
    input: Vec<PF>,
    input_lengths: Arc<HashMap<PartyId, (usize, usize)>>,
    is_authenticated: bool,
    offline_material: &MaliciousSecurityOffline<
        PACKING,
        PF,
        GF64,
        PcgBasedPairwiseBooleanCorrelation<PACKING, PF, PS, D>,
    >,
    base_port: u16,
    ctx: &mut FliopCtx<GF64>,
) -> Result<(Vec<PF>, Instant, Instant), ()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (router, mut engine) =
                set_up_router_for_party(party_id, party_ids.as_ref(), base_port).await;
            let router_handle = tokio::spawn(router.launch());
            // First, if needed, verify the triples
            if is_authenticated {
                let time = Instant::now();
                offline_material
                    .malicious_security_offline_party(
                        &mut engine.sub_protocol("verify_triples"),
                        circuit.as_ref(),
                        is_authenticated,
                        ctx,
                    )
                    .await;
                info!("Offline party took: {}ms", time.elapsed().as_millis());
            }

            // Pre Online

            let mut pre = {
                let mut engine = engine.sub_protocol("PRE-ONLINE");
                offline_material
                    .into_pre_online_material(&mut engine, circuit)
                    .await
            };

            // Online
            let (output, start) = {
                let start = Instant::now();
                let o = pre
                    .online_malicious_computation::<FC>(&mut engine, &input, &input_lengths, ctx)
                    .await
                    .ok_or(());
                (o, start)
            };
            drop(engine);
            let end = Instant::now();
            let total_bytes: usize = router_handle.await.unwrap();
            info!("Total bytes:{}", total_bytes);
            output.map(|v| (v, start, end))
        })
}
pub fn bench_2p_semi_honest(c: &mut Criterion) {
    let path = Path::new("circuits/aes_128.txt");
    let circuit = circuit_from_file(path).unwrap();
    let input = vec![PackedGF2::one(); circuit.input_wire_count];
    let dealer = Arc::new(StandardDealer::new(PPRF_COUNT, PPRF_DEPTH));
    bench_boolean_circuit_semi_honest::<
        { PackedGF2::BITS },
        _,
        PackedGF2Container,
        PackedOfflineReceiverPcgKey<8>,
        _,
    >(
        c,
        "aes semi honest packed",
        circuit.clone(),
        &input,
        2,
        3000,
        dealer.clone(),
    );

    let input = vec![GF2::one(); circuit.input_wire_count];
    bench_boolean_circuit_semi_honest::<
        { GF2::BITS },
        _,
        GF2Container,
        PackedOfflineReceiverPcgKey<8>,
        _,
    >(
        c,
        "aes semi honest bit",
        circuit.clone(),
        &input,
        2,
        3000,
        dealer.clone(),
    );
}
pub fn bench_2p_malicious(c: &mut Criterion) {
    let is_authenticated = true;
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let p = PackedGF2::one();
    info!(
        "Packed GF2 serialized size: {}",
        bincode::serialize(&p).unwrap().len()
    );
    const PCGPACK: usize = 1;
    let path = Path::new("circuits/aes_128.txt");
    let circuit = circuit_from_file(path).unwrap();
    let prexor_path = Path::new("circuits/prexor_256.txt");
    let prexor_circuit = circuit_from_file(prexor_path).unwrap();
    let circuit = prexor_circuit.try_compose(circuit).unwrap();
    let input = vec![PackedGF2::one(); circuit.input_wire_count];
    let dealer = Arc::new(StandardDealer::new(PPRF_COUNT, PPRF_DEPTH));
    let log_folding_factor: usize = 3;
    bench_malicious_circuit::<
        { PackedGF2::BITS },
        _,
        PackedGF2Container,
        PackedOfflineReceiverPcgKey<1>,
        _,
    >(
        c,
        "aes malicious packed 1",
        circuit.clone(),
        &input,
        2,
        3000,
        dealer.clone(),
        is_authenticated,
        log_folding_factor,
    );
    bench_malicious_circuit::<
        { PackedGF2::BITS },
        _,
        PackedGF2Container,
        PackedOfflineReceiverPcgKey<2>,
        _,
    >(
        c,
        "aes malicious packed 2",
        circuit.clone(),
        &input,
        2,
        3000,
        dealer.clone(),
        is_authenticated,
        log_folding_factor,
    );
    bench_malicious_circuit::<
        { PackedGF2::BITS },
        _,
        PackedGF2Container,
        PackedOfflineReceiverPcgKey<4>,
        _,
    >(
        c,
        "aes malicious packed 4",
        circuit.clone(),
        &input,
        2,
        3000,
        dealer.clone(),
        is_authenticated,
        log_folding_factor,
    );
    bench_malicious_circuit::<
        { PackedGF2::BITS },
        _,
        PackedGF2Container,
        PackedOfflineReceiverPcgKey<8>,
        _,
    >(
        c,
        "aes malicious packed 8",
        circuit.clone(),
        &input,
        2,
        3000,
        dealer.clone(),
        is_authenticated,
        log_folding_factor,
    );
    let input = vec![GF2::one(); circuit.input_wire_count];
    bench_malicious_circuit::<
        { GF2::BITS },
        _,
        GF2Container,
        PackedOfflineReceiverPcgKey<PCGPACK>,
        _,
    >(
        c,
        "aes malicious bit",
        circuit.clone(),
        &input,
        2,
        3000,
        dealer.clone(),
        is_authenticated,
        log_folding_factor,
    );
}
criterion_group!(benches, bench_2p_malicious, bench_2p_semi_honest);
criterion_main!(benches);
