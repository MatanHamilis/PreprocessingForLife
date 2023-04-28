use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    sync::Arc,
    time::Instant,
};

use criterion::{criterion_group, criterion_main, Criterion};
use futures::future::try_join_all;
use rand::thread_rng;
use silent_party::{
    circuit_eval::{
        circuit_from_file, multi_party_semi_honest_eval_circuit, FieldContainer, GF2Container,
        MaliciousSecurityOffline, OfflineSemiHonestCorrelation, PackedGF2Container, ParsedCircuit,
        PcgBasedPairwiseBooleanCorrelation, PreOnlineMaterial,
    },
    engine::{self, MultiPartyEngine, NetworkRouter},
    fields::{FieldElement, PackedField, PackedGF2, GF128, GF2},
    PartyId, UCTag,
};
use tokio::join;

const ROOT_TAG: &str = "ROOT_TAG";

async fn set_up_routers_for_parties(
    party_ids: &HashSet<PartyId>,
    base_port: u16,
) -> (
    HashMap<PartyId, NetworkRouter>,
    HashMap<PartyId, impl MultiPartyEngine>,
) {
    let addresses = Arc::new(HashMap::from_iter(party_ids.iter().map(|i| {
        (
            *i,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, base_port + *i as u16),
        )
    })));
    let mut routers = vec![];
    let parties_count = party_ids.len();
    for &id in party_ids {
        let personal_peers = addresses.clone();
        routers.push(async move {
            let personal_port = personal_peers.get(&id).unwrap().port();
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
>(
    c: &mut Criterion,
    id: &str,
    circuit: ParsedCircuit,
    input: &[F],
    party_count: usize,
    base_port: u16,
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
            let mut rng = thread_rng();
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
            let (_, _, offline_correlations) = PcgBasedPairwiseBooleanCorrelation::<N, F>::deal(
                &mut rng,
                &parties_input_lengths,
                &circuit,
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
                            println!(
                                "\t\tSemi Honest - Opening Beaver triples: {}ms",
                                timer.elapsed().as_millis()
                            );
                            Result::<_, ()>::Ok((id, bts, offline_correlation))
                        })
                    });

            let exec_results = try_join_all(engine_futures).await.unwrap();
            let engine_futures = exec_results.into_iter().map(|v| v.unwrap()).map(
                |(id, n_party_correlation, offline_corerlation)| {
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
                        let n_party_correlation = n_party_correlation;
                        let time = Instant::now();
                        let o = multi_party_semi_honest_eval_circuit::<N, _, _, _, FC>(
                            &mut engine,
                            &circuit,
                            &input,
                            &my_input_mask,
                            input_wire_masks,
                            &n_party_correlation,
                            &output_wire_masks,
                            &parties_input_lengths,
                        )
                        .await
                        .map(
                            |(masked_input_wires, masked_gate_inputs, masked_outputs)| {
                                (
                                    masked_gate_inputs,
                                    masked_outputs,
                                    output_wire_masks,
                                    n_party_correlation,
                                    masked_input_wires,
                                )
                            },
                        );
                        let time = time.elapsed();
                        println!("semi honest: {}", time.as_millis());
                        (time, o)
                    })
                },
            );

            let e = try_join_all(engine_futures).await.unwrap();
            let output = e[0].0;
            let v: usize = try_join_all(router_handles)
                .await
                .unwrap()
                .into_iter()
                .sum();
            println!("Total bytes sent: {}", v);
            output
        })
    });
}

fn bench_malicious_circuit<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    FC: FieldContainer<PF>,
>(
    c: &mut Criterion,
    id: &str,
    circuit: ParsedCircuit,
    input: &[PF],
    parties: usize,
    base_port: u16,
) {
    let mut two = GF128::zero();
    two.set_bit(true, 1);
    let three = two + GF128::one();
    let four = two * two;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(16)
        .thread_stack_size(32 * 1024 * 1024)
        .build()
        .unwrap();
    let circuit = Arc::new(circuit);
    let input = Arc::new(input);
    c.bench_function(format!("{} semi malicious online", id).as_str(), |b| {
        b.to_async(&runtime).iter_custom(|_| {
            let circuit = circuit.clone();
            let input = input.clone();
            async move {
                // Offline
                let dealer_id: PartyId = parties as PartyId + 1;
                let offline_party_ids: Vec<_> = (0..=parties).map(|i| (i + 1) as PartyId).collect();
                let offline_parties_set = HashSet::from_iter(offline_party_ids.iter().copied());
                let default_input_length = input.len() / parties;
                let addition_threshold = input.len() % parties;
                let mut inputs = HashMap::with_capacity(parties);
                let mut used_input = 0;
                let input_lengths: HashMap<_, _> = offline_party_ids
                    .iter()
                    .copied()
                    .filter(|i| i != &dealer_id)
                    .enumerate()
                    .map(|(idx, i)| {
                        let my_input_len =
                            default_input_length + (idx < addition_threshold) as usize;
                        let my_input = input[used_input..used_input + my_input_len].to_vec();
                        inputs.insert(i, my_input);
                        used_input += my_input_len;
                        (i, (used_input - my_input_len, my_input_len))
                    })
                    .collect();
                let (routers, mut engines) =
                    set_up_routers_for_parties(&offline_parties_set, base_port).await;
                let router_handles: Vec<_> = routers
                    .into_iter()
                    .map(|(_, r)| tokio::spawn(r.launch()))
                    .collect();
                let input_lengths_arc = Arc::new(input_lengths);
                let dealer_handle = {
                    let circuit_arc_clone = circuit.clone();
                    let mut dealer_engine = engines.remove(&dealer_id).unwrap();
                    let input_lengths = input_lengths_arc.clone();
                    async move {
                        MaliciousSecurityOffline::<
                            PACKING,
                            PF,
                            GF2,
                            GF128,
                            _,
                            PcgBasedPairwiseBooleanCorrelation<PACKING, PF>,
                        >::malicious_security_offline_dealer(
                            &mut dealer_engine,
                            two,
                            three,
                            four,
                            circuit_arc_clone,
                            &input_lengths,
                        )
                        .await;
                    }
                };

                let parties_handles: Vec<_> = engines
                    .into_iter()
                    .map(|(pid, mut e)| {
                        let circuit_clone_arc = circuit.clone();
                        async move {
                            let res = MaliciousSecurityOffline::<
                                PACKING,
                                PF,
                                GF2,
                                GF128,
                                _,
                                PcgBasedPairwiseBooleanCorrelation<PACKING, PF>,
                            >::malicious_security_offline_party(
                                &mut e,
                                dealer_id,
                                circuit_clone_arc,
                            )
                            .await;
                            Result::<
                                (
                                    PartyId,
                                    MaliciousSecurityOffline<PACKING, PF, GF2, GF128, _, _>,
                                ),
                                (),
                            >::Ok((pid, res))
                        }
                    })
                    .collect();

                let parties_handles = try_join_all(parties_handles);
                let (_, parties_offline_material, router_output) =
                    join!(dealer_handle, parties_handles, try_join_all(router_handles));
                router_output.unwrap();
                let parties_offline_material = parties_offline_material.unwrap();

                // Pre Online
                let online_party_ids: Vec<_> = (0..parties).map(|i| (i + 1) as PartyId).collect();
                let online_parties_set = HashSet::from_iter(online_party_ids.iter().copied());
                let (routers, mut engines) =
                    set_up_routers_for_parties(&online_parties_set, base_port).await;
                let router_handles: Vec<_> = routers
                    .into_iter()
                    .map(|(_, r)| tokio::spawn(r.launch()))
                    .collect();

                let pre_online_handles = parties_offline_material.into_iter().map(
                    |(pid, offline_material)| {
                        let mut engine = engines.get(&pid).unwrap().sub_protocol("PRE-ONLINE");
                        async move {
                            let pre_online_material =
                                offline_material.into_pre_online_material(&mut engine).await;
                            Result::<(PartyId, PreOnlineMaterial<PACKING, PF, _, _, _, _>), ()>::Ok(
                                (pid, pre_online_material),
                            )
                        }
                    },
                );

                let pre_online_handles = try_join_all(pre_online_handles).await.unwrap();

                // Online
                let online_handles = pre_online_handles.into_iter().map(|(pid, mut pre)| {
                    let input = inputs.remove(&pid).unwrap();
                    let mut engine = engines.remove(&pid).unwrap();
                    let input_lengths = input_lengths_arc.clone();
                    tokio::spawn(async move {
                        let start = Instant::now();
                        let o = pre
                            .online_malicious_computation::<FC>(
                                &mut engine,
                                input,
                                two,
                                three,
                                four,
                                &input_lengths,
                            )
                            .await
                            .ok_or(());
                        println!("Malicious eval took: {}ms", start.elapsed().as_millis());
                        o
                    })
                });
                let start = Instant::now();
                let mut online_outputs: Vec<_> = try_join_all(online_handles)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|v| v.unwrap())
                    .collect();
                let output = start.elapsed();
                println!("Running took: {}", output.as_millis());
                let total_bytes: usize = try_join_all(router_handles)
                    .await
                    .unwrap()
                    .into_iter()
                    .sum();
                println!("Total bytes:{}", total_bytes);
                output
            }
        })
    });
}
pub fn bench_2p_semi_honest(c: &mut Criterion) {
    let path = Path::new("circuits/aes_128.txt");
    let circuit = circuit_from_file(path).unwrap();
    let input = vec![PackedGF2::one(); circuit.input_wire_count];
    bench_boolean_circuit_semi_honest::<{ PackedGF2::BITS }, _, PackedGF2Container>(
        c,
        "aes semi honest packed",
        circuit.clone(),
        &input,
        2,
        3000,
    );

    let input = vec![GF2::one(); circuit.input_wire_count];
    bench_boolean_circuit_semi_honest::<{ GF2::BITS }, _, GF2Container>(
        c,
        "aes semi honest bit",
        circuit.clone(),
        &input,
        2,
        3000,
    );
}
pub fn bench_2p_malicious(c: &mut Criterion) {
    let p = PackedGF2::one();
    println!(
        "Packed GF2 serialized size: {}",
        bincode::serialize(&p).unwrap().len()
    );
    let path = Path::new("circuits/aes_128.txt");
    let circuit = circuit_from_file(path).unwrap();
    let input = vec![PackedGF2::one(); circuit.input_wire_count];
    bench_malicious_circuit::<{ PackedGF2::BITS }, _, PackedGF2Container>(
        c,
        "aes malicious packed",
        circuit.clone(),
        &input,
        2,
        3000,
    );
    let input = vec![GF2::one(); circuit.input_wire_count];
    bench_malicious_circuit::<{ GF2::BITS }, _, GF2Container>(
        c,
        "aes malicious bit",
        circuit.clone(),
        &input,
        2,
        3000,
    );
}
criterion_group!(benches, bench_2p_malicious, bench_2p_semi_honest);
criterion_main!(benches);
