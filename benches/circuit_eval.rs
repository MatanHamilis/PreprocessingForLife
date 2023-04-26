use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    sync::Arc,
};

use criterion::{criterion_group, criterion_main, Criterion};
use futures::future::try_join_all;
use rand::thread_rng;
use silent_party::{
    circuit_eval::{
        circuit_from_file, multi_party_semi_honest_eval_circuit, OfflineSemiHonestCorrelation,
        ParsedCircuit, PcgBasedPairwiseBooleanCorrelation,
    },
    engine::{self, MultiPartyEngine, NetworkRouter},
    fields::{FieldElement, PackedField, PackedGF2, GF2},
    PartyId, UCTag,
};
use tokio::time::Instant;

const CIRCUIT: &str = "circuits/aes_128.txt";
const DEALER_ID: PartyId = 1;
const PARTY_A_ID: PartyId = 2;
const PARTY_B_ID: PartyId = 3;
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
fn bench_boolean_circuit<const N: usize, F: PackedField<GF2, N>>(
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
                        async move {
                            let bts = offline_correlation
                                .get_multiparty_beaver_triples(&mut engine, &circuit)
                                .await;
                            Result::<_, ()>::Ok((id, bts, offline_correlation))
                        }
                    });
            let parties_input_lengths = Arc::new(parties_input_lengths);
            let exec_results = try_join_all(engine_futures).await.unwrap();

            let engine_futures =
                exec_results
                    .into_iter()
                    .map(|(id, n_party_correlation, offline_corerlation)| {
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
                            multi_party_semi_honest_eval_circuit(
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
                            )
                        })
                    });

            let timer_start = Instant::now();
            try_join_all(engine_futures).await.unwrap();
            let output = timer_start.elapsed();
            println!("Time: {}", output.as_millis());
            try_join_all(router_handles).await.unwrap();
            output
        })
    });
}
pub fn bench_2p_semi_honest(c: &mut Criterion) {
    let path = Path::new("circuits/aes_128.txt");
    let circuit = circuit_from_file(path).unwrap();
    let input = vec![PackedGF2::one(); circuit.input_wire_count];
    bench_boolean_circuit(c, "aes", circuit, &input, 2, 3000);
}
criterion_group!(benches, bench_2p_semi_honest);
criterion_main!(benches);
