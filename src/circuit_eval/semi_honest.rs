use super::bristol_fashion;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::{Add, AddAssign};

use aes_prng::AesRng;
use blake3::Hash;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

use crate::circuit_eval::bristol_fashion::ParsedGate;
use crate::engine::{MultiPartyEngine, PartyId};
use crate::fields::{FieldElement, GF128, GF2};
use crate::pcg::{self, FullPcgKey};

use self::bristol_fashion::ParsedCircuit;

#[derive(Serialize, Deserialize)]
struct EvalMessage {
    pub opening: Mask,
    pub gate_idx_in_layer: usize,
}

enum GateEvalState {
    And(GF2, GF2, GF2),
    WideAnd(GF2, GF128, GF128, GF128),
}

#[derive(Debug)]
pub enum CircuitEvalError {
    CommunicatorError,
}

pub enum BooleanGate {
    And {
        wires: (usize, usize, usize),
        correlation: (GF2, GF2, GF2),
    },
    WideAnd {
        wires: (usize, [usize; 128], [usize; 128]),
        correlation: (GF2, GF128, GF128),
    },
    Xor(usize, usize, usize),
    Not(usize, usize),
}

pub struct SemiHonestCircuit {
    layers: Vec<Vec<BooleanGate>>,
    input_wires: usize,
    output_wires: usize,
}

#[derive(Clone, Copy)]
pub enum MultiPartyBeaverTriple {
    Regular(GF2, GF2, GF2),
    Wide(GF2, GF128, GF128),
}
pub fn gate_masks_from_seed(
    circuit: &ParsedCircuit,
    seed: [u8; 16],
) -> (Vec<(usize, usize, Mask)>, Vec<GF2>) {
    let total_gates: usize = circuit
        .gates
        .iter()
        .map(|layer| layer.iter().filter(|g| !g.is_linear()).count())
        .sum();
    let mut rng = AesRng::from_seed(seed);
    let mut gate_input_masks = Vec::with_capacity(total_gates);
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        for (gate_idx, gate) in layer.iter().enumerate() {
            let mask = match gate {
                ParsedGate::AndGate {
                    input: _,
                    output: _,
                } => Mask::And(GF2::random(&mut rng), GF2::random(&mut rng)),
                ParsedGate::WideAndGate {
                    input: _,
                    input_bit: _,
                    output: _,
                } => Mask::WideAnd(GF2::random(&mut rng), GF128::random(&mut rng)),
                _ => continue,
            };
            gate_input_masks.push((layer_idx, gate_idx, mask));
        }
    }
    let mut output_wire_masks = Vec::with_capacity(circuit.output_wire_count);
    for _ in 0..circuit.output_wire_count {
        output_wire_masks.push(GF2::random(&mut rng));
    }
    (gate_input_masks, output_wire_masks)
}
pub async fn create_multi_party_beaver_triples(
    engine: &mut impl MultiPartyEngine,
    circuit: &ParsedCircuit,
    pcg_correlations: &mut HashMap<PartyId, FullPcgKey>,
    gate_input_masks: &Vec<(usize, usize, Mask)>,
) -> HashMap<(usize, usize), MultiPartyBeaverTriple> {
    let my_id = engine.my_party_id();
    let peers: Vec<_> = engine
        .party_ids()
        .iter()
        .copied()
        .filter(|v| *v != my_id)
        .collect();
    let mut pairwise_beaver_triples = HashMap::new();
    let mut n_wise_beaver_triples = HashMap::new();
    gate_input_masks
        .iter()
        .copied()
        .for_each(|(layer_idx, gate_idx, mask)| {
            let gate = circuit.gates[layer_idx][gate_idx];
            match (gate, mask) {
                (
                    ParsedGate::AndGate {
                        input: _,
                        output: _,
                    },
                    Mask::And(x, y),
                ) => {
                    let xy = x * y;
                    let mut z = xy;
                    for party in peers.iter() {
                        let (a, b, c) = pcg_correlations
                            .get_mut(&party)
                            .unwrap()
                            .next_bit_beaver_triple();
                        engine.send((layer_idx, gate_idx, Mask::And(x - a, y - b)), *party);
                        z += c + y * (x - a) + (y - b) * a - xy;
                        pairwise_beaver_triples.insert((layer_idx, gate_idx, *party), a);
                    }
                    n_wise_beaver_triples.insert(
                        (layer_idx, gate_idx),
                        MultiPartyBeaverTriple::Regular(x, y, z),
                    );
                }
                (
                    ParsedGate::WideAndGate {
                        input: _,
                        input_bit: _,
                        output: _,
                    },
                    Mask::WideAnd(x, wy),
                ) => {
                    let xwy = wy * x;
                    let mut wz = xwy;
                    for party in peers.iter() {
                        let (a, wb, wc) = pcg_correlations
                            .get_mut(&party)
                            .unwrap()
                            .next_wide_beaver_triple();
                        engine.send((layer_idx, gate_idx, Mask::WideAnd(x - a, wy - wb)), *party);
                        wz += wc + wy * (x - a) + (wy - wb) * a - xwy;
                        pairwise_beaver_triples.insert((layer_idx, gate_idx, *party), a);
                    }
                    n_wise_beaver_triples.insert(
                        (layer_idx, gate_idx),
                        MultiPartyBeaverTriple::Wide(x, wy, wz),
                    );
                }
                _ => {}
            }
        });

    while !pairwise_beaver_triples.is_empty() {
        let ((layer_idx, gate_idx, opening), party): ((usize, usize, Mask), _) =
            engine.recv().await.unwrap();
        let a = pairwise_beaver_triples
            .remove(&(layer_idx, gate_idx, party))
            .unwrap();
        let beaver_triple = n_wise_beaver_triples
            .get_mut(&(layer_idx, gate_idx))
            .unwrap();
        match (opening, beaver_triple) {
            (Mask::And(xa, yb), MultiPartyBeaverTriple::Regular(_, y, z)) => {
                *z += xa * *y + yb * a;
            }
            (Mask::WideAnd(xa, wyb), MultiPartyBeaverTriple::Wide(_, wy, wz)) => {
                *wz += *wy * xa + wyb * a;
            }
            _ => panic!(),
        }
    }
    n_wise_beaver_triples
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum Mask {
    And(GF2, GF2),
    WideAnd(GF2, GF128),
}

impl AddAssign for Mask {
    fn add_assign(&mut self, rhs: Self) {
        match (self, rhs) {
            (Mask::And(s_a, s_b), Mask::And(r_a, r_b)) => {
                *s_a += r_a;
                *s_b += r_b;
            }
            (Mask::WideAnd(s_a, s_b), Mask::WideAnd(r_a, r_b)) => {
                *s_a += r_a;
                *s_b += r_b;
            }
            _ => panic!(),
        }
    }
}
impl Add for Mask {
    type Output = Mask;
    fn add(self, rhs: Self) -> Self::Output {
        let mut m = self.clone();
        m += rhs;
        m
    }
}

// We assume the input to the circuit is already additively shared between the parties.
pub async fn multi_party_semi_honest_eval_circuit<E: MultiPartyEngine>(
    engine: &mut E,
    circuit: &ParsedCircuit,
    pre_shared_input: Vec<GF2>,
    multi_party_beaver_triples: &HashMap<(usize, usize), MultiPartyBeaverTriple>,
    output_wire_masks: &Vec<GF2>,
) -> Result<(HashMap<(usize, usize), Mask>, Vec<GF2>), CircuitEvalError> {
    let my_id = engine.my_party_id();
    let min_id = engine
        .party_ids()
        .iter()
        .fold(PartyId::MAX, |a, b| PartyId::min(a, *b));
    let is_first = my_id == min_id;
    let number_of_peers = engine.party_ids().len() - 1;
    let wires_num =
        circuit.input_wire_count + circuit.internal_wire_count + circuit.output_wire_count;
    let mut wires = vec![GF2::zero(); wires_num];
    wires[0..circuit.input_wire_count].copy_from_slice(&pre_shared_input);
    let total_non_linear_gates: usize = circuit
        .gates
        .iter()
        .map(|layer| layer.iter().filter(|g| !g.is_linear()).count())
        .sum();
    let mut masked_output_wires = Vec::<GF2>::with_capacity(circuit.output_wire_count);
    let mut masked_gate_inputs = HashMap::<(usize, usize), Mask>::with_capacity(
        total_non_linear_gates + circuit.output_wire_count,
    );
    let max_layer_size = circuit.gates.iter().fold(0, |acc, cur| {
        let non_linear_gates_in_layer = cur.iter().filter(|cur| !cur.is_linear()).count();
        usize::max(acc, non_linear_gates_in_layer)
    });
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        let mut and_gates_processed = 0;
        for (gate_idx, gate) in layer.iter().enumerate() {
            match &gate {
                ParsedGate::NotGate { input, output } => {
                    wires[*output] = wires[*input];
                    if is_first {
                        wires[*output].flip();
                    }
                }
                ParsedGate::XorGate { input, output } => {
                    wires[*output] = wires[input[0]] + wires[input[1]];
                }
                ParsedGate::AndGate { input, output } => {
                    and_gates_processed += 1;
                    let (a, b, c) = match multi_party_beaver_triples
                        .get(&(layer_idx, gate_idx))
                        .unwrap()
                    {
                        MultiPartyBeaverTriple::Regular(a, b, c) => (*a, *b, *c),
                        _ => panic!(),
                    };

                    let (x, y) = (wires[input[0]], wires[input[1]]);
                    wires[*output] = c + y * (x - a) + (y - b) * a;
                    let msg = EvalMessage {
                        opening: Mask::And(x - a, y - b),
                        gate_idx_in_layer: gate_idx,
                    };
                    engine.broadcast(msg);
                    let mask = Mask::And(x - a, y - b);
                    assert!(masked_gate_inputs
                        .insert((layer_idx, gate_idx), mask)
                        .is_none());
                }
                ParsedGate::WideAndGate {
                    input,
                    input_bit,
                    output,
                } => {
                    and_gates_processed += 1;
                    let (a, wb, wc) = match multi_party_beaver_triples
                        .get(&(layer_idx, gate_idx))
                        .unwrap()
                    {
                        MultiPartyBeaverTriple::Wide(a, wb, wc) => (*a, *wb, *wc),
                        _ => panic!(),
                    };
                    let x = wires[*input_bit];
                    let mut wy = GF128::zero();
                    for i in 0..input.len() {
                        let input_wire = wires[input[i]];
                        wy.set_bit(input_wire.into(), i);
                    }
                    let wz = wc + wy * (x - a) + (wy - wb) * a;
                    for (idx, output_wire) in output.iter().enumerate() {
                        wires[*output_wire] = wz.get_bit(idx).into();
                    }
                    let msg = EvalMessage {
                        opening: Mask::WideAnd(x - a, wy - wb),
                        gate_idx_in_layer: gate_idx,
                    };
                    engine.broadcast(msg);
                    let masked_inputs = wy - wb;
                    let mask = Mask::WideAnd(x - a, wy - wb);
                    masked_gate_inputs.insert((layer_idx, gate_idx), mask);
                }
            }
        }
        for _ in 0..and_gates_processed * number_of_peers {
            let (msg, _): (EvalMessage, PartyId) = engine.recv().await.unwrap();
            let gate_idx = msg.gate_idx_in_layer;
            let beaver_triple = multi_party_beaver_triples
                .get(&(layer_idx, gate_idx))
                .unwrap();
            let gate = layer[gate_idx];
            let mask = masked_gate_inputs.get_mut(&(layer_idx, gate_idx)).unwrap();
            match (msg.opening, beaver_triple, gate, mask) {
                (
                    Mask::And(ax, by),
                    MultiPartyBeaverTriple::Regular(a, _, _),
                    ParsedGate::AndGate {
                        input: input_wires,
                        output: output_wire,
                    },
                    Mask::And(mask_a, mask_b),
                ) => {
                    let y = wires[input_wires[1]];
                    wires[output_wire] += y * ax + by * *a;
                    *mask_a += ax;
                    *mask_b += by;
                }
                (
                    Mask::WideAnd(ax, wby),
                    MultiPartyBeaverTriple::Wide(a, _, _),
                    ParsedGate::WideAndGate {
                        input,
                        input_bit,
                        output,
                    },
                    Mask::WideAnd(mask_a, mask_wb),
                ) => {
                    *mask_wb += wby;
                    *mask_a += ax;
                    for i in 0..output.len() {
                        let y = wires[input[i]];
                        wires[output[i]] += y * ax + GF2::from(wby.get_bit(i)) * *a;
                    }
                }
                _ => panic!(),
            }
        }
    }

    // Create a robust secret sharing of the output wires.
    for (i, (wire, mask)) in wires
        .iter()
        .skip(wires.len() - circuit.output_wire_count)
        .zip(output_wire_masks)
        .enumerate()
    {
        engine.broadcast((i, *wire - *mask));
        masked_output_wires.push(*wire - *mask);
    }

    for _ in 0..circuit.output_wire_count * number_of_peers {
        let ((wire_id, masked_val), _): ((usize, GF2), _) = engine.recv().await.unwrap();
        assert!(wire_id < output_wire_masks.len());
        masked_output_wires[wire_id] += masked_val;
    }

    Ok((masked_gate_inputs, masked_output_wires))
}

fn local_eval_circuit(circuit: &ParsedCircuit, input: &[GF2]) -> Vec<GF2> {
    debug_assert_eq!(input.len(), circuit.input_wire_count);
    let mut wires =
        vec![
            GF2::zero();
            circuit.input_wire_count + circuit.output_wire_count + circuit.internal_wire_count
        ];
    wires[0..circuit.input_wire_count].copy_from_slice(input);
    for layer in circuit.gates.iter() {
        for gate in layer {
            match gate {
                &ParsedGate::AndGate { input, output } => {
                    wires[output] = wires[input[0]] * wires[input[1]];
                }
                &ParsedGate::NotGate { input, output } => {
                    wires[output] = wires[input];
                    wires[output].flip();
                }
                &ParsedGate::XorGate { input, output } => {
                    wires[output] = wires[input[0]] + wires[input[1]];
                }
                &ParsedGate::WideAndGate {
                    input,
                    input_bit,
                    output,
                } => {
                    for i in 0..input.len() {
                        let input_bit_val = wires[input_bit];
                        wires[output[i]] = input_bit_val * wires[input[i]];
                    }
                }
            }
        }
    }
    // wires.drain(0..wires.len() - circuit.output_wire_count);
    wires
}
#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        ops::SubAssign,
        sync::Arc,
    };

    use futures::{future::try_join_all, FutureExt};
    use rand::{random, thread_rng, RngCore};

    use super::bristol_fashion::{parse_bristol, ParsedCircuit};
    use crate::{
        circuit_eval::{
            bristol_fashion::ParsedGate,
            semi_honest::{
                create_multi_party_beaver_triples, gate_masks_from_seed, local_eval_circuit,
                multi_party_semi_honest_eval_circuit, Mask, MultiPartyBeaverTriple,
            },
        },
        engine::{LocalRouter, MultiPartyEngine, PartyId},
        fields::{FieldElement, GF2},
        pcg::FullPcgKey,
        uc_tags::UCTag,
    };

    async fn gen_pairwise_pcg_keys<E: MultiPartyEngine>(
        engine: &E,
        pprf_count: usize,
        pprf_depth: usize,
        code_weight: usize,
        code_seed: [u8; 16],
    ) -> HashMap<PartyId, FullPcgKey> {
        let my_id = engine.my_party_id();
        let futures: Vec<_> = engine
            .party_ids()
            .iter()
            .copied()
            .filter(|i| *i != my_id)
            .map(|peer| {
                let tag = if peer < my_id {
                    UCTag::new(&"PCG").derive(peer).derive(my_id)
                } else {
                    UCTag::new(&"PCG").derive(my_id).derive(peer)
                };
                let b: Box<[PartyId]> = Box::new([peer, my_id]);
                let peer_arc = Arc::from(b);
                FullPcgKey::new(
                    engine.sub_protocol_with(tag, peer_arc),
                    pprf_count,
                    pprf_depth,
                    code_seed,
                    code_weight,
                )
                .map(move |v| v.map(move |vv| (peer, vv)))
            })
            .collect();
        try_join_all(futures).await.unwrap().into_iter().collect()
    }
    async fn test_circuit(circuit: ParsedCircuit, input: &[GF2], party_count: usize) -> Vec<GF2> {
        const PPRF_COUNT: usize = 44;
        const CODE_WEIGHT: usize = 8;
        const PPRF_DEPTH: usize = 5;
        const CODE_SEED: [u8; 16] = [1u8; 16];
        assert_eq!(input.len(), circuit.input_wire_count);
        let party_ids: Vec<_> = (1..=party_count).map(|i| i as u64).collect();
        let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
        let (local_router, mut execs) = LocalRouter::new(UCTag::new(&"root_tag"), &party_ids_set);
        let router_handle = tokio::spawn(local_router.launch());

        let pcg_keys_futures = execs.iter().map(|(pid, engine)| {
            gen_pairwise_pcg_keys(engine, PPRF_COUNT, PPRF_DEPTH, CODE_WEIGHT, CODE_SEED)
                .map(move |v| Result::<_, ()>::Ok((*pid, v)))
        });

        let mut pcg_keys: HashMap<_, _> = try_join_all(pcg_keys_futures)
            .await
            .unwrap()
            .into_iter()
            .collect();

        let first_id = party_ids[0];
        let mut first_id_input = input.to_vec();
        let mut rng = thread_rng();

        let mut inputs: HashMap<_, _> = party_ids[1..]
            .iter()
            .copied()
            .map(|id| {
                let id_input: Vec<GF2> = first_id_input
                    .iter_mut()
                    .map(|v| {
                        let r = GF2::random(&mut rng);
                        v.sub_assign(r);
                        r
                    })
                    .collect();
                (id, id_input)
            })
            .collect();
        inputs.insert(first_id, first_id_input);
        let mut wire_masks = HashMap::<PartyId, Vec<(usize, usize, Mask)>>::new();
        let mut output_wire_masks = HashMap::<PartyId, Vec<GF2>>::new();
        for id in party_ids.iter().copied() {
            let seed = core::array::from_fn(|_| (rng.next_u32() & 255) as u8);
            let (wire_masks_for_party, outputs_masks) = gate_masks_from_seed(&circuit, seed);
            wire_masks.insert(id, wire_masks_for_party);
            output_wire_masks.insert(id, outputs_masks);
        }
        let engine_futures = pcg_keys.iter_mut().map(|(&id, pcg_key)| {
            let circuit = circuit.clone();
            let mut engine = execs.get(&id).unwrap().sub_protocol("MULTIPARTY BEAVER");
            let wires_mask = wire_masks.remove(&id).unwrap();
            async move {
                let circuit = circuit.clone();
                Result::<_, ()>::Ok((
                    id,
                    create_multi_party_beaver_triples(&mut engine, &circuit, pcg_key, &wires_mask)
                        .await,
                ))
            }
        });
        let exec_results = try_join_all(engine_futures).await.unwrap();
        let mut corr_sums = HashMap::clone(&exec_results[0].1);
        exec_results.iter().skip(1).for_each(|(_, v)| {
            v.iter().for_each(|((layer_idx, gate_idx), bt)| {
                let current = corr_sums.get_mut(&(*layer_idx, *gate_idx)).unwrap();
                match (current, bt) {
                    (
                        MultiPartyBeaverTriple::Regular(cur_a, cur_b, cur_c),
                        MultiPartyBeaverTriple::Regular(bt_a, bt_b, bt_c),
                    ) => {
                        *cur_a += *bt_a;
                        *cur_b += *bt_b;
                        *cur_c += *bt_c;
                    }
                    (
                        MultiPartyBeaverTriple::Wide(cur_a, cur_b, cur_c),
                        MultiPartyBeaverTriple::Wide(bt_a, bt_b, bt_c),
                    ) => {
                        *cur_a += *bt_a;
                        *cur_b += *bt_b;
                        *cur_c += *bt_c;
                    }
                    _ => panic!(),
                }
            })
        });
        for v in corr_sums.values() {
            match v {
                MultiPartyBeaverTriple::Regular(a, b, c) => {
                    assert_eq!(*a * *b, *c);
                }
                MultiPartyBeaverTriple::Wide(a, b, c) => {
                    assert_eq!(*b * *a, *c);
                }
            }
        }

        let engine_futures = exec_results.into_iter().map(|(id, n_party_correlation)| {
            let output_wire_count = circuit.output_wire_count;
            let mut engine = execs.remove(&id).unwrap();
            let circuit = circuit.clone();
            let input = inputs.remove(&id).unwrap();
            let output_wire_masks: Vec<_> = output_wire_masks.remove(&id).unwrap();
            async move {
                let n_party_correlation = n_party_correlation;
                multi_party_semi_honest_eval_circuit(
                    &mut engine,
                    &circuit,
                    input,
                    &n_party_correlation,
                    &output_wire_masks,
                )
                .await
                .map(|(masked_gate_inputs, masked_outputs)| {
                    (
                        masked_gate_inputs,
                        masked_outputs,
                        output_wire_masks,
                        n_party_correlation,
                    )
                })
            }
        });

        let exec_results = try_join_all(engine_futures).await.unwrap();
        let local_computation_wires = local_eval_circuit(&circuit, input);
        let mut local_computation_output = local_computation_wires
            [local_computation_wires.len() - circuit.output_wire_count..]
            .to_vec();
        let output = local_computation_output.clone();

        // Ensure output wires are of correct length.
        for e in exec_results.iter() {
            assert_eq!(e.1.len(), local_computation_output.len());
        }
        assert_eq!(local_computation_output.len(), circuit.output_wire_count);
        exec_results.iter().for_each(|e| {
            e.2.iter()
                .zip(local_computation_output.iter_mut())
                .for_each(|(ei, li)| li.sub_assign(*ei));
        });
        router_handle.await.unwrap().unwrap();

        // Check Computation is Correct
        for j in 0..exec_results.len() {
            for i in 0..circuit.output_wire_count {
                assert_eq!(local_computation_output[i], exec_results[j].1[i]);
            }
        }

        // Check the per-gate masks are correct.
        for (k, v) in exec_results[0].0.iter() {
            for i in 1..exec_results.len() {
                assert_eq!(exec_results[i].0.get(k).unwrap(), v);
            }
            let gate = circuit.gates[k.0][k.1];
            let corr = corr_sums.get(k).unwrap();
            match (gate, corr, v) {
                (
                    ParsedGate::AndGate { input, output },
                    MultiPartyBeaverTriple::Regular(a, b, c),
                    Mask::And(mask_a, mask_b),
                ) => {
                    assert_eq!(*a + *mask_a, local_computation_wires[input[0]]);
                    assert_eq!(*b + *mask_b, local_computation_wires[input[1]]);
                }
                (
                    ParsedGate::WideAndGate {
                        input,
                        input_bit,
                        output,
                    },
                    MultiPartyBeaverTriple::Wide(a, wb, wc),
                    Mask::WideAnd(mask_a, mask_wb),
                ) => {
                    assert_eq!(*mask_a + *a, local_computation_wires[input_bit]);
                    let full_b = *wb + *mask_wb;
                    for i in 0..input.len() {
                        assert_eq!(
                            GF2::from(full_b.get_bit(i)),
                            local_computation_wires[input[i]]
                        )
                    }
                }
                _ => panic!(),
            }
        }
        output
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn test_small_circuit() {
        let logical_or_circuit = [
            "4 6",
            "2 1 1",
            "1 1",
            "",
            "1 1 0 2 INV",
            "1 1 1 3 INV",
            "2 1 2 3 4 AND",
            "1 1 4 5 INV",
        ];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");

        // Test classical eval.
        assert_eq!(
            *local_eval_circuit(&parsed_circuit, &[GF2::one(), GF2::one()])
                .last()
                .unwrap(),
            GF2::one()
        );
        assert_eq!(
            *local_eval_circuit(&parsed_circuit, &[GF2::zero(), GF2::one()])
                .last()
                .unwrap(),
            GF2::one()
        );
        assert_eq!(
            *local_eval_circuit(&parsed_circuit, &[GF2::one(), GF2::zero()])
                .last()
                .unwrap(),
            GF2::one()
        );
        assert_eq!(
            *local_eval_circuit(&parsed_circuit, &[GF2::zero(), GF2::zero()])
                .last()
                .unwrap(),
            GF2::zero()
        );

        let input = vec![GF2::one(), GF2::zero()];
        let output = test_circuit(parsed_circuit, &input, 7).await;

        assert_eq!(output[0], GF2::one());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn test_wide_and() {
        let logical_or_circuit = [
            "1 257",
            "2 128 1",
            "1 128",
            "",
            "129 128 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203 204 205 206 207 208 209 210 211 212 213 214 215 216 217 218 219 220 221 222 223 224 225 226 227 228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255 256 wAND",
        ];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");

        let mut input = [GF2::one(); 129];
        // Test classical eval.
        let eval = local_eval_circuit(&parsed_circuit, &input[..]);

        assert_eq!(
            eval[eval.len() - parsed_circuit.output_wire_count..].to_vec(),
            Vec::from_iter(input[1..].iter().cloned())
        );

        input[0] = GF2::zero();

        let eval = local_eval_circuit(&parsed_circuit, &input[..]);
        assert_eq!(
            eval[eval.len() - parsed_circuit.output_wire_count..].to_vec(),
            vec![GF2::zero(); 128]
        );

        let input = vec![GF2::one(); 129];
        let output = test_circuit(parsed_circuit, &input, 7).await;

        assert_eq!(output, vec![GF2::one(); 128]);
    }
}
