use super::bristol_fashion;
use std::collections::HashMap;
use std::fmt::Debug;

use aes_prng::AesRng;
use blake3::Hash;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

use crate::circuit_eval::bristol_fashion::ParsedGate;
use crate::engine::{MultiPartyEngine, PartyId};
use crate::fields::{FieldElement, GF128, GF2};
use crate::pcg::{self, FullPcgKey};

use self::bristol_fashion::ParsedCircuit;

#[derive(Serialize, Deserialize, Debug)]
enum GateOpening {
    And(GF2, GF2),
    WideAnd(GF2, GF128),
}

#[derive(Serialize, Deserialize)]
struct EvalMessage {
    pub opening: GateOpening,
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

async fn create_multi_party_beaver_triples(
    mut engine: impl MultiPartyEngine,
    circuit: &ParsedCircuit,
    pcg_correlations: &mut HashMap<PartyId, FullPcgKey>,
    randomness_seed: [u8; 16],
) -> HashMap<(usize, usize), MultiPartyBeaverTriple> {
    let my_id = engine.my_party_id();
    let peers: Vec<_> = engine
        .party_ids()
        .iter()
        .copied()
        .filter(|v| *v != my_id)
        .collect();
    let mut prg = AesRng::from_seed(randomness_seed);
    let mut pairwise_beaver_triples = HashMap::new();
    let mut n_wise_beaver_triples = HashMap::new();
    circuit
        .gates
        .iter()
        .enumerate()
        .for_each(|(layer_idx, layer)| {
            layer
                .iter()
                .enumerate()
                .for_each(|(gate_idx, gate)| match gate {
                    ParsedGate::AndGate {
                        input: _,
                        output: _,
                    } => {
                        let x = GF2::random(&mut prg);
                        let y = GF2::random(&mut prg);
                        let xy = x * y;
                        let mut z = xy;
                        for party in peers.iter() {
                            let (a, b, c) = pcg_correlations
                                .get_mut(&party)
                                .unwrap()
                                .next_bit_beaver_triple();
                            engine.send(
                                (layer_idx, gate_idx, GateOpening::And(x - a, y - b)),
                                *party,
                            );
                            z += c + y * (x - a) + (y - b) * a - xy;
                            pairwise_beaver_triples.insert((layer_idx, gate_idx, *party), a);
                        }
                        n_wise_beaver_triples.insert(
                            (layer_idx, gate_idx),
                            MultiPartyBeaverTriple::Regular(x, y, z),
                        );
                    }
                    ParsedGate::WideAndGate {
                        input: _,
                        input_bit: _,
                        output: _,
                    } => {
                        let x = GF2::random(&mut prg);
                        let wy = GF128::random(&mut prg);
                        let xwy = wy * x;
                        let mut wz = xwy;
                        for party in peers.iter() {
                            let (a, wb, wc) = pcg_correlations
                                .get_mut(&party)
                                .unwrap()
                                .next_wide_beaver_triple();
                            engine.send(
                                (layer_idx, gate_idx, GateOpening::WideAnd(x - a, wy - wb)),
                                *party,
                            );
                            wz += wc + wy * (x - a) + (wy - wb) * a - xwy;
                            pairwise_beaver_triples.insert((layer_idx, gate_idx, *party), a);
                        }
                        n_wise_beaver_triples.insert(
                            (layer_idx, gate_idx),
                            MultiPartyBeaverTriple::Wide(x, wy, wz),
                        );
                    }
                    _ => {}
                })
        });

    while !pairwise_beaver_triples.is_empty() {
        let ((layer_idx, gate_idx, opening), party): ((usize, usize, GateOpening), _) =
            engine.recv().await.unwrap();
        let a = pairwise_beaver_triples
            .remove(&(layer_idx, gate_idx, party))
            .unwrap();
        let beaver_triple = n_wise_beaver_triples
            .get_mut(&(layer_idx, gate_idx))
            .unwrap();
        match (opening, beaver_triple) {
            (GateOpening::And(xa, yb), MultiPartyBeaverTriple::Regular(_, y, z)) => {
                *z += xa * *y + yb * a;
            }
            (GateOpening::WideAnd(xa, wyb), MultiPartyBeaverTriple::Wide(_, wy, wz)) => {
                *wz += *wy * xa + wyb * a;
            }
            _ => panic!(),
        }
    }
    n_wise_beaver_triples
}

// We assume the input to the circuit is already additively shared between the parties.
pub async fn multi_party_semi_honest_eval_circuit<E: MultiPartyEngine>(
    mut engine: E,
    circuit: ParsedCircuit,
    pre_shared_input: Vec<GF2>,
    multi_party_beaver_triples: HashMap<(usize, usize), MultiPartyBeaverTriple>,
    output_wire_masks: HashMap<usize, GF2>,
) -> Result<(Vec<GF2>, HashMap<usize, GF2>, HashMap<usize, GF2>), CircuitEvalError> {
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
    let mut wire_mask_shares = output_wire_masks;
    wire_mask_shares.reserve(total_non_linear_gates);
    let mut wire_masked_values =
        HashMap::<usize, GF2>::with_capacity(total_non_linear_gates + circuit.output_wire_count);
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
                    wire_mask_shares.insert(input[0], a);
                    wire_mask_shares.insert(input[1], b);

                    let (x, y) = (wires[input[0]], wires[input[1]]);
                    wires[*output] = c + y * (x - a) + (y - b) * a;
                    let msg = EvalMessage {
                        opening: GateOpening::And(x - a, y - b),
                        gate_idx_in_layer: gate_idx,
                    };
                    engine.broadcast(msg);
                    assert!(wire_masked_values.insert(input[0], x - a).is_none());
                    assert!(wire_masked_values.insert(input[1], y - b).is_none());
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
                    assert!(wire_mask_shares.insert(*input_bit, a).is_none());
                    for i in 0..input.len() {
                        let input_wire = wires[input[i]];
                        wire_mask_shares.insert(input[i], GF2::from(wb.get_bit(i)));
                        wy.set_bit(input_wire.into(), i);
                    }
                    let wz = wc + wy * (x - a) + (wy - wb) * a;
                    for (idx, output_wire) in output.iter().enumerate() {
                        wires[*output_wire] = wz.get_bit(idx).into();
                    }
                    let msg = EvalMessage {
                        opening: GateOpening::WideAnd(x - a, wy - wb),
                        gate_idx_in_layer: gate_idx,
                    };
                    engine.broadcast(msg);
                    let masked_inputs = wy - wb;
                    for (input_wire_idx, input_wire) in input.iter().enumerate() {
                        wire_masked_values
                            .insert(*input_wire, masked_inputs.get_bit(input_wire_idx).into());
                    }
                    wire_masked_values.insert(*input_bit, x - a);
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
            match (msg.opening, beaver_triple, gate) {
                (
                    GateOpening::And(ax, by),
                    MultiPartyBeaverTriple::Regular(a, _, _),
                    ParsedGate::AndGate {
                        input: input_wires,
                        output: output_wire,
                    },
                ) => {
                    let y = wires[input_wires[1]];
                    wires[output_wire] += y * ax + by * *a;
                    *wire_masked_values.get_mut(&input_wires[0]).unwrap() += ax;
                    *wire_masked_values.get_mut(&input_wires[1]).unwrap() += by;
                }
                (
                    GateOpening::WideAnd(ax, wby),
                    MultiPartyBeaverTriple::Wide(a, _, _),
                    ParsedGate::WideAndGate {
                        input,
                        input_bit,
                        output,
                    },
                ) => {
                    for (input_wire_idx, input_wire) in input.iter().enumerate() {
                        *wire_masked_values.get_mut(input_wire).unwrap() +=
                            GF2::from(wby.get_bit(input_wire_idx));
                    }
                    *wire_masked_values.get_mut(&input_bit).unwrap() += ax;
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
    for (i, wire) in wires
        .iter()
        .enumerate()
        .skip(wires.len() - circuit.output_wire_count)
    {
        let mask = wire_mask_shares.get(&i).unwrap();
        engine.broadcast((i, *wire - *mask));
        wire_masked_values.insert(i, *wire - *mask);
    }

    for _ in 0..circuit.output_wire_count * number_of_peers {
        let ((wire_id, masked_val), _): ((usize, GF2), _) = engine.recv().await.unwrap();
        assert!(wires.len() - circuit.output_wire_count <= wire_id && wire_id < wires.len());
        *wire_masked_values.get_mut(&wire_id).unwrap() += masked_val;
    }

    Ok((
        wires[wires.len() - circuit.output_wire_count..].to_vec(),
        wire_masked_values,
        wire_mask_shares,
    ))
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
        ops::{Mul, SubAssign},
        sync::Arc,
    };

    use futures::{future::try_join_all, FutureExt};
    use rand::{random, thread_rng};

    use super::bristol_fashion::{parse_bristol, ParsedCircuit};
    use crate::{
        circuit_eval::semi_honest::{
            create_multi_party_beaver_triples, local_eval_circuit,
            multi_party_semi_honest_eval_circuit, MultiPartyBeaverTriple,
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
        let engine_futures = pcg_keys.iter_mut().map(|(&id, pcg_key)| {
            let circuit = circuit.clone();
            let engine = execs.get(&id).unwrap().sub_protocol("MULTIPARTY BEAVER");
            async move {
                let random_seed = core::array::from_fn(|_| random());
                let circuit = circuit.clone();
                Result::<_, ()>::Ok((
                    id,
                    create_multi_party_beaver_triples(engine, &circuit, pcg_key, random_seed).await,
                ))
            }
        });
        let exec_results = try_join_all(engine_futures).await.unwrap();
        let mut cloned = HashMap::clone(&exec_results[0].1);
        exec_results.iter().skip(1).for_each(|(_, v)| {
            v.iter().for_each(|((layer_idx, gate_idx), bt)| {
                let current = cloned.get_mut(&(*layer_idx, *gate_idx)).unwrap();
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
        for v in cloned.values() {
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
            let output_wire_masks: HashMap<_, _> = (circuit.input_wire_count
                + circuit.internal_wire_count
                ..circuit.input_wire_count
                    + circuit.internal_wire_count
                    + circuit.output_wire_count)
                .map(|i| (i, GF2::random(&mut rng)))
                .collect();
            multi_party_semi_honest_eval_circuit(
                execs.remove(&id).unwrap(),
                circuit.clone(),
                inputs.remove(&id).unwrap(),
                n_party_correlation,
                output_wire_masks,
            )
        });

        let exec_results = try_join_all(engine_futures).await.unwrap();
        let mut local_computation_wires = local_eval_circuit(&circuit, input);
        let mut local_computation_output = local_computation_wires
            [local_computation_wires.len() - circuit.output_wire_count..]
            .to_vec();
        let output = local_computation_output.clone();
        for e in exec_results.iter() {
            assert_eq!(e.0.len(), local_computation_output.len());
        }
        assert_eq!(local_computation_output.len(), circuit.output_wire_count);
        exec_results.iter().for_each(|e| {
            e.0.iter()
                .zip(local_computation_output.iter_mut())
                .for_each(|(ei, li)| li.sub_assign(*ei));
        });
        router_handle.await.unwrap().unwrap();

        // Check Computation is Correct
        for i in 0..circuit.output_wire_count {
            assert_eq!(local_computation_output[i], GF2::zero());
        }

        for e in exec_results.iter() {
            for (wire_idx, wire_mask_share) in e.2.iter() {
                local_computation_wires[*wire_idx] += *wire_mask_share;
            }
        }
        for i in 1..exec_results.len() {
            for (wire_idx, wire_masked_value) in exec_results[i].1.iter() {
                assert_eq!(exec_results[0].1[wire_idx], *wire_masked_value);
            }
        }
        for e in exec_results.iter() {
            for (wire_idx, wire_masked_value) in e.1.iter() {
                assert_eq!(local_computation_wires[*wire_idx], *wire_masked_value);
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
