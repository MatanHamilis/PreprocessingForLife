pub mod bristol_fashion;
// mod gates;

use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Mul;

use serde::{Deserialize, Serialize};

use crate::circuit_eval::bristol_fashion::ParsedGate;
use crate::engine::{MultiPartyEngine, PartyId};
use crate::fields::{FieldElement, GF128, GF2};
use crate::pcg::FullPcgKey;

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
// We assume the input to the circuit is already additively shared between the parties.
pub async fn multi_party_semi_honest_eval_circuit<E: MultiPartyEngine>(
    mut engine: E,
    circuit: ParsedCircuit,
    input: Vec<GF2>,
    correlations: &mut HashMap<PartyId, FullPcgKey>,
) -> Result<Vec<GF2>, CircuitEvalError> {
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
    wires[0..circuit.input_wire_count].copy_from_slice(&input);
    let max_layer_size = circuit.gates.iter().fold(0, |acc, cur| {
        let non_linear_gates_in_layer = cur.iter().filter(|cur| !cur.is_linear()).count();
        usize::max(acc, non_linear_gates_in_layer)
    });
    let mut gate_eval_states = HashMap::with_capacity(max_layer_size * number_of_peers);
    for layer in circuit.gates {
        for (idx, gate) in layer.iter().enumerate() {
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
                    let (input_0, input_1) = (wires[input[0]], wires[input[1]]);
                    wires[*output] = input_0 * input_1;
                    correlations.iter_mut().for_each(|(pid, pcg)| {
                        let (a, b, c) = pcg.next_bit_beaver_triple();
                        let msg = EvalMessage {
                            opening: GateOpening::And(input_0 + a, input_1 + b),
                            gate_idx_in_layer: idx,
                        };
                        engine.send(msg, *pid); // Requires p2p-secret-channels?
                        gate_eval_states.insert((idx, *pid), GateEvalState::And(a, b, c));
                    });
                }
                ParsedGate::WideAndGate {
                    input,
                    input_bit,
                    output,
                } => {
                    let common_input = wires[*input_bit];
                    correlations.iter_mut().for_each(|(pid, pcg)| {
                        let mut wide_input_field = GF128::zero();
                        for i in 0..input.len() {
                            let input_wire = wires[input[i]];
                            wires[output[i]] = input_wire * common_input;
                            wide_input_field.set_bit(input_wire.into(), i);
                        }
                        let (a, wb, wc) = pcg.next_wide_beaver_triple();
                        let msg = EvalMessage {
                            opening: GateOpening::WideAnd(
                                a + wires[*input_bit],
                                wb + wide_input_field,
                            ),
                            gate_idx_in_layer: idx,
                        };
                        engine.send(msg, *pid);
                        assert!(gate_eval_states
                            .insert(
                                (idx, *pid),
                                GateEvalState::WideAnd(a, wb, wc, wide_input_field),
                            )
                            .is_none());
                    });
                }
            }
        }
        for _ in 0..gate_eval_states.len() {
            let (msg, from): (EvalMessage, PartyId) = engine.recv().await.unwrap();
            let gate_idx = msg.gate_idx_in_layer;
            match msg.opening {
                GateOpening::And(ax, by) => {
                    let (input_wires, output_wire) = match layer[gate_idx] {
                        ParsedGate::AndGate { input, output } => (input, output),
                        _ => {
                            return Err(CircuitEvalError::CommunicatorError);
                        }
                    };
                    let (a, b, c) = match gate_eval_states.get(&(gate_idx, from)).unwrap() {
                        &GateEvalState::And(a, b, c) => (a, b, c),
                        _ => return Err(CircuitEvalError::CommunicatorError),
                    };
                    let x_share = wires[input_wires[0]];
                    let y_share = wires[input_wires[1]];
                    let a_plus_x = ax + x_share + a;
                    let b_plus_y = by + y_share + b;
                    wires[output_wire] += b_plus_y * x_share - b * a_plus_x + c - x_share * y_share;
                }
                GateOpening::WideAnd(ax, wby) => {
                    let (_, input_bit_wire, output_wire) = match layer[gate_idx] {
                        ParsedGate::WideAndGate {
                            input,
                            input_bit,
                            output,
                        } => (input, input_bit, output),
                        _ => {
                            return Err(CircuitEvalError::CommunicatorError);
                        }
                    };
                    let (a, wb, wc, preprocessed_input) =
                        match gate_eval_states.get(&(gate_idx, from)).unwrap() {
                            &GateEvalState::WideAnd(a, wb, wc, preprocessed_input) => {
                                (a, wb, wc, preprocessed_input)
                            }
                            _ => return Err(CircuitEvalError::CommunicatorError),
                        };
                    let x_share = wires[input_bit_wire];
                    let a_plus_x = ax + x_share + a;
                    let b_plus_y = wby + preprocessed_input + wb;
                    let output_share =
                        b_plus_y * x_share - wb * a_plus_x + wc - preprocessed_input * x_share;
                    for i in 0..output_wire.len() {
                        wires[output_wire[i]] += GF2::from(output_share.get_bit(i));
                    }
                }
            }
        }
        gate_eval_states.clear()
    }
    Ok(wires[wires.len() - circuit.output_wire_count..].to_vec())
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
    wires.drain(0..wires.len() - circuit.output_wire_count);
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
    use rand::thread_rng;

    use super::bristol_fashion::{parse_bristol, ParsedCircuit};
    use crate::{
        circuit_eval::{local_eval_circuit, multi_party_semi_honest_eval_circuit},
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
        const PPRF_COUNT: usize = 50;
        const CODE_WEIGHT: usize = 8;
        const PPRF_DEPTH: usize = 10;
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

        let exec_futures = pcg_keys.iter_mut().map(|(&id, pcg_key)| {
            multi_party_semi_honest_eval_circuit(
                execs.remove(&id).unwrap(),
                circuit.clone(),
                inputs.remove(&id).unwrap(),
                pcg_key,
            )
        });

        let exec_results = try_join_all(exec_futures).await.unwrap();
        let mut local_computation_output = local_eval_circuit(&circuit, input);
        let output = local_computation_output.clone();
        for e in exec_results.iter() {
            assert_eq!(e.len(), local_computation_output.len());
        }
        assert_eq!(local_computation_output.len(), circuit.output_wire_count);
        exec_results.iter().for_each(|e| {
            e.iter()
                .zip(local_computation_output.iter_mut())
                .for_each(|(ei, li)| li.sub_assign(*ei));
        });
        router_handle.await.unwrap().unwrap();
        for i in 0..circuit.output_wire_count {
            assert_eq!(local_computation_output[i], GF2::zero());
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
            local_eval_circuit(&parsed_circuit, &[GF2::one(), GF2::one()]),
            vec![GF2::one()]
        );
        assert_eq!(
            local_eval_circuit(&parsed_circuit, &[GF2::zero(), GF2::one()]),
            vec![GF2::one()]
        );
        assert_eq!(
            local_eval_circuit(&parsed_circuit, &[GF2::one(), GF2::zero()]),
            vec![GF2::one()]
        );
        assert_eq!(
            local_eval_circuit(&parsed_circuit, &[GF2::zero(), GF2::zero()]),
            vec![GF2::zero()]
        );

        let input = vec![GF2::one(), GF2::zero()];
        let output = test_circuit(parsed_circuit, &input, 10).await;

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
        assert_eq!(
            local_eval_circuit(&parsed_circuit, &input[..]),
            Vec::from_iter(input[1..].iter().cloned())
        );

        input[0] = GF2::zero();

        assert_eq!(
            local_eval_circuit(&parsed_circuit, &input[..]),
            vec![GF2::zero(); 128]
        );

        let input = vec![GF2::one(); 129];
        let output = test_circuit(parsed_circuit, &input, 10).await;

        assert_eq!(output, vec![GF2::one(); 128]);
    }
}
