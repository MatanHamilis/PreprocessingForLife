use super::bristol_fashion;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::{Add, AddAssign};
use std::time::Instant;

use aes_prng::AesRng;
use async_trait::async_trait;
use rand::{CryptoRng, RngCore, SeedableRng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::circuit_eval::bristol_fashion::ParsedGate;
use crate::engine::{MultiPartyEngine, PartyId};
use crate::fields::{FieldElement, PackedField, GF128, GF2};
use crate::pcg::{FullPcgKey, PackedOfflineFullPcgKey, RegularBeaverTriple, WideBeaverTriple};

const PPRF_COUNT: usize = 44;
const PPRF_DEPTH: usize = 5;
const CODE_WEIGHT: usize = 8;

#[async_trait]
pub trait OfflineSemiHonestCorrelation<CF: FieldElement>: Serialize + DeserializeOwned {
    fn get_personal_circuit_input_wires_masks(&self) -> &[CF];
    fn get_circuit_input_wires_masks_shares(&self, circuit: &ParsedCircuit) -> Vec<CF>;
    fn get_circuit_output_wires_masks_shares(&self, circuit: &ParsedCircuit) -> Vec<CF>;
    fn get_gates_input_wires_masks(
        &self,
        circuit: &ParsedCircuit,
    ) -> Vec<((usize, usize), Mask<CF>)>;
    fn deal<R: CryptoRng + RngCore>(
        rng: &mut R,
        parties_input_start_and_lengths: &HashMap<PartyId, (usize, usize)>,
        circuit: &ParsedCircuit,
    ) -> (Vec<CF>, Vec<CF>, Vec<(PartyId, Self)>);
    /// This method may optionally be called in a pre-online phase to same computation time in the online phase itself.
    fn pre_online_phase_preparation(&mut self, circuit: &ParsedCircuit);
    /// This method is called in the online phase to obtain the semi honest correlation.
    async fn get_multiparty_beaver_triples(
        &mut self,
        engine: &mut impl MultiPartyEngine,
        circuit: &ParsedCircuit,
    ) -> HashMap<(usize, usize), BeaverTriple<CF>>;
}

#[derive(Serialize, Deserialize)]
pub struct PcgBasedPairwiseBooleanCorrelation<const N: usize, F: PackedField<GF2, N>> {
    #[serde(bound = "")]
    pub input_wires_masks: Vec<F>,
    pub shares_seed: [u8; 16],
    pub pcg_keys: Vec<(PartyId, (PackedOfflineFullPcgKey, [u8; 16]))>,
    #[serde(bound = "")]
    pub expanded_pcg_keys: Option<Vec<((usize, usize), PairwiseBeaverTriple<F>)>>,
}

#[async_trait]
impl<const N: usize, F: PackedField<GF2, N>> OfflineSemiHonestCorrelation<F>
    for PcgBasedPairwiseBooleanCorrelation<N, F>
{
    fn get_personal_circuit_input_wires_masks(&self) -> &[F] {
        &self.input_wires_masks
    }
    fn get_circuit_input_wires_masks_shares(&self, circuit: &ParsedCircuit) -> Vec<F> {
        input_wires_masks_from_seed(self.shares_seed, circuit)
    }
    fn pre_online_phase_preparation(&mut self, circuit: &ParsedCircuit) {
        let m = expand_pairwise_beaver_triples::<N, CODE_WEIGHT, F>(circuit, &mut self.pcg_keys);
        self.expanded_pcg_keys = Some(m);
    }

    // Only called by the dealer anyway.
    fn get_gates_input_wires_masks(
        &self,
        circuit: &ParsedCircuit,
    ) -> Vec<((usize, usize), Mask<F>)> {
        let m = expand_pairwise_beaver_triples::<N, CODE_WEIGHT, F>(circuit, &self.pcg_keys);
        // If there are only two parties...
        if self.pcg_keys.len() == 1 {
            return m
                .iter()
                .map(|(g, bts)| {
                    let bt = match bts {
                        PairwiseBeaverTriple::Regular(v) => Mask::And(v[0].1 .0, v[0].1 .1),
                        PairwiseBeaverTriple::Wide(v) => Mask::WideAnd(v[0].1 .0, v[0].1 .1),
                    };
                    (*g, bt)
                })
                .collect();
        }
        gate_masks_from_seed(circuit, self.shares_seed)
    }
    async fn get_multiparty_beaver_triples(
        &mut self,
        engine: &mut impl MultiPartyEngine,
        circuit: &ParsedCircuit,
    ) -> HashMap<(usize, usize), BeaverTriple<F>> {
        // If the preparation has not been done earlier, do it now.
        if self.expanded_pcg_keys.is_none() {
            self.pre_online_phase_preparation(circuit);
        }
        let pairwise_triples = self.expanded_pcg_keys.take().unwrap();

        // If only two parties - expansion is silent.
        if engine.party_ids().len() == 2 {
            return pairwise_triples
                .iter()
                .map(|(g, bts)| {
                    let bt = match bts {
                        PairwiseBeaverTriple::Regular(v) => BeaverTriple::Regular(v[0].1),
                        PairwiseBeaverTriple::Wide(v) => BeaverTriple::Wide(v[0].1),
                    };
                    (*g, bt)
                })
                .collect();
        }

        // Otherwise, we have to communicate.
        let gate_input_masks = gate_masks_from_seed(circuit, self.shares_seed);
        create_multi_party_beaver_triples(engine, circuit, &pairwise_triples, &gate_input_masks)
            .await
    }
    fn get_circuit_output_wires_masks_shares(&self, circuit: &ParsedCircuit) -> Vec<F> {
        output_wires_masks_from_seed(self.shares_seed, circuit)
    }
    fn deal<R: CryptoRng + RngCore>(
        mut rng: &mut R,
        parties_input_start_and_lengths: &HashMap<PartyId, (usize, usize)>,
        circuit: &ParsedCircuit,
    ) -> (Vec<F>, Vec<F>, Vec<(PartyId, Self)>) {
        let parties_count = parties_input_start_and_lengths.len();
        let mut pcg_keys = HashMap::with_capacity(parties_count);
        for (i, i_pid) in parties_input_start_and_lengths.keys().copied().enumerate() {
            pcg_keys.insert(i_pid, Vec::with_capacity(parties_count - 1));
            for j_pid in parties_input_start_and_lengths.keys().copied().take(i) {
                let mut pcg_code_seed = [0u8; 16];
                rng.fill_bytes(&mut pcg_code_seed);
                let (snd, rcv) = PackedOfflineFullPcgKey::deal(PPRF_COUNT, PPRF_DEPTH, &mut rng);
                pcg_keys
                    .get_mut(&j_pid)
                    .unwrap()
                    .push((i_pid, (snd, pcg_code_seed)));
                pcg_keys
                    .get_mut(&i_pid)
                    .unwrap()
                    .push((j_pid, (rcv, pcg_code_seed)));
            }
        }
        let mut total_input_wires_masks = vec![F::zero(); circuit.input_wire_count];
        let mut total_output_wires_masks = vec![F::zero(); circuit.output_wire_count];
        let mut mask_seeds: HashMap<_, _> = parties_input_start_and_lengths
            .keys()
            .copied()
            .map(|p| {
                let mut seed = [0u8; 16];
                rng.fill_bytes(&mut seed);
                let input_wires_masks: Vec<F> = input_wires_masks_from_seed(seed, circuit);
                total_input_wires_masks
                    .iter_mut()
                    .zip(input_wires_masks.iter())
                    .for_each(|(d, s)| *d += *s);
                let output_wires_masks: Vec<F> = output_wires_masks_from_seed(seed, circuit);
                total_output_wires_masks
                    .iter_mut()
                    .zip(output_wires_masks.iter())
                    .for_each(|(d, s)| *d += *s);
                (p, seed)
            })
            .collect();
        let offline_correlations: Vec<_> = parties_input_start_and_lengths
            .iter()
            .map(|(pid, (input_start, input_len))| {
                let pcg_key = pcg_keys.remove(pid).unwrap();
                let seed = mask_seeds.remove(pid).unwrap();
                let input_wires_masks =
                    total_input_wires_masks[*input_start..*input_start + *input_len].to_vec();
                (
                    *pid,
                    Self {
                        expanded_pcg_keys: None,
                        shares_seed: seed,
                        pcg_keys: pcg_key,
                        input_wires_masks,
                    },
                )
            })
            .collect();
        (
            total_input_wires_masks,
            total_output_wires_masks,
            offline_correlations,
        )
    }
}

use self::bristol_fashion::ParsedCircuit;

#[derive(Serialize, Deserialize)]
struct EvalMessage<F: FieldElement> {
    #[serde(bound = "")]
    pub opening: Mask<F>,
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum BeaverTriple<F: FieldElement> {
    Regular(#[serde(bound = "")] RegularBeaverTriple<F>),
    Wide(#[serde(bound = "")] WideBeaverTriple<F>),
}

#[derive(Serialize, Deserialize)]
pub enum PairwiseBeaverTriple<F: FieldElement> {
    Regular(#[serde(bound = "")] Vec<(PartyId, RegularBeaverTriple<F>)>),
    Wide(#[serde(bound = "")] Vec<(PartyId, WideBeaverTriple<F>)>),
}
pub fn expand_pairwise_beaver_triples<
    const N: usize,
    const CODE_WIDTH: usize,
    F: PackedField<GF2, N>,
>(
    circuit: &ParsedCircuit,
    pcg_keys: &[(PartyId, (PackedOfflineFullPcgKey, [u8; 16]))],
) -> Vec<((usize, usize), PairwiseBeaverTriple<F>)> {
    let mut pcg_keys: Vec<_> = pcg_keys
        .iter()
        .map(|(pid, (pk, code))| (*pid, FullPcgKey::new_from_offline(pk, *code, CODE_WIDTH)))
        .collect();
    circuit
        .iter()
        .filter(|(_, _, gate)| !gate.is_linear())
        .map(|(layer_idx, gate_idx, gate)| {
            let gate_pairwise_beaver_triple = match gate {
                ParsedGate::AndGate {
                    input: _,
                    output: _,
                } => {
                    let v: Vec<_> = pcg_keys
                        .iter_mut()
                        .map(|(pid, k)| {
                            let bt = k.next_bit_beaver_triple::<N, F>();
                            (*pid, bt)
                        })
                        .collect();
                    PairwiseBeaverTriple::Regular(v)
                }
                ParsedGate::WideAndGate {
                    input: _,
                    input_bit: _,
                    output: _,
                } => {
                    let v: Vec<_> = pcg_keys
                        .iter_mut()
                        .map(|(pid, k)| {
                            let bt = k.next_wide_beaver_triple::<N, F>();
                            (*pid, bt)
                        })
                        .collect();
                    PairwiseBeaverTriple::Wide(v)
                }
                _ => panic!(),
            };
            ((layer_idx, gate_idx), gate_pairwise_beaver_triple)
        })
        .collect()
}

pub fn derive_key_from_seed<const ID: usize>(seed: [u8; 16]) -> [u8; 16] {
    let mut aes_rng = AesRng::from_seed(seed);
    let mut array = [0u8; 16];
    for i in 0..ID + 1 {
        aes_rng.fill_bytes(&mut array);
    }
    array
}
pub fn input_wires_masks_from_seed<F: FieldElement>(
    seed: [u8; 16],
    circuit: &ParsedCircuit,
) -> Vec<F> {
    const INPUT_WIRES_SEED_ID: usize = 0;
    let mut rng = AesRng::from_seed(derive_key_from_seed::<INPUT_WIRES_SEED_ID>(seed));
    let mut input_wires_masks: Vec<_> = Vec::with_capacity(circuit.input_wire_count);
    for _ in 0..circuit.input_wire_count {
        input_wires_masks.push(F::random(&mut rng));
    }
    input_wires_masks
}
pub fn output_wires_masks_from_seed<F: FieldElement>(
    seed: [u8; 16],
    circuit: &ParsedCircuit,
) -> Vec<F> {
    const OUTPUT_WIRES_SEED_ID: usize = 1;
    let mut rng = AesRng::from_seed(derive_key_from_seed::<OUTPUT_WIRES_SEED_ID>(seed));
    let mut output_wire_masks = Vec::with_capacity(circuit.output_wire_count);
    for _ in 0..circuit.output_wire_count {
        output_wire_masks.push(F::random(&mut rng));
    }
    output_wire_masks
}
pub fn gate_masks_from_seed<F: FieldElement>(
    circuit: &ParsedCircuit,
    seed: [u8; 16],
) -> Vec<((usize, usize), Mask<F>)> {
    const GATE_INPUT_WIRES_SEED_ID: usize = 2;
    let total_gates: usize = circuit.total_non_linear_gates();
    let mut rng = AesRng::from_seed(derive_key_from_seed::<GATE_INPUT_WIRES_SEED_ID>(seed));
    let mut gate_input_masks = Vec::with_capacity(total_gates);
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        for (gate_idx, gate) in layer.iter().enumerate() {
            let mask = match gate {
                ParsedGate::AndGate {
                    input: _,
                    output: _,
                } => Mask::And(F::random(&mut rng), F::random(&mut rng)),
                ParsedGate::WideAndGate {
                    input: _,
                    input_bit: _,
                    output: _,
                } => Mask::WideAnd(
                    F::random(&mut rng),
                    core::array::from_fn(|_| F::random(&mut rng)),
                ),
                _ => continue,
            };
            gate_input_masks.push(((layer_idx, gate_idx), mask));
        }
    }
    gate_input_masks
}
pub async fn create_multi_party_beaver_triples<F: FieldElement>(
    engine: &mut impl MultiPartyEngine,
    circuit: &ParsedCircuit,
    pairwise_triples: &[((usize, usize), PairwiseBeaverTriple<F>)],
    gate_input_masks: &[((usize, usize), Mask<F>)],
) -> HashMap<(usize, usize), BeaverTriple<F>> {
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
        .zip(pairwise_triples.iter())
        .for_each(
            |(((layer_idx, gate_idx), mask), ((layer_idx_t, gate_idx_t), gate_beaver_triples))| {
                assert_eq!(&layer_idx, layer_idx_t);
                assert_eq!(&gate_idx, gate_idx_t);
                let gate = circuit.gates[layer_idx][gate_idx];
                match (gate, mask, gate_beaver_triples) {
                    (
                        ParsedGate::AndGate {
                            input: _,
                            output: _,
                        },
                        Mask::And(x, y),
                        PairwiseBeaverTriple::Regular(gate_beaver_triples),
                    ) => {
                        let xy = x * y;
                        let mut z = xy;
                        for (party, RegularBeaverTriple(a, b, c)) in
                            gate_beaver_triples.iter().copied()
                        {
                            engine.send((layer_idx, gate_idx, Mask::And(x - a, y - b)), party);
                            z += c + y * x - b * a - xy;
                            pairwise_beaver_triples.insert((layer_idx, gate_idx, party), a);
                        }
                        n_wise_beaver_triples.insert(
                            (layer_idx, gate_idx),
                            BeaverTriple::Regular(RegularBeaverTriple(x, y, z)),
                        );
                    }
                    (
                        ParsedGate::WideAndGate {
                            input: _,
                            input_bit: _,
                            output: _,
                        },
                        Mask::WideAnd(x, wy),
                        PairwiseBeaverTriple::Wide(gate_beaver_triples),
                    ) => {
                        let xwy = core::array::from_fn(|i| wy[i] * x);
                        let mut wz = xwy;
                        for (party, WideBeaverTriple(a, wb, wc)) in
                            gate_beaver_triples.iter().copied()
                        {
                            engine.send(
                                (
                                    layer_idx,
                                    gate_idx,
                                    Mask::WideAnd(x - a, core::array::from_fn(|i| wy[i] - wb[i])),
                                ),
                                party,
                            );
                            for i in 0..wz.len() {
                                wz[i] += wc[i] + wy[i] * x - wb[i] * a - xwy[i];
                            }
                            pairwise_beaver_triples.insert((layer_idx, gate_idx, party), a);
                        }
                        n_wise_beaver_triples.insert(
                            (layer_idx, gate_idx),
                            BeaverTriple::Wide(WideBeaverTriple(x, wy, wz)),
                        );
                    }
                    _ => {}
                }
            },
        );

    while !pairwise_beaver_triples.is_empty() {
        let ((layer_idx, gate_idx, opening), party): ((usize, usize, Mask<F>), _) =
            engine.recv().await.unwrap();
        let a = pairwise_beaver_triples
            .remove(&(layer_idx, gate_idx, party))
            .unwrap();
        let beaver_triple = n_wise_beaver_triples
            .get_mut(&(layer_idx, gate_idx))
            .unwrap();
        match (opening, beaver_triple) {
            (Mask::And(xa, yb), BeaverTriple::Regular(RegularBeaverTriple(_, y, z))) => {
                *z += xa * *y + yb * a;
            }
            (Mask::WideAnd(xa, wyb), BeaverTriple::Wide(WideBeaverTriple(_, wy, wz))) => {
                for i in 0..wz.len() {
                    wz[i] += wy[i] * xa + wyb[i] * a;
                }
            }
            _ => panic!(),
        }
    }
    n_wise_beaver_triples
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum Mask<F: FieldElement> {
    And(#[serde(bound = "")] F, #[serde(bound = "")] F),
    WideAnd(
        #[serde(bound = "")] F,
        #[serde(with = "BigArray")]
        #[serde(bound = "")]
        [F; 128],
    ),
}

impl<F: FieldElement> AddAssign for Mask<F> {
    fn add_assign(&mut self, rhs: Self) {
        match (self, rhs) {
            (Mask::And(s_a, s_b), Mask::And(r_a, r_b)) => {
                *s_a += r_a;
                *s_b += r_b;
            }
            (Mask::WideAnd(s_a, s_b), Mask::WideAnd(r_a, r_b)) => {
                *s_a += r_a;
                for i in 0..s_b.len() {
                    s_b[i] += r_b[i];
                }
            }
            _ => panic!(),
        }
    }
}
impl<F: FieldElement> Add for Mask<F> {
    type Output = Mask<F>;
    fn add(self, rhs: Self) -> Self::Output {
        let mut m = self.clone();
        m += rhs;
        m
    }
}

pub async fn obtain_masked_and_shared_input<F: FieldElement>(
    engine: &mut impl MultiPartyEngine,
    parties_input_pos_and_length: &HashMap<PartyId, (usize, usize)>,
    my_input: &[F],
    my_input_mask: &[F],
    input_mask_shares: &mut [F],
    circuit: &ParsedCircuit,
) -> Vec<F> {
    let my_id = engine.my_party_id();
    let my_masked_input: Vec<_> = my_input
        .iter()
        .zip(my_input_mask.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    engine.broadcast(&my_masked_input);
    let mut masked_input = vec![F::zero(); circuit.input_wire_count];
    let (my_input_start, my_input_length) = parties_input_pos_and_length.get(&my_id).unwrap();
    for i in 0..*my_input_length {
        masked_input[my_input_start + i] = my_masked_input[i];
        input_mask_shares[my_input_start + i] += my_masked_input[i];
    }
    for i in 0..parties_input_pos_and_length.len() - 1 {
        let (v, p): (Vec<_>, _) = engine.recv().await.unwrap();
        let (input_start, input_length) = parties_input_pos_and_length.get(&p).unwrap().clone();
        masked_input[input_start..input_start + input_length].copy_from_slice(&v);
    }
    masked_input
}

// We assume the input to the circuit is already additively shared between the parties.
pub async fn multi_party_semi_honest_eval_circuit<
    const N: usize,
    E: MultiPartyEngine,
    PF: FieldElement,
    F: PackedField<PF, N>,
>(
    engine: &mut E,
    circuit: &ParsedCircuit,
    my_input: &[F],
    my_input_mask: &[F],
    mut input_mask_shares: Vec<F>,
    multi_party_beaver_triples: &HashMap<(usize, usize), BeaverTriple<F>>,
    output_wire_masks: &Vec<F>,
    parties_input_pos_and_length: &HashMap<PartyId, (usize, usize)>,
) -> Result<(Vec<F>, HashMap<(usize, usize), Mask<F>>, Vec<F>), CircuitEvalError> {
    let my_id = engine.my_party_id();
    let min_id = engine
        .party_ids()
        .iter()
        .fold(PartyId::MAX, |a, b| PartyId::min(a, *b));
    let is_first = my_id == min_id;
    let number_of_peers = engine.party_ids().len() - 1;
    let wires_num =
        circuit.input_wire_count + circuit.internal_wire_count + circuit.output_wire_count;
    let mut wires = vec![F::zero(); wires_num];

    let timer_start = Instant::now();
    let masked_input = obtain_masked_and_shared_input(
        engine,
        parties_input_pos_and_length,
        my_input,
        my_input_mask,
        &mut input_mask_shares,
        circuit,
    )
    .await;
    let pre_shared_input = input_mask_shares;
    wires[0..circuit.input_wire_count].copy_from_slice(&pre_shared_input);
    let total_non_linear_gates: usize = circuit
        .gates
        .iter()
        .map(|layer| layer.iter().filter(|g| !g.is_linear()).count())
        .sum();
    let mut masked_output_wires = Vec::<F>::with_capacity(circuit.output_wire_count);
    let mut masked_gate_inputs = HashMap::<(usize, usize), Mask<F>>::with_capacity(
        total_non_linear_gates + circuit.output_wire_count,
    );
    let max_layer_size = circuit.gates.iter().fold(0, |acc, cur| {
        let non_linear_gates_in_layer = cur.iter().filter(|cur| !cur.is_linear()).count();
        usize::max(acc, non_linear_gates_in_layer)
    });
    let timer_start = Instant::now();
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        let mut and_gates_processed = 0;
        for (gate_idx, gate) in layer.iter().enumerate() {
            match &gate {
                ParsedGate::NotGate { input, output } => {
                    wires[*output] = wires[*input];
                    if is_first {
                        wires[*output] += F::one();
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
                        BeaverTriple::Regular(RegularBeaverTriple(a, b, c)) => (*a, *b, *c),
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
                        BeaverTriple::Wide(WideBeaverTriple(a, wb, wc)) => (*a, *wb, *wc),
                        _ => panic!(),
                    };
                    let x = wires[*input_bit];
                    let mut wy = [F::zero(); 128];
                    for i in 0..input.len() {
                        let input_wire = wires[input[i]];
                        wy[i] = input_wire.into();
                    }
                    for (idx, output_wire) in output.iter().enumerate() {
                        wires[*output_wire] = wc[idx] + wy[idx] * x - wb[idx] * a;
                    }
                    let masked_inputs = core::array::from_fn(|i| wy[i] - wb[i]);
                    let msg = EvalMessage {
                        opening: Mask::WideAnd(x - a, masked_inputs),
                        gate_idx_in_layer: gate_idx,
                    };
                    engine.broadcast(msg);
                    let mask = Mask::WideAnd(x - a, masked_inputs);
                    masked_gate_inputs.insert((layer_idx, gate_idx), mask);
                }
            }
        }
        for _ in 0..and_gates_processed * number_of_peers {
            let (msg, _): (EvalMessage<F>, PartyId) = engine.recv().await.unwrap();
            let gate_idx = msg.gate_idx_in_layer;
            let beaver_triple = multi_party_beaver_triples
                .get(&(layer_idx, gate_idx))
                .unwrap();
            let gate = layer[gate_idx];
            let mask = masked_gate_inputs.get_mut(&(layer_idx, gate_idx)).unwrap();
            match (msg.opening, beaver_triple, gate, mask) {
                (
                    Mask::And(ax, by),
                    BeaverTriple::Regular(RegularBeaverTriple(a, _, _)),
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
                    BeaverTriple::Wide(WideBeaverTriple(a, _, _)),
                    ParsedGate::WideAndGate {
                        input,
                        input_bit,
                        output,
                    },
                    Mask::WideAnd(mask_a, mask_wb),
                ) => {
                    for i in 0..wby.len() {
                        mask_wb[i] += wby[i];
                    }
                    *mask_a += ax;
                    for i in 0..output.len() {
                        let y = wires[input[i]];
                        wires[output[i]] += y * ax + wby[i] * *a;
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
        let ((wire_id, masked_val), _): ((usize, F), _) = engine.recv().await.unwrap();
        assert!(wire_id < output_wire_masks.len());
        masked_output_wires[wire_id] += masked_val;
    }

    Ok((masked_input, masked_gate_inputs, masked_output_wires))
}

pub fn local_eval_circuit<F: FieldElement>(circuit: &ParsedCircuit, input: &[F]) -> Vec<F> {
    debug_assert_eq!(input.len(), circuit.input_wire_count);
    let mut wires =
        vec![
            F::zero();
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
                    wires[output] += F::one();
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
        path::Path,
        sync::Arc,
    };

    use futures::future::try_join_all;
    use rand::thread_rng;
    use tokio::time::Instant;

    use super::bristol_fashion::{parse_bristol, ParsedCircuit};
    use crate::{
        circuit_eval::{
            bristol_fashion::ParsedGate,
            semi_honest::{
                local_eval_circuit, multi_party_semi_honest_eval_circuit, BeaverTriple, Mask,
                OfflineSemiHonestCorrelation, PcgBasedPairwiseBooleanCorrelation,
                RegularBeaverTriple, WideBeaverTriple,
            },
        },
        engine::{LocalRouter, MultiPartyEngine},
        fields::{FieldElement, PackedField, PackedGF2, GF2},
        uc_tags::UCTag,
    };

    async fn test_boolean_circuit<const N: usize, F: PackedField<GF2, N>>(
        circuit: ParsedCircuit,
        input: &[F],
        party_count: usize,
    ) -> Vec<F> {
        const CODE_SEED: [u8; 16] = [1u8; 16];
        assert_eq!(input.len(), circuit.input_wire_count);
        let mut party_ids: Vec<_> = (1..=party_count).map(|i| i as u64).collect();
        party_ids.sort();
        let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
        let (local_router, mut execs) = LocalRouter::new(UCTag::new(&"root_tag"), &party_ids_set);
        let router_handle = tokio::spawn(local_router.launch());

        let first_id = party_ids[0];
        let first_id_input = input.to_vec();
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
        let (total_input_wires_masks, total_output_wires_masks, offline_correlations) =
            PcgBasedPairwiseBooleanCorrelation::deal(&mut rng, &parties_input_lengths, &circuit);

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
                    let mut engine = execs.get(&id).unwrap().sub_protocol("MULTIPARTY BEAVER");
                    async move {
                        let bts = offline_correlation
                            .get_multiparty_beaver_triples(&mut engine, &circuit)
                            .await;
                        Result::<_, ()>::Ok((id, bts, offline_correlation))
                    }
                });
        let parties_input_lengths = Arc::new(parties_input_lengths);
        let exec_results = try_join_all(engine_futures).await.unwrap();
        let mut corr_sums = HashMap::clone(&exec_results[0].1);
        exec_results.iter().skip(1).for_each(|(_, v, _)| {
            v.iter().for_each(|((layer_idx, gate_idx), bt)| {
                let current = corr_sums.get_mut(&(*layer_idx, *gate_idx)).unwrap();
                match (current, bt) {
                    (
                        BeaverTriple::Regular(RegularBeaverTriple(cur_a, cur_b, cur_c)),
                        BeaverTriple::Regular(RegularBeaverTriple(bt_a, bt_b, bt_c)),
                    ) => {
                        *cur_a += *bt_a;
                        *cur_b += *bt_b;
                        *cur_c += *bt_c;
                    }
                    (
                        BeaverTriple::Wide(WideBeaverTriple(cur_a, cur_b, cur_c)),
                        BeaverTriple::Wide(WideBeaverTriple(bt_a, bt_b, bt_c)),
                    ) => {
                        *cur_a += *bt_a;
                        for i in 0..cur_b.len() {
                            cur_b[i] += bt_b[i];
                            cur_c[i] += bt_c[i];
                        }
                    }
                    _ => panic!(),
                }
            })
        });
        for v in corr_sums.values() {
            match v {
                BeaverTriple::Regular(RegularBeaverTriple(a, b, c)) => {
                    assert_eq!(*a * *b, *c);
                }
                BeaverTriple::Wide(WideBeaverTriple(a, b, c)) => {
                    assert_eq!(core::array::from_fn(|i| b[i] * *a), *c);
                }
            }
        }

        let engine_futures =
            exec_results
                .into_iter()
                .map(|(id, n_party_correlation, offline_corerlation)| {
                    let mut engine = execs.remove(&id).unwrap();
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
        let exec_results = try_join_all(engine_futures).await.unwrap();
        println!("Computation took: {}", timer_start.elapsed().as_millis());
        let exec_results: Vec<_> = exec_results.into_iter().map(|e| e.unwrap()).collect();
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
                    BeaverTriple::Regular(RegularBeaverTriple(a, b, c)),
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
                    BeaverTriple::Wide(WideBeaverTriple(a, wb, wc)),
                    Mask::WideAnd(mask_a, mask_wb),
                ) => {
                    assert_eq!(*mask_a + *a, local_computation_wires[input_bit]);
                    let full_b: [F; 128] = core::array::from_fn(|i| wb[i] + mask_wb[i]);
                    for i in 0..input.len() {
                        assert_eq!(F::from(full_b[i]), local_computation_wires[input[i]])
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

        let input = vec![PackedGF2::one(), PackedGF2::zero()];
        let output = test_boolean_circuit(parsed_circuit, &input, 2).await;

        assert_eq!(output[0], PackedGF2::one());
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
        let output = test_boolean_circuit(parsed_circuit, &input, 7).await;

        assert_eq!(output, vec![GF2::one(); 128]);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_semi_honest_aes() {
        let path = Path::new("circuits/aes_128.txt");
        let parsed_circuit = super::super::circuit_from_file(path).unwrap();

        let input = vec![PackedGF2::one(); parsed_circuit.input_wire_count];
        test_boolean_circuit(parsed_circuit, &input, 2).await;
    }
}
