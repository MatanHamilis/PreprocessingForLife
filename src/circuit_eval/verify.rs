use std::collections::{HashSet, HashMap};

use crate::{
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, GF2, GF128}, pcg::FullPcgKey,
};

use super::bristol_fashion::{ParsedCircuit, ParsedGate};

fn prepare_alpha_mapping<F: FieldElement>(alpha: &F, circuit: &ParsedCircuit) -> (HashMap<(usize, usize), usize>,Vec<F>) {
    let mut total_gates: usize = 0;
    let total_alphas: usize = circuit.gates.iter().map(|layer| layer.iter().filter_map(|g| {
        match g {
            ParsedGate::AndGate { input, output } => {
                total_gates += 1;
                Some(g.input_wires().len())
            },
            ParsedGate::WideAndGate { input, input_bit, output } => {
                total_gates += 1;
                Some(g.input_wires().len())},
            _ => None
        }
    }).fold(0usize, |acc,curr| acc + curr)).sum();
    let mapping = HashMap::with_capacity(total_gates);
    let alphas = Vec::with_capacity(total_alphas);
    let mut cur_alpha = alpha;
    for i in 0..total_alphas {
        alphas.push(*cur_alpha);
        *cur_alpha *= *alpha;
    }
    let mut current_total = 0;
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        for (gate_idx, gate) in layer.iter().enumerate() {
            if gate.is_linear() {
                continue;
            }
            mapping.insert((layer_idx,gate_idx), current_total);
            current_total += gate.input_wires().len();
        }
    }
    assert_eq!(current_total, alphas.len());
    (mapping, alphas)
}
fn compute_gammas(circuit: &ParsedCircuit, alphas: HashMap<usize, GF128>) -> HashMap<(usize, usize), GF128> {
    let max_layer_size = circuit.gates.iter().map(|l| l.iter().map(|g| g.input_wires().len()).fold(0, |acc,curr| acc+curr)).fold(0, |curr,acc| usize::max(curr, acc));
    let mut layer_wires = HashMap::with_capacity(max_layer_size);
    for layer in circuit.gates {
        for g in layer.iter().rev() {
            match g {
                ParsedGate::AndGate { input, output } => {
                    for i in input {
                        layer_wires.entry(&i).or_insert(GF128::zero()) += alphas.g
                    }
                },
                ParsedGate::WideAndGate { input, input_bit, output } => {
                    for i in input {
                        layer_wires.insert(i, alphas.get(i).unwrap());
                    }
                    layer_wires.insert(input_bit, alphas.get(input_bit).unwrap());
                },
                ParsedGate::XorGate { input, output } => {
                    for i in layer_wires.insert(k, v)
                }
            }
        }
        for g in layer.iter().rev() {
            match 
        }
    };
}

pub async fn verify_parties<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    dealer_id: PartyId,
    two: F,
    three: F,
    four: F,
    masked_values: HashMap<usize, GF2>,
    masks_shares: HashMap<usize, GF2>,
    circuit: &ParsedCircuit,
) {
    let si: F = engine.recv_from(dealer_id).await.unwrap();
    let alpha: F = engine.recv_from(dealer_id).await.unwrap();
    let mut alpha_deg = F::one();
    // Length of alphas is the total number of output wires + input wires to AND gates.
    // In case of fan out > 1 impose scenarios where the same wire is fed into multiple different wires.
    // We therefore have to "change" the representation of the circuit in a deterministic way so that each wire fed into a multiplication / output wire has a different idx.

    let alpha_degs: HashMap<usize, GF128> = (0..masked_values.len()).map(|i| (i, alpha_deg *= alpha)).collect();
}

pub async fn verify_dealer<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    two: F,
    three: F,
    four: F,
    wire_masks: HashMap<(usize,usize), Mask>,
    correlations: HashMap<PartyId, GF128>,
    circuit: &ParsedCircuit,
) {
    let mut rng = E::rng();
    let alpha = F::random(&mut rng);
    let dealer_id = engine.my_party_id();
    let parties: Vec<PartyId> = engine.party_ids().iter().copied().filter(|i| *i != dealer_id).collect();
    // Send s_i
    let s: HashMap<PartyId,F> = parties.iter().map(|pid| {
        let si = F::random(&mut rng);
        engine.send(si, *pid);
        (*pid, si)
    }).collect();

    // Send alpha
    engine.broadcast(alpha);

    let mut alpha_deg = F::one();
    let alpha_degs: HashMap<usize, GF128> = (0..wire_masks.len()).map(|i| (i, alpha_deg *= alpha)).collect();
    let mu = F::random(&mut rng);
    let omega=;

    let omega_hat = omega - mu;
}
