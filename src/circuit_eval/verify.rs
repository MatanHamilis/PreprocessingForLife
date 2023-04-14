use std::{
    collections::{HashMap, HashSet},
    mem::MaybeUninit,
};

use crate::{
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, GF128, GF2},
    pcg::FullPcgKey,
};

use super::{
    bristol_fashion::{ParsedCircuit, ParsedGate},
    semi_honest::Mask,
};

enum InputWireCoefficients<F: FieldElement> {
    And(F, F),
    WideAnd(F, [F; 128]),
}

enum GateGamma<F: FieldElement> {
    And((F, F)),
    WideAnd([(F, F); 128]),
}

fn compute_gammas_alphas<F: FieldElement>(
    alpha: &F,
    circuit: &ParsedCircuit,
) -> (
    Vec<(usize, usize, InputWireCoefficients<F>)>,
    Vec<(usize, usize, GateGamma<F>)>,
    Vec<F>,
) {
    let mut total_gates: usize = 0;
    let mut cur_alpha = *alpha;
    let mut alphas = Vec::<(usize, usize, InputWireCoefficients<F>)>::new();
    let mut gammas = Vec::<(usize, usize, GateGamma<F>)>::new();

    let mut weights_per_wire =
        vec![
            (F::zero(), F::zero());
            circuit.input_wire_count + circuit.output_wire_count + circuit.internal_wire_count
        ];
    // We first distribute alphas to output wires.
    let output_wires =
        &mut weights_per_wire[circuit.input_wire_count + circuit.internal_wire_count..];
    for v in output_wires.iter_mut() {
        *v = (cur_alpha, F::zero());
        cur_alpha *= *alpha;
    }
    let alphas_outputs: Vec<_> = output_wires.iter().map(|(a, _)| *a).collect();

    // Next, distribute alphas for the relevant gates' input wires.
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        for (gate_idx, gate) in layer.iter().enumerate() {
            let c = match gate {
                ParsedGate::AndGate { input, output } => {
                    let a = cur_alpha;
                    let b = cur_alpha * *alpha;
                    cur_alpha = b * *alpha;
                    weights_per_wire[input[0]].0 += a;
                    weights_per_wire[input[1]].0 += b;
                    InputWireCoefficients::And(a, b)
                }
                ParsedGate::WideAndGate {
                    input,
                    input_bit,
                    output,
                } => {
                    let bit_coefficient = cur_alpha;
                    cur_alpha *= *alpha;
                    weights_per_wire[*input_bit].0 += bit_coefficient;
                    let wide_coefficents: [F; 128] = core::array::from_fn(|i| {
                        let cur = cur_alpha;
                        cur_alpha *= *alpha;
                        weights_per_wire[input[i]].0 += cur;
                        cur
                    });
                    InputWireCoefficients::WideAnd(bit_coefficient, wide_coefficents)
                }
                _ => panic!(),
            };
            alphas.push((layer_idx, gate_idx, c));
        }
    }

    // Propagate alphas to compute gammas.
    for (layer_idx, layer) in circuit.gates.iter().enumerate().rev() {
        for (gate_idx, gate) in layer.iter().enumerate().rev() {
            match gate {
                ParsedGate::XorGate { input, output } => {
                    let out = weights_per_wire[*output];
                    let v = &mut weights_per_wire[input[0]];
                    v.0 += out.0;
                    v.1 += out.1;
                    let v = &mut weights_per_wire[input[1]];
                    v.0 += out.0;
                    v.1 += out.1;
                }
                ParsedGate::NotGate { input, output } => {
                    let v_output = weights_per_wire[*output];
                    weights_per_wire[*input].0 += v_output.0;
                    weights_per_wire[*input].1 += v_output.1 + F::one();
                }
                ParsedGate::AndGate { input, output } => {
                    gammas.push((
                        layer_idx,
                        gate_idx,
                        GateGamma::And(weights_per_wire[*output]),
                    ));
                }
                ParsedGate::WideAndGate {
                    input,
                    input_bit,
                    output,
                } => {
                    let g = GateGamma::WideAnd(core::array::from_fn(|i| weights_per_wire[i]));
                    gammas.push((layer_idx, gate_idx, g));
                }
            }
        }
    }
    (alphas, gammas, alphas_outputs)
}
fn compute_gamma_i<F: FieldElement>(
    gammas: &[(usize, usize, GateGamma<F>)],
    mask_shares: &HashMap<(usize, usize), Mask>,
    masked_values: &HashMap<(usize, usize), Mask>,
) -> F {
    gammas
        .iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = mask_shares.get(&(*layer_idx, *gate_idx)).unwrap();
            let masked_values = masked_values.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask, masked_values) {
                (GateGamma::And(g), Mask::And(m_a, m_b), Mask::And(v_a, v_b)) => {
                    let bit = *m_a * *v_b + *v_a * *m_b;
                    g.0.switch(bit.is_one())
                }
                (GateGamma::WideAnd(g), Mask::WideAnd(m_a, m_wb), Mask::WideAnd(v_a, v_wb)) => {
                    let bits = m_wb.switch(v_a.is_one()) + v_wb.switch(m_a.is_one());
                    let mut sum = F::zero();
                    for i in 0..g.len() {
                        sum += g[i].0.switch(bits.get_bit(i));
                    }
                    sum
                }
                _ => panic!(),
            }
        })
        .sum()
}
fn dot_product_gamma<F: FieldElement>(
    gammas: &[(usize, usize, GateGamma<F>)],
    masks_gates: &HashMap<(usize, usize), Mask>,
) -> (F, F) {
    gammas
        .iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = masks_gates.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask) {
                (GateGamma::And(g), Mask::And(m_a, m_b)) => {
                    (g.0.switch(m_a.is_one() & m_b.is_one()), g.1)
                }
                (GateGamma::WideAnd(g), Mask::WideAnd(m_a, m_wb)) => {
                    let mut sum = (F::zero(), F::zero());
                    let m = m_wb.switch(m_a.is_one());
                    for i in 0..g.len() {
                        sum.0 += g[i].0.switch(m.get_bit(i));
                        sum.1 += g[i].1;
                    }
                    sum
                }
                _ => panic!(),
            }
        })
        .fold((F::zero(), F::zero()), |acc, cur| {
            (acc.0 + cur.0, acc.1 + cur.1)
        })
}
fn dot_product_alpha<F: FieldElement>(
    alphas_gate: &[(usize, usize, InputWireCoefficients<F>)],
    alphas_outputs: &[F],
    masks_gates: &HashMap<(usize, usize), Mask>,
    masks_outputs: &[F],
) -> F {
    // Sigma alpha_w r_w
    let sigma_alpha_w_r_w_gates: F = alphas_gate
        .iter()
        .map(|(layer_id, gate_id, input_wire_coefficients)| {
            let mask = masks_gates.get(&(*layer_id, *gate_id)).unwrap();
            match (mask, input_wire_coefficients) {
                (Mask::And(a, b), InputWireCoefficients::And(c_a, c_b)) => {
                    c_a.switch(a.is_one()) + c_b.switch(b.is_one())
                }
                (Mask::WideAnd(a, wb), InputWireCoefficients::WideAnd(c_a, c_wb)) => {
                    let mut sum = c_a.switch(a.is_one());
                    for i in 0..c_wb.len() {
                        sum += c_wb[i].switch(wb.get_bit(i));
                    }
                    sum
                }
                _ => panic!(),
            }
        })
        .sum();
    let sigma_alpha_w_r_w_outputs: F = alphas_outputs
        .iter()
        .zip(masks_outputs.iter())
        .map(|(u, v)| *u * *v)
        .sum();
    sigma_alpha_w_r_w_gates + sigma_alpha_w_r_w_outputs
}

pub async fn verify_parties<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    dealer_id: PartyId,
    two: F,
    three: F,
    four: F,
    masked_values: HashMap<(usize, usize), Mask>,
    masks_shares: HashMap<(usize, usize), Mask>,
    output_wire_masked_values: Vec<F>,
    output_wire_mask_shares: Vec<F>,
    circuit: &ParsedCircuit,
) {
    let si: F = engine.recv_from(dealer_id).await.unwrap();
    let alpha: F = engine.recv_from(dealer_id).await.unwrap();
    // Length of alphas is the total number of output wires + input wires to AND gates.
    // In case of fan out > 1 impose scenarios where the same wire is fed into multiple different wires.
    // We therefore have to "change" the representation of the circuit in a deterministic way so that each wire fed into a multiplication / output wire has a different idx.

    let (alphas, gammas, alphas_output_wires) = compute_gammas_alphas(&alpha, circuit);

    let omega_hat: F = engine.recv_from(dealer_id).await.unwrap();

    // Compute Lambda
    let alpha_x_hat = dot_product_alpha(
        &alphas,
        &alphas_output_wires,
        &masked_values,
        &output_wire_masked_values,
    );
    let gamma_x_hat = dot_product_gamma(&gammas, &masked_values);

    let lambda = alpha_x_hat - gamma_x_hat.0 - gamma_x_hat.1;

    // Compute Gamma_i
    let gamma_i = compute_gamma_i(&gammas, &masks_shares, &masked_values);
}

pub async fn verify_dealer<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    two: F,
    three: F,
    four: F,
    input_wire_masks: HashMap<(usize, usize), Mask>,
    output_wire_masks: Vec<F>,
    correlations: HashMap<PartyId, GF128>,
    circuit: &ParsedCircuit,
) {
    let mut rng = E::rng();
    let alpha = F::random(&mut rng);
    let dealer_id = engine.my_party_id();
    let parties: Vec<PartyId> = engine
        .party_ids()
        .iter()
        .copied()
        .filter(|i| *i != dealer_id)
        .collect();
    // Send s_i
    let s: HashMap<PartyId, F> = parties
        .iter()
        .map(|pid| {
            let si = F::random(&mut rng);
            engine.send(si, *pid);
            (*pid, si)
        })
        .collect();

    // Send alpha
    engine.broadcast(alpha);

    let (alphas, gammas, alphas_output_wires) = compute_gammas_alphas(&alpha, circuit);

    // Compute Omega
    let mu = F::random(&mut rng);
    let alpha_r = dot_product_alpha(
        &alphas,
        &alphas_output_wires,
        &input_wire_masks,
        &output_wire_masks,
    );

    let sigma_gamma_l_r_l = dot_product_gamma(&gammas, &input_wire_masks).0;
    let omega = alpha_r + sigma_gamma_l_r_l;
    let omega_hat = omega - mu;
    engine.broadcast(omega_hat);
}
