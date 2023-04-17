use std::{collections::HashMap, sync::Arc};

use futures::{future::try_join_all, join};

use crate::{
    circuit_eval::semi_honest::gate_masks_from_seed,
    commitment::OfflineCommitment,
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, GF128, GF2},
    zkfliop::{dealer, prover_offline, verifier_offline, OfflineProver, OfflineVerifier},
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
fn construct_statement<F: FieldElement>(
    masked_gamma_i: Option<F>,
    gamma_i_mask: Option<F>,
    gate_gammas: &[(usize, usize, GateGamma<F>)],
    masked_inputs: Option<&HashMap<(usize, usize), Mask>>,
    mask_shares: Option<&HashMap<(usize, usize), Mask>>,
) -> Vec<F> {
    let statement_length: usize = gate_gammas
        .iter()
        .map(|(_, _, g)| match g {
            GateGamma::And(_) => 4,
            GateGamma::WideAnd(_) => 512,
        })
        .sum();
    // We create a statement of size that is 1 + power of 2.
    let upscaled_statement_length: usize =
        usize::try_from(1 + ((2 * statement_length - 1).ilog2())).unwrap();
    let mut statement = Vec::with_capacity(upscaled_statement_length);
    unsafe { statement.set_len(upscaled_statement_length) };
    // Nullify all redundant place.
    for i in &mut statement[statement_length..] {
        *i = F::zero();
    }

    // Initialize first entry
    statement[0] = masked_gamma_i.unwrap_or(F::zero()) + gamma_i_mask.unwrap_or(F::zero());

    let mut iter_masks = statement.iter_mut().skip(2).step_by(2);

    // Initialize mask shares
    if mask_shares.is_none() {
        iter_masks.for_each(|v| *v = F::zero());
    } else {
        let gate_masks = mask_shares.unwrap();
        for (layer_idx, gate_idx, _) in gate_gammas {
            let gate_mask = gate_masks.get(&(*layer_idx, *gate_idx)).unwrap();
            match gate_mask {
                Mask::And(m_a, m_b) => {
                    *iter_masks.next().unwrap() = F::one().switch(m_a.is_one());
                    *iter_masks.next().unwrap() = F::one().switch(m_b.is_one());
                }
                Mask::WideAnd(m_a, m_wb) => {
                    let v_a = F::one().switch(m_a.is_one());
                    for i in 0..128 {
                        *iter_masks.next().unwrap() = v_a;
                        *iter_masks.next().unwrap() = F::one().switch(m_wb.get_bit(i));
                    }
                }
            }
        }
    }

    // Initialize masked values.
    let mut iter_masked_values = statement.iter_mut().skip(1).step_by(2);
    if masked_inputs.is_none() {
        iter_masked_values.for_each(|v| *v = F::zero());
    } else {
        let gate_masked_inputs = masked_inputs.unwrap();
        for (layer_idx, gate_idx, gate_gamma) in gate_gammas {
            let gate_mask_input = gate_masked_inputs.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gate_mask_input, gate_gamma) {
                (Mask::And(m_a, m_b), GateGamma::And((g, _))) => {
                    *iter_masked_values.next().unwrap() = g.switch(m_a.is_one());
                    *iter_masked_values.next().unwrap() = g.switch(m_b.is_one());
                }
                (Mask::WideAnd(m_a, m_wb), GateGamma::WideAnd(gs)) => {
                    for i in 0..gs.len() {
                        *iter_masked_values.next().unwrap() = gs[i].0.switch(m_a.is_one());
                        *iter_masked_values.next().unwrap() = gs[i].0.switch(m_wb.get_bit(i));
                    }
                }
                _ => panic!(),
            }
        }
    }

    statement
}

pub struct OfflineCircuitVerify<F: FieldElement> {
    s_i: F,
    alpha_omega_commitment: OfflineCommitment,
    verifiers_offline_material: Vec<(PartyId, OfflineVerifier)>,
    prover_offline_material: OfflineProver<F>,
}
pub async fn offline_verify_parties<F: FieldElement>(
    mut engine: impl MultiPartyEngine,
    dealer_id: PartyId,
    round_count: usize,
) -> OfflineCircuitVerify<F> {
    let s_i: F = engine.recv_from(dealer_id).await.unwrap();
    let alpha_omega_commitment =
        OfflineCommitment::offline_obtain_commit(&mut engine, dealer_id).await;

    // Material for single zkFLIOP instances.
    let parties = engine.party_ids().to_vec();
    let my_id = engine.my_party_id();
    let prover_offline_material =
        prover_offline::<F>(engine.sub_protocol(my_id), round_count, dealer_id);
    let verifiers_offline_material: Vec<_> = parties
        .into_iter()
        .filter(|prover_id| prover_id != &dealer_id && prover_id != &my_id)
        .map(|prover_id| {
            let engine_current = engine.sub_protocol(prover_id);
            async move {
                let verifier = verifier_offline(engine_current, round_count, dealer_id).await;
                Result::<(PartyId, OfflineVerifier), ()>::Ok((prover_id, verifier))
            }
        })
        .collect();
    let verifiers_offline_material = try_join_all(verifiers_offline_material);
    let (verifiers_offline_material, prover_offline_material) =
        join!(verifiers_offline_material, prover_offline_material);
    let verifiers_offline_material = verifiers_offline_material.unwrap();

    OfflineCircuitVerify {
        s_i,
        alpha_omega_commitment,
        verifiers_offline_material,
        prover_offline_material,
    }
}

pub async fn verify_parties<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    two: F,
    three: F,
    four: F,
    masked_values: HashMap<(usize, usize), Mask>,
    masks_shares: HashMap<(usize, usize), Mask>,
    output_wire_masked_values: Vec<F>,
    output_wire_mask_shares: Vec<F>,
    circuit: &ParsedCircuit,
    offline_material: OfflineCircuitVerify<F>,
) {
    let my_id = engine.my_party_id();
    let peers: Vec<_> = engine
        .party_ids()
        .iter()
        .copied()
        .filter(|v| v != &my_id)
        .collect();
    let parties = engine.party_ids().to_vec();
    let OfflineCircuitVerify {
        s_i,
        alpha_omega_commitment,
        verifiers_offline_material,
        prover_offline_material,
    } = offline_material;
    let (alpha, omega_hat): (F, F) = alpha_omega_commitment.online_decommit(&mut engine).await;
    // Length of alphas is the total number of output wires + input wires to AND gates.
    // In case of fan out > 1 impose scenarios where the same wire is fed into multiple different wires.
    // We therefore have to "change" the representation of the circuit in a deterministic way so that each wire fed into a multiplication / output wire has a different idx.

    let (alphas, gammas, alphas_output_wires) = compute_gammas_alphas(&alpha, circuit);

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
    let masked_gamma_i = gamma_i - s_i;
    // Send Gamma_i
    engine.broadcast(masked_gamma_i);

    // Receive masked Gamma_is
    let mut masked_gamma_i_s: HashMap<u64, F> = HashMap::with_capacity(peers.len());
    for _ in peers {
        let (masked_gamma_i_peer, pid) = engine.recv().await.unwrap();
        masked_gamma_i_s.insert(pid, masked_gamma_i_peer);
    }
    let proof_statement = construct_statement(
        Some(masked_gamma_i),
        Some(s_i),
        &gammas,
        Some(&masked_values),
        Some(&masks_shares),
    );
    let verify_statement = construct_statement(
        Some(masked_gamma_i),
        Some(s_i),
        &gammas,
        Some(&masked_values),
        Some(&masks_shares),
    );
    // let proof_futures = parties.iter().map(|pid| )
}

pub async fn offline_verify_dealer<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    two: F,
    three: F,
    four: F,
    mask_seeds: Vec<(PartyId, [u8; 16])>,
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

    let mut per_party_input_wires_masks = HashMap::with_capacity(mask_seeds.len());
    let mut per_party_output_wires_masks = HashMap::with_capacity(mask_seeds.len());
    let total_gates: usize = circuit
        .gates
        .iter()
        .map(|layer| layer.iter().filter(|gate| !gate.is_linear()).count())
        .sum();
    let mut total_input_masks = Vec::with_capacity(total_gates);
    let mut total_output_masks = vec![GF2::zero(); circuit.output_wire_count];
    circuit
        .gates
        .iter()
        .enumerate()
        .for_each(|(layer_idx, layer)| {
            layer.iter().enumerate().for_each(|(gate_idx, gate)| {
                let zero_mask = match gate {
                    ParsedGate::AndGate {
                        input: _,
                        output: _,
                    } => Mask::And(GF2::zero(), GF2::zero()),
                    ParsedGate::WideAndGate {
                        input: _,
                        input_bit: _,
                        output: _,
                    } => Mask::WideAnd(GF2::zero(), GF128::zero()),
                    _ => return,
                };
                total_input_masks.push((layer_idx, gate_idx, zero_mask));
            })
        });
    assert_eq!(mask_seeds.len(), engine.party_ids().len() - 1);
    for (pid, seed) in mask_seeds {
        let (gate_input_masks, output_wires_masks) = gate_masks_from_seed(&circuit, seed);
        debug_assert_eq!(gate_input_masks.len(), total_input_masks.len());
        debug_assert_eq!(output_wires_masks.len(), total_output_masks.len());
        total_input_masks
            .iter_mut()
            .zip(gate_input_masks.iter())
            .for_each(|(a, b)| {
                debug_assert_eq!(a.0, b.0);
                debug_assert_eq!(a.1, b.1);
                match (a, b) {
                    (
                        (_, _, Mask::And(total_a, total_b)),
                        (_, _, Mask::And(current_a, current_b)),
                    ) => {
                        *total_a += *current_a;
                        *total_b += *current_b;
                    }
                    (
                        (_, _, Mask::WideAnd(total_a, total_wb)),
                        (_, _, Mask::WideAnd(current_a, current_wb)),
                    ) => {
                        *total_a += *current_a;
                        *total_wb += *current_wb;
                    }
                    _ => panic!(),
                }
            });
        total_output_masks
            .iter_mut()
            .zip(output_wires_masks.iter())
            .for_each(|(d, s)| *d += *s);
        per_party_input_wires_masks.insert(pid, gate_input_masks);
        per_party_output_wires_masks.insert(pid, output_wires_masks);
    }

    let (alphas, gammas, alphas_output_wires) = compute_gammas_alphas(&alpha, circuit);

    // Compute Omega
    let output_wire_masks: Vec<_> = total_output_masks
        .iter()
        .map(|v| F::one().switch(v.is_one()))
        .collect();
    let input_wire_masks: HashMap<_, _> = total_input_masks
        .iter()
        .copied()
        .map(|(l, g, m)| ((l, g), m))
        .collect();
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
    let gammas_rc = Arc::new(gammas);

    OfflineCommitment::offline_commit(&mut engine, &(alpha, omega_hat)).await;
    let dealer_offline_futures: Vec<_> = parties
        .into_iter()
        .map(|prover_id| {
            let gate_masks = per_party_input_wires_masks.remove(&prover_id).unwrap();
            let si = *s.get(&prover_id).unwrap();
            let gamma_rc = gammas_rc.clone();
            let engine = engine.sub_protocol(prover_id);
            async move {
                let gammas = gamma_rc.as_ref();
                let mask_shares: HashMap<_, _> = gate_masks
                    .into_iter()
                    .map(|(l, g, m)| ((l, g), m))
                    .collect();
                let mut z_tilde =
                    construct_statement(None, Some(si), &gammas, None, Some(&mask_shares));
                dealer(engine, &mut z_tilde, prover_id, two, three, four).await;
                Result::<(), ()>::Ok(())
            }
        })
        .collect();
    try_join_all(dealer_offline_futures).await.unwrap();
}
