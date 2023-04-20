use std::{collections::HashMap, sync::Arc};

use futures::{future::try_join_all, join};

use crate::{
    circuit_eval::semi_honest::gate_masks_from_seed,
    commitment::OfflineCommitment,
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, GF128, GF2},
    zkfliop::{self, dealer, prover_offline, verifier_offline, OfflineProver, OfflineVerifier},
};

use super::{
    bristol_fashion::{ParsedCircuit, ParsedGate},
    semi_honest::{Mask, MultiPartyBeaverTriple},
};

#[derive(Debug)]
enum InputWireCoefficients<F: FieldElement> {
    And(F, F),
    WideAnd(F, [F; 128]),
}

#[derive(Debug)]
enum GateGamma<F: FieldElement> {
    And(F),
    WideAnd([F; 128]),
}

fn compute_gammas_alphas<F: FieldElement>(
    alpha: &F,
    circuit: &ParsedCircuit,
) -> (
    Vec<(usize, usize, InputWireCoefficients<F>)>,
    Vec<(usize, usize, GateGamma<F>)>,
    Vec<F>,
    Vec<F>,
    F,
) {
    let mut cur_alpha = *alpha;
    let alpha = *alpha;
    let mut alphas = Vec::<(usize, usize, InputWireCoefficients<F>)>::new();
    let mut gammas = Vec::<(usize, usize, GateGamma<F>)>::new();

    let mut weights_per_wire =
        vec![
            F::zero();
            circuit.input_wire_count + circuit.output_wire_count + circuit.internal_wire_count
        ];
    // We first distribute alphas to output wires.
    let output_wires =
        &mut weights_per_wire[circuit.input_wire_count + circuit.internal_wire_count..];
    for v in output_wires.iter_mut() {
        *v = cur_alpha;
        cur_alpha *= alpha;
    }
    let output_wire_threshold = circuit.input_wire_count + circuit.internal_wire_count;
    let alphas_outputs: Vec<_> = output_wires.iter().map(|a| *a).collect();

    // Next, distribute alphas for the relevant gates' input wires.
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        for (gate_idx, gate) in layer.iter().enumerate() {
            let c = match gate {
                ParsedGate::AndGate { input, output: _ } => {
                    let a = cur_alpha;
                    let b = cur_alpha * alpha;
                    cur_alpha = b * alpha;
                    weights_per_wire[input[0]] += a;
                    weights_per_wire[input[1]] += b;
                    InputWireCoefficients::And(a, b)
                }
                ParsedGate::WideAndGate {
                    input,
                    input_bit,
                    output: _,
                } => {
                    let bit_coefficient = cur_alpha;
                    cur_alpha *= alpha;
                    weights_per_wire[*input_bit] += bit_coefficient;
                    let wide_coefficents: [F; 128] = core::array::from_fn(|i| {
                        let cur = cur_alpha;
                        cur_alpha *= alpha;
                        weights_per_wire[input[i]] += cur;
                        cur
                    });
                    InputWireCoefficients::WideAnd(bit_coefficient, wide_coefficents)
                }
                _ => continue,
            };
            alphas.push((layer_idx, gate_idx, c));
        }
    }

    let mut total_constant_addition: F = F::zero();
    // Propagate alphas to compute gammas.
    for (layer_idx, layer) in circuit.gates.iter().enumerate().rev() {
        for (gate_idx, gate) in layer.iter().enumerate().rev() {
            match gate {
                ParsedGate::XorGate { input, output } => {
                    let out = weights_per_wire[*output];
                    let v = &mut weights_per_wire[input[0]];
                    *v += out;
                    let v = &mut weights_per_wire[input[1]];
                    *v += out;
                }
                ParsedGate::NotGate { input, output } => {
                    let v_output = weights_per_wire[*output];
                    weights_per_wire[*input] += v_output;
                    total_constant_addition += v_output;
                }
                ParsedGate::AndGate { input: _, output } => {
                    gammas.push((
                        layer_idx,
                        gate_idx,
                        GateGamma::And(weights_per_wire[*output]),
                    ));
                }
                ParsedGate::WideAndGate {
                    input: _,
                    input_bit: _,
                    output,
                } => {
                    let g =
                        GateGamma::WideAnd(core::array::from_fn(|i| weights_per_wire[output[i]]));
                    gammas.push((layer_idx, gate_idx, g));
                }
            }
        }
    }
    let gammas_inputs_wires = weights_per_wire[..circuit.input_wire_count].to_vec();
    (
        alphas,
        gammas,
        alphas_outputs,
        gammas_inputs_wires,
        total_constant_addition,
    )
}
fn compute_gamma_i<F: FieldElement>(
    gammas: &[(usize, usize, GateGamma<F>)],
    mask_shares: &HashMap<(usize, usize), MultiPartyBeaverTriple>,
    masked_values: &HashMap<(usize, usize), Mask>,
) -> F {
    gammas
        .iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = mask_shares.get(&(*layer_idx, *gate_idx)).unwrap();
            let masked_values = masked_values.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask, masked_values) {
                (
                    GateGamma::And(g),
                    MultiPartyBeaverTriple::Regular(m_a, m_b, _),
                    Mask::And(v_a, v_b),
                ) => {
                    let bit = *m_a * *v_b + *v_a * *m_b;
                    g.switch(bit.is_one())
                }
                (
                    GateGamma::WideAnd(g),
                    MultiPartyBeaverTriple::Wide(m_a, m_wb, _),
                    Mask::WideAnd(v_a, v_wb),
                ) => {
                    let bits = m_wb.switch(v_a.is_one()) + v_wb.switch(m_a.is_one());
                    let mut sum = F::zero();
                    for i in 0..g.len() {
                        sum += g[i].switch(bits.get_bit(i));
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
) -> F {
    gammas
        .iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = masks_gates.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask) {
                (GateGamma::And(g), Mask::And(m_a, m_b)) => g.switch(m_a.is_one() & m_b.is_one()),
                (GateGamma::WideAnd(g), Mask::WideAnd(m_a, m_wb)) => {
                    let mut sum = F::zero();
                    let m = m_wb.switch(m_a.is_one());
                    for i in 0..g.len() {
                        sum += g[i].switch(m.get_bit(i));
                    }
                    sum
                }
                _ => panic!(),
            }
        })
        .sum()
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
pub fn statement_length(circuit: &ParsedCircuit) -> usize {
    let statement_length: usize = circuit
        .gates
        .iter()
        .flatten()
        .map(|g| match g {
            ParsedGate::AndGate {
                input: _,
                output: _,
            } => 4,
            ParsedGate::WideAndGate {
                input: _,
                input_bit: _,
                output: _,
            } => 512,
            _ => 0,
        })
        .sum();
    let statement_length = (1 << (usize::ilog2(2 * statement_length - 1))) as usize;
    usize::try_from(1 + statement_length).unwrap()
}
fn construct_statement<F: FieldElement>(
    masked_gamma_i: Option<F>,
    gamma_i_mask: Option<F>,
    gate_gammas: &[(usize, usize, GateGamma<F>)],
    masked_inputs: Option<&HashMap<(usize, usize), Mask>>,
    mask_shares: Option<&HashMap<(usize, usize), MultiPartyBeaverTriple>>,
    circuit: &ParsedCircuit,
) -> Vec<F> {
    let statement_length: usize = statement_length(circuit);
    // We create a statement of size that is 1 + power of 2.
    let mut statement = vec![F::zero(); statement_length];

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
                MultiPartyBeaverTriple::Regular(m_a, m_b, _) => {
                    *iter_masks.next().unwrap() = F::one().switch(m_b.is_one());
                    *iter_masks.next().unwrap() = F::one().switch(m_a.is_one());
                }
                MultiPartyBeaverTriple::Wide(m_a, m_wb, _) => {
                    let v_a = F::one().switch(m_a.is_one());
                    for i in 0..128 {
                        *iter_masks.next().unwrap() = F::one().switch(m_wb.get_bit(i));
                        *iter_masks.next().unwrap() = v_a;
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
                (Mask::And(m_a, m_b), GateGamma::And(g)) => {
                    *iter_masked_values.next().unwrap() = g.switch(m_a.is_one());
                    *iter_masked_values.next().unwrap() = g.switch(m_b.is_one());
                }
                (Mask::WideAnd(m_a, m_wb), GateGamma::WideAnd(gs)) => {
                    for i in 0..gs.len() {
                        *iter_masked_values.next().unwrap() = gs[i].switch(m_a.is_one());
                        *iter_masked_values.next().unwrap() = gs[i].switch(m_wb.get_bit(i));
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
    s_commitment: OfflineCommitment,
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
    let s_commitment = OfflineCommitment::offline_obtain_commit(&mut engine, dealer_id).await;

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
        s_commitment,
    }
}

pub async fn verify_parties<F: FieldElement, E: MultiPartyEngine>(
    engine: &mut E,
    two: F,
    three: F,
    four: F,
    input_wire_masked_values: &[F],
    masked_values: &HashMap<(usize, usize), Mask>,
    masks_shares: &HashMap<(usize, usize), MultiPartyBeaverTriple>,
    output_wire_masked_values: &[F],
    circuit: &ParsedCircuit,
    offline_material: &OfflineCircuitVerify<F>,
) -> bool {
    let my_id = engine.my_party_id();
    let peers: Vec<_> = engine
        .party_ids()
        .iter()
        .copied()
        .filter(|v| v != &my_id)
        .collect();
    let OfflineCircuitVerify {
        s_i,
        alpha_omega_commitment,
        verifiers_offline_material,
        prover_offline_material,
        s_commitment,
    } = offline_material;
    let (alpha, omega_hat): (F, F) = alpha_omega_commitment.online_decommit(engine).await;
    // Length of alphas is the total number of output wires + input wires to AND gates.
    // In case of fan out > 1 impose scenarios where the same wire is fed into multiple different wires.
    // We therefore have to "change" the representation of the circuit in a deterministic way so that each wire fed into a multiplication / output wire has a different idx.

    let (alphas, gammas, alphas_output_wires, gammas_input_wires, total_constant_addition) =
        compute_gammas_alphas(&alpha, circuit);

    // Compute Lambda
    let alpha_x_hat = dot_product_alpha(
        dbg!(&alphas),
        &alphas_output_wires,
        &masked_values,
        &output_wire_masked_values,
    );
    let gamma_x_hat = dot_product_gamma(dbg!(&gammas), dbg!(&masked_values));

    let lambda = dbg!(alpha_x_hat) - dbg!(gamma_x_hat) - dbg!(total_constant_addition);

    // Compute Gamma_i
    let gamma_i = compute_gamma_i(&gammas, &masks_shares, &masked_values);
    let masked_gamma_i = gamma_i - *s_i;
    // Send Gamma_i
    engine.broadcast(masked_gamma_i);

    // Receive masked Gamma_is
    let mut masked_gamma_i_s: HashMap<u64, F> = HashMap::with_capacity(peers.len());
    for _ in 0..peers.len() {
        let (masked_gamma_i_peer, pid) = engine.recv().await.unwrap();
        masked_gamma_i_s.insert(pid, masked_gamma_i_peer);
    }
    let p_hat = lambda - masked_gamma_i_s.values().copied().sum() - masked_gamma_i + omega_hat;
    let mut proof_statement = construct_statement(
        Some(masked_gamma_i),
        Some(*s_i),
        &gammas,
        Some(&masked_values),
        Some(&masks_shares),
        circuit,
    );
    let verify_statement = Arc::new(construct_statement(
        None,
        None,
        &gammas,
        Some(&masked_values),
        None,
        circuit,
    ));
    let prover_futures = zkfliop::prover(
        engine.sub_protocol(my_id),
        dbg!(&mut proof_statement),
        prover_offline_material,
        two,
        three,
        four,
    );

    let verifiers_futures =
        verifiers_offline_material
            .into_iter()
            .map(|(prover_id, offline_material)| {
                let verifier_engine = engine.sub_protocol(prover_id);
                let verify_statement_arc = verify_statement.clone();
                let masked_gamma_prover = *masked_gamma_i_s.get(&prover_id).unwrap();
                async move {
                    // We only modify the first entry (the masked Gamma_i) in the verifying statement.
                    let mut z_hat = verify_statement_arc.as_ref().clone();
                    z_hat[0] = masked_gamma_prover;
                    zkfliop::verifier(
                        verifier_engine,
                        dbg!(&mut z_hat),
                        *prover_id,
                        offline_material,
                        two,
                        three,
                        four,
                    )
                    .await;
                    Result::<(), ()>::Ok(())
                }
            });
    let verifiers_futures = try_join_all(verifiers_futures);
    let (_, verifiers_futures) = join!(prover_futures, verifiers_futures);
    verifiers_futures.unwrap();
    engine.broadcast(());
    for p in peers {
        let _: () = engine.recv_from(p).await.unwrap();
    }
    let s = s_commitment.online_decommit(engine).await;
    let p = p_hat + s;
    return p.is_zero();
}

pub async fn offline_verify_dealer<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    two: F,
    three: F,
    four: F,
    mask_seeds: Vec<(PartyId, [u8; 16])>,
    circuit: &ParsedCircuit,
) -> Vec<GF2> {
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
    let si_s: HashMap<PartyId, F> = parties
        .iter()
        .map(|pid| {
            let si = F::random(&mut rng);
            println!("si: {:?}, pid:{}", si, pid);
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

    let (alphas, gammas, alphas_output_wires, gammas_inputs, total_constant_addition) =
        compute_gammas_alphas(&alpha, circuit);

    // Compute Omega
    let output_wire_masks: Vec<_> = total_output_masks
        .iter()
        .map(|v| F::one().switch(v.is_one()))
        .collect();
    let gates_input_wire_masks: HashMap<_, _> = total_input_masks
        .iter()
        .copied()
        .map(|(l, g, m)| ((l, g), m))
        .collect();
    let mu = F::random(&mut rng);
    let alpha_r = dot_product_alpha(
        &alphas,
        &alphas_output_wires,
        &gates_input_wire_masks,
        &output_wire_masks,
    );

    let sigma_gamma_l_r_l = dot_product_gamma(&gammas, &gates_input_wire_masks);
    let omega = alpha_r + sigma_gamma_l_r_l;
    let omega_hat = omega - mu;
    let gammas_rc = Arc::new(gammas);

    OfflineCommitment::offline_commit(&mut engine, &(alpha, omega_hat)).await;
    let s = mu - si_s.values().copied().sum();
    OfflineCommitment::offline_commit(&mut engine, &s).await;
    let dealer_offline_futures: Vec<_> = parties
        .into_iter()
        .map(|prover_id| {
            let gate_masks = per_party_input_wires_masks.remove(&prover_id).unwrap();
            let si = *si_s.get(&prover_id).unwrap();
            let gamma_rc = gammas_rc.clone();
            let engine = engine.sub_protocol(prover_id);
            async move {
                let gammas = gamma_rc.as_ref();
                let mask_shares: HashMap<_, _> = gate_masks
                    .into_iter()
                    .map(|(l, g, m)| {
                        let m = match m {
                            Mask::And(a, b) => MultiPartyBeaverTriple::Regular(a, b, GF2::zero()),
                            Mask::WideAnd(a, wb) => {
                                MultiPartyBeaverTriple::Wide(a, wb, GF128::zero())
                            }
                        };
                        ((l, g), m)
                    })
                    .collect();
                let mut z_tilde =
                    construct_statement(None, Some(si), &gammas, None, Some(&mask_shares), circuit);
                dealer(engine, &mut z_tilde, prover_id, two, three, four).await;
                Result::<(), ()>::Ok(())
            }
        })
        .collect();
    try_join_all(dealer_offline_futures).await.unwrap();
    total_output_masks
}
