use std::{collections::HashMap, mem::MaybeUninit, sync::Arc, time};

use aes_prng::AesRng;
use futures::{future::try_join_all, join};
use rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;
use tokio::time::Instant;

use crate::{
    circuit_eval::semi_honest::{
        gate_masks_from_seed, input_wires_masks_from_seed, output_wires_masks_from_seed,
    },
    commitment::OfflineCommitment,
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, PackedField},
    pcg::{RegularBeaverTriple, WideBeaverTriple},
    zkfliop::{self, dealer, prover_offline, verifier_offline, OfflineProver, OfflineVerifier},
};

use super::{
    bristol_fashion::{ParsedCircuit, ParsedGate},
    semi_honest::{BeaverTriple, Mask, OfflineSemiHonestCorrelation},
};

#[derive(Debug)]
enum InputWireCoefficients<const PACKING: usize, F: FieldElement> {
    And([F; PACKING], [F; PACKING]),
    WideAnd([F; PACKING], [[F; 128]; PACKING]),
}

#[derive(Debug)]
enum GateGamma<const PACKING: usize, F: FieldElement> {
    And([F; PACKING]),
    WideAnd([[F; 128]; PACKING]),
}

fn compute_gammas_alphas<
    const PACKING: usize,
    F: FieldElement,
    PF: PackedField<impl FieldElement, PACKING>,
>(
    alpha: &[u8; 16],
    circuit: &ParsedCircuit,
) -> (
    Vec<(usize, usize, InputWireCoefficients<PACKING, F>)>,
    Vec<(usize, usize, GateGamma<PACKING, F>)>,
    Vec<[F; PACKING]>,
    Vec<[F; PACKING]>,
    F,
) {
    let mut rng = AesRng::from_seed(*alpha);
    let layer_seeds: Vec<_> = (0..circuit.gates.len())
        .map(|_| {
            let mut s = [0u8; 16];
            rng.fill_bytes(&mut s);
            s
        })
        .collect();
    let alpha = *alpha;
    let mut alphas = Vec::<(usize, usize, InputWireCoefficients<PACKING, F>)>::new();
    let mut gammas = Vec::<(usize, usize, GateGamma<PACKING, F>)>::new();

    let mut weights_per_wire =
        vec![
            [F::zero(); PACKING];
            circuit.input_wire_count + circuit.output_wire_count + circuit.internal_wire_count
        ];
    // We first distribute alphas to output wires.
    let output_wires =
        &mut weights_per_wire[circuit.input_wire_count + circuit.internal_wire_count..];
    for v in output_wires.iter_mut() {
        for p in 0..PACKING {
            v[p] = F::random(&mut rng);
        }
    }
    let output_wire_threshold = circuit.input_wire_count + circuit.internal_wire_count;
    let alphas_outputs: Vec<_> = output_wires.iter().map(|a| *a).collect();

    // Next, distribute alphas for the relevant gates' input wires.
    circuit
        .gates
        .iter()
        .enumerate()
        .zip(layer_seeds.into_iter())
        .for_each(|((layer_idx, layer), alpha)| {
            let mut rng = AesRng::from_seed(alpha);
            for (gate_idx, gate) in layer.iter().enumerate() {
                let c = match gate {
                    ParsedGate::AndGate { input, output: _ } => {
                        let mut a: [F; PACKING] = unsafe {
                            MaybeUninit::array_assume_init(MaybeUninit::<F>::uninit_array())
                        };
                        let mut b: [F; PACKING] = unsafe {
                            MaybeUninit::array_assume_init(MaybeUninit::<F>::uninit_array())
                        };
                        for i in 0..PACKING {
                            a[i] = F::random(&mut rng);
                            b[i] = F::random(&mut rng);
                            weights_per_wire[input[0]][i] += a[i];
                            weights_per_wire[input[1]][i] += b[i];
                        }
                        InputWireCoefficients::And(a, b)
                    }
                    ParsedGate::WideAndGate {
                        input,
                        input_bit,
                        output: _,
                    } => {
                        let mut bits: [F; PACKING] = unsafe {
                            MaybeUninit::array_assume_init(MaybeUninit::<F>::uninit_array())
                        };
                        let mut wides: [[F; 128]; PACKING] = unsafe {
                            MaybeUninit::array_assume_init(MaybeUninit::<[F; 128]>::uninit_array())
                        };
                        for pack in 0..PACKING {
                            let bit_coefficient = F::random(&mut rng);
                            bits[pack] = bit_coefficient;
                            weights_per_wire[*input_bit][pack] += bit_coefficient;
                            let wide_coefficents: [F; 128] = core::array::from_fn(|i| {
                                let cur = F::random(&mut rng);
                                weights_per_wire[input[i]][pack] += cur;
                                cur
                            });
                            wides[pack] = wide_coefficents;
                        }
                        InputWireCoefficients::WideAnd(bits, wides)
                    }
                    _ => continue,
                };
                alphas.push((layer_idx, gate_idx, c));
            }
        });

    let mut total_constant_addition: F = F::zero();
    // Propagate alphas to compute gammas.
    for (layer_idx, layer) in circuit.gates.iter().enumerate().rev() {
        for (gate_idx, gate) in layer.iter().enumerate().rev() {
            match gate {
                ParsedGate::XorGate { input, output } => {
                    let out = weights_per_wire[*output];
                    let v = &mut weights_per_wire[input[0]];
                    for i in 0..PACKING {
                        v[i] += out[i];
                    }
                    let v = &mut weights_per_wire[input[1]];
                    for i in 0..PACKING {
                        v[i] += out[i];
                    }
                }
                ParsedGate::NotGate { input, output } => {
                    let v_output = weights_per_wire[*output];
                    for i in 0..PACKING {
                        weights_per_wire[*input][i] += v_output[i];
                        total_constant_addition += v_output[i];
                    }
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
                    let g = GateGamma::WideAnd(core::array::from_fn(|pack| {
                        core::array::from_fn(|i| weights_per_wire[output[i]][pack])
                    }));
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
fn compute_gamma_i<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement,
    F: FieldElement + From<CF>,
>(
    gammas: &[(usize, usize, GateGamma<PACKING, F>)],
    mask_shares: &HashMap<(usize, usize), BeaverTriple<PF>>,
    masked_values: &HashMap<(usize, usize), Mask<PF>>,
) -> F {
    gammas
        .iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = mask_shares.get(&(*layer_idx, *gate_idx)).unwrap();
            let masked_values = masked_values.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask, masked_values) {
                (
                    GateGamma::And(g),
                    BeaverTriple::Regular(RegularBeaverTriple(m_a, m_b, _)),
                    Mask::And(v_a, v_b),
                ) => {
                    let bit = *m_a * *v_b + *v_a * *m_b;
                    (0..PACKING)
                        .map(|pack| g[pack] * F::from(bit.get_element(pack)))
                        .sum()
                }
                (
                    GateGamma::WideAnd(g),
                    BeaverTriple::Wide(WideBeaverTriple(m_a, m_wb, _)),
                    Mask::WideAnd(v_a, v_wb),
                ) => {
                    let mut sum = F::zero();
                    for pack in 0..PACKING {
                        for i in 0..g.len() {
                            // sum += g[i] * F::from(bits[i]);
                            sum += g[pack][i]
                                * F::from(
                                    m_wb[i].get_element(pack) * v_a.get_element(pack)
                                        + v_wb[i].get_element(pack) * m_a.get_element(pack),
                                );
                        }
                    }
                    sum
                }
                _ => panic!(),
            }
        })
        .sum()
}
fn dot_product_gamma<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement,
    F: FieldElement + From<CF>,
>(
    gammas: &[(usize, usize, GateGamma<PACKING, F>)],
    masks_gates: &HashMap<(usize, usize), Mask<PF>>,
    input_wires_gammas: &[[F; PACKING]],
    input_wires_masks: &[PF],
) -> F {
    let input_dp: F = input_wires_gammas
        .iter()
        .zip(input_wires_masks.iter())
        .map(|(a, b)| {
            (0..PACKING)
                .map(|pack| a[pack] * F::from(b.get_element(pack)))
                .sum()
        })
        .sum();
    let gates_dp = gammas
        .iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = masks_gates.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask) {
                (GateGamma::And(g), Mask::And(m_a, m_b)) => {
                    let m_a_m_b = *m_a * *m_b;
                    (0..PACKING)
                        .map(|pack| g[pack] * F::from(m_a_m_b.get_element(pack)))
                        .sum()
                }
                (GateGamma::WideAnd(g), Mask::WideAnd(m_a, m_wb)) => {
                    let mut sum = F::zero();
                    for i in 0..g.len() {
                        let m_a_m_b = m_wb[i] * *m_a;
                        for pack in 0..PACKING {
                            // sum += g[pack][i] * F::from(m_wb[i] * *m_a);
                            sum += g[pack][i] * F::from(m_a_m_b.get_element(pack));
                        }
                    }
                    sum
                }
                _ => panic!(),
            }
        })
        .sum();
    input_dp + gates_dp
}
fn dot_product_alpha<
    const N: usize,
    CF: FieldElement,
    F: FieldElement + From<CF>,
    PF: PackedField<CF, N>,
>(
    alphas_gate: &[(usize, usize, InputWireCoefficients<N, F>)],
    alphas_outputs: &[[F; N]],
    masks_gates: &HashMap<(usize, usize), Mask<PF>>,
    masks_outputs: &[PF],
) -> F {
    // Sigma alpha_w r_w
    let sigma_alpha_w_r_w_gates: F = alphas_gate
        .iter()
        .map(|(layer_id, gate_id, input_wire_coefficients)| {
            let mask = masks_gates.get(&(*layer_id, *gate_id)).unwrap();
            match (mask, input_wire_coefficients) {
                (Mask::And(a, b), InputWireCoefficients::And(c_a, c_b)) => {
                    (0..N)
                        .map(|i| {
                            c_a[i] * F::from(a.get_element(i)) + c_b[i] * F::from(b.get_element(i))
                        })
                        .sum()
                    // * c_a * F::from(*a) + *c_b * F::from(*b)
                }
                (Mask::WideAnd(a, wb), InputWireCoefficients::WideAnd(c_a, c_wb)) => {
                    let mut sum = F::zero();
                    for pack in 0..N {
                        sum += c_a[pack] * F::from(a.get_element(pack));
                        for i in 0..c_wb.len() {
                            sum += c_wb[pack][i] * F::from(wb[i].get_element(pack));
                        }
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
        .map(|(u, v)| {
            (0..N)
                .map(|pack| u[pack] * F::from(v.get_element(pack)))
                .sum()
        })
        .sum();
    sigma_alpha_w_r_w_gates + sigma_alpha_w_r_w_outputs
}
pub fn statement_length<const PACK: usize>(circuit: &ParsedCircuit) -> usize {
    let mut statement_length: usize = circuit
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
    statement_length *= PACK;
    let statement_length = (1 << (usize::ilog2(2 * statement_length - 1))) as usize;
    usize::try_from(1 + statement_length).unwrap()
}
fn construct_statement<
    const N: usize,
    PF: PackedField<CF, N>,
    CF: FieldElement,
    F: FieldElement + From<CF>,
>(
    masked_gamma_i: Option<F>,
    gamma_i_mask: Option<F>,
    gate_gammas: &[(usize, usize, GateGamma<N, F>)],
    masked_inputs: Option<&HashMap<(usize, usize), Mask<PF>>>,
    mask_shares: Option<&HashMap<(usize, usize), BeaverTriple<PF>>>,
    circuit: &ParsedCircuit,
) -> Vec<F> {
    let statement_length: usize = statement_length::<N>(circuit);
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
                BeaverTriple::Regular(RegularBeaverTriple(m_a, m_b, _)) => {
                    for i in 0..N {
                        *iter_masks.next().unwrap() = F::from(m_b.get_element(i));
                        *iter_masks.next().unwrap() = F::from(m_a.get_element(i));
                    }
                }
                BeaverTriple::Wide(WideBeaverTriple(m_a, m_wb, _)) => {
                    for pack in 0..N {
                        let v_a = F::from(m_a.get_element(pack));
                        for i in 0..128 {
                            *iter_masks.next().unwrap() = m_wb[i].get_element(pack).into();
                            *iter_masks.next().unwrap() = v_a;
                        }
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
                    for pack in 0..N {
                        *iter_masked_values.next().unwrap() =
                            g[pack] * F::from(m_a.get_element(pack));
                        *iter_masked_values.next().unwrap() =
                            g[pack] * F::from(m_b.get_element(pack));
                    }
                }
                (Mask::WideAnd(m_a, m_wb), GateGamma::WideAnd(gs)) => {
                    for pack in 0..N {
                        let v_a = F::from(m_a.get_element(pack));
                        for i in 0..gs.len() {
                            *iter_masked_values.next().unwrap() = gs[pack][i] * v_a;
                            *iter_masked_values.next().unwrap() =
                                gs[pack][i] * F::from(m_wb[i].get_element(pack));
                        }
                    }
                }
                _ => panic!(),
            }
        }
    }

    statement
}

#[derive(Clone)]
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

pub async fn verify_parties<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement,
    F: FieldElement + From<CF>,
    E: MultiPartyEngine,
>(
    engine: &mut E,
    two: F,
    three: F,
    four: F,
    input_wire_masked_values: &[PF],
    masked_values: &HashMap<(usize, usize), Mask<PF>>,
    masks_shares: &HashMap<(usize, usize), BeaverTriple<PF>>,
    output_wire_masked_values: &[PF],
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
    let timer = Instant::now();
    let prover_offline_material = prover_offline_material.clone();
    let (alpha, omega_hat): ([u8; 16], F) = alpha_omega_commitment.online_decommit(engine).await;
    println!(
        "\t\tVerify - cloning and decommit took: {}ms",
        timer.elapsed().as_millis()
    );
    // Length of alphas is the total number of output wires + input wires to AND gates.
    // In case of fan out > 1 impose scenarios where the same wire is fed into multiple different wires.
    // We therefore have to "change" the representation of the circuit in a deterministic way so that each wire fed into a multiplication / output wire has a different idx.

    let timer = Instant::now();
    let (alphas, gammas, alphas_output_wires, gammas_input_wires, total_constant_addition) =
        compute_gammas_alphas::<PACKING, _, PF>(&alpha, circuit);
    println!(
        "\t\tVerify - compute gammas alphas took: {}ms",
        timer.elapsed().as_millis()
    );
    let timer = Instant::now();
    // Compute Lambda
    let alpha_x_hat = dot_product_alpha(
        &alphas,
        &alphas_output_wires,
        masked_values,
        output_wire_masked_values,
    );
    let gamma_x_hat = dot_product_gamma(
        &gammas,
        &masked_values,
        &gammas_input_wires,
        input_wire_masked_values,
    );

    let lambda = alpha_x_hat - gamma_x_hat - total_constant_addition;

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
    println!(
        "\t\tVerify - Compute and obtain gammas: {}ms",
        timer.elapsed().as_millis()
    );
    let timer = Instant::now();
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
    println!(
        "\t\tVerify - Statements Construction: {}ms",
        timer.elapsed().as_millis()
    );
    let sub_engine = engine.sub_protocol(my_id);
    let prover_futures = tokio::spawn(async move {
        let prover_offline_material = prover_offline_material;
        let timer = Instant::now();
        zkfliop::prover(
            sub_engine,
            &mut proof_statement,
            &prover_offline_material,
            two,
            three,
            four,
        )
        .await;
        println!("\t\tVerify - Proving took: {}", timer.elapsed().as_millis());
    });

    let verifiers_futures =
        verifiers_offline_material
            .into_iter()
            .map(|(prover_id, offline_material)| {
                let timer = Instant::now();
                let offline_material = offline_material.clone();
                let verifier_engine = engine.sub_protocol(prover_id);
                let verify_statement_arc = verify_statement.clone();
                let masked_gamma_prover = *masked_gamma_i_s.get(&prover_id).unwrap();
                let prover_id = *prover_id;
                println!(
                    "\t\tVerify - Making preparations to verify: {}ms",
                    timer.elapsed().as_millis()
                );
                tokio::spawn(async move {
                    // We only modify the first entry (the masked Gamma_i) in the verifying statement.
                    let mut z_hat = verify_statement_arc.as_ref().clone();
                    z_hat[0] = masked_gamma_prover;
                    let timer = Instant::now();
                    zkfliop::verifier(
                        verifier_engine,
                        &mut z_hat,
                        prover_id,
                        &offline_material,
                        two,
                        three,
                        four,
                    )
                    .await;
                    println!(
                        "\t\tVerify - zkfliop verifier took: {}",
                        timer.elapsed().as_millis()
                    );
                    Result::<(), ()>::Ok(())
                })
            });
    let verifiers_futures = try_join_all(verifiers_futures);
    let (_, verifiers_futures) = join!(prover_futures, verifiers_futures);
    verifiers_futures.unwrap();
    let timer = Instant::now();
    let s = s_commitment.online_decommit(engine).await;
    let p = p_hat + s;
    println!(
        "\t\tVerify - last communication round took: {}ms",
        timer.elapsed().as_millis()
    );
    return p.is_zero();
}

pub async fn offline_verify_dealer<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement,
    F: FieldElement + From<CF>,
    E: MultiPartyEngine,
    SHO: OfflineSemiHonestCorrelation<PF>,
>(
    mut engine: E,
    two: F,
    three: F,
    four: F,
    circuit: &ParsedCircuit,
    total_input_wires_masks: &[PF],
    total_output_wires_masks: &[PF],
    sho: &[(PartyId, SHO)],
) {
    let mut rng = E::rng();
    let mut alpha = [0u8; 16];
    rng.fill_bytes(&mut alpha);
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
            engine.send(si, *pid);
            (*pid, si)
        })
        .collect();

    let mut per_party_gate_input_wires_masks = HashMap::with_capacity(parties.len());
    // let mut per_party_input_and_output_wires_masks = HashMap::with_capacity(mask_seeds.len());
    let total_gates: usize = circuit
        .gates
        .iter()
        .map(|layer| layer.iter().filter(|gate| !gate.is_linear()).count())
        .sum();
    let mut total_gate_input_masks = Vec::with_capacity(total_gates);
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
                    } => Mask::And(PF::zero(), PF::zero()),
                    ParsedGate::WideAndGate {
                        input: _,
                        input_bit: _,
                        output: _,
                    } => Mask::WideAnd(PF::zero(), [PF::zero(); 128]),
                    _ => return,
                };
                total_gate_input_masks.push(((layer_idx, gate_idx), zero_mask));
            })
        });
    for (pid, sho) in sho {
        let gate_input_masks = sho.get_gates_input_wires_masks(circuit);
        debug_assert_eq!(gate_input_masks.len(), total_gate_input_masks.len());
        total_gate_input_masks
            .iter_mut()
            .zip(gate_input_masks.iter())
            .for_each(|(a, b)| {
                debug_assert_eq!(a.0, b.0);
                match (a, b) {
                    ((_, Mask::And(total_a, total_b)), (_, Mask::And(current_a, current_b))) => {
                        *total_a += *current_a;
                        *total_b += *current_b;
                    }
                    (
                        (_, Mask::WideAnd(total_a, total_wb)),
                        (_, Mask::WideAnd(current_a, current_wb)),
                    ) => {
                        *total_a += *current_a;
                        for i in 0..total_wb.len() {
                            total_wb[i] += current_wb[i];
                        }
                    }
                    _ => panic!(),
                }
            });
        per_party_gate_input_wires_masks.insert(pid, gate_input_masks);
        // per_party_input_and_output_wires_masks.insert(pid, (input_wires_masks, output_wires_masks));
    }

    let (alphas, gammas, alphas_output_wires, gammas_inputs, total_constant_addition) =
        compute_gammas_alphas::<PACKING, _, PF>(&alpha, circuit);

    // Compute Omega
    let gates_input_wire_masks: HashMap<_, _> = total_gate_input_masks.iter().copied().collect();
    let mu = F::random(&mut rng);
    let alpha_r = dot_product_alpha::<PACKING, _, _, PF>(
        &alphas,
        &alphas_output_wires,
        &gates_input_wire_masks,
        total_output_wires_masks,
    );

    let sigma_gamma_l_r_l = dot_product_gamma(
        &gammas,
        &gates_input_wire_masks,
        &gammas_inputs,
        &total_input_wires_masks,
    );
    let omega = alpha_r + sigma_gamma_l_r_l;
    let omega_hat = omega - mu;
    let gammas_rc = Arc::new(gammas);

    OfflineCommitment::offline_commit(&mut engine, &(alpha, omega_hat)).await;
    let s = mu - si_s.values().copied().sum();
    OfflineCommitment::offline_commit(&mut engine, &s).await;
    let dealer_offline_futures: Vec<_> = parties
        .into_iter()
        .map(|prover_id| {
            let gate_masks = per_party_gate_input_wires_masks.remove(&prover_id).unwrap();
            let si = *si_s.get(&prover_id).unwrap();
            let gamma_rc = gammas_rc.clone();
            let engine = engine.sub_protocol(prover_id);
            async move {
                let gammas = gamma_rc.as_ref();
                let mask_shares: HashMap<_, _> = gate_masks
                    .into_iter()
                    .map(|((l, g), m)| {
                        let m = match m {
                            Mask::And(a, b) => {
                                BeaverTriple::Regular(RegularBeaverTriple(a, b, PF::zero()))
                            }
                            Mask::WideAnd(a, wb) => {
                                BeaverTriple::Wide(WideBeaverTriple(a, wb, [PF::zero(); 128]))
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
}
