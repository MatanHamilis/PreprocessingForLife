use std::{collections::HashMap, ops::Mul, sync::Arc};

use crate::{
    fields::GF2,
    zkfliop::{
        ni::{hash_statement, prove, ZkFliopProof},
        PowersIterator,
    },
};
use aes_prng::AesRng;
use blake3::Hash;
use futures::{future::try_join_all, join};
use log::info;
use rand_core::SeedableRng;
use rayon::{prelude::*, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    commitment::OfflineCommitment,
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, PackedField},
    pcg::{RegularBeaverTriple, WideBeaverTriple},
    zkfliop::{self, dealer, OfflineProver, OfflineVerifier},
};

use super::{
    bristol_fashion::{ParsedCircuit, ParsedGate},
    semi_honest::{
        construct_statement_from_bts, OfflineSemiHonestCorrelation, RegularMask, WideMask,
    },
};

#[derive(Debug)]
pub struct RegularInputWireCoefficient<const PACKING: usize, F: FieldElement>(
    [F; PACKING],
    [F; PACKING],
);
#[derive(Debug)]
pub struct WideInputWireCoefficient<const PACKING: usize, F: FieldElement>(
    [F; PACKING],
    [[F; 128]; PACKING],
);

#[derive(Debug)]
pub struct RegularGateGamma<const PACKING: usize, F: FieldElement>([F; PACKING]);
#[derive(Debug)]
pub struct WideGateGamma<const PACKING: usize, F: FieldElement>([[F; 128]; PACKING]);

fn compute_gammas_alphas<
    const PACKING: usize,
    F: FieldElement,
    PF: PackedField<impl FieldElement, PACKING>,
>(
    alpha: &F,
    circuit: &ParsedCircuit,
) -> (
    Vec<(usize, usize, RegularInputWireCoefficient<PACKING, F>)>,
    Vec<(usize, usize, WideInputWireCoefficient<PACKING, F>)>,
    Vec<(usize, usize, RegularGateGamma<PACKING, F>)>,
    Vec<(usize, usize, WideGateGamma<PACKING, F>)>,
    Vec<[F; PACKING]>,
    Vec<[F; PACKING]>,
    F,
) {
    let mut rng = PowersIterator::new(*alpha);
    let non_linear_gates = circuit.total_non_linear_gates();
    let mut alphas = Vec::<(usize, usize, RegularInputWireCoefficient<PACKING, F>)>::with_capacity(
        non_linear_gates,
    );
    let mut wide_alphas = Vec::<(usize, usize, WideInputWireCoefficient<PACKING, F>)>::new();
    let mut gammas =
        Vec::<(usize, usize, RegularGateGamma<PACKING, F>)>::with_capacity(non_linear_gates);
    let mut wide_gammas =
        Vec::<(usize, usize, WideGateGamma<PACKING, F>)>::with_capacity(non_linear_gates);

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
            v[p] = rng.next().unwrap();
        }
    }
    let alphas_outputs: Vec<_> = output_wires.iter().map(|a| *a).collect();

    let time = Instant::now();
    // Next, distribute alphas for the relevant gates' input wires.
    circuit
        .gates
        .iter()
        .enumerate()
        .for_each(|(layer_idx, layer)| {
            for (gate_idx, gate) in layer.iter().enumerate() {
                match gate {
                    ParsedGate::AndGate { input, output: _ } => {
                        let a = core::array::from_fn(|_| rng.next().unwrap());
                        let b = core::array::from_fn(|_| rng.next().unwrap());
                        for i in 0..PACKING {
                            weights_per_wire[input[0]][i] += a[i];
                            weights_per_wire[input[1]][i] += b[i];
                        }
                        alphas.push((layer_idx, gate_idx, RegularInputWireCoefficient(a, b)));
                    }
                    ParsedGate::WideAndGate {
                        input,
                        input_bit,
                        output: _,
                    } => {
                        let bits: [F; PACKING] = core::array::from_fn(|_| rng.next().unwrap());
                        let wides: [[F; 128]; PACKING] =
                            core::array::from_fn(|_| core::array::from_fn(|_| rng.next().unwrap()));
                        for pack in 0..PACKING {
                            weights_per_wire[*input_bit][pack] += bits[pack];
                            for i in 0..128 {
                                weights_per_wire[input[i]][pack] += wides[pack][i];
                            }
                        }
                        wide_alphas.push((
                            layer_idx,
                            gate_idx,
                            WideInputWireCoefficient(bits, wides),
                        ));
                    }
                    _ => continue,
                };
            }
        });
    info!(
        "\t\tVerify - Alphas initialization: {}ms",
        time.elapsed().as_millis()
    );

    let mut total_constant_addition: F = F::zero();
    let time = Instant::now();
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
                        RegularGateGamma(weights_per_wire[*output]),
                    ));
                }
                ParsedGate::WideAndGate {
                    input: _,
                    input_bit: _,
                    output,
                } => {
                    let g = WideGateGamma(core::array::from_fn(|pack| {
                        core::array::from_fn(|i| weights_per_wire[output[i]][pack])
                    }));
                    wide_gammas.push((layer_idx, gate_idx, g));
                }
            }
        }
    }
    info!(
        "\t\tVerify: Propagation took: {}ms",
        time.elapsed().as_millis()
    );
    let gammas_inputs_wires = weights_per_wire[..circuit.input_wire_count].to_vec();
    (
        alphas,
        wide_alphas,
        gammas,
        wide_gammas,
        alphas_outputs,
        gammas_inputs_wires,
        total_constant_addition,
    )
}
fn compute_gamma_i<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement + Mul<F, Output = F>,
    F: FieldElement + From<CF>,
>(
    gammas: &[(usize, usize, RegularGateGamma<PACKING, F>)],
    wide_gammas: &[(usize, usize, WideGateGamma<PACKING, F>)],
    mask_shares: &HashMap<(usize, usize), RegularBeaverTriple<PF>>,
    wide_mask_shares: &HashMap<(usize, usize), WideBeaverTriple<PF>>,
    masked_values: &HashMap<(usize, usize), RegularMask<PF>>,
    wide_masked_values: &HashMap<(usize, usize), WideMask<PF>>,
) -> F {
    let regular: F = gammas
        .par_iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = mask_shares.get(&(*layer_idx, *gate_idx)).unwrap();
            let masked_values = masked_values.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask, masked_values) {
                (RegularGateGamma(g), RegularBeaverTriple(m_a, m_b, _), RegularMask(v_a, v_b)) => {
                    let bit = *m_a * *v_b + *v_a * *m_b;
                    (0..PACKING)
                        .map(|pack| bit.get_element(pack) * g[pack])
                        .sum()
                }
            }
        })
        .sum();
    let wide: F = wide_gammas
        .par_iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = wide_mask_shares.get(&(*layer_idx, *gate_idx)).unwrap();
            let masked_values = wide_masked_values.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask, masked_values) {
                (WideGateGamma(g), WideBeaverTriple(m_a, m_wb, _), WideMask(v_a, v_wb)) => {
                    let mut sum = F::zero();
                    for pack in 0..PACKING {
                        for i in 0..g.len() {
                            // sum += g[i] * F::from(bits[i]);
                            sum += (m_wb[i].get_element(pack) * v_a.get_element(pack)
                                + v_wb[i].get_element(pack) * m_a.get_element(pack))
                                * g[pack][i]
                        }
                    }
                    sum
                }
            }
        })
        .sum();
    regular + wide
}
fn dot_product_gamma<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement + Mul<F, Output = F>,
    F: FieldElement + From<CF>,
>(
    gammas: &[(usize, usize, RegularGateGamma<PACKING, F>)],
    wide_gammas: &[(usize, usize, WideGateGamma<PACKING, F>)],
    masks_gates: &HashMap<(usize, usize), RegularMask<PF>>,
    wide_masks_gates: &HashMap<(usize, usize), WideMask<PF>>,
    input_wires_gammas: &[[F; PACKING]],
    input_wires_masks: &[PF],
) -> F {
    let input_dp: F = input_wires_gammas
        .par_iter()
        .zip(input_wires_masks.par_iter())
        .map(|(a, b)| (0..PACKING).map(|pack| b.get_element(pack) * a[pack]).sum())
        .sum();
    let regular_gates_dp = gammas
        .par_iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = masks_gates.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask) {
                (RegularGateGamma(g), RegularMask(m_a, m_b)) => {
                    let m_a_m_b = *m_a * *m_b;
                    (0..PACKING)
                        .map(|pack| m_a_m_b.get_element(pack) * g[pack])
                        .sum()
                }
            }
        })
        .sum();
    let wides_gates_dp = wide_gammas
        .par_iter()
        .map(|(layer_idx, gate_idx, gamma)| {
            let mask = wide_masks_gates.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gamma, mask) {
                (WideGateGamma(g), WideMask(m_a, m_wb)) => {
                    let mut sum = F::zero();
                    for i in 0..g.len() {
                        let m_a_m_b = m_wb[i] * *m_a;
                        for pack in 0..PACKING {
                            // sum += g[pack][i] * F::from(m_wb[i] * *m_a);
                            sum += m_a_m_b.get_element(pack) * g[pack][i];
                        }
                    }
                    sum
                }
            }
        })
        .sum();
    input_dp + regular_gates_dp + wides_gates_dp
}
fn dot_product_alpha<
    const N: usize,
    CF: FieldElement + Mul<F, Output = F>,
    F: FieldElement + From<CF>,
    PF: PackedField<CF, N>,
>(
    alphas_gate: &[(usize, usize, RegularInputWireCoefficient<N, F>)],
    wide_alphas_gate: &[(usize, usize, WideInputWireCoefficient<N, F>)],
    alphas_outputs: &[[F; N]],
    regular_masks_gates: &HashMap<(usize, usize), RegularMask<PF>>,
    wide_masks_gates: &HashMap<(usize, usize), WideMask<PF>>,
    masks_outputs: &[PF],
) -> F {
    // Sigma alpha_w r_w
    let regular_sigma_alpha_w_r_w_gates: F = alphas_gate
        .par_iter()
        .map(|(layer_id, gate_id, input_wire_coefficients)| {
            let mask = regular_masks_gates.get(&(*layer_id, *gate_id)).unwrap();
            match (mask, input_wire_coefficients) {
                (RegularMask(a, b), RegularInputWireCoefficient(c_a, c_b)) => {
                    (0..N)
                        .map(|i| a.get_element(i) * c_a[i] + b.get_element(i) * c_b[i])
                        .sum()
                    // * c_a * F::from(*a) + *c_b * F::from(*b)
                }
            }
        })
        .sum();
    let wide_sigma_alpha_w_r_w_gates: F = wide_alphas_gate
        .par_iter()
        .map(|(layer_id, gate_id, input_wire_coefficients)| {
            let mask = wide_masks_gates.get(&(*layer_id, *gate_id)).unwrap();
            match (mask, input_wire_coefficients) {
                (WideMask(a, wb), WideInputWireCoefficient(c_a, c_wb)) => {
                    let mut sum = F::zero();
                    for pack in 0..N {
                        sum += a.get_element(pack) * c_a[pack];
                        for i in 0..c_wb.len() {
                            sum += wb[i].get_element(pack) * c_wb[pack][i];
                        }
                    }
                    sum
                }
            }
        })
        .sum();
    let sigma_alpha_w_r_w_outputs: F = alphas_outputs
        .par_iter()
        .zip(masks_outputs.par_iter())
        .map(|(u, v)| (0..N).map(|pack| v.get_element(pack) * u[pack]).sum())
        .sum();
    wide_sigma_alpha_w_r_w_gates + regular_sigma_alpha_w_r_w_gates + sigma_alpha_w_r_w_outputs
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
    CF: FieldElement + Mul<F, Output = F>,
    F: FieldElement + From<CF>,
>(
    masked_gamma_i: Option<F>,
    gamma_i_mask: Option<F>,
    regular_gate_gammas: &[(usize, usize, RegularGateGamma<N, F>)],
    wide_gate_gammas: &[(usize, usize, WideGateGamma<N, F>)],
    regular_masked_inputs: Option<&HashMap<(usize, usize), RegularMask<PF>>>,
    wide_masked_inputs: Option<&HashMap<(usize, usize), WideMask<PF>>>,
    regular_mask_shares: Option<&HashMap<(usize, usize), RegularBeaverTriple<PF>>>,
    wide_mask_shares: Option<&HashMap<(usize, usize), WideBeaverTriple<PF>>>,
    circuit: &ParsedCircuit,
) -> Vec<F> {
    let statement_length: usize = statement_length::<N>(circuit);
    // We create a statement of size that is 1 + power of 2.
    let mut statement = vec![F::zero(); statement_length];

    // Initialize first entry
    statement[0] = masked_gamma_i.unwrap_or(F::zero()) + gamma_i_mask.unwrap_or(F::zero());

    let mut iter_masks = statement.iter_mut().skip(2).step_by(2);

    // Initialize mask shares
    if regular_mask_shares.is_none() {
        iter_masks.for_each(|v| *v = F::zero());
    } else {
        let gate_masks = regular_mask_shares.unwrap();
        for (layer_idx, gate_idx, _) in regular_gate_gammas {
            let gate_mask = gate_masks.get(&(*layer_idx, *gate_idx)).unwrap();
            match gate_mask {
                RegularBeaverTriple(m_a, m_b, _) => {
                    for i in 0..N {
                        *iter_masks.next().unwrap() = F::from(m_b.get_element(i));
                        *iter_masks.next().unwrap() = F::from(m_a.get_element(i));
                    }
                }
            }
        }
        let gate_masks = wide_mask_shares.unwrap();
        for (layer_idx, gate_idx, _) in wide_gate_gammas {
            let gate_mask = gate_masks.get(&(*layer_idx, *gate_idx)).unwrap();
            match gate_mask {
                WideBeaverTriple(m_a, m_wb, _) => {
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
    if regular_masked_inputs.is_none() {
        iter_masked_values.for_each(|v| *v = F::zero());
    } else {
        let gate_masked_inputs = regular_masked_inputs.unwrap();
        for (layer_idx, gate_idx, gate_gamma) in regular_gate_gammas {
            let gate_mask_input = gate_masked_inputs.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gate_mask_input, gate_gamma) {
                (RegularMask(m_a, m_b), RegularGateGamma(g)) => {
                    for pack in 0..N {
                        *iter_masked_values.next().unwrap() = m_a.get_element(pack) * g[pack];
                        *iter_masked_values.next().unwrap() = m_b.get_element(pack) * g[pack];
                    }
                }
            }
        }
        let gate_masked_inputs = wide_masked_inputs.unwrap();
        for (layer_idx, gate_idx, gate_gamma) in wide_gate_gammas {
            let gate_mask_input = gate_masked_inputs.get(&(*layer_idx, *gate_idx)).unwrap();
            match (gate_mask_input, gate_gamma) {
                (WideMask(m_a, m_wb), WideGateGamma(gs)) => {
                    for pack in 0..N {
                        let v_a = m_a.get_element(pack);
                        for i in 0..gs.len() {
                            *iter_masked_values.next().unwrap() = v_a * gs[pack][i];
                            *iter_masked_values.next().unwrap() =
                                m_wb[i].get_element(pack) * gs[pack][i];
                        }
                    }
                }
            }
        }
    }

    statement
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OfflineCircuitVerify<F: FieldElement> {
    #[serde(bound = "")]
    s_i: F,
    alpha_omega_commitment: OfflineCommitment,
    s_commitment: OfflineCommitment,
    #[serde(bound = "")]
    verifiers_offline_material: Vec<(PartyId, OfflineVerifier)>,
    #[serde(bound = "")]
    prover_offline_material: OfflineProver<F>,
}

pub async fn verify_parties<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement + Mul<F, Output = F>,
    F: FieldElement + From<CF>,
    E: MultiPartyEngine,
>(
    engine: &mut E,
    two: F,
    three: F,
    four: F,
    input_wire_masked_values: &[PF],
    regular_masked_values: &HashMap<(usize, usize), RegularMask<PF>>,
    wide_masked_values: &HashMap<(usize, usize), WideMask<PF>>,
    regular_masks_shares: &HashMap<(usize, usize), RegularBeaverTriple<PF>>,
    wide_masks_shares: &HashMap<(usize, usize), WideBeaverTriple<PF>>,
    output_wire_masked_values: &[PF],
    circuit: &ParsedCircuit,
    offline_material: &OfflineCircuitVerify<F>,
    auth_dealer: bool,
) -> bool {
    let thread_pool = ThreadPoolBuilder::new().build().unwrap();
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
    let (alpha, omega_hat): (F, F) = alpha_omega_commitment.online_decommit(engine).await;
    info!(
        "\t\tVerify - cloning and decommit took: {}ms",
        timer.elapsed().as_millis()
    );
    // Length of alphas is the total number of output wires + input wires to AND gates.
    // In case of fan out > 1 impose scenarios where the same wire is fed into multiple different wires.
    // We therefore have to "change" the representation of the circuit in a deterministic way so that each wire fed into a multiplication / output wire has a different idx.

    let timer = Instant::now();
    let (
        alphas,
        wide_alphas,
        gammas,
        wide_gammas,
        alphas_output_wires,
        gammas_input_wires,
        total_constant_addition,
    ) = compute_gammas_alphas::<PACKING, _, PF>(&alpha, circuit);
    info!(
        "\t\tVerify - compute gammas alphas took: {}ms",
        timer.elapsed().as_millis()
    );
    let timer = Instant::now();
    // Compute Lambda
    let alpha_x_hat = dot_product_alpha(
        &alphas,
        &wide_alphas,
        &alphas_output_wires,
        regular_masked_values,
        wide_masked_values,
        output_wire_masked_values,
    );
    let gamma_x_hat = dot_product_gamma(
        &gammas,
        &wide_gammas,
        &regular_masked_values,
        &wide_masked_values,
        &gammas_input_wires,
        input_wire_masked_values,
    );

    let lambda = alpha_x_hat - gamma_x_hat - total_constant_addition;

    // Compute Gamma_i
    let gamma_i = compute_gamma_i(
        &gammas,
        &wide_gammas,
        &regular_masks_shares,
        &wide_masks_shares,
        &regular_masked_values,
        &wide_masked_values,
    );
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
    info!(
        "\t\tVerify - Compute and obtain gammas: {}ms",
        timer.elapsed().as_millis()
    );
    let timer = Instant::now();
    let mut proof_statement = construct_statement(
        Some(masked_gamma_i),
        Some(*s_i),
        &gammas,
        &wide_gammas,
        Some(&regular_masked_values),
        Some(&wide_masked_values),
        Some(&regular_masks_shares),
        Some(&wide_masks_shares),
        circuit,
    );
    let dealer_statement = if auth_dealer {
        Some(construct_statement(
            None,
            Some(*s_i),
            &gammas,
            &wide_gammas,
            None,
            None,
            Some(&regular_masks_shares),
            Some(&wide_masks_shares),
            circuit,
        ))
    } else {
        None
    };
    let verify_statement = Arc::new(construct_statement(
        None,
        None,
        &gammas,
        &wide_gammas,
        Some(&regular_masked_values),
        Some(&wide_masked_values),
        None,
        None,
        circuit,
    ));
    info!(
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
            dealer_statement,
        )
        .await;
        info!("\t\tVerify - Proving took: {}", timer.elapsed().as_millis());
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
                info!(
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
                    info!(
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
    info!(
        "\t\tVerify - last communication round took: {}ms",
        timer.elapsed().as_millis()
    );
    return p.is_zero();
}

pub fn offline_verify_dealer<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    F: FieldElement + From<GF2>,
    SHO: OfflineSemiHonestCorrelation<PF>,
>(
    circuit: &ParsedCircuit,
    total_input_wires_masks: &[PF],
    total_output_wires_masks: &[PF],
    sho: &[(PartyId, SHO)],
    is_authenticated: bool,
) -> HashMap<
    PartyId,
    (
        OfflineCircuitVerify<F>,
        Option<HashMap<PartyId, ZkFliopProof<F>>>,
    ),
>
where
    GF2: Mul<F, Output = F>,
{
    let mut rng = AesRng::from_random_seed();
    let alpha = F::random(&mut rng);
    let parties: Vec<PartyId> = sho.iter().map(|v| v.0).collect();
    // Send s_i
    let si_s: HashMap<PartyId, F> = parties
        .iter()
        .map(|pid| {
            let si = F::random(&mut rng);
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
    let mut wide_total_gate_input_masks = Vec::new();
    circuit
        .gates
        .iter()
        .enumerate()
        .for_each(|(layer_idx, layer)| {
            layer.iter().enumerate().for_each(|(gate_idx, gate)| {
                match gate {
                    ParsedGate::AndGate {
                        input: _,
                        output: _,
                    } => total_gate_input_masks
                        .push(((layer_idx, gate_idx), RegularMask(PF::zero(), PF::zero()))),
                    ParsedGate::WideAndGate {
                        input: _,
                        input_bit: _,
                        output: _,
                    } => wide_total_gate_input_masks.push((
                        (layer_idx, gate_idx),
                        WideMask(PF::zero(), [PF::zero(); 128]),
                    )),
                    _ => return,
                };
            })
        });
    for (pid, sho) in sho {
        let (regular_gate_input_masks, wide_gate_input_masks) =
            sho.get_gates_input_wires_masks(circuit);
        debug_assert_eq!(regular_gate_input_masks.len(), total_gate_input_masks.len());
        total_gate_input_masks
            .iter_mut()
            .zip(regular_gate_input_masks.iter())
            .for_each(|(a, b)| {
                debug_assert_eq!(a.0, b.0);
                match (a, b) {
                    (
                        (_, RegularMask(total_a, total_b)),
                        (_, RegularMask(current_a, current_b)),
                    ) => {
                        *total_a += *current_a;
                        *total_b += *current_b;
                    }
                }
            });
        wide_total_gate_input_masks
            .iter_mut()
            .zip(wide_gate_input_masks.iter())
            .for_each(|(a, b)| {
                debug_assert_eq!(a.0, b.0);
                match (a, b) {
                    ((_, WideMask(total_a, total_wb)), (_, WideMask(current_a, current_wb))) => {
                        *total_a += *current_a;
                        for i in 0..total_wb.len() {
                            total_wb[i] += current_wb[i];
                        }
                    }
                }
            });
        per_party_gate_input_wires_masks
            .insert(pid, (regular_gate_input_masks, wide_gate_input_masks));
        // per_party_input_and_output_wires_masks.insert(pid, (input_wires_masks, output_wires_masks));
    }

    let (alphas, wide_alphas, gammas, wide_gammas, alphas_output_wires, gammas_inputs, _) =
        compute_gammas_alphas::<PACKING, _, PF>(&alpha, circuit);

    // Compute Omega
    let regular_gates_input_wire_masks: HashMap<_, _> =
        total_gate_input_masks.iter().copied().collect();
    let wide_gates_input_wire_masks: HashMap<_, _> =
        wide_total_gate_input_masks.iter().copied().collect();
    let mu = F::random(&mut rng);
    let alpha_r = dot_product_alpha::<PACKING, _, _, PF>(
        &alphas,
        &wide_alphas,
        &alphas_output_wires,
        &regular_gates_input_wire_masks,
        &wide_gates_input_wire_masks,
        total_output_wires_masks,
    );

    let sigma_gamma_l_r_l = dot_product_gamma(
        &gammas,
        &wide_gammas,
        &regular_gates_input_wire_masks,
        &wide_gates_input_wire_masks,
        &gammas_inputs,
        &total_input_wires_masks,
    );
    let omega = alpha_r + sigma_gamma_l_r_l;
    let omega_hat = omega - mu;
    let regular_gammas_rc = Arc::new(gammas);
    let wide_gammas_rc = Arc::new(wide_gammas);

    let (mut alpha_omega_commits, alpha_omega_hash) =
        OfflineCommitment::commit(&(alpha, omega_hat), parties.len());
    let s = mu - si_s.values().copied().sum();
    let (mut s_commit, s_hash) = OfflineCommitment::commit(&s, parties.len());
    let parties_num = parties.len();
    let mut parties_verifiers: HashMap<_, _> = parties
        .iter()
        .map(|p| (*p, Vec::with_capacity(parties_num - 1)))
        .collect();
    let mut offline_verifiers: HashMap<_, _> = parties
        .iter()
        .copied()
        .map(|prover_id| {
            let (regular_gate_masks, wide_gate_masks) =
                per_party_gate_input_wires_masks.remove(&prover_id).unwrap();
            let si = *si_s.get(&prover_id).unwrap();
            let regular_gamma_rc = regular_gammas_rc.clone();
            let wide_gammas_rc = wide_gammas_rc.clone();
            let regular_gammas = regular_gamma_rc.as_ref();
            let wide_gammas = wide_gammas_rc.as_ref();
            let regular_mask_shares: HashMap<_, _> = regular_gate_masks
                .into_iter()
                .map(|((l, g), m)| {
                    let m = match m {
                        RegularMask(a, b) => RegularBeaverTriple(a, b, PF::zero()),
                    };
                    ((l, g), m)
                })
                .collect();
            let wide_mask_shares: HashMap<_, _> = wide_gate_masks
                .into_iter()
                .map(|((l, g), m)| {
                    let m = match m {
                        WideMask(a, wb) => WideBeaverTriple(a, wb, [PF::zero(); 128]),
                    };
                    ((l, g), m)
                })
                .collect();
            let mut z_tilde = construct_statement(
                None,
                Some(si),
                &regular_gammas,
                &wide_gammas,
                None,
                None,
                Some(&regular_mask_shares),
                Some(&wide_mask_shares),
                circuit,
            );
            let (prover_correlation, verifiers_correlation) = dealer(&mut z_tilde, parties_num - 1);
            parties
                .iter()
                .filter(|v| *v != &prover_id)
                .zip(verifiers_correlation.into_iter())
                .for_each(|(pid, verifier_corr)| {
                    parties_verifiers
                        .get_mut(pid)
                        .unwrap()
                        .push((prover_id, verifier_corr))
                });
            (
                prover_id,
                (
                    OfflineCircuitVerify {
                        s_i: si,
                        alpha_omega_commitment: OfflineCommitment {
                            commit_share: alpha_omega_commits.pop().unwrap(),
                            commitment: alpha_omega_hash,
                        },
                        s_commitment: OfflineCommitment {
                            commit_share: s_commit.pop().unwrap(),
                            commitment: s_hash,
                        },
                        verifiers_offline_material: Vec::new(),
                        prover_offline_material: prover_correlation,
                    },
                    None,
                ),
            )
        })
        .collect();
    parties_verifiers.into_iter().for_each(|(pid, verifiers)| {
        offline_verifiers
            .get_mut(&pid)
            .unwrap()
            .0
            .verifiers_offline_material = verifiers;
    });
    if is_authenticated {
        let pairwise_triples: HashMap<_, _> = sho
            .iter()
            .map(|(pid, sho)| (*pid, sho.get_pairwise_triples(circuit)))
            .collect();
        let coin: F = sho
            .iter()
            .map(|sho| {
                let hash_correlation = sho.1.hash_correlation();
                let hash_correlation: [u8; 16] = core::array::from_fn(|i| hash_correlation[i]);
                let mut rng = AesRng::from_seed(hash_correlation);
                F::random(&mut rng)
            })
            .sum();
        let mut proofs: HashMap<PartyId, HashMap<PartyId, ZkFliopProof<F>>> = parties
            .iter()
            .copied()
            .map(|pid| (pid, HashMap::new()))
            .collect();
        for i in 0..parties.len() {
            let pi = parties[i];
            for j in 0..i {
                let pj = parties[j];
                let (reg_ci, wide_ci) = pairwise_triples.get(&pi).unwrap();
                let (reg_ci, wide_ci) = (reg_ci.get(&pj).unwrap(), wide_ci.get(&pj).unwrap());
                let (reg_cj, wide_cj) = pairwise_triples.get(&pj).unwrap();
                let (reg_cj, wide_cj) = (reg_cj.get(&pi).unwrap(), wide_cj.get(&pi).unwrap());
                let stmt_i = construct_statement_from_bts(&reg_ci, &wide_ci, coin);
                let stmt_j = construct_statement_from_bts(&reg_cj, &wide_cj, coin);
                let stmt: Vec<F> = stmt_i
                    .iter()
                    .copied()
                    .zip(stmt_j.iter().copied())
                    .map(|(i, j)| i + j)
                    .collect();
                let parties_stmts = [stmt_i, stmt_j];
                let mut cur_proofs =
                    prove(parties_stmts.iter(), stmt, F::two(), F::three(), F::four());
                let proof_j = cur_proofs.pop().unwrap();
                let proof_i = cur_proofs.pop().unwrap();
                proofs.get_mut(&pi).unwrap().insert(pj, proof_i);
                proofs.get_mut(&pj).unwrap().insert(pi, proof_j);
            }
        }
        proofs.into_iter().for_each(|(pid, proofs)| {
            offline_verifiers.get_mut(&pid).unwrap().1 = Some(proofs);
        })
    };
    offline_verifiers
}
