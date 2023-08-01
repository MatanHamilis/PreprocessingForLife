use std::{collections::HashMap, marker::PhantomData, mem::MaybeUninit, ops::Mul, sync::Arc};

use crate::{
    commitment::StandardCommitReveal,
    fields::{IntermediateMulField, GF2},
    zkfliop::{
        compute_round_count, g, internal_round_proof_length, last_round_proof_length,
        ni::{hash_statement, obtain_check_value, prove, verify_check_value, ZkFliopProof},
        PowersIterator, ProverCtx, VerifierCtx,
    },
};
use aes_prng::AesRng;
use blake3::Hash;
use futures::{future::try_join_all, join};
use log::info;
use rand_core::SeedableRng;
use rayon::{prelude::*, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use std::iter::{Peekable, Rev};
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
    mask_shares: &[((usize, usize), RegularBeaverTriple<PF>)],
    wide_mask_shares: &[((usize, usize), WideBeaverTriple<PF>)],
    masked_values: &[((usize, usize), RegularMask<PF>)],
    wide_masked_values: &[((usize, usize), WideMask<PF>)],
) -> F {
    let regular: F = gammas
        .par_iter()
        .zip(mask_shares.par_iter().rev())
        .zip(masked_values.par_iter().rev())
        .map(
            |(
                ((layer_idx, gate_idx, gamma), (gate_mask, mask)),
                (gate_masked_values, masked_values),
            )| {
                assert_eq!(gate_mask, gate_masked_values);
                assert_eq!(layer_idx, &gate_mask.0);
                assert_eq!(gate_idx, &gate_mask.1);
                // let mask = mask_shares.get(&(*layer_idx, *gate_idx)).unwrap();
                // let masked_values = masked_values.get(&(*layer_idx, *gate_idx)).unwrap();
                match (gamma, mask, masked_values) {
                    (
                        RegularGateGamma(g),
                        RegularBeaverTriple(m_a, m_b, _),
                        RegularMask(v_a, v_b),
                    ) => {
                        let bit = *m_a * *v_b + *v_a * *m_b;
                        (0..PACKING)
                            .map(|pack| bit.get_element(pack) * g[pack])
                            .sum()
                    }
                }
            },
        )
        .sum();
    let wide: F = wide_gammas
        .par_iter()
        .zip(wide_mask_shares.par_iter())
        .zip(wide_masked_values.par_iter())
        .map(
            |(((layer_idx, gate_idx, gamma), (_, mask)), (_, masked_values))| {
                // let mask = wide_mask_shares.get(&(*layer_idx, *gate_idx)).unwrap();
                // let masked_values = wide_masked_values.get(&(*layer_idx, *gate_idx)).unwrap();
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
            },
        )
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
    masks_gates: &[((usize, usize), RegularMask<PF>)],
    wide_masks_gates: &[((usize, usize), WideMask<PF>)],
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
        .zip(masks_gates.par_iter().rev())
        .map(|((layer_idx, gate_idx, gamma), (mask_idx, mask))| {
            // let mask = masks_gates.get(&(*layer_idx, *gate_idx)).unwrap();
            assert_eq!(&mask_idx.0, layer_idx);
            assert_eq!(&mask_idx.1, gate_idx);
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
        .zip(wide_masks_gates.par_iter())
        .map(|((layer_idx, gate_idx, gamma), (_, mask))| {
            // let mask = wide_masks_gates.get(&(*layer_idx, *gate_idx)).unwrap();
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
    regular_masks_gates: &[((usize, usize), RegularMask<PF>)],
    wide_masks_gates: &[((usize, usize), WideMask<PF>)],
    masks_outputs: &[PF],
) -> F {
    // Sigma alpha_w r_w
    let regular_sigma_alpha_w_r_w_gates: F = alphas_gate
        .par_iter()
        .zip(regular_masks_gates.par_iter())
        .map(
            |((layer_id, gate_id, input_wire_coefficients), (mask_idx, mask))| {
                // let mask = regular_masks_gates.get(&(*layer_id, *gate_id)).unwrap();
                assert_eq!(&mask_idx.0, layer_id);
                assert_eq!(&mask_idx.1, gate_id);
                match (mask, input_wire_coefficients) {
                    (RegularMask(a, b), RegularInputWireCoefficient(c_a, c_b)) => {
                        (0..N)
                            .map(|i| a.get_element(i) * c_a[i] + b.get_element(i) * c_b[i])
                            .sum()
                        // * c_a * F::from(*a) + *c_b * F::from(*b)
                    }
                }
            },
        )
        .sum();
    let wide_sigma_alpha_w_r_w_gates: F = wide_alphas_gate
        .par_iter()
        .zip(wide_masks_gates.par_iter())
        .map(|((layer_id, gate_id, input_wire_coefficients), mask)| {
            // let mask = wide_masks_gates.get(&(*layer_id, *gate_id)).unwrap();
            match (&mask.1, input_wire_coefficients) {
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
    // let statement_length = (1 << (usize::ilog2(2 * statement_length - 1))) as usize;
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
    regular_masked_inputs: Option<&[((usize, usize), RegularMask<PF>)]>,
    wide_masked_inputs: Option<&[((usize, usize), WideMask<PF>)]>,
    regular_mask_shares: Option<&[((usize, usize), RegularBeaverTriple<PF>)]>,
    wide_mask_shares: Option<&[((usize, usize), WideBeaverTriple<PF>)]>,
    circuit: &ParsedCircuit,
) -> Vec<F> {
    let statement_length: usize = statement_length::<N>(circuit);
    // We create a statement of size that is 1 + power of 2.
    // let mut statement = vec![F::zero(); statement_length];
    let mut statement =
        unsafe { vec![std::mem::MaybeUninit::<F>::uninit().assume_init(); statement_length] };

    // Initialize first entry
    statement[0] = masked_gamma_i.unwrap_or(F::zero()) + gamma_i_mask.unwrap_or(F::zero());

    let mut iter_masks = statement.iter_mut().skip(2).step_by(2);

    // Initialize mask shares
    if regular_mask_shares.is_none() {
        iter_masks.for_each(|v| *v = F::zero());
    } else {
        let gate_masks = regular_mask_shares.unwrap();
        for ((layer_idx, gate_idx, _), (gate_mask_idx, gate_mask)) in
            regular_gate_gammas.iter().zip(gate_masks.iter().rev())
        {
            assert_eq!(&gate_mask_idx.0, layer_idx);
            assert_eq!(&gate_mask_idx.1, gate_idx);
            // let gate_mask = gate_masks.get(&(*layer_idx, *gate_idx)).unwrap();
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
        for ((layer_idx, gate_idx, _), (_, gate_mask)) in
            wide_gate_gammas.iter().zip(gate_masks.iter())
        {
            // let gate_mask = gate_masks.get(&(*layer_idx, *gate_idx)).unwrap();
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
        for ((layer_idx, gate_idx, gate_gamma), (gate_mask_input_idx, gate_mask_input)) in
            regular_gate_gammas
                .iter()
                .zip(gate_masked_inputs.iter().rev())
        {
            assert_eq!(&gate_mask_input_idx.0, layer_idx);
            assert_eq!(&gate_mask_input_idx.1, gate_idx);
            // let gate_mask_input = gate_masked_inputs.get(&(*layer_idx, *gate_idx)).unwrap();
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
        for ((layer_idx, gate_idx, gate_gamma), (_, gate_mask_input)) in
            wide_gate_gammas.iter().zip(gate_masked_inputs.iter())
        {
            // let gate_mask_input = gate_masked_inputs.get(&(*layer_idx, *gate_idx)).unwrap();
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

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OfflineCircuitVerify<F: FieldElement> {
    #[serde(bound = "")]
    s_i: F,
    alpha_omega_commitment: OfflineCommitment,
    s_commitment: OfflineCommitment,
    #[serde(bound = "")]
    verifiers_offline_material: Vec<(PartyId, OfflineVerifier<F>)>,
    #[serde(bound = "")]
    prover_offline_material: OfflineProver<F>,
}

impl<F: FieldElement> OfflineCircuitVerify<F> {
    fn hash_for_coin(&self) -> F {
        let hash_correlation = self.prover_offline_material.hash();
        let hash_correlation: [u8; 16] = core::array::from_fn(|i| hash_correlation[i]);
        let mut rng = AesRng::from_seed(hash_correlation);
        let mut sum = F::random(&mut rng);

        let hash_correlation = *blake3::hash(self.s_i.as_bytes()).as_bytes();
        let hash_correlation: [u8; 16] = core::array::from_fn(|i| hash_correlation[i]);
        let mut rng = AesRng::from_seed(hash_correlation);
        sum += F::random(&mut rng);

        // This will be just one anyway for 2+1.
        self.verifiers_offline_material.iter().for_each(|v| {
            let hash_correlation = v.1.hash();
            let hash_correlation: [u8; 16] = core::array::from_fn(|i| hash_correlation[i]);
            let mut rng = AesRng::from_seed(hash_correlation);
            sum += F::random(&mut rng);
        });

        sum
    }
}

pub struct FliopCtx<F: IntermediateMulField> {
    pub prover_ctx: Option<ProverCtx<F>>,
    pub verifiers_ctx: Option<Vec<VerifierCtx<F>>>,
}
impl<F: IntermediateMulField> FliopCtx<F> {
    pub fn new(log_folding_factor: usize, verifiers_count: usize) -> Self {
        Self {
            prover_ctx: Some(ProverCtx::new(log_folding_factor)),
            verifiers_ctx: Some(
                (0..verifiers_count)
                    .map(|_| VerifierCtx::new(log_folding_factor))
                    .collect(),
            ),
        }
    }
}
pub async fn verify_parties<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement + Mul<F, Output = F>,
    F: IntermediateMulField + From<CF>,
    E: MultiPartyEngine,
>(
    engine: &mut E,
    input_wire_masked_values: &[PF],
    regular_masked_values: &[((usize, usize), RegularMask<PF>)],
    wide_masked_values: &[((usize, usize), WideMask<PF>)],
    regular_masks_shares: &[((usize, usize), RegularBeaverTriple<PF>)],
    wide_masks_shares: &[((usize, usize), WideBeaverTriple<PF>)],
    output_wire_masked_values: &[PF],
    circuit: &ParsedCircuit,
    offline_material: &OfflineCircuitVerify<F>,
    ctx: &mut FliopCtx<F>,
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
        regular_masked_values,
        wide_masked_values,
        &gammas_input_wires,
        input_wire_masked_values,
    );

    let lambda = alpha_x_hat - gamma_x_hat - total_constant_addition;

    // Compute Gamma_i
    let gamma_i = compute_gamma_i(
        &gammas,
        &wide_gammas,
        regular_masks_shares,
        wide_masks_shares,
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
        "\t\tVerify {} - Compute and obtain gammas: {}ms",
        my_id,
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
    let verify_statement: Arc<Vec<_>> = Arc::new(
        proof_statement
            .iter()
            .copied()
            .enumerate()
            .map(|(idx, v)| if idx & 1 == 0 { F::zero() } else { v })
            .collect(),
    );
    // let verify_statement = Arc::new(construct_statement(
    //     None,
    //     None,
    //     &gammas,
    //     &wide_gammas,
    //     Some(&regular_masked_values),
    //     Some(&wide_masked_values),
    //     None,
    //     None,
    //     circuit,
    // ));
    info!(
        "\t\tVerify {} - Statements Construction: {}ms",
        my_id,
        timer.elapsed().as_millis()
    );
    let mut prover_ctx = ctx.prover_ctx.take().unwrap();
    let mut verifiers_ctx = ctx.verifiers_ctx.take().unwrap();
    let sub_engine = engine.sub_protocol(my_id);
    let prover_futures = tokio::spawn(async move {
        let prover_offline_material = prover_offline_material;
        let timer = Instant::now();
        zkfliop::prover(
            sub_engine,
            &mut proof_statement,
            &prover_offline_material,
            &mut prover_ctx,
        )
        .await;
        info!(
            "\t\tVerify {} - Proving took: {}",
            my_id,
            timer.elapsed().as_millis()
        );
        Result::<_, ()>::Ok(prover_ctx)
    });

    let verifiers_futures = verifiers_offline_material
        .into_iter()
        .zip(verifiers_ctx.drain(..))
        .map(|((prover_id, offline_material), mut verifier_ctx)| {
            let timer = Instant::now();
            let offline_material = offline_material.clone();
            let verifier_engine = engine.sub_protocol(prover_id);
            let verify_statement_arc = verify_statement.clone();
            let masked_gamma_prover = *masked_gamma_i_s.get(&prover_id).unwrap();
            let prover_id = *prover_id;
            info!(
                "\t\tVerify {} - Making preparations to verify: {}ms",
                my_id,
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
                    &mut verifier_ctx,
                )
                .await;
                info!(
                    "\t\tVerify {} - zkfliop verifier took: {}",
                    my_id,
                    timer.elapsed().as_millis()
                );
                Result::<_, ()>::Ok(verifier_ctx)
            })
        });
    let verifiers_futures = try_join_all(verifiers_futures);
    let (prover_futures, verifiers_futures) = join!(prover_futures, verifiers_futures);
    ctx.prover_ctx = Some(prover_futures.unwrap().unwrap());
    verifiers_futures
        .unwrap()
        .into_iter()
        .for_each(|v| verifiers_ctx.push(v.unwrap()));
    ctx.verifiers_ctx = Some(verifiers_ctx);
    let timer = Instant::now();
    let s = s_commitment.online_decommit(engine).await;
    let p = p_hat + s;
    info!(
        "\t\tVerify - last communication round took: {}ms",
        timer.elapsed().as_millis()
    );
    return p.is_zero();
}

pub struct DealerCtx<F: IntermediateMulField> {
    prover_ctx: ProverCtx<F>,
    verifier_ctx: VerifierCtx<F>,
    log_folding_factor: usize,
}
impl<F: IntermediateMulField> DealerCtx<F> {
    pub fn new(log_folding_factor: usize) -> Self {
        Self {
            prover_ctx: ProverCtx::new(log_folding_factor),
            verifier_ctx: VerifierCtx::new(log_folding_factor),
            log_folding_factor,
        }
    }
}
pub fn offline_verify_dealer<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    F: IntermediateMulField + From<GF2>,
    SHO: OfflineSemiHonestCorrelation<PF>,
>(
    circuit: &ParsedCircuit,
    total_input_wires_masks: &[PF],
    total_output_wires_masks: &[PF],
    sho: &mut [(PartyId, SHO)],
    is_authenticated: bool,
    dealer_ctx: &mut DealerCtx<F>,
) -> HashMap<
    PartyId,
    (
        OfflineCircuitVerify<F>,
        Option<HashMap<PartyId, ZkFliopProof<F>>>,
        Option<ZkFliopProof<F>>,
    ),
>
where
    GF2: Mul<F, Output = F>,
{
    sho.sort_by(|a, b| a.0.cmp(&b.0));
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

    let party_id = sho[0].0;
    let another_party_id = sho[1].0;
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
    for (pid, sho) in sho.iter_mut() {
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
    let regular_gates_input_wire_masks = &total_gate_input_masks;
    let wide_gates_input_wire_masks = &wide_total_gate_input_masks;
    let mu = F::random(&mut rng);
    let alpha_r = dot_product_alpha::<PACKING, _, _, PF>(
        &alphas,
        &wide_alphas,
        &alphas_output_wires,
        regular_gates_input_wire_masks,
        wide_gates_input_wire_masks,
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
    let DealerCtx {
        prover_ctx,
        verifier_ctx,
        log_folding_factor,
    } = dealer_ctx;
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
            let regular_mask_shares: Vec<_> = regular_gate_masks
                .into_iter()
                .map(|((l, g), m)| {
                    let m = match m {
                        RegularMask(a, b) => RegularBeaverTriple(a, b, PF::zero()),
                    };
                    ((l, g), m)
                })
                .collect();
            let wide_mask_shares: Vec<_> = wide_gate_masks
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
            let (prover_correlation, verifiers_correlation) =
                dealer(&mut z_tilde, parties_num - 1, verifier_ctx);
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
    let auth_time = Instant::now();
    if is_authenticated {
        // Semi Honest Proofs
        let coin: F = sho
            .iter()
            .map(|sho| {
                let hash_correlation = sho.1.hash_correlation();
                let hash_correlation: [u8; 16] = core::array::from_fn(|i| hash_correlation[i]);
                let mut rng = AesRng::from_seed(hash_correlation);
                F::random(&mut rng)
            })
            .sum();
        let pairwise_triples: HashMap<_, _> = sho
            .iter_mut()
            .map(|(pid, sho)| (*pid, sho.get_pairwise_triples(circuit)))
            .collect();

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
                let (reg_ci, wide_ci) = (
                    reg_ci.iter().find(|v| v.0 == pj).unwrap(),
                    wide_ci.iter().find(|v| v.0 == pj).unwrap(),
                );
                let (reg_cj, wide_cj) = pairwise_triples.get(&pj).unwrap();
                let (reg_cj, wide_cj) = (
                    reg_cj.iter().find(|v| v.0 == pi).unwrap(),
                    wide_cj.iter().find(|v| v.0 == pi).unwrap(),
                );
                let mut stmt_i_powers = PowersIterator::new(coin);
                let mut stmt_j_powers = PowersIterator::new(coin);
                let stmt_i =
                    construct_statement_from_bts(&reg_ci.1, &wide_ci.1, &mut stmt_i_powers);
                let stmt_j =
                    construct_statement_from_bts(&reg_cj.1, &wide_cj.1, &mut stmt_j_powers);
                let stmt: Vec<F> = stmt_i
                    .iter()
                    .copied()
                    .zip(stmt_j.iter().copied())
                    .map(|(i, j)| i + j)
                    .collect();
                let parties_stmts = [stmt_i, stmt_j];
                let mut cur_proofs = prove(parties_stmts.iter(), stmt, prover_ctx);
                let proof_j = cur_proofs.pop().unwrap();
                let proof_i = cur_proofs.pop().unwrap();
                proofs.get_mut(&pi).unwrap().insert(pj, proof_i);
                proofs.get_mut(&pj).unwrap().insert(pi, proof_j);
            }
        }
        // FLIOP proof (we prove all FLIOPs together)
        let coin: F = offline_verifiers
            .iter()
            .map(|(_, verifier)| verifier.0.hash_for_coin())
            .sum();
        // remember each gate has two inputs and therefore two masks.
        let total_masks = 2 * pairwise_triples.get(&party_id).unwrap().0[0].1.len() * PACKING;
        let round_count =
            compute_round_count(statement_length::<PACKING>(circuit), *log_folding_factor);
        let single_fliop_size = 2
            * (total_masks
                + 1
                + internal_round_proof_length(*log_folding_factor) * (round_count - 1)
                + last_round_proof_length(*log_folding_factor));
        let party_count = sho.len();
        let mut parties: Vec<_> = sho.iter().map(|v| v.0).collect();
        parties.sort();
        let parties_statements: Vec<_> = sho
            .iter()
            .enumerate()
            .map(|(idx, (pid, sho_corr))| {
                let party_statement = construct_party_statement(
                    coin,
                    sho_corr,
                    *log_folding_factor,
                    &offline_verifiers.get(pid).unwrap().0,
                    &parties,
                    *pid,
                );
                (*pid, party_statement)
            })
            .collect();
        let mut large_statement = parties_statements[0].1.clone();
        // We sum all statements.
        parties_statements.iter().skip(1).for_each(|s| {
            s.1.iter()
                .skip(1)
                .zip(large_statement.iter_mut().skip(1))
                .for_each(|(i, o)| {
                    if o.is_zero() {
                        *o = *i;
                    }
                });
        });
        large_statement[0] = parties_statements.iter().map(|v| v.1[0]).sum();
        debug_assert_eq!(large_statement[0], g(&large_statement[1..]));
        // At last, let's prove
        let proof = prove(
            parties_statements.iter().map(|v| &v.1),
            large_statement,
            prover_ctx,
        );
        info!("Auth time: {}ms", auth_time.elapsed().as_millis());
        parties_statements
            .iter()
            .zip(proof.into_iter())
            .for_each(|(s, p)| {
                offline_verifiers.get_mut(&s.0).unwrap().2 = Some(p);
            });
        proofs.into_iter().for_each(|(pid, proofs)| {
            offline_verifiers.get_mut(&pid).unwrap().1 = Some(proofs);
        })
    };
    offline_verifiers
}
struct MasksIterator<
    'a,
    const N: usize,
    PF: PackedField<F, N>,
    F: FieldElement,
    VF: FieldElement + IntermediateMulField + From<F>,
> {
    masks: &'a [((usize, usize), RegularBeaverTriple<PF>)],
    masks_iter: Peekable<Rev<std::slice::Iter<'a, ((usize, usize), RegularBeaverTriple<PF>)>>>,
    index_iter: Peekable<Rev<std::ops::Range<usize>>>,
    is_a: bool,
    _phantom: PhantomData<(VF, F)>,
}
impl<
        'a,
        const N: usize,
        PF: PackedField<F, N>,
        F: FieldElement,
        VF: FieldElement + IntermediateMulField + From<F>,
    > MasksIterator<'a, N, PF, F, VF>
{
    fn new(masks: &'a [((usize, usize), RegularBeaverTriple<PF>)]) -> Self {
        let a = (0..9).into_iter().rev();
        Self {
            masks,
            masks_iter: masks.iter().rev().peekable(),
            index_iter: (0..N).into_iter().rev().peekable(),
            is_a: false,
            _phantom: PhantomData,
        }
    }
}
impl<
        'a,
        const N: usize,
        PF: PackedField<F, N>,
        F: FieldElement,
        VF: FieldElement + IntermediateMulField + From<F>,
    > Iterator for MasksIterator<'a, N, PF, F, VF>
{
    type Item = VF;
    fn next(&mut self) -> Option<Self::Item> {
        let output = match self.masks_iter.peek() {
            None => return None,
            Some(v) => *v,
        };
        let idx = *self.index_iter.peek().unwrap();
        let output = if self.is_a {
            self.index_iter.next();
            if self.index_iter.peek().is_none() {
                self.index_iter = (0..N).into_iter().rev().peekable();
                self.masks_iter.next();
            }
            output.1 .0.get_element(idx)
        } else {
            output.1 .1.get_element(idx)
        };
        self.is_a = !self.is_a;
        Some(VF::from(output))
    }
}

pub fn construct_party_statement<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    F: IntermediateMulField + From<GF2>,
    SHO: OfflineSemiHonestCorrelation<PF>,
>(
    coin: F,
    sho_corr: &SHO,
    log_folding_factor: usize,
    verifier: &OfflineCircuitVerify<F>,
    sorted_parties: &[PartyId],
    my_party_id: PartyId,
) -> Vec<F> {
    let party_count = sorted_parties.len();
    let round_count = verifier.prover_offline_material.get_round_count();
    let idx = sorted_parties
        .iter()
        .enumerate()
        .find(|(idx, v)| **v == my_party_id)
        .unwrap()
        .0;
    let (prover_beaver_triples, _) = sho_corr.get_prepared_multiparty_beaver_triples();
    let total_masks = prover_beaver_triples.len() * 2 * PACKING;
    let single_fliop_size = 2
        * (total_masks
            + 1
            + internal_round_proof_length(log_folding_factor) * (round_count - 1)
            + last_round_proof_length(log_folding_factor));
    let mut powers = PowersIterator::new(coin);
    let mut party_statement = unsafe {
        vec![MaybeUninit::<F>::uninit().assume_init(); 1 + single_fliop_size * party_count]
    };
    party_statement[0] = F::zero();
    for i in 0..sorted_parties.len() {
        if i == idx {
            // If we're a prover.
            let mut iterator = MasksIterator::new(prover_beaver_triples);
            let prover = Some(&verifier.prover_offline_material);
            let prover_s = Some(verifier.s_i);
            zkfliop::verify_fliop_construct_statement(
                Some(iterator),
                prover,
                prover_s,
                None,
                total_masks,
                log_folding_factor,
                &mut powers,
                &mut party_statement
                    [1 + single_fliop_size * (idx)..1 + single_fliop_size * (idx + 1)],
            );
            continue;
        }
        // Otherwise we're a verifier
        let verifier = &verifier
            .verifiers_offline_material
            .iter()
            .find(|v| v.0 == sorted_parties[i])
            .unwrap()
            .1;
        let sum = zkfliop::verify_fliop_construct_statement::<MasksIterator<PACKING, PF, GF2, F>, F>(
            None,
            None,
            None,
            Some(verifier),
            total_masks,
            log_folding_factor,
            &mut powers,
            &mut party_statement[1 + single_fliop_size * i..1 + single_fliop_size * (i + 1)],
        );
        party_statement[0] += sum;
    }
    party_statement
}

pub async fn verify_fliop_correlation<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    F: IntermediateMulField + From<GF2>,
    SHO: OfflineSemiHonestCorrelation<PF>,
>(
    engine: impl MultiPartyEngine,
    verifier: &OfflineCircuitVerify<F>,
    sho_corr: &SHO,
    verifier_ctx: &mut VerifierCtx<F>,
    proof: &ZkFliopProof<F>,
) -> bool {
    let coin_share = verifier.hash_for_coin();
    let coin = StandardCommitReveal::commit(engine.sub_protocol("coin"), coin_share)
        .await
        .reveal()
        .await
        .into_iter()
        .map(|v| v.1)
        .sum::<F>()
        + coin_share;
    let statement_share = construct_party_statement(
        coin,
        sho_corr,
        verifier_ctx.log_folding_factor(),
        verifier,
        engine.party_ids(),
        engine.my_party_id(),
    );
    let (is_ok, chk) = obtain_check_value(statement_share, proof, verifier_ctx);
    verify_check_value(engine, is_ok, chk).await
}
