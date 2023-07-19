use std::time::Instant;

use crate::{
    commitment::{CommmitShare, OfflineCommitment},
    engine::{MultiPartyEngine, PartyId},
    fields::FieldElement,
};
use aes_prng::AesRng;
use log::info;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

pub mod ni;

// const INTERNAL_ROUND_PROOF_LENGTH: usize = 3;
// const LAST_ROUND_PROOF_LENGTH: usize = 5;
pub fn internal_round_proof_length(log_folding_factor: usize) -> usize {
    (2 << log_folding_factor) - 1
}

pub fn last_round_proof_length(log_folding_factor: usize) -> usize {
    // f_1(0),f_2(0)
    2 +
    // evaluations of p(f_1(x),f_2(x)).
    // Deg of f_i is L (due to HVZK).
    // Deg of p is 2.
    // Total is 2*L so 2*L+1 evals needed.
    (2<<log_folding_factor) + 1
}
// const CHUNK_SIZE: usize = 1 << 10;
pub struct PowersIterator<F: FieldElement> {
    alpha: F,
    current: F,
}
impl<F: FieldElement> PowersIterator<F> {
    pub fn new(alpha: F) -> Self {
        Self {
            alpha,
            current: F::one(),
        }
    }
}
impl<F: FieldElement> Iterator for PowersIterator<F> {
    type Item = F;
    fn next(&mut self) -> Option<Self::Item> {
        self.current *= self.alpha;
        Some(self.current)
    }
}

pub fn compute_round_count(mut z_len: usize, log_folding_factor: usize) -> usize {
    z_len -= 1;
    let m = 1 << log_folding_factor;
    // We only need that at the beginning the statement's length is a multiple of folding factor.
    assert_eq!(z_len % 2, 0);
    let mut round_count = 1;
    while z_len > 2 * m {
        z_len = ((z_len + 2 * m - 1) / (2 * m)) * (2 * m);
        z_len /= m;
        round_count += 1;
    }
    // This might not be needed, we can round up to a multiple of folding factor at each round.
    // assert_eq!(1 << (round_count * log_folding_factor), m);
    round_count
    // for folding_factor = 4, z_len = 101.
    // last_round = 16.
    // m = 100 / 16 = 6.
    // round_count = (2 + 2 -1)/ 2 = 3/2 = 1.
    // total = 2
    // actually: first: 100
    // second: 25 -> 28.
    // third: 7 -> 16.
}

pub fn g<F: FieldElement>(z: &[F]) -> F {
    z.chunks_exact(2).map(|f| f[0] * f[1]).sum()
}
#[derive(Clone, Serialize, Deserialize)]
pub struct OfflineProver<F: FieldElement> {
    #[serde(bound = "")]
    proof_masks: Vec<F>,
    round_challenges: Vec<OfflineCommitment>,
    final_msg: OfflineCommitment,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OfflineVerifier {
    round_challenges: Vec<OfflineCommitment>,
    final_msg: OfflineCommitment,
}

struct EvalCtx<F: FieldElement> {
    numbers: Vec<F>,
    prefix_buf: Vec<F>,
    suffix_buf: Vec<F>,
    denoms: Vec<F>,
    eval_points: usize,
    coeffs: Vec<F>,
    interpolation_buf: Vec<F>,
}
impl<F: FieldElement> EvalCtx<F> {
    fn new(interpolation_points: usize, eval_points: usize) -> Self {
        let numbers: Vec<_> = (0..interpolation_points)
            .map(|i| F::number(i as u32))
            .collect();
        let suffix_buf = vec![F::zero(); interpolation_points * eval_points];
        let prefix_buf = vec![F::zero(); interpolation_points * eval_points];
        let denoms: Vec<_> = (0..interpolation_points)
            .map(|i| {
                ((0..i).chain(i + 1..interpolation_points))
                    .map(|j| numbers[i] - numbers[j])
                    .fold(F::one(), |cur, acc| cur * acc)
            })
            .collect();
        let coeffs = vec![F::zero(); interpolation_points * eval_points];
        Self {
            numbers,
            prefix_buf,
            suffix_buf,
            denoms,
            eval_points,
            coeffs,
            interpolation_buf: vec![F::zero(); interpolation_points * eval_points],
        }
    }
    fn prepare_at_points(&mut self, at: &[F]) {
        assert_eq!(at.len(), self.eval_points);
        let M = self.denoms.len();
        // buffer prefixes [i] = (at - evals[0].0)....(at - evals[i-1].0).
        // buffer suffexies [i] = (at - evals[i+1].0)....(at - evals[l-1].0).
        self.prefix_buf
            .chunks_exact_mut(M)
            .zip(self.suffix_buf.chunks_exact_mut(M))
            .zip(at.iter())
            .for_each(|((prefix_chunk, suffix_chunk), eval_point)| {
                prefix_chunk[0] = F::one();
                suffix_chunk[M - 1] = F::one();
                for i in 0..(M - 1) {
                    prefix_chunk[i + 1] = prefix_chunk[i] * (*eval_point - self.numbers[i]);
                    suffix_chunk[M - i - 2] =
                        suffix_chunk[M - i - 1] * (*eval_point - self.numbers[M - i - 1]);
                }
            });
        self.prefix_buf
            .chunks_exact(M)
            .zip(self.suffix_buf.chunks_exact(M))
            .enumerate()
            .for_each(|(chunk_idx, (prefix_buf, suffix_buf))| {
                (0..prefix_buf.len()).for_each(|in_chunk_idx| {
                    self.coeffs[in_chunk_idx * self.eval_points + chunk_idx] =
                        prefix_buf[in_chunk_idx] * suffix_buf[in_chunk_idx]
                            / self.denoms[in_chunk_idx];
                })
            });
        //ventually self.coeffs is ordered such that first we have Lagrange Coefficients for interpolation of all eval points that should be multiplied by the first interpolated point and so on..
    }
    fn interpolate(&mut self, evals: &[F], output: &mut [F], base: usize, step: usize) {
        let M = self.denoms.len();
        let L = evals.len() / M;
        assert_eq!(output.len(), L * self.eval_points);
        assert_eq!(evals.len(), L * M);
        // output[i*L + j] is the evaluation
        // of i-th eval point on j-th polynomial.
        // output.iter_mut().for_each(|v| *v = F::zero());
        for poly_chunk_base in (0..L).step_by(M) {
            self.interpolation_buf
                .iter_mut()
                .for_each(|v| *v = F::zero());
            let poly_chunk_size = usize::min(L, poly_chunk_base + M) - poly_chunk_base;
            for evalled in 0..M {
                let in_coeff_idx = evalled * L + poly_chunk_base;
                for eval_point in 0..self.eval_points {
                    for p in (base..poly_chunk_size).step_by(step) {
                        self.interpolation_buf[eval_point * M + p] += evals[in_coeff_idx + p]
                            * self.coeffs[eval_point + evalled * self.eval_points];
                        // output[eval_point * L + poly_chunk_base + p] += evals[in_coeff_idx + p]
                        // * self.coeffs[eval_point + evalled * self.eval_points];
                    }
                }
            }
            for eval_point in 0..self.eval_points {
                for p in 0..poly_chunk_size {
                    output[eval_point * L + poly_chunk_base + p] =
                        self.interpolation_buf[eval_point * M + p];
                }
            }
        }
    }
    // Denoms are independent of evaluation point and therefore can be preprocessed.
    fn interpolate_with_g<'a>(&self, evals: &[F], output: &mut [F]) {
        let M = self.denoms.len();
        output.iter_mut().for_each(|v| *v = F::zero());
        let L = evals.len() / M;
        assert_eq!(output.len(), self.eval_points);
        assert_eq!(evals.len(), L * M);
        // output[i*self.eval_points + j]=interpolation of i-th polynomial at point j.
        // The first 'eval_count' elements are evals at 0, next 'eval_count' elements are evals at 1, etc...
        // we take each coefficient
        // The statement is structured as follows:
        //
        //                   evals of 0                         evals of 1                      evals of M-1
        // | output | f_0(0) | f_1(0) |...| f_L-1(0)| f_0(1) | f_1(1) |...|f_L-1(1) |...| f_0(M-1) |...| f_L-1(M-1)
        //
        // If we rearrange it in a matrix we get (besides the first element)
        //
        //
        // f_0(0)   f_1(0)  ... f_L-1(0)
        // f_0(1)   f_1(1)  ... f_L-1(1)
        //  ..         ..   ...    ..
        // f_0(M-1) f_1(M-1)... f_L-1(M-1)
        //
        // We wish to multiply the matrix ,A from the right by the lagrange coefficient matrix.
        // So that each polynomial f_i will be evaluated at additional points.
        // Each time we take a block of M polynomials and eval their outputs.
        // If the number of polynomials fill the cache line this should be good for utilizing memory.
        // For every chunk of M polynomials we evaluation all of them on a set of `eval_points` points.
        // First M will be evals at first point, next will be evals of second point etc...
        // Since M is even we can make partial computation out of it.
        let mut interpolation_buf = vec![F::zero(); M * self.eval_points];
        for poly_chunk_base in (0..L).step_by(M) {
            interpolation_buf.iter_mut().for_each(|v| *v = F::zero());
            let poly_chunk_size = usize::min(L, poly_chunk_base + M) - poly_chunk_base;
            for evalled in 0..M {
                let in_coeff_idx = evalled * L + poly_chunk_base;
                for eval_point in 0..self.eval_points {
                    let c = self.coeffs[eval_point + evalled * self.eval_points];
                    interpolation_buf[eval_point * M..eval_point * M + poly_chunk_size]
                        .iter_mut()
                        .zip(evals[in_coeff_idx..in_coeff_idx + poly_chunk_size].iter())
                        .for_each(|(o, i)| {
                            *o += c * *i;
                        });
                }
            }
            output
                .iter_mut()
                .zip(interpolation_buf.chunks(M))
                .for_each(|(o, chunk)| {
                    // Ok because entries we didn't touch are zero.
                    *o += g(chunk);
                });
        }
    }
}
pub struct VerifierCtx<F: FieldElement> {
    eval_ctx_internal_round_proof: EvalCtx<F>,
    eval_ctx_internal_round_polys: EvalCtx<F>,
    eval_ctx_last_round_polys: EvalCtx<F>,
    eval_ctx_last_round_proof: EvalCtx<F>,
    log_folding_factor: usize,
}
impl<F: FieldElement> VerifierCtx<F> {
    pub fn new(log_folding_factor: usize) -> Self {
        Self {
            eval_ctx_internal_round_proof: EvalCtx::<F>::new(
                internal_round_proof_length(log_folding_factor),
                1,
            ),
            eval_ctx_internal_round_polys: EvalCtx::<F>::new(1 << log_folding_factor, 1),
            eval_ctx_last_round_proof: EvalCtx::<F>::new(
                last_round_proof_length(log_folding_factor) - 2,
                1,
            ),
            eval_ctx_last_round_polys: EvalCtx::<F>::new(1 + (1 << log_folding_factor), 1),
            log_folding_factor,
        }
    }
    pub fn log_folding_factor(&self) -> usize {
        self.log_folding_factor
    }
}
pub fn dealer<F: FieldElement>(
    mut z_tilde: &mut [F],
    num_verifiers: usize,
    verifier_ctx: &mut VerifierCtx<F>,
) -> (OfflineProver<F>, Vec<OfflineVerifier>) {
    let VerifierCtx {
        eval_ctx_internal_round_proof,
        eval_ctx_internal_round_polys,
        eval_ctx_last_round_polys,
        eval_ctx_last_round_proof,
        log_folding_factor,
    } = verifier_ctx;
    let log_folding_factor = *log_folding_factor;
    // Init
    debug_assert!(z_tilde.iter().skip(1).step_by(2).all(|v| v.is_zero()));
    let round_count = compute_round_count(z_tilde.len(), log_folding_factor);
    let mut b_tilde = Vec::with_capacity(round_count);
    let mut rng = AesRng::from_random_seed();
    let internal_proof_length = internal_round_proof_length(log_folding_factor);
    let total_proof_mask_len =
        internal_proof_length * (round_count - 1) + last_round_proof_length(log_folding_factor);
    let proof_masks: Vec<_> = (0..total_proof_mask_len)
        .map(|_| F::random(&mut rng))
        .collect();
    // let s_tilde = (F::random(&mut rng), F::random(&mut rng));

    // Rounds
    let mut round_challenges_shares = vec![Vec::with_capacity(round_count); num_verifiers + 1];
    let M = 1 << log_folding_factor;
    for round_id in 1..round_count {
        let z_len = z_tilde.len();
        let r = F::random(&mut rng);
        let (challenge_commit_shares, commitment) =
            OfflineCommitment::commit(&r, num_verifiers + 1);
        round_challenges_shares
            .iter_mut()
            .zip(challenge_commit_shares.into_iter())
            .for_each(|(v, commit_share)| {
                v.push(OfflineCommitment {
                    commit_share,
                    commitment,
                });
            });
        let q_base = (round_id - 1) * internal_proof_length;
        let b_tilde_value = z_tilde[0] - (0..M).map(|i| proof_masks[q_base + i]).sum();
        b_tilde.push(b_tilde_value);
        let L = (z_len - 1) / M;
        eval_ctx_internal_round_polys.prepare_at_points(std::slice::from_ref(&r));
        const CHUNK_SIZE: usize = 32;
        let z_output = unsafe { std::slice::from_raw_parts_mut(z_tilde[1..1 + L].as_mut_ptr(), L) };
        eval_ctx_internal_round_polys.interpolate(&z_tilde[1..], z_output, 1, 2);

        let next_round_size = ((L + 2 * M - 1) / (2 * M)) * (2 * M);
        // We now round up z_tilde's length to be a multiple of 2*M. This is OK for inner product.
        for i in L..next_round_size {
            z_tilde[1 + i] = F::zero();
        }
        eval_ctx_internal_round_proof.prepare_at_points(std::slice::from_ref(&r));
        eval_ctx_internal_round_proof.interpolate(
            &proof_masks[q_base..q_base + internal_proof_length],
            &mut z_tilde[0..1],
            0,
            1,
        );
        z_tilde = &mut z_tilde[..=next_round_size];
    }
    // last round
    debug_assert_eq!(z_tilde.len(), 1 + 2 * M);
    let r = F::random(&mut rng);
    let (challenge_commit_shares, commitment) = OfflineCommitment::commit(&r, num_verifiers + 1);
    round_challenges_shares
        .iter_mut()
        .zip(challenge_commit_shares.into_iter())
        .for_each(|(v, commit_share)| {
            v.push(OfflineCommitment {
                commit_share,
                commitment,
            });
        });
    let last_round_masks =
        &proof_masks[proof_masks.len() - last_round_proof_length(log_folding_factor)..];
    // let mut polys_eval_ctx = EvalCtx::<F>::new(M + 1);
    // let mut last_poly_eval_ctx = EvalCtx::<F>::new(2 * M + 1);
    eval_ctx_last_round_polys.prepare_at_points(std::slice::from_ref(&r));
    eval_ctx_last_round_proof.prepare_at_points(std::slice::from_ref(&r));
    let s_tilde = [last_round_masks[0], last_round_masks[1]];
    let interpolation_buf: Vec<_> = z_tilde[1..].iter().chain(s_tilde.iter()).copied().collect();
    let mut f_tilde_r = [F::zero(); 2];
    eval_ctx_last_round_polys.interpolate(&interpolation_buf, &mut f_tilde_r[..], 0, 1);
    let mut g_tilde_r = F::zero();
    eval_ctx_last_round_proof.interpolate(
        &last_round_masks[2..],
        std::slice::from_mut(&mut g_tilde_r),
        0,
        1,
    );
    b_tilde.push(z_tilde[0] - (0..M).map(|i| last_round_masks[2 + i]).sum());

    // Decision
    let betas: Vec<_> = (0..round_count).map(|_| F::random(&mut rng)).collect();
    debug_assert_eq!(betas.len(), b_tilde.len());
    let b_tilde_check = betas
        .iter()
        .zip(b_tilde.iter())
        .map(|(a, b)| *a * *b)
        .fold(F::zero(), |acc, cur| acc + cur);
    let final_value = (betas, b_tilde_check, f_tilde_r[0], f_tilde_r[1], g_tilde_r);
    let (mut last_value_commitments, commitment) =
        OfflineCommitment::commit(&final_value, num_verifiers + 1);
    let prover = OfflineProver {
        final_msg: OfflineCommitment {
            commit_share: last_value_commitments.pop().unwrap(),
            commitment,
        },
        proof_masks,
        round_challenges: round_challenges_shares.pop().unwrap(),
    };
    let verifiers = round_challenges_shares
        .into_iter()
        .zip(last_value_commitments.into_iter())
        .map(|(challenge, last_val)| OfflineVerifier {
            round_challenges: challenge,
            final_msg: OfflineCommitment {
                commit_share: last_val,
                commitment,
            },
        })
        .collect();
    (prover, verifiers)
}

fn make_round_proof<F: FieldElement>(
    z: &[F],
    log_folding_factor: usize,
    eval_ctx_at_m_to_2m_minus_1: &mut EvalCtx<F>,
) -> Vec<F> {
    let z_len = z.len();
    let L = (z_len - 1) >> log_folding_factor;
    let M = 1 << log_folding_factor;
    let mut output: Vec<F> = unsafe {
        std::mem::transmute(vec![
            std::mem::MaybeUninit::<F>::uninit();
            internal_round_proof_length(log_folding_factor)
        ])
    };
    output[0..M]
        .iter_mut()
        .zip(z[1..].chunks_exact(L))
        .for_each(|(o, is)| {
            *o = g(is);
        });
    eval_ctx_at_m_to_2m_minus_1.interpolate_with_g(&z[1..], &mut output[M..]);
    output
}
fn multi_eval_at_point<F: FieldElement>(
    z: &mut [F],
    round_proof: &[F],
    challenge: F,
    log_folding_factor: usize,
    eval_ctx_polys: &mut EvalCtx<F>,
    eval_ctx_proof: &mut EvalCtx<F>,
) -> F {
    let z_len = z.len();
    let M = 1 << log_folding_factor;
    let L = (z_len - 1) >> log_folding_factor;

    let z_output = unsafe { std::slice::from_raw_parts_mut(z[1..1 + L].as_mut_ptr(), L) };
    const CHUNK_SIZE: usize = 32;

    eval_ctx_polys.interpolate(&z[1..], z_output, 0, 1);
    let next_round_statement_size = ((L + 2 * M - 1) / (2 * M)) * (2 * M);
    for i in L..next_round_statement_size {
        z[1 + i] = F::zero();
    }
    let mut output = F::zero();
    eval_ctx_proof.interpolate(round_proof, std::slice::from_mut(&mut output), 0, 1);
    output
}
pub struct ProverCtx<F: FieldElement> {
    eval_ctx_internal_round_polys_challenge: EvalCtx<F>,
    eval_ctx_internal_round_proof_challenge: EvalCtx<F>,
    eval_ctx_internal_round_proof_gen: EvalCtx<F>,
    eval_ctx_last_round_proof_gen: EvalCtx<F>,
    eval_ctx_auth_polys: EvalCtx<F>,
    eval_ctx_auth_proof: EvalCtx<F>,
    log_folding_factor: usize,
}
impl<F: FieldElement> ProverCtx<F> {
    pub fn new(log_folding_factor: usize) -> Self {
        let mut output = Self {
            eval_ctx_internal_round_polys_challenge: EvalCtx::<F>::new(1 << log_folding_factor, 1),
            eval_ctx_internal_round_proof_challenge: EvalCtx::<F>::new(
                internal_round_proof_length(log_folding_factor),
                1,
            ),
            eval_ctx_internal_round_proof_gen: EvalCtx::<F>::new(
                1 << log_folding_factor,
                (1 << log_folding_factor) - 1,
            ),
            eval_ctx_last_round_proof_gen: EvalCtx::<F>::new(
                1 + (1 << log_folding_factor),
                1 << log_folding_factor,
            ),
            eval_ctx_auth_polys: EvalCtx::<F>::new(1 + (1 << log_folding_factor), 1),
            eval_ctx_auth_proof: EvalCtx::<F>::new(
                last_round_proof_length(log_folding_factor) - 2,
                1,
            ),
            log_folding_factor,
        };
        let proof_points: Vec<_> = ((1 << log_folding_factor)
            ..internal_round_proof_length(log_folding_factor))
            .map(|i| F::number(i as u32))
            .collect();
        output
            .eval_ctx_internal_round_proof_gen
            .prepare_at_points(&proof_points);
        let last_round_proof_points: Vec<_> = (1 + (1 << log_folding_factor)
            ..(last_round_proof_length(log_folding_factor) - 2))
            .map(|i| F::number(i as u32))
            .collect();
        output
            .eval_ctx_last_round_proof_gen
            .prepare_at_points(&last_round_proof_points);
        output
    }
}
pub async fn prover<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    mut z: &mut [F],
    offline_material: &OfflineProver<F>,
    mut auth_statement: Option<Vec<F>>,
    prover_ctx: &mut ProverCtx<F>,
) {
    let mut time = Instant::now();
    let ProverCtx {
        eval_ctx_internal_round_polys_challenge,
        eval_ctx_internal_round_proof_challenge,
        eval_ctx_internal_round_proof_gen,
        eval_ctx_last_round_proof_gen,
        eval_ctx_auth_polys,
        eval_ctx_auth_proof,
        log_folding_factor,
    } = prover_ctx;
    let log_folding_factor = *log_folding_factor;
    let OfflineProver {
        proof_masks,
        round_challenges,
        final_msg,
    } = offline_material;
    let M: usize = 1 << log_folding_factor;
    let last_round_challenge = round_challenges.last().unwrap();
    // Init
    let round_count = compute_round_count(z.len(), log_folding_factor);
    let mut b_tilde = Vec::with_capacity(round_count);
    let mut masked_internal_proof =
        vec![F::zero(); internal_round_proof_length(log_folding_factor)];
    info!("Proving: round count {}", round_count);
    // Rounds
    for (round_id, (round_challenge, masks)) in round_challenges
        .into_iter()
        .take(round_challenges.len() - 1)
        .zip(proof_masks.chunks_exact(internal_round_proof_length(log_folding_factor)))
        .enumerate()
    {
        // Computation
        let proof = make_round_proof(z, log_folding_factor, eval_ctx_internal_round_proof_gen);
        masked_internal_proof
            .iter_mut()
            .zip(proof.iter())
            .zip(masks.iter())
            .for_each(|((masked_proof_i, proof_i), mask_i)| *masked_proof_i = *proof_i - *mask_i);

        // Communication
        engine.broadcast(&masked_internal_proof);
        let r: F = round_challenge.online_decommit(&mut engine).await;
        eval_ctx_internal_round_polys_challenge.prepare_at_points(std::slice::from_ref(&r));
        eval_ctx_internal_round_proof_challenge.prepare_at_points(std::slice::from_ref(&r));
        // Query
        z[0] = multi_eval_at_point(
            &mut z,
            &proof,
            r,
            log_folding_factor,
            eval_ctx_internal_round_polys_challenge,
            eval_ctx_internal_round_proof_challenge,
        );
        let z_len = z.len();
        let L = (z_len - 1) >> log_folding_factor;
        let next_round_statement_size = ((L + 2 * M - 1) / (2 * M)) * (2 * M);
        z = &mut z[..=next_round_statement_size];
        if auth_statement.is_some() {
            // Perform the same computation as the dealer.
            let mut z_tilde = auth_statement.unwrap();
            b_tilde.push(z_tilde[0] - masks[0..M].iter().copied().sum());

            let L = (z_len - 1) / M;
            let z_output =
                unsafe { std::slice::from_raw_parts_mut(z_tilde[1..1 + L].as_mut_ptr(), L) };
            eval_ctx_internal_round_polys_challenge.interpolate(&z_tilde[1..], z_output, 0, 1);

            let next_round_size = ((L + 2 * M - 1) / (2 * M)) * (2 * M);
            // We now round up z_tilde's length to be a multiple of 2*M. This is OK for inner product.
            for i in L..next_round_size {
                z_tilde[1 + i] = F::zero();
            }
            eval_ctx_internal_round_proof_challenge.interpolate(&masks, &mut z_tilde[0..1], 0, 1);
            z_tilde.drain(1 + next_round_statement_size..);
            auth_statement = Some(z_tilde);
        }
    }
    // last round
    debug_assert_eq!(z.len(), 1 + 2 * M);
    let mut last_round_proof = Vec::with_capacity(last_round_proof_length(log_folding_factor));
    let (s_0, s_1) = (F::random(E::rng()), F::random(E::rng()));
    let proof_masks_last_round =
        &proof_masks[proof_masks.len() - last_round_proof_length(log_folding_factor)..];
    last_round_proof.push(s_0);
    last_round_proof.push(s_1);
    for i in 0..M {
        last_round_proof.push(z[1 + 2 * i] * z[2 + 2 * i]);
    }
    last_round_proof.push(s_0 * s_1);
    // let mut eval_ctx_m_plus_one_points = EvalCtx::<F>::new(M + 1);
    let last_round_buf: Vec<_> = z[1..].iter().chain([s_0, s_1].iter()).copied().collect();
    // We have both polynomials evaluated on points 0..M-1.
    // The zk blinders are evaluations at point M.
    // p(x) = g(f_0(x),f_1(x)) is of deg 2*M so we need 2*M+1 evaluations of it.
    // We need to evaluate therefore each f_i on M+1..2*M which is 2*M
    // evaluations overall.
    let mut last_round_interpolation_output = vec![F::zero(); 2 * M];
    eval_ctx_last_round_proof_gen.interpolate(
        &last_round_buf,
        &mut last_round_interpolation_output,
        0,
        1,
    );
    last_round_interpolation_output
        .chunks_exact(2)
        .for_each(|c| last_round_proof.push(c[0] * c[1]));
    last_round_proof
        .iter_mut()
        .zip(proof_masks_last_round.iter())
        .for_each(|(p, a)| *p -= *a);
    engine.broadcast(last_round_proof);
    let r: F = last_round_challenge.online_decommit(&mut engine).await;
    // Decision
    let (betas, b_tilde_check_dealer, f_0_tilde_dealer, f_1_tilde_dealer, q_tilde_dealer): (
        Vec<F>,
        F,
        F,
        F,
        F,
    ) = final_msg.online_decommit(&mut engine).await;
    if auth_statement.is_some() {
        let z_tilde = auth_statement.unwrap();
        debug_assert_eq!(z_tilde.len(), 1 + 2 * M);
        eval_ctx_auth_polys.prepare_at_points(std::slice::from_ref(&r));
        eval_ctx_auth_proof.prepare_at_points(std::slice::from_ref(&r));
        let s_tilde = (proof_masks_last_round[0], proof_masks_last_round[1]);
        let mut interpolation_buf = vec![F::zero(); 2 * M + 1];
        z_tilde
            .iter()
            .skip(1)
            .step_by(2)
            .chain(std::iter::once(&s_tilde.0))
            .zip(interpolation_buf.iter_mut())
            .for_each(|(i, o)| *o = *i);
        let mut f_0_tilde_r = F::zero();
        eval_ctx_auth_polys.interpolate(
            &interpolation_buf[..M + 1],
            std::slice::from_mut(&mut f_0_tilde_r),
            0,
            1,
        );
        z_tilde
            .iter()
            .skip(2)
            .step_by(2)
            .chain(std::iter::once(&s_tilde.1))
            .zip(interpolation_buf.iter_mut())
            .for_each(|(i, o)| *o = *i);
        let mut f_1_tilde_r = F::zero();
        eval_ctx_auth_polys.interpolate(
            &interpolation_buf[..M + 1],
            std::slice::from_mut(&mut f_1_tilde_r),
            0,
            1,
        );
        let mut g_tilde_r = F::zero();
        eval_ctx_auth_proof.interpolate(
            &proof_masks_last_round[2..],
            std::slice::from_mut(&mut g_tilde_r),
            0,
            1,
        );
        b_tilde.push(z_tilde[0] - (0..M).map(|i| proof_masks_last_round[2 + i]).sum());

        // Decision
        debug_assert_eq!(betas.len(), b_tilde.len());
        let b_tilde_check = betas
            .iter()
            .zip(b_tilde.iter())
            .map(|(a, b)| *a * *b)
            .fold(F::zero(), |acc, cur| acc + cur);

        // Decision
        debug_assert_eq!(betas.len(), b_tilde.len());
        let b_tilde_check = betas
            .iter()
            .zip(b_tilde.iter())
            .map(|(a, b)| *a * *b)
            .fold(F::zero(), |acc, cur| acc + cur);
        let final_value = (betas, b_tilde_check, f_0_tilde_r, f_1_tilde_r, g_tilde_r);

        assert_eq!(final_value.2, f_0_tilde_dealer);
        assert_eq!(final_value.3, f_1_tilde_dealer);
        assert_eq!(final_value.4, q_tilde_dealer);
        assert_eq!(b_tilde_check, b_tilde_check_dealer);
    }
    println!("Prover LAST: {} ms", time.elapsed().as_millis());
}

pub async fn verifier<F: FieldElement>(
    mut engine: impl MultiPartyEngine,
    mut z_hat: &mut [F],
    prover_id: PartyId,
    offline_material: &OfflineVerifier,
    verifier_ctx: &mut VerifierCtx<F>,
) {
    let VerifierCtx {
        eval_ctx_internal_round_proof,
        eval_ctx_internal_round_polys,
        eval_ctx_last_round_polys,
        eval_ctx_last_round_proof,
        log_folding_factor,
    } = verifier_ctx;
    let log_folding_factor = *log_folding_factor;
    // Init
    let round_count = compute_round_count(z_hat.len(), log_folding_factor);
    let M = 1 << log_folding_factor;
    debug_assert!(z_hat.iter().skip(2).step_by(2).all(|v| v.is_zero()));
    let OfflineVerifier {
        final_msg,
        round_challenges,
    } = offline_material;
    let last_round_challenge = round_challenges.last().unwrap();

    let mut b_hat = Vec::with_capacity(round_count);
    // Rounds
    for (_, round_challenge) in round_challenges
        .into_iter()
        .take(round_challenges.len() - 1)
        .enumerate()
    {
        let z_len = z_hat.len();
        let L = (z_len - 1) / M;
        let round_proof: Vec<F> = engine.recv_from(prover_id).await.unwrap();
        assert_eq!(
            round_proof.len(),
            internal_round_proof_length(log_folding_factor)
        );
        let r: F = round_challenge.online_decommit(&mut engine).await;
        b_hat.push(z_hat[0] - round_proof[0..M].iter().copied().sum());
        let z_output = unsafe { std::slice::from_raw_parts_mut(z_hat[1..1 + L].as_mut_ptr(), L) };
        const CHUNK_SIZE: usize = 32;
        eval_ctx_internal_round_polys.prepare_at_points(std::slice::from_ref(&r));
        eval_ctx_internal_round_proof.prepare_at_points(std::slice::from_ref(&r));
        eval_ctx_internal_round_polys.interpolate(&z_hat[1..], z_output, 0, 2);
        let next_round_size = ((L + 2 * M - 1) / (2 * M)) * (2 * M);
        // We now round up z_tilde's length to be a multiple of 2*M. This is OK for inner product.
        for i in L..next_round_size {
            z_hat[i + 1] = F::zero();
        }

        eval_ctx_internal_round_proof.interpolate(&round_proof, &mut z_hat[0..1], 0, 1);
        z_hat = &mut z_hat[..=next_round_size];
    }
    //last_round
    debug_assert_eq!(z_hat.len(), 1 + 2 * M);
    let last_round_proof: Vec<F> = engine.recv_from(prover_id).await.unwrap();
    assert_eq!(
        last_round_proof.len(),
        last_round_proof_length(log_folding_factor)
    );
    let r: F = last_round_challenge.online_decommit(&mut engine).await;
    eval_ctx_last_round_polys.prepare_at_points(std::slice::from_ref(&r));
    let interpolation_buf: Vec<F> = z_hat[1..]
        .iter()
        .chain(&last_round_proof[0..2])
        .copied()
        .collect();
    let mut f_hat_r = [F::zero(); 2];
    eval_ctx_last_round_polys.interpolate(&interpolation_buf, &mut f_hat_r, 0, 1);
    eval_ctx_last_round_proof.prepare_at_points(std::slice::from_ref(&r));
    let mut q_hat_r = F::zero();
    eval_ctx_last_round_proof.interpolate(
        &last_round_proof[2..],
        std::slice::from_mut(&mut q_hat_r),
        0,
        1,
    );
    b_hat.push(z_hat[0] - last_round_proof[2..2 + M].iter().copied().sum());

    // Decision
    let (betas, b_tilde_check, f_0_tilde_r, f_1_tilde_r, q_tilde_r): (Vec<F>, F, F, F, F) =
        final_msg.online_decommit(&mut engine).await;
    assert_eq!(betas.len(), b_hat.len());
    let b_hat_check = betas
        .iter()
        .zip(b_hat.iter())
        .map(|(a, b)| *a * *b)
        .fold(F::zero(), |acc, cur| acc + cur);
    assert_eq!(b_tilde_check + b_hat_check, F::zero());
    let f_0_r = f_0_tilde_r + f_hat_r[0];
    let f_1_r = f_1_tilde_r + f_hat_r[1];
    let q_r = q_tilde_r + q_hat_r;
    assert_eq!(q_r, f_0_r * f_1_r);
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::simd::u64x2;
    use std::time::Instant;

    use aes_prng::AesRng;
    use futures::future::join_all;
    use futures::future::try_join_all;
    use rand::thread_rng;
    use tokio::join;

    use super::compute_round_count;
    use super::g;
    use super::internal_round_proof_length;
    use super::last_round_proof_length;
    use super::EvalCtx;
    use super::{dealer, prover, verifier, OfflineVerifier};
    use super::{ProverCtx, VerifierCtx};
    use crate::engine::LocalRouter;
    use crate::uc_tags::UCTag;
    use crate::zkfliop::PowersIterator;
    use crate::{
        engine::PartyId,
        fields::{FieldElement, GF128},
    };

    #[test]
    fn test_evalctx() {
        let mut rng = AesRng::from_random_seed();
        const POLYS_COUNT: usize = 16;
        const DEGREE: usize = 15;
        const EVAL_POINTS: usize = 15;
        let mut eval_ctx = EvalCtx::<GF128>::new(DEGREE + 1, EVAL_POINTS);
        let polys: Vec<Vec<_>> = (0..POLYS_COUNT)
            .map(|_| (0..DEGREE).map(|_| GF128::random(&mut rng)).collect())
            .collect();
        let eval_points: Vec<_> = ((DEGREE + 1)..(DEGREE + 1 + EVAL_POINTS))
            .map(|i| GF128::number(i as u32))
            .collect();
        let eval_input_points: Vec<_> = (0..=DEGREE).map(|i| GF128::number(i as u32)).collect();
        let mut evals_input = vec![GF128::zero(); POLYS_COUNT * (DEGREE + 1)];
        for (point_idx, point) in eval_input_points.iter().enumerate() {
            for (poly_idx, poly) in polys.iter().enumerate() {
                let powers = PowersIterator::new(*point);
                let mut sum = poly[0];
                sum += poly[1..]
                    .iter()
                    .copied()
                    .zip(powers)
                    .map(|(a, b)| a * b)
                    .sum::<GF128>();
                evals_input[point_idx * POLYS_COUNT + poly_idx] = sum;
            }
        }
        let mut evals_output: Vec<GF128> = vec![GF128::zero(); EVAL_POINTS * POLYS_COUNT];
        for (point_idx, point) in eval_points.iter().enumerate() {
            for (poly_idx, poly) in polys.iter().enumerate() {
                let powers = PowersIterator::new(*point);
                let mut sum = poly[0];
                sum += poly[1..]
                    .iter()
                    .copied()
                    .zip(powers)
                    .map(|(a, b)| a * b)
                    .sum::<GF128>();
                evals_output[point_idx * POLYS_COUNT + poly_idx] = sum;
            }
        }
        eval_ctx.prepare_at_points(&eval_points);
        let mut output: Vec<GF128> = vec![GF128::zero(); EVAL_POINTS * POLYS_COUNT];
        eval_ctx.interpolate(&evals_input, &mut output, 0, 1);
        // verify
        assert_eq!(evals_output, output);

        let mut inter_with_g_output = vec![GF128::zero(); EVAL_POINTS];
        eval_ctx.interpolate_with_g(&evals_input, &mut inter_with_g_output);
        for ((point_idx, point), evals_at_point) in eval_points
            .iter()
            .enumerate()
            .zip(evals_output.chunks_exact(POLYS_COUNT))
        {
            assert_eq!(inter_with_g_output[point_idx], g(evals_at_point));
        }
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn test_zkfliop() {
        const LOG_FOLDING_FACTOR: usize = 1;
        const LOG: usize = 25;
        const Z_LEN: usize = 1 + 100_000;
        const PARTIES: usize = 3;
        const ONLINE_PARTIES: usize = PARTIES - 1;
        let party_ids: [PartyId; PARTIES] = core::array::from_fn(|i| i as u64);
        let online_party_ids: [PartyId; ONLINE_PARTIES] = core::array::from_fn(|i| (i + 1) as u64);
        let prover_id = party_ids[1];

        let mut rng = thread_rng();

        // Offline proof preparation
        let mut dealer_input: Vec<_> = vec![GF128::zero(); Z_LEN];
        dealer_input
            .iter_mut()
            .step_by(2)
            .for_each(|v| *v = GF128::random(&mut rng));
        let mut dealer_input_clone = dealer_input.clone();
        let mut dealer_ctx = VerifierCtx::<GF128>::new(LOG_FOLDING_FACTOR);
        let mut prover_ctx = ProverCtx::<GF128>::new(LOG_FOLDING_FACTOR);
        let mut verifiers_ctx: Vec<_> = (0..PARTIES - 2)
            .map(|_| VerifierCtx::<GF128>::new(LOG_FOLDING_FACTOR))
            .collect();
        let time = Instant::now();
        let (prover_offline, verifiers_offline) =
            dealer(&mut dealer_input_clone, PARTIES - 2, &mut dealer_ctx);
        println!("Dealer time: {}", time.elapsed().as_millis());

        // Online proof.
        let online_party_ids_set = HashSet::from_iter(online_party_ids.iter().copied());
        let (router, mut engines) = LocalRouter::new(UCTag::new(&"root"), &online_party_ids_set);
        let router_handle = tokio::spawn(router.launch());

        let mut prover_input = Vec::with_capacity(Z_LEN);
        unsafe { prover_input.set_len(Z_LEN) };
        for i in (1..prover_input.len()).step_by(2) {
            prover_input[i] = GF128::random(&mut rng);
        }
        for i in (2..prover_input.len()).step_by(2) {
            prover_input[i] = dealer_input[i];
        }
        prover_input[0] = g(&prover_input[1..]);

        let mut verifier_input: Vec<_> = prover_input
            .iter()
            .enumerate()
            .map(|(idx, v)| if idx % 2 != 0 { *v } else { GF128::zero() })
            .collect();
        verifier_input[0] = prover_input[0] - dealer_input[0];

        let prover_exec = engines.remove(&prover_id).unwrap();
        let prover_future = tokio::spawn(async move {
            let mut prover_input = prover_input;
            prover(
                prover_exec,
                &mut prover_input,
                &prover_offline,
                // Some(dealer_input),
                None,
                &mut prover_ctx,
            )
            .await
        });
        let verifiers_futures: Vec<_> = verifiers_offline
            .into_iter()
            .zip(engines.into_iter())
            .zip(verifiers_ctx.into_iter())
            .map(|((v, (pid, engine)), mut verifier_ctx)| {
                let input = verifier_input.clone();
                async move {
                    let mut input = input;
                    verifier(engine, &mut input, prover_id, &v, &mut verifier_ctx).await;
                    Result::<(), ()>::Ok(())
                }
            })
            .collect();
        let v = try_join_all(verifiers_futures);
        let (_, v) = join!(prover_future, v);
        v.unwrap();
        router_handle.await.unwrap().unwrap();
    }
}
