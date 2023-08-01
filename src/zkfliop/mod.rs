use std::time::Instant;

use crate::{
    commitment::{commit_value, CommmitShare, OfflineCommitment},
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, IntermediateMulField, MulResidue},
    pcg::RegularBeaverTriple,
};
use aes_prng::AesRng;
use blake3::{Hasher, OUT_LEN};
use log::info;
use rand_core::{RngCore, SeedableRng};
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
const CHUNK_SIZE: usize = 1 << 4;
pub struct PowersIterator<F: FieldElement> {
    alpha_pow: F,
    current: [F; CHUNK_SIZE],
    index: usize,
}
impl<F: FieldElement> PowersIterator<F> {
    pub fn new(alpha: F) -> Self {
        let mut cur = F::one();
        let current = core::array::from_fn(|_| {
            let output = cur;
            cur *= alpha;
            output
        });
        let alpha_pow = cur * alpha;

        Self {
            alpha_pow,
            current,
            index: 0,
        }
    }
}
impl<F: FieldElement> Iterator for PowersIterator<F> {
    type Item = F;
    fn next(&mut self) -> Option<Self::Item> {
        let output = Some(self.current[self.index]);
        self.index += 1;
        self.index &= CHUNK_SIZE - 1;
        if self.index == 0 {
            self.current[0] *= self.alpha_pow;
            self.current[1] *= self.alpha_pow;
            self.current[2] *= self.alpha_pow;
            self.current[3] *= self.alpha_pow;
            self.current[4] *= self.alpha_pow;
            self.current[5] *= self.alpha_pow;
            self.current[6] *= self.alpha_pow;
            self.current[7] *= self.alpha_pow;
            self.current[8] *= self.alpha_pow;
            self.current[9] *= self.alpha_pow;
            self.current[10] *= self.alpha_pow;
            self.current[11] *= self.alpha_pow;
            self.current[12] *= self.alpha_pow;
            self.current[13] *= self.alpha_pow;
            self.current[14] *= self.alpha_pow;
            self.current[15] *= self.alpha_pow;
        }
        output
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
pub fn g_mul_res<F: IntermediateMulField>(z: &[F::MulRes]) -> F {
    z.chunks_exact(2)
        .map(|f| f[0].reduce() * f[1].reduce())
        .sum()
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OfflineProver<F: FieldElement> {
    #[serde(bound = "")]
    proof_masks: Vec<F>,
    round_challenges_commitments: Vec<[u8; OUT_LEN]>,
    final_msg_commitment: [u8; OUT_LEN],
}

impl<F: FieldElement> OfflineProver<F> {
    pub fn get_round_count(&self) -> usize {
        self.round_challenges_commitments.len()
    }
    pub fn hash(&self) -> [u8; OUT_LEN] {
        let mut hasher = Hasher::new();
        self.proof_masks.iter().for_each(|v| {
            hasher.update(v.as_bytes());
        });
        self.round_challenges_commitments.iter().for_each(|v| {
            hasher.update(&v[..]);
        });
        hasher.update(&self.final_msg_commitment);
        *hasher.finalize().as_bytes()
    }
}
// pub fn generate_fliop_verification_statement_prover<F: FieldElement>(
//     prover: &OfflineProver<F>,
//     masks: &mut [F],
//     log_folding_factor: usize,
// ) -> Vec<F> {
//     /// The masks_and_output should be of length that is a multiple of 2M.
//     /// The part not made of masks should be zeros.
//     let M = 1 << log_folding_factor;
//     let initial_length = (masks.len() + 2 * M - 1) / (2 * M);
//     let mut output_vec: Vec<_> = masks
//         .iter()
//         .copied()
//         .chain(
//             std::iter::once(F::zero())
//                 .cycle()
//                 .take(initial_length - masks.len()),
//         )
//         .collect();
//     let mut window_size = output_vec.len() / M;
//     while  {

//     }
// }
// pub fn generate_fliop_verification_statement_verifier<F: FieldElement>(
//     prover: &OfflineVerifier,
//     masks: &mut [F],
//     log_folding_factor: usize,
// ) -> Vec<F> {
//     /// The masks_and_output should be of length that is a multiple of 2M.
//     /// The part not made of masks should be zeros.
//     let M = 1 << log_folding_factor;
//     let initial_length = (masks.len() + 2 * M - 1) / (2 * M);
//     let mut output_vec: Vec<_> = masks
//         .iter()
//         .copied()
//         .chain(
//             std::iter::once(F::zero())
//                 .cycle()
//                 .take(initial_length - masks.len()),
//         )
//         .collect();
//     let mut window_size = output_vec.len() / M;
//     while  {

//     }
// }

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OfflineVerifier<F: FieldElement> {
    #[serde(bound = "")]
    round_challenges: Vec<F>,
    #[serde(bound = "")]
    final_msg: ([u8; 16], F, F, F, F),
}
impl<F: FieldElement> OfflineVerifier<F> {
    pub fn hash(&self) -> [u8; OUT_LEN] {
        let mut hasher = Hasher::new();
        self.round_challenges.iter().for_each(|v| {
            hasher.update(v.as_bytes());
        });
        hasher.update(&self.final_msg.0);
        hasher.update(self.final_msg.1.as_bytes());
        hasher.update(self.final_msg.2.as_bytes());
        hasher.update(self.final_msg.3.as_bytes());
        hasher.update(self.final_msg.4.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

struct EvalCtx<F: IntermediateMulField> {
    numbers: Vec<F>,
    prefix_buf: Vec<F>,
    suffix_buf: Vec<F>,
    denoms: Vec<F>,
    eval_points: usize,
    coeffs: Vec<F>,
    interpolation_buf: Vec<F::MulRes>,
}
impl<F: IntermediateMulField> EvalCtx<F> {
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
            interpolation_buf: vec![F::zero().into(); interpolation_points * eval_points],
        }
    }
    fn obtain_coeffs(&self) -> &[F] {
        &self.coeffs
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
        // let L = evals.len() / M;
        // assert_eq!(output.len(), L * self.eval_points);
        let L = output.len() / self.eval_points;
        // assert_eq!(evals.len(), L * M);
        // output[i*L + j] is the evaluation
        // of i-th eval point on j-th polynomial.
        // output.iter_mut().for_each(|v| *v = F::zero());
        for poly_chunk_base in (0..L).step_by(M) {
            self.interpolation_buf
                .iter_mut()
                .for_each(|v| *v = F::zero().into());
            let poly_chunk_size = usize::min(L, poly_chunk_base + M) - poly_chunk_base;
            for evalled in 0..M {
                let in_coeff_idx = evalled * L + poly_chunk_base;
                if in_coeff_idx >= evals.len() {
                    continue;
                }
                let current_chunk_size = poly_chunk_size.min(evals.len() - in_coeff_idx);
                for eval_point in 0..self.eval_points {
                    for p in (base..current_chunk_size).step_by(step) {
                        self.interpolation_buf[eval_point * M + p] += evals[in_coeff_idx + p]
                            .intermediate_mul(
                                &self.coeffs[eval_point + evalled * self.eval_points],
                            );
                        // output[eval_point * L + poly_chunk_base + p] += evals[in_coeff_idx + p]
                        // * self.coeffs[eval_point + evalled * self.eval_points];
                    }
                }
            }
            for eval_point in 0..self.eval_points {
                for p in 0..poly_chunk_size {
                    output[eval_point * L + poly_chunk_base + p] =
                        self.interpolation_buf[eval_point * M + p].reduce();
                }
            }
        }
    }
    // Denoms are independent of evaluation point and therefore can be preprocessed.
    fn interpolate_with_g<'a>(&mut self, evals: &[F], output: &mut [F]) {
        let M = self.denoms.len();
        output.iter_mut().for_each(|v| *v = F::zero());
        // let L = evals.len() / M;
        let L = compute_L(evals.len() + 1, M.ilog2() as usize);
        assert_eq!(output.len(), self.eval_points);
        // assert_eq!(evals.len(), L * M);
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
        // let mut interpolation_buf = vec![F::zero(); M * self.eval_points];
        for poly_chunk_base in (0..L).step_by(M) {
            self.interpolation_buf
                .iter_mut()
                .for_each(|v| *v = F::zero().into());
            let poly_chunk_size = usize::min(L, poly_chunk_base + M) - poly_chunk_base;
            for evalled in 0..M {
                let in_coeff_idx = evalled * L + poly_chunk_base;
                if in_coeff_idx >= evals.len() {
                    continue;
                }
                let current_chunk_size = poly_chunk_size.min(evals.len() - in_coeff_idx);
                for eval_point in 0..self.eval_points {
                    let c = self.coeffs[eval_point + evalled * self.eval_points];
                    self.interpolation_buf[eval_point * M..eval_point * M + poly_chunk_size]
                        .iter_mut()
                        .zip(evals[in_coeff_idx..(in_coeff_idx + current_chunk_size)].iter())
                        .for_each(|(o, i)| {
                            *o += c.intermediate_mul(i);
                        });
                }
            }
            output
                .iter_mut()
                .zip(self.interpolation_buf.chunks(M))
                .for_each(|(o, chunk)| {
                    // Ok because entries we didn't touch are zero.
                    *o += g_mul_res(chunk);
                });
        }
    }
}
pub struct VerifierCtx<F: IntermediateMulField> {
    eval_ctx_internal_round_proof: EvalCtx<F>,
    eval_ctx_internal_round_polys: EvalCtx<F>,
    eval_ctx_last_round_polys: EvalCtx<F>,
    eval_ctx_last_round_proof: EvalCtx<F>,
    log_folding_factor: usize,
}
impl<F: IntermediateMulField> VerifierCtx<F> {
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
pub fn dealer<F: IntermediateMulField>(
    mut z_tilde: &mut [F],
    num_verifiers: usize,
    verifier_ctx: &mut VerifierCtx<F>,
) -> (OfflineProver<F>, Vec<OfflineVerifier<F>>) {
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
    let mut round_challenges = Vec::with_capacity(round_count);
    let mut round_challenges_commitments = Vec::with_capacity(round_count);
    let M = 1 << log_folding_factor;
    let mut pow = 2 * M;
    while pow < (z_tilde.len() - 1) {
        pow *= M;
    }
    let mut z_len = 1 + pow;
    for round_id in 1..round_count {
        let r = F::random(&mut rng);
        let r_comm = commit_value(&r);
        round_challenges_commitments.push(r_comm);
        round_challenges.push(r);
        // let (challenge_commit_shares, commitment) =
        //     OfflineCommitment::commit(&r, num_verifiers + 1);
        // round_challenges_shares
        //     .iter_mut()
        //     .zip(challenge_commit_shares.into_iter())
        //     .for_each(|(v, commit_share)| {
        //         v.push(OfflineCommitment {
        //             commit_share,
        //             commitment,
        //         });
        //     });
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
        z_len = 1 + (z_len - 1) / M;
    }
    // last round
    debug_assert_eq!(z_tilde.len(), 1 + 2 * M);
    let r = F::random(&mut rng);
    let r_comm = commit_value(&r);
    round_challenges.push(r);
    round_challenges_commitments.push(r_comm);
    // let (challenge_commit_shares, commitment) = OfflineCommitment::commit(&r, num_verifiers + 1);
    // round_challenges_shares
    //     .iter_mut()
    //     .zip(challenge_commit_shares.into_iter())
    //     .for_each(|(v, commit_share)| {
    //         v.push(OfflineCommitment {
    //             commit_share,
    //             commitment,
    //         });
    //     });
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
    let mut betas_seed: [u8; 16] = core::array::from_fn(|_| 0u8);
    rng.fill_bytes(&mut betas_seed);
    let mut betas_rng = AesRng::from_seed(betas_seed);
    let betas: Vec<_> = (0..round_count)
        .map(|_| F::random(&mut betas_rng))
        .collect();
    debug_assert_eq!(betas.len(), b_tilde.len());
    let b_tilde_check = betas
        .iter()
        .zip(b_tilde.iter())
        .map(|(a, b)| *a * *b)
        .fold(F::zero(), |acc, cur| acc + cur);
    let final_msg = (
        betas_seed,
        b_tilde_check,
        f_tilde_r[0],
        f_tilde_r[1],
        g_tilde_r,
    );
    let final_msg_commitment = commit_value(&final_msg);
    let (mut last_value_commitments, commitment) =
        OfflineCommitment::commit(&final_msg, num_verifiers + 1);
    let prover = OfflineProver {
        final_msg_commitment,
        round_challenges_commitments,
        // final_msg: OfflineCommitment {
        //     commit_share: last_value_commitments.pop().unwrap(),
        //     commitment,
        // },
        proof_masks,
        // round_challenges: round_challenges_shares.pop().unwrap(),
    };
    let verifiers = vec![
        OfflineVerifier {
            round_challenges,
            final_msg
        };
        num_verifiers
    ];
    // (0..num_verifiers)
    // .into_iter()
    // .zip(last_value_commitments.into_iter())
    // .map(|(challenge, last_val)| OfflineVerifier {
    //     round_challenges: challenge,
    //     final_msg: OfflineCommitment {
    //         commit_share: last_val,
    //         commitment,
    //     },
    // })
    // .collect();
    (prover, verifiers)
}

fn compute_L(z_len: usize, log_folding_factor: usize) -> usize {
    let mut pow = 2 << log_folding_factor;
    while pow < z_len - 1 {
        pow <<= log_folding_factor;
    }
    pow >> log_folding_factor
}
fn make_round_proof<F: IntermediateMulField>(
    z: &[F],
    log_folding_factor: usize,
    eval_ctx_at_m_to_2m_minus_1: &mut EvalCtx<F>,
) -> Vec<F> {
    let z_len = z.len();
    let L = compute_L(z_len, log_folding_factor);
    let M = 1 << log_folding_factor;
    let mut output: Vec<F> = unsafe {
        std::mem::transmute(vec![
            std::mem::MaybeUninit::<F>::uninit();
            internal_round_proof_length(log_folding_factor)
        ])
    };
    output[0..M].iter_mut().for_each(|v| *v = F::zero());
    output[0..M]
        .iter_mut()
        .zip(z[1..].chunks(L))
        .for_each(|(o, is)| {
            *o = g(is);
        });
    eval_ctx_at_m_to_2m_minus_1.interpolate_with_g(&z[1..], &mut output[M..]);
    output
}
fn multi_eval_at_point<F: IntermediateMulField>(
    z: &mut [F],
    round_proof: &[F],
    challenge: F,
    log_folding_factor: usize,
    eval_ctx_polys: &mut EvalCtx<F>,
    eval_ctx_proof: &mut EvalCtx<F>,
) -> F {
    let z_len = z.len();
    let M = 1 << log_folding_factor;
    let L = compute_L(z_len, log_folding_factor);

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
pub struct ProverCtx<F: IntermediateMulField> {
    eval_ctx_internal_round_polys_challenge: EvalCtx<F>,
    eval_ctx_internal_round_proof_challenge: EvalCtx<F>,
    eval_ctx_internal_round_proof_gen: EvalCtx<F>,
    eval_ctx_last_round_proof_gen: EvalCtx<F>,
    eval_ctx_auth_polys: EvalCtx<F>,
    eval_ctx_auth_proof: EvalCtx<F>,
    log_folding_factor: usize,
}
impl<F: IntermediateMulField> ProverCtx<F> {
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
pub async fn prover<F: IntermediateMulField, E: MultiPartyEngine>(
    mut engine: E,
    mut z: &mut [F],
    offline_material: &OfflineProver<F>,
    prover_ctx: &mut ProverCtx<F>,
) {
    debug_assert_eq!(z[0], g(&z[1..]));
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
    let challenges_sender = *engine
        .party_ids()
        .iter()
        .find(|v| **v != engine.my_party_id())
        .unwrap();
    let OfflineProver {
        proof_masks,
        round_challenges_commitments,
        final_msg_commitment,
    } = offline_material;
    let M: usize = 1 << log_folding_factor;
    let last_round_challenge_commitment = round_challenges_commitments.last().unwrap();
    // Init
    let round_count = compute_round_count(z.len(), log_folding_factor);
    let mut masked_internal_proof =
        vec![F::zero(); internal_round_proof_length(log_folding_factor)];
    let mut pow = 2 * M;
    while pow < (z.len() - 1) {
        pow *= M;
    }
    let mut z_len = 1 + pow;
    // Rounds
    for (round_id, (round_challenge_commitments, masks)) in round_challenges_commitments
        .into_iter()
        .take(round_challenges_commitments.len() - 1)
        .zip(proof_masks.chunks_exact(internal_round_proof_length(log_folding_factor)))
        .enumerate()
    {
        // Computation
        let L = (z_len - 1) >> log_folding_factor;
        let proof = make_round_proof(z, log_folding_factor, eval_ctx_internal_round_proof_gen);
        masked_internal_proof
            .iter_mut()
            .zip(proof.iter())
            .zip(masks.iter())
            .for_each(|((masked_proof_i, proof_i), mask_i)| *masked_proof_i = *proof_i - *mask_i);

        // Communication
        engine.broadcast(&masked_internal_proof);
        let r: F = engine.recv_from(challenges_sender).await.unwrap();
        assert_eq!(&commit_value(&r), round_challenge_commitments);
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
        // let z_len = z.len();
        let next_round_statement_size = ((L + 2 * M - 1) / (2 * M)) * (2 * M);
        z = &mut z[..=next_round_statement_size];
        z_len = 1 + (z_len - 1) / M;
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
    // let r: F = last_round_challenge.online_decommit(&mut engine).await;
    let r: F = engine.recv_from(challenges_sender).await.unwrap();
    assert_eq!(&commit_value(&r), last_round_challenge_commitment);
    // Decision
    let last_round_msg: ([u8; 16], F, F, F, F) = engine.recv_from(challenges_sender).await.unwrap();
    assert_eq!(&commit_value(&last_round_msg), final_msg_commitment);
    let (betas_seed, b_tilde_check_dealer, f_0_tilde_dealer, f_1_tilde_dealer, q_tilde_dealer) =
        last_round_msg;
    // ) = final_msg.online_decommit(&mut engine).await;
}

pub async fn verifier<F: IntermediateMulField>(
    mut engine: impl MultiPartyEngine,
    mut z_hat: &mut [F],
    prover_id: PartyId,
    offline_material: &OfflineVerifier<F>,
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
    let challenges_sender = *engine
        .party_ids()
        .iter()
        .find(|v| **v != prover_id)
        .unwrap();
    let should_send_challenge = challenges_sender == engine.my_party_id();

    let mut b_hat = Vec::with_capacity(round_count);
    let mut pow = 2 * M;
    while pow < (z_hat.len() - 1) {
        pow *= M;
    }
    let mut z_len = 1 + pow;
    // Rounds
    for (_, round_challenge) in round_challenges
        .into_iter()
        .take(round_challenges.len() - 1)
        .enumerate()
    {
        let L = (z_len - 1) / M;
        let round_proof: Vec<F> = engine.recv_from(prover_id).await.unwrap();
        assert_eq!(
            round_proof.len(),
            internal_round_proof_length(log_folding_factor)
        );
        let r = round_challenge;
        if should_send_challenge {
            engine.send(r, prover_id);
        }
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
        z_len = 1 + (z_len - 1) / M;
    }
    //last_round
    debug_assert_eq!(z_hat.len(), 1 + 2 * M);
    let last_round_proof: Vec<F> = engine.recv_from(prover_id).await.unwrap();
    assert_eq!(
        last_round_proof.len(),
        last_round_proof_length(log_folding_factor)
    );
    let r: F = *last_round_challenge;
    if should_send_challenge {
        engine.send(r, prover_id);
    }
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
    if should_send_challenge {
        engine.send(final_msg, prover_id);
    }
    let (betas_seed, b_tilde_check, f_0_tilde_r, f_1_tilde_r, q_tilde_r): ([u8; 16], F, F, F, F) =
        *final_msg;
    let mut betas_rng = AesRng::from_seed(betas_seed);
    let betas: Vec<_> = (0..round_count)
        .map(|_| F::random(&mut betas_rng))
        .collect();
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

/// The Verification of the FLIOP correlation can be described as a degree-2 circuit of the following input:
///
/// First, we denote With L_{i,S}^x the lagrange coefficient of point i at point x from set of points S.
/// That is, the coefficient f(x)  is interpolated by sum_{i in S} f(i)*(L_{i,S}^x).
/// We wish to express this circuit for folding factor M.
///
/// The verifier is holding the round challenges (r_1,...,r_rho) and the values beta_1,...,beta_rho as well as the expected resulting check values determined by the dealer.
/// The online prover is holding the masks, the zk-blinding-factors the mask s and the proof masks.
/// The parties should verify that both sum beta_i * b_i is correct (held by the online verifier) and that the masked share of q(r)-f_1(r)*f_2(r) is correct (also held by the online verifier).
/// Their input to the degree-2 circuit that computes sum beta_i * b_i is:
///     - For verifier each summand of can be described easily if we have a circuit for b_i.
///         - Each b_i is z[0] - sum(pi_i[0]...pi_i[M-1]) where:
///             - pi[0]...pi[M-1] are known to the online prover.
///             - z[0] is shared between the online prover and verifier with a degree two circuit taking:
///                 - From the prover       [pi_(i-1)[0]        ...     pi_(i-1)[M]         ]
///                 - From the verifier:    [L_(0,[M])^r_(i-1)....      L_(M,[M]^r_(i-1))   ]
///             - Except for the first round where z[0] is known to the online prover which is exactly s.
///         - So beta_i*b_i can be computed by:
///             - For i=1:
///                 - For the prover:   [s - sum(pi_1[0]...pi_1[M-1])]
///                 - For the verifier: [beta_1]
///             - For i > 1:
///                 - For the prover:   [s - sum(pi_1[0]...pi_1[M-1])]
///                 - From the prover       [pi_(i-1)[0]                ... pi_(i-1)[M]                 sum(pi_i[0..M])]
///                 - From the verifier:    [beta_i * L_(0,[M])^r_(i-1) ... beta_i * L_(M,[M]^r_(i-1))  beta_i ]
///         - To obtain sum, simply concatanate shares.
///
/// Their input to the degree-2 circuit that computes q(r_rho)-f_1(r_rho)*f_2(r_rho) is:
///     - For computing q(r_rho) they interpolate the masked proof on r_rho, similar to what we already did.
///     - For computing f_2(r_rho) they multiply L_{M,[M+1]} by z_2 (the blinding factor held by the prover).
///     - For computing f_1(r_rho) they generate the following inputs:
///         - The prover computes recursively the differences vector.
///         - The verifier computes iteratively the lagrange coefficients subsets multiplication vector.
///         - The prover adds a last item of z_1.
///         - The verifier adds a last item of L_{M,[M+1]}^{r_rho} and is multiplying each consecutive M values by L_{i,[M+1]}^{r_rho} for i in 0..M-1.
pub fn verify_fliop_construct_statement<
    I: Iterator<Item = F>,
    F: FieldElement + IntermediateMulField,
>(
    prover_semi_honest_masks: Option<I>,
    prover: Option<&OfflineProver<F>>,
    prover_s: Option<F>,
    verifier: Option<&OfflineVerifier<F>>,
    masks_count: usize,
    log_folding_factor: usize,
    powers: &mut PowersIterator<F>,
    output: &mut [F],
) -> F {
    let M = 1 << log_folding_factor;
    // We check four equalities.
    let f_2_coefficient = powers.next().unwrap();
    let f_1_coefficient = powers.next().unwrap();
    let q_r_coefficient = powers.next().unwrap();
    let bi_betai_coefficient = powers.next().unwrap();

    let mut output_val = F::zero();
    if prover_s.is_some() {
        let OfflineProver {
            proof_masks,
            round_challenges_commitments,
            final_msg_commitment,
        } = prover.unwrap();
        let masks = prover_semi_honest_masks.unwrap();
        let s = prover_s.unwrap();
        let last_round_proof_size = last_round_proof_length(log_folding_factor);
        let internal_round_proof_size = internal_round_proof_length(log_folding_factor);
        let internal_round_count =
            (proof_masks.len() - last_round_proof_size) / internal_round_proof_size;
        let z_1 = proof_masks[internal_round_proof_size * internal_round_count];
        let z_2 = proof_masks[internal_round_proof_size * internal_round_count + 1];
        // First, verify f_2_r, this is the longest verification.
        let first_eq_start = 0;
        let first_eq_len = (masks_count + 1) * 2;
        output[first_eq_start..first_eq_start + first_eq_len]
            .iter_mut()
            .step_by(2)
            .zip(masks.chain(std::iter::once(z_2)))
            .for_each(|(o, i)| *o = i);

        // Verify f_1_r
        let second_eq_start = first_eq_start + first_eq_len;
        let second_eq_len = 2;
        output[second_eq_start] = z_1;

        // Verify q_r
        let third_eq_start = second_eq_start + second_eq_len;
        let third_eq_len = proof_masks.len() - 1;
        output[third_eq_start] = s;
        output[third_eq_start + 2..]
            .iter_mut()
            .step_by(2)
            .zip(
                proof_masks
                    .iter()
                    .take(internal_round_count * internal_round_proof_size)
                    .chain(
                        proof_masks
                            .iter()
                            .skip(internal_round_proof_size * internal_round_count + 2),
                    ),
            )
            .for_each(|(o, i)| *o = *i);

        // Verify bi_betai
        // We don't need anything extra here.
    } else {
        output.iter_mut().step_by(2).for_each(|o| *o = F::zero());
    }
    if verifier.is_some() {
        let OfflineVerifier {
            round_challenges,
            final_msg: (betas_seed, bi_betai, f_1_r, f_2_r, q_r),
        } = verifier.unwrap();
        let round_count = round_challenges.len();
        let mut betas_rng = AesRng::from_seed(*betas_seed);
        let betas: Vec<_> = (0..round_count)
            .map(|_| F::random(&mut betas_rng))
            .collect();
        let mut verifier_ctx = EvalCtx::new(M, round_challenges.len() - 1);
        verifier_ctx.prepare_at_points(&round_challenges[0..round_challenges.len() - 1]);
        let coeffs = verifier_ctx.obtain_coeffs();
        let mut verifier_ctx_last = EvalCtx::new(M + 1, 1);
        verifier_ctx_last.prepare_at_points(std::slice::from_ref(round_challenges.last().unwrap()));
        let last_coeffs = verifier_ctx_last.obtain_coeffs();

        // Set expected output
        output_val = *f_1_r * f_1_coefficient
            + *f_2_r * f_2_coefficient
            + *q_r * q_r_coefficient
            + *bi_betai * bi_betai_coefficient;

        // First, verify f_2_r
        let first_eq_start = 1;
        let first_eq_len = (masks_count + 1) * 2;
        output[first_eq_start + first_eq_len - 2] = *last_coeffs.last().unwrap() * f_2_coefficient;
        let first_eq_output = &mut output[first_eq_start..first_eq_start + first_eq_len - 2];
        let to = M.min(masks_count);
        first_eq_output
            .iter_mut()
            .step_by(2)
            .take(to)
            .zip(last_coeffs.iter())
            .for_each(|(o, c)| {
                *o = f_2_coefficient * *c;
            });
        let mut window_size = M;
        let internal_round_count = round_challenges.len() - 1;
        for i in (0..internal_round_count).rev() {
            coeffs
                .iter()
                .skip(i)
                .step_by(internal_round_count)
                .enumerate()
                .rev()
                .for_each(|(idx, c)| {
                    let max_index = window_size * (idx + 1) - 1;
                    let min_index = window_size * idx;
                    let iterations = if max_index < masks_count {
                        window_size
                    } else if min_index >= masks_count {
                        0
                    } else {
                        masks_count - min_index
                    };
                    let base_out = window_size * idx;
                    for j in 0..iterations {
                        first_eq_output[2 * (base_out + j)] = first_eq_output[2 * j] * *c;
                    }
                });
            window_size *= M;
        }
        assert!(window_size >= masks_count);

        // Second, verify f_1_r
        let second_eq_start = first_eq_start + first_eq_len;
        let second_eq_len = 2;
        output[second_eq_start] = f_1_coefficient * *last_coeffs.last().unwrap();

        // Verify q_r -- this depends only on last proof masks.
        let third_eq_start = second_eq_start + second_eq_len;
        let s_start = third_eq_start;
        let first_mask_start = s_start + 2;
        let last_round_start = first_mask_start
            + 2 * internal_round_count * internal_round_proof_length(log_folding_factor);
        output[third_eq_start
            ..(last_round_start - 1 + 2 * (last_round_proof_length(log_folding_factor) - 2))]
            .iter_mut()
            .step_by(2)
            .for_each(|o| *o = F::zero());
        let mut interpolation_ctx = EvalCtx::new(2 * M + 1, 1);
        interpolation_ctx.prepare_at_points(std::slice::from_ref(round_challenges.last().unwrap()));
        let coeffs = interpolation_ctx.obtain_coeffs();
        output[last_round_start..]
            .iter_mut()
            .step_by(2)
            .zip(coeffs)
            .for_each(|(o, i)| *o = *i * q_r_coefficient);

        // verify bi_betai
        let internal_round_proof_len = internal_round_proof_length(log_folding_factor);
        let mut interpolation_ctx =
            EvalCtx::new(internal_round_proof_len, round_challenges.len() - 1);
        interpolation_ctx.prepare_at_points(&round_challenges[..round_challenges.len() - 1]);
        let coeffs = interpolation_ctx.obtain_coeffs();
        let mut beta_coeff = betas[0] * bi_betai_coefficient;
        output[s_start] = beta_coeff;
        for i in 0..internal_round_count {
            let mask_begin = first_mask_start + 2 * i * internal_round_proof_len;
            output[mask_begin..]
                .iter_mut()
                .step_by(2)
                .take(M)
                .for_each(|o| *o = -beta_coeff);
            beta_coeff = betas[i + 1] * bi_betai_coefficient;
            output[mask_begin..]
                .iter_mut()
                .step_by(2)
                .take(internal_round_proof_len)
                .zip(coeffs.iter().skip(i).step_by(internal_round_count))
                .for_each(|(o, c)| *o += beta_coeff * *c);
        }
        output[last_round_start..]
            .iter_mut()
            .step_by(2)
            .take(M)
            .for_each(|o| *o -= beta_coeff);
        debug_assert!(output.iter().step_by(2).all(|v| v.is_zero()));
    } else {
        output
            .iter_mut()
            .skip(1)
            .step_by(2)
            .for_each(|o| *o = F::zero());
    }
    output_val
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
        const POLYS_COUNT: usize = 17;
        const DEGREE: usize = 17;
        const EVAL_POINTS: usize = 16;
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
    #[tokio::test]
    async fn test_zkfliop() {
        const LOG_FOLDING_FACTOR: usize = 1;
        // const LOG: usize = 2;
        const Z_LEN: usize = 1 + 1020;
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
