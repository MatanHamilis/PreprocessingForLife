use aes_prng::AesRng;
use blake3::OUT_LEN;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    add_assign_arrays, diff_assign_arrays,
    engine::MultiPartyEngine,
    fields::{FieldElement, IntermediateMulField},
    zkfliop::{compute_L, internal_round_proof_length, last_round_proof_length, PowersIterator},
};

use super::{compute_round_count, make_round_proof, multi_eval_at_point, ProverCtx, VerifierCtx};

fn compute_new_hash<F: FieldElement>(
    current_hash: &[u8; OUT_LEN],
    blinder: &[u8; 16],
    proof_share: &[F],
) -> [u8; OUT_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(current_hash);
    hasher.update(blinder);
    for s in proof_share {
        s.hash(&mut hasher);
    }
    *hasher.finalize().as_bytes()
}
fn commit_and_obtain_challenge<F: FieldElement>(
    parties_transcript_hashes: &mut [[u8; OUT_LEN]],
    proof_shares: &[Vec<F>],
    mut rng: impl CryptoRng + RngCore,
) -> (F, Vec<[u8; 16]>) {
    let blinding_factors: Vec<_> = parties_transcript_hashes
        .iter_mut()
        .zip(proof_shares.iter())
        .map(|(party_hash, proof_share)| {
            let mut blinding_factor = [0; 16];
            rng.fill_bytes(&mut blinding_factor);
            *party_hash = compute_new_hash(party_hash, &blinding_factor, proof_share);
            blinding_factor
        })
        .collect();
    let challenge = F::random(random_oracle(parties_transcript_hashes));
    (challenge, blinding_factors)
}
pub fn hash_statement<F: FieldElement>(statement_share: &[F]) -> [u8; OUT_LEN] {
    let mut hasher = blake3::Hasher::new();
    let size_in_bytes = std::mem::size_of::<F>();
    let statement_share_size_in_bytes = statement_share.len() * size_in_bytes;
    let statement_share_u8_slice = unsafe {
        std::slice::from_raw_parts(
            statement_share.as_ptr() as *const u8,
            statement_share_size_in_bytes,
        )
    };
    *blake3::hash(statement_share_u8_slice).as_bytes()
}

fn random_oracle(commits: &[[u8; OUT_LEN]]) -> impl RngCore + CryptoRng {
    let mut challenge = blake3::Hasher::new();
    for commit in commits.iter() {
        challenge.update(commit);
    }
    let hash = challenge.finalize();
    let seed = core::array::from_fn(|i| hash.as_bytes()[i]);
    AesRng::from_seed(seed)
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkFliopProof<F: FieldElement> {
    #[serde(bound = "")]
    proof_shares: Vec<Vec<F>>,
    commit_blinders: Vec<[u8; 16]>,
    commit_idx: usize,
    commits: Vec<Vec<[u8; OUT_LEN]>>,
    #[serde(bound = "")]
    last_round_proof_share: Vec<F>,
}
impl<F: FieldElement> ZkFliopProof<F> {
    fn new(round_count: usize, commit_idx: usize, log_folding_factor: usize) -> Self {
        Self {
            proof_shares: Vec::with_capacity(round_count),
            commit_blinders: Vec::with_capacity(round_count),
            commits: Vec::with_capacity(round_count),
            last_round_proof_share: vec![F::zero(); last_round_proof_length(log_folding_factor)],
            commit_idx,
        }
    }
    fn push_proof_shares(&mut self, proof_shares: Vec<F>) {
        self.proof_shares.push(proof_shares);
    }
    fn push_blinders(&mut self, blinder: [u8; 16]) {
        self.commit_blinders.push(blinder);
    }
    fn push_commits(&mut self, commits: Vec<[u8; OUT_LEN]>) {
        self.commits.push(commits);
    }
}
pub fn prove<'a, F: IntermediateMulField>(
    parties_statements: impl Iterator<Item = &'a Vec<F>>,
    mut statement: Vec<F>,
    prover_ctx: &mut ProverCtx<F>,
) -> Vec<ZkFliopProof<F>> {
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
    let mut parties_shares_hashes: Vec<_> = parties_statements.map(|v| hash_statement(v)).collect();
    let M = 1 << log_folding_factor;
    let verifiers_num = parties_shares_hashes.len();
    let mut z = &mut statement[..];
    let round_count = compute_round_count(z.len(), log_folding_factor);
    let mut output: Vec<ZkFliopProof<F>> = (0..verifiers_num)
        .map(|i| ZkFliopProof::new(round_count, i, log_folding_factor))
        .collect();
    let mut rng = AesRng::from_random_seed();
    let internal_round_proof_len = internal_round_proof_length(log_folding_factor);
    for _ in 1..round_count {
        let round_proof =
            make_round_proof(z, log_folding_factor, eval_ctx_internal_round_proof_gen);
        let mut proof_shares: Vec<Vec<F>> = Vec::with_capacity(verifiers_num);
        let mut last_masks = round_proof.clone();
        for _ in 0..verifiers_num - 1 {
            proof_shares.push(
                (0..internal_round_proof_len)
                    .map(|_| F::random(&mut rng))
                    .collect(),
            );
            diff_assign_arrays(&mut last_masks, proof_shares.last().unwrap());
        }
        proof_shares.push(last_masks);
        let (challenge, blinders) =
            commit_and_obtain_challenge(&mut parties_shares_hashes[..], &proof_shares, &mut rng);
        eval_ctx_internal_round_polys_challenge.prepare_at_points(std::slice::from_ref(&challenge));
        eval_ctx_internal_round_proof_challenge.prepare_at_points(std::slice::from_ref(&challenge));
        for ((p, blinder), proof_share) in output
            .iter_mut()
            .zip(blinders.into_iter())
            .zip(proof_shares.into_iter())
        {
            p.push_blinders(blinder);
            p.push_proof_shares(proof_share);
            p.push_commits(parties_shares_hashes.clone());
        }
        z[0] = multi_eval_at_point(
            z,
            &round_proof,
            challenge,
            log_folding_factor,
            eval_ctx_internal_round_polys_challenge,
            eval_ctx_internal_round_proof_challenge,
        );
        let z_len = z.len();
        let L = compute_L(z_len, log_folding_factor);
        let next_round_size = ((L + 2 * M - 1) / (2 * M)) * (2 * M);
        for i in L..next_round_size {
            z[i + 1] = F::zero();
        }
        z = &mut z[..=next_round_size];
    }
    let M = 1 << log_folding_factor;
    debug_assert_eq!(z.len(), 1 + 2 * M);
    let mut last_round_proof = Vec::with_capacity(last_round_proof_length(log_folding_factor));
    let (s_0, s_1) = (F::random(&mut rng), F::random(&mut rng));
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
    let mut last_proof_shares: Vec<_> = (1..verifiers_num)
        .map(|_| {
            let proof_share: Vec<_> = (0..last_round_proof.len())
                .map(|_| F::random(&mut rng))
                .collect();
            diff_assign_arrays(&mut last_round_proof, &proof_share);
            proof_share
        })
        .collect();
    last_proof_shares.push(last_round_proof);

    let (_, blinders) =
        commit_and_obtain_challenge(&mut parties_shares_hashes[..], &last_proof_shares, &mut rng);
    for ((p, blinder), proof_share) in output
        .iter_mut()
        .zip(blinders.into_iter())
        .zip(last_proof_shares.into_iter())
    {
        p.push_blinders(blinder);
        p.last_round_proof_share = proof_share;
        p.push_commits(parties_shares_hashes.clone());
    }
    output
}
pub fn obtain_check_value<F: IntermediateMulField>(
    mut statement_share: Vec<F>,
    proof: &ZkFliopProof<F>,
    verifier_ctx: &mut VerifierCtx<F>,
) -> (bool, [F; 4]) {
    let VerifierCtx {
        eval_ctx_internal_round_proof,
        eval_ctx_internal_round_polys,
        eval_ctx_last_round_polys,
        eval_ctx_last_round_proof,
        log_folding_factor,
    } = verifier_ctx;
    let log_folding_factor = *log_folding_factor;
    let mut statement_hash = hash_statement(&statement_share);
    let commit_idx = proof.commit_idx;
    let round_count = compute_round_count(statement_share.len(), log_folding_factor);

    let mut checks_vector = Vec::with_capacity(round_count);
    let mut z = &mut statement_share[..];
    let mut bool = true;
    let M = 1 << log_folding_factor;
    // Rounds
    for ((proof_share, blinder), commits) in proof
        .proof_shares
        .iter()
        .zip(proof.commit_blinders.iter())
        .zip(proof.commits.iter())
    {
        let z_len = z.len();
        let L = compute_L(z_len, log_folding_factor);
        statement_hash = compute_new_hash(&statement_hash, blinder, proof_share);
        let commit_to_check = commits[commit_idx];
        bool &= statement_hash == commit_to_check;
        let r: F = F::random(random_oracle(commits));
        eval_ctx_internal_round_polys.prepare_at_points(std::slice::from_ref(&r));
        eval_ctx_internal_round_proof.prepare_at_points(std::slice::from_ref(&r));
        checks_vector.push(z[0] - proof_share.iter().take(M).copied().sum::<F>());
        let z_output = unsafe { std::slice::from_raw_parts_mut(z[1..1 + L].as_mut_ptr(), L) };
        eval_ctx_internal_round_polys.interpolate(&z[1..], z_output, 0, 1);
        let next_round_size = ((L + 2 * M - 1) / (2 * M)) * (2 * M);
        for i in L..next_round_size {
            z[i + 1] = F::zero();
        }
        eval_ctx_internal_round_proof.interpolate(&proof_share, &mut z[0..1], 0, 1);
        z = &mut z[..=next_round_size];
    }
    //last_round
    debug_assert_eq!(z.len(), 1 + 2 * M);
    let last_round_proof = &proof.last_round_proof_share;
    let last_round_blinder = proof.commit_blinders.last().unwrap();
    let last_round_commits = proof.commits.last().unwrap();
    let commit_to_check = last_round_commits[commit_idx];
    statement_hash = compute_new_hash(&statement_hash, last_round_blinder, &last_round_proof);
    bool &= statement_hash == commit_to_check;
    let mut rng = random_oracle(&last_round_commits);
    let r: F = F::random(&mut rng);
    eval_ctx_last_round_polys.prepare_at_points(std::slice::from_ref(&r));
    eval_ctx_last_round_proof.prepare_at_points(std::slice::from_ref(&r));
    let alpha = F::random(&mut rng);
    let interpolation_buf: Vec<F> = z[1..]
        .iter()
        .chain(&last_round_proof[0..2])
        .copied()
        .collect();
    let mut f_hat_r = [F::zero(); 2];
    eval_ctx_last_round_polys.interpolate(&interpolation_buf, &mut f_hat_r, 0, 1);
    let mut q_hat_r = F::zero();
    eval_ctx_last_round_proof.interpolate(
        &last_round_proof[2..],
        std::slice::from_mut(&mut q_hat_r),
        0,
        1,
    );
    checks_vector.push(z[0] - last_round_proof[2..2 + M].iter().copied().sum());
    let check_value: F = PowersIterator::new(alpha)
        .zip(checks_vector)
        .map(|(a, b)| a * b)
        .sum();
    (bool, [f_hat_r[0], f_hat_r[1], q_hat_r, check_value])
}

pub async fn verify_check_value<F: FieldElement>(
    mut engine: impl MultiPartyEngine,
    mut is_commit_ok: bool,
    mut input: [F; 4],
) -> bool {
    let peers_num = engine.party_ids().len() - 1;
    engine.broadcast((is_commit_ok, input));
    for _ in 0..peers_num {
        let ((is_commit_ok_peer, msg), _): ((bool, _), _) = engine.recv().await.unwrap();
        is_commit_ok &= is_commit_ok_peer;
        add_assign_arrays(&mut input, &msg);
    }
    (input[3].is_zero()) && (input[0] * input[1] == input[2]) && is_commit_ok
}

#[cfg(test)]
mod test {
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use aes_prng::AesRng;
    use futures::future::try_join_all;
    use rand::thread_rng;

    use crate::{
        engine::LocalRouter,
        fields::{FieldElement, IntermediateMulField, GF64},
        zkfliop::{ProverCtx, VerifierCtx},
        UCTag,
    };

    use super::{obtain_check_value, prove, verify_check_value};

    async fn test_nizk_fliop<F: IntermediateMulField>(
        statement: &[F],
        verifiers: u64,
        log_folding_factor: usize,
    ) {
        let mut last_vec = statement.to_vec();
        let mut rng = AesRng::from_random_seed();
        let mut shares: Vec<Vec<F>> = (0..verifiers - 1)
            .map(|_| {
                last_vec
                    .iter_mut()
                    .map(|v| {
                        let random = F::random(&mut rng);
                        *v -= random;
                        random
                    })
                    .collect()
            })
            .collect();
        shares.push(last_vec);
        let mut prover_ctx = ProverCtx::<F>::new(log_folding_factor);
        let mut verifier_ctx: Vec<_> = (0..verifiers)
            .map(|_| VerifierCtx::<F>::new(log_folding_factor))
            .collect();
        let proofs = prove(shares.iter(), statement.to_vec(), &mut prover_ctx);
        let party_ids: Vec<_> = (1..=verifiers as u64).collect();
        let party_ids_set: HashSet<u64> = HashSet::from_iter(party_ids.iter().copied());
        let (router, engines) = LocalRouter::new(UCTag::new(&"ROOT_TAG"), &party_ids_set);
        let handle = tokio::spawn(router.launch());
        let handles: Vec<_> = shares
            .into_iter()
            .zip(proofs.into_iter())
            .zip(engines.into_iter())
            .zip(verifier_ctx.into_iter())
            .map(
                |(((share, proof), (_, engine)), mut verifier_ctx)| async move {
                    let (is_commit_ok, input) =
                        obtain_check_value(share, &proof, &mut verifier_ctx);
                    Result::<bool, ()>::Ok(verify_check_value(engine, is_commit_ok, input).await)
                },
            )
            .collect();
        let v = try_join_all(handles).await.unwrap();
        handle.await.unwrap().unwrap();
        assert!(v.into_iter().all(|v| v));
    }

    fn get_statement<F: FieldElement>(len: usize) -> Vec<F> {
        let mut output = Vec::with_capacity(2 * len + 1);
        output.push(F::zero());
        let mut sum = F::zero();
        for _ in 0..len {
            let x = F::random(thread_rng());
            let y = F::random(thread_rng());
            sum += x * y;
            output.push(x);
            output.push(y);
        }
        output[0] = sum;
        output
    }
    #[tokio::test]
    async fn test_small_state() {
        let x = GF64::random(thread_rng());
        let y = GF64::random(thread_rng());
        let statement = [x * y, x, y, GF64::zero(), GF64::zero()];
        let log_folding_factor = 1;
        test_nizk_fliop(&statement[..], 2, log_folding_factor).await;
    }

    #[tokio::test]
    async fn test_one_layer_fliop() {
        let log_folding_factor = 1;
        test_nizk_fliop(&get_statement::<GF64>(4), 2, log_folding_factor).await;
    }
    #[tokio::test]
    async fn test_large_fliop() {
        let log_folding_factor = 3;
        test_nizk_fliop(&get_statement::<GF64>(1 << 10), 2, log_folding_factor).await;
    }
    #[tokio::test]
    async fn test_large_fliop_five_verifiers() {
        let log_folding_factor = 3;
        test_nizk_fliop(&get_statement::<GF64>(1 << 10), 5, log_folding_factor).await;
    }
}
