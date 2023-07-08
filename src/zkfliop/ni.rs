use aes_prng::AesRng;
use blake3::OUT_LEN;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    add_assign_arrays, diff_assign_arrays,
    engine::MultiPartyEngine,
    fields::FieldElement,
    zkfliop::{interpolate, PowersIterator},
};

use super::{compute_round_count, make_round_proof, multi_eval_at_point};

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
fn commit_and_obtain_challenge<const PROOF_LEN: usize, F: FieldElement>(
    parties_transcript_hashes: &mut [[u8; OUT_LEN]],
    proof_shares: &[[F; PROOF_LEN]],
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
    for v in statement_share {
        v.hash(&mut hasher);
    }
    *hasher.finalize().as_bytes()
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
#[derive(Serialize, Deserialize, Clone)]
pub struct ZkFliopProof<F: FieldElement> {
    #[serde(bound = "")]
    proof_shares: Vec<Vec<F>>,
    commit_blinders: Vec<[u8; 16]>,
    commit_idx: usize,
    commits: Vec<Vec<[u8; OUT_LEN]>>,
    #[serde(bound = "")]
    last_round_proof_share: [F; 7],
}
impl<F: FieldElement> ZkFliopProof<F> {
    fn new(round_count: usize, commit_idx: usize) -> Self {
        Self {
            proof_shares: Vec::with_capacity(round_count),
            commit_blinders: Vec::with_capacity(round_count),
            commits: Vec::with_capacity(round_count),
            last_round_proof_share: [F::zero(); 7],
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
pub fn prove<'a, F: FieldElement>(
    parties_statements: impl Iterator<Item = &'a Vec<F>>,
    mut statement: Vec<F>,
    two: F,
    three: F,
    four: F,
    log_folding_factor: usize,
) -> Vec<ZkFliopProof<F>> {
    let mut parties_shares_hashes: Vec<_> = parties_statements.map(|v| hash_statement(v)).collect();
    let verifiers_num = parties_shares_hashes.len();
    let mut z = &mut statement[..];
    let round_count = compute_round_count(z.len(), log_folding_factor);
    let mut output: Vec<ZkFliopProof<F>> = (0..verifiers_num)
        .map(|i| ZkFliopProof::new(round_count, i))
        .collect();
    let mut rng = AesRng::from_random_seed();
    for _ in 1..round_count {
        let round_proof = make_round_proof(z, two);
        let mut proof_shares = Vec::with_capacity(verifiers_num);
        let mut last_masks = round_proof;
        for _ in 0..verifiers_num - 1 {
            proof_shares.push(core::array::from_fn(|_| F::random(&mut rng)));
            diff_assign_arrays(&mut last_masks, proof_shares.last().unwrap());
        }
        proof_shares.push(last_masks);
        let (challenge, blinders) =
            commit_and_obtain_challenge(&mut parties_shares_hashes[..], &proof_shares, &mut rng);
        for ((p, blinder), proof_share) in output
            .iter_mut()
            .zip(blinders.into_iter())
            .zip(proof_shares.iter())
        {
            p.push_blinders(blinder);
            p.push_proof_shares(*proof_share);
            p.push_commits(parties_shares_hashes.clone());
        }
        z[0] = multi_eval_at_point(z, &round_proof, challenge, two);
        let z_len = z.len();
        z = &mut z[..=z_len / 2];
    }
    debug_assert_eq!(z.len(), 5);
    let s_0: F = F::random(&mut rng);
    let s_1: F = F::random(&mut rng);
    let mut f_0 = [
        (F::zero(), z[1]),
        (F::one(), z[3]),
        (two, s_0),
        (three, F::zero()),
        (four, F::zero()),
    ];
    let mut f_1 = [
        (F::zero(), z[2]),
        (F::one(), z[4]),
        (two, s_1),
        (three, F::zero()),
        (four, F::zero()),
    ];
    f_0[3].1 = interpolate(&f_0[0..3], three);
    f_0[4].1 = interpolate(&f_0[0..3], four);
    f_1[3].1 = interpolate(&f_1[0..3], three);
    f_1[4].1 = interpolate(&f_1[0..3], four);
    let q: [_; 5] = core::array::from_fn(|i| f_0[i].1 * f_1[i].1);
    let mut last_proof_share = [s_0, s_1, q[0], q[1], q[2], q[3], q[4]];
    let mut last_proof_shares: Vec<_> = (1..verifiers_num)
        .map(|_| {
            let proof_share = core::array::from_fn(|_| F::random(&mut rng));
            diff_assign_arrays(&mut last_proof_share, &proof_share);
            proof_share
        })
        .collect();
    last_proof_shares.push(last_proof_share);

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
pub fn obtain_check_value<F: FieldElement>(
    mut statement_share: Vec<F>,
    proof: &ZkFliopProof<F>,
) -> (bool, [F; 4]) {
    let mut statement_hash = hash_statement(&statement_share);
    let commit_idx = proof.commit_idx;
    let (_, round_count) = compute_round_count(statement_share.len());

    let mut checks_vector = Vec::with_capacity(round_count);
    let mut z = &mut statement_share[..];
    let mut bool = true;
    // Rounds
    for ((proof_share @ &[q_0, q_1, q_2], blinder), commits) in proof
        .proof_shares
        .iter()
        .zip(proof.commit_blinders.iter())
        .zip(proof.commits.iter())
    {
        let z_len = z.len();
        statement_hash = compute_new_hash(&statement_hash, blinder, proof_share);
        let commit_to_check = commits[commit_idx];
        bool &= statement_hash == commit_to_check;
        let r: F = F::random(random_oracle(commits));
        checks_vector.push(z[0] - q_0 - q_1);
        let z_second_half =
            unsafe { std::slice::from_raw_parts(z[z_len / 2 + 1..].as_ptr(), z_len / 2) };
        z[1..=z_len / 2]
            .par_iter_mut()
            .zip(z_second_half.par_iter())
            .for_each(|(f_zero, f_one)| {
                let slope_i = *f_one - *f_zero;
                *f_zero += r * slope_i;
            });
        let q_r = interpolate(&[(F::zero(), q_0), (F::one(), q_1), (F::two(), q_2)], r);
        z[0] = q_r;
        z = &mut z[..=z_len / 2];
    }
    //last_round
    debug_assert_eq!(z.len(), 5);
    let last_round_proof: [F; 7] = proof.last_round_proof_share;
    let last_round_blinder = proof.commit_blinders.last().unwrap();
    let last_round_commits = proof.commits.last().unwrap();
    let commit_to_check = last_round_commits[commit_idx];
    statement_hash = compute_new_hash(&statement_hash, last_round_blinder, &last_round_proof);
    bool &= statement_hash == commit_to_check;
    let mut rng = random_oracle(&last_round_commits);
    let r: F = F::random(&mut rng);
    let alpha = F::random(&mut rng);
    let mut f_0_hat = [
        (F::zero(), z[1]),
        (F::one(), z[3]),
        (F::two(), last_round_proof[0]),
        (r, F::zero()),
    ];
    let mut f_1_hat = [
        (F::zero(), z[2]),
        (F::one(), z[4]),
        (F::two(), last_round_proof[1]),
        (r, F::zero()),
    ];
    let mut q_hat = [
        (F::zero(), last_round_proof[2]),
        (F::one(), last_round_proof[3]),
        (F::two(), last_round_proof[4]),
        (F::three(), last_round_proof[5]),
        (F::four(), last_round_proof[6]),
        (r, F::zero()),
    ];
    f_0_hat[3].1 = interpolate(&f_0_hat[0..3], f_0_hat[3].0);
    f_1_hat[3].1 = interpolate(&f_1_hat[0..3], f_1_hat[3].0);
    q_hat[5].1 = interpolate(&q_hat[0..5], q_hat[5].0);
    checks_vector.push(z[0] - q_hat[0].1 - q_hat[1].1);
    let check_value: F = PowersIterator::new(alpha)
        .zip(checks_vector)
        .map(|(a, b)| a * b)
        .sum();
    (bool, [f_0_hat[3].1, f_1_hat[3].1, q_hat[5].1, check_value])
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
        fields::{FieldElement, GF64},
        UCTag,
    };

    use super::{obtain_check_value, prove, verify_check_value};

    async fn test_nizk_fliop<F: FieldElement>(statement: &[F], parties: u64) {
        let mut last_vec = statement.to_vec();
        let mut rng = AesRng::from_random_seed();
        let mut shares: Vec<Vec<F>> = (0..parties - 1)
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
        let proofs = prove(
            shares.iter(),
            statement.to_vec(),
            F::two(),
            F::three(),
            F::four(),
        );
        let party_ids: Vec<_> = (1..=parties as u64).collect();
        let party_ids_set: HashSet<u64> = HashSet::from_iter(party_ids.iter().copied());
        let (router, engines) = LocalRouter::new(UCTag::new(&"ROOT_TAG"), &party_ids_set);
        let handle = tokio::spawn(router.launch());
        let handles: Vec<_> = shares
            .into_iter()
            .zip(proofs.into_iter())
            .zip(engines.into_iter())
            .map(|((share, proof), (_, engine))| async move {
                let (is_commit_ok, input) = obtain_check_value(share, &proof);
                Result::<bool, ()>::Ok(verify_check_value(engine, is_commit_ok, input).await)
            })
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
        test_nizk_fliop(&statement[..], 2).await;
    }

    #[tokio::test]
    async fn test_one_layer_fliop() {
        test_nizk_fliop(&get_statement::<GF64>(4), 2).await;
    }
    #[tokio::test]
    async fn test_large_fliop() {
        test_nizk_fliop(&get_statement::<GF64>(1 << 10), 2).await;
    }
    #[tokio::test]
    async fn test_large_fliop_five_verifiers() {
        test_nizk_fliop(&get_statement::<GF64>(1 << 10), 5).await;
    }
}
