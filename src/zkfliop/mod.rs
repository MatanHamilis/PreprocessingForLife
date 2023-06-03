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

const INTERNAL_ROUND_PROOF_LENGTH: usize = 3;
const LAST_ROUND_PROOF_LENGTH: usize = 5;
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

pub fn compute_round_count_and_m(z_len: usize) -> (usize, usize) {
    assert_eq!((z_len - 1) & 3, 0);
    let m = (z_len - 1) / 4;
    let round_count = usize::ilog2(m);
    assert_eq!(1 << round_count, m);
    (m, 1 + round_count as usize)
}

fn interpolate<F: FieldElement>(evals: &[(F, F)], at: F) -> F {
    let l = evals.len();
    let mut sum = F::zero();
    for i in 0..l {
        let mut cur_nom = F::one();
        let mut cur_denom = F::one();
        for j in 0..l {
            if j == i {
                continue;
            }
            cur_nom *= at - evals[j].0;
            cur_denom *= evals[i].0 - evals[j].0;
        }
        sum += cur_nom * evals[i].1 / cur_denom;
    }
    sum
}

pub fn g<F: FieldElement>(z: &[F]) -> F {
    z.par_chunks_exact(2).map(|f| f[0] * f[1]).sum()
}
#[derive(Clone, Serialize, Deserialize)]
pub struct OfflineProver<F: FieldElement> {
    #[serde(bound = "")]
    proof_masks: Vec<F>,
    #[serde(bound = "")]
    s_tilde: (F, F),
    round_challenges: Vec<OfflineCommitment>,
    final_msg: OfflineCommitment,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OfflineVerifier {
    round_challenges: Vec<OfflineCommitment>,
    final_msg: OfflineCommitment,
}
pub async fn prover_offline<F: FieldElement>(
    mut engine: impl MultiPartyEngine,
    round_count: usize,
    dealer_id: PartyId,
) -> OfflineProver<F> {
    let (proof_masks, s_tilde): (Vec<F>, (F, F)) = engine.recv_from(dealer_id).await.unwrap();
    debug_assert_eq!(
        proof_masks.len(),
        INTERNAL_ROUND_PROOF_LENGTH * (round_count - 1) + LAST_ROUND_PROOF_LENGTH
    );
    let mut round_challenges = Vec::with_capacity(round_count);
    for _ in 1..=round_count {
        let comm = OfflineCommitment::offline_obtain_commit(&mut engine, dealer_id).await;
        round_challenges.push(comm);
    }
    let final_msg = OfflineCommitment::offline_obtain_commit(&mut engine, dealer_id).await;
    OfflineProver {
        proof_masks,
        s_tilde,
        round_challenges,
        final_msg,
    }
}

pub async fn verifier_offline<E: MultiPartyEngine>(
    mut engine: E,
    round_count: usize,
    dealer_id: PartyId,
) -> OfflineVerifier {
    let mut round_challenges = Vec::with_capacity(round_count);
    for _ in 1..=round_count {
        let comm = OfflineCommitment::offline_obtain_commit(&mut engine, dealer_id).await;
        round_challenges.push(comm);
    }
    let final_msg = OfflineCommitment::offline_obtain_commit(&mut engine, dealer_id).await;

    OfflineVerifier {
        round_challenges,
        final_msg,
    }
}

pub fn dealer<F: FieldElement>(
    mut z_tilde: &mut [F],
    num_verifiers: usize,
) -> (OfflineProver<F>, Vec<OfflineVerifier>) {
    // Init
    debug_assert!(z_tilde.iter().skip(1).step_by(2).all(|v| v.is_zero()));
    let (_, round_count) = compute_round_count_and_m(z_tilde.len());
    let mut b_tilde = Vec::with_capacity(round_count);
    let mut rng = AesRng::from_random_seed();
    let total_proof_mask_len =
        INTERNAL_ROUND_PROOF_LENGTH * (round_count - 1) + LAST_ROUND_PROOF_LENGTH;
    let proof_masks: Vec<_> = (0..total_proof_mask_len)
        .map(|_| F::random(&mut rng))
        .collect();
    let s_tilde = (F::random(&mut rng), F::random(&mut rng));

    // Rounds
    let mut round_challenges_shares = vec![Vec::with_capacity(round_count); num_verifiers + 1];
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
        let q_base = (round_id - 1) * INTERNAL_ROUND_PROOF_LENGTH;
        let (q_0_tilde, q_1_tilde, q_2_tilde) = (
            proof_masks[q_base],
            proof_masks[q_base + 1],
            proof_masks[q_base + 2],
        );
        b_tilde.push(z_tilde[0] - q_0_tilde - q_1_tilde);
        let z_second_half =
            unsafe { std::slice::from_raw_parts(z_tilde[z_len / 2 + 1..].as_ptr(), z_len / 2) };
        z_tilde[1..=z_len / 2]
            .par_iter_mut()
            .zip(z_second_half.par_iter())
            .for_each(|(f_zero, f_one)| {
                let slope_i = *f_one - *f_zero;
                *f_zero += slope_i * r;
            });
        let q_r = interpolate(
            &[
                (F::zero(), q_0_tilde),
                (F::one(), q_1_tilde),
                (F::two(), q_2_tilde),
            ],
            r,
        );
        z_tilde[0] = q_r;
        z_tilde = &mut z_tilde[..=z_len / 2];
    }
    // last round
    debug_assert_eq!(z_tilde.len(), 5);
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
    let last_round_masks = &proof_masks[proof_masks.len() - LAST_ROUND_PROOF_LENGTH..];
    let mut f_0_tilde = [
        (F::zero(), z_tilde[1]),
        (F::one(), z_tilde[3]),
        (F::two(), s_tilde.0),
        (r, F::zero()),
    ];
    let mut f_1_tilde = [
        (F::zero(), z_tilde[2]),
        (F::one(), z_tilde[4]),
        (F::two(), s_tilde.1),
        (r, F::zero()),
    ];
    let mut q_tilde = [
        (F::zero(), last_round_masks[0]),
        (F::one(), last_round_masks[1]),
        (F::two(), last_round_masks[2]),
        (F::three(), last_round_masks[3]),
        (F::four(), last_round_masks[4]),
        (r, F::zero()),
    ];
    f_0_tilde[3].1 = interpolate(&f_0_tilde[0..3], f_0_tilde[3].0);
    f_1_tilde[3].1 = interpolate(&f_1_tilde[0..3], f_1_tilde[3].0);
    q_tilde[5].1 = interpolate(&q_tilde[0..5], q_tilde[5].0);
    b_tilde.push(z_tilde[0] - q_tilde[0].1 - q_tilde[1].1);

    // Decision
    let betas: Vec<_> = (0..round_count).map(|_| F::random(&mut rng)).collect();
    debug_assert_eq!(betas.len(), b_tilde.len());
    let b_tilde_check = betas
        .iter()
        .zip(b_tilde.iter())
        .map(|(a, b)| *a * *b)
        .fold(F::zero(), |acc, cur| acc + cur);
    let final_value = (
        betas,
        b_tilde_check,
        f_0_tilde[3].1,
        f_1_tilde[3].1,
        q_tilde[5].1,
    );
    let (mut last_value_commitments, commitment) =
        OfflineCommitment::commit(&final_value, num_verifiers + 1);
    let prover = OfflineProver {
        final_msg: OfflineCommitment {
            commit_share: last_value_commitments.pop().unwrap(),
            commitment,
        },
        proof_masks,
        s_tilde,
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

fn make_round_proof<F: FieldElement>(z: &[F], two: F) -> [F; 3] {
    let z_len = z.len();
    let i0 = &z[1..=z_len / 2];
    let q_0 = g(i0);
    let i1 = &z[z_len / 2 + 1..];
    let q_1 = g(i1);
    debug_assert_eq!(z[0], q_0 + q_1);
    let q_2 = z[1..=z_len / 2]
        .par_chunks(2)
        .zip(z[z_len / 2 + 1..].par_chunks(2))
        .map(|(f_zero, f_one)| {
            let slope_first = f_one[0] - f_zero[0];
            let slope_second = f_one[1] - f_zero[1];
            let q_2_first = f_zero[0] + slope_first * two;
            let q_2_second = f_zero[1] + slope_second * two;
            q_2_first * q_2_second
        })
        .sum();
    [q_0, q_1, q_2]
}
fn multi_eval_at_point<F: FieldElement>(
    z: &mut [F],
    round_proof: &[F; 3],
    challenge: F,
    two: F,
) -> F {
    let z_len = z.len();
    let z_second_output =
        unsafe { std::slice::from_raw_parts(z[z_len / 2 + 1..].as_ptr(), z_len / 2) };
    z[1..=z_len / 2]
        .par_iter_mut()
        .zip(z_second_output.par_iter())
        .for_each(|(z_i, f_one)| {
            *z_i += challenge * (*f_one - *z_i);
        });
    interpolate(
        &[
            (F::zero(), round_proof[0]),
            (F::one(), round_proof[1]),
            (two, round_proof[2]),
        ],
        challenge,
    )
}
pub async fn prover<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    mut z: &mut [F],
    offline_material: &OfflineProver<F>,
    mut auth_statement: Option<Vec<F>>,
) {
    let OfflineProver {
        proof_masks,
        s_tilde,
        round_challenges,
        final_msg,
    } = offline_material;
    let last_round_challenge = round_challenges.last().unwrap();
    // Init
    let (_, round_count) = compute_round_count_and_m(z.len());
    let mut b_tilde = Vec::with_capacity(round_count);
    info!("Proving: round count {}", round_count);
    // Rounds
    for (_, (round_challenge, masks)) in round_challenges
        .into_iter()
        .take(round_challenges.len() - 1)
        .zip(proof_masks.chunks_exact(3))
        .enumerate()
    {
        // Computation
        let proof = make_round_proof(z, F::two());
        let masked_proof = (
            proof[0] - masks[0],
            proof[1] - masks[1],
            proof[2] - masks[2],
        );

        // Communication
        engine.broadcast(masked_proof);
        let r: F = round_challenge.online_decommit(&mut engine).await;

        // Query
        z[0] = multi_eval_at_point(&mut z, &proof, r, F::two());
        let z_len = z.len();
        z = &mut z[..=z_len / 2];
        if auth_statement.is_some() {
            // Perform the same computation as the dealer.
            let mut z_tilde = auth_statement.unwrap();
            b_tilde.push(z_tilde[0] - masks[0] - masks[1]);
            let z_second_half =
                unsafe { std::slice::from_raw_parts(z_tilde[z_len / 2 + 1..].as_ptr(), z_len / 2) };
            z_tilde[1..=z_len / 2]
                .par_iter_mut()
                .zip(z_second_half.par_iter())
                .for_each(|(f_zero, f_one)| {
                    let slope_i = *f_one - *f_zero;
                    *f_zero += slope_i * r;
                });
            let q_r = interpolate(
                &[
                    (F::zero(), masks[0]),
                    (F::one(), masks[1]),
                    (F::two(), masks[2]),
                ],
                r,
            );
            z_tilde[0] = q_r;
            z_tilde.drain(z_len / 2 + 1..);
            auth_statement = Some(z_tilde);
        }
    }
    // last round
    debug_assert_eq!(z.len(), 5);
    let (s_0, s_1) = (F::random(E::rng()), F::random(E::rng()));
    let mut f_0 = [
        (F::zero(), z[1]),
        (F::one(), z[3]),
        (F::two(), s_0),
        (F::three(), F::zero()),
        (F::four(), F::zero()),
    ];
    let mut f_1 = [
        (F::zero(), z[2]),
        (F::one(), z[4]),
        (F::two(), s_1),
        (F::three(), F::zero()),
        (F::four(), F::zero()),
    ];
    f_0[3].1 = interpolate(&f_0[0..3], F::three());
    f_0[4].1 = interpolate(&f_0[0..3], F::four());
    f_1[3].1 = interpolate(&f_1[0..3], F::three());
    f_1[4].1 = interpolate(&f_1[0..3], F::four());
    let proof_masks_last_round = &proof_masks[proof_masks.len() - LAST_ROUND_PROOF_LENGTH..];
    let q: [_; 5] = core::array::from_fn(|i| f_0[i].1 * f_1[i].1);
    let last_round_proof = [
        s_0 - s_tilde.0,
        s_1 - s_tilde.1,
        q[0] - proof_masks_last_round[0],
        q[1] - proof_masks_last_round[1],
        q[2] - proof_masks_last_round[2],
        q[3] - proof_masks_last_round[3],
        q[4] - proof_masks_last_round[4],
    ];
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
        debug_assert_eq!(z_tilde.len(), 5);
        let mut f_0_tilde = [
            (F::zero(), z_tilde[1]),
            (F::one(), z_tilde[3]),
            (F::two(), s_tilde.0),
            (r, F::zero()),
        ];
        let mut f_1_tilde = [
            (F::zero(), z_tilde[2]),
            (F::one(), z_tilde[4]),
            (F::two(), s_tilde.1),
            (r, F::zero()),
        ];
        let mut q_tilde = [
            (F::zero(), proof_masks_last_round[0]),
            (F::one(), proof_masks_last_round[1]),
            (F::two(), proof_masks_last_round[2]),
            (F::three(), proof_masks_last_round[3]),
            (F::four(), proof_masks_last_round[4]),
            (r, F::zero()),
        ];
        f_0_tilde[3].1 = interpolate(&f_0_tilde[0..3], f_0_tilde[3].0);
        f_1_tilde[3].1 = interpolate(&f_1_tilde[0..3], f_1_tilde[3].0);
        q_tilde[5].1 = interpolate(&q_tilde[0..5], q_tilde[5].0);
        b_tilde.push(z_tilde[0] - q_tilde[0].1 - q_tilde[1].1);

        // Decision
        debug_assert_eq!(betas.len(), b_tilde.len());
        let b_tilde_check = betas
            .iter()
            .zip(b_tilde.iter())
            .map(|(a, b)| *a * *b)
            .fold(F::zero(), |acc, cur| acc + cur);
        let final_value = (
            betas,
            b_tilde_check,
            f_0_tilde[3].1,
            f_1_tilde[3].1,
            q_tilde[5].1,
        );
        assert_eq!(final_value.2, f_0_tilde_dealer);
        assert_eq!(final_value.3, f_1_tilde_dealer);
        assert_eq!(final_value.4, q_tilde_dealer);
        assert_eq!(b_tilde_check, b_tilde_check_dealer);
    }
}

pub async fn verifier<F: FieldElement>(
    mut engine: impl MultiPartyEngine,
    mut z_hat: &mut [F],
    prover_id: PartyId,
    offline_material: &OfflineVerifier,
    two: F,
    three: F,
    four: F,
) {
    // Init
    let (_, round_count) = compute_round_count_and_m(z_hat.len());
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
        let (q_0_hat, q_1_hat, q_2_hat): (F, F, F) = engine.recv_from(prover_id).await.unwrap();
        let r: F = round_challenge.online_decommit(&mut engine).await;
        b_hat.push(z_hat[0] - q_0_hat - q_1_hat);
        let z_second_half =
            unsafe { std::slice::from_raw_parts(z_hat[z_len / 2 + 1..].as_ptr(), z_len / 2) };
        z_hat[1..=z_len / 2]
            .par_iter_mut()
            .zip(z_second_half.par_iter())
            .for_each(|(f_zero, f_one)| {
                let slope_i = *f_one - *f_zero;
                *f_zero += r * slope_i;
            });
        let q_r = interpolate(
            &[(F::zero(), q_0_hat), (F::one(), q_1_hat), (two, q_2_hat)],
            r,
        );
        z_hat[0] = q_r;
        z_hat = &mut z_hat[..=z_len / 2];
    }
    //last_round
    debug_assert_eq!(z_hat.len(), 5);
    let last_round_proof: [F; 7] = engine.recv_from(prover_id).await.unwrap();
    let r: F = last_round_challenge.online_decommit(&mut engine).await;
    let mut f_0_hat = [
        (F::zero(), z_hat[1]),
        (F::one(), z_hat[3]),
        (two, last_round_proof[0]),
        (r, F::zero()),
    ];
    let mut f_1_hat = [
        (F::zero(), z_hat[2]),
        (F::one(), z_hat[4]),
        (two, last_round_proof[1]),
        (r, F::zero()),
    ];
    let mut q_hat = [
        (F::zero(), last_round_proof[2]),
        (F::one(), last_round_proof[3]),
        (two, last_round_proof[4]),
        (three, last_round_proof[5]),
        (four, last_round_proof[6]),
        (r, F::zero()),
    ];
    f_0_hat[3].1 = interpolate(&f_0_hat[0..3], f_0_hat[3].0);
    f_1_hat[3].1 = interpolate(&f_1_hat[0..3], f_1_hat[3].0);
    q_hat[5].1 = interpolate(&q_hat[0..5], q_hat[5].0);
    b_hat.push(z_hat[0] - q_hat[0].1 - q_hat[1].1);

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
    let f_0_r = f_0_tilde_r + f_0_hat[3].1;
    let f_1_r = f_1_tilde_r + f_1_hat[3].1;
    let q_r = q_tilde_r + q_hat[5].1;
    assert_eq!(q_r, f_0_r * f_1_r);
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use futures::future::join_all;
    use futures::future::try_join_all;
    use rand::thread_rng;
    use tokio::join;

    use super::compute_round_count_and_m;
    use super::g;
    use super::{dealer, prover, prover_offline, verifier, verifier_offline, OfflineVerifier};
    use crate::engine::LocalRouter;
    use crate::uc_tags::UCTag;
    use crate::{
        engine::PartyId,
        fields::{FieldElement, GF128},
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn test_zkfliop() {
        const LOG: usize = 15;
        const Z_LEN: usize = (1 << LOG) + 1;
        const PARTIES: usize = 3;
        const ONLINE_PARTIES: usize = PARTIES - 1;
        let party_ids: [PartyId; PARTIES] = core::array::from_fn(|i| i as u64);
        let online_party_ids: [PartyId; ONLINE_PARTIES] = core::array::from_fn(|i| (i + 1) as u64);
        let prover_id = party_ids[1];
        let mut two = GF128::zero();
        two.set_bit(true, 1);
        let three = two + GF128::one();
        let four = two * two;

        let mut rng = thread_rng();

        // Offline proof preparation
        let mut dealer_input: Vec<_> = vec![GF128::zero(); Z_LEN];
        dealer_input
            .iter_mut()
            .step_by(2)
            .for_each(|v| *v = GF128::random(&mut rng));
        let mut dealer_input_clone = dealer_input.clone();

        let (prover_offline, verifiers_offline) = dealer(&mut dealer_input_clone, PARTIES - 2);
        let (_, round_count) = compute_round_count_and_m(Z_LEN);

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
                Some(dealer_input),
            )
            .await
        });
        let verifiers_futures: Vec<_> = verifiers_offline
            .into_iter()
            .zip(engines.into_iter())
            .map(|(v, (pid, engine))| {
                let input = verifier_input.clone();
                async move {
                    let mut input = input;
                    verifier(engine, &mut input, prover_id, &v, two, three, four).await;
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
