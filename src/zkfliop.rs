use crate::{
    commitment::OfflineCommitment,
    engine::{MultiPartyEngine, PartyId},
    fields::FieldElement,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use std::{mem::MaybeUninit, println};

const INTERNAL_ROUND_PROOF_LENGTH: usize = 3;
const LAST_ROUND_PROOF_LENGTH: usize = 5;
// const CHUNK_SIZE: usize = 1 << 10;

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

pub async fn dealer<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    mut z_tilde: &mut [F],
    prover_id: PartyId,
    two: F,
    three: F,
    four: F,
) {
    // Init
    debug_assert!(z_tilde.iter().skip(1).step_by(2).all(|v| v.is_zero()));
    let (_, round_count) = compute_round_count_and_m(z_tilde.len());
    let mut b_tilde = Vec::with_capacity(round_count);
    let mut rng = E::rng();
    let total_proof_mask_len =
        INTERNAL_ROUND_PROOF_LENGTH * (round_count - 1) + LAST_ROUND_PROOF_LENGTH;
    let proof_masks: Vec<_> = (0..total_proof_mask_len)
        .map(|_| F::random(&mut rng))
        .collect();
    let s_tilde = (F::random(&mut rng), F::random(&mut rng));
    engine.send((&proof_masks, s_tilde), prover_id);

    // Rounds
    for round_id in 1..round_count {
        let z_len = z_tilde.len();
        let r = F::random(&mut rng);
        OfflineCommitment::offline_commit(&mut engine, &r).await;
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
                (two, q_2_tilde),
            ],
            r,
        );
        z_tilde[0] = q_r;
        z_tilde = &mut z_tilde[..=z_len / 2];
    }
    // last round
    debug_assert_eq!(z_tilde.len(), 5);
    let r = F::random(&mut rng);
    OfflineCommitment::offline_commit(&mut engine, &r).await;
    let last_round_masks = &proof_masks[proof_masks.len() - LAST_ROUND_PROOF_LENGTH..];
    let mut f_0_tilde = [
        (F::zero(), z_tilde[1]),
        (F::one(), z_tilde[3]),
        (two, s_tilde.0),
        (r, F::zero()),
    ];
    let mut f_1_tilde = [
        (F::zero(), z_tilde[2]),
        (F::one(), z_tilde[4]),
        (two, s_tilde.1),
        (r, F::zero()),
    ];
    let mut q_tilde = [
        (F::zero(), last_round_masks[0]),
        (F::one(), last_round_masks[1]),
        (two, last_round_masks[2]),
        (three, last_round_masks[3]),
        (four, last_round_masks[4]),
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
    OfflineCommitment::offline_commit(&mut engine, &final_value).await;
}

pub async fn prover<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    mut z: &mut [F],
    offline_material: &OfflineProver<F>,
    two: F,
    three: F,
    four: F,
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
    println!("Proving: round count {}", round_count);

    // Rounds
    for (round_id, round_challenge) in round_challenges
        .into_iter()
        .take(round_challenges.len() - 1)
        .enumerate()
    {
        // let time = Instant::now();
        // Computation
        let z_len = z.len();
        let i0 = &z[1..=z_len / 2];
        let first_g_time = Instant::now();
        let q_0 = g(i0);
        println!(
            "First g took: {} round: {}",
            first_g_time.elapsed().as_millis(),
            round_id
        );
        let i1 = &z[z_len / 2 + 1..];
        // let first_g_time = Instant::now();
        let q_1 = g(i1);
        // println!(
        //     "second g took: {} round: {}",
        //     first_g_time.elapsed().as_millis(),
        //     round_id
        // );
        debug_assert_eq!(z[0], q_0 + q_1);
        // let first_g_time = Instant::now();
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

        // println!(
        //     "last loop took: {} round: {}",
        //     first_g_time.elapsed().as_millis(),
        //     round_id
        // );
        let proof_masks_base = INTERNAL_ROUND_PROOF_LENGTH * (round_id);
        let mask_0 = proof_masks[proof_masks_base];
        let mask_1 = proof_masks[proof_masks_base + 1];
        let mask_2 = proof_masks[proof_masks_base + 2];
        let masked_proof = (q_0 - mask_0, q_1 - mask_1, q_2 - mask_2);
        // println!(
        //     "prover round: {} part 1 took: {}ms",
        //     round_id,
        //     time.elapsed().as_millis()
        // );

        // Communication
        engine.broadcast(masked_proof);
        let r: F = round_challenge.online_decommit(&mut engine).await;

        // let time = Instant::now();
        // Query
        let z_second_output =
            unsafe { std::slice::from_raw_parts(z[z_len / 2 + 1..].as_ptr(), z_len / 2) };
        z[1..=z_len / 2]
            .par_iter_mut()
            .zip(z_second_output.par_iter())
            .for_each(|(z_i, f_one)| {
                *z_i += r * (*f_one - *z_i);
            });
        let q_r = interpolate(&[(F::zero(), q_0), (F::one(), q_1), (two, q_2)], r);
        z[0] = q_r;
        z = &mut z[..=z_len / 2];
        // println!(
        //     "prover round: {} part 2 took: {}ms",
        //     round_id,
        //     time.elapsed().as_millis()
        // );
    }
    // last round
    debug_assert_eq!(z.len(), 5);
    let (s_0, s_1) = (F::random(E::rng()), F::random(E::rng()));
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
    let _: F = last_round_challenge.online_decommit(&mut engine).await;

    // Decision
    let _: (Vec<F>, F, F, F, F) = final_msg.online_decommit(&mut engine).await;
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
        let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
        let dealer_id = party_ids[0];
        let prover_id = party_ids[1];
        let mut two = GF128::zero();
        two.set_bit(true, 1);
        let three = two + GF128::one();
        let four = two * two;

        let mut rng = thread_rng();

        // Offline proof preparation
        let (router, mut engines) = LocalRouter::new(UCTag::new(&"root"), &party_ids_set);

        let mut dealer_input: Vec<_> = vec![GF128::zero(); Z_LEN];
        dealer_input
            .iter_mut()
            .step_by(2)
            .for_each(|v| *v = GF128::random(&mut rng));
        let mut dealer_input_clone = dealer_input.clone();

        let router_handle = tokio::spawn(router.launch());
        let dealer_handle = dealer(
            engines.remove(&dealer_id).unwrap(),
            &mut dealer_input_clone,
            prover_id,
            two,
            three,
            four,
        );
        let (_, round_count) = compute_round_count_and_m(Z_LEN);
        let prover_handle =
            prover_offline::<GF128>(engines.remove(&prover_id).unwrap(), round_count, dealer_id);
        let verifiers_handle: Vec<_> = engines
            .into_iter()
            .map(|(pid, e)| async move {
                Result::<(u64, OfflineVerifier), ()>::Ok((
                    pid,
                    verifier_offline(e, round_count, dealer_id).await,
                ))
            })
            .collect();
        let (_, prover_offline, verifiers_offline) =
            join!(dealer_handle, prover_handle, join_all(verifiers_handle));
        router_handle.await.unwrap().unwrap();

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
                two,
                three,
                four,
            )
            .await
        });
        let verifiers_futures: Vec<_> = verifiers_offline
            .into_iter()
            .map(|v| {
                let (pid, offline_verifier) = v.unwrap();
                let engine = engines.remove(&pid).unwrap();
                let input = verifier_input.clone();
                async move {
                    let mut input = input;
                    verifier(
                        engine,
                        &mut input,
                        prover_id,
                        &offline_verifier,
                        two,
                        three,
                        four,
                    )
                    .await;
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
