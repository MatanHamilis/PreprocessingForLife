use rayon::prelude::*;
use std::{
    mem::MaybeUninit,
    ops::Mul,
    time::{Duration, Instant},
};

use crate::{
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, GF128},
};

const INTERNAL_ROUND_PROOF_LENGTH: usize = 3;
const LAST_ROUND_PROOF_LENGTH: usize = 5;
const CHUNK_SIZE: usize = 1 << 10;

fn compute_round_count_and_m<F: FieldElement>(z: &[F]) -> (usize, usize) {
    assert_eq!((z.len() - 1) & 3, 0);
    let m = (z.len() - 1) / 4;
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
    let output = z
        .par_chunks(CHUNK_SIZE)
        .map(|f| f.chunks_exact(2).map(|f| f[0] * f[1]).sum())
        .sum();
    output
}
pub async fn prover<F: FieldElement, E: MultiPartyEngine>(
    mut engine: E,
    mut z: &mut [F],
    dealer_id: PartyId,
    two: F,
    three: F,
    four: F,
) {
    // Init
    let (_, round_count) = compute_round_count_and_m(&z);
    let (proof_masks, s_tilde): (Vec<F>, (F, F)) = engine.recv_from(dealer_id).await.unwrap();
    debug_assert_eq!(
        proof_masks.len(),
        INTERNAL_ROUND_PROOF_LENGTH * (round_count - 1) + LAST_ROUND_PROOF_LENGTH
    );

    let my_id = engine.my_party_id();
    let parties: Vec<_> = engine
        .party_ids()
        .iter()
        .copied()
        .filter(|id| id != &my_id && id != &dealer_id)
        .collect();

    let inv_two_minus_one = F::one() / (two - F::one());
    let mut q_3_container_uninit = vec![MaybeUninit::<F>::uninit(); z.len() / 2];
    let mut q_3_container = unsafe {
        Vec::from_raw_parts(
            q_3_container_uninit.as_mut_ptr() as *mut F,
            q_3_container_uninit.len(),
            q_3_container_uninit.capacity(),
        )
    };
    std::mem::forget(q_3_container_uninit);
    let mut slope_container_uninit = vec![MaybeUninit::<F>::uninit(); z.len() / 2];
    let mut slope_container = unsafe {
        Vec::from_raw_parts(
            slope_container_uninit.as_mut_ptr() as *mut F,
            slope_container_uninit.len(),
            slope_container_uninit.capacity(),
        )
    };
    std::mem::forget(slope_container_uninit);
    // Rounds
    for round_id in 1..round_count {
        // Computation
        let z_len = z.len();
        let i1 = &z[1..=z_len / 2];
        let q_1 = g(i1);
        let i2 = &z[z_len / 2 + 1..];
        let q_2 = g(i2);
        debug_assert_eq!(z[0], q_1 + q_2);
        q_3_container
            .par_chunks_mut(CHUNK_SIZE)
            .zip(slope_container.par_chunks_mut(CHUNK_SIZE))
            .zip(z[1..=z_len / 2].par_chunks(CHUNK_SIZE))
            .zip(z[z_len / 2 + 1..].par_chunks(CHUNK_SIZE))
            .for_each(|(((q_3_i, slope_i), f_one), f_two)| {
                for i in 0..f_one.len() {
                    slope_i[i] = (f_two[i] - f_one[i]) * inv_two_minus_one;
                    q_3_i[i] = f_two[i] + slope_i[i] * (three - two);
                }
            });

        let q_3 = g(&q_3_container[..z.len() / 2]);
        let proof_masks_base = INTERNAL_ROUND_PROOF_LENGTH * (round_id - 1);
        let mask_1 = proof_masks[proof_masks_base];
        let mask_2 = proof_masks[proof_masks_base + 1];
        let mask_3 = proof_masks[proof_masks_base + 2];
        let masked_proof = (q_1 - mask_1, q_2 - mask_2, q_3 - mask_3);

        // Communication
        engine.send_multicast(masked_proof, &parties);
        let r: F = engine.recv_from(dealer_id).await.unwrap();

        // Query
        z.par_iter_mut()
            .skip(1)
            .take(z_len / 2)
            .zip(slope_container.par_iter().take(z_len / 2))
            .for_each(|(z_i, slope_i)| {
                let f_one = *z_i;
                let f_zero = f_one - *slope_i;
                *z_i = f_zero + r * *slope_i;
            });
        let q_r = interpolate(&[(F::one(), q_1), (two, q_2), (three, q_3)], r);
        z[0] = q_r;
        z = &mut z[..=z_len / 2];
    }
    // last round
    debug_assert_eq!(z.len(), 5);
    let (s_1, s_2) = (F::random(E::rng()), F::random(E::rng()));
    let mut f_1 = [
        (F::zero(), s_1),
        (F::one(), z[1]),
        (two, z[3]),
        (three, F::zero()),
        (four, F::zero()),
    ];
    let mut f_2 = [
        (F::zero(), s_2),
        (F::one(), z[2]),
        (two, z[4]),
        (three, F::zero()),
        (four, F::zero()),
    ];
    f_1[3].1 = interpolate(&f_1[0..3], three);
    f_1[4].1 = interpolate(&f_1[0..3], four);
    f_2[3].1 = interpolate(&f_2[0..3], three);
    f_2[4].1 = interpolate(&f_2[0..3], four);
    let proof_masks_last_round = &proof_masks[proof_masks.len() - LAST_ROUND_PROOF_LENGTH..];
    let q: [_; 5] = core::array::from_fn(|i| f_1[i].1 * f_2[i].1);
    let last_round_proof = [
        s_1 - s_tilde.0,
        s_2 - s_tilde.1,
        q[0] - proof_masks_last_round[0],
        q[1] - proof_masks_last_round[1],
        q[2] - proof_masks_last_round[2],
        q[3] - proof_masks_last_round[3],
        q[4] - proof_masks_last_round[4],
    ];
    engine.send_multicast(last_round_proof, &parties);
    let _: F = engine.recv_from(dealer_id).await.unwrap();

    // Decision
    let _: (Vec<F>, F, F, F, F) = engine.recv_from(dealer_id).await.unwrap();
}

pub async fn verifier<F: FieldElement>(
    mut engine: impl MultiPartyEngine,
    mut z_hat: &mut [F],
    prover_id: PartyId,
    dealer_id: PartyId,
    two: F,
    three: F,
    four: F,
) {
    // Init
    let (_, round_count) = compute_round_count_and_m(&z_hat);
    debug_assert!(z_hat.iter().skip(2).step_by(2).all(|v| v.is_zero()));

    let mut b_hat = Vec::with_capacity(round_count);
    // Rounds
    let inv_two_minus_one = F::one() / (two - F::one());
    let mut slope_container_uninit = vec![MaybeUninit::<F>::uninit(); z_hat.len() / 2];
    let mut slope_container = unsafe {
        Vec::from_raw_parts(
            slope_container_uninit.as_mut_ptr() as *mut F,
            slope_container_uninit.len(),
            slope_container_uninit.capacity(),
        )
    };
    std::mem::forget(slope_container_uninit);
    for _ in 1..round_count {
        let z_len = z_hat.len();
        let (q_1_hat, q_2_hat, q_3_hat): (F, F, F) = engine.recv_from(prover_id).await.unwrap();
        let r: F = engine.recv_from(dealer_id).await.unwrap();
        b_hat.push(z_hat[0] - q_1_hat - q_2_hat);
        slope_container
            .par_chunks_mut(CHUNK_SIZE)
            .zip(z_hat[1..=z_len / 2].par_chunks(CHUNK_SIZE))
            .zip(z_hat[z_len / 2 + 1..].par_chunks(CHUNK_SIZE))
            .for_each(|((slope_i, f_one), f_two)| {
                for i in 0..f_one.len() {
                    slope_i[i] = (f_two[i] - f_one[i]) * inv_two_minus_one;
                }
            });
        z_hat[1..=z_len / 2]
            .par_chunks_mut(CHUNK_SIZE)
            .zip(slope_container.par_chunks(CHUNK_SIZE))
            .for_each(|(z_i, slope_i)| {
                for i in 0..z_i.len() {
                    let f_one = z_i[i];
                    let f_zero = f_one - slope_i[i];
                    z_i[i] = f_zero + r * slope_i[i];
                }
            });
        let q_r = interpolate(&[(F::one(), q_1_hat), (two, q_2_hat), (three, q_3_hat)], r);
        z_hat[0] = q_r;
        z_hat = &mut z_hat[..=z_len / 2];
    }
    //last_round
    debug_assert_eq!(z_hat.len(), 5);
    let last_round_proof: [F; 7] = engine.recv_from(prover_id).await.unwrap();
    let r: F = engine.recv_from(dealer_id).await.unwrap();
    let mut f_1_hat = [
        (F::zero(), last_round_proof[0]),
        (F::one(), z_hat[1]),
        (two, z_hat[3]),
        (r, F::zero()),
    ];
    let mut f_2_hat = [
        (F::zero(), last_round_proof[1]),
        (F::one(), z_hat[2]),
        (two, z_hat[4]),
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
    f_1_hat[3].1 = interpolate(&f_1_hat[0..3], f_1_hat[3].0);
    f_2_hat[3].1 = interpolate(&f_2_hat[0..3], f_2_hat[3].0);
    q_hat[5].1 = interpolate(&q_hat[0..5], q_hat[5].0);
    b_hat.push(z_hat[0] - q_hat[1].1 - q_hat[2].1);

    // Decision
    let (betas, b_tilde_check, f_1_tilde_r, f_2_tilde_r, q_tilde_r): (Vec<F>, F, F, F, F) =
        engine.recv_from(dealer_id).await.unwrap();
    assert_eq!(betas.len(), b_hat.len());
    let b_hat_check = betas
        .iter()
        .zip(b_hat.iter())
        .map(|(a, b)| *a * *b)
        .fold(F::zero(), |acc, cur| acc + cur);
    assert_eq!(b_tilde_check + b_hat_check, F::zero());
    let f_1_r = f_1_tilde_r + f_1_hat[3].1;
    let f_2_r = f_2_tilde_r + f_2_hat[3].1;
    let q_r = q_tilde_r + q_hat[5].1;
    assert_eq!(q_r, f_1_r * f_2_r);
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
    let (_, round_count) = compute_round_count_and_m(&z_tilde);
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
    let inv_two_minus_one = F::one() / (two - F::one());
    let mut slope_container_uninit = vec![MaybeUninit::<F>::uninit(); z_tilde.len() / 2];
    let mut slope_container = unsafe {
        Vec::from_raw_parts(
            slope_container_uninit.as_mut_ptr() as *mut F,
            slope_container_uninit.len(),
            slope_container_uninit.capacity(),
        )
    };
    std::mem::forget(slope_container_uninit);
    for round_id in 1..round_count {
        let z_len = z_tilde.len();
        let r = F::random(&mut rng);
        engine.broadcast(r);
        let q_base = (round_id - 1) * INTERNAL_ROUND_PROOF_LENGTH;
        let (q_1_tilde, q_2_tilde, q_3_tilde) = (
            proof_masks[q_base],
            proof_masks[q_base + 1],
            proof_masks[q_base + 2],
        );
        b_tilde.push(z_tilde[0] - q_1_tilde - q_2_tilde);
        slope_container
            .par_chunks_mut(CHUNK_SIZE)
            .zip(z_tilde[1..=z_len / 2].par_chunks(CHUNK_SIZE))
            .zip(z_tilde[z_len / 2 + 1..].par_chunks(CHUNK_SIZE))
            .for_each(|((slope_i, f_one), f_two)| {
                for i in 0..f_one.len() {
                    slope_i[i] = (f_two[i] - f_one[i]) * inv_two_minus_one;
                }
            });
        z_tilde[1..=z_len / 2]
            .par_chunks_mut(CHUNK_SIZE)
            .zip(slope_container.par_chunks(CHUNK_SIZE))
            .for_each(|(z_i, slope_i)| {
                for i in 0..z_i.len() {
                    let f_one = z_i[i];
                    let f_zero = f_one - slope_i[i];
                    let f_hat_r = f_zero + r * slope_i[i];
                    z_i[i] = f_hat_r;
                }
            });
        let q_r = interpolate(
            &[(F::one(), q_1_tilde), (two, q_2_tilde), (three, q_3_tilde)],
            r,
        );
        z_tilde[0] = q_r;
        z_tilde = &mut z_tilde[..=z_len / 2];
    }
    // last round
    debug_assert_eq!(z_tilde.len(), 5);
    let r = F::random(&mut rng);
    engine.broadcast(r);
    let last_round_masks = &proof_masks[proof_masks.len() - LAST_ROUND_PROOF_LENGTH..];
    let mut f_1_tilde = [
        (F::zero(), s_tilde.0),
        (F::one(), z_tilde[1]),
        (two, z_tilde[3]),
        (r, F::zero()),
    ];
    let mut f_2_tilde = [
        (F::zero(), s_tilde.1),
        (F::one(), z_tilde[2]),
        (two, z_tilde[4]),
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
    f_1_tilde[3].1 = interpolate(&f_1_tilde[0..3], f_1_tilde[3].0);
    f_2_tilde[3].1 = interpolate(&f_2_tilde[0..3], f_2_tilde[3].0);
    q_tilde[5].1 = interpolate(&q_tilde[0..5], q_tilde[5].0);
    b_tilde.push(z_tilde[0] - q_tilde[1].1 - q_tilde[2].1);

    // Decision
    let betas: Vec<_> = (0..round_count).map(|_| F::random(&mut rng)).collect();
    debug_assert_eq!(betas.len(), b_tilde.len());
    let b_tilde_check = betas
        .iter()
        .zip(b_tilde.iter())
        .map(|(a, b)| *a * *b)
        .fold(F::zero(), |acc, cur| acc + cur);
    engine.broadcast((
        betas,
        b_tilde_check,
        f_1_tilde[3].1,
        f_2_tilde[3].1,
        q_tilde[5].1,
    ));
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use futures::future::try_join_all;
    use futures::FutureExt;
    use rand::thread_rng;
    use tokio::join;

    use super::g;
    use super::{dealer, prover, verifier};
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
        const PARTIES: usize = 10;
        let party_ids: [PartyId; PARTIES] = core::array::from_fn(|i| i as u64);
        let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
        let prover_id = party_ids[0];
        let dealer_id = party_ids[1];
        let mut two = GF128::zero();
        two.set_bit(true, 1);
        let three = two + GF128::one();
        let four = two * two;

        let mut rng = thread_rng();
        let (router, mut executors) = LocalRouter::new(UCTag::new(&"root"), &party_ids_set);

        let router_handle = tokio::spawn(router.launch());
        let mut prover_input = vec![GF128::zero(); Z_LEN];
        for i in 1..prover_input.len() {
            prover_input[i] = GF128::random(&mut rng);
        }
        prover_input[0] = g(&prover_input[1..]);

        let mut verifier_input: Vec<_> = prover_input
            .iter()
            .enumerate()
            .map(|(idx, v)| if idx % 2 != 0 { *v } else { GF128::zero() })
            .collect();
        verifier_input[0] -= GF128::random(&mut rng);
        let mut dealer_input: Vec<_> = prover_input
            .iter()
            .zip(verifier_input.iter())
            .map(|(a, b)| *a - *b)
            .collect();

        let prover_exec = executors.remove(&prover_id).unwrap();
        let prover_future = tokio::spawn(async move {
            let mut prover_input = prover_input;
            prover(prover_exec, &mut prover_input, dealer_id, two, three, four).await
        });
        let dealer_exec = executors.remove(&dealer_id).unwrap();
        let dealer_future = tokio::spawn(async move {
            let mut dealer_input = dealer_input;
            dealer(dealer_exec, &mut dealer_input, prover_id, two, three, four).await
        });
        let mut verifiers = vec![verifier_input; executors.len()];
        let verfiers_futures: Vec<_> = executors
            .into_values()
            .zip(verifiers.iter_mut())
            .map(|(e, input)| {
                verifier(e, input, prover_id, dealer_id, two, three, four)
                    .map(|_| Result::<(), ()>::Ok(()))
            })
            .collect();
        let v = try_join_all(verfiers_futures);
        let (_, _, v) = join!(prover_future, dealer_future, v);
        v.unwrap();
        router_handle.await.unwrap().unwrap()
    }
}
