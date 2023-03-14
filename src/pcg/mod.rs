use crate::{
    engine::MultiPartyEngine,
    fields::{FieldElement, GF128, GF2},
    pprf::{pprf_receiver, pprf_sender},
    pseudorandom::hash::correlation_robust_hash_block_field,
};
use aes_prng::AesRng;
use futures::future::try_join_all;
use rand_core::RngCore;

pub struct ReceiverPcgKey {
    evals: Vec<GF128>,
    code_seed: AesRng,
    code_width: usize,
    delta: GF128,
}
pub async fn receiver_pcg_key<E: MultiPartyEngine>(
    engine: E,
    pprf_count: usize,
    pprf_depth: usize,
    code_seed: AesRng,
    code_width: usize,
) -> Result<ReceiverPcgKey, ()> {
    let t = pprf_count;
    let N = pprf_count * (1 << pprf_depth);
    let delta = GF128::random(E::rng());
    let pprf_futures: Vec<_> = (0..t)
        .map(|i| {
            let sub_engine = engine.sub_protocol(format!("PCG TO PPRF {}", i));
            tokio::spawn(pprf_sender(sub_engine, pprf_depth, delta))
        })
        .collect();
    let pprfs = try_join_all(pprf_futures).await.or(Err(()))?;
    let mut acc = GF128::zero();
    let mut evals = Vec::<GF128>::with_capacity(N);
    for pprf in pprfs.into_iter() {
        let pprf = pprf?;
        for o in pprf.evals.into_iter() {
            acc += o;
            evals.push(acc);
        }
    }
    Ok(ReceiverPcgKey {
        evals,
        code_seed,
        code_width,
        delta,
    })
}
impl ReceiverPcgKey {
    fn next_subfield_vole(&mut self) -> GF128 {
        let mut acc = GF128::zero();
        for _ in 0..self.code_width {
            let entry = self.evals[self.code_seed.next_u64() as usize & (self.evals.len() - 1)];
            acc += entry;
        }
        acc
    }

    fn next_correlated_ot(&mut self) -> (GF128, GF128) {
        let v = self.next_subfield_vole();
        (v, v + self.delta)
    }

    fn next_random_ot(&mut self) -> (GF128, GF128) {
        let (m_0, m_1) = self.next_correlated_ot();
        (
            correlation_robust_hash_block_field(m_0),
            correlation_robust_hash_block_field(m_1),
        )
    }

    fn next_random_bit_ot(&mut self) -> (GF2, GF2) {
        let (m_0, m_1) = self.next_random_ot();
        (m_0.get_bit(0).into(), m_1.get_bit(0).into())
    }

    fn next_bit_beaver_triple(&mut self) -> (GF2, GF2, GF2) {
        let (m_0_0, mut m_0_1) = self.next_random_bit_ot();
        let (m_1_0, mut m_1_1) = self.next_random_bit_ot();
        m_0_1 -= m_0_0;
        m_1_1 -= m_1_0;
        (m_1_1, m_0_1, m_1_1 * m_0_1 + m_0_0 + m_1_0)
    }
}

pub struct SenderPcgKey {
    evals: Vec<(GF128, GF2)>,
    code_seed: AesRng,
    code_width: usize,
}
pub async fn sender_pcg_key<E: MultiPartyEngine>(
    engine: E,
    pprf_count: usize,
    pprf_depth: usize,
    code_seed: AesRng,
    code_width: usize,
) -> Result<SenderPcgKey, ()> {
    let t = pprf_count;
    let N = pprf_count * (1 << pprf_depth);
    let pprf_futures: Vec<_> = (0..t)
        .map(|i| {
            let sub_engine = engine.sub_protocol(format!("PCG TO PPRF {}", i));
            tokio::spawn(pprf_receiver(sub_engine, pprf_depth))
        })
        .collect();
    let pprfs = try_join_all(pprf_futures).await.or(Err(()))?;
    let mut acc = GF128::zero();
    let mut acc_bit = GF2::zero();
    let mut evals = Vec::<(GF128, GF2)>::with_capacity(N);
    for pprf in pprfs.into_iter() {
        let pprf = pprf?;
        for (idx, o) in pprf.evals.into_iter().enumerate() {
            acc += o;
            if idx == pprf.punctured_index {
                acc_bit.flip();
            }
            evals.push((acc, acc_bit));
        }
    }
    Ok(SenderPcgKey {
        evals,
        code_seed,
        code_width,
    })
}

impl SenderPcgKey {
    fn next_subfield_vole(&mut self) -> (GF128, GF2) {
        let mut acc = GF128::zero();
        let mut acc_bit = GF2::zero();
        for _ in 0..self.code_width {
            let entry = self.evals[self.code_seed.next_u64() as usize & (self.evals.len() - 1)];
            acc += entry.0;
            acc_bit += entry.1;
        }
        (acc, acc_bit)
    }
    fn next_correlated_ot(&mut self) -> (GF128, GF2) {
        self.next_subfield_vole()
    }

    fn next_random_ot(&mut self) -> (GF128, GF2) {
        let (m_b, b) = self.next_correlated_ot();
        (correlation_robust_hash_block_field(m_b), b)
    }

    fn next_random_bit_ot(&mut self) -> (GF2, GF2) {
        let (m_b, b) = self.next_random_ot();
        (m_b.get_bit(0).into(), b)
    }

    fn next_bit_beaver_triplet(&mut self) -> (GF2, GF2, GF2) {
        let (m_b0, b_0) = self.next_random_bit_ot();
        let (m_b1, b_1) = self.next_random_bit_ot();
        (b_0, b_1, b_0 * b_1 + m_b0 + m_b1)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use tokio::join;

    use super::{receiver_pcg_key, sender_pcg_key};
    use crate::engine::LocalRouter;
    use aes_prng::AesRng;
    use rand_core::SeedableRng;

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn test_sparse_vole() {
        const PPRF_COUNT: usize = 50;
        const PPRF_DEPTH: usize = 20;
        const CODE_WIDTH: usize = 8;
        const CORRELATION_COUNT: usize = 500_000;
        let seed = [0; 16];
        let party_ids = [1, 2];
        let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
        let (router, mut engines) = LocalRouter::new("root tag".into(), &party_ids_set);
        let sender_engine = engines.remove(&party_ids[0]).unwrap();
        let receiver_engine = engines.remove(&party_ids[1]).unwrap();

        let local_handle = tokio::spawn(router.launch());
        let sender_h = tokio::spawn(sender_pcg_key(
            sender_engine,
            PPRF_COUNT,
            PPRF_DEPTH,
            AesRng::from_seed(seed),
            CODE_WIDTH,
        ));
        let receiver_h = receiver_pcg_key(
            receiver_engine,
            PPRF_COUNT,
            PPRF_DEPTH,
            AesRng::from_seed(seed),
            CODE_WIDTH,
        );

        let (snd_res, rcv_res) = join!(sender_h, receiver_h);
        let (mut snd_res, mut rcv_res) = (snd_res.unwrap().unwrap(), rcv_res.unwrap());
        for _ in 0..CORRELATION_COUNT {
            let sender_corr = snd_res.next_bit_beaver_triplet();
            let rcv_corr = rcv_res.next_bit_beaver_triple();
            assert_eq!(
                (sender_corr.0 + rcv_corr.0) * (sender_corr.1 + rcv_corr.1),
                sender_corr.2 + rcv_corr.2
            );
        }
        local_handle.await.unwrap().unwrap();
    }
}
