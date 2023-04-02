use std::mem::MaybeUninit;

use crate::{
    engine::MultiPartyEngine,
    fields::{FieldElement, GF128, GF2},
    pprf::{
        pprf_receiver, pprf_sender, OfflinePprfSender, PackedPprfReceiver, PprfReceiver, PprfSender,
    },
    pseudorandom::{
        double_prg,
        hash::correlation_robust_hash_block_field,
        prg::{double_prg_field, fill_prg},
    },
};
use aes_prng::AesRng;
use futures::future::try_join_all;
use rand::{random, CryptoRng, SeedableRng};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tokio::join;

#[derive(Serialize, Deserialize)]
pub struct PackedOfflineReceiverPcgKey {
    pprfs: Vec<OfflinePprfSender>,
    delta: GF128,
}

impl PackedOfflineReceiverPcgKey {
    fn random(pprf_count: usize, pprf_depth: usize, mut rng: impl RngCore + CryptoRng) -> Self {
        let pprfs: Vec<_> = (0..pprf_count)
            .map(|_| OfflinePprfSender::new(pprf_depth, GF128::random(&mut rng)))
            .collect();
        Self {
            pprfs,
            delta: GF128::random(&mut rng),
        }
    }

    fn unpack(&self) -> (OfflineReceiverPcgKey, Vec<Vec<(GF128, GF128)>>) {
        let n = self.pprfs.iter().map(|v| 1 << v.depth).sum();
        let delta = self.delta;
        let mut evals = Vec::with_capacity(n);
        let (left_right_sums, evals_vecs): (Vec<_>, Vec<_>) = self
            .pprfs
            .iter()
            .enumerate()
            .map(|(idx, v)| {
                let sender = PprfSender::from(v);
                (sender.left_right_sums, sender.evals)
            })
            .unzip();
        let mut acc = GF128::zero();
        evals_vecs.iter().for_each(|v| {
            v.iter().for_each(|o| {
                acc += o;
                evals.push(acc);
            })
        });
        (
            OfflineReceiverPcgKey {
                delta: self.delta,
                evals,
            },
            left_right_sums,
        )
    }
}

pub struct OfflineReceiverPcgKey {
    evals: Vec<GF128>,
    delta: GF128,
}

pub struct ReceiverPcgKey {
    evals: Vec<GF128>,
    code_seed: AesRng,
    code_width: usize,
    delta: GF128,
}
pub async fn receiver_pcg_key<E: MultiPartyEngine>(
    engine: E,
    packed_key: &PackedOfflineReceiverPcgKey,
) -> Result<OfflineReceiverPcgKey, ()> {
    let n: usize = packed_key.pprfs.iter().map(|v| 1 << v.depth).sum();
    let (offline_key, left_right_sums) = packed_key.unpack();
    let delta = packed_key.delta;
    let pprf_futures: Vec<_> = left_right_sums
        .into_iter()
        .enumerate()
        .map(|(i, left_right_sum)| {
            let sub_engine = engine.sub_protocol(format!("PCG TO PPRF {}", i));
            tokio::spawn(async move {
                let left_right_sum = left_right_sum;
                pprf_sender(sub_engine, &left_right_sum, delta).await;
            })
        })
        .collect();
    let pprfs = try_join_all(pprf_futures).await.or(Err(()))?;
    Ok(offline_key)
}
impl ReceiverPcgKey {
    fn new(code_seed: AesRng, code_width: usize, offline_key: OfflineReceiverPcgKey) -> Self {
        Self {
            evals: offline_key.evals,
            delta: offline_key.delta,
            code_seed,
            code_width,
        }
    }
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

#[derive(Serialize, Deserialize)]
pub struct PackedOfflineSenderPcgKey {
    receivers: Vec<PackedPprfReceiver>,
}

pub struct OfflineSenderPcgKey {
    evals: Vec<(GF128, GF2)>,
}

impl From<&PackedOfflineSenderPcgKey> for OfflineSenderPcgKey {
    fn from(value: &PackedOfflineSenderPcgKey) -> Self {
        let n = value
            .receivers
            .iter()
            .map(|v| 1 << v.subtree_seeds.len())
            .sum();
        let mut evals = Vec::with_capacity(n);
        let mut acc = GF128::zero();
        let mut bin_acc = GF2::zero();
        for pprf in value.receivers.iter().map(|v| PprfReceiver::from(v)) {
            for (idx, v) in pprf.evals.into_iter().enumerate() {
                acc += v;
                if idx == pprf.punctured_index {
                    bin_acc.flip();
                }
                evals.push((acc, bin_acc));
            }
        }
        OfflineSenderPcgKey { evals }
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
    let n = pprf_count * (1 << pprf_depth);
    let pprf_futures: Vec<_> = (0..t)
        .map(|i| {
            let sub_engine = engine.sub_protocol(format!("PCG TO PPRF {}", i));
            tokio::spawn(pprf_receiver(sub_engine, pprf_depth))
        })
        .collect();
    let pprfs = try_join_all(pprf_futures).await.or(Err(()))?;
    let mut acc = GF128::zero();
    let mut acc_bit = GF2::zero();
    let mut evals = Vec::<(GF128, GF2)>::with_capacity(n);
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
    pub fn new(
        offline_key: OfflineSenderPcgKey,
        code_seed: AesRng,
        code_width: usize,
    ) -> SenderPcgKey {
        Self {
            code_seed,
            code_width,
            evals: offline_key.evals,
        }
    }
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

#[derive(Serialize, Deserialize)]
pub struct PackedOfflineFullPcgKey {
    sender: PackedOfflineSenderPcgKey,
    receiver: PackedOfflineReceiverPcgKey,
    is_first: bool,
}

fn deal_sender_receiver_keys(
    pprf_count: usize,
    pprf_depth: usize,
    mut rng: impl RngCore + CryptoRng,
) -> (PackedOfflineSenderPcgKey, PackedOfflineReceiverPcgKey) {
    let code_seed = AesRng::from_random_seed();
    let receiver = PackedOfflineReceiverPcgKey::random(pprf_count, pprf_depth, &mut rng);
    let (receiver_offline, _) = receiver.unpack();
    let receivers = receiver
        .pprfs
        .iter()
        .map(|v| {
            let mut punctured_index = 0;
            let mut seed = v.seed;
            let mut random_number = rng.next_u64();
            let subtree_seeds: Vec<_> = (0..pprf_depth)
                .into_iter()
                .map(|i| {
                    let (mut s_0, mut s_1) = double_prg_field(&seed);
                    punctured_index <<= 1;
                    if random_number & 1 == 1 {
                        punctured_index += 1;
                        seed = s_1;
                        s_0
                    } else {
                        seed = s_0;
                        s_1
                    }
                })
                .collect();
            let val_at_index = seed + receiver.delta;
            PackedPprfReceiver {
                punctured_index,
                subtree_seeds,
                val_at_index,
            }
        })
        .collect();
    let sender = PackedOfflineSenderPcgKey { receivers };
    (sender, receiver)
}
impl PackedOfflineFullPcgKey {
    pub fn deal(
        pprf_count: usize,
        pprf_depth: usize,
        code_width: usize,
        mut rng: impl RngCore + CryptoRng,
    ) -> (PackedOfflineFullPcgKey, PackedOfflineFullPcgKey) {
        let (first_sender, first_receiver) =
            deal_sender_receiver_keys(pprf_count, pprf_depth, &mut rng);
        let (second_sender, second_receiver) =
            deal_sender_receiver_keys(pprf_count, pprf_depth, &mut rng);
        let first_full_key = PackedOfflineFullPcgKey {
            sender: first_sender,
            receiver: second_receiver,
            is_first: true,
        };
        let second_full_key = PackedOfflineFullPcgKey {
            sender: second_sender,
            receiver: first_receiver,
            is_first: false,
        };
        (first_full_key, second_full_key)
    }
}

pub struct FullPcgKey {
    sender: SenderPcgKey,
    receiver: ReceiverPcgKey,
    is_first: bool,
}

impl FullPcgKey {
    pub fn new_from_offline(
        offline_key: &PackedOfflineFullPcgKey,
        code_seed: [u8; 16],
        code_width: usize,
    ) -> Self {
        let sender = SenderPcgKey::new(
            OfflineSenderPcgKey::from(&offline_key.sender),
            AesRng::from_seed(code_seed),
            code_width,
        );
        let (offline_key_recv, _) = offline_key.receiver.unpack();
        let receiver =
            ReceiverPcgKey::new(AesRng::from_seed(code_seed), code_width, offline_key_recv);
        Self {
            sender,
            receiver,
            is_first: offline_key.is_first,
        }
    }
    pub async fn new<E: MultiPartyEngine>(
        engine: E,
        pprf_count: usize,
        pprf_depth: usize,
        code_seed: [u8; 16],
        code_width: usize,
    ) -> Result<Self, ()> {
        let my_id = engine.my_party_id();
        let peer_id = engine.party_ids()[0] + engine.party_ids()[1] - my_id;
        let (mut first_engine, mut second_engine) = (
            engine.sub_protocol("FULL PCG TO FIRST SUB PCG"),
            engine.sub_protocol("FULL PCG TO SECOND SUB PCG"),
        );
        if my_id > peer_id {
            (first_engine, second_engine) = (second_engine, first_engine)
        }
        let seed_sender = AesRng::from_seed(code_seed);
        let sender = tokio::spawn(sender_pcg_key(
            first_engine,
            pprf_count,
            pprf_depth,
            seed_sender,
            code_width,
        ));
        let delta = GF128::random(E::rng());
        let pprfs: Vec<_> = (0..pprf_count)
            .map(|_| OfflinePprfSender::new(pprf_depth, GF128::random(E::rng())))
            .collect();
        let receiver = tokio::spawn(async move {
            let pprfs = pprfs;
            let packed_key = PackedOfflineReceiverPcgKey { delta, pprfs };
            receiver_pcg_key(second_engine, &packed_key).await
        });
        let (snd_res, rcv_res) = join!(sender, receiver);
        Ok(Self {
            sender: snd_res.or(Err(()))??,
            receiver: ReceiverPcgKey::new(
                AesRng::from_seed(code_seed),
                code_width,
                rcv_res.or(Err(()))??,
            ),
            is_first: my_id < peer_id,
        })
    }
    pub fn next_wide_beaver_triple(&mut self) -> (GF2, GF128, GF128) {
        let (m_b, b) = self.sender.next_random_ot();
        let (m_0, mut m_1) = self.receiver.next_random_ot();
        m_1 -= m_0;
        (b, m_1, m_1 * b + m_b + m_0)
    }
    pub fn next_bit_beaver_triple(&mut self) -> (GF2, GF2, GF2) {
        if self.is_first {
            self.sender.next_bit_beaver_triplet()
        } else {
            self.receiver.next_bit_beaver_triple()
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use rand::thread_rng;
    use tokio::join;

    use super::{receiver_pcg_key, sender_pcg_key};
    use crate::{
        engine::LocalRouter,
        fields::{FieldElement, GF128},
        pcg::FullPcgKey,
        pprf::OfflinePprfSender,
        uc_tags::UCTag,
    };
    use aes_prng::AesRng;
    use rand_core::SeedableRng;

    #[tokio::test]
    async fn test_bit_beaver_triples() {
        const PPRF_COUNT: usize = 5;
        const PPRF_DEPTH: usize = 8;
        const CODE_WIDTH: usize = 7;
        const CORRELATION_COUNT: usize = 10_000;
        let seed = [0; 16];
        let party_ids = [1, 2];
        let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
        let (router, mut engines) = LocalRouter::new(UCTag::new(&"root tag"), &party_ids_set);
        let sender_engine = engines.remove(&party_ids[0]).unwrap();
        let receiver_engine = engines.remove(&party_ids[1]).unwrap();

        let local_handle = tokio::spawn(router.launch());
        let sender_h = sender_pcg_key(
            sender_engine,
            PPRF_COUNT,
            PPRF_DEPTH,
            AesRng::from_seed(seed),
            CODE_WIDTH,
        );
        let offline_pprfs: Vec<_> = (0..PPRF_COUNT)
            .map(|_| OfflinePprfSender::new(PPRF_DEPTH, GF128::random(thread_rng())))
            .collect();
        let receiver_h = receiver_pcg_key(
            receiver_engine,
            &offline_pprfs,
            AesRng::from_seed(seed),
            CODE_WIDTH,
        );

        let (snd_res, rcv_res) = join!(sender_h, receiver_h);
        let (mut snd_res, mut rcv_res) = (snd_res.unwrap(), rcv_res.unwrap());
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
    #[tokio::test]
    async fn test_full_pcg_key() {
        const PPRF_COUNT: usize = 10;
        const PPRF_DEPTH: usize = 7;
        const CODE_WIDTH: usize = 8;
        const CORRELATION_COUNT: usize = 10_000;
        let seed = [0; 16];
        let party_ids = [1, 2];
        let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
        let (router, mut engines) =
            LocalRouter::new(UCTag::new(&"root tag").into(), &party_ids_set);
        let sender_engine = engines.remove(&party_ids[0]).unwrap();
        let receiver_engine = engines.remove(&party_ids[1]).unwrap();

        let local_handle = tokio::spawn(router.launch());
        let sender_h = tokio::spawn(FullPcgKey::new(
            sender_engine,
            PPRF_COUNT,
            PPRF_DEPTH,
            seed,
            CODE_WIDTH,
        ));
        let receiver_h = FullPcgKey::new(receiver_engine, PPRF_COUNT, PPRF_DEPTH, seed, CODE_WIDTH);

        let (snd_res, rcv_res) = join!(sender_h, receiver_h);
        let (mut snd_res, mut rcv_res) = (snd_res.unwrap().unwrap(), rcv_res.unwrap());
        for _ in 0..CORRELATION_COUNT {
            let sender_corr = snd_res.next_wide_beaver_triple();
            let rcv_corr = rcv_res.next_wide_beaver_triple();
            assert_eq!(
                (sender_corr.1 + rcv_corr.1) * (sender_corr.0 + rcv_corr.0),
                sender_corr.2 + rcv_corr.2
            );
        }
        local_handle.await.unwrap().unwrap();
    }
}
