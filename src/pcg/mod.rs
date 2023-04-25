use crate::{
    engine::MultiPartyEngine,
    fields::{FieldElement, PackedField, GF128, GF2},
    pprf::{
        distributed_pprf_receiver, distributed_pprf_sender, PackedPprfReceiver, PackedPprfSender,
        PprfReceiver, PprfSender,
    },
    pseudorandom::{
        hash::correlation_robust_hash_block_field, prf::prf_eval, prg::double_prg_field,
    },
};
use aes_prng::AesRng;
use bincode::de;
use futures::future::try_join_all;
use rand::{CryptoRng, SeedableRng};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tokio::join;

#[derive(Serialize, Deserialize)]
pub struct PackedOfflineReceiverPcgKey {
    pprfs: Vec<PackedPprfSender>,
    delta: GF128,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct RegularBeaverTriple<F: FieldElement>(
    #[serde(bound = "")] pub F,
    #[serde(bound = "")] pub F,
    #[serde(bound = "")] pub F,
);
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct WideBeaverTriple<F: FieldElement>(
    #[serde(bound = "")] pub F,
    #[serde(with = "BigArray")]
    #[serde(bound = "")]
    pub [F; 128],
    #[serde(with = "BigArray")]
    #[serde(bound = "")]
    pub [F; 128],
);

impl PackedOfflineReceiverPcgKey {
    fn new(pprfs: Vec<PackedPprfSender>, delta: GF128) -> Self {
        Self { pprfs, delta }
    }
    fn random(pprf_count: usize, pprf_depth: usize, mut rng: impl RngCore + CryptoRng) -> Self {
        let pprfs: Vec<_> = (0..pprf_count)
            .map(|_| PackedPprfSender::new(pprf_depth, GF128::random(&mut rng)))
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
pub async fn distributed_receiver_pcg_key<E: MultiPartyEngine>(
    engine: E,
    packed_key: &PackedOfflineReceiverPcgKey,
) -> Result<OfflineReceiverPcgKey, ()> {
    let (offline_key, left_right_sums) = packed_key.unpack();
    let delta = packed_key.delta;
    let pprf_futures: Vec<_> = left_right_sums
        .into_iter()
        .enumerate()
        .map(|(i, left_right_sum)| {
            let mut sub_engine = engine.sub_protocol(format!("PCG TO PPRF {}", i));
            tokio::spawn(async move {
                let left_right_sum = left_right_sum;
                let last = left_right_sum.last().unwrap();
                let leaf_sum = last.0 + last.1;
                sub_engine.broadcast(leaf_sum + delta);
                distributed_pprf_sender(sub_engine, &left_right_sum)
                    .await
                    .unwrap()
            })
        })
        .collect();
    try_join_all(pprf_futures).await.or(Err(()))?;
    Ok(offline_key)
}
impl ReceiverPcgKey {
    fn new(offline_key: OfflineReceiverPcgKey, code_seed: AesRng, code_width: usize) -> Self {
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

    fn next_random_ot<const N: usize, F: PackedField<GF2, N>>(&mut self) -> ([F; 128], [F; 128]) {
        let mut m0_arr = [F::zero(); 128];
        let mut m1_arr = [F::zero(); 128];
        for i in 0..N {
            let (m_0, m_1) = self.next_correlated_ot();
            let (m_0, m_1) = (
                correlation_robust_hash_block_field(m_0),
                correlation_robust_hash_block_field(m_1),
            );
            for j in 0..128 {
                m0_arr[j].set_bit(m_0.get_bit(j), i);
                m1_arr[j].set_bit(m_1.get_bit(j), i);
            }
        }
        (m0_arr, m1_arr)
    }

    fn next_random_bit_ot<const N: usize, F: PackedField<GF2, N>>(&mut self) -> (F, F) {
        let mut a = F::zero();
        let mut b = F::zero();
        for i in 0..N {
            let (m_0, m_1) = self.next_random_ot::<1, GF2>();
            let (a_0, b_0) = (m_0[0], m_1[0]);
            a.set_element(i, &a_0);
            b.set_element(i, &b_0);
        }
        (a, b)
    }

    fn next_bit_beaver_triple<const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> RegularBeaverTriple<F> {
        let (m_0_0, mut m_0_1) = self.next_random_bit_ot();
        let (m_1_0, mut m_1_1) = self.next_random_bit_ot();
        m_0_1 -= m_0_0;
        m_1_1 -= m_1_0;
        RegularBeaverTriple(m_1_1, m_0_1, m_1_1 * m_0_1 + m_0_0 + m_1_0)
    }
}

#[derive(Serialize, Deserialize)]
pub struct PackedOfflineSenderPcgKey {
    receivers: Vec<(PackedPprfReceiver, GF128)>,
}

pub struct OfflineSenderPcgKey {
    evals: Vec<(GF128, GF2)>,
}

impl From<&PackedOfflineSenderPcgKey> for OfflineSenderPcgKey {
    fn from(value: &PackedOfflineSenderPcgKey) -> Self {
        let n = value
            .receivers
            .iter()
            .map(|v| 1 << v.0.subtree_seeds.len())
            .sum();
        let mut evals = Vec::with_capacity(n);
        let mut acc = GF128::zero();
        let mut bin_acc = GF2::zero();
        for (mut pprf, punctured_val) in value
            .receivers
            .iter()
            .map(|v| (PprfReceiver::from(&v.0), v.1))
        {
            pprf.evals[pprf.punctured_index] = punctured_val;
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
pub async fn distributed_sender_pcg_key<E: MultiPartyEngine>(
    engine: E,
    pprf_count: usize,
    pprf_depth: usize,
) -> Result<OfflineSenderPcgKey, ()> {
    let t = pprf_count;
    let n = pprf_count * (1 << pprf_depth);
    let pprf_futures: Vec<_> = (0..t)
        .map(|i| {
            let mut sub_engine = engine.sub_protocol(format!("PCG TO PPRF {}", i));
            tokio::spawn(async move {
                let (sum, _): (GF128, _) = sub_engine.recv().await.unwrap();
                let mut recv = distributed_pprf_receiver(sub_engine, pprf_depth).await?;
                let leaf_sum = recv.evals.iter().fold(GF128::zero(), |acc, cur| acc + *cur);
                recv.evals[recv.punctured_index] = sum - leaf_sum;
                Ok(recv)
            })
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
    Ok(OfflineSenderPcgKey { evals })
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

    fn next_random_ot<const N: usize, F: PackedField<GF2, N>>(&mut self) -> ([F; 128], F) {
        let mut m_arr = [F::zero(); 128];
        let mut c = F::zero();
        for i in 0..N {
            let (m_b, b) = self.next_correlated_ot();
            let (m_b, b) = (correlation_robust_hash_block_field(m_b), b);
            for j in 0..128 {
                m_arr[j].set_bit(m_b.get_bit(j), i);
            }
            c.set_element(i, &b);
        }
        (m_arr, c)
    }

    fn next_random_bit_ot<const N: usize, F: PackedField<GF2, N>>(&mut self) -> (F, F) {
        let mut wb = F::zero();
        let mut wa = F::zero();
        for i in 0..N {
            let (m_b, b) = self.next_random_ot::<1, GF2>();
            wb.set_element(i, &b);
            wa.set_element(i, &m_b[0]);
        }
        (wa, wb)
    }

    fn next_bit_beaver_triplet<const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> RegularBeaverTriple<F> {
        let (m_b0, b_0) = self.next_random_bit_ot();
        let (m_b1, b_1) = self.next_random_bit_ot();
        RegularBeaverTriple(b_0, b_1, b_0 * b_1 + m_b0 + m_b1)
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
    let receiver = PackedOfflineReceiverPcgKey::random(pprf_count, pprf_depth, &mut rng);
    let receivers = receiver
        .pprfs
        .iter()
        .map(|v| {
            let punctured_index = (rng.next_u64() % (1 << v.depth)) as usize;
            let leaf_val = prf_eval(&v.seed, v.depth, punctured_index);
            (v.puncture(punctured_index), leaf_val + receiver.delta)
        })
        .collect();
    let sender = PackedOfflineSenderPcgKey { receivers };
    (sender, receiver)
}
impl PackedOfflineFullPcgKey {
    pub fn deal(
        pprf_count: usize,
        pprf_depth: usize,
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
            ReceiverPcgKey::new(offline_key_recv, AesRng::from_seed(code_seed), code_width);
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
        let sender = tokio::spawn(distributed_sender_pcg_key(
            first_engine,
            pprf_count,
            pprf_depth,
        ));
        let delta = GF128::random(E::rng());
        let pprfs: Vec<_> = (0..pprf_count)
            .map(|_| PackedPprfSender::new(pprf_depth, GF128::random(E::rng())))
            .collect();
        let receiver = tokio::spawn(async move {
            let pprfs = pprfs;
            let packed_key = PackedOfflineReceiverPcgKey { delta, pprfs };
            distributed_receiver_pcg_key(second_engine, &packed_key).await
        });
        let (snd_res, rcv_res) = join!(sender, receiver);
        let sender = SenderPcgKey::new(snd_res.or(Err(()))??, seed_sender, code_width);
        let receiver = ReceiverPcgKey::new(
            rcv_res.or(Err(()))??,
            AesRng::from_seed(code_seed),
            code_width,
        );
        Ok(Self {
            sender,
            receiver,
            is_first: my_id < peer_id,
        })
    }
    pub fn next_wide_beaver_triple<const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> WideBeaverTriple<F> {
        let (m_b, b) = self.sender.next_random_ot();
        let (m_0, mut m_1) = self.receiver.next_random_ot();
        for i in 0..m_0.len() {
            m_1[i] -= m_0[i];
        }
        let c = core::array::from_fn(|i| m_1[i] * b + m_b[i] + m_0[i]);
        WideBeaverTriple(b, m_1, c)
        // (b, m_1, m_1 * b + m_b + m_0)
    }
    pub fn next_bit_beaver_triple<const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> RegularBeaverTriple<F> {
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

    use super::{
        distributed_receiver_pcg_key, distributed_sender_pcg_key, PackedOfflineReceiverPcgKey,
        PackedOfflineSenderPcgKey, ReceiverPcgKey, SenderPcgKey,
    };
    use crate::{
        engine::LocalRouter,
        fields::{FieldElement, GF128, GF2},
        pcg::{
            deal_sender_receiver_keys, FullPcgKey, OfflineReceiverPcgKey, OfflineSenderPcgKey,
            PackedOfflineFullPcgKey,
        },
        pprf::PackedPprfSender,
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
        let sender_h = distributed_sender_pcg_key(sender_engine, PPRF_COUNT, PPRF_DEPTH);
        let packed_offline_receiver =
            PackedOfflineReceiverPcgKey::random(PPRF_COUNT, PPRF_DEPTH, thread_rng());
        let receiver_h = distributed_receiver_pcg_key(receiver_engine, &packed_offline_receiver);

        let (snd_res, rcv_res) = join!(sender_h, receiver_h);
        let (snd_res, rcv_res) = (snd_res.unwrap(), rcv_res.unwrap());
        let mut online_sender = SenderPcgKey::new(snd_res, AesRng::from_seed(seed), CODE_WIDTH);
        let mut online_receiver = ReceiverPcgKey::new(rcv_res, AesRng::from_seed(seed), CODE_WIDTH);
        for _ in 0..CORRELATION_COUNT {
            let sender_corr = online_sender.next_bit_beaver_triplet::<1, GF2>();
            let rcv_corr = online_receiver.next_bit_beaver_triple();
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
            let sender_corr = snd_res.next_wide_beaver_triple::<1, GF2>();
            let rcv_corr = rcv_res.next_wide_beaver_triple::<1, GF2>();
            for i in 0..sender_corr.1.len() {
                assert_eq!(
                    (sender_corr.1[i] + rcv_corr.1[i]) * (sender_corr.0 + rcv_corr.0),
                    sender_corr.2[i] + rcv_corr.2[i]
                );
            }
        }
        local_handle.await.unwrap().unwrap();
    }
    #[test]
    fn test_deal() {
        const PPRF_COUNT: usize = 1;
        const PPRF_DEPTH: usize = 2;
        const CODE_WIDTH: usize = 8;
        const CORRELATION_COUNT: usize = 10_000;
        let seed = [0u8; 16];
        let (sender, receiver) = deal_sender_receiver_keys(PPRF_COUNT, PPRF_DEPTH, thread_rng());
        let offline_sender = OfflineSenderPcgKey::from(&sender);
        let (offline_receiver, sums) = receiver.unpack();
        for i in 0..offline_receiver.evals.len() {
            assert_eq!(
                offline_sender.evals[i].0 + offline_receiver.evals[i],
                receiver.delta * offline_sender.evals[i].1
            );
        }
    }
    #[test]
    fn test_deal_full() {
        const PPRF_COUNT: usize = 10;
        const PPRF_DEPTH: usize = 13;
        const CODE_WIDTH: usize = 8;
        const CORRELATION_COUNT: usize = 10_000;
        let seed = [0u8; 16];
        let (packed_full_key_1, packed_full_key_2) =
            PackedOfflineFullPcgKey::deal(PPRF_COUNT, PPRF_DEPTH, thread_rng());
        let mut full_key_1 = FullPcgKey::new_from_offline(&packed_full_key_1, seed, CODE_WIDTH);
        let mut full_key_2 = FullPcgKey::new_from_offline(&packed_full_key_2, seed, CODE_WIDTH);

        for _ in 0..CORRELATION_COUNT {
            let sender_corr = full_key_1.next_wide_beaver_triple::<1, GF2>();
            let rcv_corr = full_key_2.next_wide_beaver_triple::<1, GF2>();
            for i in 0..sender_corr.1.len() {
                assert_eq!(
                    (sender_corr.1[i] + rcv_corr.1[i]) * (sender_corr.0 + rcv_corr.0),
                    sender_corr.2[i] + rcv_corr.2[i]
                );
            }
        }
    }
}
