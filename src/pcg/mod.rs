use std::{fmt::Debug, mem::MaybeUninit, time::Instant};

use crate::{
    fields::{FieldElement, PackedField, GF128, GF2},
    pprf::{PackedPprfReceiver, PackedPprfSender, PprfReceiver},
    pseudorandom::{
        hash::{correlation_robust_hash_block_field, correlation_robust_hash_block_field_slice},
        prf::prf_eval,
        prg::alloc_aligned_vec,
    },
};
use aes_prng::AesRng;
use log::info;
use rand::{CryptoRng, SeedableRng};
use rand_core::RngCore;
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_big_array::BigArray;

pub trait PackedSenderCorrelationGenerator:
    Serialize + DeserializeOwned + Send + Sync + Clone + Debug
{
    type Offline: OfflineSenderCorrelationGenerator;
    type Receiver: PackedReceiverCorrelationGenerator;
    fn unpack(&self) -> Self::Offline;
}
pub trait PackedReceiverCorrelationGenerator:
    Serialize + DeserializeOwned + Send + Sync + Clone + Debug
{
    type Offline: OfflineReceiverCorrelationGenerator;
    type Sender: PackedSenderCorrelationGenerator;
    fn unpack(&self) -> Self::Offline;
}

pub trait PackedKeysDealer<S: PackedSenderCorrelationGenerator>:
    Send + Sync + Clone + Debug
{
    fn deal<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (S, S::Receiver);
}
pub trait OfflineSenderCorrelationGenerator {
    type Online: OnlineSenderCorrelationGenerator;
    fn into_online(self, code: [u8; 16]) -> Self::Online;
}
pub trait OfflineReceiverCorrelationGenerator {
    type Online: OnlineReceiverCorrelationGenerator;
    fn into_online(self, code: [u8; 16]) -> Self::Online;
}
pub trait OnlineReceiverCorrelationGenerator {
    type Sender: OnlineSenderCorrelationGenerator;
    fn next_random_ot<const O: usize, const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> ([F; O], F);
    fn next_random_bit_ot<const N: usize, F: PackedField<GF2, N>>(&mut self) -> (F, F) {
        let (m_b, b) = self.next_random_ot::<1, N, F>();
        (m_b[0], b)
    }
    fn next_bit_beaver_triple<const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> RegularBeaverTriple<F> {
        let (m_b0, b_0) = self.next_random_bit_ot();
        let (m_b1, b_1) = self.next_random_bit_ot();
        RegularBeaverTriple(b_0, b_1, b_0 * b_1 + m_b0 + m_b1)
    }
}
pub trait OnlineSenderCorrelationGenerator {
    type Receiver: OnlineReceiverCorrelationGenerator;
    fn next_random_ot<const O: usize, const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> ([F; O], [F; O]);
    fn next_random_bit_ot<const N: usize, F: PackedField<GF2, N>>(&mut self) -> (F, F) {
        let (m_0, m_1) = self.next_random_ot::<1, N, F>();
        (m_0[0], m_1[0])
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

#[derive(Clone, Copy, Debug)]
pub struct StandardDealer {
    pprf_count: usize,
    pprf_depth: usize,
}
impl StandardDealer {
    pub fn new(pprf_count: usize, pprf_depth: usize) -> Self {
        Self {
            pprf_count,
            pprf_depth,
        }
    }
}
impl<const N: usize> PackedKeysDealer<PackedOfflineReceiverPcgKey<N>> for StandardDealer
where
    [(); (N + 7) / 8]:,
{
    fn deal<R: CryptoRng + RngCore>(
        &self,
        mut rng: &mut R,
    ) -> (
        PackedOfflineReceiverPcgKey<N>,
        <PackedOfflineReceiverPcgKey<N> as PackedSenderCorrelationGenerator>::Receiver,
    ) {
        let receiver =
            PackedOfflineReceiverPcgKey::random(self.pprf_count, self.pprf_depth, &mut rng);
        let receivers = core::array::from_fn(|i| {
            receiver.pprfs[i]
                .iter()
                .map(|v| {
                    let punctured_index = (rng.next_u32() % (1 << v.depth)) as usize;
                    let leaf_val = prf_eval(&v.seed, v.depth, punctured_index);
                    (v.puncture(punctured_index), leaf_val + receiver.delta[i])
                })
                .collect()
        });
        let sender = PackedOfflineSenderPcgKey { receivers };
        (receiver, sender)
    }
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PackedOfflineReceiverPcgKey<const N: usize> {
    #[serde(with = "BigArray")]
    pprfs: [Vec<PackedPprfSender>; N],
    #[serde(with = "BigArray")]
    delta: [GF128; N],
}
impl<const N: usize> PackedSenderCorrelationGenerator for PackedOfflineReceiverPcgKey<N>
where
    [(); (N + 7) / 8]:,
{
    type Offline = OfflineReceiverPcgKey<N>;
    type Receiver = PackedOfflineSenderPcgKey<N>;
    fn unpack(&self) -> OfflineReceiverPcgKey<N> {
        self.unpack_internal(true).0
    }
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

impl<const N: usize> PackedOfflineReceiverPcgKey<N> {
    fn random(pprf_count: usize, pprf_depth: usize, mut rng: impl RngCore + CryptoRng) -> Self {
        let pprfs = core::array::from_fn(|_| {
            (0..pprf_count)
                .map(|_| PackedPprfSender::new(pprf_depth, GF128::random(&mut rng)))
                .collect()
        });
        let delta = core::array::from_fn(|_| {
            let mut v = GF128::random(&mut rng);
            v.set_bit(false, 0);
            v
        });
        Self { pprfs, delta }
    }

    fn unpack_internal(
        &self,
        is_deal: bool,
    ) -> (
        OfflineReceiverPcgKey<N>,
        Option<[Vec<Vec<(GF128, GF128)>>; N]>,
    ) {
        let n = self.pprfs[0].iter().map(|v| 1 << v.depth).sum();
        let single_pprf_size = 1 << self.pprfs[0][0].depth;
        let pprf_count = self.pprfs[0].len();
        let mut evals: [_; N] = core::array::from_fn(|_| {
            let mut v = alloc_aligned_vec(n);
            unsafe { v.set_len(n) };
            v
        });
        let mut left_right_sums: [_; N] = core::array::from_fn(|_| Vec::with_capacity(pprf_count));
        let time = Instant::now();
        self.pprfs
            .par_iter()
            .zip(evals.par_iter_mut())
            .zip(left_right_sums.par_iter_mut())
            .for_each(|((p, evals), left_right_sums)| {
                let mut sums = vec![GF128::zero(); p.len()];
                if is_deal {
                    let time = Instant::now();
                    p.par_iter()
                        .zip(sums.par_iter_mut())
                        .zip(evals.par_chunks_exact_mut(single_pprf_size))
                        .for_each(|((v, s), output)| {
                            let mut buf = alloc_aligned_vec(output.len());
                            let mut sum = GF128::zero();
                            v.inflate_with_deal(output, &mut buf);
                            output.iter_mut().for_each(|v| {
                                v.set_bit(false, 0);
                                sum += *v;
                                *v = sum;
                            });
                            *s = sum;
                        });
                    info!(
                        "time internal pprfs expansion only: {}ms",
                        time.elapsed().as_millis()
                    );
                } else {
                    p.par_iter()
                        .zip(left_right_sums.par_iter_mut())
                        .zip(sums.par_iter_mut())
                        .zip(evals.par_chunks_exact_mut(single_pprf_size))
                        .for_each(|(((v, sums), s), output)| {
                            let mut buf = alloc_aligned_vec(output.len());
                            *sums = v.inflate_distributed(output, &mut buf);
                            let mut sum = GF128::zero();
                            output.iter_mut().for_each(|v| {
                                v.set_bit(false, 0);
                                sum += *v;
                                *v = sum;
                            });
                            *s = sum;
                        });
                };
                //prefix sum
                let mut sum = GF128::zero();
                sums.iter_mut().for_each(|v| {
                    let a = *v;
                    *v = sum;
                    sum += a;
                });
                evals
                    .par_chunks_exact_mut(single_pprf_size)
                    .zip(sums.par_iter())
                    .for_each(|(v, s)| {
                        let s = *s;
                        v.iter_mut().for_each(|vv| *vv += s);
                    });
            });
        info!(
            "PCG: Finished tree expansion {}ms!",
            time.elapsed().as_millis()
        );
        let time = Instant::now();
        let p = unsafe {
            std::alloc::alloc(
                std::alloc::Layout::from_size_align(n * std::mem::size_of::<[GF128; N]>(), 256)
                    .unwrap(),
            ) as *mut [GF128; N]
        };
        let mut final_evals: Vec<[GF128; N]> = unsafe { Vec::from_raw_parts(p, n, n) };
        unsafe { final_evals.set_len(n) };
        final_evals.par_iter_mut().enumerate().for_each(|(i, v)| {
            *v = core::array::from_fn(|j| evals[j][i]);
        });
        info!("PCG: Finished final evals! {}", time.elapsed().as_millis());
        (
            OfflineReceiverPcgKey {
                delta: self.delta,
                evals: final_evals,
            },
            Some(left_right_sums),
        )
    }
    fn unpack_distributed(&self) -> (OfflineReceiverPcgKey<N>, [Vec<Vec<(GF128, GF128)>>; N]) {
        let (a, b) = self.unpack_internal(false);
        (a, b.unwrap())
    }
}

pub struct OfflineReceiverPcgKey<const N: usize> {
    evals: Vec<[GF128; N]>,
    delta: [GF128; N],
}
impl<const N: usize> OfflineSenderCorrelationGenerator for OfflineReceiverPcgKey<N>
where
    [(); (N + 7) / 8]:,
{
    type Online = ReceiverPcgKey<N>;
    fn into_online(self, code: [u8; 16]) -> Self::Online {
        ReceiverPcgKey::new(self, AesRng::from_seed(code), 7)
    }
}

pub struct ReceiverPcgKey<const N: usize> {
    evals: Vec<[GF128; N]>,
    code_seed: AesRng,
    code_width: usize,
    delta: [GF128; N],
    idx: usize,
    arr: [GF128; N],
}

impl<const PCGPACK: usize> OnlineSenderCorrelationGenerator for ReceiverPcgKey<PCGPACK>
where
    [(); (PCGPACK + 7) / 8]:,
{
    type Receiver = SenderPcgKey<PCGPACK>;
    fn next_random_ot<const O: usize, const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> ([F; O], [F; O]) {
        let mut m0_arr = [F::zero(); O];
        let mut m1_arr = [F::zero(); O];
        for i in 0..N {
            let mut n = self.next_correlated_ot();
            n[0] = correlation_robust_hash_block_field(n[0]);
            n[1] = correlation_robust_hash_block_field(n[1]);
            for j in 0..O {
                m0_arr[j].set_bit(n[0].get_bit(j), i);
                m1_arr[j].set_bit(n[1].get_bit(j), i);
            }
        }
        (m0_arr, m1_arr)
    }
}
impl<const N: usize> ReceiverPcgKey<N> {
    fn new(offline_key: OfflineReceiverPcgKey<N>, code_seed: AesRng, code_width: usize) -> Self {
        Self {
            evals: offline_key.evals,
            delta: offline_key.delta,
            code_seed,
            code_width,
            idx: 0,
            arr: [GF128::zero(); N],
        }
    }
    fn next_subfield_vole(&mut self) -> GF128 {
        if self.idx == 0 {
            self.arr.iter_mut().for_each(|v| *v = GF128::zero());
            for _ in 0..self.code_width {
                let entry = self.evals[self.code_seed.next_u32() as usize & (self.evals.len() - 1)];
                self.arr.iter_mut().zip(entry.iter()).for_each(|(a, e)| {
                    *a += *e;
                })
            }
        }
        let ridx = self.idx;
        self.idx = (self.idx + 1) % N;
        self.arr[ridx]
    }

    fn next_correlated_ot(&mut self) -> [GF128; 2] {
        if self.idx == 0 {
            self.arr.iter_mut().for_each(|v| *v = GF128::zero());
            for _ in 0..self.code_width {
                let entry = self.evals[self.code_seed.next_u32() as usize & (self.evals.len() - 1)];
                self.arr.iter_mut().zip(entry.iter()).for_each(|(a, e)| {
                    *a += *e;
                })
            }
        }
        let ridx = self.idx;
        self.idx = (self.idx + 1) % N;
        [self.arr[ridx], self.arr[ridx] + self.delta[ridx]]
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PackedOfflineSenderPcgKey<const N: usize> {
    #[serde(with = "BigArray")]
    receivers: [Vec<(PackedPprfReceiver, GF128)>; N],
}
impl<const N: usize> PackedReceiverCorrelationGenerator for PackedOfflineSenderPcgKey<N>
where
    [(); (N + 7) / 8]:,
{
    type Offline = OfflineSenderPcgKey<N>;
    type Sender = PackedOfflineReceiverPcgKey<N>;
    fn unpack(&self) -> Self::Offline {
        OfflineSenderPcgKey::from(self)
    }
}

pub struct OfflineSenderPcgKey<const PCGPACK: usize>
where
    [(); (PCGPACK + 7) / 8]:,
{
    evals: Vec<[GF128; PCGPACK]>,
}

impl<const PCGPACK: usize> OfflineReceiverCorrelationGenerator for OfflineSenderPcgKey<PCGPACK>
where
    [(); (PCGPACK + 7) / 8]:,
{
    type Online = SenderPcgKey<PCGPACK>;
    fn into_online(self, code: [u8; 16]) -> Self::Online {
        SenderPcgKey::new(self, AesRng::from_seed(code), 7)
    }
}

impl<const PCGPACK: usize> From<&PackedOfflineSenderPcgKey<PCGPACK>>
    for OfflineSenderPcgKey<PCGPACK>
where
    [(); (PCGPACK + 7) / 8]:,
{
    fn from(value: &PackedOfflineSenderPcgKey<PCGPACK>) -> Self {
        let pprf_depth = value.receivers[0][0].0.subtree_seeds.len();
        for i in 0..value.receivers.len() {
            for j in 0..value.receivers[i].len() {
                assert_eq!(value.receivers[i][j].0.subtree_seeds.len(), pprf_depth);
            }
        }
        let n = value.receivers[0].len() * (1 << pprf_depth);
        let mut evals: [Vec<GF128>; PCGPACK] = core::array::from_fn(|_| {
            let mut v = alloc_aligned_vec(n);
            unsafe {
                v.set_len(n);
            };
            v
        });
        evals
            .iter_mut()
            .zip(value.receivers.iter())
            .for_each(|(evals, r)| {
                let mut sums = vec![GF128::zero(); r.len()];
                r.par_iter()
                    .zip(evals.par_chunks_exact_mut(1 << pprf_depth))
                    .zip(sums.par_iter_mut())
                    .for_each(|((v, evals), sum_cell)| {
                        let mut buf = alloc_aligned_vec(evals.len());
                        v.0.unpack_into(evals, &mut buf);
                        let (punctured_index, punctured_val) = (v.0.punctured_index, v.1);
                        evals[punctured_index] = punctured_val;
                        let mut sum = GF128::zero();
                        for (idx, d) in evals.iter_mut().enumerate() {
                            d.set_bit(idx == punctured_index, 0);
                            sum += *d;
                            *d = sum;
                        }
                        *sum_cell = sum;
                    });
                // prefix sum the sums (non inclusively)
                let mut sum = GF128::zero();
                for i in 0..sums.len() {
                    (sum, sums[i]) = (sum + sums[i], sum);
                }
                // disperse the sum
                evals
                    .par_chunks_exact_mut(1 << pprf_depth)
                    .zip(sums.par_iter())
                    .for_each(|(chunk, prefix_sum)| {
                        for c in chunk {
                            *c += *prefix_sum;
                        }
                    });
            });
        let v = if PCGPACK > 1 {
            let mut final_evals: Vec<[GF128; PCGPACK]> = Vec::with_capacity(n);
            unsafe {
                final_evals.set_len(n);
            }
            for i in 0..n {
                for j in 0..PCGPACK {
                    final_evals[i][j] = evals[j][i];
                }
            }
            final_evals
        } else {
            let final_evals = unsafe {
                Vec::from_raw_parts(
                    evals[0].as_mut_ptr() as *mut [GF128; PCGPACK],
                    evals[0].len(),
                    evals[0].capacity(),
                )
            };
            std::mem::forget(evals);
            final_evals
        };
        OfflineSenderPcgKey { evals: v }
    }
}

pub struct SenderPcgKey<const PCGPACK: usize>
where
    [(); (PCGPACK + 7) / 8]:,
{
    evals: Vec<[GF128; PCGPACK]>,
    code_seed: AesRng,
    code_width: usize,
    idx: usize,
    arr: [GF128; PCGPACK],
}
impl<const PCGPACK: usize> OnlineReceiverCorrelationGenerator for SenderPcgKey<PCGPACK>
where
    [(); (PCGPACK + 7) / 8]:,
{
    type Sender = ReceiverPcgKey<PCGPACK>;
    fn next_random_ot<const O: usize, const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> ([F; O], F) {
        let mut m_arr = [F::zero(); O];
        let mut c = F::zero();
        for i in 0..N {
            let (m_b, b) = self.next_correlated_ot();
            c.set_element(i, &b);
            for j in 0..O {
                m_arr[j].set_bit(m_b.get_bit(j), i);
            }
        }
        (m_arr, c)
    }
}

impl<const PCGPACK: usize> SenderPcgKey<PCGPACK>
where
    [(); (PCGPACK + 7) / 8]:,
{
    pub fn new(
        offline_key: OfflineSenderPcgKey<PCGPACK>,
        code_seed: AesRng,
        code_width: usize,
    ) -> SenderPcgKey<PCGPACK> {
        Self {
            code_seed,
            code_width,
            evals: offline_key.evals,
            idx: 0,
            arr: [GF128::zero(); PCGPACK],
        }
    }
    fn next_subfield_vole(&mut self) -> (GF128, GF2) {
        if self.idx == 0 {
            self.arr.iter_mut().for_each(|v| *v = GF128::zero());
            for _ in 0..self.code_width {
                let entry = self.evals[self.code_seed.next_u32() as usize & (self.evals.len() - 1)];
                self.arr.iter_mut().zip(entry.iter()).for_each(|(a, e)| {
                    *a += *e;
                });
            }
        }
        let ridx = self.idx;
        self.idx = (self.idx + 1) % PCGPACK;
        let bit = self.arr[ridx].get_bit(0);
        self.arr[ridx].set_bit(false, 0);
        (self.arr[ridx], GF2::from(bit))
    }
    fn next_correlated_ot(&mut self) -> (GF128, GF2) {
        self.next_subfield_vole()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "S: Serialize + DeserializeOwned, R: Serialize+DeserializeOwned")]
pub struct PackedOfflineFullPcgKey<
    S: PackedSenderCorrelationGenerator,
    R: PackedReceiverCorrelationGenerator,
> {
    sender: S,
    receiver: R,
    is_first: bool,
}

impl<S: PackedSenderCorrelationGenerator> PackedOfflineFullPcgKey<S, S::Receiver> {
    pub fn deal<D: PackedKeysDealer<S>>(
        dealer: &D,
        mut rng: impl RngCore + CryptoRng,
    ) -> (
        PackedOfflineFullPcgKey<S, S::Receiver>,
        PackedOfflineFullPcgKey<S, S::Receiver>,
    ) {
        let (first_sender, first_receiver) = dealer.deal(&mut rng);
        let (second_sender, second_receiver) = dealer.deal(&mut rng);
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

pub struct FullPcgKey<PS: PackedSenderCorrelationGenerator> {
    sender: Option<<PS::Offline as OfflineSenderCorrelationGenerator>::Online>,
    receiver: Option<<<PS::Receiver as PackedReceiverCorrelationGenerator>::Offline as OfflineReceiverCorrelationGenerator>::Online>,
    is_first: bool,
}

impl<PS: PackedSenderCorrelationGenerator> FullPcgKey<PS> {
    pub fn new_from_offline(
        offline_key: &PackedOfflineFullPcgKey<PS, PS::Receiver>,
        code_seed: [u8; 16],
        both: bool,
    ) -> Self {
        let sender = if both || offline_key.is_first {
            Some(offline_key.sender.unpack().into_online(code_seed))
        } else {
            None
        };
        let receiver = if both || !offline_key.is_first {
            Some(offline_key.receiver.unpack().into_online(code_seed))
        } else {
            None
        };

        Self {
            sender,
            receiver,
            is_first: offline_key.is_first,
        }
    }
    pub fn next_wide_beaver_triple<const N: usize, F: PackedField<GF2, N>>(
        &mut self,
    ) -> WideBeaverTriple<F> {
        let (m_b, b) = self
            .receiver
            .as_mut()
            .unwrap()
            .next_random_ot::<128, N, _>();
        let (m_0, mut m_1) = self.sender.as_mut().unwrap().next_random_ot::<128, N, _>();
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
            self.sender.as_mut().unwrap().next_bit_beaver_triple()
        } else {
            self.receiver.as_mut().unwrap().next_bit_beaver_triple()
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use rand::thread_rng;
    use tokio::join;

    use super::{PackedOfflineReceiverPcgKey, ReceiverPcgKey, SenderPcgKey};
    use crate::{
        engine::LocalRouter,
        fields::{FieldElement, PackedGF2, GF2},
        pcg::{
            FullPcgKey, OnlineReceiverCorrelationGenerator, OnlineSenderCorrelationGenerator,
            PackedKeysDealer, PackedOfflineFullPcgKey, PackedOfflineSenderPcgKey,
            PackedReceiverCorrelationGenerator, PackedSenderCorrelationGenerator, StandardDealer,
        },
        uc_tags::UCTag,
    };
    use aes_prng::AesRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_deal() {
        const PPRF_COUNT: usize = 10;
        const PPRF_DEPTH: usize = 13;
        const PCGPACK: usize = 4;
        let dealer = StandardDealer::new(PPRF_COUNT, PPRF_DEPTH);
        let (sender, receiver): (PackedOfflineReceiverPcgKey<PCGPACK>, _) =
            dealer.deal(&mut thread_rng());
        let offline_sender = sender.unpack();
        let mut offline_receiver = receiver.unpack();
        for i in 0..offline_receiver.evals.len() {
            for j in 0..offline_sender.evals[i].len() {
                let bit = offline_receiver.evals[i][j].get_bit(0);
                offline_receiver.evals[i][j].set_bit(false, 0);
                assert_eq!(
                    offline_receiver.evals[i][j] + offline_sender.evals[i][j],
                    sender.delta[j] * GF2::from(bit)
                );
            }
        }
    }
    #[test]
    fn test_deal_full() {
        const PPRF_COUNT: usize = 10;
        const PPRF_DEPTH: usize = 13;
        const PCGPACK: usize = 4;
        const CORRELATION_COUNT: usize = 100;
        let seed = [0u8; 16];
        let dealer = StandardDealer::new(PPRF_COUNT, PPRF_DEPTH);
        let (packed_full_key_1, packed_full_key_2): (
            PackedOfflineFullPcgKey<
                PackedOfflineReceiverPcgKey<PCGPACK>,
                PackedOfflineSenderPcgKey<PCGPACK>,
            >,
            _,
        ) = PackedOfflineFullPcgKey::deal(&dealer, &mut thread_rng());
        let mut full_key_2 = FullPcgKey::new_from_offline(&packed_full_key_2, seed, true);
        let mut full_key_1 = FullPcgKey::new_from_offline(&packed_full_key_1, seed, true);

        for _ in 0..CORRELATION_COUNT {
            let sender_corr = full_key_1.next_bit_beaver_triple::<{ PackedGF2::BITS }, PackedGF2>();
            let rcv_corr = full_key_2.next_bit_beaver_triple::<{ PackedGF2::BITS }, PackedGF2>();
            assert_eq!(
                (sender_corr.0 + rcv_corr.0) * (sender_corr.1 + rcv_corr.1),
                sender_corr.2 + rcv_corr.2
            );
        }

        for _ in 0..CORRELATION_COUNT {
            let sender_corr =
                full_key_1.next_wide_beaver_triple::<{ PackedGF2::BITS }, PackedGF2>();
            let rcv_corr = full_key_2.next_wide_beaver_triple::<{ PackedGF2::BITS }, PackedGF2>();
            for i in 0..sender_corr.1.len() {
                assert_eq!(
                    (sender_corr.1[i] + rcv_corr.1[i]) * (sender_corr.0 + rcv_corr.0),
                    sender_corr.2[i] + rcv_corr.2[i]
                );
            }
        }
    }
}
