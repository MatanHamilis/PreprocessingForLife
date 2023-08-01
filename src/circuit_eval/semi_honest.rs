use super::bristol_fashion;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Mul};
use std::sync::Arc;

use crate::commitment::{self, StandardCommitReveal};
use crate::zkfliop::ni::{obtain_check_value, verify_check_value, ZkFliopProof};
use crate::zkfliop::{self, PowersIterator, VerifierCtx};
use aes_prng::AesRng;
use async_trait::async_trait;
use bitvec::vec::BitVec;
use blake3::{Hasher, OUT_LEN};
use futures::future::try_join_all;
use log::info;
use rand::{CryptoRng, RngCore, SeedableRng};
use rayon::ThreadPoolBuilder;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tokio::time::Instant;

use crate::circuit_eval::bristol_fashion::ParsedGate;
use crate::engine::{MultiPartyEngine, PartyId};
use crate::fields::{FieldElement, IntermediateMulField, PackedField, PackedGF2, GF2};
use crate::pcg::{
    FullPcgKey, PackedKeysDealer, PackedOfflineFullPcgKey, PackedSenderCorrelationGenerator,
    RegularBeaverTriple, WideBeaverTriple,
};

pub trait FieldContainer<F: FieldElement>: Serialize + DeserializeOwned + Send {
    fn new_with_capacity(capacity: usize) -> Self;
    fn clear(&mut self);
    fn push(&mut self, element: RegularMask<F>);
    fn push_wide(&mut self, element: WideMask<F>);
    fn to_vec(self) -> (Vec<RegularMask<F>>, Vec<WideMask<F>>);
    fn is_empty(&self) -> bool;
}

#[derive(Serialize, Deserialize)]
pub struct GF2Container {
    v: BitVec,
    wv: BitVec,
}
impl FieldContainer<GF2> for GF2Container {
    fn is_empty(&self) -> bool {
        self.v.is_empty() && self.wv.is_empty()
    }
    fn new_with_capacity(capacity: usize) -> Self {
        Self {
            v: BitVec::with_capacity(capacity),
            wv: BitVec::with_capacity(capacity),
        }
    }
    fn clear(&mut self) {
        self.v.clear();
        self.wv.clear();
    }
    fn push(&mut self, element: RegularMask<GF2>) {
        let RegularMask(a, b) = element;
        self.v.push(a.is_one());
        self.v.push(b.is_one());
    }
    fn push_wide(&mut self, element: WideMask<GF2>) {
        let WideMask(a, wb) = element;
        self.wv.push(a.is_one());
        for i in 0..wb.len() {
            self.wv.push(wb[i].is_one());
        }
    }
    fn to_vec(self) -> (Vec<RegularMask<GF2>>, Vec<WideMask<GF2>>) {
        let regulars = self.v.len() / 2;
        let wides = self.wv.len() / 129;
        let GF2Container { v, wv } = self;
        let mut v = v.into_iter();
        let mut wv = wv.into_iter();
        let mut v_out = Vec::with_capacity(regulars);
        let mut wv_out = Vec::with_capacity(wides);
        loop {
            let a = match v.next() {
                Some(a) => GF2::from(a),
                None => {
                    break;
                }
            };
            let b = GF2::from(v.next().unwrap());
            v_out.push(RegularMask(a, b));
        }
        loop {
            let bit = match wv.next() {
                Some(a) => GF2::from(a),
                None => {
                    break;
                }
            };
            let arr = core::array::from_fn(|_| GF2::from(wv.next().unwrap()));
            wv_out.push(WideMask(bit, arr));
        }
        (v_out, wv_out)
    }
}

#[derive(Serialize, Deserialize)]
pub struct PackedGF2Container {
    v: Vec<usize>,
    wv: Vec<usize>,
}

impl FieldContainer<PackedGF2> for PackedGF2Container {
    fn is_empty(&self) -> bool {
        self.v.is_empty() && self.wv.is_empty()
    }
    fn clear(&mut self) {
        self.v.clear();
    }
    fn new_with_capacity(capacity: usize) -> Self {
        Self {
            v: Vec::with_capacity(capacity),
            wv: Vec::new(),
        }
    }
    fn push(&mut self, element: RegularMask<PackedGF2>) {
        let RegularMask(a, b) = element;
        a.bits
            .as_raw_slice()
            .into_iter()
            .copied()
            .for_each(|a| self.v.push(a));
        b.bits
            .as_raw_slice()
            .into_iter()
            .copied()
            .for_each(|b| self.v.push(b));
    }
    fn push_wide(&mut self, element: WideMask<PackedGF2>) {
        let WideMask(a, wb) = element;
        a.bits
            .as_raw_slice()
            .into_iter()
            .copied()
            .for_each(|a| self.wv.push(a));
        for i in 0..wb.len() {
            wb[i]
                .bits
                .as_raw_slice()
                .into_iter()
                .copied()
                .for_each(|b| self.wv.push(b));
        }
    }
    fn to_vec(self) -> (Vec<RegularMask<PackedGF2>>, Vec<WideMask<PackedGF2>>) {
        let regulars = self.v.len() / (2 * PackedGF2::BITS / (usize::BITS as usize));
        let wides = self.wv.len() / (129 * PackedGF2::BITS / (usize::BITS as usize));
        let Self { v, wv } = self;
        let mut v = v.into_iter();
        let mut wv = wv.into_iter();
        let mut v_out = Vec::with_capacity(regulars);
        let mut wv_out = Vec::with_capacity(wides);
        'outer: loop {
            let mut a = PackedGF2::zero();
            for part in a.bits.as_raw_mut_slice() {
                *part = match v.next() {
                    Some(a) => a,
                    None => {
                        break 'outer;
                    }
                }
            }
            let mut b = PackedGF2::zero();
            b.bits
                .as_raw_mut_slice()
                .iter_mut()
                .for_each(|part| *part = v.next().unwrap());
            v_out.push(RegularMask(a, b));
        }
        'outer_wide: loop {
            let mut a = PackedGF2::zero();
            for part in a.bits.as_raw_mut_slice() {
                *part = match wv.next() {
                    Some(a) => a,
                    None => {
                        break 'outer_wide;
                    }
                }
            }
            let wb = core::array::from_fn(|_| {
                let mut b = PackedGF2::zero();
                b.bits
                    .as_raw_mut_slice()
                    .iter_mut()
                    .for_each(|part| *part = v.next().unwrap());
                b
            });

            wv_out.push(WideMask(a, wb));
        }
        (v_out, wv_out)
    }
}
#[async_trait]
pub trait OfflineSemiHonestCorrelation<CF: FieldElement>:
    Serialize + DeserializeOwned + Send + Sync + Clone + Debug
{
    type Dealer: Sync + Send;
    fn get_personal_circuit_input_wires_masks(&self) -> &[CF];
    fn get_circuit_input_wires_masks_shares(&self, circuit: &ParsedCircuit) -> Vec<CF>;
    fn get_circuit_output_wires_masks_shares(&self, circuit: &ParsedCircuit) -> Vec<CF>;
    fn hash_correlation(&self) -> [u8; OUT_LEN];
    fn get_pairwise_triples(
        &mut self,
        circuit: &ParsedCircuit,
    ) -> (
        &Vec<(PartyId, Vec<((usize, usize), RegularBeaverTriple<CF>)>)>,
        &Vec<(PartyId, Vec<((usize, usize), WideBeaverTriple<CF>)>)>,
    );
    fn get_gates_input_wires_masks(
        &mut self,
        circuit: &ParsedCircuit,
    ) -> (
        Vec<((usize, usize), RegularMask<CF>)>,
        Vec<((usize, usize), WideMask<CF>)>,
    );
    fn deal<R: CryptoRng + RngCore + Sync + Send>(
        rng: &mut R,
        parties_input_start_and_lengths: &HashMap<PartyId, (usize, usize)>,
        circuit: &ParsedCircuit,
        dealer: &Self::Dealer,
    ) -> (Vec<CF>, Vec<CF>, Vec<(PartyId, Self)>);
    /// This method may optionally be called in a pre-online phase to same computation time in the online phase itself.
    fn pre_online_phase_preparation(&mut self, circuit: &ParsedCircuit);
    async fn verify_correlation<VF: IntermediateMulField>(
        &self,
        engine: &mut impl MultiPartyEngine,
        circuit: &ParsedCircuit,
        proof: &HashMap<PartyId, ZkFliopProof<VF>>,
        verifier_ctx: &mut Vec<VerifierCtx<VF>>,
    ) -> bool
    where
        GF2: Mul<VF, Output = VF>;
    /// This method is called in the online phase to obtain the semi honest correlation.
    async fn get_multiparty_beaver_triples(
        &mut self,
        engine: &mut impl MultiPartyEngine,
        circuit: &ParsedCircuit,
    ) -> (
        &[((usize, usize), RegularBeaverTriple<CF>)],
        &[((usize, usize), WideBeaverTriple<CF>)],
    );
    fn get_prepared_multiparty_beaver_triples(
        &self,
    ) -> (
        &[((usize, usize), RegularBeaverTriple<CF>)],
        &[((usize, usize), WideBeaverTriple<CF>)],
    );
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "PS: Serialize + DeserializeOwned")]
pub struct PcgBasedPairwiseBooleanCorrelation<
    const N: usize,
    F: PackedField<GF2, N>,
    PS: PackedSenderCorrelationGenerator + Debug,
    D: PackedKeysDealer<PS>,
> {
    #[serde(bound = "")]
    pub input_wires_masks: Vec<F>,
    pub shares_seed: [u8; 16],
    pub pcg_keys: Vec<(
        PartyId,
        (PackedOfflineFullPcgKey<PS, PS::Receiver>, [u8; 16]),
    )>,
    #[serde(bound = "", skip)]
    pub regular_expanded_pcg_keys:
        Option<Vec<(PartyId, Vec<((usize, usize), RegularBeaverTriple<F>)>)>>,
    #[serde(bound = "", skip)]
    pub wide_expanded_pcg_keys: Option<Vec<(PartyId, Vec<((usize, usize), WideBeaverTriple<F>)>)>>,
    #[serde(bound = "", skip)]
    pub multi_party_correlations: Option<(
        Vec<((usize, usize), RegularBeaverTriple<F>)>,
        Vec<((usize, usize), WideBeaverTriple<F>)>,
    )>,
    #[serde(bound = "", skip)]
    _d: PhantomData<D>,
}

pub fn construct_statement_from_bts<const N: usize, PF: PackedField<GF2, N>, VF: FieldElement>(
    regular_bts: &[((usize, usize), RegularBeaverTriple<PF>)],
    wide_bts: &[((usize, usize), WideBeaverTriple<PF>)],
    powers: &mut PowersIterator<VF>,
) -> Vec<VF>
where
    GF2: Mul<VF, Output = VF>,
{
    let len = 1 + 2 * N * (regular_bts.len() + wide_bts.len() * 128);
    const MINIMAL_STATEMENT_SIZE: usize = 5;
    let len = if len < MINIMAL_STATEMENT_SIZE {
        MINIMAL_STATEMENT_SIZE
    } else {
        1 + (len - 1).next_power_of_two()
    };
    let mut v = Vec::with_capacity(len);
    v.push(VF::zero());
    let mut sum = VF::zero();
    for (_, bt) in regular_bts {
        for i in 0..N {
            let pow = powers.next().unwrap();
            let zero = bt.0.get_element(i) * pow;
            let one = bt.1.get_element(i) * VF::one();
            sum += bt.2.get_element(i) * pow;
            v.push(zero);
            v.push(one);
        }
    }
    for (_, wbt) in wide_bts {
        for i in 0..N {
            let mut zero = VF::zero();
            let mut one = VF::zero();
            for j in 0..128 {
                let pow = powers.next().unwrap();
                zero += pow;
                one += wbt.1[j].get_element(i) * pow;
                sum += wbt.2[j].get_element(i) * pow;
            }
            zero = wbt.0.get_element(i) * zero;
            v.push(zero);
            v.push(one);
        }
    }
    while v.len() < len {
        v.push(VF::zero());
    }
    assert_eq!(len, v.len());
    v[0] = sum;
    v
}
#[async_trait]
impl<
        const N: usize,
        F: PackedField<GF2, N>,
        PS: PackedSenderCorrelationGenerator,
        D: PackedKeysDealer<PS>,
    > OfflineSemiHonestCorrelation<F> for PcgBasedPairwiseBooleanCorrelation<N, F, PS, D>
{
    type Dealer = D;
    fn get_personal_circuit_input_wires_masks(&self) -> &[F] {
        &self.input_wires_masks
    }
    fn get_circuit_input_wires_masks_shares(&self, circuit: &ParsedCircuit) -> Vec<F> {
        input_wires_masks_from_seed(self.shares_seed, circuit)
    }
    fn hash_correlation(&self) -> [u8; OUT_LEN] {
        let mut hasher = Hasher::new();
        for (_, k) in self.pcg_keys.iter() {
            let s = bincode::serialize(k).unwrap();
            hasher.update(&s);
        }
        *hasher.finalize().as_bytes()
    }
    fn get_pairwise_triples(
        &mut self,
        circuit: &ParsedCircuit,
    ) -> (
        &Vec<(PartyId, Vec<((usize, usize), RegularBeaverTriple<F>)>)>,
        &Vec<(PartyId, Vec<((usize, usize), WideBeaverTriple<F>)>)>,
    ) {
        if self.regular_expanded_pcg_keys.is_none() {
            self.pre_online_phase_preparation(circuit);
        }
        (
            self.regular_expanded_pcg_keys.as_ref().unwrap(),
            self.wide_expanded_pcg_keys.as_ref().unwrap(),
        )
        // let (reg_bts, wide_bts) =
        //     expand_pairwise_beaver_triples::<N, F, _>(circuit, &self.pcg_keys);
        // let reg_bts: HashMap<_, _> = reg_bts.into_iter().collect();
        // let wide_bts: HashMap<_, _> = wide_bts.into_iter().collect();
        // (reg_bts, wide_bts)
    }
    fn pre_online_phase_preparation(&mut self, circuit: &ParsedCircuit) {
        let (m, wm) = expand_pairwise_beaver_triples::<N, F, PS>(circuit, &self.pcg_keys);
        self.regular_expanded_pcg_keys = Some(m);
        self.wide_expanded_pcg_keys = Some(wm);
    }

    async fn verify_correlation<VF: IntermediateMulField>(
        &self,
        engine: &mut impl MultiPartyEngine,
        circuit: &ParsedCircuit,
        proof: &HashMap<PartyId, ZkFliopProof<VF>>,
        verifier_ctx: &mut Vec<VerifierCtx<VF>>,
    ) -> bool
    where
        GF2: Mul<VF, Output = VF>,
    {
        let my_pid = engine.my_party_id();
        let (regular_bts, wide_bts) =
            expand_pairwise_beaver_triples::<N, F, _>(circuit, &self.pcg_keys);
        let hash_correlation = self.hash_correlation();
        let hash_correlation: [u8; 16] = core::array::from_fn(|i| hash_correlation[i]);
        let mut rng = AesRng::from_seed(hash_correlation);
        let my_random_share = VF::random(&mut rng);
        let v =
            StandardCommitReveal::commit(engine.sub_protocol(&"COMMIT_REVEAL"), my_random_share)
                .await
                .reveal()
                .await;
        let coin: VF = v.values().copied().sum::<VF>() + my_random_share;
        let handles: Vec<_> = regular_bts
            .into_iter()
            .zip(wide_bts.into_iter())
            .zip(verifier_ctx.drain(..))
            .map(|(((pid, bts), (wpid, wbts)), mut verifier_ctx)| {
                assert_eq!(pid, wpid);
                let pids = if pid > my_pid {
                    vec![my_pid, pid]
                } else {
                    vec![pid, my_pid]
                };
                let min_pid = pids[0];
                let max_pid = pids[1];
                let pids: Arc<Box<[PartyId]>> = Arc::new(pids.into());
                let engine = engine
                    .sub_protocol_with(format!("verify_triples_{}_{}", min_pid, max_pid), pids);
                let proof = proof.get(&pid).unwrap();
                let coin = coin.clone();
                async move {
                    let mut powers = PowersIterator::new(coin);
                    let statement_share = construct_statement_from_bts(&bts, &wbts, &mut powers);
                    let (flag, check_vals) =
                        obtain_check_value(statement_share, proof, &mut verifier_ctx);
                    let output = verify_check_value(engine, flag, check_vals).await;
                    Result::<(bool, VerifierCtx<VF>), ()>::Ok((output, verifier_ctx))
                }
            })
            .collect();
        try_join_all(handles).await.unwrap().into_iter().all(|v| {
            verifier_ctx.push(v.1);
            v.0
        })
    }
    // Only called by the dealer anyway.
    fn get_gates_input_wires_masks(
        &mut self,
        circuit: &ParsedCircuit,
    ) -> (
        Vec<((usize, usize), RegularMask<F>)>,
        Vec<((usize, usize), WideMask<F>)>,
    ) {
        if self.regular_expanded_pcg_keys.is_none() {
            self.pre_online_phase_preparation(circuit);
        }
        let (m, wm) = (
            self.regular_expanded_pcg_keys.as_ref().unwrap(),
            self.wide_expanded_pcg_keys.as_ref().unwrap(),
        );
        // let (m, wm) = expand_pairwise_beaver_triples::<N, F, PS>(circuit, &self.pcg_keys);
        // If there are only two parties...
        if self.pcg_keys.len() == 1 {
            let mut regular = Vec::<((usize, usize), RegularMask<F>)>::new();
            let mut wide = Vec::<((usize, usize), WideMask<F>)>::new();
            m[0].1.iter().for_each(|(g, bts)| {
                regular.push((*g, RegularMask(bts.0, bts.1)));
            });
            wm[0].1.iter().for_each(|(g, bts)| {
                wide.push((*g, WideMask(bts.0, bts.1)));
            });
            return (regular, wide);
        }
        gate_masks_from_seed(circuit, self.shares_seed)
    }
    fn get_prepared_multiparty_beaver_triples(
        &self,
    ) -> (
        &[((usize, usize), RegularBeaverTriple<F>)],
        &[((usize, usize), WideBeaverTriple<F>)],
    ) {
        // If the preparation has not been done earlier, do it now.
        if self.regular_expanded_pcg_keys.is_none() {
            panic!();
            // self.pre_online_phase_preparation(circuit);
        }
        let pairwise_triples = self.regular_expanded_pcg_keys.as_ref().unwrap();
        let wide_pairwise_triples = self.wide_expanded_pcg_keys.as_ref().unwrap();

        // If only two parties - expansion is silent.
        if pairwise_triples.len() == 1 {
            let regular_output = &pairwise_triples[0].1;
            let wide_output = &wide_pairwise_triples[0].1;
            // let regular_output = pairwise_triples[0].1.iter().copied().collect();
            // let wide_output = wide_pairwise_triples[0].1.iter().copied().collect();
            return (regular_output, wide_output);
        }
        if self.multi_party_correlations.is_none() {
            panic!();
        }

        let v = self.multi_party_correlations.as_ref().unwrap();
        (&v.0, &v.1)
    }
    async fn get_multiparty_beaver_triples(
        &mut self,
        engine: &mut impl MultiPartyEngine,
        circuit: &ParsedCircuit,
    ) -> (
        &[((usize, usize), RegularBeaverTriple<F>)],
        &[((usize, usize), WideBeaverTriple<F>)],
    ) {
        // If the preparation has not been done earlier, do it now.
        if self.regular_expanded_pcg_keys.is_none() {
            self.pre_online_phase_preparation(circuit);
        }
        let pairwise_triples = self.regular_expanded_pcg_keys.as_ref().unwrap();
        let wide_pairwise_triples = self.wide_expanded_pcg_keys.as_ref().unwrap();

        // If only two parties - expansion is silent.
        if engine.party_ids().len() == 2 {
            let regular_output = &pairwise_triples[0].1;
            let wide_output = &wide_pairwise_triples[0].1;
            // let regular_output = pairwise_triples[0].1.iter().copied().collect();
            // let wide_output = wide_pairwise_triples[0].1.iter().copied().collect();
            return (regular_output, wide_output);
        }
        if self.multi_party_correlations.is_none() {
            let (gate_input_masks, wide_gate_input_masks) =
                gate_masks_from_seed(circuit, self.shares_seed);
            self.multi_party_correlations = Some(
                create_multi_party_beaver_triples(
                    engine,
                    circuit,
                    &pairwise_triples,
                    &wide_pairwise_triples,
                    &gate_input_masks,
                    &wide_gate_input_masks,
                )
                .await,
            );
        }

        // Otherwise, we have to communicate.
        let v = self.multi_party_correlations.as_ref().unwrap();
        (&v.0, &v.1)
    }
    fn get_circuit_output_wires_masks_shares(&self, circuit: &ParsedCircuit) -> Vec<F> {
        output_wires_masks_from_seed(self.shares_seed, circuit)
    }
    fn deal<R: CryptoRng + RngCore + Send + Sync>(
        mut rng: &mut R,
        parties_input_start_and_lengths: &HashMap<PartyId, (usize, usize)>,
        circuit: &ParsedCircuit,
        dealer: &Self::Dealer,
    ) -> (Vec<F>, Vec<F>, Vec<(PartyId, Self)>) {
        let parties_count = parties_input_start_and_lengths.len();
        let mut pcg_keys = HashMap::with_capacity(parties_count);
        for (i, i_pid) in parties_input_start_and_lengths.keys().copied().enumerate() {
            pcg_keys.insert(i_pid, Vec::with_capacity(parties_count - 1));
            for j_pid in parties_input_start_and_lengths.keys().copied().take(i) {
                let mut pcg_code_seed = [0u8; 16];
                rng.fill_bytes(&mut pcg_code_seed);
                let (snd, rcv) = PackedOfflineFullPcgKey::deal(dealer, &mut rng);
                pcg_keys
                    .get_mut(&j_pid)
                    .unwrap()
                    .push((i_pid, (snd, pcg_code_seed)));
                pcg_keys
                    .get_mut(&i_pid)
                    .unwrap()
                    .push((j_pid, (rcv, pcg_code_seed)));
            }
        }
        let mut total_input_wires_masks = vec![F::zero(); circuit.input_wire_count];
        let mut total_output_wires_masks = vec![F::zero(); circuit.output_wire_count];
        let mut mask_seeds: HashMap<_, _> = parties_input_start_and_lengths
            .keys()
            .copied()
            .map(|p| {
                let mut seed = [0u8; 16];
                rng.fill_bytes(&mut seed);
                let input_wires_masks: Vec<F> = input_wires_masks_from_seed(seed, circuit);
                total_input_wires_masks
                    .iter_mut()
                    .zip(input_wires_masks.iter())
                    .for_each(|(d, s)| *d += *s);
                let output_wires_masks: Vec<F> = output_wires_masks_from_seed(seed, circuit);
                total_output_wires_masks
                    .iter_mut()
                    .zip(output_wires_masks.iter())
                    .for_each(|(d, s)| *d += *s);
                (p, seed)
            })
            .collect();
        let offline_correlations: Vec<_> = parties_input_start_and_lengths
            .iter()
            .map(|(pid, (input_start, input_len))| {
                let pcg_key = pcg_keys.remove(pid).unwrap();
                let seed = mask_seeds.remove(pid).unwrap();
                let input_wires_masks =
                    total_input_wires_masks[*input_start..*input_start + *input_len].to_vec();
                (
                    *pid,
                    Self {
                        regular_expanded_pcg_keys: None,
                        wide_expanded_pcg_keys: None,
                        multi_party_correlations: None,
                        shares_seed: seed,
                        pcg_keys: pcg_key,
                        input_wires_masks,
                        _d: PhantomData,
                    },
                )
            })
            .collect();
        (
            total_input_wires_masks,
            total_output_wires_masks,
            offline_correlations,
        )
    }
}

use self::bristol_fashion::ParsedCircuit;

#[derive(Serialize, Deserialize)]
struct RegularEvalMessage<F: FieldElement> {
    #[serde(bound = "")]
    pub opening: RegularMask<F>,
    pub gate_idx_in_layer: usize,
}
#[derive(Serialize, Deserialize)]
struct WideEvalMessage<F: FieldElement> {
    #[serde(bound = "")]
    pub opening: WideMask<F>,
    pub gate_idx_in_layer: usize,
}

#[derive(Debug)]
pub enum CircuitEvalError {
    CommunicatorError,
}

#[derive(Serialize, Deserialize)]
pub struct RegularPairwiseBeaverTriple<F: FieldElement>(
    #[serde(bound = "")] Vec<(PartyId, RegularBeaverTriple<F>)>,
);
#[derive(Serialize, Deserialize)]
pub struct WidePairwiseBeaverTriple<F: FieldElement>(
    #[serde(bound = "")] Vec<(PartyId, WideBeaverTriple<F>)>,
);
pub fn expand_pairwise_beaver_triples<
    const N: usize,
    F: PackedField<GF2, N>,
    PS: PackedSenderCorrelationGenerator,
>(
    circuit: &ParsedCircuit,
    pcg_keys: &[(
        PartyId,
        (PackedOfflineFullPcgKey<PS, PS::Receiver>, [u8; 16]),
    )],
) -> (
    Vec<(PartyId, Vec<((usize, usize), RegularBeaverTriple<F>)>)>,
    Vec<(PartyId, Vec<((usize, usize), WideBeaverTriple<F>)>)>,
) {
    ThreadPoolBuilder::new().build().unwrap().install(|| {
        info!(
            "Entered threadpool, threads: {}",
            rayon::current_num_threads()
        );
        // Check if circuit has Wide-ANDs, otherwise expand only one of the PCGs.
        let mut wand_count: usize = 0;
        let mut and_count: usize = 0;
        circuit.gates.iter().for_each(|layer| {
            layer.iter().for_each(|gate| match gate {
                ParsedGate::WideAndGate {
                    input: _,
                    input_bit: _,
                    output: _,
                } => wand_count += 1,
                ParsedGate::AndGate {
                    input: _,
                    output: _,
                } => and_count += 1,
                _ => {}
            })
        });
        let has_wand = wand_count > 0;
        let time = Instant::now();
        let mut pcg_keys: Vec<_> = pcg_keys
            .iter()
            .map(|(pid, (pk, code))| (*pid, FullPcgKey::new_from_offline(pk, *code, has_wand)))
            .collect();
        info!("PCG Offline took: {}ms", time.elapsed().as_millis());
        let time = Instant::now();
        let regular_beaver_triples: Vec<(PartyId, Vec<((usize, usize), RegularBeaverTriple<F>)>)> =
            pcg_keys
                .iter_mut()
                .map(|(id, key)| {
                    let time = Instant::now();
                    let o = (
                        *id,
                        circuit
                            .iter()
                            .filter(|g| match g.2 {
                                ParsedGate::AndGate {
                                    input: _,
                                    output: _,
                                } => true,
                                _ => false,
                            })
                            .map(|g| ((g.0, g.1), key.next_bit_beaver_triple()))
                            .collect(),
                    );
                    info!("Bit PCG for party took: {}ms", time.elapsed().as_millis());
                    o
                })
                .collect();
        let wide_beaver_triples: Vec<(PartyId, Vec<((usize, usize), WideBeaverTriple<F>)>)> =
            pcg_keys
                .iter_mut()
                .map(|(id, key)| {
                    (
                        *id,
                        circuit
                            .iter()
                            .filter(|g| match g.2 {
                                ParsedGate::WideAndGate {
                                    input: _,
                                    input_bit: _,
                                    output: _,
                                } => true,
                                _ => false,
                            })
                            .map(|g| ((g.0, g.1), key.next_wide_beaver_triple()))
                            .collect(),
                    )
                })
                .collect();
        info!("online PCG took: {}ms", time.elapsed().as_millis());
        (regular_beaver_triples, wide_beaver_triples)
    })
}

pub fn derive_key_from_seed<const ID: usize>(seed: [u8; 16]) -> [u8; 16] {
    let mut aes_rng = AesRng::from_seed(seed);
    let mut array = [0u8; 16];
    for _ in 0..ID + 1 {
        aes_rng.fill_bytes(&mut array);
    }
    array
}
pub fn input_wires_masks_from_seed<F: FieldElement>(
    seed: [u8; 16],
    circuit: &ParsedCircuit,
) -> Vec<F> {
    const INPUT_WIRES_SEED_ID: usize = 0;
    let mut rng = AesRng::from_seed(derive_key_from_seed::<INPUT_WIRES_SEED_ID>(seed));
    let mut input_wires_masks: Vec<_> = Vec::with_capacity(circuit.input_wire_count);
    for _ in 0..circuit.input_wire_count {
        input_wires_masks.push(F::random(&mut rng));
    }
    input_wires_masks
}
pub fn output_wires_masks_from_seed<F: FieldElement>(
    seed: [u8; 16],
    circuit: &ParsedCircuit,
) -> Vec<F> {
    const OUTPUT_WIRES_SEED_ID: usize = 1;
    let mut rng = AesRng::from_seed(derive_key_from_seed::<OUTPUT_WIRES_SEED_ID>(seed));
    let mut output_wire_masks = Vec::with_capacity(circuit.output_wire_count);
    for _ in 0..circuit.output_wire_count {
        output_wire_masks.push(F::random(&mut rng));
    }
    output_wire_masks
}
pub fn gate_masks_from_seed<F: FieldElement>(
    circuit: &ParsedCircuit,
    seed: [u8; 16],
) -> (
    Vec<((usize, usize), RegularMask<F>)>,
    Vec<((usize, usize), WideMask<F>)>,
) {
    const GATE_INPUT_WIRES_SEED_ID: usize = 2;
    let total_gates: usize = circuit.total_non_linear_gates();
    let mut rng = AesRng::from_seed(derive_key_from_seed::<GATE_INPUT_WIRES_SEED_ID>(seed));
    let mut gate_input_masks = Vec::with_capacity(total_gates);
    let mut wide_gate_input_masks = Vec::new();
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        for (gate_idx, gate) in layer.iter().enumerate() {
            match gate {
                ParsedGate::AndGate {
                    input: _,
                    output: _,
                } => gate_input_masks.push((
                    (layer_idx, gate_idx),
                    RegularMask(F::random(&mut rng), F::random(&mut rng)),
                )),
                ParsedGate::WideAndGate {
                    input: _,
                    input_bit: _,
                    output: _,
                } => wide_gate_input_masks.push((
                    (layer_idx, gate_idx),
                    WideMask(
                        F::random(&mut rng),
                        core::array::from_fn(|_| F::random(&mut rng)),
                    ),
                )),
                _ => continue,
            };
        }
    }
    (gate_input_masks, wide_gate_input_masks)
}
pub async fn create_multi_party_beaver_triples<F: FieldElement>(
    engine: &mut impl MultiPartyEngine,
    circuit: &ParsedCircuit,
    pairwise_triples: &[(PartyId, Vec<((usize, usize), RegularBeaverTriple<F>)>)],
    wide_pairwise_triples: &[(PartyId, Vec<((usize, usize), WideBeaverTriple<F>)>)],
    gate_input_masks: &[((usize, usize), RegularMask<F>)],
    wide_gate_input_masks: &[((usize, usize), WideMask<F>)],
) -> (
    Vec<((usize, usize), RegularBeaverTriple<F>)>,
    Vec<((usize, usize), WideBeaverTriple<F>)>,
) {
    let mut n_wise_beaver_triples: Vec<_> = gate_input_masks
        .iter()
        .map(|(g, m)| (*g, RegularBeaverTriple(m.0, m.1, m.0 * m.1)))
        .collect();
    let mut n_wise_wide_beaver_triples: Vec<_> = wide_gate_input_masks
        .iter()
        .map(|(g, m)| {
            (
                *g,
                WideBeaverTriple(m.0, m.1, core::array::from_fn(|i| m.0 * m.1[i])),
            )
        })
        .collect();
    pairwise_triples.iter().for_each(|(pid, triples)| {
        let mut v = Vec::with_capacity(triples.len());
        triples
            .iter()
            .zip(gate_input_masks.iter())
            .zip(n_wise_beaver_triples.iter_mut())
            .for_each(|((triple, mask), t)| {
                assert_eq!(triple.0, mask.0);
                let gate = circuit.gates[triple.0 .0][triple.0 .1];
                match (gate, mask.1, triple.1) {
                    (
                        ParsedGate::AndGate {
                            input: _,
                            output: _,
                        },
                        RegularMask(x, y),
                        RegularBeaverTriple(a, b, c),
                    ) => {
                        v.push((mask.0 .0, mask.0 .1, RegularMask(x - a, y - b)));
                        let z = c - b * a;
                        t.1 .2 += z;
                    }
                    _ => panic!(),
                }
            });
        engine.send(v, *pid);
    });
    for (p, triples) in pairwise_triples {
        let v_p: Vec<(usize, usize, RegularMask<F>)> = engine.recv_from(*p).await.unwrap();
        assert_eq!(v_p.len(), triples.len());
        for ((t, m), bt) in triples
            .iter()
            .zip(v_p.into_iter())
            .zip(n_wise_beaver_triples.iter_mut())
        {
            assert_eq!(t.0, (m.0, m.1));
            // let bt = n_wise_beaver_triples.get_mut(&t.0).unwrap();
            bt.1 .2 += m.2 .0 * bt.1 .1 + m.2 .1 * t.1 .0;
        }
    }
    wide_pairwise_triples.iter().for_each(|(pid, triples)| {
        let mut v = Vec::with_capacity(triples.len());
        triples
            .iter()
            .zip(wide_gate_input_masks.iter())
            .zip(n_wise_wide_beaver_triples.iter_mut())
            .for_each(|((triple, mask), t)| {
                assert_eq!(triple.0, mask.0);
                let gate = circuit.gates[triple.0 .0][triple.0 .1];
                match (gate, mask.1, triple.1) {
                    (
                        ParsedGate::WideAndGate {
                            input: _,
                            input_bit: _,
                            output: _,
                        },
                        WideMask(x, wy),
                        WideBeaverTriple(a, wb, wc),
                    ) => {
                        v.push((
                            mask.0 .0,
                            mask.0 .1,
                            WideMask(x - a, core::array::from_fn(|i| wy[i] - wb[i])),
                        ));
                        // let t = n_wise_wide_beaver_triples.get_mut(&triple.0).unwrap();
                        t.1 .2
                            .iter_mut()
                            .enumerate()
                            .for_each(|(i, ti)| *ti += wc[i] - wb[i] * a);
                    }
                    _ => panic!(),
                }
            });
        engine.send(v, *pid);
    });
    for (p, triples) in wide_pairwise_triples {
        let v_p: Vec<(usize, usize, WideMask<F>)> = engine.recv_from(*p).await.unwrap();
        for ((t, m), bt) in triples
            .iter()
            .zip(v_p.into_iter())
            .zip(n_wise_wide_beaver_triples.iter_mut())
        {
            assert_eq!(t.0, (m.0, m.1));
            // let bt = n_wise_wide_beaver_triples.get_mut(&t.0).unwrap();
            for i in 0..bt.1 .2.len() {
                bt.1 .2[i] += m.2 .0 * bt.1 .1[i] + m.2 .1[i] * t.1 .0;
            }
        }
    }
    (n_wise_beaver_triples, n_wise_wide_beaver_triples)
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct RegularMask<F: FieldElement>(#[serde(bound = "")] pub F, #[serde(bound = "")] pub F);
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct WideMask<F: FieldElement>(
    #[serde(bound = "")] pub F,
    #[serde(with = "BigArray")]
    #[serde(bound = "")]
    pub [F; 128],
);
impl<F: FieldElement> AddAssign for RegularMask<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
        self.1 += rhs.1;
    }
}
impl<F: FieldElement> AddAssign for WideMask<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
        for i in 0..self.1.len() {
            self.1[i] += rhs.1[i];
        }
    }
}
impl<F: FieldElement> Add for RegularMask<F> {
    type Output = RegularMask<F>;
    fn add(self, rhs: Self) -> Self::Output {
        let mut m = self.clone();
        m += rhs;
        m
    }
}
impl<F: FieldElement> Add for WideMask<F> {
    type Output = WideMask<F>;
    fn add(self, rhs: Self) -> Self::Output {
        let mut m = self.clone();
        m += rhs;
        m
    }
}

pub async fn obtain_masked_and_shared_input<F: FieldElement>(
    engine: &mut impl MultiPartyEngine,
    parties_input_pos_and_length: &HashMap<PartyId, (usize, usize)>,
    my_input: &[F],
    my_input_mask: &[F],
    input_mask_shares: &mut [F],
    circuit: &ParsedCircuit,
) -> Vec<F> {
    let my_id = engine.my_party_id();
    let my_masked_input: Vec<_> = my_input
        .iter()
        .zip(my_input_mask.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    engine.broadcast(&my_masked_input);
    let mut masked_input = vec![F::zero(); circuit.input_wire_count];
    let (my_input_start, my_input_length) = parties_input_pos_and_length.get(&my_id).unwrap();
    for i in 0..*my_input_length {
        masked_input[my_input_start + i] = my_masked_input[i];
        input_mask_shares[my_input_start + i] += my_masked_input[i];
    }
    for _ in 0..parties_input_pos_and_length.len() - 1 {
        let (v, p): (Vec<_>, _) = engine.recv().await.unwrap();
        let (input_start, input_length) = parties_input_pos_and_length.get(&p).unwrap().clone();
        masked_input[input_start..input_start + input_length].copy_from_slice(&v);
    }
    masked_input
}

// We assume the input to the circuit is already additively shared between the parties.
pub async fn multi_party_semi_honest_eval_circuit<
    const N: usize,
    E: MultiPartyEngine,
    PF: FieldElement,
    F: PackedField<PF, N>,
    FC: FieldContainer<F>,
>(
    engine: &mut E,
    circuit: &ParsedCircuit,
    my_input: &[F],
    my_input_mask: &[F],
    mut input_mask_shares: Vec<F>,
    multi_party_beaver_triples: &[((usize, usize), RegularBeaverTriple<F>)],
    wide_multi_party_beaver_triples: &[((usize, usize), WideBeaverTriple<F>)],
    output_wire_masks: &Vec<F>,
    parties_input_pos_and_length: &HashMap<PartyId, (usize, usize)>,
) -> Result<
    (
        Vec<F>,
        Vec<((usize, usize), RegularMask<F>)>,
        Vec<((usize, usize), WideMask<F>)>,
        Vec<F>,
    ),
    CircuitEvalError,
> {
    let my_id = engine.my_party_id();
    let min_id = engine
        .party_ids()
        .iter()
        .fold(PartyId::MAX, |a, b| PartyId::min(a, *b));
    let is_first = my_id == min_id;
    let number_of_peers = engine.party_ids().len() - 1;
    let wires_num =
        circuit.input_wire_count + circuit.internal_wire_count + circuit.output_wire_count;
    let mut wires = vec![F::zero(); wires_num];

    let time = Instant::now();
    info!("Starting obtain masked and shared input");
    let masked_input = obtain_masked_and_shared_input(
        engine,
        parties_input_pos_and_length,
        my_input,
        my_input_mask,
        &mut input_mask_shares,
        circuit,
    )
    .await;
    info!(
        "\t\tSemi Honest - obtain masked and shared input: {}ms",
        time.elapsed().as_millis()
    );
    let pre_shared_input = input_mask_shares;
    wires[0..circuit.input_wire_count].copy_from_slice(&pre_shared_input);
    let time = Instant::now();
    let total_non_linear_gates: usize = circuit
        .gates
        .iter()
        .map(|layer| layer.iter().filter(|g| !g.is_linear()).count())
        .sum();
    info!(
        "\t\tSemi Honest - count non linear gates: {}ms",
        time.elapsed().as_millis()
    );
    let mut masked_output_wires = Vec::<F>::with_capacity(circuit.output_wire_count);
    let mut masked_gate_inputs = Vec::<((usize, usize), RegularMask<F>)>::with_capacity(
        total_non_linear_gates + circuit.output_wire_count,
    );
    let mut wide_masked_gate_inputs = Vec::<((usize, usize), WideMask<F>)>::new();
    let max_layer_size = circuit.gates.iter().fold(0, |acc, cur| {
        let non_linear_gates_in_layer = cur.iter().filter(|cur| !cur.is_linear()).count();
        usize::max(acc, non_linear_gates_in_layer)
    });
    let mut msg_vec = FC::new_with_capacity(max_layer_size);
    let mut bts = multi_party_beaver_triples.iter();
    let mut wide_bts = wide_multi_party_beaver_triples.iter();
    for (layer_idx, layer) in circuit.gates.iter().enumerate() {
        let mut open_bts = bts.clone();
        let mut open_wide_bts = wide_bts.clone();
        let current_masked_gate_inputs_len = masked_gate_inputs.len();
        let wide_current_masked_gate_inputs_len = wide_masked_gate_inputs.len();
        for (gate_idx, gate) in layer.iter().enumerate() {
            match &gate {
                ParsedGate::NotGate { input, output } => {
                    wires[*output] = wires[*input];
                    if is_first {
                        wires[*output] += F::one();
                    }
                }
                ParsedGate::XorGate { input, output } => {
                    wires[*output] = wires[input[0]] + wires[input[1]];
                }
                ParsedGate::AndGate { input, output } => {
                    let &RegularBeaverTriple(a, b, c) = &bts.next().unwrap().1;
                    // let &RegularBeaverTriple(a, b, c) = multi_party_beaver_triples
                    //     .get(&(layer_idx, gate_idx))
                    //     .unwrap();

                    let (x, y) = (wires[input[0]], wires[input[1]]);
                    wires[*output] = c + y * (x - a) + (y - b) * a;

                    let mask = RegularMask(x - a, y - b);
                    msg_vec.push(mask);
                    masked_gate_inputs.push(((layer_idx, gate_idx), mask));
                }
                ParsedGate::WideAndGate {
                    input,
                    input_bit,
                    output,
                } => {
                    let &WideBeaverTriple(a, wb, wc) = &wide_bts.next().unwrap().1;
                    // let &WideBeaverTriple(a, wb, wc) = wide_multi_party_beaver_triples
                    //     .get(&(layer_idx, gate_idx))
                    //     .unwrap();
                    let x = wires[*input_bit];
                    let mut wy = [F::zero(); 128];
                    for i in 0..input.len() {
                        let input_wire = wires[input[i]];
                        wy[i] = input_wire.into();
                    }
                    for (idx, output_wire) in output.iter().enumerate() {
                        wires[*output_wire] = wc[idx] + wy[idx] * x - wb[idx] * a;
                    }
                    let masked_inputs = core::array::from_fn(|i| wy[i] - wb[i]);
                    // let msg = EvalMessage {
                    //     opening: Mask::WideAnd(x - a, masked_inputs),
                    //     gate_idx_in_layer: gate_idx,
                    // };
                    // engine.broadcast(msg);
                    let mask = WideMask(x - a, masked_inputs);
                    msg_vec.push_wide(mask);
                    wide_masked_gate_inputs.push(((layer_idx, gate_idx), mask));
                }
            }
        }
        if !msg_vec.is_empty() {
            engine.broadcast(&msg_vec);
            msg_vec.clear();
            for _ in 0..number_of_peers {
                let mut open_bts_peer = open_bts.clone();
                let mut wide_open_bts_peer = open_wide_bts.clone();
                let mut masked_gates_inputs_layer_iter = masked_gate_inputs
                    .iter_mut()
                    .skip(current_masked_gate_inputs_len);
                let mut wide_masked_gates_inputs_layer_iter = wide_masked_gate_inputs
                    .iter_mut()
                    .skip(wide_current_masked_gate_inputs_len);
                let (recv_vec, _): (FC, PartyId) = engine.recv().await.unwrap();
                // let (msg, _): (EvalMessage<F>, PartyId) = engine.recv().await.unwrap();
                let (gate_masks, wide_gate_masks) = recv_vec.to_vec();
                let mut gate_masks = gate_masks.into_iter();
                let mut wide_gate_masks = wide_gate_masks.into_iter();
                for (gate_idx, _) in layer.iter().enumerate().filter(|(_, g)| !g.is_linear()) {
                    let gate = layer[gate_idx];
                    match gate {
                        ParsedGate::AndGate {
                            input: input_wires,
                            output: output_wire,
                        } => {
                            let RegularMask(ax, by) = gate_masks.next().unwrap();
                            let RegularMask(mask_a, mask_b) =
                                &mut masked_gates_inputs_layer_iter.next().unwrap().1;
                            // .get_mut(&(layer_idx, gate_idx)).unwrap();
                            let &RegularBeaverTriple(a, _, _) = &open_bts_peer.next().unwrap().1;
                            // let &RegularBeaverTriple(a, _, _) = multi_party_beaver_triples
                            //     .get(&(layer_idx, gate_idx))
                            //     .unwrap();
                            let y = wires[input_wires[1]];
                            wires[output_wire] += y * ax + by * a;
                            *mask_a += ax;
                            *mask_b += by;
                        }

                        ParsedGate::WideAndGate {
                            input,
                            input_bit: _,
                            output,
                        } => {
                            let WideMask(ax, wby) = wide_gate_masks.next().unwrap();
                            let WideMask(mask_a, mask_wb) =
                                &mut wide_masked_gates_inputs_layer_iter.next().unwrap().1;
                            // wide_masked_gate_inputs
                            //     .get_mut(&(layer_idx, gate_idx))
                            //     .unwrap();
                            let &WideBeaverTriple(a, _, _) = &wide_open_bts_peer.next().unwrap().1;
                            // let &WideBeaverTriple(a, _, _) = wide_multi_party_beaver_triples
                            //     .get(&(layer_idx, gate_idx))
                            //     .unwrap();
                            for i in 0..wby.len() {
                                mask_wb[i] += wby[i];
                            }
                            *mask_a += ax;
                            for i in 0..output.len() {
                                let y = wires[input[i]];
                                wires[output[i]] += y * ax + wby[i] * a;
                            }
                        }
                        _ => panic!(),
                    }
                }
            }
        }
    }
    // Create a robust secret sharing of the output wires.
    for (_, (wire, mask)) in wires
        .iter()
        .skip(wires.len() - circuit.output_wire_count)
        .zip(output_wire_masks)
        .enumerate()
    {
        masked_output_wires.push(*wire - *mask);
    }
    engine.broadcast(&masked_output_wires);

    for _ in 0..number_of_peers {
        let (v, _): (Vec<F>, _) = engine.recv().await.unwrap();
        masked_output_wires
            .iter_mut()
            .zip(v.into_iter())
            .for_each(|(d, s)| *d += s);
    }

    Ok((
        masked_input,
        masked_gate_inputs,
        wide_masked_gate_inputs,
        masked_output_wires,
    ))
}

pub fn local_eval_circuit<F: FieldElement>(circuit: &ParsedCircuit, input: &[F]) -> Vec<F> {
    debug_assert_eq!(input.len(), circuit.input_wire_count);
    let mut wires =
        vec![
            F::zero();
            circuit.input_wire_count + circuit.output_wire_count + circuit.internal_wire_count
        ];
    wires[0..circuit.input_wire_count].copy_from_slice(input);
    for layer in circuit.gates.iter() {
        for gate in layer {
            match gate {
                &ParsedGate::AndGate { input, output } => {
                    wires[output] = wires[input[0]] * wires[input[1]];
                }
                &ParsedGate::NotGate { input, output } => {
                    wires[output] = wires[input];
                    wires[output] += F::one();
                }
                &ParsedGate::XorGate { input, output } => {
                    wires[output] = wires[input[0]] + wires[input[1]];
                }
                &ParsedGate::WideAndGate {
                    input,
                    input_bit,
                    output,
                } => {
                    for i in 0..input.len() {
                        let input_bit_val = wires[input_bit];
                        wires[output[i]] = input_bit_val * wires[input[i]];
                    }
                }
            }
        }
    }
    // wires.drain(0..wires.len() - circuit.output_wire_count);
    wires
}
#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        path::Path,
        sync::Arc,
    };

    use aes_prng::AesRng;
    use futures::future::try_join_all;
    use log::info;
    use rand::thread_rng;
    use tokio::time::Instant;

    use super::{
        bristol_fashion::{parse_bristol, ParsedCircuit},
        FieldContainer, GF2Container, PackedGF2Container,
    };
    use crate::{
        circuit_eval::{
            bristol_fashion::ParsedGate,
            semi_honest::{
                local_eval_circuit, multi_party_semi_honest_eval_circuit,
                OfflineSemiHonestCorrelation, PcgBasedPairwiseBooleanCorrelation,
                RegularBeaverTriple, RegularMask, WideBeaverTriple, WideMask,
            },
        },
        engine::{LocalRouter, MultiPartyEngine},
        fields::{FieldElement, PackedField, PackedGF2, GF2},
        pcg::{PackedOfflineReceiverPcgKey, StandardDealer},
        uc_tags::UCTag,
    };

    async fn test_boolean_circuit<
        const PPRF_COUNT: usize,
        const PPRF_DEPTH: usize,
        const PCGPACK: usize,
        const N: usize,
        F: PackedField<GF2, N>,
        FC: FieldContainer<F>,
    >(
        circuit: ParsedCircuit,
        input: &[F],
        party_count: usize,
    ) -> Vec<F>
    where
        [(); (PCGPACK + 7) / 8]:,
    {
        assert_eq!(input.len(), circuit.input_wire_count);
        let mut party_ids: Vec<_> = (1..=party_count).map(|i| i as u64).collect();
        party_ids.sort();
        let party_ids_set = HashSet::from_iter(party_ids.iter().copied());
        let (local_router, mut execs) = LocalRouter::new(UCTag::new(&"root_tag"), &party_ids_set);
        let router_handle = tokio::spawn(local_router.launch());

        let mut rng = AesRng::from_random_seed();
        let addition_threshold = circuit.input_wire_count % party_count;
        let mut total_input_previous = 0;
        let parties_input_lengths: HashMap<_, _> = party_ids
            .iter()
            .enumerate()
            .map(|(i, pid)| {
                let addition = (i < addition_threshold) as usize;
                let my_input_length = circuit.input_wire_count / party_count + addition;
                let my_input_start = total_input_previous;
                total_input_previous += my_input_length;
                (*pid, (my_input_start, my_input_length))
            })
            .collect();
        let dealer = StandardDealer::new(PPRF_COUNT, PPRF_DEPTH);
        let (_, _, offline_correlations): (
            _,
            _,
            Vec<(
                u64,
                PcgBasedPairwiseBooleanCorrelation<N, _, PackedOfflineReceiverPcgKey<PCGPACK>, _>,
            )>,
        ) = PcgBasedPairwiseBooleanCorrelation::deal(
            &mut rng,
            &parties_input_lengths,
            &circuit,
            &dealer,
        );

        let mut inputs: HashMap<_, _> = parties_input_lengths
            .iter()
            .map(|(&pid, &(input_start, input_len))| {
                let my_input = input[input_start..input_start + input_len].to_vec();
                (pid, my_input)
            })
            .collect();
        let engine_futures =
            offline_correlations
                .into_iter()
                .map(|(id, mut offline_correlation)| {
                    let circuit = circuit.clone();
                    let mut engine = execs.get(&id).unwrap().sub_protocol("MULTIPARTY BEAVER");
                    async move {
                        offline_correlation
                            .get_multiparty_beaver_triples(&mut engine, &circuit)
                            .await;
                        Result::<_, ()>::Ok((id, offline_correlation))
                    }
                });
        let parties_input_lengths = Arc::new(parties_input_lengths);
        let exec_results = try_join_all(engine_futures).await.unwrap();
        let mut corr_sums = HashMap::<(usize, usize), RegularBeaverTriple<F>>::from_iter(
            exec_results[0]
                .1
                .get_prepared_multiparty_beaver_triples()
                .0
                .iter()
                .copied()
                .into_iter(),
        );
        let mut wide_corr_sums = HashMap::<(usize, usize), WideBeaverTriple<F>>::from_iter(
            exec_results[0]
                .1
                .get_prepared_multiparty_beaver_triples()
                .1
                .iter()
                .copied(),
        );
        exec_results.iter().skip(1).for_each(|(_, v)| {
            v.get_prepared_multiparty_beaver_triples()
                .0
                .iter()
                .for_each(|((layer_idx, gate_idx), bt)| {
                    let current = corr_sums.get_mut(&(*layer_idx, *gate_idx)).unwrap();
                    match (current, bt) {
                        (
                            RegularBeaverTriple(cur_a, cur_b, cur_c),
                            RegularBeaverTriple(bt_a, bt_b, bt_c),
                        ) => {
                            *cur_a += *bt_a;
                            *cur_b += *bt_b;
                            *cur_c += *bt_c;
                        }
                    }
                });
            v.get_prepared_multiparty_beaver_triples()
                .1
                .iter()
                .for_each(|((layer_idx, gate_idx), bt)| {
                    let current = wide_corr_sums.get_mut(&(*layer_idx, *gate_idx)).unwrap();
                    match (current, bt) {
                        (
                            WideBeaverTriple(cur_a, cur_b, cur_c),
                            WideBeaverTriple(bt_a, bt_b, bt_c),
                        ) => {
                            *cur_a += *bt_a;
                            for i in 0..cur_b.len() {
                                cur_b[i] += bt_b[i];
                                cur_c[i] += bt_c[i];
                            }
                        }
                    }
                })
        });
        for v in corr_sums.values() {
            match v {
                RegularBeaverTriple(a, b, c) => {
                    assert_eq!(*a * *b, *c);
                }
            }
        }
        for v in wide_corr_sums.values() {
            match v {
                WideBeaverTriple(a, b, c) => {
                    assert_eq!(core::array::from_fn(|i| b[i] * *a), *c);
                }
            }
        }

        let engine_futures = exec_results.into_iter().map(|(id, offline_corerlation)| {
            let mut engine = execs.remove(&id).unwrap();
            let circuit = circuit.clone();
            let input = inputs.remove(&id).unwrap();
            let output_wire_masks: Vec<_> =
                offline_corerlation.get_circuit_output_wires_masks_shares(&circuit);
            let input_wire_masks: Vec<_> =
                offline_corerlation.get_circuit_input_wires_masks_shares(&circuit);
            let my_input_mask = offline_corerlation
                .get_personal_circuit_input_wires_masks()
                .to_vec();
            let parties_input_lengths = parties_input_lengths.clone();
            tokio::spawn(async move {
                let (n_party_correlation, wide_n_party_correlation) =
                    offline_corerlation.get_prepared_multiparty_beaver_triples();
                multi_party_semi_honest_eval_circuit::<N, _, _, _, FC>(
                    &mut engine,
                    &circuit,
                    &input,
                    &my_input_mask,
                    input_wire_masks,
                    n_party_correlation,
                    wide_n_party_correlation,
                    &output_wire_masks,
                    &parties_input_lengths,
                )
                .await
                .map(
                    |(
                        masked_input_wires,
                        masked_gate_inputs,
                        wide_masked_gate_inputs,
                        masked_outputs,
                    )| {
                        (
                            masked_gate_inputs,
                            wide_masked_gate_inputs,
                            masked_outputs,
                            output_wire_masks,
                            // n_party_correlation,
                            // wide_n_party_correlation,
                            masked_input_wires,
                        )
                    },
                )
            })
        });

        let timer_start = Instant::now();
        let exec_results = try_join_all(engine_futures).await.unwrap();
        info!("Computation took: {}", timer_start.elapsed().as_millis());
        let exec_results: Vec<_> = exec_results.into_iter().map(|e| e.unwrap()).collect();
        let local_computation_wires = local_eval_circuit(&circuit, input);
        let mut local_computation_output = local_computation_wires
            [local_computation_wires.len() - circuit.output_wire_count..]
            .to_vec();
        let output = local_computation_output.clone();

        // Ensure output wires are of correct length.
        for e in exec_results.iter() {
            assert_eq!(e.2.len(), local_computation_output.len());
        }
        assert_eq!(local_computation_output.len(), circuit.output_wire_count);
        exec_results.iter().for_each(|e| {
            e.3.iter()
                .zip(local_computation_output.iter_mut())
                .for_each(|(ei, li)| li.sub_assign(*ei));
        });
        router_handle.await.unwrap().unwrap();

        // Check Computation is Correct
        for j in 0..exec_results.len() {
            for i in 0..circuit.output_wire_count {
                assert_eq!(local_computation_output[i], exec_results[j].2[i]);
            }
        }

        // Check the per-gate masks are correct.
        for (idx, (k, v)) in exec_results[0].0.iter().enumerate() {
            for i in 1..exec_results.len() {
                assert_eq!(&exec_results[i].0[idx].1, v);
                assert_eq!(&exec_results[i].0[idx].0, k);
            }
            let gate = circuit.gates[k.0][k.1];
            let corr = corr_sums.get(k).unwrap();
            match (gate, corr, v) {
                (
                    ParsedGate::AndGate { input, output: _ },
                    RegularBeaverTriple(a, b, _),
                    RegularMask(mask_a, mask_b),
                ) => {
                    assert_eq!(*a + *mask_a, local_computation_wires[input[0]]);
                    assert_eq!(*b + *mask_b, local_computation_wires[input[1]]);
                }
                _ => panic!(),
            }
        }
        for (idx, (k, v)) in exec_results[0].1.iter().enumerate() {
            for i in 1..exec_results.len() {
                assert_eq!(&exec_results[i].1[idx].1, v);
                assert_eq!(&exec_results[i].1[idx].0, k);
            }
            let gate = circuit.gates[k.0][k.1];
            let corr = wide_corr_sums.get(k).unwrap();
            match (gate, corr, v) {
                (
                    ParsedGate::WideAndGate {
                        input,
                        input_bit,
                        output: _,
                    },
                    WideBeaverTriple(a, wb, _),
                    WideMask(mask_a, mask_wb),
                ) => {
                    assert_eq!(*mask_a + *a, local_computation_wires[input_bit]);
                    let full_b: [F; 128] = core::array::from_fn(|i| wb[i] + mask_wb[i]);
                    for i in 0..input.len() {
                        assert_eq!(F::from(full_b[i]), local_computation_wires[input[i]])
                    }
                }
                _ => panic!(),
            }
        }
        output
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_small_circuit() {
        let logical_or_circuit = [
            "4 6",
            "2 1 1",
            "1 1",
            "",
            "1 1 0 2 INV",
            "1 1 1 3 INV",
            "2 1 2 3 4 AND",
            "1 1 4 5 INV",
        ];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");

        // Test classical eval.
        assert_eq!(
            *local_eval_circuit(&parsed_circuit, &[GF2::one(), GF2::one()])
                .last()
                .unwrap(),
            GF2::one()
        );
        assert_eq!(
            *local_eval_circuit(&parsed_circuit, &[GF2::zero(), GF2::one()])
                .last()
                .unwrap(),
            GF2::one()
        );
        assert_eq!(
            *local_eval_circuit(&parsed_circuit, &[GF2::one(), GF2::zero()])
                .last()
                .unwrap(),
            GF2::one()
        );
        assert_eq!(
            *local_eval_circuit(&parsed_circuit, &[GF2::zero(), GF2::zero()])
                .last()
                .unwrap(),
            GF2::zero()
        );

        let input = vec![GF2::one(), GF2::zero()];
        let output =
            test_boolean_circuit::<10, 5, 1, 1, GF2, GF2Container>(parsed_circuit, &input, 2).await;

        assert_eq!(output[0], GF2::one());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_wide_and() {
        let logical_or_circuit = [
            "1 257",
            "2 128 1",
            "1 128",
            "",
            "129 128 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203 204 205 206 207 208 209 210 211 212 213 214 215 216 217 218 219 220 221 222 223 224 225 226 227 228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255 256 wAND",
        ];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");

        let mut input = [GF2::one(); 129];
        // Test classical eval.
        let eval = local_eval_circuit(&parsed_circuit, &input[..]);

        assert_eq!(
            eval[eval.len() - parsed_circuit.output_wire_count..].to_vec(),
            Vec::from_iter(input[1..].iter().cloned())
        );

        input[0] = GF2::zero();

        let eval = local_eval_circuit(&parsed_circuit, &input[..]);
        assert_eq!(
            eval[eval.len() - parsed_circuit.output_wire_count..].to_vec(),
            vec![GF2::zero(); 128]
        );

        let input = vec![GF2::one(); 129];
        let output =
            test_boolean_circuit::<10, 5, 4, 1, GF2, GF2Container>(parsed_circuit, &input, 7).await;

        assert_eq!(output, vec![GF2::one(); 128]);
    }
    #[test]
    fn test_semi_honest_aes() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(32 * 1024 * 1024)
            .build()
            .unwrap();
        runtime.block_on(async {
            let path = Path::new("circuits/aes_128.txt");
            let parsed_circuit = super::super::circuit_from_file(path).unwrap();

            let input = vec![PackedGF2::one(); parsed_circuit.input_wire_count];
            test_boolean_circuit::<10, 5, 4, { PackedGF2::BITS }, _, PackedGF2Container>(
                parsed_circuit,
                &input,
                2,
            )
            .await;
        })
    }
}
