use std::{collections::HashMap, marker::PhantomData, ops::Mul, sync::Arc};

use aes_prng::AesRng;
use log::info;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    commitment::OfflineCommitment,
    engine::MultiPartyEngine,
    fields::{FieldElement, IntermediateMulField, PackedField, GF2},
    zkfliop::{self, ni::ZkFliopProof, VerifierCtx},
    PartyId,
};

use super::{
    bristol_fashion::ParsedCircuit,
    semi_honest::{self, FieldContainer, OfflineSemiHonestCorrelation},
    verify::{
        self, statement_length, verify_fliop_correlation, DealerCtx, FliopCtx, OfflineCircuitVerify,
    },
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MaliciousSecurityOffline<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    F: FieldElement + From<GF2>,
    SHO: OfflineSemiHonestCorrelation<PF>,
> {
    #[serde(bound = "")]
    semi_honest_offline_correlation: SHO,
    output_wire_mask_commitments: OfflineCommitment,
    #[serde(bound = "")]
    offline_verification_material: OfflineCircuitVerify<F>,
    #[serde(bound = "")]
    dealer_verification_triples: Option<HashMap<PartyId, ZkFliopProof<F>>>,
    #[serde(bound = "")]
    dealer_verification_fliop: Option<ZkFliopProof<F>>,
    _phantom: PhantomData<PF>,
}
impl<
        const PACKING: usize,
        PF: PackedField<GF2, PACKING>,
        F: IntermediateMulField + From<GF2>,
        SHO: OfflineSemiHonestCorrelation<PF>,
    > MaliciousSecurityOffline<PACKING, PF, F, SHO>
where
    GF2: Mul<F, Output = F>,
{
    pub async fn verify_dealer<E: MultiPartyEngine>(
        &self,
        engine: &mut E,
        circuit: &ParsedCircuit,
        verifier_ctx: &mut Vec<VerifierCtx<F>>,
    ) {
        if self.dealer_verification_triples.is_none() {
            return;
        }
        self.semi_honest_offline_correlation
            .verify_correlation(
                &mut engine.sub_protocol("verify triples"),
                circuit,
                self.dealer_verification_triples.as_ref().unwrap(),
                verifier_ctx,
            )
            .await;
        assert!(
            verify_fliop_correlation(
                engine.sub_protocol("fliop"),
                &self.offline_verification_material,
                &self.semi_honest_offline_correlation,
                &mut verifier_ctx[0],
                self.dealer_verification_fliop.as_ref().unwrap(),
            )
            .await
        );
    }
    pub fn malicious_security_offline_dealer(
        circuit: &ParsedCircuit,
        party_input_length: &HashMap<PartyId, (usize, usize)>,
        dealer: &SHO::Dealer,
        is_authenticated: bool,
        dealer_ctx: &mut DealerCtx<F>,
    ) -> HashMap<PartyId, MaliciousSecurityOffline<PACKING, PF, F, SHO>> {
        // Correlated Randomness for Semi-Honest
        let mut aes_rng = AesRng::from_random_seed();
        let parties_num = party_input_length.len();
        let (input_wire_masks, output_wire_masks, mut offline_correlations) =
            SHO::deal(&mut aes_rng, party_input_length, circuit, dealer);
        // Correlated random for Verify
        let time = Instant::now();
        let mut verifier_correlations = verify::offline_verify_dealer(
            circuit,
            &input_wire_masks,
            &output_wire_masks,
            &mut offline_correlations,
            is_authenticated,
            dealer_ctx,
        );
        info!(
            "Offline verify dealer took: {}ms",
            time.elapsed().as_millis()
        );

        let (mut output_wires_share, output_wires_commitment) =
            OfflineCommitment::commit(&output_wire_masks, parties_num);
        offline_correlations
            .into_iter()
            .map(|(pid, sho)| {
                let (verify, dealer_verify_triples, dealer_verify_fliop) =
                    verifier_correlations.remove(&pid).unwrap();
                (
                    pid,
                    MaliciousSecurityOffline {
                        semi_honest_offline_correlation: sho,
                        output_wire_mask_commitments: OfflineCommitment {
                            commit_share: output_wires_share.pop().unwrap(),
                            commitment: output_wires_commitment,
                        },
                        offline_verification_material: verify,
                        dealer_verification_triples: dealer_verify_triples,
                        dealer_verification_fliop: dealer_verify_fliop,
                        _phantom: PhantomData::<PF>,
                    },
                )
            })
            .collect()
    }
    pub async fn malicious_security_offline_party(
        &self,
        engine: &mut impl MultiPartyEngine,
        circuit: &ParsedCircuit,
        is_authenticated: bool,
        ctx: &mut FliopCtx<F>,
    ) -> bool {
        if !is_authenticated {
            return true;
        }
        let proof_statement_length = statement_length::<PACKING>(circuit);
        println!("Verifying triples...");
        let proofs = self.dealer_verification_triples.as_ref().unwrap();
        let peers: Vec<PartyId> = engine.party_ids().iter().copied().collect();
        let peers = Arc::new(peers.into());
        let semi_honest_offline_correlation = &self.semi_honest_offline_correlation;
        let triples_verdict = semi_honest_offline_correlation
            .verify_correlation(
                &mut engine.sub_protocol_with("verify triples", peers),
                circuit,
                proofs,
                ctx.verifiers_ctx.as_mut().unwrap(),
            )
            .await;
        assert!(triples_verdict);
        println!("Triples OK!");
        return triples_verdict;
    }
    pub async fn into_pre_online_material<E: MultiPartyEngine, C: AsRef<ParsedCircuit>>(
        &self,
        _: &mut E,
        circuit: C,
    ) -> PreOnlineMaterial<PACKING, PF, F, C, SHO> {
        // In this phase we expand the compressed correlations, right before the online phase.
        let Self {
            semi_honest_offline_correlation,
            output_wire_mask_commitments,
            offline_verification_material,
            dealer_verification_triples: _,
            dealer_verification_fliop: _,
            _phantom: _,
        } = &self;
        let output_wire_mask_shares =
            semi_honest_offline_correlation.get_circuit_output_wires_masks_shares(circuit.as_ref());
        let input_wire_mask_shares =
            semi_honest_offline_correlation.get_circuit_input_wires_masks_shares(circuit.as_ref());
        let my_input_mask = semi_honest_offline_correlation
            .get_personal_circuit_input_wires_masks()
            .to_vec();

        let mut semi_honest_offline_correlation = semi_honest_offline_correlation.clone();
        semi_honest_offline_correlation.pre_online_phase_preparation(circuit.as_ref());

        PreOnlineMaterial {
            circuit,
            output_wire_mask_commitments: output_wire_mask_commitments.clone(),
            output_wire_mask_shares,
            input_wire_mask_shares,
            offline_verification_material: offline_verification_material.clone(),
            semi_honest_offline_correlation,
            my_input_mask,
        }
    }
}

pub struct PreOnlineMaterial<
    const PACKING: usize,
    PF: PackedField<GF2, PACKING>,
    F: FieldElement + From<GF2>,
    C: AsRef<ParsedCircuit>,
    SHO: OfflineSemiHonestCorrelation<PF>,
> {
    circuit: C,
    output_wire_mask_commitments: OfflineCommitment,
    output_wire_mask_shares: Vec<PF>,
    input_wire_mask_shares: Vec<PF>,
    my_input_mask: Vec<PF>,
    semi_honest_offline_correlation: SHO,
    offline_verification_material: OfflineCircuitVerify<F>,
}

impl<
        const PACKING: usize,
        PF: PackedField<GF2, PACKING>,
        F: IntermediateMulField + From<GF2>,
        C: AsRef<ParsedCircuit>,
        SHO: OfflineSemiHonestCorrelation<PF>,
    > PreOnlineMaterial<PACKING, PF, F, C, SHO>
where
    GF2: Mul<F, Output = F>,
{
    pub async fn online_malicious_computation<FC: FieldContainer<PF>>(
        &mut self,
        engine: &mut impl MultiPartyEngine,
        my_input: &[PF],
        parties_input_pos_and_lengths: &HashMap<PartyId, (usize, usize)>,
        ctx: &mut FliopCtx<F>,
    ) -> Option<Vec<PF>> {
        let Self {
            circuit,
            output_wire_mask_commitments,
            output_wire_mask_shares,
            offline_verification_material,
            input_wire_mask_shares,
            my_input_mask,
            semi_honest_offline_correlation,
        } = self;
        let timer = Instant::now();
        let (regular_multi_party_beaver_triples, wide_multi_party_beaver_triples) =
            semi_honest_offline_correlation
                .get_multiparty_beaver_triples(engine, circuit.as_ref())
                .await;
        info!("Getting triples took: {}", timer.elapsed().as_millis());
        let input_wire_mask_shares = input_wire_mask_shares.clone();
        let timer = Instant::now();
        let (masked_input_wires, masked_gate_inputs, wide_masked_gate_inputs, masked_outputs) =
            semi_honest::multi_party_semi_honest_eval_circuit::<PACKING, _, _, _, FC>(
                engine,
                circuit.as_ref(),
                &my_input,
                &my_input_mask,
                input_wire_mask_shares,
                &regular_multi_party_beaver_triples,
                &wide_multi_party_beaver_triples,
                &output_wire_mask_shares,
                parties_input_pos_and_lengths,
            )
            .await
            .unwrap();
        info!("Semi Honest took: {}", timer.elapsed().as_millis());
        let timer = Instant::now();
        if !verify::verify_parties(
            engine,
            &masked_input_wires,
            &masked_gate_inputs,
            &wide_masked_gate_inputs,
            regular_multi_party_beaver_triples,
            wide_multi_party_beaver_triples,
            &masked_outputs,
            circuit.as_ref(),
            offline_verification_material,
            ctx,
        )
        .await
        {
            return None;
        }
        info!(
            "Verify {} took: {}",
            engine.my_party_id(),
            timer.elapsed().as_millis()
        );
        let timer = Instant::now();
        let output_wire_masks: Vec<PF> = output_wire_mask_commitments.online_decommit(engine).await;
        let outputs: Vec<_> = output_wire_masks
            .into_iter()
            .zip(masked_outputs.into_iter())
            .map(|(a, b)| a + b)
            .collect();
        info!("Output opening took: {}", timer.elapsed().as_millis());
        Some(outputs)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        path::Path,
        sync::Arc,
    };

    use futures::future::try_join_all;
    use log::info;
    use semi_honest::OfflineSemiHonestCorrelation;
    use tokio::{join, runtime, time::Instant};

    use super::MaliciousSecurityOffline;
    use crate::{
        circuit_eval::{
            bristol_fashion::{parse_bristol, ParsedCircuit},
            malicious::PreOnlineMaterial,
            semi_honest::{self, FieldContainer, GF2Container, PcgBasedPairwiseBooleanCorrelation},
            verify::{DealerCtx, FliopCtx},
        },
        engine::{LocalRouter, MultiPartyEngine},
        fields::{FieldElement, PackedField, GF128, GF2},
        pcg::{
            PackedKeysDealer, PackedOfflineReceiverPcgKey, PackedSenderCorrelationGenerator,
            StandardDealer,
        },
        PartyId, UCTag,
    };

    async fn test_malicious_circuit<
        const PACKING: usize,
        PF: PackedField<GF2, PACKING>,
        PS: PackedSenderCorrelationGenerator + 'static,
        D: PackedKeysDealer<PS> + 'static,
        FC: FieldContainer<PF>,
    >(
        circuit: ParsedCircuit,
        input: Vec<PF>,
        dealer: Arc<D>,
        is_authenticated: bool,
        log_folding_factor: usize,
    ) -> Vec<PF> {
        let mut local_eval_output = semi_honest::local_eval_circuit(&circuit, &input);
        local_eval_output.drain(0..local_eval_output.len() - circuit.output_wire_count);
        const PARTIES: usize = 2;
        const DEALER_ID: PartyId = (PARTIES + 1) as PartyId;

        // Init CTXs
        let mut dealer_ctx = DealerCtx::new(log_folding_factor);
        let mut parties_ctx: Vec<_> = (0..PARTIES)
            .map(|_| FliopCtx::new(log_folding_factor, PARTIES - 1))
            .collect();
        // Offline
        let offline_party_ids: [PartyId; PARTIES + 1] =
            core::array::from_fn(|i| (i + 1) as PartyId);
        let default_input_length = input.len() / PARTIES;
        let addition_threshold = input.len() % PARTIES;
        let mut inputs = HashMap::with_capacity(PARTIES);
        let mut used_input = 0;
        let input_lengths: HashMap<_, _> = offline_party_ids
            .iter()
            .copied()
            .filter(|i| i != &DEALER_ID)
            .enumerate()
            .map(|(idx, i)| {
                let my_input_len = default_input_length + (idx < addition_threshold) as usize;
                let my_input = input[used_input..used_input + my_input_len].to_vec();
                inputs.insert(i, my_input);
                used_input += my_input_len;
                (i, (used_input - my_input_len, my_input_len))
            })
            .collect();
        let mut parties_offline_material = MaliciousSecurityOffline::<
            PACKING,
            PF,
            GF128,
            PcgBasedPairwiseBooleanCorrelation<PACKING, PF, _, _>,
        >::malicious_security_offline_dealer(
            &circuit,
            &input_lengths,
            dealer.as_ref(),
            is_authenticated,
            &mut dealer_ctx,
        );
        let input_lengths = Arc::new(input_lengths);
        let circuit = Arc::new(circuit);
        // Pre Online & Verify Correlation
        let online_party_ids: [PartyId; PARTIES] = core::array::from_fn(|i| (i + 1) as PartyId);
        let online_parties_set = HashSet::from_iter(online_party_ids.iter().copied());
        let (online_router, mut online_engines) =
            LocalRouter::new(UCTag::new(&"ROOT_TAG"), &online_parties_set);
        let router_handle = tokio::spawn(online_router.launch());

        let verification_handles: Vec<_> = parties_offline_material
            .iter_mut()
            .zip(parties_ctx.drain(..))
            .map(|((pid, material), mut ctx)| {
                let mut engine = online_engines
                    .get(&pid)
                    .unwrap()
                    .sub_protocol("verify_corr");
                let circuit = circuit.clone();
                async move {
                    let res = material
                        .malicious_security_offline_party(
                            &mut engine,
                            circuit.as_ref(),
                            is_authenticated,
                            &mut ctx,
                        )
                        .await;
                    Result::<(bool, FliopCtx<_>), ()>::Ok((res, ctx))
                }
            })
            .collect();
        assert!(try_join_all(verification_handles)
            .await
            .unwrap()
            .into_iter()
            .all(|v| {
                parties_ctx.push(v.1);
                v.0
            }));

        let pre_online_handles =
            parties_offline_material
                .into_iter()
                .map(|(pid, offline_material)| {
                    let mut engine = online_engines.get(&pid).unwrap().sub_protocol("PRE-ONLINE");
                    let circuit = circuit.clone();
                    async move {
                        let pre_online_material = offline_material
                            .into_pre_online_material(&mut engine, circuit)
                            .await;
                        Result::<(PartyId, PreOnlineMaterial<PACKING, PF, _, _, _>), ()>::Ok((
                            pid,
                            pre_online_material,
                        ))
                    }
                });

        let pre_online_handles = try_join_all(pre_online_handles).await.unwrap();

        // Online

        let online_handles = pre_online_handles
            .into_iter()
            .zip(parties_ctx.drain(..))
            .map(|((pid, mut pre), mut ctx)| {
                let input = inputs.remove(&pid).unwrap();
                let mut engine = online_engines.remove(&pid).unwrap();
                let input_lengths = input_lengths.clone();
                tokio::spawn(async move {
                    let start = Instant::now();
                    let o = pre
                        .online_malicious_computation::<FC>(
                            &mut engine,
                            &input,
                            &input_lengths,
                            &mut ctx,
                        )
                        .await
                        .ok_or(());
                    info!("Malicious eval took: {}ms", start.elapsed().as_millis());
                    (o, ctx)
                })
            });
        let start = Instant::now();
        let mut online_outputs: Vec<_> = try_join_all(online_handles)
            .await
            .unwrap()
            .into_iter()
            .map(|v| {
                parties_ctx.push(v.1);
                v.0.unwrap()
            })
            .collect();
        info!("Running took: {}", start.elapsed().as_millis());
        let first_output = online_outputs.pop().unwrap();
        for o in online_outputs.into_iter() {
            assert_eq!(first_output, o);
        }
        router_handle.await.unwrap().unwrap();

        assert_eq!(first_output, local_eval_output);
        first_output
    }

    #[tokio::test]
    async fn test_small_circuit_malicious() {
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
        let input = vec![GF2::one(), GF2::zero()];
        let dealer = StandardDealer::new(10, 7);
        test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
            parsed_circuit,
            input,
            Arc::new(dealer),
            true,
            1,
        )
        .await;
    }
    #[tokio::test]
    async fn test_three_bit_and() {
        let logical_or_circuit = ["2 5", "1 3", "1 1", "", "2 1 0 1 3 AND", "2 1 2 3 4 AND"];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");
        let input = vec![GF2::zero(), GF2::zero(), GF2::zero()];
        let dealer = StandardDealer::new(10, 7);
        test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
            parsed_circuit,
            input,
            Arc::new(dealer),
            true,
            1,
        )
        .await;
    }
    #[tokio::test]
    async fn test_four_bit_and() {
        let logical_or_circuit = [
            "3 7",
            "1 4",
            "1 1",
            "",
            "2 1 0 1 4 AND",
            "2 1 2 3 5 AND",
            "2 1 4 5 6 AND",
        ];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");
        let input = vec![GF2::zero(); 4];
        let dealer = StandardDealer::new(10, 7);
        test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
            parsed_circuit,
            input,
            Arc::new(dealer),
            true,
            1,
        )
        .await;
    }
    #[tokio::test]
    async fn test_five_bit_and() {
        let logical_or_circuit = [
            "4 9",
            "1 5",
            "1 1",
            "",
            "2 1 0 1 5 AND",
            "2 1 2 3 6 AND",
            "2 1 4 5 7 AND",
            "2 1 6 7 8 AND",
        ];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");
        let input = vec![GF2::zero(); 5];
        let dealer = StandardDealer::new(10, 7);
        test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
            parsed_circuit,
            input,
            Arc::new(dealer),
            true,
            1,
        )
        .await;
    }
    #[tokio::test]
    async fn test_three_bit_or() {
        let logical_or_circuit = [
            "6 9",
            "1 3",
            "1 1",
            "",
            "1 1 0 3 INV",
            "1 1 1 4 INV",
            "1 1 2 5 INV",
            "2 1 3 4 6 AND",
            "2 1 5 6 7 AND",
            "1 1 7 8 INV",
        ];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");
        let input = vec![GF2::one(), GF2::zero(), GF2::zero()];
        let dealer = StandardDealer::new(10, 7);
        test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
            parsed_circuit,
            input,
            Arc::new(dealer),
            true,
            1,
        )
        .await;
    }

    #[test]
    fn test_add() {
        let rt = runtime::Builder::new_multi_thread()
            .worker_threads(16)
            .thread_stack_size(1 << 27)
            .build()
            .unwrap();
        rt.block_on(async {
            let path = Path::new("circuits/adder64.txt");
            let circuit = super::super::circuit_from_file(path).unwrap();
            let mut input = Vec::with_capacity(circuit.input_wire_count);
            for _ in 0..circuit.input_wire_count {
                input.push(GF2::one())
            }
            let dealer = StandardDealer::new(10, 7);
            test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
                circuit,
                input,
                Arc::new(dealer),
                true,
                3,
            )
            .await;
        });
    }
    #[test]
    fn test_aes() {
        let rt = runtime::Builder::new_multi_thread()
            .worker_threads(16)
            .thread_stack_size(1 << 27)
            .build()
            .unwrap();
        rt.block_on(async {
            let path = Path::new("circuits/aes_128.txt");
            let circuit = super::super::circuit_from_file(path).unwrap();
            let mut input = Vec::with_capacity(circuit.input_wire_count);
            for _ in 0..circuit.input_wire_count {
                input.push(GF2::one())
            }
            let dealer = StandardDealer::new(10, 7);
            test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
                circuit,
                input,
                Arc::new(dealer),
                true,
                4,
            )
            .await;
        });
    }
}
