use std::{collections::HashMap, marker::PhantomData, ops::Mul, sync::Arc};

use aes_prng::AesRng;
use log::info;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    commitment::OfflineCommitment,
    engine::MultiPartyEngine,
    fields::{FieldElement, PackedField, GF2},
    zkfliop::{self, ni::ZkFliopProof},
    PartyId,
};

use super::{
    bristol_fashion::ParsedCircuit,
    semi_honest::{self, FieldContainer, OfflineSemiHonestCorrelation},
    verify::{self, statement_length, OfflineCircuitVerify},
};

#[derive(Serialize, Deserialize)]
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
    dealer_verification_material: Option<HashMap<PartyId, ZkFliopProof<F>>>,
    _phantom: PhantomData<PF>,
}
impl<
        const PACKING: usize,
        PF: PackedField<GF2, PACKING>,
        F: FieldElement + From<GF2>,
        SHO: OfflineSemiHonestCorrelation<PF>,
    > MaliciousSecurityOffline<PACKING, PF, F, SHO>
where
    GF2: Mul<F, Output = F>,
{
    pub fn malicious_security_offline_dealer(
        circuit: &ParsedCircuit,
        party_input_length: &HashMap<PartyId, (usize, usize)>,
        dealer: &SHO::Dealer,
        is_authenticated: bool,
    ) -> HashMap<PartyId, MaliciousSecurityOffline<PACKING, PF, F, SHO>> {
        // Correlated Randomness for Semi-Honest
        let mut aes_rng = AesRng::from_random_seed();
        let parties_num = party_input_length.len();
        let (input_wire_masks, output_wire_masks, offline_correlations) =
            SHO::deal(&mut aes_rng, party_input_length, circuit, dealer);
        // Correlated random for Verify
        let mut verifier_correlations = verify::offline_verify_dealer(
            circuit,
            &input_wire_masks,
            &output_wire_masks,
            &offline_correlations,
            is_authenticated,
        );

        let (mut output_wires_share, output_wires_commitment) =
            OfflineCommitment::commit(&output_wire_masks, parties_num);
        offline_correlations
            .into_iter()
            .map(|(pid, sho)| {
                let (verify, dealer_verify) = verifier_correlations.remove(&pid).unwrap();
                (
                    pid,
                    MaliciousSecurityOffline {
                        semi_honest_offline_correlation: sho,
                        output_wire_mask_commitments: OfflineCommitment {
                            commit_share: output_wires_share.pop().unwrap(),
                            commitment: output_wires_commitment,
                        },
                        offline_verification_material: verify,
                        dealer_verification_material: dealer_verify,
                        _phantom: PhantomData::<PF>,
                    },
                )
            })
            .collect()
    }
    pub async fn malicious_security_offline_party(
        engine: &mut impl MultiPartyEngine,
        circuit: impl AsRef<ParsedCircuit>,
        correlation: &MaliciousSecurityOffline<PACKING, PF, F, SHO>,
        is_authenticated: bool,
    ) -> bool {
        if !is_authenticated {
            return true;
        }
        let proof_statement_length = statement_length::<PACKING>(circuit.as_ref());
        println!("Verifying triples...");
        let proofs = correlation.dealer_verification_material.as_ref().unwrap();
        let peers: Vec<PartyId> = engine.party_ids().iter().copied().collect();
        let peers = Arc::new(peers.into());
        let semi_honest_offline_correlation = &correlation.semi_honest_offline_correlation;
        let triples_verdict = semi_honest_offline_correlation
            .verify_correlation(
                &mut engine.sub_protocol_with("verify triples", peers),
                circuit.as_ref(),
                proofs,
            )
            .await;
        assert!(triples_verdict);
        println!("Triples OK!");
        return triples_verdict;
    }
    pub async fn into_pre_online_material<E: MultiPartyEngine, C: AsRef<ParsedCircuit>>(
        self,
        _: &mut E,
        circuit: C,
    ) -> PreOnlineMaterial<PACKING, PF, F, C, SHO> {
        // In this phase we expand the compressed correlations, right before the online phase.
        let Self {
            mut semi_honest_offline_correlation,
            output_wire_mask_commitments,
            offline_verification_material,
            dealer_verification_material: _,
            _phantom: _,
        } = self;
        let output_wire_mask_shares =
            semi_honest_offline_correlation.get_circuit_output_wires_masks_shares(circuit.as_ref());
        let input_wire_mask_shares =
            semi_honest_offline_correlation.get_circuit_input_wires_masks_shares(circuit.as_ref());
        let my_input_mask = semi_honest_offline_correlation
            .get_personal_circuit_input_wires_masks()
            .to_vec();

        semi_honest_offline_correlation.pre_online_phase_preparation(circuit.as_ref());

        PreOnlineMaterial {
            circuit,
            output_wire_mask_commitments,
            output_wire_mask_shares,
            input_wire_mask_shares,
            offline_verification_material,
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
        F: FieldElement + From<GF2>,
        C: AsRef<ParsedCircuit>,
        SHO: OfflineSemiHonestCorrelation<PF>,
    > PreOnlineMaterial<PACKING, PF, F, C, SHO>
where
    GF2: Mul<F, Output = F>,
{
    pub async fn online_malicious_computation<FC: FieldContainer<PF>>(
        &mut self,
        engine: &mut impl MultiPartyEngine,
        my_input: Vec<PF>,
        two: F,
        three: F,
        four: F,
        parties_input_pos_and_lengths: &HashMap<PartyId, (usize, usize)>,
        is_verified_dealer: bool,
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
            two,
            three,
            four,
            &masked_input_wires,
            &masked_gate_inputs,
            &wide_masked_gate_inputs,
            &regular_multi_party_beaver_triples,
            &wide_multi_party_beaver_triples,
            &masked_outputs,
            circuit.as_ref(),
            offline_verification_material,
            is_verified_dealer,
        )
        .await
        {
            return None;
        }
        info!("Verify took: {}", timer.elapsed().as_millis());
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
    ) -> Vec<PF> {
        let mut local_eval_output = semi_honest::local_eval_circuit(&circuit, &input);
        local_eval_output.drain(0..local_eval_output.len() - circuit.output_wire_count);
        const PARTIES: usize = 2;
        const DEALER_ID: PartyId = (PARTIES + 1) as PartyId;

        let mut two = GF128::zero();
        two.set_bit(true, 1);
        let three = two + GF128::one();
        let four = two * two;

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
            .map(|(pid, material)| {
                let mut engine = online_engines
                    .get(&pid)
                    .unwrap()
                    .sub_protocol("verify_corr");
                let circuit = circuit.clone();
                async move {
                    let res = MaliciousSecurityOffline::malicious_security_offline_party(
                        &mut engine,
                        circuit,
                        material,
                        is_authenticated,
                    )
                    .await;
                    Result::<bool, ()>::Ok(res)
                }
            })
            .collect();
        assert!(try_join_all(verification_handles)
            .await
            .unwrap()
            .into_iter()
            .all(|v| v));

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

        let online_handles = pre_online_handles.into_iter().map(|(pid, mut pre)| {
            let input = inputs.remove(&pid).unwrap();
            let mut engine = online_engines.remove(&pid).unwrap();
            let input_lengths = input_lengths.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                let o = pre
                    .online_malicious_computation::<FC>(
                        &mut engine,
                        input,
                        two,
                        three,
                        four,
                        &input_lengths,
                        is_authenticated,
                    )
                    .await
                    .ok_or(());
                info!("Malicious eval took: {}ms", start.elapsed().as_millis());
                o
            })
        });
        let start = Instant::now();
        let mut online_outputs: Vec<_> = try_join_all(online_handles)
            .await
            .unwrap()
            .into_iter()
            .map(|v| v.unwrap())
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
        let input = vec![GF2::zero(), GF2::zero()];
        let dealer = StandardDealer::new(10, 7);
        test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
            parsed_circuit,
            input,
            Arc::new(dealer),
            true,
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
        let input = vec![GF2::zero(), GF2::zero(), GF2::zero()];
        let dealer = StandardDealer::new(10, 7);
        test_malicious_circuit::<1, _, PackedOfflineReceiverPcgKey<4>, _, GF2Container>(
            parsed_circuit,
            input,
            Arc::new(dealer),
            true,
        )
        .await;
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
            )
            .await;
        });
    }
}
