use std::{collections::HashMap, marker::PhantomData};

use aes_prng::AesRng;

use crate::{
    commitment::OfflineCommitment,
    engine::MultiPartyEngine,
    fields::{FieldElement, PackedField},
    zkfliop, PartyId,
};

use super::{
    bristol_fashion::ParsedCircuit,
    semi_honest::{self, OfflineSemiHonestCorrelation},
    verify::{self, statement_length, OfflineCircuitVerify},
};

const PPRF_COUNT: usize = 50;
const PPRF_DEPTH: usize = 10;
const CODE_WIDTH: usize = 7;

pub struct MaliciousSecurityOffline<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement,
    F: FieldElement + From<CF>,
    C: AsRef<ParsedCircuit>,
    SHO: OfflineSemiHonestCorrelation<PF>,
> {
    circuit: C,
    semi_honest_offline_correlation: SHO,
    output_wire_mask_commitments: OfflineCommitment,
    offline_verification_material: OfflineCircuitVerify<F>,
    _phantom: PhantomData<(CF, PF)>,
}
impl<
        const PACKING: usize,
        PF: PackedField<CF, PACKING>,
        CF: FieldElement,
        F: FieldElement + From<CF>,
        C: AsRef<ParsedCircuit>,
        SHO: OfflineSemiHonestCorrelation<PF>,
    > MaliciousSecurityOffline<PACKING, PF, CF, F, C, SHO>
{
    pub async fn malicious_security_offline_dealer<E: MultiPartyEngine>(
        engine: &mut E,
        two: F,
        three: F,
        four: F,
        circuit: C,
        party_input_length: &HashMap<PartyId, (usize, usize)>,
    ) {
        let my_id = engine.my_party_id();
        let mut parties: Vec<_> = engine
            .party_ids()
            .iter()
            .copied()
            .filter(|p| p != &my_id)
            .collect();
        parties.sort();

        // Correlated Randomness for Semi-Honest
        let mut aes_rng = AesRng::from_random_seed();

        let (input_wire_masks, output_wire_masks, offline_correlations) =
            SHO::deal(&mut aes_rng, party_input_length, circuit.as_ref());
        for (p, oc) in offline_correlations.iter() {
            engine.send(oc, *p);
        }
        // Correlated random for Verify
        verify::offline_verify_dealer(
            engine.sub_protocol("offline verify"),
            two,
            three,
            four,
            circuit.as_ref(),
            &input_wire_masks,
            &output_wire_masks,
            &offline_correlations,
        )
        .await;

        OfflineCommitment::offline_commit(engine, &output_wire_masks).await;
    }
    pub async fn malicious_security_offline_party(
        engine: &mut impl MultiPartyEngine,
        dealer_id: PartyId,
        circuit: C,
    ) -> MaliciousSecurityOffline<PACKING, PF, CF, F, C, SHO> {
        let proof_statement_length = statement_length::<PACKING>(circuit.as_ref());
        let (_, round_count) = zkfliop::compute_round_count_and_m(proof_statement_length);
        let semi_honest_offline_correlation: SHO = engine.recv_from(dealer_id).await.unwrap();
        let offline_verification_material = verify::offline_verify_parties::<F>(
            engine.sub_protocol("offline verify"),
            dealer_id,
            round_count,
        )
        .await;
        let output_wire_mask_commitments =
            OfflineCommitment::offline_obtain_commit(engine, dealer_id).await;
        MaliciousSecurityOffline {
            circuit,
            semi_honest_offline_correlation,
            output_wire_mask_commitments,
            offline_verification_material,
            _phantom: PhantomData,
        }
    }
    pub async fn into_pre_online_material<E: MultiPartyEngine>(
        self,
        engine: &mut E,
    ) -> PreOnlineMaterial<PACKING, PF, CF, F, C, SHO> {
        // In this phase we expand the compressed correlations, right before the online phase.
        let Self {
            circuit,
            mut semi_honest_offline_correlation,
            output_wire_mask_commitments,
            offline_verification_material,
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
            _phantom: PhantomData,
        }
    }
}

pub struct PreOnlineMaterial<
    const PACKING: usize,
    PF: PackedField<CF, PACKING>,
    CF: FieldElement,
    F: FieldElement + From<CF>,
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
    _phantom: PhantomData<CF>,
}

impl<
        const PACKING: usize,
        PF: PackedField<CF, PACKING>,
        CF: FieldElement,
        F: FieldElement + From<CF>,
        C: AsRef<ParsedCircuit>,
        SHO: OfflineSemiHonestCorrelation<PF>,
    > PreOnlineMaterial<PACKING, PF, CF, F, C, SHO>
{
    pub async fn online_malicious_computation(
        &mut self,
        engine: &mut impl MultiPartyEngine,
        my_input: Vec<PF>,
        two: F,
        three: F,
        four: F,
        parties_input_pos_and_lengths: &HashMap<PartyId, (usize, usize)>,
    ) -> Option<Vec<PF>> {
        let Self {
            circuit,
            output_wire_mask_commitments,
            output_wire_mask_shares,
            offline_verification_material,
            input_wire_mask_shares,
            my_input_mask,
            semi_honest_offline_correlation,
            _phantom: _,
        } = self;
        let multi_party_beaver_triples = semi_honest_offline_correlation
            .get_multiparty_beaver_triples(engine, circuit.as_ref())
            .await;
        let input_wire_mask_shares = input_wire_mask_shares.clone();
        let (masked_input_wires, masked_gate_inputs, masked_outputs) =
            semi_honest::multi_party_semi_honest_eval_circuit(
                engine,
                circuit.as_ref(),
                &my_input,
                &my_input_mask,
                input_wire_mask_shares,
                &multi_party_beaver_triples,
                &output_wire_mask_shares,
                parties_input_pos_and_lengths,
            )
            .await
            .unwrap();
        let embedded_masked_input_wires: Vec<_> = masked_input_wires
            .iter()
            .map(|v| F::one().switch(v.is_one()))
            .collect();
        if !verify::verify_parties(
            engine,
            two,
            three,
            four,
            &masked_input_wires,
            &masked_gate_inputs,
            &multi_party_beaver_triples,
            &masked_outputs,
            circuit.as_ref(),
            offline_verification_material,
        )
        .await
        {
            return None;
        }
        let output_wire_masks: Vec<PF> = output_wire_mask_commitments.online_decommit(engine).await;
        let outputs: Vec<_> = output_wire_masks
            .into_iter()
            .zip(masked_outputs.into_iter())
            .map(|(a, b)| a + b)
            .collect();
        Some(outputs)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        path::{Path, PathBuf},
        sync::Arc,
    };

    use aes_prng::AesRng;
    use futures::{future::try_join_all, FutureExt};
    use tokio::{join, runtime, time::Instant};

    use super::MaliciousSecurityOffline;
    use crate::{
        circuit_eval::{
            bristol_fashion::{parse_bristol, ParsedCircuit},
            malicious::PreOnlineMaterial,
            semi_honest::{self, PcgBasedPairwiseBooleanCorrelation},
        },
        engine::{self, LocalRouter, MultiPartyEngine, MultiPartyEngineImpl},
        fields::{FieldElement, PackedField, PackedGF2, GF128, GF2},
        PartyId, UCTag,
    };

    async fn test_malicious_circuit<const PACKING: usize, PF: PackedField<GF2, PACKING>>(
        circuit: ParsedCircuit,
        input: Vec<PF>,
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
        let offline_parties_set = HashSet::from_iter(offline_party_ids.iter().copied());
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
        let (offline_router, mut offline_engines) =
            LocalRouter::new(UCTag::new(&"ROOT_TAG"), &offline_parties_set);
        let circuit_arc = Arc::new(circuit);
        let input_lengths_arc = Arc::new(input_lengths);
        let dealer_handle = {
            let circuit_arc_clone = circuit_arc.clone();
            let mut dealer_engine = offline_engines.remove(&DEALER_ID).unwrap();
            let input_lengths = input_lengths_arc.clone();
            async move {
                MaliciousSecurityOffline::<
                    PACKING,
                    PF,
                    GF2,
                    GF128,
                    _,
                    PcgBasedPairwiseBooleanCorrelation<PACKING, PF>,
                >::malicious_security_offline_dealer(
                    &mut dealer_engine,
                    two,
                    three,
                    four,
                    circuit_arc_clone,
                    &input_lengths,
                )
                .await;
            }
        };

        let parties_handles: Vec<_> = offline_engines
            .into_iter()
            .map(|(pid, mut e)| {
                let circuit_clone_arc = circuit_arc.clone();
                async move {
                    let res = MaliciousSecurityOffline::<
                        PACKING,
                        PF,
                        GF2,
                        GF128,
                        _,
                        PcgBasedPairwiseBooleanCorrelation<PACKING, PF>,
                    >::malicious_security_offline_party(
                        &mut e, DEALER_ID, circuit_clone_arc
                    )
                    .await;
                    Result::<
                        (
                            PartyId,
                            MaliciousSecurityOffline<PACKING, PF, GF2, GF128, _, _>,
                        ),
                        (),
                    >::Ok((pid, res))
                }
            })
            .collect();

        let parties_handles = try_join_all(parties_handles);
        let router_handle = tokio::spawn(offline_router.launch());
        let (_, parties_offline_material, router_output) =
            join!(dealer_handle, parties_handles, router_handle);
        router_output.unwrap().unwrap();
        let parties_offline_material = parties_offline_material.unwrap();

        // Pre Online
        let online_party_ids: [PartyId; PARTIES] = core::array::from_fn(|i| (i + 1) as PartyId);
        let online_parties_set = HashSet::from_iter(online_party_ids.iter().copied());
        let (online_router, mut online_engines) =
            LocalRouter::new(UCTag::new(&"ROOT_TAG"), &online_parties_set);
        let router_handle = tokio::spawn(online_router.launch());

        let pre_online_handles =
            parties_offline_material
                .into_iter()
                .map(|(pid, offline_material)| {
                    let mut engine = online_engines.get(&pid).unwrap().sub_protocol("PRE-ONLINE");
                    async move {
                        let pre_online_material =
                            offline_material.into_pre_online_material(&mut engine).await;
                        Result::<(PartyId, PreOnlineMaterial<PACKING, PF, _, _, _, _>), ()>::Ok((
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
            let input_lengths = input_lengths_arc.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                let o = pre
                    .online_malicious_computation(
                        &mut engine,
                        input,
                        two,
                        three,
                        four,
                        &input_lengths,
                    )
                    .await
                    .ok_or(());
                println!("Malicious eval took: {}ms", start.elapsed().as_millis());
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
        println!("Running took: {}", start.elapsed().as_millis());
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
        test_malicious_circuit(parsed_circuit, input).await;
    }
    #[tokio::test]
    async fn test_three_bit_and() {
        let logical_or_circuit = ["2 5", "1 3", "1 1", "", "2 1 0 1 3 AND", "2 1 2 3 4 AND"];
        let parsed_circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");
        let input = vec![GF2::zero(), GF2::zero(), GF2::zero()];
        test_malicious_circuit(parsed_circuit, input).await;
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
        test_malicious_circuit(parsed_circuit, input).await;
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
            let mut aes_rng = AesRng::from_random_seed();
            let mut input = Vec::with_capacity(circuit.input_wire_count);
            for _ in 0..circuit.input_wire_count {
                input.push(PackedGF2::one())
            }
            test_malicious_circuit(circuit, input).await;
        });
    }
}
