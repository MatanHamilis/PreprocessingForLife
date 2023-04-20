use std::{collections::HashMap, ops::Mul};

use aes_prng::AesRng;
use rand::RngCore;

use crate::{
    commitment::OfflineCommitment,
    engine::MultiPartyEngine,
    fields::{FieldElement, GF2},
    pcg::{self, FullPcgKey, PackedOfflineFullPcgKey},
    zkfliop, PartyId,
};

use super::{
    bristol_fashion::ParsedCircuit,
    semi_honest::{self, MultiPartyBeaverTriple},
    verify::{self, statement_length, OfflineCircuitVerify},
};

const PPRF_COUNT: usize = 50;
const PPRF_DEPTH: usize = 10;
const CODE_WIDTH: usize = 7;

pub struct MaliciousSecurityOffline<F: FieldElement, C: AsRef<ParsedCircuit>> {
    circuit: C,
    input_mask_seed: [u8; 16],
    my_input_mask: Vec<GF2>,
    pcg_keys: HashMap<PartyId, (PackedOfflineFullPcgKey, [u8; 16])>,
    output_wire_mask_commitments: OfflineCommitment,
    offline_verification_material: OfflineCircuitVerify<F>,
}
impl<F: FieldElement, C: AsRef<ParsedCircuit>> MaliciousSecurityOffline<F, C> {
    pub async fn malicious_security_offline_dealer<E: MultiPartyEngine>(
        engine: &mut E,
        two: F,
        three: F,
        four: F,
        circuit: C,
        party_input_length: &HashMap<PartyId, usize>,
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
        let mut pcg_keys = Vec::with_capacity(parties.len());
        for i in 0..parties.len() {
            pcg_keys.push(HashMap::with_capacity(parties.len() - 1));
            for j in 0..i {
                let mut online_pcg_key = [0u8; 16];
                aes_rng.fill_bytes(&mut online_pcg_key);
                let (snd, rcv) =
                    PackedOfflineFullPcgKey::deal(PPRF_COUNT, PPRF_DEPTH, &mut aes_rng);
                pcg_keys[j].insert(parties[i], (snd, online_pcg_key));
                pcg_keys[i].insert(parties[j], (rcv, online_pcg_key));
            }
        }
        let mask_seeds: Vec<_> = pcg_keys
            .into_iter()
            .enumerate()
            .map(|(p, pcg_key)| {
                let p = parties[p];
                let mut seed = [0u8; 16];
                aes_rng.fill_bytes(&mut seed);
                engine.send((seed, pcg_key), p);
                (p, seed)
            })
            .collect();

        // Correlated random for Verify
        let (input_wire_masks, output_wire_masks) = verify::offline_verify_dealer(
            engine.sub_protocol("offline verify"),
            two,
            three,
            four,
            mask_seeds,
            circuit.as_ref(),
        )
        .await;

        OfflineCommitment::offline_commit(engine, &output_wire_masks).await;
        let mut total_sent = 0;
        parties.iter().for_each(|pid| {
            let input_len = *party_input_length.get(pid).unwrap();
            engine.send(&input_wire_masks[total_sent..total_sent + input_len], *pid);
            total_sent += input_len;
        })
    }
    pub async fn malicious_security_offline_party(
        engine: &mut impl MultiPartyEngine,
        dealer_id: PartyId,
        circuit: C,
    ) -> MaliciousSecurityOffline<F, C> {
        let (input_mask_seed, pcg_key): (
            [u8; 16],
            HashMap<PartyId, (PackedOfflineFullPcgKey, [u8; 16])>,
        ) = engine.recv_from(dealer_id).await.unwrap();
        let proof_statement_length = statement_length(circuit.as_ref());
        let (_, round_count) = zkfliop::compute_round_count_and_m(proof_statement_length);
        let offline_verification_material = verify::offline_verify_parties::<F>(
            engine.sub_protocol("offline verify"),
            dealer_id,
            round_count,
        )
        .await;
        let output_wire_mask_commitments =
            OfflineCommitment::offline_obtain_commit(engine, dealer_id).await;
        let my_input_mask: Vec<GF2> = engine.recv_from(dealer_id).await.unwrap();
        MaliciousSecurityOffline {
            circuit,
            input_mask_seed,
            pcg_keys: pcg_key,
            output_wire_mask_commitments,
            offline_verification_material,
            my_input_mask,
        }
    }
    pub async fn into_pre_online_material<E: MultiPartyEngine>(
        self,
        engine: &mut E,
    ) -> PreOnlineMaterial<F, C> {
        // In this phase we expand the compressed correlations, right before the online phase.
        let Self {
            circuit,
            input_mask_seed,
            my_input_mask,
            pcg_keys,
            output_wire_mask_commitments,
            offline_verification_material,
        } = self;

        let (gate_input_masks, output_wire_mask_shares, input_wire_mask_shares) =
            semi_honest::gate_masks_from_seed(circuit.as_ref(), input_mask_seed);

        let mut expanded_pcg_keys: HashMap<_, _> = pcg_keys
            .into_iter()
            .map(|(pid, (packed_key, code))| {
                (
                    pid,
                    FullPcgKey::new_from_offline(&packed_key, code, CODE_WIDTH),
                )
            })
            .collect();
        let multi_party_beaver_triples = semi_honest::create_multi_party_beaver_triples(
            engine,
            circuit.as_ref(),
            &mut expanded_pcg_keys,
            &gate_input_masks,
        )
        .await;

        PreOnlineMaterial {
            circuit,
            output_wire_mask_commitments,
            multi_party_beaver_triples,
            output_wire_mask_shares,
            input_wire_mask_shares,
            offline_verification_material,
            my_input_mask,
        }
    }
}

pub struct PreOnlineMaterial<F: FieldElement, C: AsRef<ParsedCircuit>> {
    circuit: C,
    multi_party_beaver_triples: HashMap<(usize, usize), MultiPartyBeaverTriple>,
    output_wire_mask_commitments: OfflineCommitment,
    output_wire_mask_shares: Vec<GF2>,
    input_wire_mask_shares: Vec<GF2>,
    my_input_mask: Vec<GF2>,
    offline_verification_material: OfflineCircuitVerify<F>,
}

impl<F: FieldElement, C: AsRef<ParsedCircuit>> PreOnlineMaterial<F, C> {
    pub async fn online_malicious_computation(
        &self,
        engine: &mut impl MultiPartyEngine,
        my_input: Vec<GF2>,
        two: F,
        three: F,
        four: F,
    ) -> Option<Vec<GF2>> {
        let Self {
            circuit,
            multi_party_beaver_triples,
            output_wire_mask_commitments,
            output_wire_mask_shares,
            offline_verification_material,
            input_wire_mask_shares,
            my_input_mask,
        } = self;
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
            )
            .await
            .unwrap();
        let embedded_masked_input_wires: Vec<_> = masked_input_wires
            .iter()
            .map(|v| F::one().switch(v.is_one()))
            .collect();
        let masked_outputs_in_field: Vec<_> = masked_outputs
            .iter()
            .map(|v| if v.is_one() { F::one() } else { F::zero() })
            .collect();
        if !verify::verify_parties(
            engine,
            two,
            three,
            four,
            &embedded_masked_input_wires,
            &masked_gate_inputs,
            multi_party_beaver_triples,
            &masked_outputs_in_field,
            circuit.as_ref(),
            offline_verification_material,
        )
        .await
        {
            return None;
        }
        let output_wire_masks: Vec<GF2> =
            output_wire_mask_commitments.online_decommit(engine).await;
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
    use tokio::join;

    use super::MaliciousSecurityOffline;
    use crate::{
        circuit_eval::{
            bristol_fashion::{parse_bristol, ParsedCircuit},
            malicious::PreOnlineMaterial,
            semi_honest,
        },
        engine::{self, LocalRouter, MultiPartyEngine, MultiPartyEngineImpl},
        fields::{FieldElement, GF128, GF2},
        PartyId, UCTag,
    };

    async fn test_malicious_circuit(circuit: ParsedCircuit, input: Vec<GF2>) -> Vec<GF2> {
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
                (i, my_input_len)
            })
            .collect();
        let (offline_router, mut offline_engines) =
            LocalRouter::new(UCTag::new(&"ROOT_TAG"), &offline_parties_set);
        let circuit_arc = Arc::new(circuit);
        let dealer_handle = {
            let circuit_arc_clone = circuit_arc.clone();
            let mut dealer_engine = offline_engines.remove(&DEALER_ID).unwrap();
            async move {
                MaliciousSecurityOffline::malicious_security_offline_dealer(
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
                    let res = MaliciousSecurityOffline::malicious_security_offline_party(
                        &mut e,
                        DEALER_ID,
                        circuit_clone_arc,
                    )
                    .await;
                    Result::<(PartyId, MaliciousSecurityOffline<GF128, _>), ()>::Ok((pid, res))
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
                        Result::<(PartyId, PreOnlineMaterial<_, _>), ()>::Ok((
                            pid,
                            pre_online_material,
                        ))
                    }
                });

        let pre_online_handles = try_join_all(pre_online_handles).await.unwrap();

        // Input sharing
        let mut aes_rng = AesRng::from_random_seed();

        // Online
        let online_handles = pre_online_handles.into_iter().map(|(pid, pre)| {
            let input = inputs.remove(&pid).unwrap();
            let mut engine = online_engines.remove(&pid).unwrap();
            async move {
                pre.online_malicious_computation(&mut engine, input, two, three, four)
                    .await
                    .ok_or(())
            }
        });
        let mut online_outputs = try_join_all(online_handles).await.unwrap();
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

    #[tokio::test]
    async fn test_aes() {
        let path = Path::new("circuits/adder64.txt");
        let circuit = super::super::circuit_from_file(path).unwrap();
        let mut aes_rng = AesRng::from_random_seed();
        let mut input = Vec::with_capacity(circuit.input_wire_count);
        for _ in 0..circuit.input_wire_count {
            input.push(GF2::one())
        }
        test_malicious_circuit(circuit, input).await;
    }
}
