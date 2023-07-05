use std::{
    assert_eq, collections::HashMap, debug_assert, ops::Mul, print, time::Duration, unimplemented,
};

use aes_prng::AesRng;
use blake3::{Hash, OUT_LEN};
use log::info;
use rand::Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use tokio::time::Instant;

use crate::{
    circuit_eval::bristol_fashion::ParsedGate,
    commitment::OfflineCommitment,
    engine::MultiPartyEngine,
    fields::{FieldElement, PackedField, GF2},
    PartyId,
};

use super::{FieldContainer, ParsedCircuit};

#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedValue<const N: usize, PF: PackedField<GF2, N>, VF: FieldElement>
where
    VF: Mul<GF2, Output = VF>,
{
    value: PF,
    mac: [VF; N],
}
impl<const N: usize, PF: PackedField<GF2, N>, VF: FieldElement + Mul<GF2, Output = VF>>
    AuthenticatedValue<N, PF, VF>
{
    fn random(
        value: &PF,
        mac_key: &VF,
        mut rng: impl CryptoRng + RngCore,
        parties_count: usize,
    ) -> Vec<Self> {
        let mut last_value = *value;
        let mut last_mac: [VF; N] = core::array::from_fn(|i| *mac_key * value.get_element(i));
        let mut output: Vec<_> = (0..parties_count - 1)
            .map(|_| {
                let value_share = PF::random(&mut rng);
                last_value -= value_share;
                let random_mac_share = core::array::from_fn(|i| {
                    let r = VF::random(&mut rng);
                    last_mac[i] -= r;
                    r
                });
                AuthenticatedValue {
                    value: value_share,
                    mac: random_mac_share,
                }
            })
            .collect();
        output.push(AuthenticatedValue {
            value: last_value,
            mac: last_mac,
        });
        output
    }
    fn add_into(&mut self, rhs: &Self) {
        self.value += rhs.value;
        for i in 0..N {
            self.mac[i] += rhs.mac[i];
        }
    }
    fn add(&self, rhs: &Self) -> Self {
        Self {
            value: self.value + rhs.value,
            mac: core::array::from_fn(|i| self.mac[i] + rhs.mac[i]),
        }
    }
    fn add_public_value_into(&mut self, rhs: &PF, mac_key_share: &VF, is_first: bool) {
        if is_first {
            self.value += *rhs;
        }
        for i in 0..N {
            self.mac[i] += *mac_key_share * rhs.get_element(i);
        }
    }
    fn add_public_value(&self, rhs: &PF, mac_key_share: &VF, is_first: bool) -> Self {
        let value = if is_first {
            self.value + *rhs
        } else {
            self.value
        };
        Self {
            value,
            mac: core::array::from_fn(|i| self.mac[i] + *mac_key_share * rhs.get_element(i)),
        }
    }
    fn mul_open(
        &self,
        y: &Self,
        AuthenticatedBeaverTriple(a, b, ab): &AuthenticatedBeaverTriple<N, PF, VF>,
    ) -> (PF, PF) {
        (self.value - a.value, y.value - b.value)
    }
    fn mul_compute(
        &self,
        y: &Self,
        xa: PF,
        yb: PF,
        AuthenticatedBeaverTriple(a, b, ab): &AuthenticatedBeaverTriple<N, PF, VF>,
    ) -> Self {
        AuthenticatedValue {
            value: y.value * xa + a.value * yb + ab.value,
            mac: core::array::from_fn(|i| {
                y.mac[i] * xa.get_element(i) + a.mac[i] * yb.get_element(i) + ab.mac[i]
            }),
        }
    }
}
pub struct AuthenticatedBeaverTriple<
    const N: usize,
    F: PackedField<GF2, N>,
    VF: FieldElement + Mul<GF2, Output = VF>,
>(
    AuthenticatedValue<N, F, VF>,
    AuthenticatedValue<N, F, VF>,
    AuthenticatedValue<N, F, VF>,
);

impl<const N: usize, F: PackedField<GF2, N>, VF: FieldElement + Mul<GF2, Output = VF>>
    AuthenticatedBeaverTriple<N, F, VF>
{
    fn random(mut rng: impl CryptoRng + RngCore, mac_key: &VF, parties_count: usize) -> Vec<Self> {
        let a = F::random(&mut rng);
        let b = F::random(&mut rng);
        let ab = a * b;
        let va = AuthenticatedValue::random(&a, mac_key, &mut rng, parties_count);
        let vb = AuthenticatedValue::random(&b, mac_key, &mut rng, parties_count);
        let vab = AuthenticatedValue::random(&ab, mac_key, rng, parties_count);
        va.into_iter()
            .zip(vb.into_iter())
            .zip(vab.into_iter())
            .map(|((vai, vbi), vabi)| AuthenticatedBeaverTriple(vai, vbi, vabi))
            .collect()
    }
}
pub struct SpdzCorrelation<
    const N: usize,
    PF: PackedField<GF2, N>,
    VF: FieldElement + Mul<GF2, Output = VF>,
> {
    mac_share: VF,
    auth_input: Vec<AuthenticatedValue<N, PF, VF>>,
    check_seed: OfflineCommitment,
    personal_input_masks: Vec<PF>,
    triples: Vec<AuthenticatedBeaverTriple<N, PF, VF>>,
}
pub fn spdz_deal<
    const N: usize,
    PF: PackedField<GF2, N>,
    VF: FieldElement + Mul<GF2, Output = VF>,
>(
    circuit: &ParsedCircuit,
    input_pos: &HashMap<PartyId, (usize, usize)>,
) -> HashMap<PartyId, SpdzCorrelation<N, PF, VF>> {
    let time = Instant::now();
    let party_count = input_pos.len();
    let mut rng = AesRng::from_random_seed();
    let mut mac = VF::zero();
    let mut macs: HashMap<_, _> = input_pos
        .iter()
        .map(|v| {
            let m = VF::random(&mut rng);
            mac += m;
            (*v.0, m)
        })
        .collect();
    let random_inputs: Vec<_> = (0..circuit.input_wire_count)
        .map(|_| PF::random(&mut rng))
        .collect();
    let mut random_input_shares: HashMap<_, _> =
        input_pos.keys().map(|&pid| (pid, Vec::new())).collect();
    random_inputs.iter().for_each(|input| {
        let auth_shared = AuthenticatedValue::random(input, &mac, &mut rng, party_count);
        random_input_shares
            .values_mut()
            .zip(auth_shared.into_iter())
            .for_each(|(v, s)| v.push(s));
    });
    let mut per_party_input: HashMap<_, _> = input_pos
        .iter()
        .map(|(&pid, &(start, len))| (pid, random_inputs[start..start + len].to_vec()))
        .collect();

    let mut check_seed: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut check_seed);
    let (comms, commitment) = OfflineCommitment::commit(&check_seed, party_count);
    let mut check_seeds: HashMap<_, _> = comms
        .into_iter()
        .zip(input_pos.keys())
        .map(|(commit_share, &pid)| {
            (
                pid,
                OfflineCommitment {
                    commit_share,
                    commitment,
                },
            )
        })
        .collect();
    let total_triples_count = circuit
        .iter()
        .filter(|g| match g.2 {
            &ParsedGate::AndGate {
                input: _,
                output: _,
            } => true,
            &ParsedGate::WideAndGate {
                input: _,
                input_bit: _,
                output: _,
            } => unimplemented!("Wide gates not supported for SPDZ now"),
            _ => false,
        })
        .count();
    let mut party_triples: HashMap<_, _> = input_pos
        .keys()
        .map(|&pid| {
            (
                pid,
                Vec::<AuthenticatedBeaverTriple<N, PF, VF>>::with_capacity(total_triples_count),
            )
        })
        .collect();
    (0..total_triples_count).for_each(|_| {
        let triples = AuthenticatedBeaverTriple::random(&mut rng, &mac, party_count);
        triples
            .into_iter()
            .zip(party_triples.values_mut())
            .for_each(|(bt, v)| v.push(bt));
    });
    debug_assert_eq!(macs.values().copied().sum::<VF>(), mac);
    let o = input_pos
        .keys()
        .map(|pid| {
            (
                *pid,
                SpdzCorrelation {
                    mac_share: macs.remove(pid).unwrap(),
                    auth_input: random_input_shares.remove(pid).unwrap(),
                    personal_input_masks: per_party_input.remove(pid).unwrap(),
                    check_seed: check_seeds.remove(pid).unwrap(),
                    triples: party_triples.remove(pid).unwrap(),
                },
            )
        })
        .collect();
    info!("SPDZ Dealer took: {}ms", time.elapsed().as_millis());
    o
}
pub async fn online_spdz<
    const N: usize,
    PF: PackedField<GF2, N>,
    VF: FieldElement + Mul<GF2, Output = VF>,
>(
    engine: &mut impl MultiPartyEngine,
    circuit: &ParsedCircuit,
    input: &[PF],
    correlation: SpdzCorrelation<N, PF, VF>,
    input_pos: impl AsRef<HashMap<PartyId, (usize, usize)>>,
) -> Vec<PF> {
    let SpdzCorrelation {
        mac_share,
        auth_input,
        check_seed,
        personal_input_masks,
        triples,
    } = correlation;
    let my_id = engine.my_party_id();
    let is_first = engine.party_ids()[0] == my_id;
    let mut wires = Vec::<AuthenticatedValue<N, PF, VF>>::with_capacity(
        circuit.input_wire_count + circuit.output_wire_count + circuit.internal_wire_count,
    );
    unsafe {
        wires.set_len(
            circuit.input_wire_count + circuit.output_wire_count + circuit.internal_wire_count,
        )
    }
    debug_assert_eq!(auth_input.len(), circuit.input_wire_count);
    let input_pos = input_pos.as_ref();
    let total_input_pos: usize = input_pos.iter().map(|(_, len)| len.1).sum();
    debug_assert_eq!(total_input_pos, circuit.input_wire_count);

    // Input preparation
    let time = Instant::now();
    let (my_input_start, my_input_len) = input_pos[&my_id];
    assert_eq!(my_input_len, input.len());
    wires[..circuit.input_wire_count].copy_from_slice(&auth_input);
    let openings: Vec<_> = personal_input_masks
        .iter()
        .zip(input.iter())
        .map(|(m, i)| *i - *m)
        .collect();
    wires[my_input_start..my_input_start + input.len()]
        .iter_mut()
        .zip(openings.iter())
        .for_each(|(w, o)| {
            w.add_public_value_into(o, &mac_share, is_first);
        });
    engine.broadcast(openings);
    let peers_num = engine.party_ids().len() - 1;
    for _ in 0..peers_num {
        let (openings, pid): (Vec<PF>, PartyId) = engine.recv().await.unwrap();
        let (input_start, input_len) = input_pos[&pid];
        assert_eq!(input_len, openings.len());
        wires[input_start..input_start + input_len]
            .iter_mut()
            .zip(openings.iter())
            .for_each(|(w, o)| {
                w.add_public_value_into(o, &mac_share, is_first);
            })
    }
    // Semi-honest Computation

    let mut open_triples_iter = triples.iter().enumerate();
    let mut eval_triples_iter = triples.iter().enumerate();
    let mut msgs = Vec::new();
    let mut gates = Vec::new();
    let mut proof_values = Vec::new();
    let time = Instant::now();
    let mut non_comm_time = Duration::new(0, 0);
    let mut comm_time = Duration::new(0, 0);
    for layer in circuit.gates.iter() {
        msgs.clear();
        gates.clear();
        let time = Instant::now();
        for gate in layer.iter() {
            match gate {
                &ParsedGate::XorGate { input, output } => {
                    wires[output] = wires[input[0]].add(&wires[input[1]]);
                }
                &ParsedGate::NotGate { input, output } => {
                    wires[output] = wires[input].add_public_value(&PF::one(), &mac_share, is_first)
                }
                ParsedGate::AndGate { input, output } => {
                    let bt = open_triples_iter.next().unwrap();
                    let (xa, yb) = wires[input[0]].mul_open(&wires[input[1]], bt.1);
                    msgs.push((xa, yb));
                    gates.push((input, output))
                }
                ParsedGate::WideAndGate {
                    input: _,
                    input_bit: _,
                    output: _,
                } => {
                    unimplemented!("This is not implemented for now")
                }
            }
        }
        non_comm_time += time.elapsed();
        let time = Instant::now();
        engine.broadcast(&msgs);
        for _ in 0..peers_num {
            let (peer_msg, _): (Vec<(PF, PF)>, _) = engine.recv().await.unwrap();
            assert_eq!(msgs.len(), peer_msg.len());
            msgs.iter_mut()
                .zip(peer_msg.into_iter())
                .for_each(|(msg, peer_msg)| {
                    msg.0 += peer_msg.0;
                    msg.1 += peer_msg.1;
                })
        }
        comm_time += time.elapsed();
        let time = Instant::now();
        gates
            .iter()
            .copied()
            .zip(msgs.iter())
            .for_each(|((input, output), opening)| {
                let x = &wires[input[0]];
                let y = &wires[input[1]];
                let (_, bt) = eval_triples_iter.next().unwrap();
                let AuthenticatedBeaverTriple(a, b, _) = &bt;
                let check_first_opening = core::array::from_fn(|i| {
                    x.mac[i] - a.mac[i] + mac_share * opening.0.get_element(i)
                });
                let check_second_opening: [_; N] = core::array::from_fn(|i| {
                    y.mac[i] - b.mac[i] + mac_share * opening.1.get_element(i)
                });
                proof_values.push(check_first_opening);
                proof_values.push(check_second_opening);
                wires[*output] =
                    wires[input[0]].mul_compute(&wires[input[1]], opening.0, opening.1, bt);
            });
        non_comm_time += time.elapsed();
    }
    info!("Non Communication Time: {}ms", non_comm_time.as_millis());
    info!("Communication Time: {}ms", comm_time.as_millis());
    info!("Semi Honest Time: {}", time.elapsed().as_millis());
    let challenge: [u8; 16] = check_seed.online_decommit(engine).await;
    let mut rng = AesRng::from_seed(challenge);

    // Verify Openings
    let time = Instant::now();
    info!("Proof Values Len:{}", proof_values.len());
    info!("Proof Values [0] Len:{}", proof_values[0].len());
    let check_value_time = Instant::now();
    let check_value: VF = proof_values
        .iter()
        .map(|p| p.iter().map(|pp| *pp * VF::random(&mut rng)).sum())
        .sum();
    info!(
        "Check Value Computation: {}ms",
        check_value_time.elapsed().as_millis()
    );
    let commitment = blake3::hash(&bincode::serialize(&check_value).unwrap());
    engine.broadcast(commitment.as_bytes());
    let mut comms = HashMap::new();
    while comms.len() != peers_num {
        let (comm, pid): ([u8; OUT_LEN], _) = engine.recv().await.unwrap();
        assert!(comms.insert(pid, comm).is_none());
    }
    engine.broadcast(check_value);
    let mut sum = check_value;
    while !comms.is_empty() {
        let (decomm, pid): (VF, _) = engine.recv().await.unwrap();
        let comm = comms.remove(&pid).unwrap();
        let comm_recv = blake3::hash(&bincode::serialize(&decomm).unwrap());
        assert_eq!(&comm, comm_recv.as_bytes());
        sum += decomm;
    }
    assert!(sum.is_zero());

    info!("Verification Time: {}", time.elapsed().as_millis());
    // Output
    let time = Instant::now();
    let output_wires = &mut wires[circuit.input_wire_count + circuit.internal_wire_count..];
    let mut output_wires_vals: Vec<_> = output_wires.iter().map(|v| v.value).collect();
    engine.broadcast(&output_wires_vals);
    for _ in 0..peers_num {
        let (v, _): (Vec<PF>, _) = engine.recv().await.unwrap();
        output_wires_vals
            .iter_mut()
            .zip(v.iter())
            .for_each(|(o, v)| *o += *v);
    }
    info!("Output Obtaining Time: {}", time.elapsed().as_millis());

    // Verify output
    let time = Instant::now();
    proof_values.clear();
    output_wires
        .iter()
        .zip(output_wires_vals.iter())
        .for_each(|(o, v)| {
            proof_values.push(core::array::from_fn(|i| {
                o.mac[i] - mac_share * v.get_element(i)
            }));
        });
    let check_value: VF = proof_values
        .iter()
        .map(|p| p.iter().map(|pp| *pp * VF::random(&mut rng)).sum())
        .sum();
    let commitment = blake3::hash(&bincode::serialize(&check_value).unwrap());
    engine.broadcast(commitment.as_bytes());
    let mut comms = HashMap::new();
    while comms.len() != peers_num {
        let (comm, pid): ([u8; OUT_LEN], _) = engine.recv().await.unwrap();
        assert!(comms.insert(pid, comm).is_none());
    }
    engine.broadcast(check_value);
    let mut sum = check_value;
    while !comms.is_empty() {
        let (decomm, pid): (VF, _) = engine.recv().await.unwrap();
        let comm = comms.remove(&pid).unwrap();
        let comm_recv = blake3::hash(&bincode::serialize(&decomm).unwrap());
        assert_eq!(&comm, comm_recv.as_bytes());
        sum += decomm;
    }
    assert!(sum.is_zero());
    info!("Output Verification Time: {}", time.elapsed().as_millis());
    output_wires_vals
}

#[cfg(test)]
mod tests {
    use std::{
        assert_eq,
        collections::{HashMap, HashSet},
        path::Path,
        sync::Arc,
    };

    use aes_prng::AesRng;
    use tokio::join;

    use crate::{
        circuit_eval::{parse_bristol, semi_honest::local_eval_circuit, ParsedCircuit},
        engine::{LocalRouter, NetworkRouter},
        fields::{FieldElement, PackedField, PackedGF2, GF2, GF64},
        PartyId, UCTag,
    };

    use super::{online_spdz, spdz_deal};
    fn spdz_test_circuit<const N: usize, PF: PackedField<GF2, N>>(
        circuit: ParsedCircuit,
        party_count: usize,
        input: Vec<PF>,
    ) {
        let circuit = Arc::new(circuit);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let party_ids: [PartyId; 2] = [1, 2];
        let input_pos: HashMap<PartyId, (usize, usize)> = HashMap::from([
            (1, (0, circuit.input_wire_count / 2)),
            (
                2,
                (
                    circuit.input_wire_count / 2,
                    circuit.input_wire_count - circuit.input_wire_count / 2,
                ),
            ),
        ]);
        let local_value = local_eval_circuit(circuit.as_ref(), &input);
        let first_pos = input_pos[&party_ids[0]];
        let input_first: Vec<_> = input[first_pos.0..first_pos.0 + first_pos.1].to_vec();
        let second_pos = input_pos[&party_ids[1]];
        let input_second: Vec<_> = input[second_pos.0..second_pos.0 + second_pos.1].to_vec();
        let mut corr = spdz_deal::<N, PF, GF64>(circuit.as_ref(), &input_pos);
        let parties_set = HashSet::from_iter(party_ids);
        let (router, mut execs) = LocalRouter::new(UCTag::new(&"ROOT TAG"), &parties_set);
        let router_handle = runtime.spawn(router.launch());
        let first_party = execs.remove(&party_ids[0]).unwrap();
        let second_party = execs.remove(&party_ids[1]).unwrap();
        let first_party_circuit = circuit.clone();
        let second_party_circuit = circuit.clone();
        let corr_first = corr.remove(&party_ids[0]).unwrap();
        let corr_second = corr.remove(&party_ids[1]).unwrap();
        let input_pos_first = Arc::new(input_pos);
        let input_pos_second = input_pos_first.clone();
        let first_party_handle = runtime.spawn(async move {
            let mut first_party = first_party;
            online_spdz(
                &mut first_party,
                &first_party_circuit,
                &input_first,
                corr_first,
                input_pos_first,
            )
            .await
        });
        let second_party_handle = runtime.spawn(async move {
            let mut second_party = second_party;
            online_spdz(
                &mut second_party,
                &second_party_circuit,
                &input_second,
                corr_second,
                input_pos_second,
            )
            .await
        });
        let (first, second, router) = runtime
            .block_on(async move { join!(first_party_handle, second_party_handle, router_handle) });
        router.unwrap().unwrap();
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_eq!(first, second);
        let output_start = circuit.as_ref().input_wire_count + circuit.as_ref().internal_wire_count;
        assert_eq!(first, local_value[output_start..]);
    }

    #[test]
    fn spdz_small_circuit_test() {
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

        spdz_test_circuit::<{ GF2::BITS }, GF2>(parsed_circuit, 2, vec![GF2::zero(), GF2::zero()]);
    }
    #[test]
    fn spdz_test() {
        const PARTY_COUNT: usize = 2;
        let path = Path::new("circuits/aes_128.txt");
        let parsed_circuit = super::super::circuit_from_file(path).unwrap();
        spdz_test_circuit::<{ PackedGF2::BITS }, PackedGF2>(
            parsed_circuit,
            PARTY_COUNT,
            vec![PackedGF2::one(); 256],
        );
    }
}
