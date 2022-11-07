pub mod bristol_fashion;
mod gates;

use std::fmt::Debug;
use std::io::{Read, Write};

use crate::pcg::full_key::CorrelationGenerator;
use crate::{communicator::Communicator, fields::FieldElement};

use self::bristol_fashion::ParsedCircuit;
use self::gates::{Gate, Msg};

pub struct Circuit<S: FieldElement> {
    gates: Vec<Vec<Gate<S>>>,
    wires: Vec<S>,
    input_wire_count: usize,
    output_wire_count: usize,
}

impl<S: FieldElement> From<ParsedCircuit> for Circuit<S> {
    fn from(parsed_circuit: ParsedCircuit) -> Self {
        let gates = parsed_circuit
            .gates
            .into_iter()
            .map(|layer| layer.into_iter().map(|g| Gate::from(g)).collect())
            .collect();

        let wires = vec![
            S::default();
            parsed_circuit.input_wire_count
                + parsed_circuit.output_wire_count
                + parsed_circuit.internal_wire_count
        ];
        Self {
            gates,
            wires,
            input_wire_count: parsed_circuit.input_wire_count,
            output_wire_count: parsed_circuit.output_wire_count,
        }
    }
}

impl<S: FieldElement> Circuit<S> {
    fn input_wires(&self) -> &[S] {
        &self.wires[0..self.input_wire_count]
    }

    fn output_wires(&self) -> &[S] {
        &self.wires[self.wires.len() - self.output_wire_count..]
    }
    fn input_wires_mut(&mut self) -> &mut [S] {
        &mut self.wires[0..self.input_wire_count]
    }

    pub fn eval_circuit(&mut self, input_wires: &[S]) -> Option<Vec<S>> {
        assert_eq!(input_wires.len(), self.input_wire_count());
        input_wires
            .iter()
            .zip(self.input_wires_mut().iter_mut())
            .for_each(|(input, wire)| *wire = *input);
        for gate in self.gates.iter().flatten() {
            gate.eval(&mut self.wires);
        }
        Some(self.output_wires().iter().cloned().collect())
    }

    pub fn input_wire_count(&self) -> usize {
        self.input_wire_count
    }
    pub fn get_layer_count(&self) -> usize {
        self.gates.len()
    }
    pub fn output_wire_count(&self) -> usize {
        self.output_wire_count
    }
}

pub enum CircuitEvalSessionState<'a, 'b, S: FieldElement, T: CorrelationGenerator> {
    WaitingToSend(CircuitEvalSessionWaitingToSend<'a, 'b, S, T>),
    WaitingToGenCorrelation(CircuitEvalSessionWaitingToGenCorrelation<'a, 'b, S, T>),
    WaitingToReceive(CircuitEvalSessionWaitingToReceive<'a, 'b, S, T>),
    Finished(Vec<S>),
}
struct CircuitEvalSession<'a, 'b, S: FieldElement, T: CorrelationGenerator> {
    circuit: &'b mut Circuit<S>,
    layer_to_process: usize,
    beaver_triple_gen: &'a mut T,
    gates_in_layer_waiting_for_response: Option<Vec<usize>>,
    party_id: bool,
}

// We use three different structs to enforce certain actions to be done only in certain states by the typing system.

pub struct CircuitEvalSessionWaitingToSend<'a, 'b, S: FieldElement, T: CorrelationGenerator> {
    session: CircuitEvalSession<'a, 'b, S, T>,
}
pub struct CircuitEvalSessionWaitingToGenCorrelation<
    'a,
    'b,
    S: FieldElement,
    T: CorrelationGenerator,
> {
    session: CircuitEvalSession<'a, 'b, S, T>,
}
pub struct CircuitEvalSessionWaitingToReceive<'a, 'b, S: FieldElement, T: CorrelationGenerator> {
    session: CircuitEvalSession<'a, 'b, S, T>,
}

impl<'a, 'b, S: FieldElement, T: CorrelationGenerator> CircuitEvalSession<'a, 'b, S, T> {
    fn generate_beaver_triples_for_layer(&mut self, layer: usize) -> Result<(), ()> {
        let layer = self.circuit.gates.get_mut(layer).ok_or(())?;
        layer
            .iter_mut()
            .try_for_each(|g| g.generate_correlation(self.beaver_triple_gen))
    }
}

impl<'a, 'b, S: FieldElement, T: CorrelationGenerator> CircuitEvalSessionState<'a, 'b, S, T> {
    pub fn new(
        circuit: &'b mut Circuit<S>,
        input_shares: &[S],
        beaver_triple_gen: &'a mut T,
        party_id: bool,
    ) -> Self {
        assert_eq!(circuit.input_wire_count(), input_shares.len());
        circuit
            .input_wires_mut()
            .iter_mut()
            .zip(input_shares.iter())
            .for_each(|(input_wire, input_share)| *input_wire = *input_share);
        let mut session = CircuitEvalSession {
            circuit,
            beaver_triple_gen,
            layer_to_process: 0,
            gates_in_layer_waiting_for_response: None,
            party_id,
        };
        session
            .generate_beaver_triples_for_layer(0)
            .expect("Error generating beaver triples for first layer");
        CircuitEvalSessionState::WaitingToSend(CircuitEvalSessionWaitingToSend { session })
    }
}

impl<'a, 'b, S: FieldElement, T: CorrelationGenerator>
    CircuitEvalSessionWaitingToSend<'a, 'b, S, T>
{
    pub fn fetch_layer_messages(self) -> (CircuitEvalSessionState<'a, 'b, S, T>, Vec<Msg<S>>) {
        // Prepare beaver triples for this layer.
        let mut session = self.session;
        let layer_id = session.layer_to_process;
        let current_layer = session
            .circuit
            .gates
            .get(layer_id)
            .expect("Missing layer, corrupt state!");

        // Generate the messages.
        let (msgs, ids) = current_layer
            .iter()
            .enumerate()
            .filter_map(|(id, gate)| {
                gate.eval_and_generate_msg(&mut session.circuit.wires, session.party_id)
                    .expect("Failed to generate message for the gate")
                    .map(|v| (v, id))
            })
            .unzip();
        session.gates_in_layer_waiting_for_response = Some(ids);

        let new_state = CircuitEvalSessionState::WaitingToGenCorrelation(
            CircuitEvalSessionWaitingToGenCorrelation { session },
        );
        (new_state, msgs)
    }
}

impl<'a, 'b, S: FieldElement, T: CorrelationGenerator>
    CircuitEvalSessionWaitingToGenCorrelation<'a, 'b, S, T>
{
    pub fn gen_correlation_for_next_layer(mut self) -> CircuitEvalSessionState<'a, 'b, S, T> {
        if self.session.circuit.gates.len() > self.session.layer_to_process + 1 {
            self.session
                .generate_beaver_triples_for_layer(self.session.layer_to_process + 1)
                .expect("Failed to generate beaver triples for next layer!");
        }
        CircuitEvalSessionState::WaitingToReceive(CircuitEvalSessionWaitingToReceive {
            session: self.session,
        })
    }
}
impl<'a, 'b, S: FieldElement, T: CorrelationGenerator>
    CircuitEvalSessionWaitingToReceive<'a, 'b, S, T>
{
    pub fn handle_layer_responses(
        self,
        responses: Vec<Msg<S>>,
    ) -> CircuitEvalSessionState<'a, 'b, S, T> {
        let mut session = self.session;
        let layer_id = session.layer_to_process;
        let current_layer = session
            .circuit
            .gates
            .get_mut(layer_id)
            .expect("Current layer id missing, corrupt struct");
        let gates_expecting_response = session
            .gates_in_layer_waiting_for_response
            .take()
            .expect("Expecting gates vector isn't initalized, this has to be a bug!");
        assert_eq!(responses.len(), gates_expecting_response.len());
        for (response, gate_id_in_layer) in
            responses.iter().zip(gates_expecting_response.into_iter())
        {
            current_layer[gate_id_in_layer].handle_peer_msg(&mut session.circuit.wires, response);
        }
        session.layer_to_process = layer_id + 1;
        if session
            .circuit
            .gates
            .get(session.layer_to_process)
            .is_none()
        {
            CircuitEvalSessionState::Finished(
                session
                    .circuit
                    .output_wires()
                    .into_iter()
                    .cloned()
                    .collect(),
            )
        } else {
            CircuitEvalSessionState::WaitingToSend(CircuitEvalSessionWaitingToSend { session })
        }
    }
}

#[derive(Debug)]
pub enum CircuitEvalError {
    CommunicatorError,
}
pub fn eval_circuit<C: Read + Write, S: FieldElement, T: CorrelationGenerator>(
    mut circuit: Circuit<S>,
    (mut my_input, peer_input): (Vec<S>, Vec<S>),
    correlations: &mut T,
    communicator: &mut Communicator<C>,
    is_first: bool,
) -> Result<Vec<S>, CircuitEvalError> {
    assert_eq!(my_input.len(), peer_input.len());
    let mut received_input = communicator
        .exchange(peer_input)
        .ok_or(CircuitEvalError::CommunicatorError)?;
    if is_first {
        my_input.append(&mut received_input);
    } else {
        received_input.append(&mut my_input);
        my_input = received_input;
    }
    let mut session =
        CircuitEvalSessionState::new(&mut circuit, &my_input[..], correlations, is_first);
    let party_output = loop {
        let (session_temp, queries_to_send) = match session {
            CircuitEvalSessionState::WaitingToSend(session) => session.fetch_layer_messages(),
            _ => panic!(),
        };
        session = session_temp;
        communicator
            .send(queries_to_send)
            .ok_or(CircuitEvalError::CommunicatorError)?;
        session = match session {
            CircuitEvalSessionState::WaitingToGenCorrelation(session) => {
                session.gen_correlation_for_next_layer()
            }
            _ => panic!(),
        };
        let queries_received: Vec<_> = communicator
            .receive()
            .ok_or(CircuitEvalError::CommunicatorError)?;
        session = match session {
            CircuitEvalSessionState::WaitingToReceive(session) => {
                session.handle_layer_responses(queries_received)
            }
            _ => panic!(),
        };
        if let CircuitEvalSessionState::Finished(party_output) = session {
            break party_output;
        }
    };
    Ok(party_output)
}

#[cfg(test)]
mod tests {
    use super::bristol_fashion::{parse_bristol, ParsedCircuit};
    use super::Circuit;
    use crate::circuit_eval::CircuitEvalSessionState;
    use crate::fields::{FieldElement, GF128, GF2};
    use crate::pcg::codes::EACode;
    use crate::pcg::full_key::{CorrelationGenerator, FullPcgKey};
    use crate::pcg::receiver_key::PcgKeyReceiver;
    use crate::pcg::sender_key::PcgKeySender;
    use crate::pcg::sparse_vole::scalar_party::OnlineSparseVoleKey as ScalarOnlineSparseVoleKey;
    use crate::pcg::sparse_vole::vector_party::OnlineSparseVoleKey as VectorOnlineSparseVoleKey;
    use crate::pprf::usize_to_bits;
    use crate::pseudorandom::prf::PrfInput;
    use crate::pseudorandom::prg::PrgValue;
    use crate::pseudorandom::KEY_SIZE;

    fn get_prf_keys(amount: u8) -> Vec<PrgValue> {
        let mut base_prf_key = [0u8; KEY_SIZE];
        (0..amount)
            .map(|i| {
                base_prf_key[KEY_SIZE - 1] = i;
                base_prf_key.into()
            })
            .collect()
    }

    fn get_puncturing_points<const INPUT_BITLEN: usize>(amount: u8) -> Vec<PrfInput<INPUT_BITLEN>> {
        (0..amount)
            .map(|i| usize_to_bits(100 * usize::from(i) + 1).into())
            .collect()
    }

    fn eval_mpc_circuit<S: FieldElement>(
        first_party_circuit: &mut Circuit<S>,
        second_party_circuit: &mut Circuit<S>,
        input_a: &[S],
        input_b: &[S],
        beaver_triple_scalar_key: &mut impl CorrelationGenerator,
        beaver_triple_vector_key: &mut impl CorrelationGenerator,
    ) -> (Vec<S>, Vec<S>) {
        let mut first_party_session = CircuitEvalSessionState::new(
            first_party_circuit,
            input_a,
            beaver_triple_scalar_key,
            false,
        );
        let mut second_party_session = CircuitEvalSessionState::new(
            second_party_circuit,
            input_b,
            beaver_triple_vector_key,
            true,
        );
        let (first_party_output, second_party_output) = loop {
            let (first_party_session_temp, first_party_queries) = match first_party_session {
                CircuitEvalSessionState::WaitingToSend(session) => session.fetch_layer_messages(),
                _ => panic!(),
            };
            first_party_session = first_party_session_temp;
            let (second_party_session_temp, second_party_queries) = match second_party_session {
                CircuitEvalSessionState::WaitingToSend(session) => session.fetch_layer_messages(),
                _ => panic!(),
            };
            second_party_session = second_party_session_temp;
            first_party_session = match first_party_session {
                CircuitEvalSessionState::WaitingToGenCorrelation(session) => {
                    session.gen_correlation_for_next_layer()
                }
                _ => panic!(),
            };
            first_party_session = match first_party_session {
                CircuitEvalSessionState::WaitingToReceive(session) => {
                    session.handle_layer_responses(second_party_queries)
                }
                _ => panic!(),
            };
            second_party_session = match second_party_session {
                CircuitEvalSessionState::WaitingToGenCorrelation(session) => {
                    session.gen_correlation_for_next_layer()
                }
                _ => panic!(),
            };
            second_party_session = match second_party_session {
                CircuitEvalSessionState::WaitingToReceive(session) => {
                    session.handle_layer_responses(first_party_queries)
                }
                _ => panic!(),
            };
            if let CircuitEvalSessionState::Finished(first_party_output) = first_party_session {
                if let CircuitEvalSessionState::Finished(second_party_output) = second_party_session
                {
                    break (first_party_output, second_party_output);
                }
                panic!();
            }
        };
        (first_party_output, second_party_output)
    }

    fn gen_sparse_vole_online_keys<
        const WEIGHT: u8,
        const INPUT_BITLEN: usize,
        const CODE_WEIGHT: usize,
    >() -> (
        PcgKeySender<ScalarOnlineSparseVoleKey<CODE_WEIGHT, EACode<CODE_WEIGHT>>>,
        PcgKeyReceiver<VectorOnlineSparseVoleKey<CODE_WEIGHT, EACode<CODE_WEIGHT>>>,
    ) {
        let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let prf_keys = get_prf_keys(WEIGHT);
        let puncturing_points: Vec<PrfInput<INPUT_BITLEN>> = get_puncturing_points(WEIGHT);
        let keys = crate::pcg::sparse_vole::trusted_deal::<INPUT_BITLEN, CODE_WEIGHT>(
            &scalar,
            puncturing_points,
            prf_keys,
        );
        (PcgKeySender::from(keys.0), PcgKeyReceiver::from(keys.1))
    }

    fn test_circuit(circuit: ParsedCircuit, input: &[GF2], random_share: &[GF2]) -> Vec<GF2> {
        const WEIGHT: u8 = 128;
        const CODE_WEIGHT: usize = 8;
        const INPUT_BITLEN: usize = 12;
        assert_eq!(input.len(), random_share.len());
        assert_eq!(input.len(), circuit.input_wire_count);
        let mut circuit_local = Circuit::from(circuit.clone());
        let local_computation_output = circuit_local.eval_circuit(input).unwrap();

        let (scalar_online_key_primary, vector_online_key_primary) =
            gen_sparse_vole_online_keys::<WEIGHT, INPUT_BITLEN, CODE_WEIGHT>();
        let (scalar_online_key_seconary, vector_online_key_secondary) =
            gen_sparse_vole_online_keys::<WEIGHT, INPUT_BITLEN, CODE_WEIGHT>();

        let mut beaver_triple_scalar_key = FullPcgKey::new(
            scalar_online_key_primary,
            vector_online_key_secondary,
            crate::pcg::full_key::Role::Sender,
        );
        let mut beaver_triple_vector_key = FullPcgKey::new(
            scalar_online_key_seconary,
            vector_online_key_primary,
            crate::pcg::full_key::Role::Receiver,
        );

        let input_a = random_share.to_vec();
        let input_b: Vec<_> = input
            .iter()
            .zip(random_share.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        let (output_a, output_b) = eval_mpc_circuit(
            &mut Circuit::from(circuit.clone()),
            &mut Circuit::from(circuit.clone()),
            &input_a,
            &input_b,
            &mut beaver_triple_scalar_key,
            &mut beaver_triple_vector_key,
        );
        assert_eq!(output_a.len(), output_b.len());
        assert_eq!(output_a.len(), circuit.output_wire_count);
        for i in 0..circuit.output_wire_count {
            assert_eq!(output_a[i] + output_b[i], local_computation_output[i]);
        }
        local_computation_output
    }

    #[test]
    fn test_small_circuit() {
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
        let mut circuit = Circuit::from(parsed_circuit.clone());

        // Test classical eval.
        assert_eq!(
            circuit.eval_circuit(&[GF2::one(), GF2::one()]),
            Some(vec![GF2::one()])
        );
        assert_eq!(
            circuit.eval_circuit(&[GF2::zero(), GF2::one()]),
            Some(vec![GF2::one()])
        );
        assert_eq!(
            circuit.eval_circuit(&[GF2::one(), GF2::zero()]),
            Some(vec![GF2::one()])
        );
        assert_eq!(
            circuit.eval_circuit(&[GF2::zero(), GF2::zero()]),
            Some(vec![GF2::zero()])
        );

        let input = vec![GF2::one(), GF2::zero()];
        let rand = vec![GF2::zero(), GF2::zero()];
        let output = test_circuit(parsed_circuit, &input, &rand);

        assert_eq!(output[0], GF2::one());
    }
}
